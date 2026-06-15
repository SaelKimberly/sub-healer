use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use fastbloom::BloomFilter;

use crate::proto_spec::{ProtoSpec, ProtocolConfig};
use crate::urlx::HostSpec;

use rustls::pki_types::IpAddr::V4;

// ── Flag bitmask constants ────────────────────────────────────────────────

pub const SNI_WHITELISTED: u8 = 1 << 0;
pub const CIDR_WHITELISTED: u8 = 1 << 1;
pub const IP_WHITELISTED: u8 = 1 << 2;

// ── WhitelistChecker ──────────────────────────────────────────────────────

/// Three-way whitelist checker backed by bloom filters (fast-negative guard)
/// plus exact HashSet/interval verification (zero false positives).
pub struct WhitelistChecker {
    /// SNI whitelist (whitelist.txt) — hostnames
    sni_bloom: BloomFilter,
    sni_set: HashSet<String>,
    /// IP whitelist (ipwhitelist.txt) — IPv4 as u32 big-endian
    ip_bloom: BloomFilter,
    ip_set: HashSet<u32>,
    /// CIDR whitelist (cidrwhitelist.txt) — sorted (start_u32, end_u32) intervals
    cidr_ranges: Vec<(u32, u32)>,
}

impl WhitelistChecker {
    const FP_RATE: f64 = 0.01;

    /// Load all three whitelist files.
    ///
    /// # Errors
    ///
    /// Returns an error if any file cannot be read or contains invalid entries.
    pub fn new(sni_path: &Path, ip_path: &Path, cidr_path: &Path) -> anyhow::Result<Self> {
        let (sni_bloom, sni_set) = Self::load_sni(sni_path)?;
        let (ip_bloom, ip_set) = Self::load_ip(ip_path)?;
        let cidr_ranges = Self::load_cidr(cidr_path)?;

        Ok(Self {
            sni_bloom,
            sni_set,
            ip_bloom,
            ip_set,
            cidr_ranges,
        })
    }

    // ── Loaders ──────────────────────────────────────────────────────────

    fn load_sni(path: &Path) -> anyhow::Result<(BloomFilter, HashSet<String>)> {
        let content = std::fs::read_to_string(path)?;
        let mut set = HashSet::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            set.insert(trimmed.to_ascii_lowercase());
        }

        let bloom = BloomFilter::with_false_pos(Self::FP_RATE).items(set.iter());
        Ok((bloom, set))
    }

    fn load_ip(path: &Path) -> anyhow::Result<(BloomFilter, HashSet<u32>)> {
        let content = std::fs::read_to_string(path)?;
        let mut set = HashSet::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let addr: Ipv4Addr = match trimmed.parse() {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(line = trimmed, error = %e, "Skipping malformed IP");
                    continue;
                }
            };
            let key = u32::from_be_bytes(addr.octets());
            set.insert(key);
        }

        let bloom = BloomFilter::with_false_pos(Self::FP_RATE).items(set.iter());
        Ok((bloom, set))
    }

    fn load_cidr(path: &Path) -> anyhow::Result<Vec<(u32, u32)>> {
        let content = std::fs::read_to_string(path)?;
        let mut ranges = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some((ip_str, mask_str)) = trimmed.split_once('/') else {
                tracing::debug!(line = trimmed, "Skipping malformed CIDR (no /)");
                continue;
            };
            let base: Ipv4Addr = match ip_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(line = trimmed, error = %e, "Skipping malformed CIDR IP");
                    continue;
                }
            };
            let mask_bits: u8 = match mask_str.parse() {
                Ok(m) if m <= 32 => m,
                _ => {
                    tracing::debug!(line = trimmed, "Skipping malformed CIDR mask");
                    continue;
                }
            };
            let base_u32 = u32::from_be_bytes(base.octets());
            let mask = if mask_bits == 0 {
                0u32
            } else {
                (!0u32) << (32 - mask_bits)
            };
            let start = base_u32 & mask;
            let end = start | !mask;
            ranges.push((start, end));
        }

        ranges.sort_unstable_by_key(|r| r.0);
        Ok(ranges)
    }

    // ── Lookup methods ───────────────────────────────────────────────────

    /// Fast-negative bloom filter + HashSet verification.
    #[must_use]
    pub fn is_sni_whitelisted(&self, host: &str) -> bool {
        let lower = host.to_ascii_lowercase();
        if !self.sni_bloom.contains(&lower) {
            return false;
        }
        self.sni_set.contains(&lower)
    }

    #[must_use]
    pub fn is_ip_whitelisted(&self, ip: Ipv4Addr) -> bool {
        let key = u32::from_be_bytes(ip.octets());
        if !self.ip_bloom.contains(&key) {
            return false;
        }
        self.ip_set.contains(&key)
    }

    #[must_use]
    pub fn is_cidr_whitelisted(&self, ip: Ipv4Addr) -> bool {
        let key = u32::from_be_bytes(ip.octets());
        let idx = self.cidr_ranges.partition_point(|&(s, _)| s <= key);
        idx > 0 && key <= self.cidr_ranges[idx - 1].1
    }

    /// Check a parsed ProtocolConfig against all three whitelists.
    /// Returns bitmask of matched flags.
    pub fn check_config(&self, config: &ProtocolConfig) -> u8 {
        let mut flags = 0u8;

        // SNI from TLS security config
        if let Some(sni) = config.security().and_then(|s| s.sni())
            && self.is_sni_whitelisted(sni)
        {
            flags |= SNI_WHITELISTED;
        }

        // Host-based checks
        if let Some(host) = config.host() {
            match host {
                HostSpec::DnsName(name) => {
                    if self.is_sni_whitelisted(name.as_ref()) {
                        flags |= SNI_WHITELISTED;
                    }
                }
                HostSpec::IpAddress(V4(ip)) => {
                    let addr = std::net::Ipv4Addr::from(*ip);
                    if self.is_ip_whitelisted(addr) {
                        flags |= IP_WHITELISTED;
                    }
                    if self.is_cidr_whitelisted(addr) {
                        flags |= CIDR_WHITELISTED;
                    }
                }
                _ => {} // IPv6 — IPv4-only whitelists, skip
            }
        }

        flags
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto_spec::ProtoSpec;
    use crate::proto_spec::ProtocolConfig;
    use crate::urlx::RawUrlX;
    use std::io::Write;

    fn write_temp(content: &[u8]) -> std::path::PathBuf {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        let path = f.path().to_owned();
        // Keep the file alive (leaks the temp file, fine for tests)
        std::mem::forget(f);
        path
    }

    fn sni_file(hosts: &[&str]) -> std::path::PathBuf {
        write_temp(hosts.join("\n").as_bytes())
    }

    fn ip_file(ips: &[&str]) -> std::path::PathBuf {
        write_temp(ips.join("\n").as_bytes())
    }

    fn cidr_file(cidrs: &[&str]) -> std::path::PathBuf {
        write_temp(cidrs.join("\n").as_bytes())
    }

    /// Convenience: create a checker with the given sni/ip/cidr slices.
    fn make_checker(sni: &[&str], ip: &[&str], cidr: &[&str]) -> WhitelistChecker {
        WhitelistChecker::new(&sni_file(sni), &ip_file(ip), &cidr_file(cidr)).unwrap()
    }

    #[test]
    fn sni_present() {
        let checker = make_checker(&["example.com", "test.server.org"], &[], &[]);
        assert!(checker.is_sni_whitelisted("example.com"));
        assert!(checker.is_sni_whitelisted("Example.COM")); // case insensitive
        assert!(!checker.is_sni_whitelisted("unknown.com"));
    }

    #[test]
    fn sni_absent() {
        let checker = make_checker(&["known.example"], &[], &[]);
        assert!(!checker.is_sni_whitelisted("not.known.example"));
    }

    #[test]
    fn ip_present() {
        let checker = make_checker(&[], &["1.2.3.4", "10.0.0.1"], &[]);
        assert!(checker.is_ip_whitelisted(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(checker.is_ip_whitelisted(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!checker.is_ip_whitelisted(Ipv4Addr::new(9, 9, 9, 9)));
    }

    #[test]
    fn cidr_present() {
        let checker = make_checker(&[], &[], &["192.168.0.0/16", "10.0.0.0/8"]);
        assert!(checker.is_cidr_whitelisted(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(checker.is_cidr_whitelisted(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!checker.is_cidr_whitelisted(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn ip_not_in_cidr() {
        let checker = make_checker(&[], &[], &["10.0.0.0/8"]);
        assert!(!checker.is_cidr_whitelisted(Ipv4Addr::new(11, 0, 0, 1)));
        assert!(!checker.is_cidr_whitelisted(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn config_with_tls_sni() {
        // VLESS config with TLS SNI matching whitelist
        let checker = make_checker(&["whitelisted.example"], &[], &[]);

        let url = "vless://uuid@1.2.3.4:443?security=tls&sni=whitelisted.example";
        let raw = RawUrlX::from(url);
        let config = ProtocolConfig::try_parse(&raw).unwrap();

        let flags = checker.check_config(&config);
        assert!(
            flags & SNI_WHITELISTED != 0,
            "SNI-whitelisted host should set SNI_WHITELISTED flag"
        );
    }

    #[test]
    fn config_with_ip_whitelisted() {
        let checker = make_checker(&[], &["1.2.3.4"], &[]);

        let url = "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6ODAsImlkIjoiYWJjZGUtMTIzNDUtNjc4OTAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSJ9";
        let raw = RawUrlX::from(url);
        let config = ProtocolConfig::try_parse(&raw).unwrap();

        let flags = checker.check_config(&config);
        assert!(
            flags & IP_WHITELISTED != 0,
            "IP-whitelisted server should set IP_WHITELISTED flag"
        );
    }

    #[test]
    fn empty_whitelists() {
        let checker = make_checker(&[], &[], &[]);
        assert!(!checker.is_sni_whitelisted("anything"));
        assert!(!checker.is_ip_whitelisted(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(!checker.is_cidr_whitelisted(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn malformed_lines_skipped() {
        let content = b"valid.example\n  \n# comment\n\nother.valid\n";
        let sni = write_temp(content);
        let checker = WhitelistChecker::new(&sni, &ip_file(&[]), &cidr_file(&[])).unwrap();
        // Our loader treats every non-empty line as a hostname (no comment stripping).
        // "# comment" is stored literally as "# comment" (with hash), so it's whitelisted.
        assert!(checker.is_sni_whitelisted("valid.example"));
        assert!(checker.is_sni_whitelisted("other.valid"));
        assert!(checker.is_sni_whitelisted("# comment"));
    }

    #[test]
    fn malformed_ip_lines_skipped() {
        let content = b"1.2.3.4\n  \nnot_an_ip\n5.6.7.8\n";
        let ip = write_temp(content);
        let checker = WhitelistChecker::new(&sni_file(&[]), &ip, &cidr_file(&[])).unwrap();

        assert!(checker.is_ip_whitelisted(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(checker.is_ip_whitelisted(Ipv4Addr::new(5, 6, 7, 8)));
        assert!(!checker.is_ip_whitelisted(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn malformed_cidr_lines_skipped() {
        let content = b"10.0.0.0/8\nbad\n192.168.0.0/16\n1.2.3.4/33\n";
        let cidr = write_temp(content);
        let checker = WhitelistChecker::new(&sni_file(&[]), &ip_file(&[]), &cidr).unwrap();

        assert!(checker.is_cidr_whitelisted(Ipv4Addr::new(10, 10, 10, 10)));
        assert!(checker.is_cidr_whitelisted(Ipv4Addr::new(192, 168, 1, 1)));
        // /33 is invalid, skipped; 0.0.0.0 is not matched
        assert!(!checker.is_cidr_whitelisted(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn alt_dns_name_is_sni_whitelisted() {
        // Config where the host is a DNS name (not an IP) should get SNI check
        let checker = make_checker(&["proxy.example.com"], &[], &[]);
        // Trojan often uses domain names as host
        let url = "trojan://password@proxy.example.com:443?security=tls&sni=proxy.example.com";
        let raw = RawUrlX::from(url);
        let config = ProtocolConfig::try_parse(&raw).unwrap();

        let flags = checker.check_config(&config);
        assert!(
            flags & SNI_WHITELISTED != 0,
            "DNS name matching whitelist should set SNI_WHITELISTED"
        );
    }
}
