//! ShadowsocksR (`ssr://`) URL parsing.
//!
//! # Format
//! ```text
//! ssr://<base64url(host:port:protocol:method:obfs:base64(password)/?params)>
//! ```
//!
//! The entire body after `ssr://` is a single base64-encoded payload with
//! 6 colon-separated fields plus optional `/`-delimited query parameters.
//!
//! # Fields
//!
//! | Position | Field      | Purpose                         | Examples                        |
//! |----------|------------|---------------------------------|---------------------------------|
//! | 1        | `host`     | Server address                  | `example.com`                   |
//! | 2        | `port`     | Server port                     | `443`                           |
//! | 3        | `protocol` | Protocol plugin                 | `origin`, `auth_aes128_md5`     |
//! | 4        | `method`   | Encryption cipher               | `rc4-md5`, `aes-256-cfb`        |
//! | 5        | `obfs`     | Obfuscation plugin              | `plain`, `http_simple`          |
//! | 6        | `password` | Base64-encoded shared secret    | `base64(password)`              |
//!
//! # Query Parameters (after `/?`)
//!
//! | Key        | Encoding | Purpose                         |
//! |------------|----------|---------------------------------|
//! | `group`    | base64   | Provider/group name             |
//! | `remarks`  | base64   | Node name (display)             |
//! | `obfsparam`| base64   | Obfuscation parameter (e.g., host) |
//! | `protoparam`| base64  | Protocol parameter              |
//!
//! # Edge Cases
//! - Port is last-5th colon-delimited field (handles IPv6 with multiple colons)
//! - Password may contain `/?` or `?` split for query params
//! - Trailing non-base64 garbage (Telegram annotation) is stripped before decode
//! - `remarks` extracted from query params (base64-decoded, URL-safe alphabet)
//!
//! # References
//! - subconverter: `subparser.cpp` `explodeSSR()`, `subexport.cpp`
//! - sing-box: `option/shadowsocksr.go`

use std::num::NonZeroU64;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText, host_serde, port_serde};

use super::common::SecurityConfig;
use super::impl_sig_cache;
use super::utils;
use super::{ParseError, ProtoSpec};

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct SsrConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,
    #[serde(skip)]
    cred_hash_cache: std::sync::OnceLock<NonZeroU64>,

    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub protocol: TinyText,
    pub method: TinyText,
    pub obfs: TinyText,
    pub password: String,
    pub params: std::collections::HashMap<String, String>,
    pub remarks: Option<TinyText>,
}

impl ProtoSpec for SsrConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let clean_userinfo = clean_ssr_userinfo(raw.userinfo);
        let decoded = utils::decode_base64(clean_userinfo)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::SSR))?;
        let text =
            String::from_utf8(decoded).map_err(|_| ParseError::InvalidStructure(SchemeX::SSR))?;

        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() < 6 {
            return Err(ParseError::InvalidStructure(SchemeX::SSR));
        }

        // Index from end: last 5 are port, protocol, method, obfs, password.
        // Everything before is the host (handles IPv6 with colons).
        let raw_host = parts[..parts.len() - 5].join(":");
        let raw_port = parts[parts.len() - 5];
        let protocol = TinyText::from(parts[parts.len() - 4]);
        let method = TinyText::from(parts[parts.len() - 3]);
        let obfs = TinyText::from(parts[parts.len() - 2]);
        let raw_password = parts[parts.len() - 1..].join(":");

        let (password, query_part) = raw_password
            .split_once("/?")
            .or_else(|| raw_password.split_once('?'))
            .unwrap_or((&raw_password, ""));

        let mut params = std::collections::HashMap::new();
        params.insert("protocol".into(), protocol.to_string());
        params.insert("obfs".into(), obfs.to_string());

        if !query_part.is_empty() {
            for pair in query_part.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    params.insert(k.to_string(), v.to_string());
                }
            }
        }

        let remarks = params.remove("remarks").map(|r| {
            base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(r.trim_end_matches('='))
                .ok()
                .and_then(|d| {
                    simdutf8::basic::from_utf8(d.as_ref())
                        .map(TinyText::from)
                        .ok()
                })
                .unwrap_or_else(|| TinyText::from(r.as_str()))
        });

        let parsed_host = utils::parse_host(&raw_host)?;
        let parsed_port: u16 = raw_port
            .parse()
            .map_err(|_| ParseError::InvalidPort(raw_port.to_string().into()))?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            cred_hash_cache: std::sync::OnceLock::new(),
            host: parsed_host,
            port: parsed_port,
            security: SecurityConfig::default(),
            protocol,
            method,
            obfs,
            password: password.to_string(),
            params,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        use base64::Engine as _;

        let mut query_str = String::new();
        let mut sorted_params: Vec<_> = self.params.iter().collect();
        sorted_params.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in &sorted_params {
            let k_str = k.as_str();
            // protocol and obfs are already in the colon-delimited fields above
            if k_str == "protocol" || k_str == "obfs" {
                continue;
            }
            if !query_str.is_empty() {
                query_str.push('&');
            }
            query_str.push_str(format!("{k}={v}").as_str());
        }
        // Add remarks back to the query string (base64-encoded, URL-safe no-pad)
        if let Some(remarks) = &self.remarks {
            if !query_str.is_empty() {
                query_str.push('&');
            }
            query_str.push_str("remarks=");
            query_str.push_str(&base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(remarks.as_bytes()));
        }

        let raw = format!(
            "{host}:{port}:{proto}:{method}:{obfs}:{password}/?{query_str}",
            host = self.host.to_str(),
            port = self.port,
            proto = self.protocol,
            method = self.method,
            obfs = self.obfs,
            password = self.password,
            query_str = query_str,
        );
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(raw.as_bytes());
        Ok(format!("ssr://{encoded}"))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::SSR
    }

    fn host(&self) -> Option<&HostSpec> {
        Some(&self.host)
    }

    fn port(&self) -> Option<u16> {
        Some(self.port)
    }

    fn remarks(&self) -> Option<&str> {
        self.remarks.as_deref()
    }

    fn cred_hash(&self) -> u64 {
        let v = self.cred_hash_cache.get_or_init(|| {
            let val = utils::compute_cred_hash(
                Some(&self.host),
                Some(self.port),
                None,
                &self.method,
                &self.password,
            );
            NonZeroU64::new(val).unwrap_or(NonZeroU64::MIN)
        });
        v.get()
    }

    fn set_cred_hash_cache(&self, v: NonZeroU64) {
        _ = self.cred_hash_cache.set(v);
    }

    impl_sig_cache!();

    fn transport_type(&self) -> Option<&str> {
        None
    }
}

/// Strip trailing non-base64 garbage (Telegram annotation text and decorative
/// hyphens) from the SSR userinfo before base64 decoding.
///
/// Strategy:
/// 1. If the base64 has `=` padding, everything after the last `=` that is
///    hyphens followed by non-ASCII is stripped.
/// 2. For no-pad base64, find the first occurrence of 3+ consecutive decorative
///    `-` or `_` that is followed by non-ASCII and truncate there.
/// 3. If neither heuristic triggers, return the string unchanged.
fn clean_ssr_userinfo(s: &str) -> &str {
    // Try padded-base64 heuristic first
    if let Some(last_eq) = s.rfind('=') {
        let after = &s[last_eq + 1..];
        match after.trim_start_matches(['-', '_']).as_bytes().first() {
            None => return &s[..=last_eq],
            Some(n) if !n.is_ascii() => return &s[..=last_eq],
            _ => (),
        }
    }

    // For NO_PAD base64: find 3+ consecutive '-' or '_' that are followed
    // by non-ASCII (Telegram annotation text). 3+ consecutive hyphens are
    // virtually never valid URL-safe base64 data.
    let bytes = s.as_bytes();
    let mut hyphen_run: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'-' || b == b'_' {
            hyphen_run += 1;
        } else {
            if hyphen_run >= 3 && (i >= bytes.len() || !bytes[i].is_ascii()) {
                return &s[..i - hyphen_run as usize];
            }
            hyphen_run = 0;
        }
    }
    // Handle case where the run extends to the end
    if hyphen_run >= 3 {
        return &s[..s.len() - hyphen_run as usize];
    }

    s
}

impl SsrConfig {
    fn compute_sig(&self) -> u64 {
        use rapidhash::v3::RapidStreamHasherV3;
        let mut hasher = RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);
        hasher.write(b"ssr");
        let mut sorted_keys: Vec<&String> = self.params.keys().collect();
        sorted_keys.sort();
        for k in &sorted_keys {
            if k.as_str() == "remarks" {
                continue;
            }
            hasher.write(k.as_bytes());
            if let Some(v) = self.params.get(*k) {
                hasher.write(v.as_bytes());
            }
        }
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProtoSpec;
    use super::super::test_helpers::check_roundtrip;
    use crate::urlx::SchemeX;

    const SSR_URL: &str = "ssr://ZXhhbXBsZS5jb206NDQzOm9yaWdpbjpyYzQtbWQ1OnBsYWluOmNHRnpjM2R2Y21RLz9ncm91cD1WR1Z6ZEVkeWIzVncmcmVtYXJrcz1WR1Z6ZEZObGNuWmxjZw";

    #[test]
    fn test_ssr_basic() {
        let raw = crate::urlx::RawUrlX::from(SSR_URL);
        let config = SsrConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::SSR);
        assert_eq!(config.method, "rc4-md5");
        assert_eq!(config.host.to_str(), "example.com");
        assert_eq!(config.remarks.as_deref(), Some("TestServer"));
    }

    #[test]
    fn test_reconstruct_roundtrip() {
        let raw = crate::urlx::RawUrlX::from(SSR_URL);
        let parsed = SsrConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        assert!(
            reconstructed.starts_with("ssr://"),
            "should start with ssr://"
        );

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = SsrConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_ssr_trailing_text() {
        // Valid base64 with trailing Chinese annotation text (Telegram pattern)
        let url = "ssr://MTE2LjE2Mi4xMjAuMjY6NTYxOmF1dGhfYWVzMTI4X21kNTpjaGFjaGEyMC1pZXRmOnBsYWluOmJXSnNZVzVyTVhCdmNuUT0vP2dyb3VwPWFIUjBjSE02THk5Mk1uSmhlWE5sTG1OdmJRPT0mcHJvdG9wYXJhbT1OVEUzTmpBNlRFeE1NRGt3ZFdrNGIyeHNPQT0=必进：【全网导航】》下载地址：";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = SsrConfig::try_parse(&raw).expect("failed to parse url with trailing text");
        assert_eq!(config.host.to_str(), "116.162.120.26");
        assert_eq!(config.port, 561_u16);
        assert_eq!(config.protocol, "auth_aes128_md5");
        assert_eq!(config.method, "chacha20-ietf");
        assert_eq!(config.obfs, "plain");
    }

    #[test]
    fn test_ssr_no_query() {
        // Valid SSR URL with no /? query params and a # fragment
        let url = "ssr://MTMuMzcuMjguMjM6NTk0NzpvcmlnaW46Y2hhY2hhMjAtaWV0ZjpwbGFpbjpOVGswTnc#@dark_telecom";
        let raw = crate::urlx::RawUrlX::from(url);
        let config =
            SsrConfig::try_parse(&raw).expect("failed to parse url with hash and no query");
        assert_eq!(config.host.to_str(), "13.37.28.23");
        assert_eq!(config.port, 5947_u16);
        assert_eq!(config.protocol, "origin");
        assert_eq!(config.method, "chacha20-ietf");
        assert_eq!(config.obfs, "plain");
    }

    #[test]
    fn test_ssr_garbage_returns_err() {
        // Chinese text only — not a valid SSR URL
        let url = "ssr://的格式";
        let raw = crate::urlx::RawUrlX::from(url);
        assert!(SsrConfig::try_parse(&raw).is_err());
    }

    #[test]
    fn test_ssr_remarks_decoded() {
        // URL with base64-encoded remarks in query params
        let url = "ssr://MTIzLjQ1LjY3Ljg5OjEwMDA6b3JpZ2luOnBsYWluOnBsYWluOmRHVnpkRjl3WVhOei8_cmVtYXJrcz1jM055WDNSbGMzUT0";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = SsrConfig::try_parse(&raw).expect("failed to parse");
        assert_eq!(config.remarks.as_deref(), Some("ssr_test"));
    }

    use super::SsrConfig;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<SsrConfig>(SSR_URL);
    }
}
