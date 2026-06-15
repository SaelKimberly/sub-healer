//! Trojan (`trojan://`) URL parsing.
//!
//! # Format
//! ```text
//! trojan://<password>@<host>:<port>?<query_params>#<remarks>
//! ```
//!
//! Standard URI format. Password in userinfo, query params for transport
//! and TLS configuration, fragment for remarks.
//!
//! # Query Parameters
//!
//! | Key       | Values                                    | Purpose                     | Default   |
//! |-----------|--------------------------------------------|-----------------------------|-----------|
//! | `security`| tls, none, reality                          | TLS/security mode           | `"tls"`   |
//! | `type`    | tcp, ws, grpc, http, kcp, quic             | Transport type              | `"tcp"`   |
//! | `path`    | URL path                                   | WS path / gRPC serviceName  | —         |
//! | `sni`     | domain                                     | TLS SNI (folllowed by host) | hostname  |
//! | `alpn`    | comma-separated (h2,http/1.1)              | ALPN list                   | —         |
//! | `fp`      | chrome, firefox, safari, randomized        | uTLS fingerprint            | —         |
//! | `allowInsecure` | 1/0, true/false                    | Skip TLS cert verification  | `"0"`     |
//! | `encryption` | ss;method;password                       | Trojan-Go SS layer          | —         |
//!
//! # Edge Cases
//! - Security defaults to **`"tls"`** (not `"none"` — unlike VLESS)
//! - `allowInsecure` accepts 4 aliases: `allowInsecure`, `allow_insecure`,
//!   `allowinsecure`, `skipVerify` (outbound/dialer compat)
//! - `sni` fallback: `peer` query param → `sni` → URL hostname
//! - Legacy format: `ws=1` + `wspath=` instead of `type=ws` + `path=`
//! - Wire protocol uses SHA-224(password) → 56-byte hex for auth
//!
//! # References
//! - trojan-gfw C++: `src/core/config.h`
//! - outbound: `dialer/trojan/trojan.go`
//! - Xray-core: `proxy/trojan/protocol.go`
//! - sing-box: `option/trojan.go`
//! - subconverter: `subparser.cpp` `explodeTrojan()`

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText, host_serde, port_serde};

use super::common::{
    RealityOpts, SecurityConfig, TlsConfig, TlsOpts, TransportConfig, should_skip_param,
};
use super::impl_sig_cache;
use super::utils;
use super::{ParseError, ProtoSpec};

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct TrojanConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,
    #[serde(skip)]
    cred_hash_cache: std::sync::OnceLock<NonZeroU64>,

    pub password: String,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub transport: TransportConfig,
    pub path: Option<TinyText>,
    pub remarks: Option<TinyText>,
}

impl ProtoSpec for TrojanConfig {
    /// Parse a Trojan URL.
    ///
    /// Trojan uses standard URI: password in userinfo, server in host:port,
    /// config in query params, remarks in fragment.
    /// Security defaults to "tls" (Trojan always uses TLS by default).
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let (username, hostport) = if let Some(hostport) = raw.hostport {
            (raw.userinfo, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (username, hostport) = userinfo.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{userinfo}: missing hostport").into())
            })?;
            (username, hostport)
        };

        let (parsed_host, parsed_port) = utils::parse_hostport(hostport)?;
        let parsed_port = parsed_port
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;

        let query = utils::parse_query(raw.query);

        // Security mode: tls (default), none, or reality
        let security = match utils::query_get(&query, "security") {
            Some("tls") | None => SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts {
                    sni: utils::query_get(&query, "sni").map(TinyText::from),
                    alpn: utils::query_get(&query, "alpn").map(TinyText::from),
                    fp: utils::query_get(&query, "fp").map(TinyText::from),
                    insecure: None,
                })),
                enc: None,
            },
            Some("reality") => SecurityConfig {
                tls: Some(TlsConfig::Reality(RealityOpts {
                    sni: utils::query_get(&query, "sni").map(TinyText::from),
                    fp: utils::query_get(&query, "fp").map(TinyText::from),
                    pbk: utils::query_get(&query, "pbk").map(str::to_string),
                    sid: utils::query_get(&query, "sid").map(TinyText::from),
                    spx: utils::query_get(&query, "spx").map(TinyText::from),
                })),
                enc: None,
            },
            _ => SecurityConfig::default(),
        };
        // Transport type: tcp (default), ws, grpc, http, quic, kcp
        let transport_type = utils::query_get(&query, "type").unwrap_or("tcp").to_string();
        let path = utils::query_get(&query, "path").map(TinyText::from);

        let remarks = utils::decode_fragment(raw)?;

        let host = utils::query_get(&query, "host").map(str::to_string);
        let server_addr = Some(parsed_host.to_str().into_owned());

        let mut transport =
            TransportConfig::from_type_and_path(Some(&transport_type), path.as_deref())?
                .unwrap_or(TransportConfig::Tcp);
        transport = transport.with_host(host, utils::query_get(&query, "sni").map(str::to_string), server_addr);


        let path = match transport {
            TransportConfig::Ws(ref ws) => ws.path.clone(),
            TransportConfig::Grpc(ref g) => g.path.clone(),
            TransportConfig::Http(ref h) => h.path.clone(),
            TransportConfig::HttpUpgrade(ref cfg) => cfg.path.clone(),
            TransportConfig::XHttp(ref cfg) => cfg.path.clone(),
            _ => path,
        };

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            cred_hash_cache: std::sync::OnceLock::new(),
            password: username.to_string(),
            host: parsed_host,
            port: parsed_port,
            transport,
            security,
            path,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let host = self.host.to_str();
        let hostport = if host.contains(':') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        };

        let query_string = {
            let mut parts: Vec<String> = Vec::new();
            // Security config. TLS is the default — only emit when reality or sni/alpn/fp set.
            if let Some(ref tls_config) = self.security.tls {
                match tls_config {
                    TlsConfig::Tls(opts) => {
                        if opts.sni.is_some() || opts.alpn.is_some() || opts.fp.is_some() {
                            parts.push("security=tls".to_string());
                        }
                        if let Some(ref v) = opts.sni
                            && !should_skip_param(&self.host, v) {
                                parts.push(format!("sni={}", urlencoding::encode(v)));
                            }
                        if let Some(ref v) = opts.alpn {
                            parts.push(format!("alpn={}", urlencoding::encode(v)));
                        }
                        if let Some(ref v) = opts.fp {
                            parts.push(format!("fp={}", urlencoding::encode(v)));
                        }
                    }
                    TlsConfig::Reality(opts) => {
                        parts.push("security=reality".to_string());
                        if let Some(ref v) = opts.sni
                            && !should_skip_param(&self.host, v) {
                                parts.push(format!("sni={}", urlencoding::encode(v)));
                            }
                        if let Some(ref v) = opts.fp {
                            parts.push(format!("fp={}", urlencoding::encode(v)));
                        }
                        if let Some(ref v) = opts.pbk {
                            parts.push(format!("pbk={}", urlencoding::encode(v)));
                        }
                        if let Some(ref v) = opts.sid {
                            parts.push(format!("sid={}", urlencoding::encode(v)));
                        }
                    }
                }
            }
            if self.transport.type_str() != "tcp" {
                parts.push(format!("type={}", self.transport.type_str()));
            }
            match &self.transport {
                TransportConfig::HttpUpgrade(cfg) => {
                    if let Some(ref host) = cfg.host
                        && !should_skip_param(&self.host, host) {
                            parts.push(format!("host={}", urlencoding::encode(host)));
                        }
                }
                TransportConfig::XHttp(cfg) => {
                    if let Some(ref host) = cfg.host
                        && !should_skip_param(&self.host, host) {
                            parts.push(format!("host={}", urlencoding::encode(host)));
                        }
                }
                _ => {}
            }
            if let Some(ref path) = self.path {
                parts.push(format!("path={}", urlencoding::encode(path)));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!("?{}", parts.join("&"))
            }
        };

        let fragment = self
            .remarks
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();

        Ok(format!(
            "trojan://{password}@{hostport}{query_string}{fragment}",
            password = self.password,
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Trojan
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
                &self.password,
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
        Some(self.transport.type_str())
    }

    fn security(&self) -> Option<&SecurityConfig> {
        Some(&self.security)
    }
}

impl TrojanConfig {
    fn compute_sig(&self) -> u64 {
        use rapidhash::v3::RapidStreamHasherV3;
        let mut hasher = RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);
        hasher.write(b"trojan");
        let sec_type = self.security.type_str().unwrap_or("none");
        hasher.write(sec_type.as_bytes());
        hasher.write(self.transport.type_str().as_bytes());
        match &self.transport {
            TransportConfig::HttpUpgrade(cfg) => {
                if let Some(ref v) = cfg.host {
                    hasher.write(v.as_bytes());
                }
            }
            TransportConfig::XHttp(cfg) => {
                if let Some(ref v) = cfg.host {
                    hasher.write(v.as_bytes());
                }
            }
            _ => {}
        }
        if let Some(ref path) = self.path {
            hasher.write(path.as_bytes());
        }
        if let Some(v) = self.security.sni() {
            hasher.write(v.as_bytes());
        }
        if let Some(v) = self.security.alpn() {
            hasher.write(v.as_bytes());
        }
        if let Some(v) = self.security.fp() {
            hasher.write(v.as_bytes());
        }
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProtoSpec;
    use crate::urlx::SchemeX;

    #[test]
    fn test_trojan_basic() {
        let url = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = TrojanConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Trojan);
        assert_eq!(
            config.host().map(|h| h.to_str()),
            Some("172.64.152.23".into())
        );
        assert_eq!(config.password, "humanity");
    }

    #[test]
    fn test_reconstruct_trojan_roundtrip() {
        let input = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = TrojanConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = TrojanConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.password, reparsed.password, "password mismatch");
    }

    #[test]
    fn test_trojan_serde_roundtrip() {
        let input = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = TrojanConfig::try_parse(&raw).expect("failed to parse");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: TrojanConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.host, deserialized.host, "host mismatch");
        assert_eq!(parsed.port, deserialized.port, "port mismatch");
        assert_eq!(parsed.password, deserialized.password, "password mismatch");
    }

    use super::super::test_helpers::check_roundtrip;
    use super::TrojanConfig;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<TrojanConfig>(
            "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org",
        );
    }
}
