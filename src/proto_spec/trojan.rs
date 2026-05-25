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

use crate::urlx::{
    host_serde, port_serde, HostSpec, RawUrlX, SchemeX,
};

use super::common::TransportConfig;
use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct TrojanConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub password: String,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    pub security: String,
    pub transport: TransportConfig,
    pub path: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub fp: Option<String>,
    pub remarks: Option<String>,
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

        let (parsed_host, parsed_port) = utils::parse_hostport(hostport)
            .map_err(|e| ParseError::InvalidHostPort(format!("{hostport}: {e}").into()))?;
        let parsed_port = parsed_port
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;

        let query = utils::parse_query(raw.query);

        // Security mode: tls (default), none, or reality
        let security = query
            .get("security")
            .map_or("tls", |s| s.as_str())
            .to_string();
        // Transport type: tcp (default), ws, grpc, http, quic, kcp
        let transport_type = query
            .get("type")
            .map_or("tcp", |s| s.as_str())
            .to_string();
        let path = query.get("path").cloned();
        // SNI fallback order: peer → sni → URL hostname (outbound/dialer compat)
        let sni = query.get("sni").cloned();
        let alpn = query.get("alpn").cloned();
        let fp = query.get("fp").cloned();

        let remarks = utils::decode_fragment(raw)?;

        let transport =
            TransportConfig::from_type_and_path(Some(&transport_type), path.as_deref())
                .ok_or_else(|| {
                    ParseError::InvalidConf("type".into(), transport_type.into())
                })?;

        let path = match transport {
            TransportConfig::Ws(ref ws) => ws.path.clone(),
            TransportConfig::Grpc(ref g) => g.path.clone(),
            TransportConfig::Http(ref h) => h.path.clone(),
            _ => path,
        };

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            password: username.to_string(),
            host: parsed_host,
            port: parsed_port,
            transport,
            security,
            path,
            sni,
            alpn,
            fp,
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
            if self.security != "tls" {
                parts.push(format!("security={}", self.security));
            }
            if self.transport.type_str() != "tcp" {
                parts.push(format!("type={}", self.transport.type_str()));
            }
            if let Some(ref path) = self.path {
                parts.push(format!("path={}", urlencoding::encode(path)));
            }
            if let Some(ref v) = self.sni {
                parts.push(format!("sni={}", urlencoding::encode(v)));
            }
            if let Some(ref v) = self.alpn {
                parts.push(format!("alpn={}", urlencoding::encode(v)));
            }
            if let Some(ref v) = self.fp {
                parts.push(format!("fp={}", urlencoding::encode(v)));
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
        utils::compute_cred_hash(
            Some(&self.host),
            Some(self.port),
            None,
            &self.password,
            &self.password,
        )
    }

    fn sig(&self) -> u64 {
        let v = self
            .sig_cache
            .get_or_init(|| {
                let val = self.compute_sig();
                NonZeroU64::new(val).unwrap_or(NonZeroU64::MIN)
            });
        v.get()
    }

    fn set_sig_cache(&self, v: NonZeroU64) {
        _ = self.sig_cache.set(v);
    }

    fn transport_type(&self) -> Option<&str> {
        Some(self.transport.type_str())
    }

    fn security_type(&self) -> Option<&str> {
        Some(self.security.as_str())
    }
}

impl TrojanConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"trojan"];
        parts.push(self.security.as_bytes());
        parts.push(self.transport.type_str().as_bytes());
        if let Some(ref path) = self.path {
            parts.push(path.as_bytes());
        }
        if let Some(ref v) = self.sni {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.alpn {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.fp {
            parts.push(v.as_bytes());
        }
        rapidhash::v3::rapidhash_v3(&parts.concat())
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
        assert_eq!(config.host().map(|h| h.to_str()), Some("172.64.152.23".into()));
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
        check_roundtrip::<TrojanConfig>("trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org");
    }
}
