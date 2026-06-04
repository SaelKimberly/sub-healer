//! TUIC (`tuic://`) URL parsing.
//!
//! # Format
//! ```text
//! tuic://<uuid>:<password>@<host>:<port>?<query_params>#<remarks>
//! ```
//!
//! Standard URI format. UUID and password in userinfo separated by colon.
//! Configuration in query parameters, remarks in fragment.
//!
//! # Query Parameters
//!
//! | Key                  | Values                       | Purpose                          | Default   |
//! |----------------------|------------------------------|----------------------------------|-----------|
//! | `congestion_control` | cubic, bbr, new_reno, bbr3  | QUIC congestion control          | `"bbr"`   |
//! | `udp_relay_mode`     | native, quic                 | UDP relay transport              | `"native"`|
//! | `alpn`               | comma-separated (h3,h2)      | TLS ALPN negotiation             | `"h3"`    |
//! | `sni`                | domain                       | TLS SNI override                 | hostname  |
//! | `allow_insecure`     | 1/0                          | Skip TLS cert verification       | `"0"`     |
//!
//! # Edge Cases
//! - `allow_insecure` accepts 3 aliases: `allow_insecure`, `allowInsecure`, `insecure`
//! - ALPN is comma-separated and URL-decoded
//! - Default congestion control is `bbr` (from tuic-client/src/config.rs)
//! - Default ALPN is `h3`
//! - IPv6 addresses must be bracketed
//! - UUID validated via `uuid::Uuid::parse_str`
//!
//! # References
//! - TUIC: `tuic-client/src/config.rs`, `tuic-core/src/utils.rs`
//! - v2rayN: `TuicFmt.cs`, `BaseFmt.cs`
//! - sing-box: `option/tuic.go`

use std::{fmt::Write, num::NonZeroU64};

use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText, host_serde, port_serde};

use super::common::{SecurityConfig, TlsConfig, TlsOpts};
use super::impl_sig_cache;
use super::utils;
use super::{ParseError, ProtoSpec};

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct TuicConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    #[serde(skip)]
    cred_hash_cache: std::sync::OnceLock<NonZeroU64>,

    pub uuid: String,
    pub password: String,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    pub congestion_control: Option<TinyText>,
    pub udp_relay_mode: Option<TinyText>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl ProtoSpec for TuicConfig {
    /// Parse a TUIC URL.
    ///
    /// Userinfo is `uuid:password` (colon-separated). UUID validated via
    /// `uuid::Uuid::parse_str`. Server address and port from hostport.
    /// `allow_insecure` accepts 3 alias variants for compatibility.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let (userinfo, hostport) = if let Some(hostport) = raw.hostport {
            (raw.userinfo, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (ui, hp) = userinfo.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{userinfo}: missing hostport").into())
            })?;
            (ui, hp)
        };

        let (uuid, password) = userinfo.split_once(':').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{userinfo}: expected uuid:password").into())
        })?;

        uuid::Uuid::parse_str(uuid)
            .map_err(|_| ParseError::InvalidUserInfo(format!("invalid UUID: {uuid}").into()))?;

        let (parsed_host, parsed_port) = utils::parse_hostport(hostport)?;
        let parsed_port = parsed_port
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;

        let query = utils::parse_query(raw.query);

        // congestion_control: cubic/bbr/new_reno/bbr3. Defaults to bbr.
        let congestion_control = query.get("congestion_control").cloned().map(TinyText::from);
        // udp_relay_mode: native/quic. Defaults to native.
        let udp_relay_mode = query.get("udp_relay_mode").cloned().map(TinyText::from);
        let security = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: query.get("sni").cloned().map(TinyText::from),
                alpn: query.get("alpn").cloned().map(TinyText::from),
                fp: None,
                insecure: query
                    .get("allow_insecure")
                    .or_else(|| query.get("insecure"))
                    .or_else(|| query.get("allowInsecure"))
                    .and_then(|v| match v.as_str() {
                        "1" | "true" => Some(true),
                        "0" | "false" => Some(false),
                        _ => None,
                    }),
            })),
            enc: None,
        };
        let remarks = utils::decode_fragment(raw)?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            cred_hash_cache: std::sync::OnceLock::new(),
            uuid: uuid.to_string(),
            password: password.to_string(),
            host: parsed_host,
            port: parsed_port,
            congestion_control,
            udp_relay_mode,
            security,
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

        let mut base = format!("tuic://{}:{}@{}", self.uuid, self.password, hostport);

        let query_string = {
            let mut parts: Vec<String> = Vec::new();
            if let Some(ref v) = self.congestion_control {
                parts.push(format!("congestion_control={}", urlencoding::encode(v)));
            }
            if let Some(ref v) = self.udp_relay_mode {
                parts.push(format!("udp_relay_mode={}", urlencoding::encode(v)));
            }
            // Security config (TUIC always uses TLS)
            if let Some(v) = self.security.alpn() {
                parts.push(format!("alpn={}", urlencoding::encode(v)));
            }
            if let Some(v) = self.security.insecure() {
                parts.push(format!("allow_insecure={}", if v { "1" } else { "0" }));
            }
            if let Some(v) = self.security.sni() {
                parts.push(format!("sni={}", urlencoding::encode(v)));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!("?{}", parts.join("&"))
            }
        };
        base.push_str(&query_string);

        if let Some(ref remarks) = self.remarks {
            let frag = crate::Unescaper::default()
                .enc_pct()
                .enc_uni(true)
                .chardet(true, true)
                .do_unescape(remarks.as_bytes())
                .unwrap();
            let frag = frag.trim();
            if !frag.is_empty() {
                _ = write!(base, "#{}", urlencoding::encode(frag));
            }
        }

        Ok(base)
    }

    fn schema(&self) -> SchemeX {
        SchemeX::TUIC
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
                &self.uuid,
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

    fn security(&self) -> Option<&SecurityConfig> {
        Some(&self.security)
    }
}

impl TuicConfig {
    fn compute_sig(&self) -> u64 {
        use rapidhash::v3::RapidStreamHasherV3;
        let mut hasher = RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);
        hasher.write(b"tuic");
        if let Some(ref v) = self.congestion_control {
            hasher.write(v.as_bytes());
        }
        if let Some(ref v) = self.udp_relay_mode {
            hasher.write(v.as_bytes());
        }
        if let Some(v) = self.security.alpn() {
            hasher.write(v.as_bytes());
        }
        if let Some(v) = self.security.insecure() {
            hasher.write(if v { b"true" } else { b"false" });
        }
        if let Some(v) = self.security.sni() {
            hasher.write(v.as_bytes());
        }
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ProtoSpec, ProtocolConfig};
    use crate::urlx::SchemeX;

    #[test]
    fn test_tuic_basic() {
        let url = "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = TuicConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::TUIC);
        assert_eq!(
            config.host().map(|h| h.to_str()),
            Some("5.178.101.117".into())
        );
        assert_eq!(config.port(), Some(30006_u16));
        assert_eq!(config.uuid, "36106e0f-4d9a-470b-a3fd-535f3b7a1e92");
        assert_eq!(config.password, "dongtaiwang.com");
        assert_eq!(config.congestion_control.as_deref(), Some("cubic"));
        assert_eq!(config.udp_relay_mode.as_deref(), Some("native"));
        assert_eq!(config.security.alpn(), Some("h3"));
    }

    #[test]
    fn test_tuic_allow_insecure() {
        let url = "tuic://9bbd1f42-7ae7-4239-bd10-a68de95e3295:dongtaiwang.com@ip1.758733.xyz:10088?allow_insecure=0&alpn=h3&congestion_control=bbr&sni=apple.com";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = TuicConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::TUIC);
        assert_eq!(
            config.host().map(|h| h.to_str()),
            Some("ip1.758733.xyz".into())
        );
        assert_eq!(config.security.insecure(), Some(false));
        assert_eq!(config.security.sni(), Some("apple.com"));
        assert_eq!(config.congestion_control.as_deref(), Some("bbr"));
    }

    #[test]
    fn test_tuic_with_remark() {
        let url = "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3#DE";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = TuicConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.remarks(), Some("DE"));
    }

    #[test]
    fn test_tuic_via_protocol_config() {
        let url = "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3#DE";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = ProtocolConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::TUIC);
        assert_eq!(
            config.host().map(|h| h.to_str()),
            Some("5.178.101.117".into())
        );
    }

    #[test]
    fn test_reconstruct_tuic_roundtrip() {
        let input = "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = TuicConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = TuicConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.uuid, reparsed.uuid, "uuid mismatch");
        assert_eq!(parsed.password, reparsed.password, "password mismatch");
        assert_eq!(
            parsed.congestion_control, reparsed.congestion_control,
            "congestion_control mismatch"
        );
    }

    #[test]
    fn test_tuic_serde_roundtrip() {
        let input = "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = TuicConfig::try_parse(&raw).expect("failed to parse");

        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: TuicConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.host, deserialized.host, "host mismatch");
        assert_eq!(parsed.port, deserialized.port, "port mismatch");
        assert_eq!(parsed.uuid, deserialized.uuid, "uuid mismatch");
        assert_eq!(parsed.password, deserialized.password, "password mismatch");
    }

    use super::super::test_helpers::check_roundtrip;
    use super::TuicConfig;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<TuicConfig>(
            "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3",
        );
    }
}
