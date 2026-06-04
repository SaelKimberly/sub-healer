//! Hysteria2 (`hysteria2://` / `hy2://`) URL parsing.
//!
//! # Format
//! ```text
//! hysteria2://<auth>@<host>:<port>/?<query_params>#<remarks>
//! hy2://<auth>@<host>:<port>/?<query_params>#<remarks>
//! ```
//!
//! Canonical reference: `thirdparty/hysteria/app/cmd/client.go` `parseURI()`.
//! Both `hysteria2://` and `hy2://` schemes are accepted.
//!
//! # Fields
//!
//! | Component     | Source       | Purpose                         |
//! |---------------|--------------|---------------------------------|
//! | `auth`        | userinfo     | Authentication token/password   |
//! | `host`        | host         | Server address                  |
//! | `port`        | port         | Port (supports port hopping)    |
//! | `remarks`     | fragment (#) | Display name                    |
//!
//! # Query Parameters
//!
//! | Key            | Values                    | Purpose                          | Default   |
//! |----------------|---------------------------|----------------------------------|-----------|
//! | `security`     | tls                       | TLS mode (always QUIC-TLS)       | `"tls"`   |
//! | `obfs`         | salamander                | Obfuscation type                 | —         |
//! | `obfs-password`| string (min 4 bytes)      | Obfuscation pre-shared key       | —         |
//! | `insecure`     | 1/0, true/false           | Skip TLS verification            | `false`   |
//! | `sni`          | domain                    | TLS SNI override                 | hostname  |
//! | `pinSHA256`    | hex hash                  | Certificate pinning (SHA-256)    | —         |
//! | `up`           | bandwidth string          | Upload speed limit               | —         |
//! | `down`         | bandwidth string          | Download speed limit             | —         |
//!
//! # Port Hopping
//! Port supports special syntax from Hysteria's URL parser fork:
//! - Single: `:443`
//! - List: `:443,7788,9999`
//! - Range: `:8888-9999`
//! - Mixed: `:443,7788-8899,10010`
//!
//! # Edge Cases
//! - Auth can be single token (`auth@`) or `user:pass` pair (concatenated to `user:pass`)
//! - No auth → empty auth token (unusual, server may reject)
//! - Port defaults to 443
//! - Default port `"443"` when no port specified
//! - Salamander obfuscation uses BLAKE2b-256 with 8-byte random salt
//! - IPv6 addresses must be bracketed `[::1]`
//!
//! # References
//! - Hysteria2: `app/cmd/client.go` `parseURI()`, `app/internal/url/url.go`
//! - sing-box: `protocol/hysteria2/outbound.go`, `option/hysteria2.go`

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, PortSpec, RawUrlX, SchemeX, TinyText, host_serde, port_spec_serde};

use super::common::{SecurityConfig, TlsConfig, TlsOpts};
use super::impl_sig_cache;
use super::utils;
use super::{ParseError, ProtoSpec};

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct Hysteria2Config {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,
    #[serde(skip)]
    cred_hash_cache: std::sync::OnceLock<NonZeroU64>,

    pub auth: String,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_spec_serde")]
    pub port: PortSpec,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub obfs: Option<TinyText>,
    pub obfs_password: Option<TinyText>,
    pub up: Option<TinyText>,
    pub down: Option<TinyText>,
    pub remarks: Option<TinyText>,
}

impl ProtoSpec for Hysteria2Config {
    /// Parse a Hysteria2 URL.
    ///
    /// Auth token is the userinfo (single token or user:pass pair).
    /// Port supports Hysteria's extended `PortSpec` (ranges, lists, mixed).
    /// Security defaults to "tls" (QUIC always uses TLS).
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let (auth, hostport) = if let Some(hostport) = raw.hostport {
            (raw.userinfo, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (auth, hostport) = userinfo.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{userinfo}: missing hostport").into())
            })?;
            (auth, hostport)
        };

        let (parsed_host, parsed_port) = utils::parse_hostport(hostport)?;

        let query = utils::parse_query(raw.query);

        // obfs: obfuscation type (e.g., "salamander")
        let obfs = query.get("obfs").cloned().map(TinyText::from);
        // obfs-password: pre-shared key for salamander obfuscation
        let obfs_password = query.get("obfs-password").cloned().map(TinyText::from);
        // up/down: bandwidth limits (canonical impl doesn't parse these from URL)
        let up = query.get("up").cloned().map(TinyText::from);
        let security = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: query.get("sni").cloned().map(TinyText::from),
                alpn: None,
                fp: None,
                insecure: query.get("insecure").and_then(|v| match v.as_str() {
                    "1" | "true" | "yes" => Some(true),
                    "0" | "false" | "no" => Some(false),
                    _ => None,
                }),
            })),
            enc: None,
        };
        let down = query.get("down").cloned().map(TinyText::from);
        let remarks = utils::decode_fragment(raw)?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            cred_hash_cache: std::sync::OnceLock::new(),
            auth: auth.to_string(),
            host: parsed_host,
            port: parsed_port,
            security,
            obfs,
            obfs_password,
            up,
            down,
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
            // Security config (always Tls for Hysteria2)
            if self.security.tls.is_some() {
                if self.security.insecure() == Some(true) {
                    parts.push("insecure=1".to_string());
                }
                if let Some(v) = self.security.sni() {
                    parts.push(format!("sni={}", urlencoding::encode(v)));
                }
            }
            if let Some(ref v) = self.obfs {
                parts.push(format!("obfs={}", urlencoding::encode(v)));
            }
            if let Some(ref v) = self.obfs_password {
                parts.push(format!("obfs-password={}", urlencoding::encode(v)));
            }
            if let Some(ref v) = self.up {
                parts.push(format!("up={}", urlencoding::encode(v)));
            }
            if let Some(ref v) = self.down {
                parts.push(format!("down={}", urlencoding::encode(v)));
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
            "hysteria2://{auth}@{hostport}{query_string}{fragment}",
            auth = self.auth,
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Hysteria2
    }

    fn host(&self) -> Option<&HostSpec> {
        Some(&self.host)
    }

    fn port(&self) -> Option<u16> {
        self.port.first()
    }

    fn remarks(&self) -> Option<&str> {
        self.remarks.as_deref()
    }

    fn cred_hash(&self) -> u64 {
        let v = self.cred_hash_cache.get_or_init(|| {
            let val = utils::compute_cred_hash(
                Some(&self.host),
                None,
                Some(&self.port),
                &self.auth,
                &self.auth,
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

impl Hysteria2Config {
    fn compute_sig(&self) -> u64 {
        use rapidhash::v3::RapidStreamHasherV3;
        let mut hasher = RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);
        hasher.write(b"hysteria2");
        let sec_type = self.security.type_str().unwrap_or("none");
        hasher.write(sec_type.as_bytes());
        if let Some(ref v) = self.obfs {
            hasher.write(v.as_bytes());
        }
        if let Some(ref v) = self.obfs_password {
            hasher.write(v.as_bytes());
        }
        if let Some(v) = self.security.insecure() {
            hasher.write(if v { b"true" } else { b"false" });
        }
        if let Some(v) = self.security.sni() {
            hasher.write(v.as_bytes());
        }
        if let Some(ref v) = self.up {
            hasher.write(v.as_bytes());
        }
        if let Some(ref v) = self.down {
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
    fn test_hysteria2_basic() {
        let url = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = Hysteria2Config::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Hysteria2);
        assert_eq!(config.obfs.as_deref(), Some("salamander"));
        assert_eq!(config.security.insecure(), Some(true));
    }

    #[test]
    fn test_hy2_ipv6() {
        let url =
            "hy2://linux.do@[2a01:4f9:4b:f378::1]:13599?security=tls&insecure=1&sni=www.bing.com";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = Hysteria2Config::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Hysteria2);
        assert_eq!(config.host.to_str(), "2a01:4f9:4b:f378::1");
    }

    #[test]
    fn test_reconstruct_roundtrip() {
        let input = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = Hysteria2Config::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = Hysteria2Config::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.auth, reparsed.auth, "auth mismatch");
    }

    #[test]
    fn test_serde_roundtrip() {
        let input = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = Hysteria2Config::try_parse(&raw).expect("failed");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: Hysteria2Config = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.host, deserialized.host);
        assert_eq!(parsed.auth, deserialized.auth);
    }

    use super::super::test_helpers::check_roundtrip;
    use super::Hysteria2Config;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<Hysteria2Config>(
            "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com",
        );
    }
}
