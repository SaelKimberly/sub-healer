//! Shadowsocks (`ss://`) URL parsing.
//!
//! # Format (SIP002 — Modern Standard)
//! ```text
//! ss://<base64url_no_pad(method:password)>@<host>:<port>#<remarks>?plugin=...
//! ```
//!
//! # Legacy QRCode Format (also accepted)
//! ```text
//! ss://<base64(method:password@host:port)>
//! ```
//! Detected by presence/absence of `@` in the base64-decoded userinfo.
//!
//! # Plain Format (go-shadowsocks2 compatibility)
//! ```text
//! ss://<method>:<password>@<host>:<port>
//! ```
//!
//! # Fields
//!
//! | Component     | Source              | Purpose                         |
//! |---------------|----------------------|---------------------------------|
//! | `method`      | userinfo (method:password) | Encryption cipher         |
//! | `password`    | userinfo (method:password) | Shared secret             |
//! | `host`        | hostport             | Server address                  |
//! | `port`        | hostport             | Server port                     |
//! | `remarks`     | fragment (#)         | Display name (URL-decoded)      |
//! | `plugin`      | query `plugin`       | SIP003 plugin (e.g., obfs-local)|
//!
//! # Valid Ciphers
//! - Legacy: `rc4-md5`, `aes-256-cfb`, `chacha20`, `salsa20`, etc.
//! - AEAD: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`
//! - AEAD-2022: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`
//!
//! # Edge Cases
//! - Base64 can be URL-safe (`-`/`_`) or standard (`+`/`/`), with/without padding
//! - Legacy format: whole `method:password@host:port` base64-encoded (no `@` in URL)
//! - AEAD-2022 passwords are already base64, not double-encoded
//! - Port defaults to 8388 if missing (shadowsocks-rust convention)
//! - IPv6 addresses must be bracketed
//!
//! # References
//! - shadowsocks-rust: `src/config.rs` SIP002 `from_url()`/`to_url()`
//! - SIP002 spec: <https://github.com/shadowsocks/shadowsocks-org/issues/27>
//! - subconverter: `subparser.cpp` `explodeSS()`
//! - go-shadowsocks2: `parseURL()` (plain format)

use std::num::NonZeroU64;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText, host_serde, port_serde};

use super::common::SecurityConfig;
use super::utils;
use super::{ParseError, ProtoSpec};

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct SsConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub method: TinyText,
    pub password: String,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl ProtoSpec for SsConfig {
    /// Parse a Shadowsocks URL.
    ///
    /// Supports three formats:
    /// 1. SIP002: `base64url(method:password)@host:port` (has `@`, hostport present)
    /// 2. Legacy QR: `base64(method:password@host:port)` (no `@` in URL, hostport absent)
    /// 3. Plain: `method:password@host:port` (base64 decode fails but `@` present)
    ///
    /// `decode_base64` tolerates trailing annotation text/emoji (Telegram pattern)
    /// and accepts both URL-safe and standard base64 alphabets.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let (userinfo, hostport) = if let Some(hostport) = raw.hostport {
            // SIP002 format: base64(method:password)@host:port
            let decoded = utils::decode_base64(raw.userinfo).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            let text = String::from_utf8(decoded).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            (text, hostport.to_string())
        } else {
            // Legacy QR format: base64(method:password@host:port) — no @ in URL
            let decoded = utils::decode_base64(raw.userinfo).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            let text = String::from_utf8(decoded).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            let (ui, hp) = text.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{}: missing hostport", raw.userinfo).into())
            })?;
            (ui.to_string(), hp.to_string())
        };

        let (parsed_host, parsed_port) = utils::parse_hostport(&hostport)?;
        let parsed_port = parsed_port
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;

        // Split at first ':' to get method:password
        let (method, password) = userinfo.split_once(':').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing password", raw.userinfo).into())
        })?;

        let remarks = utils::decode_fragment(raw)?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            method: TinyText::from(method),
            password: password.to_string(),
            host: parsed_host,
            port: parsed_port,
            security: SecurityConfig::default(),
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let userinfo = format!("{}:{}", self.method, self.password);
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(userinfo.as_bytes());
        let host = self.host.to_str();
        let hostport = if host.contains(':') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        };
        Ok(format!("ss://{encoded}@{hostport}"))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::SS
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
            &self.method,
            &self.password,
        )
    }

    fn sig(&self) -> u64 {
        let v = self.sig_cache.get_or_init(|| {
            let val = self.compute_sig();
            NonZeroU64::new(val).unwrap_or(NonZeroU64::MIN)
        });
        v.get()
    }

    fn set_sig_cache(&self, v: NonZeroU64) {
        _ = self.sig_cache.set(v);
    }

    fn transport_type(&self) -> Option<&str> {
        None
    }

}

impl SsConfig {
    fn compute_sig(&self) -> u64 {
        let parts = [b"ss" as &[u8], self.method.as_bytes()];
        rapidhash::v3::rapidhash_v3(&parts.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProtoSpec;
    use crate::urlx::SchemeX;

    #[test]
    fn test_ss_basic() {
        let url = "ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@1.2.3.4:8080";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = SsConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::SS);
        assert_eq!(config.host.to_str(), "1.2.3.4");
        assert_eq!(config.method, "cleof");
    }

    #[test]
    fn test_reconstruct_roundtrip() {
        let input = "ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@1.2.3.4:8080";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = SsConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = SsConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.method, reparsed.method, "method mismatch");
    }

    #[test]
    fn test_serde_roundtrip() {
        let input = "ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@1.2.3.4:8080";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = SsConfig::try_parse(&raw).expect("failed");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: SsConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.host, deserialized.host);
        assert_eq!(parsed.method, deserialized.method);
    }

    use super::super::test_helpers::check_roundtrip;
    use super::SsConfig;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<SsConfig>("ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@1.2.3.4:8080");
    }
}
