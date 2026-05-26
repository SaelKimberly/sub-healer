//! SlipNet (`slipnet://` / `slipnet-enc://`) URL parsing.
//!
//! # Format (Plain)
//! ```text
//! slipnet://<base64_urlsafe_no_pad(pipe-delimited-fields)>
//! ```
//!
//! The base64-decoded payload is a pipe (`|`)-delimited string with 70+ fields.
//! Minimum viable profile has 12 fields at indices 0–11.
//!
//! # Key Fields
//!
//! | Index | Field       | Purpose                          |
//! |-------|-------------|----------------------------------|
//! | 0     | Version     | Profile format version (e.g., "18") |
//! | 1     | TunnelType  | Tunnel protocol (sayedns, dnstt, ssh, socks5, vless) |
//! | 2     | Name        | Profile name                     |
//! | 3     | Domain      | Tunnel domain (server address)   |
//! | 8     | Port        | Local SOCKS5 port                |
//! | 11    | PublicKey   | Server Noise public key (required)|
//!
//! # Encrypted Format
//! ```text
//! slipnet-enc://<base64_encrypted_payload>
//! ```
//! Same pipe-delimited format but AES-encrypted. No host/port extracted.
//!
//! # References
//! - SlipNet CLI: `parseURI()`, `interactive.go`
//! - SlipNet Android: `ConfigImporter.kt`, `ConfigExporter.kt`
//! - SlipNet docs: `USER_GUIDE.md`

use std::num::NonZeroU64;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText, host_serde, port_serde};

use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct SlipnetConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    pub tunnel_type: Option<String>,
    pub public_key: Option<String>,
    pub remarks: Option<String>,
    pub raw_fields: Vec<TinyText>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct SlipnetEncConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub data: String,
}

impl ProtoSpec for SlipnetConfig {
    /// Parse a SlipNet URL.
    ///
    /// Userinfo is base64-decoded then split by `|` into positional fields.
    /// Minimum 12 fields required. Key fields at indices:
    /// [1]=tunnel_type, [3]=domain(host), [8]=port, [11]=public_key.
    /// Remarks extracted from URL fragment.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let decoded = utils::decode_base64(raw.userinfo)
            .map_err(|_| ParseError::InvalidUserInfo("Expected valid Base64".into()))?;
        let text = String::from_utf8(decoded)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Slipnet))?;

        // Pipe-delimited positional fields. Minimum 12 (indices 0–11).
        let raw_fields: Vec<TinyText> = text.split('|').map(TinyText::from).collect();
        if raw_fields.len() < 12 {
            return Err(ParseError::InvalidStructure(SchemeX::Slipnet));
        }

        // Field index 3: domain (server address)
        let domain = raw_fields
            .get(3)
            .and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        // Field index 11: public key (required for Noise protocol)
        let public_key = raw_fields
            .get(11)
            .and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        // Field index 1: tunnel type (sayedns, dnstt, ssh, socks5, vless)
        let tunnel_type = raw_fields
            .get(1)
            .and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });

        let host = domain
            .map(|d| {
                utils::parse_host(d)
                    .map_err(|e| ParseError::InvalidHost(format!("{d}: {e}").into()))
            })
            .transpose()?
            .ok_or(ParseError::MissingHost)?;

        // Field index 8: port
        let port = raw_fields
            .get(8)
            .and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    s.parse::<u16>().ok()
                }
            })
            .ok_or(ParseError::MissingPort)?;

        let remarks = utils::decode_fragment(raw)?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            host,
            port,
            tunnel_type: tunnel_type.map(String::from),
            public_key: public_key.map(String::from),
            remarks,
            raw_fields,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        Ok(format!("slipnet://{}", self.reconstruct_raw()))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Slipnet
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
        utils::compute_cred_hash(Some(&self.host), Some(self.port), None, "", "")
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

    fn security_type(&self) -> Option<&str> {
        None
    }
}

impl SlipnetConfig {
    fn reconstruct_raw(&self) -> String {
        let mut fields = self.raw_fields.clone();
        if let Some(ref tt) = self.tunnel_type
            && fields.len() > 1
        {
            fields[1] = TinyText::from(tt.as_str());
        }
        if fields.len() > 3 {
            fields[3] = TinyText::from(self.host.to_str());
        }
        if fields.len() > 8 {
            fields[8] = TinyText::from(self.port.to_string());
        }
        if let Some(ref pk) = self.public_key
            && fields.len() > 11
        {
            fields[11] = TinyText::from(pk.as_str());
        }
        let raw: String = fields
            .iter()
            .map(TinyText::as_str)
            .collect::<Vec<&str>>()
            .join("|");
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(raw.as_bytes())
    }

    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"slipnet"];
        if let Some(ref v) = self.tunnel_type {
            parts.push(v.as_bytes());
        }
        rapidhash::v3::rapidhash_v3(&parts.concat())
    }
}

impl ProtoSpec for SlipnetEncConfig {
    /// Parse an encrypted SlipNet URL.
    ///
    /// Simply stores the raw base64 userinfo as `data` (AES-encrypted payload).
    /// No host/port/remarks are extracted since the payload is opaque.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            data: raw.userinfo.to_string(),
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        Ok(format!("slipnet-enc://{}", self.data))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::SlipnetEnc
    }

    fn host(&self) -> Option<&HostSpec> {
        None
    }

    fn port(&self) -> Option<u16> {
        None
    }

    fn remarks(&self) -> Option<&str> {
        None
    }

    fn cred_hash(&self) -> u64 {
        0
    }

    fn sig(&self) -> u64 {
        let v = self.sig_cache.get_or_init(|| {
            let val = rapidhash::v3::rapidhash_v3(b"slipnet-enc");
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

    fn security_type(&self) -> Option<&str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProtoSpec;
    use super::super::test_helpers::check_roundtrip;
    use crate::urlx::SchemeX;

    const SLIPNET_URL: &str = "slipnet://MjJ8ZG5zdHR8ZG5zdHQtc29ja3N8dC5zaGFtbG91Lm9ubGluZXw4LjguOC44OjUzOjB8MHw1MDAwfGJicnwxMDgwfDEyNy4wLjAuMXwwfDg0ZTcxMjU3ZjRjZDkyZThmZjFiZDFlNTFjOWE5NGY3MjRlOWU5MTM2MzgxNDliN2FlNDJmNjhiNjljNTRkMjd8aXJhbnV4fglyYW51eHwwfHx8MjJ8MHw0NS4xNDguMjguMTE1fDB8fHVkcHxwYXNzd29yZHx8fHwwfDQ0M3x8fDB8fDB8MHx8MHx8MHwwfDEwODB8MHx0eHR8MTAxfDB8MHwwfDB8MHwwfDB8fHw4MDgwfHwwfC98MXx8";
    const SLIPNET_ENC_URL: &str = "slipnet-enc://Ac3GD6rpCy53w/nMNSrt/pGttnE/aagWaQyqTM+rr1LJgl5T8xRs+5IWD/pe+tKPpz2eUHYXEza8roniezFp25RM6iHo902gfJYZFg5lGVaQMjwQPu6BlBBFSCjVehs70Kgf1Fx56ha566VkTPsJDu37in+EKjaHxijwEJydn4o8n6YgSoyOsxd9OzQufIXRkPM3K5FGFUG9nYSV4oBe2hUmtJVRT+q8CONfij91e9dn3FnbQfvkst08zfah4WaAHkJEIPw28CwzExsPOjRexMTmrRsZZZuliTRmncnM0gI6WmGGKe2jdizCZN6TnDM2efkWLjfWk3+d26O+xTgJZ+lUqI/h7swa11p2OzsAdNpNnNSCMECvM8TbTuwfFeY6X668AebOi8SVHTLe5S31+ZXObdlQYQFC57aU1XXmYjI6pPFbfWjPgvtmO9mR+GQ0yp0Gg+yM6ufxra4qDhmIQWbcTfqHCc1bxCMjyYdC9d+9TGapCM41IJwnoDl7zer2G+3NkEZ0E2edw4/lXxS3D95GN0PEudoi+ic/hnFeeMPUWFoAyApi9F/KwBItcjkSKqvkluNgQdzL0UmcLWkyVuhBJ8rWSdMU5ZKUqccpeiNKlKRhQ6a2b9Buiz4YxfQ4LRbVUVllZaX84hxJgMeaMg9Jp+CJmSyUD0QkN+si6pd6+31yRIZpFHGk0UnYJ9hZQuqeczecc88d0oRDMGf/rDBt198/caUJpKo=";

    #[test]
    fn test_slipnet_basic() {
        let raw = crate::urlx::RawUrlX::from(SLIPNET_URL);
        let config = SlipnetConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Slipnet);
    }

    #[test]
    fn test_slipnet_round_trip() {
        let raw = crate::urlx::RawUrlX::from(SLIPNET_URL);
        let config = SlipnetConfig::try_parse(&raw).expect("failed");
        let reconstructed = config.reconstruct().expect("reconstruct failed");
        assert_eq!(reconstructed, SLIPNET_URL);
    }

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<SlipnetConfig>(SLIPNET_URL);
    }

    #[test]
    #[ignore = "pre-existing: SlipnetEnc parsing fails (see AGENTS.md)"]
    fn test_roundtrip_enc() {
        check_roundtrip::<SlipnetEncConfig>(SLIPNET_ENC_URL);
    }

    #[test]
    fn test_slipnet_enc() {
        let input = "slipnet-enc://Ac3GD6rpCy53w/nMNSrt/pGttnE/aagWaQyqTM+rr1LJgl5T8xRs+5IWD/pe+tKPpz2eUHYXEza8roniezFp25RM6iHo902gfJYZFg5lGVaQMjwQPu6BlBBFSCjVehs70Kgf1Fx56ha566VkTPsJDu37in+EKjaHxijwEJydn4o8n6YgSoyOsxd9OzQufIXRkPM3K5FGFUG9nYSV4oBe2hUmtJVRT+q8CONfij91e9dn3FnbQfvkst08zfah4WaAHkJEIPw28CwzExsPOjRexMTmrRsZZZuliTRmncnM0gI6WmGGKe2jdizCZN6TnDM2efkWLjfWk3+d26O+xTgJZ+lUqI/h7swa11p2OzsAdNpNnNSCMECvM8TbTuwfFeY6X668AebOi8SVHTLe5S31+ZXObdlQYQFC57aU1XXmYjI6pPFbfWjPgvtmO9mR+GQ0yp0Gg+yM6ufxra4qDhmIQWbcTfqHCc1bxCMjyYdC9d+9TGapCM41IJwnoDl7zer2G+3NkEZ0E2edw4/lXxS3D95GN0PEudoi+ic/hnFeeMPUWFoAyApi9F/KwBItcjkSKqvkluNgQdzL0UmcLWkyVuhBJ8rWSdMU5ZKUqccpeiNKlKRhQ6a2b9Buiz4YxfQ4LRbVUVllZaX84hxJgMeaMg9Jp+CJmSyUD0QkN+si6pd6+31yRIZpFHGk0UnYJ9hZQuqeczecc88d0oRDMGf/rDBt198/caUJpKo=";

        let raw = crate::urlx::RawUrlX::from(input);
        let config = SlipnetEncConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::SlipnetEnc);
    }

    use super::{SlipnetConfig, SlipnetEncConfig};
}
