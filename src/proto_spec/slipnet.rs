use std::num::NonZeroU64;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::urlx::{
    host_serde, port_serde, HostSpec, RawUrlX, SchemeX,
};

use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SlipnetEncConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub data: String,
}

impl ProtoSpec for SlipnetConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let decoded = utils::decode_base64(raw.userinfo)
            .map_err(|_| ParseError::InvalidUserInfo("Expected valid Base64".into()))?;
        let text = String::from_utf8(decoded)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Slipnet))?;

        let fields: Vec<&str> = text.split('|').collect();
        if fields.len() < 12 {
            return Err(ParseError::InvalidStructure(SchemeX::Slipnet));
        }

        let domain = fields.get(3).copied().filter(|s| !s.is_empty());
        let public_key = fields.get(11).copied().filter(|s| !s.is_empty());
        let tunnel_type = fields.get(1).copied().filter(|s| !s.is_empty());

        let host = domain
            .map(|d| {
                utils::parse_host(d)
                    .map_err(|e| ParseError::InvalidHost(format!("{d}: {e}").into()))
            })
            .transpose()?
            .ok_or(ParseError::MissingHost)?;

        let port = fields
            .get(8)
            .copied()
            .ok_or(ParseError::MissingPort)
            .and_then(|s| {
                s.parse::<u16>()
                    .map_err(|_| ParseError::InvalidPort(s.to_string().into()))
            })?;

        let remarks = utils::decode_fragment(raw)?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            host: host,
            port,
            tunnel_type: tunnel_type.map(String::from),
            public_key: public_key.map(String::from),
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let encoded = self
            .reconstruct_raw()
            .map_err(|e| ParseError::Unknown(e.into()))?;
        Ok(format!("slipnet://{encoded}"))
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
}

impl SlipnetConfig {
    fn reconstruct_raw(&self) -> Result<String, base64::DecodeError> {
        let raw = format!(
            "22|{}|{}|{}|8.8.8.8:53:0|0|5000|bbr|{}|127.0.0.1|0|{}|iranux\tranux|0|||22|0|45.148.28.115|0||udp|password||||0|443|||0||0|0||0||0|0||0|1080|0|txt|101|0|0|0|0|0|0|||8080||0|/|1||",
            self.tunnel_type.as_deref().unwrap_or("dnstt"),
            self.tunnel_type.as_deref().unwrap_or("dnstt-socks"),
            self.host.to_str(),
            self.port,
            self.public_key.as_deref().unwrap_or("0"),
        );
        Ok(base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(raw.as_bytes()))
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
}

#[cfg(test)]
mod tests {
    use super::super::ProtoSpec;
    use crate::urlx::SchemeX;

    const SLIPNET_URL: &str = "slipnet://MjJ8ZG5zdHR8ZG5zdHQtc29ja3N8dC5zaGFtbG91Lm9ubGluZXw4LjguOC44OjUzOjB8MHw1MDAwfGJicnwxMDgwfDEyNy4wLjAuMXwwfDg0ZTcxMjU3ZjRjZDkyZThmZjFiZDFlNTFjOWE5NGY3MjRlOWU5MTM2MzgxNDliN2FlNDJmNjhiNjljNTRkMjd8aXJhbnV4fglyYW51eHwwfHx8MjJ8MHw0NS4xNDguMjguMTE1fDB8fHVkcHxwYXNzd29yZHx8fHwwfDQ0M3x8fDB8fDB8MHx8MHx8MHwwfDEwODB8MHx0eHR8MTAxfDB8MHwwfDB8MHwwfDB8fHw4MDgwfHwwfC98MXx8";

    #[test]
    fn test_slipnet_basic() {
        let raw = crate::urlx::RawUrlX::from(SLIPNET_URL);
        let config = SlipnetConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Slipnet);
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
