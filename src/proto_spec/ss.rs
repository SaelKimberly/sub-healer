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
pub struct SsConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub method: String,
    pub password: String,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    pub remarks: Option<String>,
}

impl ProtoSpec for SsConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let (userinfo, hostport) = if let Some(hostport) = raw.hostport {
            let decoded = utils::decode_base64(raw.userinfo)
                .map_err(|e| ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into()))?;
            let text = String::from_utf8(decoded)
                .map_err(|e| ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into()))?;
            (text, hostport.to_string())
        } else {
            let decoded = utils::decode_base64(raw.userinfo)
                .map_err(|e| ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into()))?;
            let text = String::from_utf8(decoded)
                .map_err(|e| ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into()))?;
            let (ui, hp) = text.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{}: missing hostport", raw.userinfo).into())
            })?;
            (ui.to_string(), hp.to_string())
        };

        let (parsed_host, parsed_port) = utils::parse_hostport(&hostport)
            .map_err(|e| ParseError::InvalidHostPort(format!("{hostport}: {e}").into()))?;
        let parsed_port = parsed_port
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;

        let (method, password) = userinfo.split_once(':').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing password", raw.userinfo).into())
        })?;

        let remarks = utils::decode_fragment(raw)?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            method: method.to_string(),
            password: password.to_string(),
            host: parsed_host,
            port: parsed_port,
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
        let url = "ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@127.0.0.1:8080";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = SsConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::SS);
        assert_eq!(config.host.to_str(), "127.0.0.1");
        assert_eq!(config.method, "cleof");
    }

    #[test]
    fn test_reconstruct_roundtrip() {
        let input = "ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@127.0.0.1:8080";
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
        let input = "ss://Y2xlb2Y6cGFzc3dvcmRAMTwzMC4wLjE2MDo4MDgw@127.0.0.1:8080";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = SsConfig::try_parse(&raw).expect("failed");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: SsConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.host, deserialized.host);
        assert_eq!(parsed.method, deserialized.method);
    }

    use super::SsConfig;
}
