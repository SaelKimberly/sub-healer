use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{
    host_serde, port_serde, HostSpec, RawUrlX, SchemeX,
};

use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TgConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    #[serde(rename = "server", with = "host_serde")]
    pub host: HostSpec,
    #[serde(rename = "port", with = "port_serde")]
    pub port: u16,
    pub secret: String,
    pub transport: String,
    pub remarks: Option<String>,
}

impl ProtoSpec for TgConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let is_socks = if raw.schema == SchemeX::Https && raw.userinfo == "t.me" {
            match raw.path {
                Some("/socks") => true,
                Some("/proxy") => false,
                _ => return Err(ParseError::InvalidStructure(SchemeX::Tg)),
            }
        } else if raw.schema == SchemeX::Tg {
            match raw.userinfo {
                "socks" => true,
                "proxy" => false,
                _ => return Err(ParseError::InvalidStructure(SchemeX::Tg)),
            }
        } else {
            return Err(ParseError::InvalidStructure(raw.schema.clone()));
        };

        let query = raw
            .query()
            .map_err(|e| ParseError::InvalidConf("query".into(), e.to_string().into()))?;

        let server_raw = query
            .iter()
            .find_map(|(k, v)| if k == "server" { v.as_ref() } else { None })
            .ok_or(ParseError::MissingHost)?;
        let host: HostSpec = rustls::pki_types::ServerName::try_from(server_raw.as_str())
            .map_err(|e| ParseError::InvalidHost(format!("{server_raw}: {e}").into()))?
            .to_owned();

        let port = query
            .iter()
            .find_map(|(k, v)| if k == "port" { v.as_ref() } else { None })
            .ok_or(ParseError::MissingPort)?
            .parse::<u16>()
            .map_err(|e| ParseError::InvalidPort(format!("cannot parse port: {e}").into()))?;

        let secret = query
            .iter()
            .find_map(|(k, v)| if k == "secret" { v.as_ref() } else { None })
            .ok_or_else(|| ParseError::MissingConf("secret".into()))?
            .to_string();

        let remarks = utils::decode_fragment(raw)?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            host,
            port,
            secret,
            transport: if is_socks { "socks".into() } else { "mtproto".into() },
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let userinfo = if self.transport == "socks" { "socks" } else { "proxy" };

        let tg_url = url::Url::parse(
            format!(
                "tg://{userinfo}?server={server}&port={port}&secret={secret}",
                server = self.host.to_str(),
                port = self.port,
                secret = self.secret,
            )
            .as_str(),
        )
        .map_err(|e| ParseError::Unknown(e.into()))?;

        Ok(tg_url.to_string())
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Tg
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
        utils::compute_cred_hash(Some(&self.host), Some(self.port), None, &self.secret, &self.secret)
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

impl TgConfig {
    fn compute_sig(&self) -> u64 {
        let parts = [b"tg" as &[u8], self.transport.as_bytes()];
        rapidhash::v3::rapidhash_v3(&parts.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProtoSpec;
    use crate::urlx::SchemeX;

    #[test]
    fn test_tg_basic() {
        let url = "https://t.me/proxy?server=146.185.211.126&port=443&secret=ee1e36377253a29133d290f3d14ae0163873756e342d32302e757365726170692e636f6d";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = TgConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Tg);
        assert_eq!(config.host.to_str(), "146.185.211.126");
    }

    #[test]
    fn test_tg_hostname() {
        let url = "https://t.me/proxy?server=proxium.rest&port=888&secret=a669r5a45920422f9d417e4867efdc4fb8jllllloo9w88220wpwoow9";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = TgConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Tg);
        assert_eq!(config.host.to_str(), "proxium.rest");
    }

    #[test]
    fn test_reconstruct_roundtrip() {
        let input = "https://t.me/proxy?server=146.185.211.126&port=443&secret=ee1e36377253a29133d290f3d14ae0163873756e342d32302e757365726170692e636f6d";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = TgConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        assert!(reconstructed.contains("server="), "should contain server param");
        assert!(reconstructed.contains("port="), "should contain port param");
        assert!(reconstructed.contains("secret="), "should contain secret param");
    }

    #[test]
    fn test_serde_roundtrip() {
        let input = "https://t.me/proxy?server=146.185.211.126&port=443&secret=ee1e36377253a29133d290f3d14ae0163873756e342d32302e757365726170692e636f6d";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = TgConfig::try_parse(&raw).expect("failed");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: TgConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.host, deserialized.host);
        assert_eq!(parsed.port, deserialized.port);
    }

    use super::TgConfig;
}
