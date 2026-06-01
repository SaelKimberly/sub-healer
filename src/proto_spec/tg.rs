//! Telegram MTProto (`tg://` / `https://t.me/`) proxy URL parsing.
//!
//! # Formats
//! ```text
//! https://t.me/proxy?server=<host>&port=<port>&secret=<secret>   (MTProto)
//! https://t.me/socks?server=<host>&port=<port>[&user=<u>&pass=<p>] (SOCKS5)
//! tg://proxy?server=<host>&port=<port>&secret=<secret>
//! tg://socks?server=<host>&port=<port>[&user=<u>&pass=<p>]
//! ```
//!
//! The primary format uses `https://t.me/proxy` with the Telegram web link
//! format. `tg://` scheme is the shorter alternative.
//!
//! # Fields
//!
//! | Parameter | Source       | Purpose                          | Required |
//! |-----------|--------------|----------------------------------|----------|
//! | `server`  | query param  | Proxy server address             | Yes      |
//! | `port`    | query param  | Proxy server port                | Yes      |
//! | `secret`  | query param  | Obfuscation secret (hex/base64)  | Yes*     |
//! | `user`    | query param  | SOCKS5 username                  | No       |
//! | `pass`    | query param  | SOCKS5 password                  | No       |
//!
//! *secret is required for MTProto proxy, optional for SOCKS5.
//!
//! # Secret Format
//! The secret encodes a 16-byte key with optional type prefix and domain:
//! ```text
//! [type_byte][16_bytes_secret][optional_domain]
//! ```
//! - `0xee` = Fake TLS (creates fake TLS handshake, domain used for SNI)
//! - `0xdd` = Random Padding
//! - `0x00` = Simple (no obfuscation)
//!
//! # References
//! - v2ray-core: `proxy/mtproto/config.proto`
//! - subconverter: `nodemanip.cpp` telegram detection

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText, host_serde, port_serde};

use super::common::SecurityConfig;
use super::utils;
use super::impl_sig_cache;
use super::{ParseError, ProtoSpec};

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct TgConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    #[serde(skip)]
    cred_hash_cache: std::sync::OnceLock<NonZeroU64>,

    #[serde(rename = "server", with = "host_serde")]
    pub host: HostSpec,
    #[serde(rename = "port", with = "port_serde")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub secret: String,
    pub transport: TinyText,
    pub remarks: Option<TinyText>,
}

impl ProtoSpec for TgConfig {
    /// Parse a Telegram proxy URL.
    ///
    /// Accepts two URL patterns:
    /// - `https://t.me/proxy` or `https://t.me/socks` (Telegram web links)
    /// - `tg://proxy` or `tg://socks` (short scheme)
    ///
    /// Detects transport type (MTProto proxy vs SOCKS5) from the URL path/userinfo.
    /// Server address is validated via `rustls::pki_types::ServerName`.
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
            cred_hash_cache: std::sync::OnceLock::new(),
            host,
            port,
            security: SecurityConfig::default(),
            secret,
            transport: if is_socks {
                "socks".into()
            } else {
                "mtproto".into()
            },
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let userinfo = if self.transport == "socks" {
            "socks"
        } else {
            "proxy"
        };

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
        let v = self.cred_hash_cache.get_or_init(|| {
            let val = utils::compute_cred_hash(
                Some(&self.host),
                Some(self.port),
                None,
                &self.secret,
                &self.secret,
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
        Some(self.transport.as_str())
    }

}

impl TgConfig {
    fn compute_sig(&self) -> u64 {
        use rapidhash::v3::RapidStreamHasherV3;
        let mut hasher = RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);
        hasher.write(b"tg");
        hasher.write(self.transport.as_bytes());
        hasher.finish()
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

        assert!(
            reconstructed.contains("server="),
            "should contain server param"
        );
        assert!(reconstructed.contains("port="), "should contain port param");
        assert!(
            reconstructed.contains("secret="),
            "should contain secret param"
        );
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

    use super::super::test_helpers::check_roundtrip;
    use super::TgConfig;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<TgConfig>(
            "https://t.me/proxy?server=146.185.211.126&port=443&secret=ee1e36377253a29133d290f3d14ae0163873756e342d32302e757365726170692e636f6d",
        );
    }
}
