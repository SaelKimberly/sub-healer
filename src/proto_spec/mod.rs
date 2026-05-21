use std::borrow::Cow;
use std::num::NonZeroU64;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::urlx::{RawUrlX, SchemeX};

pub mod common;
pub mod utils;

mod hysteria2;
mod slipnet;
mod ss;
mod ssr;
mod stormdns;
mod tg;
mod trojan;
mod tuic;
mod vless;
mod vmess;
mod wireguard;

pub use hysteria2::Hysteria2Config;
pub use slipnet::{SlipnetConfig, SlipnetEncConfig};
pub use ss::SsConfig;
pub use ssr::SsrConfig;
pub use stormdns::StormdnsConfig;
pub use tg::TgConfig;
pub use trojan::TrojanConfig;
pub use tuic::TuicConfig;
pub use vless::VlessConfig;
pub use vmess::VmessConfig;
pub use wireguard::WireguardConfig;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid host: {0}")]
    InvalidHost(Cow<'static, str>),
    #[error("invalid port: {0}")]
    InvalidPort(Cow<'static, str>),
    #[error("missing host")]
    MissingHost,
    #[error("missing port")]
    MissingPort,
    #[error("invalid userinfo: {0}")]
    InvalidUserInfo(Cow<'static, str>),
    #[error("invalid hostport: {0}")]
    InvalidHostPort(Cow<'static, str>),
    #[error("missing conf: {0}")]
    MissingConf(Cow<'static, str>),
    #[error("invalid conf: {0}: {1}")]
    InvalidConf(Cow<'static, str>, Cow<'static, str>),
    #[error("unknown error: {0}")]
    Unknown(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("invalid structure for {0}")]
    InvalidStructure(SchemeX),
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(SchemeX),
    #[error("not a proxy config URL (promotion or navigation link)")]
    PromotionUrl,
}

pub trait ProtoSpec: Serialize + DeserializeOwned + std::fmt::Debug + Clone {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError>;
    /// # Errors
    ///
    /// If internal configuration is invalid.
    fn reconstruct(&self) -> Result<String, ParseError>;
    fn schema(&self) -> SchemeX;
    fn host(&self) -> Option<&str>;
    fn port(&self) -> Option<&str>;
    fn remarks(&self) -> Option<&str>;
    fn cred_hash(&self) -> u64;
    fn sig(&self) -> u64;
    fn set_sig_cache(&self, v: std::num::NonZeroU64);
    fn uid(&self) -> u64 {
        self.sig() ^ self.cred_hash()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "schema")]
pub enum ProtocolConfig {
    Vless(VlessConfig),
    Vmess(VmessConfig),
    Trojan(TrojanConfig),
    Hysteria2(Hysteria2Config),
    Ss(SsConfig),
    Ssr(SsrConfig),
    Tg(TgConfig),
    Slipnet(SlipnetConfig),
    SlipnetEnc(SlipnetEncConfig),
    Stormdns(StormdnsConfig),
    Tuic(TuicConfig),
    Wireguard(WireguardConfig),
}

impl ProtoSpec for ProtocolConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let e = match raw.schema {
            SchemeX::Vless => match VlessConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Vless(v)),
                Err(e) => e,
            },
            SchemeX::Trojan => match TrojanConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Trojan(v)),
                Err(e) => e,
            },
            SchemeX::Vmess => match VmessConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Vmess(v)),
                Err(e) => e,
            },
            SchemeX::Hysteria | SchemeX::Hysteria2 => match Hysteria2Config::try_parse(raw) {
                Ok(v) => return Ok(Self::Hysteria2(v)),
                Err(e) => e,
            },
            SchemeX::SS => match SsConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Ss(v)),
                Err(e) => e,
            },
            SchemeX::SSR => match SsrConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Ssr(v)),
                Err(e) => e,
            },
            SchemeX::Slipnet => match SlipnetConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Slipnet(v)),
                Err(e) => e,
            },
            SchemeX::SlipnetEnc => match SlipnetEncConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::SlipnetEnc(v)),
                Err(e) => e,
            },
            SchemeX::Stormdns => match StormdnsConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Stormdns(v)),
                Err(e) => e,
            },
            SchemeX::TUIC => match TuicConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Tuic(v)),
                Err(e) => e,
            },
            SchemeX::WireGuard => match WireguardConfig::try_parse(raw) {
                Ok(v) => return Ok(Self::Wireguard(v)),
                Err(e) => e,
            },
            SchemeX::Tg | SchemeX::Https => {
                if raw.schema == SchemeX::Https && raw.userinfo != "t.me" {
                    return Err(ParseError::PromotionUrl);
                }
                match TgConfig::try_parse(raw) {
                    Ok(v) => return Ok(Self::Tg(v)),
                    Err(e) => e,
                }
            }
            ref other => return Err(ParseError::UnsupportedScheme(other.clone())),
        };

        let should_try_fallback = matches!(
            e,
            ParseError::InvalidStructure(_)
                | ParseError::MissingHost
                | ParseError::MissingPort
                | ParseError::InvalidUserInfo(_)
                | ParseError::InvalidHostPort(_)
                | ParseError::InvalidHost(_)
                | ParseError::Unknown(_)
        );
        if !should_try_fallback {
            return Err(e);
        }

        let original_schema = raw.schema.clone();
        let v = SsConfig::try_parse(raw)
            .map(ProtocolConfig::Ss)
            .or_else(|_| SsrConfig::try_parse(raw).map(ProtocolConfig::Ssr))
            .or_else(|_| VmessConfig::try_parse(raw).map(ProtocolConfig::Vmess))
            .or_else(|_| VlessConfig::try_parse(raw).map(ProtocolConfig::Vless))
            .or_else(|_| TrojanConfig::try_parse(raw).map(ProtocolConfig::Trojan))
            .or_else(|_| Hysteria2Config::try_parse(raw).map(ProtocolConfig::Hysteria2))
            .or_else(|_| SlipnetConfig::try_parse(raw).map(ProtocolConfig::Slipnet))
            .or_else(|_| TgConfig::try_parse(raw).map(ProtocolConfig::Tg))
            .or(Err(e))?;

        tracing::warn!(target: "visit::basic", "Schema fallback success: [{} => {}]", original_schema, v.schema());
        Ok(v)
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        match self {
            Self::Vless(c) => c.reconstruct(),
            Self::Vmess(c) => c.reconstruct(),
            Self::Trojan(c) => c.reconstruct(),
            Self::Hysteria2(c) => c.reconstruct(),
            Self::Ss(c) => c.reconstruct(),
            Self::Ssr(c) => c.reconstruct(),
            Self::Tg(c) => c.reconstruct(),
            Self::Slipnet(c) => c.reconstruct(),
            Self::SlipnetEnc(c) => c.reconstruct(),
            Self::Stormdns(c) => c.reconstruct(),
            Self::Tuic(c) => c.reconstruct(),
            Self::Wireguard(c) => c.reconstruct(),
        }
    }

    fn schema(&self) -> SchemeX {
        match self {
            Self::Vless(c) => c.schema(),
            Self::Vmess(c) => c.schema(),
            Self::Trojan(c) => c.schema(),
            Self::Hysteria2(c) => c.schema(),
            Self::Ss(c) => c.schema(),
            Self::Ssr(c) => c.schema(),
            Self::Tg(c) => c.schema(),
            Self::Slipnet(c) => c.schema(),
            Self::SlipnetEnc(c) => c.schema(),
            Self::Stormdns(c) => c.schema(),
            Self::Tuic(c) => c.schema(),
            Self::Wireguard(c) => c.schema(),
        }
    }

    fn host(&self) -> Option<&str> {
        match self {
            Self::Vless(c) => c.host(),
            Self::Vmess(c) => c.host(),
            Self::Trojan(c) => c.host(),
            Self::Hysteria2(c) => c.host(),
            Self::Ss(c) => c.host(),
            Self::Ssr(c) => c.host(),
            Self::Tg(c) => Some(c.server.as_str()),
            Self::Slipnet(c) => c.host(),
            Self::SlipnetEnc(_) => None,
            Self::Stormdns(c) => c.host(),
            Self::Tuic(c) => c.host(),
            Self::Wireguard(c) => c.host(),
        }
    }

    fn port(&self) -> Option<&str> {
        match self {
            Self::Vless(c) => c.port(),
            Self::Vmess(c) => c.port(),
            Self::Trojan(c) => c.port(),
            Self::Hysteria2(c) => c.port(),
            Self::Ss(c) => c.port(),
            Self::Ssr(c) => c.port(),
            Self::Tg(c) => Some(&c.port),
            Self::Slipnet(c) => c.port(),
            Self::SlipnetEnc(_) => None,
            Self::Stormdns(c) => c.port(),
            Self::Tuic(c) => c.port(),
            Self::Wireguard(c) => c.port(),
        }
    }

    fn remarks(&self) -> Option<&str> {
        match self {
            Self::Vless(c) => c.remarks(),
            Self::Vmess(c) => c.remarks(),
            Self::Trojan(c) => c.remarks(),
            Self::Hysteria2(c) => c.remarks(),
            Self::Ss(c) => c.remarks(),
            Self::Ssr(c) => c.remarks(),
            Self::Tg(c) => c.remarks.as_deref(),
            Self::Slipnet(c) => c.remarks(),
            Self::SlipnetEnc(_) => None,
            Self::Stormdns(c) => c.name.as_deref(),
            Self::Tuic(c) => c.remarks(),
            Self::Wireguard(c) => c.remarks(),
        }
    }

    fn cred_hash(&self) -> u64 {
        match self {
            Self::Vless(c) => c.cred_hash(),
            Self::Vmess(c) => c.cred_hash(),
            Self::Trojan(c) => c.cred_hash(),
            Self::Hysteria2(c) => c.cred_hash(),
            Self::Ss(c) => c.cred_hash(),
            Self::Ssr(c) => c.cred_hash(),
            Self::Tg(c) => c.cred_hash(),
            Self::Slipnet(c) => c.cred_hash(),
            Self::SlipnetEnc(c) => c.cred_hash(),
            Self::Stormdns(c) => c.cred_hash(),
            Self::Tuic(c) => c.cred_hash(),
            Self::Wireguard(c) => c.cred_hash(),
        }
    }

    fn sig(&self) -> u64 {
        match self {
            Self::Vless(c) => c.sig(),
            Self::Vmess(c) => c.sig(),
            Self::Trojan(c) => c.sig(),
            Self::Hysteria2(c) => c.sig(),
            Self::Ss(c) => c.sig(),
            Self::Ssr(c) => c.sig(),
            Self::Tg(c) => c.sig(),
            Self::Slipnet(c) => c.sig(),
            Self::SlipnetEnc(c) => c.sig(),
            Self::Stormdns(c) => c.sig(),
            Self::Tuic(c) => c.sig(),
            Self::Wireguard(c) => c.sig(),
        }
    }

    fn set_sig_cache(&self, v: NonZeroU64) {
        match self {
            Self::Vless(c) => c.set_sig_cache(v),
            Self::Vmess(c) => c.set_sig_cache(v),
            Self::Trojan(c) => c.set_sig_cache(v),
            Self::Hysteria2(c) => c.set_sig_cache(v),
            Self::Ss(c) => c.set_sig_cache(v),
            Self::Ssr(c) => c.set_sig_cache(v),
            Self::Tg(c) => c.set_sig_cache(v),
            Self::Slipnet(c) => c.set_sig_cache(v),
            Self::SlipnetEnc(c) => c.set_sig_cache(v),
            Self::Stormdns(c) => c.set_sig_cache(v),
            Self::Tuic(c) => c.set_sig_cache(v),
            Self::Wireguard(c) => c.set_sig_cache(v),
        }
    }
}
