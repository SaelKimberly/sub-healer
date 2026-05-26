use std::borrow::Cow;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX};

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
    fn host(&self) -> Option<&HostSpec>;
    fn port(&self) -> Option<u16>;
    fn remarks(&self) -> Option<&str>;
    fn cred_hash(&self) -> u64;
    fn sig(&self) -> u64;
    fn set_sig_cache(&self, v: std::num::NonZeroU64);
    fn uid(&self) -> u64 {
        self.sig() ^ self.cred_hash()
    }
    fn transport_type(&self) -> Option<&str>;
    fn security_type(&self) -> Option<&str>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
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

macro_rules! dispatch {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            ProtocolConfig::Vless(c) => c.$method($($arg),*),
            ProtocolConfig::Vmess(c) => c.$method($($arg),*),
            ProtocolConfig::Trojan(c) => c.$method($($arg),*),
            ProtocolConfig::Hysteria2(c) => c.$method($($arg),*),
            ProtocolConfig::Ss(c) => c.$method($($arg),*),
            ProtocolConfig::Ssr(c) => c.$method($($arg),*),
            ProtocolConfig::Tg(c) => c.$method($($arg),*),
            ProtocolConfig::Slipnet(c) => c.$method($($arg),*),
            ProtocolConfig::SlipnetEnc(c) => c.$method($($arg),*),
            ProtocolConfig::Stormdns(c) => c.$method($($arg),*),
            ProtocolConfig::Tuic(c) => c.$method($($arg),*),
            ProtocolConfig::Wireguard(c) => c.$method($($arg),*),
        }
    };
}

impl ProtoSpec for ProtocolConfig {
    fn reconstruct(&self) -> Result<String, ParseError> { dispatch!(self, reconstruct) }
    fn schema(&self) -> SchemeX { dispatch!(self, schema) }
    fn host(&self) -> Option<&HostSpec> { dispatch!(self, host) }
    fn port(&self) -> Option<u16> { dispatch!(self, port) }
    fn remarks(&self) -> Option<&str> { dispatch!(self, remarks) }
    fn cred_hash(&self) -> u64 { dispatch!(self, cred_hash) }
    fn sig(&self) -> u64 { dispatch!(self, sig) }
    fn set_sig_cache(&self, v: std::num::NonZeroU64) { dispatch!(self, set_sig_cache, v) }
    fn transport_type(&self) -> Option<&str> { dispatch!(self, transport_type) }
    fn security_type(&self) -> Option<&str> { dispatch!(self, security_type) }

    /// # Errors
    ///
    /// If the URL is not a valid proxy URL for any supported protocol.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let r = match raw.schema {
            SchemeX::Vless => VlessConfig::try_parse(raw).map(Self::Vless),
            SchemeX::Trojan => TrojanConfig::try_parse(raw).map(Self::Trojan),
            SchemeX::Vmess => VmessConfig::try_parse(raw).map(Self::Vmess),
            SchemeX::Hysteria | SchemeX::Hysteria2 => {
                Hysteria2Config::try_parse(raw).map(Self::Hysteria2)
            }
            SchemeX::SS => SsConfig::try_parse(raw).map(Self::Ss),
            SchemeX::SSR => SsrConfig::try_parse(raw).map(Self::Ssr),
            SchemeX::Slipnet => SlipnetConfig::try_parse(raw).map(Self::Slipnet),
            SchemeX::SlipnetEnc => SlipnetEncConfig::try_parse(raw).map(Self::SlipnetEnc),
            SchemeX::Stormdns => StormdnsConfig::try_parse(raw).map(Self::Stormdns),
            SchemeX::TUIC => TuicConfig::try_parse(raw).map(Self::Tuic),
            SchemeX::WireGuard => WireguardConfig::try_parse(raw).map(Self::Wireguard),
            SchemeX::Https if raw.userinfo == "t.me" => TgConfig::try_parse(raw).map(Self::Tg),
            SchemeX::Tg => TgConfig::try_parse(raw).map(Self::Tg),
            SchemeX::Https => return Err(ParseError::PromotionUrl),
            ref other => return Err(ParseError::UnsupportedScheme(other.clone())),
        };

        let original_err = match r {
            Ok(r) => return Ok(r),
            Err(
                e @ (ParseError::InvalidStructure(_)
                | ParseError::MissingHost
                | ParseError::MissingPort
                | ParseError::InvalidUserInfo(_)
                | ParseError::InvalidHostPort(_)
                | ParseError::InvalidHost(_)
                | ParseError::Unknown(_)),
            ) => e,
            unrecoverable @ Err(_) => return unrecoverable,
        };

        let original_schema = raw.schema.clone();
        let v = SsConfig::try_parse(raw)
            .map(Self::Ss)
            .or_else(|_| SsrConfig::try_parse(raw).map(Self::Ssr))
            .or_else(|_| VmessConfig::try_parse(raw).map(Self::Vmess))
            .or_else(|_| VlessConfig::try_parse(raw).map(Self::Vless))
            .or_else(|_| TrojanConfig::try_parse(raw).map(Self::Trojan))
            .or_else(|_| Hysteria2Config::try_parse(raw).map(Self::Hysteria2))
            .or_else(|_| SlipnetConfig::try_parse(raw).map(Self::Slipnet))
            .or_else(|_| TgConfig::try_parse(raw).map(Self::Tg))
            .or(Err(original_err))?;

        tracing::warn!(target: "visit::basic", "Schema fallback success: [{} => {}]", original_schema, v.schema());
        Ok(v)
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::urlx::RawUrlX;
    use super::ProtoSpec;

    pub fn check_roundtrip<T>(url: &str)
    where
        T: ProtoSpec + std::fmt::Debug + PartialEq,
    {
        let raw = RawUrlX::from(url);
        let parsed = T::try_parse(&raw).unwrap_or_else(|e| panic!("parse failed for {url}: {e}"));
        parsed.sig();
        let reconstructed = parsed.reconstruct().unwrap_or_else(|e| panic!("reconstruct failed for {url}: {e}"));
        let re_raw = RawUrlX::from(reconstructed.as_str());
        let reparsed = T::try_parse(&re_raw).unwrap_or_else(|e| panic!("reparse failed for {reconstructed}: {e}"));
        reparsed.sig();
        assert_eq!(parsed, reparsed, "roundtrip failed for: {url}");
    }
}