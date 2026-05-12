mod hysteria2;
mod slipnet;
mod ss;
mod ssr;
mod tg;
mod trojan;
mod vless;
mod vmess;
mod wireguard;

use std::borrow::Cow;

use crate::Unescaper;
use crate::urlx::{HostSpec, PortSpec, RawUrlX, SchemeX, UrlX};

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
}

impl ParseError {
    pub fn unknown(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Unknown(Box::new(e))
    }
}

pub trait ProtoVisitor {
    fn parse(raw: &RawUrlX<'_>) -> Result<UrlX, ParseError>;
    fn build(url: &UrlX) -> Result<String, ParseError>;

    fn visit(url: &mut UrlX) -> Result<(), ParseError>;
}

// ========================================
// Type aliases
// ========================================
type Input<'a> = RawUrlX<'a>;

// ========================================
// Shared helpers
// ========================================
fn _parse_hostport(hostport: &str) -> Result<(HostSpec, PortSpec), ParseError> {
    let (tail, (host, port)) = crate::utils::host_port_spec(hostport.as_bytes().into())
        .map_err(|_| ParseError::InvalidHostPort(hostport.to_owned().into()))?;
    if !tail.is_empty() {
        return Err(ParseError::InvalidHostPort(
            format!("{hostport} (non-empty tail found: {})", unsafe {
                str::from_utf8_unchecked(tail.into_fragment())
            })
            .into(),
        ));
    }
    Ok((host.to_owned(), port))
}

fn _parse_base64(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let data = urlencoding::decode_binary(data.as_bytes());
    let data = data.trim_end_with(|c| c == '=' || c.is_whitespace());
    'block: {
        let e = match base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(data) {
            Ok(r) => break 'block Ok(r),
            Err(e) => e,
        };
        if let Ok(r) = base64::prelude::BASE64_STANDARD_NO_PAD.decode(data) {
            break 'block Ok(r);
        }
        // return error from url-safe version
        Err(e)
    }
}

// ========================================
// Dispatcher
// ========================================
pub(in crate::urlx) fn try_accept_raw(raw: Input<'_>) -> Result<UrlX, ParseError> {
    let result = match raw.schema {
        SchemeX::SS => ss::SsProto::parse(&raw),
        SchemeX::SSR => ssr::SsrProto::parse(&raw),
        SchemeX::Vmess => vmess::VmessProto::parse(&raw),
        SchemeX::Vless => vless::VlessProto::parse(&raw),
        SchemeX::Trojan => trojan::TrojanProto::parse(&raw),
        SchemeX::Hysteria2 => hysteria2::Hysteria2Proto::parse(&raw),
        SchemeX::Tg | SchemeX::Https => tg::TgProto::parse(&raw),

        ref _other @ (SchemeX::Slipnet | SchemeX::SlipnetEnc) => {
            tracing::debug!(target: "visit", "SlipNet - trying to parse as slipnet");
            slipnet::SlipnetProto::parse(&raw)
        }
        ref _other @ SchemeX::Hysteria => {
            tracing::debug!(target: "visit", "Hysteria not implemented, treating as Hysteria2");
            hysteria2::Hysteria2Proto::parse(&raw)
        }
        ref other => unimplemented!("{other}"),
    };

    let e = match result {
        Err(
            e @ (ParseError::InvalidStructure(_)
            | ParseError::MissingHost
            | ParseError::MissingPort
            | ParseError::InvalidUserInfo(_)
            | ParseError::Unknown(_)),
        ) => {
            tracing::warn!(target: "visit::basic", "Schema not accepted, trying fallbacks: {} ({e})", raw.schema);
            e
        }
        Err(e) => return Err(e),
        Ok(v) => return Ok(v),
    };

    let original_schema = raw.schema.clone();
    let v = 'block: {
        if let Ok(v) = ss::SsProto::parse(&raw) {
            break 'block v;
        }
        if let Ok(v) = ssr::SsrProto::parse(&raw) {
            break 'block v;
        }
        if let Ok(v) = vmess::VmessProto::parse(&raw) {
            break 'block v;
        }
        if let Ok(v) = vless::VlessProto::parse(&raw) {
            break 'block v;
        }
        if let Ok(v) = trojan::TrojanProto::parse(&raw) {
            break 'block v;
        }
        if let Ok(v) = hysteria2::Hysteria2Proto::parse(&raw) {
            break 'block v;
        }
        if let Ok(v) = slipnet::SlipnetProto::parse(&raw) {
            break 'block v;
        }
        if let Ok(v) = tg::TgProto::parse(&raw) {
            break 'block v;
        }

        return Err(e);
    };
    tracing::warn!(target: "visit::basic", "Schema fallback success: [{} => {}]", original_schema, v.schema);
    Ok(v)
}

use base64::Engine;
use bstr::ByteSlice;
// ========================================
// Re-exports
// ========================================
pub use hysteria2::Hysteria2Proto;
pub use slipnet::SlipnetProto;
pub use ss::SsProto;
pub use ssr::SsrProto;
pub use tg::TgProto;
pub use trojan::TrojanProto;
pub use vless::VlessProto;
pub use vmess::VmessProto;
pub use wireguard::WireguardProto;
