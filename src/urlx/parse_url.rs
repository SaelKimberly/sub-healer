use std::{borrow::Cow, str::FromStr};

use base64::Engine;
use bstr::ByteSlice;

use super::{HostSpec, PortSpec, RawUrlX, SchemeX, TinyText, UrlX};

///
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
}

impl ParseError {
    pub fn unknown(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Unknown(Box::new(e))
    }
}

type Input<'a> = RawUrlX<'a>;
type Output = Result<Option<UrlX>, ParseError>;

// ==================================================
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

fn _parse_vmess(raw: &mut Input) -> Output {
    todo!()
}
fn _parse_ss(raw: &mut Input) -> Output {
    let (userinfo, hostport) = if let Some(hostport) = raw.hostport {
        // * Scenario 1: raw url, as is (separate userinfo and hostport):
        // * ss://[userinfo]@[hostport]#[fragment]
        // ? ========================================
        (raw.userinfo, hostport)
    } else {
        // * Scenario 2: raw url, with decoded userinfo (no hostport):
        // * ss://[userinfo(decoded)]#fragment
        // ? ========================================
        raw.userinfo.split_once('@').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing hostport", raw.userinfo).into())
        })?
    };
    let (host, port) = _parse_hostport(hostport)?;
    let (method, password): (TinyText, TinyText) =
        if let Some((method, password)) = userinfo.split_once(':') {
            (method.into(), password.into())
        } else {
            todo!()
        };

    let (method, password, host, port): (TinyText, TinyText, HostSpec, PortSpec) =
        if let Some((host, port)) = raw.hostport().map_err(|e| {
            ParseError::InvalidHostPort(format!("{}: {e}", raw.hostport.unwrap()).into())
        })? {
            let userinfo = raw.userinfo_smart(|s| !s.contains(&b':')).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            let userinfo = str::from_utf8(&userinfo).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            let (method, password) = userinfo.split_once(':').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{}: missing password", raw.userinfo).into())
            })?;
            (method.into(), password.into(), host, port)
        } else {
            let Some((userinfo, hostport)) = raw.userinfo.split_once('@') else {
                return Ok(None);
            };
            let (host, port) = _parse_hostport(hostport)?;
            if let Some((method, password)) = userinfo.split_once(':') {
                (method.into(), password.into(), host, port)
            } else {
                let userinfo = _parse_base64(userinfo).map_err(|e| {
                    ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
                })?;
                let userinfo = String::from_utf8(userinfo).map_err(|e| {
                    ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
                })?;
                let (method, password) = userinfo.split_once(':').ok_or_else(|| {
                    ParseError::InvalidUserInfo(
                        format!("{}: missing password", raw.userinfo).into(),
                    )
                })?;
                (method.into(), password.into(), host, port)
            }
        };

    let userinfo = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));

    Ok(Some(UrlX {
        hashsum: 0,
        schema: SchemeX::SS,
        username: userinfo.into(),
        password: password.into(),
        host,
        port,
        path: None,
        query: vec![],
        transport: Some("tcp".into()),
        security: Some(TinyText::new_const()),
        fragment: raw.fragment.map(TinyText::from),
    }))
}
fn _parse_ssr(raw: &mut Input) -> Output {
    todo!()
}
fn _parse_mtproto(raw: &mut Input) -> Output {
    todo!()
}

// ==================================================

fn _parse_vless(raw: &mut Input) -> Output {
    todo!()
}

// fn parse(raw: &mut Input) -> Output {
//     if let Some(mut userinfo) = raw
//         .userinfo_only(raw.schema != SchemeX::MTProto, true)
//         .map_err(|e| ParseError::InvalidUserInfo(raw.userinfo.into()))?
//     {
//         let userinfo = str::from_utf8(&userinfo)
//             .map_err(|e| ParseError::InvalidUserInfo(raw.userinfo.into()))?;

//         let mut unencoded_url = RawUrlX {
//             schema: raw.schema.clone(),
//             userinfo,
//             hostport: raw.hostport,
//             path: raw.path,
//             query: raw.query,
//             fragment: raw.fragment,
//         };

//         if raw.schema == SchemeX::MTProto {
//             return _parse_mtproto(&mut unencoded_url);
//         }
//         let r = if let Some(r) = _parse_vmess(&mut unencoded_url)? {
//             r
//         } else if let Some(r) = _parse_ss(&mut unencoded_url)? {
//             r
//         } else if let Some(r) = _parse_ssr(&mut unencoded_url)? {
//             r
//         } else {
//             return Ok(None);
//         };

//         return Ok(Some(r));
//     }

//     match raw.schema {
//         // SchemeX::Vmess | SchemeX::SSR | SchemeX::MTProto => {
//         //     Err("url contains unexpected elements".into())
//         // }
//         SchemeX::SS => {
//             if uuid::Uuid::from_str(raw.userinfo).is_ok() {
//                 return _parse_vless(raw);
//             }
//             let r = _parse_ss(raw);
//             if matches!(r, Ok(None))
//                 && let r @ Ok(Some(_)) = _parse_vless(raw)
//             {
//                 return r;
//             }
//             r
//         }

//         _ => todo!(),
//     }
// }
