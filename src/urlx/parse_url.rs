use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use base64::Engine;
use bstr::ByteSlice;
use nom::Err;
use rustls::pki_types::ServerName;
use serde_json::Value;

use crate::urlx::{UserInfo, user_info::UserInfoEncoding};

use super::{HostSpec, PortSpec, RawUrlX, SchemeX, TinyText, UrlX};

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

const NOT_ACCEPTED: Result<Option<UrlX>, ParseError> = Ok(None);

fn _parse_vmess(raw: &Input) -> Output {
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Structural Check
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // 1: Verify, that the raw url contains only userinfo (and optional fragment)
    let RawUrlX {
        schema: _,
        userinfo,
        hostport: None,
        path: None,
        query: None,
        fragment: _,
    } = raw
    else {
        return NOT_ACCEPTED;
    };

    // 2: Verify, that userinfo is base64 encoded
    let Ok(mut userinfo) = UserInfo::new_from_b64(userinfo) else {
        return NOT_ACCEPTED;
    };
    // 3: Verify, that userinfo is json (and decode it, permissive)
    let Ok(json) = userinfo.as_json_decoded(true) else {
        return NOT_ACCEPTED;
    };

    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Basic Validation And Normalization
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    // 1: Extract and validate host
    let host: HostSpec = {
        let host = json
            .get("add")
            .ok_or(ParseError::MissingHost)
            .and_then(|v| {
                v.as_str()
                    .ok_or_else(|| ParseError::InvalidHost(format!("cannot parse: {}", v).into()))
            })?;
        let host = if let Some(new_host) = host.strip_prefix("[") {
            new_host
                .strip_suffix("]")
                .ok_or_else(|| ParseError::InvalidHost(format!("cannot parse: {}", host).into()))?
        } else {
            host
        };
        ServerName::try_from(host)
            .map_err(|e| ParseError::InvalidHost(format!("cannot parse: {} {}", host, e).into()))?
            .to_owned()
    };

    // 2: Extract and validate port
    let port = {
        let port = json
            .get("port")
            .ok_or(ParseError::MissingPort)
            .and_then(|v| {
                v.as_u64()
                    .ok_or_else(|| ParseError::InvalidPort(format!("cannot parse: {}", v).into()))
            })?;

        u16::try_from(port)
            .map_err(|e| ParseError::InvalidPort(format!("cannot parse: {} {}", port, e).into()))
            .map(PortSpec::new_with)?
    };

    // 3: Extract and validate security
    let security: TinyText = json
        .get("scy")
        .map(|v| {
            v.as_str()
                .ok_or_else(|| ParseError::InvalidConf("scy".into(), v.to_string().into()))
        })
        .transpose()?
        .unwrap_or("auto")
        .into();

    // 4: Extract and validate transport
    let transport: TinyText = json
        .get("net")
        .map(|v| {
            v.as_str()
                .ok_or_else(|| ParseError::InvalidConf("net".into(), v.to_string().into()))
        })
        .transpose()?
        .unwrap_or("tcp")
        .into();

    // 5: Extract and validate remarks (if any)
    let remarks = json
        .as_object_mut()
        .and_then(|o| o.remove("ps"))
        .map(|v| {
            v.as_str()
                .map(|s| s.trim_matches(['"', '\'']))
                .map(TinyText::from)
                .ok_or(ParseError::InvalidConf("ps".into(), v.to_string().into()))
        })
        .transpose()?;

    // 6: Extract and validate user
    let user = json
        .get("id")
        .map(|v| {
            v.as_str()
                .map(TinyText::from)
                .ok_or(ParseError::InvalidConf("id".into(), v.to_string().into()))
        })
        .transpose()?
        .ok_or_else(|| ParseError::MissingConf("id".into()))?;

    // 7: Normalize UUID (if user is UUID in non-hyphen format)
    let user = uuid::Uuid::parse_str(&user).map_or(user, |uuid| uuid.to_string().into());

    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Finalize
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    Ok(Some(UrlX {
        uid: 0,
        sig: 0,
        schema: SchemeX::Vmess,
        host: Some(host),
        port: Some(port),
        transport: transport.into(),
        security: security.into(),
        username: userinfo,
        password: Some(user),
        path: None,
        query: vec![],
        fragment: remarks,
    }))
}

fn _parse_ss(raw: &Input) -> Output {
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Structural Check
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    let (userinfo, hostport) = if let Some(hostport) = raw.hostport {
        // * Scenario 1: raw url, as is (separate userinfo and hostport):
        // * ss://[base64:userinfo]@[hostport]#[fragment]
        // ? ========================================
        let userinfo = UserInfo::new_from_b64(raw.userinfo)
            .map_err(|e| ParseError::InvalidUserInfo(format!("{}: {}", raw.userinfo, e).into()))?;
        (
            userinfo.as_text().expect("should be text").clone(),
            TinyText::from(hostport),
        )
    } else {
        // * Scenario 2: raw url, with encoded userinfo and hostport (no hostport in raw url):
        // * ss://[base64:userinfo@hostport]#fragment
        // ? ========================================
        let userinfo = UserInfo::new_from_b64(raw.userinfo)
            .map_err(|e| ParseError::InvalidUserInfo(format!("{}: {}", raw.userinfo, e).into()))?;

        let userinfo = userinfo.as_text().expect("should be text");

        let (userinfo, hostport) = userinfo.split_once('@').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing hostport", raw.userinfo).into())
        })?;

        (userinfo.into(), TinyText::from(hostport))
    };

    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Basic Validation And Normalization
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    // Parse hostport
    let (host, port) = _parse_hostport(hostport.as_str())?;
    // Parse userinfo
    let Some((method, password)) = userinfo.split_once(':') else {
        return Err(ParseError::InvalidUserInfo(
            format!("{}: missing password", raw.userinfo).into(),
        ));
    };

    // Extract and validate fragment
    let fragment = raw
        .fragment
        .map(urlencoding::decode)
        .transpose()
        .map_err(|e| ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
        .map(TinyText::from);

    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Finalize
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    Ok(Some(UrlX {
        uid: 0,
        sig: 0,
        schema: SchemeX::SS,
        username: super::UserInfo::Text(
            format!("{method}:{password}").into(),
            super::user_info::UserInfoEncoding::B64,
        ),
        password: Some(password.into()),
        host: Some(host),
        port: Some(port),
        path: None,
        query: vec![],
        transport: Some("tcp".into()),
        security: Some(method.into()),
        fragment,
    }))
}

fn _parse_ssr(raw: &Input) -> Output {
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Structural Check
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // 1: Verify, that the raw url contains only userinfo (and optional fragment)
    let RawUrlX {
        schema: _,
        userinfo,
        hostport: None,
        path: None,
        query: None,
        fragment: _,
    } = raw
    else {
        return NOT_ACCEPTED;
    };
    // 1: Verify, that userinfo is base64
    let Ok(userinfo) = UserInfo::new_from_b64(userinfo) else {
        return NOT_ACCEPTED;
    };
    let Some(text) = userinfo.as_text().cloned() else {
        unreachable!();
    };
    // 2: Verify, that userinfo is in the correct format (host:port:protocol:method:obfs:password)
    let &[raw_host, raw_port, protocol, method, obfs, raw_password] =
        text.split(':').collect::<Vec<_>>().as_slice()
    else {
        return NOT_ACCEPTED;
    };

    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Basic Validation And Normalization
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    // 1: Parse host
    let host: HostSpec = ServerName::try_from(raw_host)
        .map_err(|_| ParseError::InvalidHost(raw_host.to_owned().into()))?
        .to_owned();

    // 2: Parse port
    let port = raw_port
        .parse::<u16>()
        .map(PortSpec::new_with)
        .map_err(|_| ParseError::InvalidPort(raw_port.to_owned().into()))?;

    // 3: Make security
    let security: TinyText = TinyText::from(method);

    // 4: Make transport
    let transport: TinyText = "tcp".into();

    // 5: Extract password and query-like params
    let Some((password, query)) = raw_password
        .split_once("/?")
        .or_else(|| raw_password.split_once('?'))
    else {
        return NOT_ACCEPTED;
    };

    // 6: Construct params
    let mut query_pairs = if query.is_empty() {
        BTreeMap::new()
    } else {
        query
            .split('&')
            .map(|s| {
                if let Some((k, v)) = s.split_once('=') {
                    if v.is_empty() {
                        (k, Option::<TinyText>::None)
                    } else {
                        (k, Some(v.into()))
                    }
                } else {
                    (s, None)
                }
            })
            .collect::<BTreeMap<_, _>>()
    };

    // 7: Extract remarks
    let remarks = if let Some(e) = query_pairs.remove("remarks") {
        let Some(remarks) = e else {
            return Err(ParseError::InvalidConf(
                "remarks (should be base64)".into(),
                "".into(),
            ));
        };
        let decoded = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(remarks.trim_end_matches('='))
            .map_err(|_| {
                ParseError::InvalidConf(
                    "remarks (should be base64)".into(),
                    remarks.to_string().into(),
                )
            })?;
        let decoded = urlencoding::decode_binary(decoded.as_ref());
        let decoded = str::from_utf8(decoded.as_ref()).map_err(|_| {
            ParseError::InvalidConf(
                "remarks (should be utf8)".into(),
                remarks.to_string().into(),
            )
        })?;
        Some(decoded.into())
    } else {
        None
    };

    let unique_username = format!(
        "{}:{}:{}:{}:{}:{}/?{}",
        raw_host,
        raw_port,
        protocol,
        method,
        obfs,
        password,
        query_pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v.as_deref().unwrap_or_default()))
            .collect::<Vec<_>>()
            .join("&")
    );

    let username = UserInfo::Text(unique_username.into(), UserInfoEncoding::B64);

    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // * Finalize
    // ? =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    Ok(Some(UrlX {
        uid: 0,
        sig: 0,
        schema: SchemeX::SSR,
        username,
        password: Some(password.into()),
        host: Some(host),
        port: Some(port),
        path: None,
        query: [
            (TinyText::from("protocol"), Some(protocol.into())),
            (TinyText::from("obfs"), Some(obfs.into())),
        ]
        .into_iter()
        .chain(query_pairs.into_iter().map(|(k, v)| (k.into(), v)))
        .collect(),
        transport: Some(transport),
        security: Some(security),
        fragment: remarks,
    }))
}
fn _parse_mtproto(raw: &Input) -> Output {
    todo!()
}

// ==================================================

fn _parse_vless(raw: &Input) -> Output {
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

pub fn visit_basic(raw: &Input) -> Result<UrlX, ParseError> {
    let result = match raw.schema {
        SchemeX::SS => _parse_ss(raw),
        SchemeX::SSR => _parse_ssr(raw),
        SchemeX::Vmess => _parse_vmess(raw),

        ref other => unimplemented!("{other}"),
    };

    match result {
        Err(
            e @ (ParseError::MissingHost
            | ParseError::MissingPort
            | ParseError::InvalidUserInfo(_)
            | ParseError::Unknown(_)),
        ) => {
            tracing::warn!(target: "visit::basic", "Schema not accepted, trying fallbacks: {} ({e})", raw.schema);
        }
        Err(e) => return Err(e),
        Ok(Some(v)) => return Ok(v),
        Ok(None) => {
            tracing::warn!(target: "visit::basic", "Schema not accepted, trying fallbacks: {} (by structure)", raw.schema);
        }
    };

    let original_schema = raw.schema.clone();
    let v = 'block: {
        if let Ok(Some(v)) = _parse_ss(raw) {
            break 'block v;
        }
        if let Ok(Some(v)) = _parse_ssr(raw) {
            break 'block v;
        }
        if let Ok(Some(v)) = _parse_vmess(raw) {
            break 'block v;
        }
        if let Ok(Some(v)) = _parse_mtproto(raw) {
            break 'block v;
        }
        if let Ok(Some(v)) = _parse_vless(raw) {
            break 'block v;
        }

        todo!()
    };
    tracing::warn!(target: "visit::basic", "Schema fallback success: [{} => {}]", original_schema, v.schema);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess() {
        let url = "ss://eyJhZGQiOiIxMDQuMjEuNy4xNjIiLCJhaWQiOiIwIiwiaWQiOiI1MjBhNWY0NS1kMzU0LTQyZjQtYTY1OC0xOGRiYzM3NTQ2NDUiLCJuZXQiOiJ3cyIsInBhdGgiOiIvZndzIiwicG9ydCI6MjA4NywicHMiOiJcIlhYIPCfj7PvuI8g4pSHIFZNRVNTLVdTLVRMUyAtIENMT1VERkxBUkVORVQg4pSHIDEwNC4yMS43LjE2MlwiIiwic2N5IjoiYXV0byIsInRscyI6InRscyIsInYiOiIyIn0=";

        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(url).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_ssr() {
        let url = "ssr://MTA3LjE1MS4xODIuMjUzOjgwODA6b3JpZ2luOnJjNC1tZDU6cGxhaW46TVRSbVJsQnlZbVY2UlROSVJGcDZjMDFQY2pZLz9ncm91cD1VMU5TVUhKdmRtbGtaWEkmcmVtYXJrcz04Si1IdXZDZmg3Z2dVMU5TTGVlLWp1V2J2UzFPUnVpbm8tbVVnZWlIcXVXSXR1V0pweTFEYUdGMFIxQlVMVlJwYTFSdmF5MVpiM1ZVZFdKbExURXdOeTR4TlRFdU1UZ3lMakkxTXpvNE1EZ3cmb2Jmc3BhcmFtPSZwcm90b3BhcmFtPQ";

        let raw = RawUrlX::from(url);
        eprintln!("{raw:?}");

        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(url).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_ss() {
        tracing_subscriber::fmt().compact().init();

        let url = "vmess://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTozMTM0NzA1Ny03YWY1LTQ1NjItYjkxMi1mMWMyMTdjNGMxNjA@hnt.cndns.shop:27761#%F0%9F%87%A8%F0%9F%87%B3_CN_%E4%B8%AD%E5%9B%BD-%3E%F0%9F%87%B7%F0%9F%87%BA_RU_%E4%BF%84%E7%BD%97%E6%96%AF%E8%81%94%E9%82%A6";
        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(url).unwrap()).unwrap()
        );
    }
}
