use std::{borrow::Cow, collections::BTreeMap};

use base64::Engine;
use bstr::ByteSlice;
use rusqlite::Name;
use rustls::pki_types::ServerName;

use crate::urlx::{HostSpec, PortSpec, UserInfo, user_info::UserInfoEncoding};

use super::{RawUrlX, SchemeX, TinyText, UrlX};

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
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
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

fn _parse_vless(raw: &Input) -> Output {
    let (username, hostport) = if let Some(hostport) = raw.hostport {
        let username = raw.userinfo;
        (username, hostport)
    } else {
        let userinfo = raw.userinfo;
        let (userinfo, hostport) = userinfo.split_once('@').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing hostport", userinfo).into())
        })?;
        (userinfo, hostport)
    };

    let (host, port) = _parse_hostport(hostport)?;
    let uuid = uuid::Uuid::parse_str(username)
        .map_err(|_| ParseError::InvalidUserInfo(format!("invalid UUID: {}", username).into()))?;

    let query_string = raw.query.unwrap_or("");
    let query_pairs: Vec<(TinyText, Option<TinyText>)> = if query_string.is_empty() {
        vec![]
    } else {
        query_string
            .split('&')
            .filter_map(|s| {
                if let Some((k, v)) = s.split_once('=') {
                    if v.is_empty() {
                        Some((TinyText::from(k), None))
                    } else {
                        Some((TinyText::from(k), Some(TinyText::from(v))))
                    }
                } else if !s.is_empty() {
                    Some((TinyText::from(s), None))
                } else {
                    None
                }
            })
            .collect()
    };

    let security = query_pairs
        .iter()
        .find(|(k, _)| k.as_str() == "security")
        .and_then(|(_, v)| v.as_ref())
        .map(|v| TinyText::from(v.as_str()))
        .unwrap_or_else(|| "none".into());
    let transport = query_pairs
        .iter()
        .find(|(k, _)| k.as_str() == "type")
        .and_then(|(_, v)| v.as_ref())
        .map(|v| TinyText::from(v.as_str()))
        .unwrap_or_else(|| "tcp".into());
    let path = query_pairs
        .iter()
        .find(|(k, _)| k.as_str() == "path")
        .and_then(|(_, v)| v.as_ref())
        .cloned();

    let remarks = raw
        .fragment
        .map(urlencoding::decode)
        .transpose()
        .map_err(|e| ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
        .map(TinyText::from);

    Ok(Some(UrlX {
        uid: 0,
        sig: 0,
        schema: SchemeX::Vless,
        username: super::UserInfo::Text(username.into(), super::user_info::UserInfoEncoding::URL),
        password: Some(uuid.to_string().into()),
        host: Some(host),
        port: Some(port),
        path,
        query: query_pairs,
        transport: Some(transport),
        security: Some(security),
        fragment: remarks,
    }))
}

fn _parse_trojan(raw: &Input) -> Output {
    let (username, hostport) = if let Some(hostport) = raw.hostport {
        (raw.userinfo, hostport)
    } else {
        let userinfo = raw.userinfo;
        let (username, hostport) = userinfo.split_once('@').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing hostport", userinfo).into())
        })?;
        (username, hostport)
    };

    let (host, port) = _parse_hostport(hostport)?;

    let query_string = raw.query.unwrap_or("");
    let query_pairs: Vec<(TinyText, Option<TinyText>)> = if query_string.is_empty() {
        vec![]
    } else {
        query_string
            .split('&')
            .filter_map(|s| {
                if let Some((k, v)) = s.split_once('=') {
                    if v.is_empty() {
                        Some((TinyText::from(k), None))
                    } else {
                        Some((TinyText::from(k), Some(TinyText::from(v))))
                    }
                } else if !s.is_empty() {
                    Some((TinyText::from(s), None))
                } else {
                    None
                }
            })
            .collect()
    };

    let security: TinyText = query_pairs
        .iter()
        .find(|(k, _)| k.as_str() == "security")
        .and_then(|(_, v)| v.as_deref())
        .unwrap_or("tls")
        .into();
    let transport: TinyText = query_pairs
        .iter()
        .find(|(k, _)| k.as_str() == "type")
        .and_then(|(_, v)| v.as_deref())
        .unwrap_or("tcp")
        .into();
    let path = query_pairs.iter().find_map(|(k, v)| {
        if k.as_str() == "path"
            && let Some(v) = v
        {
            Some(v.to_owned())
        } else {
            None
        }
    });

    let remarks = raw
        .fragment
        .map(urlencoding::decode)
        .transpose()
        .map_err(|e| ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
        .map(TinyText::from);

    Ok(Some(UrlX {
        uid: 0,
        sig: 0,
        schema: SchemeX::Trojan,
        username: super::UserInfo::Text(username.into(), super::user_info::UserInfoEncoding::URL),
        password: Some(username.into()),
        host: Some(host),
        port: Some(port),
        path,
        query: query_pairs,
        transport: Some(transport),
        security: Some(security),
        fragment: remarks,
    }))
}

fn _parse_hysteria2(raw: &Input) -> Output {
    let (username, hostport) = if let Some(hostport) = raw.hostport {
        (raw.userinfo, hostport)
    } else {
        let userinfo = raw.userinfo;
        let (username, hostport) = userinfo.split_once('@').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing hostport", userinfo).into())
        })?;
        (username, hostport)
    };

    let (host, port) = _parse_hostport(hostport)?;

    let query_string = raw.query.unwrap_or("");
    let query_pairs: Vec<(TinyText, Option<TinyText>)> = if query_string.is_empty() {
        vec![]
    } else {
        query_string
            .split('&')
            .filter_map(|s| {
                if let Some((k, v)) = s.split_once('=') {
                    if v.is_empty() {
                        Some((TinyText::from(k), None))
                    } else {
                        Some((TinyText::from(k), Some(TinyText::from(v))))
                    }
                } else if !s.is_empty() {
                    Some((TinyText::from(s), None))
                } else {
                    None
                }
            })
            .collect()
    };

    let security: TinyText = query_pairs
        .iter()
        .find(|(k, _)| k.as_str() == "security")
        .and_then(|(_, v)| v.as_deref())
        .unwrap_or("tls")
        .into();

    let remarks = raw
        .fragment
        .map(urlencoding::decode)
        .transpose()
        .map_err(|e| ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
        .map(TinyText::from);

    Ok(Some(UrlX {
        uid: 0,
        sig: 0,
        schema: SchemeX::Hysteria2,
        username: super::UserInfo::Text(username.into(), super::user_info::UserInfoEncoding::URL),
        password: Some(username.into()),
        host: Some(host),
        port: Some(port),
        path: None,
        query: query_pairs,
        transport: Some("udp".into()),
        security: Some(security),
        fragment: remarks,
    }))
}

fn _parse_tg(raw: &Input) -> Output {
    let is_socks = if raw.schema == SchemeX::Https && raw.userinfo == "t.me" {
        match raw.path {
            Some("/socks") => true,
            Some("/proxy") => false,
            _ => return NOT_ACCEPTED,
        }
    } else if raw.schema == SchemeX::Tg {
        match raw.userinfo {
            "socks" => true,
            "proxy" => false,
            _ => return NOT_ACCEPTED,
        }
    } else {
        return NOT_ACCEPTED;
    };

    let query = raw
        .query()
        .map_err(|e| ParseError::InvalidConf("query".into(), e.to_string().into()))?;

    let host: HostSpec = {
        let host_raw = query
            .iter()
            .find_map(|(k, v)| if k == "server" { v.as_ref() } else { None })
            .ok_or(ParseError::MissingHost)?;
        ServerName::try_from(host_raw.as_str())
            .map_err(|e| ParseError::InvalidConf("server".into(), e.to_string().into()))?
            .to_owned()
    };

    let port: PortSpec = {
        let port_raw = query
            .iter()
            .find_map(|(k, v)| if k == "port" { v.as_ref() } else { None })
            .ok_or(ParseError::MissingPort)?;

        port_raw
            .parse::<u16>()
            .map(PortSpec::new_with)
            .map_err(|e| ParseError::InvalidConf("port".into(), e.to_string().into()))?
    };

    let secret = query
        .iter()
        .find_map(|(k, v)| if k == "secret" { v.as_ref() } else { None })
        .ok_or(ParseError::MissingConf("secret".into()))?;

    let remarks = raw
        .fragment
        .map(urlencoding::decode)
        .transpose()
        .map_err(|e| ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
        .map(TinyText::from);

    Ok(Some(UrlX {
        uid: 0,
        sig: 0,
        schema: SchemeX::Tg,
        username: super::UserInfo::Text(secret.to_owned(), super::user_info::UserInfoEncoding::URL),
        password: Some(secret.to_owned()),
        host: Some(host),
        port: Some(port),
        path: None,
        query: vec![],
        transport: Some(if is_socks { "socks" } else { "mtproto" }.into()),
        security: Some("tls".into()),
        fragment: remarks,
    }))
}

fn _parse_slipnet(raw: &Input) -> Output {
    let encrypted = matches!(raw.schema, SchemeX::SlipnetEnc);
    let config_data = raw.userinfo;

    if encrypted {
        return Ok(Some(UrlX {
            uid: 0,
            sig: 0,
            schema: SchemeX::SlipnetEnc,
            username: super::UserInfo::Text(
                config_data.into(),
                super::user_info::UserInfoEncoding::B64,
            ),
            password: Some(config_data.into()),
            host: None,
            port: None,
            path: None,
            query: vec![],
            transport: None,
            security: None,
            fragment: None,
        }));
    }

    let decoded = base64::prelude::BASE64_STANDARD_NO_PAD.decode(config_data);

    let bytes = match decoded {
        Ok(b) => b,
        Err(_) => {
            return NOT_ACCEPTED;
        }
    };

    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => {
            return NOT_ACCEPTED;
        }
    };

    let fields: Vec<&str> = text.split('|').collect();

    if fields.len() < 12 {
        return NOT_ACCEPTED;
    }

    let domain = fields
        .get(3)
        .copied()
        .filter(|s| !s.is_empty())
        .map(TinyText::from);
    let public_key = fields
        .get(11)
        .copied()
        .filter(|s| !s.is_empty())
        .map(TinyText::from);
    let tunnel_type = fields
        .get(1)
        .copied()
        .filter(|s| !s.is_empty())
        .map(TinyText::from);
    let local_port = fields.get(8).and_then(|s| s.parse::<u16>().ok());

    let host = domain
        .as_ref()
        .and_then(|d| ServerName::try_from(d.as_str()).ok())
        .map(|s| s.to_owned());

    let query: Vec<(TinyText, Option<TinyText>)> = std::iter::empty()
        .chain(
            public_key
                .as_ref()
                .map(|pk| (TinyText::from("pk"), Some(pk.clone()))),
        )
        .chain(
            tunnel_type
                .as_ref()
                .map(|tt| (TinyText::from("type"), Some(tt.clone()))),
        )
        .collect();

    let port = local_port.map(PortSpec::new_with);

    let remarks = raw
        .fragment
        .map(urlencoding::decode)
        .transpose()
        .map_err(|e| ParseError::InvalidConf("remarks".into(), e.to_string().into()))?
        .map(TinyText::from);

    Ok(Some(UrlX {
        uid: 0,
        sig: 0,
        schema: SchemeX::Slipnet,
        username: super::UserInfo::Text(
            config_data.into(),
            super::user_info::UserInfoEncoding::B64,
        ),
        password: Some(config_data.into()),
        host,
        port,
        path: None,
        query,
        transport: tunnel_type,
        security: None,
        fragment: remarks,
    }))
}
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
        SchemeX::Vless => _parse_vless(raw),
        SchemeX::Trojan => _parse_trojan(raw),
        SchemeX::Hysteria2 => _parse_hysteria2(raw),
        SchemeX::Tg | SchemeX::Https => _parse_tg(raw),

        ref _other @ (SchemeX::Slipnet | SchemeX::SlipnetEnc) => {
            tracing::debug!(target: "visit", "SlipNet - trying to parse as slipnet");
            _parse_slipnet(raw)
        }
        ref _other @ SchemeX::Hysteria => {
            tracing::debug!(target: "visit", "Hysteria not implemented, treating as Hysteria2");
            _parse_hysteria2(raw)
        }
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
        if let Ok(Some(v)) = _parse_vless(raw) {
            break 'block v;
        }
        if let Ok(Some(v)) = _parse_trojan(raw) {
            break 'block v;
        }
        if let Ok(Some(v)) = _parse_hysteria2(raw) {
            break 'block v;
        }
        if let Ok(Some(v)) = _parse_slipnet(raw) {
            break 'block v;
        }
        if let Ok(Some(v)) = _parse_tg(raw) {
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
        _ = tracing_subscriber::fmt().compact().try_init();

        let url = "vmess://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTozMTM0NzA1Ny03YWY1LTQ1NjItYjkxMi1mMWMyMTdjNGMxNjA@hnt.cndns.shop:27761#%F0%9F%87%A8%F0%9F%87%B3_CN_%E4%B8%AD%E5%9B%BD-%3E%F0%9F%87%B7%F0%9F%87%BA_RU_%E4%BF%84%E7%BD%97%E6%96%AF%E8%81%94%E9%82%A6";
        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(url).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_reconstruct_vmess() {
        let input = "vmess://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTozMTM0NzA1Ny03YWY1LTQ1NjItYjkxMi1mMWMyMTdjNGMxNjA@hnt.cndns.shop:27761";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_reconstruct_ssr() {
        let input = "ssr://MTA3LjE1MS4xODIuMjUzOjgwODA6b3JpZ2luOnJjNC1tZDU6cGxhaW46TVRSbVJsQnlZbVY2UlROSVJGcDZjMDFQY2pZLz9ncm91cD1VMU5TVUhKdmRtbGtaWEkmcmVtYXJrcz04Si1IdXZDZmg3Z2dVMU5TTGVlLWp1V2J2UzFPUnVpbm8tbVVnZWlIcXVXSXR1V0pweTFEYUdGMFIxQlVMVlJwYTFSdmF5MVpiM1ZVZFdKbExURXdOeTR4TlRFdU1UZ3lMakkxTXpvNE1EZ3cmb2Jmc3BhcmFtPSZwcm90b3BhcmFtPQ";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_reconstruct_ss() {
        let input = "ss://Y2xlb2Y6cGFzc3dvcmRAMTI3LjAuMC4xOjgwODA=@127.0.0.1:8080";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_reconstruct_vless() {
        let input = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.schema, reparsed.schema, "schema mismatch");
    }

    #[test]
    fn test_reconstruct_trojan() {
        let input = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_reconstruct_hysteria2() {
        let input = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_reconstruct_tg() {
        let input = "https://t.me/proxy?server=146.185.211.126&port=443&secret=ee1e36377253a29133d290f3d14ae0163873756e342d32302e757365726170692e636f6d";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

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
    fn test_reconstruct_slipnet() {
        let input = "slipnet://MjJ8ZG5zdHR8ZG5zdHQtc29ja3N8dC5zaGFtbG91Lm9ubGluZXw4LjguOC44OjUzOjB8MHw1MDAwfGJicnwxMDgwfDEyNy4wLjAuMXwwfDg0ZTcxMjU3ZjRjZDkyZThmZjFiZDFlNTFjOWE5NGY3MjRlOWU5MTM2MzgxNDliN2FlNDJmNjhiNjljNTRkMjd8aXJhbnV4fglyYW51eHwwfHx8MjJ8MHw0NS4xNDguMjguMTE1fDB8fHVkcHxwYXNzd29yZHx8fHwwfDQ0M3x8fDB8fDB8MHx8MHx8MHwwfDEwODB8MHx0eHR8MTAxfDB8MHwwfDB8MHwwfDB8fHw4MDgwfHwwfC98MXx8";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        assert!(
            reconstructed.starts_with("slipnet://"),
            "should start with slipnet://"
        );
    }

    #[test]
    fn test_reconstruct_slipnet_enc() {
        let input = "slipnet-enc://Ac3GD6rpCy53w/nMNSrt/pGttnE/aagWaQyqTM+rr1LJgl5T8xRs+5IWD/pe+tKPpz2eUHYXEza8roniezFp25RM6iHo902gfJYZFg5lGVaQMjwQPu6BlBBFSCjVehs70Kgf1Fx56ha566VkTPsJDu37in+EKjaHxijwEJydn4o8n6YgSoyOsxd9OzQufIXRkPM3K5FGFUG9nYSV4oBe2hUmtJVRT+q8CONfij91e9dn3FnbQfvkst08zfah4WaAHkJEIPw28CwzExsPOjRexMTmrRsZZZuliTRmncnM0gI6WmGGKe2jdizCZN6TnDM2efkWLjfWk3+d26O+xTgJZ+lUqI/h7swa11p2OzsAdNpNnNSCMECvM8TbTuwfFeY6X668AebOi8SVHTLe5S31+ZXObdlQYQFC57aU1XXmYjI6pPFbfWjPgvtmO9mR+GQ0yp0Gg+yM6ufxra4qDhmIQWbcTfqHCc1bxCMjyYdC9d+9TGapCM41IJwnoDl7zer2G+3NkEZ0E2edw4/lXxS3D95GN0PEudoi+ic/hnFeeMPUWFoAyApi9F/KwBItcjkSKqvkluNgQdzL0UmcLWkyVuhBJ8rWSdMU5ZKUqccpeiNKlKRhQ6a2b9Buiz4YxfQ4LRbVUVllZaX84hxJgMeaMg9Jp+CJmSyUD0QkN+si6pd6+31yRIZpFHGk0UnYJ9hZQuqeczecc88d0oRDMGf/rDBt198/caUJpKo=";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        assert_eq!(
            input, reconstructed,
            "slipnet-enc:// URLs must be exactly equal after reconstruction"
        );
    }

    #[test]
    fn test_reconstruct_wireguard() {
        let input = "wireguard://MHlIYW5kYWNlZToxMjcuMC4wLjE6ODQ4Mw==";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_vless() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";

        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::Vless);
    }

    #[test]
    fn test_vless_reality() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&pbk=abc123";

        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::Vless);
    }

    #[test]
    fn test_trojan() {
        let url = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";

        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::Trojan);
    }

    #[test]
    fn test_hysteria2() {
        let url = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com";

        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::Hysteria2);
    }

    #[test]
    fn test_hy2() {
        let url =
            "hy2://linux.do@[2a01:4f9:4b:f378::1]:13599?security=tls&insecure=1&sni=www.bing.com";

        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::Hysteria2);
    }

    #[test]
    fn test_tg() {
        let url = "https://t.me/proxy?server=146.185.211.126&port=443&secret=ee1e36377253a29133d290f3d14ae0163873756e342d32302e757365726170692e636f6d";

        let raw = RawUrlX::from(url);
        eprintln!("{raw:?}");
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::Tg);
    }

    #[test]
    fn test_tg_hostname() {
        let url = "https://t.me/proxy?server=proxium.rest&port=888&secret=a669r5a45920422f9d417e4867efdc4fb8jllllloo9w88220wpwoow9";

        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::Tg);
    }

    #[test]
    fn test_slipnet() {
        let url = "slipnet://MjJ8ZG5zdHR8ZG5zdHQtc29ja3N8dC5zaGFtbG91Lm9ubGluZXw4LjguOC44OjUzOjB8MHw1MDAwfGJicnwxMDgwfDEyNy4wLjAuMXwwfDg0ZTcxMjU3ZjRjZDkyZThmZjFiZDFlNTFjOWE5NGY3MjRlOWU5MTM2MzgxNDliN2FlNDJmNjhiNjljNTRkMjd8aXJhbnV4fglyYW51eHwwfHx8MjJ8MHw0NS4xNDguMjguMTE1fDB8fHVkcHxwYXNzd29yZHx8fHwwfDQ0M3x8fDB8fDB8MHx8MHx8MHwwfDEwODB8MHx0eHR8MTAxfDB8MHwwfDB8MHwwfDB8fHw4MDgwfHwwfC98MXx8";

        let raw = RawUrlX::from(url);
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::Slipnet);
    }

    #[test]
    fn test_slipnet_enc() {
        let url = "slipnet-enc://Ac3GD6rpCy53w/nMNSrt/pGttnE/aagWaQyqTM+rr1LJgl5T8xRs+5IWD/pe+tKPpz2eUHYXEza8roniezFp25RM6iHo902gfJYZFg5lGVaQMjwQPu6BlBBFSCjVehs70Kgf1Fx56ha566VkTPsJDu37in+EKjaHxijwEJydn4o8n6YgSoyOsxd9OzQufIXRkPM3K5FGFUG9nYSV4oBe2hUmtJVRT+q8CONfij91e9dn3FnbQfvkst08zfah4WaAHkJEIPw28CwzExsPOjRexMTmrRsZZZuliTRmncnM0gI6WmGGKe2jdizCZN6TnDM2efkWLjfWk3+d26O+xTgJZ+lUqI/h7swa11p2OzsAdNpNnNSCMECvM8TbTuwfFeY6X668AebOi8SVHTLe5S31+ZXObdlQYQFC57aU1XXmYjI6pPFbfWjPgvtmO9mR+GQ0yp0Gg+yM6ufxra4qDhmIQWbcTfqHCc1bxCMjyYdC9d+9TGapCM41IJwnoDl7zer2G+3NkEZ0E2edw4/lXxS3D95GN0PEudoi+ic/hnFeeMPUWFoAyApi9F/KwBItcjkSKqvkluNgQdzL0UmcLWkyVuhBJ8rWSdMU5ZKUqccpeiNKlKRhQ6a2b9Buiz4YxfQ4LRbVUVllZaX84hxJgMeaMg9Jp+CJmSyUD0QkN+si6pd6+31yRIZpFHGk0UnYJ9hZQuqeczecc88d0oRDMGf/rDBt198/caUJpKo=";

        let raw = RawUrlX::from(url);
        eprintln!("{raw:?}");
        let url = visit_basic(&raw).expect("failed");

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::to_value(&url).unwrap()).unwrap()
        );

        assert_eq!(url.schema, SchemeX::SlipnetEnc);
    }

    #[test]
    fn test_reconstruct_vmess_roundtrip() {
        let input = "vmess://eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        eprintln!("schema: {:?}", parsed.schema);
        eprintln!("host: {:?}", parsed.host);
        eprintln!("port: {:?}", parsed.port);
        eprintln!("fragment: {:?}", parsed.fragment);

        assert_eq!(parsed.schema, SchemeX::Vmess, "schema should be Vmess");

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        assert!(
            reconstructed.starts_with("vmess://"),
            "should start with vmess://"
        );

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(
            parsed.schema, reparsed.schema,
            "schema mismatch after re-parse"
        );
    }

    #[test]
    fn test_reconstruct_ssr_roundtrip() {
        let input = "ssr://MTA3LjE1MS4xODIuMjUzOjgwODA6b3JpZ2luOnJjNC1tZDU6cGxhaW46TVRSbVJsQnlZbVY2UlROSVJGcDZjMDFQY2pZLz9ncm91cD1VMU5TVUhKdmRtbGtaWEkmcmVtYXJrcz04Si1IdXZDZmg3Z2dVMU5TTGVlLWp1V2J2UzFPUnVpbm8tbVVnZWlIcXVXSXR1V0pweTFEYUdGMFIxQlVMVlJwYTFSdmF5MVpiM1ZVZFdKbExURXdOeTR4TlRFdU1UZ3lMakkxTXpvNE1EZ3cmb2Jmc3BhcmFtPSZwcm90b3BhcmFtPQ";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        eprintln!("schema: {:?}", parsed.schema);
        eprintln!("host: {:?}", parsed.host);
        eprintln!("port: {:?}", parsed.port);
        eprintln!("query: {:?}", parsed.query);

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        assert!(
            reconstructed.starts_with("ssr://"),
            "should start with ssr://"
        );

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.schema, reparsed.schema, "schema mismatch");
        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_reconstruct_slipnet_roundtrip() {
        let input = "slipnet://MjJ8ZG5zdHR8ZG5zdHQtc29ja3N8dC5zaGFtbG91Lm9ubGluZXw4LjguOC44OjUzOjB8MHw1MDAwfGJicnwxMDgwfDEyNy4wLjAuMXwwfDg0ZTcxMjU3ZjRjZDkyZThmZjFiZDFlNTFjOWE5NGY3MjRlOWU5MTM2MzgxNDliN2FlNDJmNjhiNjljNTRkMjd8aXJhbnV4fglyYW51eHwwfHx8MjJ8MHw0NS4xNDguMjguMTE1fDB8fHVkcHxwYXNzd29yZHx8fHwwfDQ0M3x8fDB8fDB8MHx8MHx8MHwwfDEwODB8MHx0eHR8MTAxfDB8MHwwfDB8MHwwfDB8fHw4MDgwfHwwfC98MXx8";

        let raw = RawUrlX::from(input);
        let parsed = visit_basic(&raw).expect("failed to parse");

        eprintln!("schema: {:?}", parsed.schema);
        eprintln!("host: {:?}", parsed.host);
        eprintln!("port: {:?}", parsed.port);
        eprintln!("query: {:?}", parsed.query);

        let reconstructed = parsed.reconstruct();
        eprintln!("input:        {}", input);
        eprintln!("reconstructed: {}", reconstructed);

        assert_eq!(
            input, reconstructed,
            "slipnet:// URLs must be exactly equal after reconstruction"
        );

        let raw2 = RawUrlX::from(reconstructed.as_str());
        let reparsed = visit_basic(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.schema, reparsed.schema, "schema mismatch");
        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }
}
