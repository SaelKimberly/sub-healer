use std::{borrow::Cow, str::FromStr};

use base64::Engine;
use bstr::ByteSlice;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rustls::pki_types::{IpAddr, ServerName};
use serde_json::Value;

use crate::{PortSpec, SchemeX, UrlX};

static KNOWN_SCHEMAS: &[&str] = &[
    "vless://",
    "vmess://",
    "trojan://",
    "hhysteria2://",
    "hhysteria://",
    "hysteria2://",
    "hysteria://",
    "hy2://",
    "hy://",
    "warp://",
    "anytls://",
    "ss://",
    "ssr://",
];

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Data<'a> {
    Raw {
        scheme: &'static str,
        url: Cow<'a, str>,
    },
    Url(UrlX),
}

#[derive(Debug, Clone)]
pub struct Line<'a> {
    pub(crate) row: usize,
    pub(crate) url: Data<'a>,
    pub(crate) wrn: Option<Vec<Cow<'static, str>>>,
    pub(crate) err: Option<Cow<'static, str>>,
}

impl<'a> Line<'a> {
    fn parse_raw(self) -> Self {
        let Self {
            row,
            url: Data::Raw { scheme, url },
            mut wrn,
            err: None,
        } = self
        else {
            return self;
        };

        let url: Cow<'a, str> = {
            let norm = url
                .as_ref()
                .replace("&nbsp;", " ")
                .replace("&amp;", "&")
                .replace("&amp&", "&")
                .replace("&amp%3B", "&")
                .replace("?amp;", "?")
                .replace("?amp%3B", "?");
            if norm != url {
                wrn.get_or_insert_default()
                    .push("Detected HTML entities".into());
            }

            let norm = norm.replace("security=", "&security=");

            let norm = norm
                .split("&")
                .filter(|chunk| !chunk.is_empty())
                .collect::<Vec<_>>()
                .join("&");

            if norm != url {
                wrn.get_or_insert_default()
                    .push("Detected HTML entities".into());
                Cow::Owned(norm)
            } else {
                url
            }
        };

        let Ok(scheme) = SchemeX::from_str(scheme);
        if matches!(scheme, SchemeX::Unknown(_)) {
            wrn.get_or_insert_default()
                .push(format!("Unknown protocol schema: {scheme}").into());
        }

        let Ok(urlx) = UrlX::from_str(url.as_ref());

        Self {
            row,
            url: Data::Url(urlx),
            wrn,
            err: None,
        }
    }
}

#[derive(Clone)]
pub struct Lines<'a> {
    basic: Cow<'a, str>,
    // keep original line number for lints
    inner: Vec<Line<'a>>,
}

fn _split_at_scheme<'a>(
    (i, s): (usize, &'a str),
    schemas: &[&'static str],
) -> Vec<(usize, &'static str, &'a str)> {
    let mut slice = Option::<(&'static str, &'a str)>::None;
    let mut result = Vec::<(usize, &'static str, &'a str)>::with_capacity(1);

    // 1: Find first schema in line
    if let Some(prefix) = s.split_inclusive("://").next() {
        for schema in KNOWN_SCHEMAS {
            if let Some(prefix) = prefix.strip_suffix(schema) {
                let s = if prefix.is_empty() {
                    s
                } else {
                    s.strip_prefix(prefix)
                        .expect("Prefix is always a part of line")
                };
                slice.replace((schema, s));
                break;
            }
        }
    }

    while let Some((schema, sx)) = slice.take() {
        if sx.is_empty() || sx.len() < 5 {
            result.push((i, schema, sx));
            break;
        }

        // try to find another known schema in the area of current url (longest first)
        let mut min_schema_pos = Option::<(usize, &'static str)>::None;

        for s in schemas {
            let idx = sx.floor_char_boundary(5);
            let Some(pos) = sx[idx..].find(s).map(|p| p + idx) else {
                continue;
            };
            if let Some((current, found)) = min_schema_pos.as_mut() {
                if pos < *current {
                    *current = pos;
                    *found = s;
                }
            } else {
                min_schema_pos = Some((pos, *s));
            }
        }

        if let Some((min_schema_pos, another_schema)) = min_schema_pos {
            let (prefix, schema_and_tail) = sx.split_at(min_schema_pos);
            result.push((i, schema, prefix));
            _ = slice.replace((another_schema, schema_and_tail));
        } else {
            result.push((i, schema, sx));
            break;
        }
    }

    result
}

impl<'a> Lines<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &Line<'a>> {
        self.inner.iter()
    }

    pub(crate) fn new_raw(content: &'a str) -> Self {
        let this = Self {
            basic: content.into(),
            inner: content
                .lines()
                .enumerate()
                .flat_map(|(idx, line)| line.split("<br/>").map(move |s| (idx, s)))
                .flat_map(|s| _split_at_scheme(s, KNOWN_SCHEMAS))
                .map(|(i, s, sx)| Line {
                    row: i,
                    url: Data::Raw {
                        scheme: s,
                        url: Cow::Borrowed(sx),
                    },
                    wrn: None,
                    err: None,
                })
                .collect(),
        };
        tracing::info!("{} lines parsed", this.inner.len());
        this
    }

    pub(crate) fn parsed(mut self) -> Self {
        self.inner = self
            .inner
            .into_par_iter()
            .map(|l| {
                let mut l = l.parse_raw();

                if let Line {
                    url:
                        Data::Url(UrlX {
                            schema: SchemeX::Vmess | SchemeX::SS | SchemeX::SSR,
                            username,
                            password: None,
                            host: None,
                            port: None,
                            path,
                            query,
                            ..
                        }),
                    ..
                } = &mut l
                    && query.is_empty()
                    && let Some(path) = path.take()
                {
                    username.push('/');
                    username.push_str(path.as_str());
                }

                l
            })
            .collect();
        tracing::info!("{} lines parsed", self.inner.len());
        self
    }

    fn _visit_vmess(
        u: &mut UrlX,
        lints: &mut Option<Vec<Cow<'static, str>>>,
        decoded_username: &[u8],
    ) -> Result<(ServerName<'static>, PortSpec), Cow<'static, str>> {
        let (_, mut json) = crate::permissive_json(decoded_username.into())
            .map_err(|_| "VMESS area should be JSON")?;

        let host = {
            let Some(host) = json.get("add").and_then(Value::as_str) else {
                return Err(format!("Missing 'add' field in VMESS JSON {}", json).into());
            };
            ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']'))
                .map_err(|e| format!("Invalid host in VMESS JSON: {} {}", host, e))?
                .to_owned()
        };

        let port = match json
            .get("port")
            .ok_or_else(|| format!("Missing 'port' field in VMESS JSON {}", json))?
        {
            Value::String(s) => <u16 as FromStr>::from_str(s.trim())
                .map_err(|_| format!("Invalid port number in VMESS JSON: {}", s))?,
            Value::Number(n) => n
                .as_u64()
                .ok_or_else(|| format!("Invalid port number in VMESS JSON: {}", n))?
                .try_into()
                .map_err(|_| format!("Invalid port number in VMESS JSON: {}", n))?,
            other => {
                return Err(format!("Invalid port number in VMESS JSON: {}", other).into());
            }
        };

        let security = match json.get("scy").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => s,
            _ => "auto",
        };
        let transport = match json.get("net").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => s,
            _ => "tcp",
        };

        u.security.replace(security.into());
        u.transport.replace(transport.into());

        if let Some(Value::String(remark)) = json.get("ps") {
            u.id = rapidhash::v3::rapidhash_v3(remark.as_bytes());
            u.fragment.replace(remark.clone().into());
        }

        if let Some(aid) = json.get("aid") {
            match aid {
                Value::Number(n) if let Some(0) = n.as_u64() => {
                    json["aid"] = Value::String("0".to_owned())
                }
                Value::String(s) if s == "0" => {
                    //
                }
                _ => {
                    lints
                        .get_or_insert_default()
                        .push(format!("Deprecated or invalid aid in VMESS JSON: {}", aid).into());
                }
            }
        } else {
            json["aid"] = Value::String("0".to_owned());
        }

        let username = json.to_string();
        let username = base64::prelude::BASE64_URL_SAFE.encode(username);

        u.username.clear();
        u.username.push_str(username.as_str());

        Ok((host.to_owned(), PortSpec::new_with(port)))
    }
    fn _visit_ss(
        u: &mut UrlX,
        lints: &mut Option<Vec<Cow<'static, str>>>,
        decoded_username: &[u8],
    ) -> Result<(ServerName<'static>, PortSpec), Cow<'static, str>> {
        let area = str::from_utf8(decoded_username)
            .map_err(|e| format!("Invalid {} URL (non utf8): {e}", u.schema))?;

        if matches!(u.schema, SchemeX::SSR) {
            return Self::_visit_ssr(u, lints, area);
        }

        let Some((userinfo, hostport)) = area.rsplit_once('@') else {
            return Self::_visit_ssr(u, lints, area)
                .map_err(|e| format!("Either missing '@' in SS URL, or {}", e).into())
                .inspect(|_| {
                    lints
                        .get_or_insert_default()
                        .push("SSR with SS schema detected".into())
                });
        };

        let (_, (host, spec)) = super::host_port::host_port_spec(hostport.as_bytes().into())
            .map_err(|_| format!("Invalid SS URL {}", area))?;
        let (method, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));

        let userinfo =
            base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));

        u.username.clear();
        u.username.push_str(userinfo.as_str());

        u.schema = SchemeX::SS;

        u.security.replace(method.into());
        u.transport.replace("".into());

        Ok((host.to_owned(), spec.clone()))
    }
    fn _visit_ssr(
        u: &mut UrlX,
        lints: &mut Option<Vec<Cow<'static, str>>>,
        decoded_username: &str,
    ) -> Result<(ServerName<'static>, PortSpec), Cow<'static, str>> {
        let parts: Vec<&str> = decoded_username.splitn(6, ':').collect();

        let &[raw_host, raw_port, _protocol, method, _obfs, raw_password] = parts.as_slice() else {
            return Err(format!("Invalid SSR URL {}", decoded_username).into());
        };

        let host = ServerName::try_from(raw_host).map_err(|e| {
            format!(
                "Invalid host in SSR URL: {} {} ({e})",
                raw_host, decoded_username
            )
        })?;
        let port = parts[1]
            .parse::<u16>()
            .map_err(|_| format!("Invalid port in SSR URL: {} {}", raw_port, decoded_username))?;

        u.security.replace(method.into());
        u.transport.replace("tcp".into());

        u.schema = SchemeX::SSR;

        if let Some((_, path)) = raw_password.split_once('/')
            && let Some((_, query)) = path.split_once('?')
            && let Some(remarks) = query
                .split('&')
                .flat_map(|s| s.split_once('='))
                .find_map(|(k, v)| (k == "remarks").then_some(v))
        {
            'block: {
                let Ok(decoded) =
                    base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(remarks.trim_end_matches('='))
                else {
                    lints.get_or_insert_default().push(
                        format!("Unable to decode remarks in SSR URL: {}", decoded_username).into(),
                    );
                    break 'block;
                };
                let fragment = String::from_utf8_lossy(&decoded);

                u.fragment
                    .replace(urlencoding::encode(fragment.as_ref()).into());
            }
        }
        Ok((host.to_owned(), PortSpec::new_with(port)))
    }

    fn _visit_line(line: Line<'a>) -> Option<Line<'static>> {
        // first deconstruct
        let Line {
            row,
            url: Data::Url(mut url),
            mut wrn,
            ..
        } = line
        else {
            return None;
        };

        if let UrlX {
            schema: SchemeX::Unknown(s),
            ..
        } = &url
        {
            wrn.get_or_insert_default()
                .push(format!("Unknown protocol schema: {s}").into());
        }

        if let UrlX {
            schema: SchemeX::SS,
            password: None,
            host: Some(_),
            port: Some(_),
            username,
            ..
        } = &mut url
        {
            if let Ok(uuid) = uuid::Uuid::from_str(username.as_str()) {
                let uuid = uuid.to_string();
                username.clear();
                username.push_str(uuid.as_str());
                wrn.get_or_insert_default()
                    .push("VLESS with trucated schema detected (UUID instead of base64)".into());
                url.schema = SchemeX::Vless;
            }

            // ShadowSocks cannot have query parameter "security" with value "reality"
            if let Some("reality") = url.get_query_param("security") {
                wrn.get_or_insert_default()
                    .push("VLESS with truncated schema detected (security=reality)".into());
                url.schema = SchemeX::Vless;
            }
        }

        if let Some(userinfo) = url.has_only_userinfo().map(str::trim_ascii_start) {
            let area: Cow<'_, _> = percent_encoding::percent_decode_str(userinfo).into();
            let area = area.trim_end_with(|c| c.is_whitespace() || c == '=');
            let Ok(area) = base64::prelude::BASE64_STANDARD_NO_PAD
                .decode(area)
                .or_else(|_| base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(area))
            else {
                let schema = url.schema.clone();
                return Some(Line {
                    row,
                    url: Data::Url(url),
                    wrn,
                    err: Some(format!("Failed to decode {} URL body", schema).into()),
                });
            };

            let (host, port) = if area.starts_with_str("{") {
                match Self::_visit_vmess(&mut url, &mut wrn, area.as_slice()) {
                    Ok((host, port)) => (host, port),
                    Err(e) => {
                        return Some(Line {
                            row,
                            url: Data::Url(url),
                            wrn,
                            err: Some(e),
                        });
                    }
                }
            } else {
                match Self::_visit_ss(&mut url, &mut wrn, area.as_slice()) {
                    Ok((host, port)) => (host, port),
                    Err(e) => {
                        return Some(Line {
                            row,
                            url: Data::Url(url),
                            wrn,
                            err: Some(e),
                        });
                    }
                }
            };

            url.host.replace(host);
            url.port.replace(port);
        }

        let (host, port) = if let Some(host) = url.host.as_ref()
            && let Some(port) = url.port.as_ref()
        {
            (host, port)
        } else {
            let schema = url.schema.clone();
            return Some(Line {
                row,
                url: Data::Url(url),
                wrn,
                err: Some(format!("Invalid {} URL (missing host or port)", schema).into()),
            });
        };

        // check IP address
        if let ServerName::IpAddress(IpAddr::V4(ip)) = host {
            let ip = std::net::Ipv4Addr::from_octets(*ip.as_ref());
            'block: {
                let err = if ip.is_broadcast() {
                    "Broadcast IP address detected"
                } else if ip.is_loopback() {
                    "Loopback IP address detected"
                } else if ip.is_private() {
                    "Private IP address detected"
                } else if ip.is_unspecified() {
                    "Unspecified IP address detected"
                } else {
                    break 'block;
                };

                return Some(Line {
                    row,
                    url: Data::Url(url),
                    wrn,
                    err: Some(err.into()),
                });
            }
        } else if let ServerName::IpAddress(IpAddr::V6(ip)) = host {
            let ip = std::net::Ipv6Addr::from_octets(*ip.as_ref());
            'block: {
                let err = if ip.is_loopback() {
                    "Loopback IP address detected"
                } else if ip.is_unspecified() {
                    "Unspecified IP address detected"
                } else {
                    break 'block;
                };

                return Some(Line {
                    row,
                    url: Data::Url(url),
                    wrn,
                    err: Some(err.into()),
                });
            }
        }

        if url.id == 0 {
            let mut hasher =
                rapidhash::v3::RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);

            if let Some(ref p) = url.password {
                hasher.write(p.as_bytes());
            }
            match host.to_str() {
                Cow::Borrowed(host) => hasher.write(host.as_bytes()),
                Cow::Owned(host) => hasher.write(host.as_bytes()),
            };
            hasher.write(port.to_string().as_bytes());

            if let Some(ref path) = url.path {
                hasher.write(path.as_bytes());
            }

            if let Some(q) = url.query_string() {
                hasher.write(q.as_bytes());
            }

            url.id = hasher.finish();
        }

        Some(Line {
            row,
            url: Data::Url(url),
            wrn,
            err: None,
        })
    }

    pub(crate) fn visited(self) -> Lines<'static> {
        let mut visited_lines: Vec<Line<'static>> = self
            .inner
            .into_par_iter()
            .flat_map(|s| Self::_visit_line(s))
            .collect();

        visited_lines.sort_by_key(|u| u.row);

        tracing::info!("Visited {} lines", visited_lines.len());
        Lines::<'static> {
            basic: match self.basic {
                Cow::Owned(ref s) => Cow::Owned(s.to_owned()),
                Cow::Borrowed(s) => Cow::Owned(s.to_owned()),
            },
            inner: visited_lines,
        }
    }
}
