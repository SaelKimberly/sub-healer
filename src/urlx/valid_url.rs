use std::{borrow::Cow, collections::HashMap, str::FromStr};

use base64::Engine;
use rustls::pki_types::ServerName;
use simd_json::derived::ValueObjectAccessTryAsScalar;

use crate::{PortDecl, urlx::RawUrlX};

use super::{HostSpec, PortSpec, SchemeX, TinyText};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UrlX {
    hashsum: u64,

    schema: SchemeX,

    /// host (may be included in username, always present)
    #[serde(with = "super::host_serde")]
    host: HostSpec,

    /// port (may be included in username, always present)
    #[serde(with = "super::port_serde")]
    port: PortSpec,

    /// username part (always present)
    username: TinyText,
    /// password (also, identity for protocols with encoded username)
    password: Option<TinyText>,
    /// path
    path: Option<TinyText>,
    /// query
    query: Vec<(TinyText, Option<TinyText>)>,
    /// fragment
    fragment: Option<TinyText>,

    /// detected transport (metadata)
    transport: Option<TinyText>,
    /// detected security (metadata)
    security: Option<TinyText>,
}

struct Extracted {
    schema: SchemeX,
    host: HostSpec,
    port: PortSpec,
    identity: TinyText,
    transport: Option<TinyText>,
    security: Option<TinyText>,
    remarks: Option<TinyText>,
}

impl UrlX {
    pub fn get_query_param<'a>(&'a self, key: &str) -> Option<&'a str> {
        self.query
            .iter()
            .find_map(|(k, v)| if k == key { v.as_deref() } else { None })
    }
    pub fn query_string(&self) -> Option<String> {
        if self.query.is_empty() {
            None
        } else {
            self.query
                .iter()
                .map(|(k, v)| {
                    if let Some(v) = v {
                        format!("{}={}", k, urlencoding::encode(v))
                    } else {
                        format!("{}=", k)
                    }
                })
                .collect::<Vec<_>>()
                .join("&")
                .into()
        }
    }

    /// Check if the url is valid for VMESS protocol config
    ///
    /// First, try to deserialize as JSON
    /// Second, validate fields
    /// Third, extract:
    /// - add field -> HostSpec
    /// - port field -> PortSpec
    /// - net field -> transport
    /// - scy field -> security
    /// - ps field -> fragment
    fn check_vmess<'a>(
        _url: &mut RawUrlX<'a>,
        s: &mut Cow<'a, [u8]>,
    ) -> Result<Option<Extracted>, Cow<'static, str>> {
        let s = s.to_mut();
        let Ok(json) = simd_json::serde::from_slice::<simd_json::BorrowedValue>(s.as_mut_slice())
        else {
            return Ok(None);
        };

        // * 1: Validate aid field
        'aid_check: {
            let e = match json.try_get_u8("aid") {
                Ok(Some(0)) => break 'aid_check,
                Ok(Some(deprecated)) => {
                    return Err(format!("found deprecated aid field: {deprecated}").into());
                }
                Ok(None) => return Err("aid field is missing".into()),
                Err(e) => e,
            };
            match json.try_get_str("aid") {
                Ok(Some("0")) => break 'aid_check,
                Ok(Some(deprecated)) => {
                    return Err(format!("found deprecated aid field: {deprecated}").into());
                }
                Ok(None) => unreachable!(),
                Err(_) => {}
            }
            return Err(format!("invalid aid field: {e}").into());
        }

        // ? 1: Extract hostspec
        let hostspec: HostSpec = {
            let host = json
                .try_get_str("add")
                .map_err(|e| format!("VMESS has invalid add field: {e}"))?
                .ok_or("add field is missing")?;
            if let Some(host) = host.strip_prefix('[') {
                let host = host
                    .strip_suffix(']')
                    .ok_or("invalid add field (missing closing bracket in IPv6 address)")?;
                std::net::Ipv6Addr::from_str(host)
                    .map(HostSpec::from)
                    .map_err(|e| format!("invalid add field: {e}"))?
            } else {
                ServerName::try_from(host)
                    .map(|s| s.to_owned())
                    .map_err(|e| format!("invalid add field: {e}"))?
            }
        };

        // ? 2: Extract portspec
        let portspec: PortSpec = {
            let port = 'block: {
                let e = match json.try_get_u16("port") {
                    Ok(Some(port)) => break 'block Ok(port),
                    Ok(None) => return Err("port field is missing".into()),
                    Err(e) => e,
                };
                match json.try_get_str("port") {
                    Ok(Some(port)) => break 'block port.parse::<u16>(),
                    Ok(None) => unreachable!(),
                    Err(_) => {}
                };
                return Err(format!("invalid port field: {e}").into());
            };
            port.map(PortSpec::new_with)
                .map_err(|e| format!("invalid port field: {e}"))?
        };

        // ? 3: Extract username
        let identity: TinyText = json
            .try_get_str("id")
            .map_err(|e| format!("invalid id field: {e}"))?
            .ok_or("VMESS has no id field")?
            .into();

        // ? 4: Extract transport
        let transport: TinyText = json
            .try_get_str("net")
            .map_err(|e| format!("invalid net field: {e}"))?
            .filter(|s| !s.is_empty())
            .unwrap_or("tcp")
            .into();

        // ? 5: Extract security
        let security: TinyText = json
            .try_get_str("scy")
            .map_err(|e| format!("invalid scy field: {e}"))?
            .filter(|s| !s.is_empty())
            .unwrap_or("auto")
            .into();

        // ? 6: Extract fragment
        let remarks = json
            .try_get_str("ps")
            .map_err(|e| format!("invalid ps field: {e}"))?
            .map(|s| s.trim_matches('"'))
            .and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(TinyText::from(s))
                }
            });

        Ok(Some(Extracted {
            schema: SchemeX::Vmess,
            host: hostspec,
            port: portspec,
            identity,
            transport: Some(transport),
            security: Some(security),
            remarks,
        }))
    }

    fn _default_hostport(hostport: &str) -> Result<(HostSpec, PortSpec), Cow<'static, str>> {
        let (tail, (host, port)) = crate::utils::host_port_spec(hostport.as_bytes().into())
            .map_err(|e| format!("Invalid hostport: {hostport}: {e}"))?;
        if !tail.is_empty() {
            return Err(format!(
                "Invalid hostport: {hostport} (non-empty tail found: {})",
                unsafe { str::from_utf8_unchecked(tail.into_fragment()) }
            )
            .into());
        }
        Ok((host.to_owned(), port))
    }

    fn check_ss<'a>(
        url: &mut RawUrlX<'a>,
        s: &mut Cow<'a, [u8]>,
    ) -> Result<Option<Extracted>, Cow<'static, str>> {
        let area = str::from_utf8(s)
            .map_err(|e| format!("Url body (base64-decoded) is not valid UTF-8: {e}"))?;
        let Some((userinfo, hostport)) = area.rsplit_once('@') else {
            return Ok(None);
        };

        let (hostspec, portspec) = Self::_default_hostport(hostport)?;

        let (method, _password) = userinfo
            .split_once(':')
            .ok_or_else(|| format!("invalid userinfo: {userinfo}"))?;
        let remarks = url
            .fragment()
            .map_err(|e| format!("invalid fragment: {e}"))?;

        Ok(Some(Extracted {
            schema: SchemeX::SS,
            host: hostspec,
            port: portspec,
            identity: base64::prelude::BASE64_URL_SAFE.encode(userinfo).into(),
            transport: Some(TinyText::new_const()),
            security: Some(method.into()),
            remarks,
        }))
    }
    fn check_ssr<'a>(
        _url: &mut RawUrlX<'a>,
        s: &mut Cow<'a, [u8]>,
    ) -> Result<Option<Extracted>, Cow<'static, str>> {
        let area = str::from_utf8(s)
            .map_err(|e| format!("Url body (base64-decoded) is not valid UTF-8: {e}"))?;
        let parts: Vec<&str> = area.splitn(6, ':').collect();

        let &[raw_host, raw_port, _protocol, method, _obfs, raw_password] = parts.as_slice() else {
            return Ok(None);
        };
        let hostspec = ServerName::try_from(raw_host)
            .map_err(|e| format!("invalid host: {e}"))?
            .to_owned();
        let portspec = raw_port
            .parse::<u16>()
            .map(PortSpec::new_with)
            .map_err(|e| format!("invalid port: {e}"))?;

        let (identity, remarks) = if let Some((raw_password, path)) = raw_password.split_once('/') {
            let remarks = if let Some((_, query)) = path.split_once('?')
                && let Some(remarks) = query
                    .split('&')
                    .flat_map(|s| s.split_once('='))
                    .find_map(|(k, v)| (k == "remarks").then_some(v))
            {
                let Ok(decoded) =
                    base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(remarks.trim_end_matches('='))
                else {
                    return Err(format!("invalid remarks: {remarks}").into());
                };
                let fragment = String::from_utf8_lossy(&decoded);
                let decoded = urlencoding::decode_binary(fragment.as_bytes());
                let decoded = String::from_utf8_lossy(&decoded);
                Some(TinyText::from(decoded.as_ref()))
            } else {
                None
            };

            (TinyText::from(raw_password), remarks)
        } else {
            (TinyText::from(raw_password), None)
        };

        Ok(Some(Extracted {
            schema: SchemeX::SSR,
            host: hostspec,
            port: portspec,
            identity,
            transport: Some("tcp".into()),
            security: Some(method.into()),
            remarks,
        }))
    }
    fn check_mtproto<'a>(
        _url: &mut RawUrlX<'a>,
        s: &mut Cow<'a, [u8]>,
    ) -> Result<Option<Extracted>, Cow<'static, str>> {
        let unparsed = unsafe { std::str::from_utf8_unchecked(s) };
        // ? Custom logic for MTProto links
        if let Some(query_raw) = unparsed.strip_prefix("t.me/proxy?") {
            let query_pairs = query_raw
                .split('&')
                .map(|s| {
                    s.split_once('=')
                        .map(|(k, v)| -> Result<_, std::string::FromUtf8Error> {
                            Ok((
                                k,
                                if v.is_empty() {
                                    None
                                } else {
                                    let v = urlencoding::decode(v)?;
                                    Some(TinyText::from(v))
                                },
                            ))
                        })
                        .unwrap_or_else(|| Ok((s, None)))
                })
                .collect::<Result<HashMap<_, _>, _>>()
                .map_err(|e| format!("invalid query: {e}"))?;

            let hostspec: HostSpec = {
                let host = query_pairs
                    .get("server")
                    .ok_or("invalid query: missing server")?
                    .as_ref()
                    .ok_or("invalid query: server is empty")?;

                if let Some(host) = host.strip_prefix('[') {
                    let host = host
                        .strip_suffix(']')
                        .ok_or("invalid query: missing IPv6 closing bracket in server")?;
                    let addr = std::net::Ipv6Addr::from_str(host).map_err(|e| {
                        format!("invalid query: invalid IPv6 address in server: {e}")
                    })?;
                    ServerName::from(addr)
                } else {
                    ServerName::try_from(host.as_str())
                        .map_err(|e| format!("invalid query: invalid host in server: {e}"))?
                        .to_owned()
                }
            };

            let portspec = {
                let port = query_pairs
                    .get("port")
                    .ok_or("invalid query: missing port")?
                    .as_ref()
                    .ok_or("invalid query: port is empty")?
                    .parse::<u16>()
                    .map_err(|e| format!("invalid query: invalid port: {e}"))?;
                PortSpec::new_with(port)
            };

            let identity = query_pairs
                .get("secret")
                .ok_or("invalid query: missing secret")?
                .as_ref()
                .ok_or("invalid query: secret is empty")?
                .clone();

            Ok(Some(Extracted {
                schema: SchemeX::MTProto,
                host: hostspec,
                port: portspec,
                identity,
                transport: Some("tcp".into()),
                security: Some(TinyText::new_const()),
                remarks: None,
            }))
        } else {
            Ok(None)
        }
    }

    fn check_vless_url(u: &mut RawUrlX<'_>) -> Result<Option<Extracted>, Cow<'static, str>> {
        let identity = if let Ok(uuid) = uuid::Uuid::from_str(u.userinfo) {
            TinyText::from(uuid.to_string())
        } else {
            TinyText::from(u.userinfo)
        };
        let Some((hostspec, portspec)) = u.hostport()? else {
            return Ok(None);
        };
        let query = u.query().map_err(|e| format!("invalid query: {e}"))?;
        let security = query
            .iter()
            .find_map(|(k, v)| if k == "security" { v.as_deref() } else { None })
            .map(TinyText::from);
        let transport = query
            .iter()
            .find_map(|(k, v)| if k == "type" { v.as_deref() } else { None })
            .map(TinyText::from);
        let remarks = u.fragment().map_err(|e| format!("invalid fragment: {e}"))?;

        Ok(Some(Extracted {
            schema: SchemeX::Vless,
            host: hostspec,
            port: portspec,
            identity,
            transport,
            security,
            remarks,
        }))
    }

    fn check_ss_url(u: &mut RawUrlX<'_>) -> Result<Option<Extracted>, Cow<'static, str>> {
        if let Ok(s) = urlencoding::decode(u.userinfo)
            && let Ok(_) = uuid::Uuid::from_str(s.as_ref())
        {
            Self::check_vless_url(u)
        } else {
            todo!()
        }
    }

    fn parse_with_no_id(raw: &mut RawUrlX<'_>) -> Result<Self, Cow<'static, str>> {
        if let Some(mut userinfo) = raw
            .userinfo_only(raw.schema != SchemeX::MTProto, true)
            .map_err(|e| format!("Url contains userinfo only, but it cannot be decoded: {e}"))?
        {
            if raw.schema == SchemeX::MTProto {
                let Extracted {
                    schema: extracted_schema,
                    host,
                    port,
                    identity,
                    transport,
                    security,
                    remarks: fragment,
                } = match Self::check_mtproto(raw, &mut userinfo) {
                    Ok(Some(extracted)) => extracted,
                    Ok(None) => return Err("invalid MTProto link".into()),
                    Err(e) => return Err(e),
                };

                let host_repr = TinyText::from(host.to_str().as_ref());
                let port_repr = TinyText::from(port.first().unwrap().to_string());

                return Ok(UrlX {
                    hashsum: 0,
                    schema: extracted_schema,
                    host,
                    port,
                    username: "t.me".into(),
                    password: Some(identity.clone()),
                    path: Some("proxy".into()),
                    query: vec![
                        ("server".into(), Some(host_repr)),
                        ("port".into(), Some(port_repr)),
                        ("secret".into(), Some(identity)),
                    ],
                    fragment,
                    transport,
                    security,
                });
            }

            let Extracted {
                schema: extracted_schema,
                host,
                port,
                identity,
                transport,
                security,
                remarks: fragment,
            } = 'block: {
                let e1 = match Self::check_vmess(raw, &mut userinfo) {
                    Ok(Some(extracted)) => break 'block extracted,
                    Ok(None) => None,
                    Err(e) => Some(e),
                };
                let e3 = match Self::check_ssr(raw, &mut userinfo) {
                    Ok(Some(extracted)) => break 'block extracted,
                    Ok(None) => None,
                    Err(e) => Some(e),
                };
                let e2 = match Self::check_ss(raw, &mut userinfo) {
                    Ok(Some(extracted)) => break 'block extracted,
                    Ok(None) => None,
                    Err(e) => Some(e),
                };

                let errors = [e1, e2, e3]
                    .iter()
                    .flatten()
                    .map(Cow::as_ref)
                    .collect::<Vec<_>>()
                    .join(", ");
                let errors = if errors.is_empty() {
                    "all parsing attempts failed"
                } else {
                    errors.as_str()
                };

                return Err(format!(
                    "No matching schema for userinfo: {}: {errors}",
                    String::from_utf8_lossy(&userinfo)
                )
                .into());
            };

            if raw.schema != extracted_schema {
                tracing::warn!(
                    "schema mismatch: {} (raw) != {} (extracted)",
                    raw.schema,
                    extracted_schema
                );
            }

            return Ok(Self {
                hashsum: 0,
                schema: extracted_schema,
                host,
                port,
                username: raw.userinfo.into(),
                password: Some(identity),
                path: None,
                query: vec![],
                fragment,
                transport,
                security,
            });
        }

        let mut identity: Option<TinyText> = None;

        let extracted_schema = if matches!(raw.schema, SchemeX::SS)
            && let Ok(uuid) = uuid::Uuid::from_str(&raw.userinfo)
        {
            identity.replace(uuid.to_string().into());
            SchemeX::Vless
        } else {
            raw.schema.clone()
        };

        if raw.schema != extracted_schema {
            tracing::warn!(
                "schema mismatch: {} (raw) != {} (extracted)",
                raw.schema,
                extracted_schema
            );
        }

        let (host, port): (HostSpec, PortSpec) = {
            let hostport = raw.hostport.ok_or("host:port not found")?;

            let (tail, (host, port)) = crate::utils::host_port_spec(hostport.as_bytes().into())
                .map_err(|_| format!("invalid host:port: {hostport}"))?;
            if !tail.is_empty() {
                return Err(format!(
                    "host:port has unexpected tail: {}",
                    String::from_utf8_lossy(tail.into_fragment())
                )
                .into());
            }
            (host.to_owned(), port)
        };

        let (username, password) = if let Some((user, pass)) = raw.userinfo.split_once(':') {
            (TinyText::from(user), Some(TinyText::from(pass)))
        } else {
            (raw.userinfo.into(), None)
        };

        let query = raw.query().map_err(|e| format!("invalid query: {e}"))?;

        let transport = if matches!(
            raw.schema,
            SchemeX::TUIC | SchemeX::Hysteria | SchemeX::Hysteria2
        ) {
            Some(TinyText::from("quic"))
        } else {
            query
                .iter()
                .find_map(|(k, v)| if k == "type" { v.as_deref() } else { None })
                .map(TinyText::from)
        };

        let security = query
            .iter()
            .find_map(|(k, v)| if k == "security" { v.as_deref() } else { None })
            .map(TinyText::from);

        Ok(Self {
            hashsum: 0,
            schema: raw.schema.clone(),
            host,
            port,
            username,
            password,
            path: raw.path().map_err(|e| format!("invalid path: {e}"))?,
            query,
            fragment: raw
                .fragment()
                .map_err(|e| format!("invalid fragment: {e}"))?,
            transport,
            security,
        })
    }

    pub fn parse(s: &str) -> Result<Self, Cow<'static, str>> {
        let mut raw = super::RawUrlX::from(s);
        let mut url = Self::parse_with_no_id(&mut raw)?;

        let id = {
            let UrlX {
                schema,
                username,
                password,
                host,
                port,
                transport,
                security,
                ..
            } = &url;
            let mut hasher =
                rapidhash::v3::RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);

            let identity = match schema {
                SchemeX::Vmess | SchemeX::SSR | SchemeX::MTProto => password.as_ref().unwrap(),
                _ => username,
            };
            if matches!(schema, SchemeX::Vless | SchemeX::Vmess)
                && let Ok(uuid) = uuid::Uuid::from_str(username)
            {
                hasher.write(uuid.as_bytes());
            } else if let Some(identity) = password {
                hasher.write(identity.as_bytes());
            } else {
                hasher.write(username.as_bytes());
            }

            hasher.write(host.to_str().as_bytes());
            for port_decl in port.iter_raw() {
                match port_decl {
                    PortDecl::Single(p) => hasher.write(&p.to_le_bytes()),
                    PortDecl::Range(r) => {
                        hasher.write(&r.start.to_le_bytes());
                        hasher.write(&r.end.to_le_bytes());
                    }
                }
            }
            if let Some(t) = transport.as_ref() {
                hasher.write(t.as_bytes());
            }
            if let Some(s) = security.as_ref() {
                hasher.write(s.as_bytes());
            }

            hasher.finish()
        };
        url.hashsum = id;
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess() {
        let url = "vmess://eyJhZGQiOiI4MDk1OTc4YS00Y2Y4LTM2NjgtYmRmMi00YmY3YmQxNzkwODYub25lcGx1cy5wdWIiLCJhaWQiOiIwIiwiaWQiOiI0NmNmY2ZlMS1lNDUwLTQ1OWQtYTNhYi05NDA2MDExYWIzZWIiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6ODAsInBzIjoiXCJYWCDwn4-z77iPIOKUhyBWTUVTUy1XUy1OVExTIOKUhyBOb25lXCIiLCJzY3kiOiJhdXRvIiwidiI6IjIifQ==";
        let url = UrlX::parse(url).unwrap();

        eprintln!("{:?}", url);
    }

    #[test]
    fn test_ssr() {
        let url = "ssr://MTA3LjE1MS4xODIuMjUzOjgwODA6b3JpZ2luOnJjNC1tZDU6cGxhaW46TVRSbVJsQnlZbVY2UlROSVJGcDZjMDFQY2pZLz9ncm91cD1VMU5TVUhKdmRtbGtaWEkmcmVtYXJrcz04Si1IdXZDZmg3Z2dVMU5TTGVlLWp1V2J2UzFPUnVpbm8tbVVnZWlIcXVXSXR1V0pweTFEYUdGMFIxQlVMVlJwYTFSdmF5MVpiM1ZVZFdKbExURXdOeTR4TlRFdU1UZ3lMakkxTXpvNE1EZ3cmb2Jmc3BhcmFtPSZwcm90b3BhcmFtPQ";
        let url = UrlX::parse(url).unwrap();

        eprintln!("{:?}", url);
    }

    #[test]
    fn test_ss() {
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTowZmFiOTAxZGUxOWQ1NDE5ZGZjN2JiNTQ5NGEzYzBlZkBjbnZpcDAxLjg4YTU4MTc1NTI3MDEyNC45NjA1MGZhNC4zZHlmazIuY29tOjEzOTA4#日本高速防墙节点-购买网址：ct77.me";
        let raw = RawUrlX::from(url);
        eprintln!("{:?}", raw);

        let url = UrlX::parse(url).unwrap();

        eprintln!("{:?}", url);
    }

    #[test]
    fn test_mtproto() {
        let url = "https://t.me/proxy?server=77.72.80.83&port=9443&secret=eeNEgYdJvXrFGRMCIMJdCQ";
        let raw = RawUrlX::from(url);

        eprintln!("{:?}", raw);

        let url = UrlX::parse(url).unwrap();

        eprintln!("{:?}", url);
    }
}
