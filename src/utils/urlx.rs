use std::{borrow::Cow, convert::Infallible, fmt::Display, ops::Range, str::FromStr};

use crate::{PortSpec, Unescaper};
use base64::Engine;
use bstr::ByteSlice;
use rustls::pki_types::{IpAddr, ServerName};
use serde_json::Value;
use smartstring::{LazyCompact, SmartString};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum SchemeX {
    Vless,
    Vmess,
    Hysteria,
    Hysteria2,
    SS,
    SSR,
    Trojan,
    TUIC,
    Warp,
    AnyTLS,
    Unknown(SmartString<LazyCompact>),
}

impl SchemeX {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::SS => "ss",
            Self::SSR => "ssr",
            Self::Hysteria2 => "hy2",
            Self::Hysteria => "hy",
            Self::Trojan => "trojan",
            Self::TUIC => "tuic",
            Self::Warp => "warp",
            Self::AnyTLS => "anytls",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for SchemeX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SchemeX {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let r = match s.strip_suffix("://").unwrap_or(s) {
            "vless" => SchemeX::Vless,
            "vmess" => SchemeX::Vmess,
            "shadowsocks" | "ss" => SchemeX::SS,
            "ssr" => SchemeX::SSR,
            "hhysteria2" | "hysteria2" | "hhy2" | "hy2" => SchemeX::Hysteria2,
            "hhysteria" | "hysteria" | "hhy" | "hy" => SchemeX::Hysteria,
            "trojan" => SchemeX::Trojan,
            "tuic" => SchemeX::TUIC,
            "warp" => SchemeX::Warp,
            "anytls" => SchemeX::AnyTLS,
            _ => SchemeX::Unknown(s.into()),
        };
        Ok(r)
    }
}

/// Parsed V2ray URL.
///
/// Note, that, based on schema, some fields may be not used in url composition:
/// they may be extracted only for metadata.
///
/// Such as VMESS config is always contained in [Self::username] part, as Base64 encoded JSON.
/// Also, SSR config is always contained in [Self::username] part, as colon-separated string.
/// So, [Self::host], [Self::port], for these, will not be included when [Self::to_v2ray_url] is called.
///
/// Why not use `url::Url`? Because of VMESS/SSR configs bodies will be parsed as hostname (DNS name),
/// and in the middle of processing, it will be turned to lower-case strings, which will completely broke Base64 encoding.
#[derive(Debug, Clone, PartialEq)]
pub struct UrlX {
    /// hash of unique connection-defining url components
    pub(crate) id: u64,
    /// protocol schema
    pub(crate) schema: SchemeX,
    /// username part (always present)
    pub(crate) username: String,
    /// password
    pub(crate) password: Option<SmartString<LazyCompact>>,
    /// host (may be included in username)
    pub(crate) host: Option<ServerName<'static>>,
    /// port (may be included in username)
    pub(crate) port: Option<PortSpec>,
    /// path
    pub(crate) path: Option<String>,
    /// query
    pub(crate) query: Vec<(SmartString<LazyCompact>, Option<SmartString<LazyCompact>>)>,
    /// fragment
    pub(crate) fragment: Option<SmartString<LazyCompact>>,
    // used transport (metadata, may be not included in url)
    pub(crate) transport: Option<SmartString<LazyCompact>>,
    // used security (metadata, may be not included in url)
    pub(crate) security: Option<SmartString<LazyCompact>>,
}

impl UrlX {
    pub fn host_str(&self) -> String {
        self.host
            .as_ref()
            .map(ServerName::to_str)
            .unwrap_or(Cow::Borrowed(""))
            .into_owned()
    }

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
    pub const fn has_only_userinfo(&self) -> Option<&str> {
        match self {
            Self {
                schema: _,
                username: s,
                password: None,
                host: None,
                port: None,
                path: None,
                query: q,
                ..
            } if q.is_empty() => Some(s.as_str()),
            _ => None,
        }
    }

    fn _visit_vmess(
        &mut self,
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

        self.security.replace(security.into());
        self.transport.replace(transport.into());

        if let Some(Value::String(remark)) = json.get("ps") {
            self.id = rapidhash::v3::rapidhash_v3(remark.as_bytes());
            self.fragment.replace(remark.clone().into());
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

        self.username.clear();
        self.username.push_str(username.as_str());

        Ok((host.to_owned(), PortSpec::new_with(port)))
    }

    fn _visit_ss(
        &mut self,
        lints: &mut Option<Vec<Cow<'static, str>>>,
        decoded_username: &[u8],
    ) -> Result<(ServerName<'static>, PortSpec), Cow<'static, str>> {
        let area = str::from_utf8(decoded_username)
            .map_err(|e| format!("Invalid {} URL (non utf8): {e}", self.schema))?;

        if matches!(self.schema, SchemeX::SSR) {
            return Self::_visit_ssr(self, lints, area);
        }

        let Some((userinfo, hostport)) = area.rsplit_once('@') else {
            return Self::_visit_ssr(self, lints, area)
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

        self.username.clear();
        self.username.push_str(userinfo.as_str());

        self.schema = SchemeX::SS;

        self.security.replace(method.into());
        self.transport.replace("".into());

        Ok((host.to_owned(), spec.clone()))
    }

    fn _visit_ssr(
        &mut self,
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

        self.security.replace(method.into());
        self.transport.replace("tcp".into());

        self.schema = SchemeX::SSR;

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

                self.fragment
                    .replace(urlencoding::encode(fragment.as_ref()).into());
            }
        }
        Ok((host.to_owned(), PortSpec::new_with(port)))
    }

    pub fn normalize(
        &mut self,
        lints: &mut Option<Vec<Cow<'static, str>>>,
    ) -> Result<(), Cow<'static, str>> {
        if let SchemeX::Unknown(u) = &self.schema {
            lints
                .get_or_insert_default()
                .push(format!("Unknown protocol schema: {u}").into());
        }

        if let UrlX {
            schema: SchemeX::SS,
            password: None,
            host: Some(_),
            port: Some(_),
            username,
            ..
        } = self
        {
            if let Ok(uuid) = uuid::Uuid::from_str(username.as_str()) {
                let uuid = uuid.to_string();
                username.clear();
                username.push_str(uuid.as_str());
                lints
                    .get_or_insert_default()
                    .push("VLESS with trucated schema detected (UUID instead of base64)".into());
                self.schema = SchemeX::Vless;
            }

            // ShadowSocks cannot have query parameter "security" with value "reality"
            if let Some("reality") = self.get_query_param("security") {
                lints
                    .get_or_insert_default()
                    .push("VLESS with truncated schema detected (security=reality)".into());
                self.schema = SchemeX::Vless;
            }
        }

        if let Some(userinfo) = self.has_only_userinfo().map(str::trim_ascii_start) {
            let area: Cow<'_, _> = percent_encoding::percent_decode_str(userinfo).into();
            let area = area.trim_end_with(|c| c.is_whitespace() || c == '=');
            let Ok(area) = base64::prelude::BASE64_STANDARD_NO_PAD
                .decode(area)
                .or_else(|_| base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(area))
            else {
                let schema = self.schema.clone();
                return Err(format!("Failed to decode {} URL body", schema).into());
            };

            let (host, port) = if area.starts_with_str("{") {
                self._visit_vmess(lints, area.as_slice())?
            } else {
                self._visit_ss(lints, area.as_slice())
                    .or_else(|_| self._visit_vmess(lints, area.as_slice()))?
            };

            self.host.replace(host);
            self.port.replace(port);
        }

        let (host, port) = if let Some(host) = self.host.as_ref()
            && let Some(port) = self.port.as_ref()
        {
            (host, port)
        } else {
            let schema = self.schema.clone();
            return Err(format!("Invalid {} URL (missing host or port)", schema).into());
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

                return Err(err.into());
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

                return Err(err.into());
            }
        }

        if self.id == 0 {
            let mut hasher =
                rapidhash::v3::RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);

            if let Some(ref p) = self.password {
                hasher.write(p.as_bytes());
            }

            hasher.write(host.to_str().as_bytes());
            for (i, spec) in port.iter_raw().enumerate() {
                if i > 0 {
                    hasher.write(b",");
                }
                match spec {
                    crate::PortDecl::Single(p) => {
                        hasher.write(&p.to_le_bytes() as &[u8]);
                    }
                    crate::PortDecl::Range(Range { start, end }) => {
                        hasher.write(&start.to_le_bytes() as &[u8]);
                        hasher.write(&end.to_le_bytes() as &[u8]);
                    }
                }
            }

            if let Some(ref path) = self.path {
                hasher.write(path.as_bytes());
            }

            if let Some(q) = self.query_string() {
                hasher.write(q.as_bytes());
            }

            self.id = hasher.finish();
        }

        Ok(())
    }
}

impl Display for UrlX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.schema, self.username)?;
        if matches!(self.schema, SchemeX::Vmess | SchemeX::SSR) {
            return Ok(());
        }
        if let Some(p) = &self.password {
            write!(f, ":{}", p)?;
        }
        if let Some(h) = &self.host {
            write!(f, "@{}", h.to_str())?;
        }
        if let Some(p) = &self.port {
            write!(f, ":{}", p)?;
        }
        if let Some(p) = &self.path {
            write!(f, "/{}", p)?;
        }
        if let Some(q) = &self.query_string() {
            write!(f, "?{}", q)?;
        }
        if let Some(frag) = &self.fragment {
            write!(f, "#{}", frag)?;
        }
        Ok(())
    }
}

impl FromStr for UrlX {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // ? 1. Extract and detect schema
        // ==============================
        let (schema, mut rest) = s.split_once("://").expect("Missing schema");

        let mut result = UrlX {
            id: 0,
            schema: match schema {
                "vless" => SchemeX::Vless,
                "vmess" => SchemeX::Vmess,
                "ss" => SchemeX::SS,
                "ssr" => SchemeX::SSR,
                "hhysteria" | "hysteria" | "hhy" | "hy" => SchemeX::Hysteria,
                "hhysteria2" | "hysteria2" | "hhy2" | "hy2" => SchemeX::Hysteria2,
                "trojan" => SchemeX::Trojan,
                "tuic" => SchemeX::TUIC,
                "warp" => SchemeX::Warp,
                "anytls" => SchemeX::AnyTLS,
                _ => SchemeX::Unknown(schema.into()),
            },
            username: String::new(),
            password: None,
            host: None,
            port: None,
            path: None,
            query: Vec::new(),
            fragment: None,
            transport: None,
            security: None,
        };

        let mut result_query = None;

        // ? 2. Extract fragment
        // ==============================
        if let Some((body, frag)) = rest.split_once('#') {
            rest = body.trim_end();

            let frag = Unescaper::default()
                .enc_pct()
                .enc_uni(true)
                .chardet(true, true)
                .do_unescape(frag.as_bytes())
                .unwrap();
            let frag = frag.trim();
            let frag = frag.split_whitespace().collect::<Vec<_>>().join(" ");
            let frag = urlencoding::encode(frag.as_str());
            if !frag.is_empty() {
                result.fragment.replace(frag.into());
            }
        }

        // ? 3. Extract query
        // ==============================
        if let Some((body, query)) = rest.split_once('?') {
            rest = body;
            if !query.is_empty() {
                result_query.replace(query.to_owned());
            }
        }

        // ? 4. Extract path
        // ==============================
        if let Some((body, path)) = rest.split_once('/')
            && !body.ends_with('=')
        {
            rest = body;

            let path = if let Some((path, query)) = path.split_once('?') {
                if !query.is_empty() {
                    result_query.replace(query.to_owned());
                }
                path
            } else {
                path
            };

            if !path.is_empty() {
                result.path.replace(path.to_owned());
            }
        }

        // ? 5. Extract query
        if let Some((body, query)) = rest.split_once('&') {
            rest = body;
            if !query.is_empty() {
                result_query.replace(query.to_owned());
            }
        }

        let userinfo = if let Some((userinfo, hostport)) = rest.split_once('@') {
            let hostport = if let Some((_, hostport)) = hostport.split_once('@') {
                hostport
            } else {
                hostport
            };

            if let Ok((_, (host, port))) =
                super::host_port::host_port_spec(hostport.as_bytes().into())
            {
                result.host.replace(host.to_owned());
                result.port.replace(port);
            } else if let Ok((_, host)) = super::host_port::host(hostport.as_bytes().into()) {
                result.host.replace(host.to_owned());
            }
            userinfo
        } else {
            rest
        };

        if let Some((username, password)) = userinfo.split_once(':') {
            result.username.clear();
            result.username.push_str(username);
            result.password.replace(password.into());
        } else {
            result.username.clear();
            result.username.push_str(userinfo);
        }

        if let Some(q) = result_query.as_deref() {
            let q = q
                .replace("security=tls", "&security=tls")
                .replace("&&", "&");
            let q = q.trim_start_matches('&');

            let mut q = q
                .split('&')
                .map(|kv| {
                    kv.split_once('=')
                        .map(|(k, v)| {
                            let v = Unescaper::default()
                                .enc_pct()
                                .enc_uni(true)
                                .chardet(true, true)
                                .do_unescape(v.as_bytes())
                                .unwrap();

                            (
                                SmartString::<LazyCompact>::from(k),
                                Some(SmartString::<LazyCompact>::from(v)),
                            )
                        })
                        .unwrap_or((kv.into(), None))
                })
                .collect::<Vec<_>>();
            q.sort();
            result.query.extend_from_slice(q.as_slice());
        }

        if let UrlX {
            schema: SchemeX::Vmess | SchemeX::SS | SchemeX::SSR,
            username,
            password: None,
            host: None,
            path,
            query,
            ..
        } = &mut result
            && query.is_empty()
            && let Some(path) = path.take()
        {
            username.push('/');
            username.push_str(path.as_str());
        }

        Ok(result)
    }
}
