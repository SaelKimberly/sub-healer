use std::{convert::Infallible, fmt::Display, str::FromStr};

use crate::{PortSpec, Unescaper};
use rustls::pki_types::ServerName;
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

        Ok(result)
    }
}
