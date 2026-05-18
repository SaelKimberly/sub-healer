mod port_spec;
mod proto_vis;
mod schemex;
mod serde_util;
mod split_url;
mod user_info;

use std::borrow::Cow;

use base64::Engine;
use rustls::pki_types::{IpAddr, ServerName};
use serde_util::{host_serde, port_serde};

pub(crate) use user_info::UserInfo;
pub(crate) type TinyText = smartstring::SmartString<smartstring::LazyCompact>;
pub(crate) type HostSpec = rustls::pki_types::ServerName<'static>;

use crate::Unescaper;
pub(crate) use port_spec::{PortDecl, PortSpec};

pub use proto_vis::try_accept_raw;
pub(crate) use proto_vis::{
    Hysteria2Proto, ParseError, ProtoVisitor, SlipnetProto, SsProto, SsrProto, TgProto,
    TrojanProto, VlessProto, VmessProto,
};

pub use schemex::SchemeX;
pub use split_url::RawUrlX;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UrlX {
    /// hash of unique connection-defining url components
    pub(crate) uid: u64,
    /// hash of unique connection-defining url components (without specific host and port)
    /// useful for statistics about specific signature lifetime across the observed data:
    /// - frequency of each signature per hour/day
    /// - earliest and latest appearance of each signature
    pub(crate) sig: u64,

    pub(crate) schema: SchemeX,

    /// host (may be included in username, always present)
    #[serde(default, with = "host_serde")]
    pub(crate) host: Option<HostSpec>,

    /// port (may be included in username, always present)
    #[serde(default, with = "port_serde")]
    pub(crate) port: Option<PortSpec>,

    /// username part (always present)
    pub(crate) username: UserInfo,
    /// password (also, identity for protocols with encoded username)
    pub(crate) password: Option<TinyText>,
    /// path
    pub(crate) path: Option<TinyText>,
    /// query
    pub(crate) query: Vec<(TinyText, Option<TinyText>)>,
    /// fragment
    pub(crate) fragment: Option<TinyText>,

    /// detected transport (metadata)
    pub(crate) transport: Option<TinyText>,
    /// detected security (metadata)
    pub(crate) security: Option<TinyText>,
}

impl UrlX {
    pub fn host_str(&self) -> Cow<'_, str> {
        if let Some(ref host) = self.host {
            host.to_str()
        } else {
            Cow::Borrowed("")
        }
    }

    pub fn try_accept<V: ProtoVisitor>(url: &str) -> Result<Self, ParseError> {
        let url = url.into();
        let mut parsed = V::parse(&url)?;
        V::visit(&mut parsed)?;
        Ok(parsed)
    }

    #[inline]
    pub fn try_build<V: ProtoVisitor>(&self) -> Result<String, ParseError> {
        V::build(self)
    }
}

impl UrlX {
    pub fn get_query_param<'a>(&'a self, key: &str) -> Option<&'a TinyText> {
        self.query
            .iter()
            .find_map(|(k, v)| if k == key { v.as_ref() } else { None })
    }

    pub(crate) fn _safe_hostport(&self, default_port: Option<u16>) -> Result<String, ParseError> {
        let addr = match self.host {
            Some(ref addr @ ServerName::IpAddress(IpAddr::V6(_))) => format!("[{}]", addr.to_str()),
            Some(ref addr) => addr.to_str().into_owned(),
            None => return Err(ParseError::MissingHost),
        };
        self.port
            .as_ref()
            .map(ToString::to_string)
            .or_else(|| default_port.as_ref().map(ToString::to_string))
            .as_ref()
            .map_or_else(
                || Err(ParseError::MissingPort),
                |spec| Ok(format!("{}:{}", addr, spec)),
            )
    }
    pub(crate) fn _safe_userinfo(&self) -> Result<String, ParseError> {
        Ok(self
            .username
            .as_url_safe()
            .map_err(|e| ParseError::InvalidConf("username".into(), e.to_string().into()))?
            .as_str()
            .to_string())
    }

    pub fn reconstruct(&self) -> String {
        use proto_vis::*;
        let reconstructed = match self.schema {
            SchemeX::Vless => VlessProto::build(self),
            SchemeX::Tg | SchemeX::Https => TgProto::build(self),
            SchemeX::Slipnet => SlipnetProto::build(self),
            SchemeX::SlipnetEnc => SlipnetProto::build(self),
            SchemeX::Vmess | SchemeX::SSR => VmessProto::build(self),
            SchemeX::SS => SsProto::build(self),
            SchemeX::Trojan => TrojanProto::build(self),
            SchemeX::Hysteria | SchemeX::Hysteria2 => Hysteria2Proto::build(self),
            _ => return Self::reconstruct_fallback(self),
        };
        reconstructed.unwrap_or_else(|_| Self::reconstruct_fallback(self))
    }

    pub(crate) fn reconstruct_fallback(this: &Self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        write!(out, "{}://", this.schema.as_str()).unwrap();

        let username_str = this.username.as_url_safe().unwrap_or_else(|_| {
            this.username
                .as_text()
                .map(|t| t.as_str())
                .unwrap_or_default()
                .to_string()
        });
        write!(out, "{}", username_str).unwrap();

        if let Some(ref p) = this.password {
            write!(out, ":{}", p).unwrap();
        }

        if let Some(ref h) = this.host {
            write!(out, "@{}", h.to_str()).unwrap();
        }

        if let Some(ref p) = this.port {
            write!(out, ":{}", p).unwrap();
        }

        if let Some(ref path) = this.path {
            write!(out, "/{}", path).unwrap();
        }

        let query_sorted = this.build_query();
        if !query_sorted.is_empty() {
            write!(out, "?{}", query_sorted).unwrap();
        }

        if let Some(ref frag) = this.fragment {
            write!(out, "#{}", urlencoding::encode(frag)).unwrap();
        }

        out
    }

    fn build_query(&self) -> String {
        let is_mtproto = matches!(self.schema, SchemeX::Tg | SchemeX::Https);

        let mut filtered: Vec<(TinyText, Option<TinyText>)> = self
            .query
            .iter()
            .filter(|(k, v)| {
                if is_mtproto && matches!(k.as_str(), "server" | "port" | "secret") {
                    return true;
                }

                let def = match self.schema {
                    SchemeX::Vless => {
                        matches!(k.as_str(), "security" | "type" | "encryption")
                            && matches!(v.as_deref(), Some("none") | Some("tcp") | None)
                    }
                    SchemeX::Trojan | SchemeX::Hysteria | SchemeX::Hysteria2 => {
                        k.as_str() == "security" && matches!(v.as_deref(), Some("tls") | None)
                    }
                    _ => false,
                };
                !def
            })
            .cloned()
            .collect();

        if filtered.is_empty() {
            return String::new();
        }

        if is_mtproto {
            let mut core = Vec::new();
            let mut rest = Vec::new();
            for (k, v) in filtered.into_iter() {
                match k.as_str() {
                    "server" | "port" | "secret" => core.push((k, v)),
                    _ => rest.push((k, v)),
                }
            }
            rest.sort_by(|a, b| a.0.cmp(&b.0));
            core.extend(rest);
            filtered = core;
        } else {
            filtered.sort_by(|a, b| a.0.cmp(&b.0));
        }

        filtered
            .iter()
            .map(|(k, v)| {
                v.as_ref().map_or_else(
                    || format!("{}=", k),
                    |v| format!("{}={}", k, urlencoding::encode(v)),
                )
            })
            .collect::<Vec<_>>()
            .join("&")
    }
}

impl std::fmt::Display for UrlX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reconstruct())
    }
}

impl std::str::FromStr for UrlX {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw: RawUrlX = s.into();
        let schema = raw.schema.clone();
        try_accept_raw(raw).or_else(|_| {
            Ok(UrlX {
                uid: 0,
                sig: 0,
                schema,
                host: None,
                port: None,
                username: UserInfo::Text(Default::default(), Default::default()),
                password: None,
                path: None,
                query: Vec::new(),
                fragment: None,
                transport: None,
                security: None,
            })
        })
    }
}
