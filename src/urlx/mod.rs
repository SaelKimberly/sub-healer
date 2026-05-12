mod parse_url;
mod port_spec;
mod schemex;
mod serde_util;
mod split_url;
mod user_info;
mod valid_url;

use base64::Engine;
use rustls::pki_types::{IpAddr, ServerName};
use serde_util::{host_serde, port_serde};

pub(crate) use user_info::UserInfo;
pub(crate) type TinyText = smartstring::SmartString<smartstring::LazyCompact>;
pub(crate) type HostSpec = rustls::pki_types::ServerName<'static>;

pub(crate) use port_spec::{PortDecl, PortSpec};
pub(crate) use schemex::SchemeX;
pub use split_url::RawUrlX;

use crate::{Unescaper, urlx::parse_url::ParseError};

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
    pub fn get_query_param<'a>(&'a self, key: &str) -> Option<&'a TinyText> {
        self.query
            .iter()
            .find_map(|(k, v)| if k == key { v.as_ref() } else { None })
    }

    fn _safe_hostport(&self, default_port: Option<u16>) -> Result<String, ParseError> {
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
    fn _safe_userinfo(&self) -> Result<String, ParseError> {
        Ok(self
            .username
            .as_url_safe()
            .map_err(|e| ParseError::InvalidConf("username".into(), e.to_string().into()))?
            .as_str()
            .to_string())
    }

    fn _reconstruct_vless(&mut self) -> Result<String, ParseError> {
        // 1: Create a URL base from the components
        // For some protocols (like VMESS, SSR, SlipNet(encrypted)), `url::Url` cannot be used, because they embed host and port into username.
        let mut url = url::Url::parse(
            format!(
                "{}://{}@{}",
                self.schema.as_str(),
                self._safe_userinfo()?,
                self._safe_hostport(None)?,
            )
            .as_str(),
        )
        .map_err(|e| ParseError::Unknown(e.into()))?;

        if let Some(ref path) = self.path {
            url.set_path(path.as_str());
        }

        if !self.query.is_empty() {
            self.query.sort_by_key(|(k, _)| k.clone());

            let mut q = url.query_pairs_mut();

            for (k, v) in &self.query {
                if let Some(v) = v {
                    q.append_pair(k, v);
                } else {
                    q.append_key_only(k);
                }
            }

            _ = q.finish();
        }
        if let Some(ref frag) = self.fragment {
            let frag = Unescaper::default()
                .enc_pct()
                .enc_uni(true)
                .chardet(true, true)
                .do_unescape(frag.as_bytes())
                .unwrap();
            let frag = frag.trim();
            let frag = frag.split_whitespace().collect::<Vec<_>>().join(" ");
            if !frag.is_empty() {
                url.set_fragment(Some(frag.as_str()));
            }
        }

        url.set_username(
            self.username
                .as_url_safe()
                .map_err(|e| ParseError::InvalidConf("username".into(), e.to_string().into()))?
                .as_str(),
        )
        .expect("username should be always present");

        Ok(url.to_string())
    }

    fn _reconstruct_tg(&self) -> Result<String, ParseError> {
        let userinfo = self
            .transport
            .as_ref()
            .and_then(|t| (t.as_str() == "socks").then_some("socks"))
            .unwrap_or("proxy");

        let secret = self
            .password
            .as_ref()
            .ok_or_else(|| ParseError::MissingConf("password".into()))?;

        let url = url::Url::parse(
            format!(
                "tg://{}?server={}&port={}&secret={}",
                userinfo,
                self.host
                    .as_ref()
                    .map(|h| h.to_str().into_owned())
                    .unwrap_or_default(),
                self.port
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
                secret
            )
            .as_str(),
        )
        .map_err(|e| ParseError::Unknown(e.into()))?;

        Ok(url.to_string())
    }

    pub fn reconstruct(&self) -> String {
        let mut this = self.clone();

        let reconstructed = match self.schema {
            SchemeX::Vless => this._reconstruct_vless(),
            SchemeX::Tg | SchemeX::Https => this._reconstruct_tg(),
            SchemeX::Slipnet => this._reconstruct_slipnet(),
            SchemeX::SlipnetEnc => this._reconstruct_slipnet_enc(),
            SchemeX::Vmess | SchemeX::SSR => this._reconstruct_embed_userinfo(),
            SchemeX::SS => this._reconstruct_ss(),
            _ => return Self::reconstruct_fallback(&this),
        };
        reconstructed.unwrap_or_else(|_| Self::reconstruct_fallback(&this))
    }

    fn _reconstruct_ss(&self) -> Result<String, ParseError> {
        let raw_username = self.username.as_raw();
        let encoded = base64::prelude::BASE64_STANDARD_NO_PAD.encode(raw_username.as_bytes());
        let hostport = self._safe_hostport(None)?;
        Ok(format!("ss://{}@{}", encoded, hostport))
    }

    fn _reconstruct_embed_userinfo(&self) -> Result<String, ParseError> {
        let username = self
            .username
            .as_url_safe()
            .map_err(|e| ParseError::InvalidUserInfo(e.to_string().into()))?;

        Ok(format!("{}://{}", self.schema.as_str(), username))
    }

    fn _reconstruct_slipnet(&self) -> Result<String, ParseError> {
        let config_data = self.username.as_raw();
        Ok(format!("slipnet://{}", config_data))
    }

    fn _reconstruct_slipnet_enc(&self) -> Result<String, ParseError> {
        let config_data = self.username.as_raw();
        Ok(format!("slipnet-enc://{}", config_data))
    }

    fn reconstruct_fallback(this: &Self) -> String {
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
