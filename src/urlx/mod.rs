mod parse_url;
mod port_spec;
mod schemex;
mod serde_util;
mod split_url;
mod user_info;
mod valid_url;

use serde_util::{host_serde, port_serde};

pub(crate) use user_info::UserInfo;
pub(crate) type TinyText = smartstring::SmartString<smartstring::LazyCompact>;
pub(crate) type HostSpec = rustls::pki_types::ServerName<'static>;

pub(crate) use port_spec::{PortDecl, PortSpec};
pub(crate) use schemex::SchemeX;
pub use split_url::RawUrlX;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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
        if let Some(ref spec) = self
            .port
            .as_ref()
            .map(ToString::to_string)
            .or_else(|| default_port.as_ref().map(ToString::to_string))
        {
            Ok(format!("{}:{}", addr, spec))
        } else {
            Err(ParseError::MissingPort)
        }
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
        } else {
            self.query
                .iter()
                .map(|(k, v)| {
                    v.as_ref().map_or_else(
                        || format!("{}=", k),
                        |v| format!("{}={}", k, urlencoding::encode(v)),
                    )
                })
                .collect::<Vec<_>>()
                .join("&")
                .into()
        }
    }
}
