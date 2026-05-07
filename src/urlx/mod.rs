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
    pub fn query_string(&self) -> Option<String> {
        if self.query.is_empty() {
            None
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
