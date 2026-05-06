mod parse_url;
mod parsed;
mod port_spec;
mod schemex;
mod serde_util;
mod split_url;
mod valid_url;

use serde_util::{host_serde, port_serde};

pub(crate) type TinyText = smartstring::SmartString<smartstring::LazyCompact>;
pub(crate) type HostSpec = rustls::pki_types::ServerName<'static>;

pub(crate) use port_spec::{PortDecl, PortSpec};
pub(crate) use schemex::SchemeX;
pub use split_url::RawUrlX;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UrlX {
    hashsum: u64,

    schema: SchemeX,

    /// host (may be included in username, always present)
    #[serde(default, with = "host_serde")]
    host: Option<HostSpec>,

    /// port (may be included in username, always present)
    #[serde(default, with = "port_serde")]
    port: Option<PortSpec>,

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
