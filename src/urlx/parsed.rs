use std::borrow::Cow;

use rustls::pki_types::ServerName;

use super::{HostSpec, PortSpec, SchemeX, TinyText};

mod host_serde {
    use std::borrow::Cow;

    use serde::{Deserialize, Serialize};

    use super::*;

    pub fn deserialize<'de, D>(d: D) -> Result<ServerName<'static>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = super::TinyText::deserialize(d)?;
        Ok(ServerName::try_from(s.as_str())
            .map_err(|e| serde::de::Error::custom(format!("invalid server name: {e}")))?
            .to_owned())
    }

    pub fn serialize<S>(v: &ServerName<'static>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Cow::Owned(text) = v.to_str() else {
            unreachable!()
        };
        <String as Serialize>::serialize(&text, s)
    }
}

mod port_serde {
    use serde::{Deserialize, Serialize};

    pub fn deserialize<'de, D>(d: D) -> Result<super::PortSpec, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = super::TinyText::deserialize(d)?;
        s.parse()
            .map_err(|e| serde::de::Error::custom(format!("invalid port number: {e}")))
    }

    pub fn serialize<S>(v: &super::PortSpec, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <String as Serialize>::serialize(&v.to_string(), s)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UrlX {
    schema: SchemeX,

    /// host (may be included in username, always present)
    #[serde(with = "host_serde")]
    host: HostSpec,

    /// port (may be included in username, always present)
    #[serde(with = "port_serde")]
    port: PortSpec,

    /// username part (always present)
    username: TinyText,
    /// password
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

    fn parse(s: &str) -> Result<Self, Cow<'static, str>> {
        let mut raw = super::RawUrlX::from(s);

        #[allow(unreachable_code)]
        Ok(Self {
            schema: todo!(),
            host: todo!(),
            port: todo!(),
            username: todo!(),
            password: todo!(),
            path: todo!(),
            query: todo!(),
            fragment: todo!(),
            transport: todo!(),
            security: todo!(),
        })
    }
}
