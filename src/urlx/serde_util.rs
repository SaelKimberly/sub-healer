use super::{HostSpec, PortSpec, TinyText};

#[allow(dead_code)]
pub(super) mod host_serde {
    use std::borrow::Cow;

    use serde::{Deserialize, Serialize};

    pub fn deserialize<'de, D>(d: D) -> Result<super::HostSpec, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = super::TinyText::deserialize(d)?;
        Ok(rustls::pki_types::ServerName::try_from(s.as_str())
            .map_err(|e| serde::de::Error::custom(format!("invalid server name: {e}")))?
            .to_owned())
    }

    pub fn serialize<S>(v: &super::HostSpec, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Cow::Owned(text) = v.to_str() else {
            unreachable!()
        };
        <String as Serialize>::serialize(&text, s)
    }
}

#[allow(dead_code)]
pub(super) mod port_serde {
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
