use super::{HostSpec, PortSpec, TinyText};

#[allow(dead_code)]
pub(super) mod host_serde {

    use serde::{Deserialize, Serialize};

    pub fn deserialize<'de, D>(d: D) -> Result<Option<super::HostSpec>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let Some(s) = Option::<super::TinyText>::deserialize(d)? else {
            return Ok(None);
        };

        let s = rustls::pki_types::ServerName::try_from(s.as_str())
            .map_err(|e| serde::de::Error::custom(format!("invalid server name: {e}")))?;

        Ok(Some(s.to_owned()))
    }

    pub fn serialize<S>(v: &Option<super::HostSpec>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        v.as_ref().map(|v| v.to_str()).serialize(s)
    }
}

#[allow(dead_code)]
pub(super) mod port_serde {
    use serde::{Deserialize, Serialize};

    pub fn deserialize<'de, D>(d: D) -> Result<Option<super::PortSpec>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let Some(s) = Option::<super::TinyText>::deserialize(d)? else {
            return Ok(None);
        };
        let s = s
            .parse()
            .map_err(|e| serde::de::Error::custom(format!("invalid port number: {e}")))?;
        Ok(Some(s))
    }

    pub fn serialize<S>(v: &Option<super::PortSpec>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        v.as_ref().map(|v| v.to_string()).serialize(s)
    }
}
