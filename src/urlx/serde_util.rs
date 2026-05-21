use super::{HostSpec, PortSpec, TinyText};

pub(crate) mod host_opt_serde {

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

    #[allow(clippy::ref_option, reason = "serde requires this")]
    pub fn serialize<S>(v: &Option<super::HostSpec>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        v.as_ref().map(|v| v.to_str()).serialize(s)
    }
}

pub(crate) mod host_serde {
    use serde::Deserialize;

    pub fn deserialize<'de, D>(d: D) -> Result<super::HostSpec, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        rustls::pki_types::ServerName::try_from(s.as_str())
            .map_err(|e| serde::de::Error::custom(format!("invalid server name: {e}")))
            .map(|h| h.to_owned())
    }

    pub fn serialize<S>(v: &super::HostSpec, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&v.to_str())
    }
}

pub(crate) mod port_opt_serde {
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
            .map_err(|e| serde::de::Error::custom(format!("invalid port spec: {e}")))?;
        Ok(Some(s))
    }

    #[allow(clippy::ref_option, reason = "serde requires this")]
    pub fn serialize<S>(v: &Option<super::PortSpec>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        v.as_ref()
            .map(std::string::ToString::to_string)
            .serialize(s)
    }
}

pub(crate) mod port_serde {

    pub fn deserialize<'de, D>(d: D) -> Result<u16, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PortVisitor;
        impl<'de> serde::de::Visitor<'de> for PortVisitor {
            type Value = u16;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a port number or string")
            }

            fn visit_u64<E>(self, v: u64) -> Result<u16, E>
            where
                E: serde::de::Error,
            {
                u16::try_from(v).map_err(|_| E::custom("port out of range"))
            }

            fn visit_str<E>(self, v: &str) -> Result<u16, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(|_| E::custom("invalid port"))
            }
        }
        d.deserialize_any(PortVisitor)
    }

    pub fn serialize<S>(v: &u16, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_u16(*v)
    }
}

pub(crate) mod port_spec_serde {
    use serde::Deserialize;

    pub fn deserialize<'de, D>(d: D) -> Result<super::PortSpec, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        s.parse()
            .map_err(|e| serde::de::Error::custom(format!("invalid port spec: {e}")))
    }

    pub fn serialize<S>(v: &super::PortSpec, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&v.to_string())
    }
}
