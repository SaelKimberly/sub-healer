use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{RawUrlX, SchemeX};

use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VmessConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub uuid: String,
    pub host: String,
    pub port: String,
    pub security: Option<String>,
    pub transport: Option<String>,
    pub alter_id: Option<String>,
    pub path: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub fp: Option<String>,
    pub tls: Option<String>,
    pub net: Option<String>,
    pub remarks: Option<String>,
}

impl ProtoSpec for VmessConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let decoded = utils::decode_base64(raw.userinfo)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Vmess))?;

        let span = nom_locate::LocatedSpan::new(decoded.as_slice());
        let (_, json): (_, serde_json::Value) =
            crate::utils::permissive_json::permissive_json(span)
                .map_err(|_| ParseError::InvalidStructure(SchemeX::Vmess))?;

        let host_str = json
            .get("add")
            .and_then(|v| v.as_str())
            .ok_or(ParseError::MissingHost)?;
        let parsed_host = utils::parse_host(host_str)
            .map_err(|e| ParseError::InvalidHost(format!("{host_str}: {e}").into()))?;

        let port_val = json
            .get("port")
            .ok_or(ParseError::MissingPort)
            .and_then(|v| {
                utils::coerce_u16(v)
                    .ok_or_else(|| ParseError::InvalidPort(format!("cannot parse: {v}").into()))
            })?;

        let uuid = json
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::MissingConf("id".into()))?
            .to_string();

        let security = json
            .get("scy")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"null")
            .or_else(|| Some("auto"))
            .map(String::from);

        let net = json
            .get("net")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"null")
            .map(String::from);

        let path = json
            .get("path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        let sni = json
            .get("sni")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        let alpn = json
            .get("alpn")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"")
            .map(String::from);

        let fp = json
            .get("fp")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        let tls = json
            .get("tls")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"")
            .map(String::from);

        let alter_id = json
            .get("aid")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"" && s != &"0")
            .map(String::from);

        let remarks = json
            .get("ps")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_matches(['"', '\'']).to_string());

        let transport = net
            .clone()
            .or_else(|| json.get("type").and_then(|v| v.as_str()).map(String::from));

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            uuid,
            host: parsed_host.to_str().into_owned(),
            port: port_val.to_string(),
            security,
            transport,
            alter_id,
            path,
            sni,
            alpn,
            fp,
            tls,
            net,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        use base64::Engine as _;

        let mut map = serde_json::Map::new();
        map.insert("add".into(), serde_json::Value::String(self.host.clone()));
        map.insert("port".into(), serde_json::Value::String(self.port.clone()));
        map.insert("id".into(), serde_json::Value::String(self.uuid.clone()));

        if let Some(ref v) = self.security {
            map.insert("scy".into(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.net {
            map.insert("net".into(), serde_json::Value::String(v.clone()));
        } else if let Some(ref v) = self.transport {
            map.insert("net".into(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.path {
            map.insert("path".into(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.sni {
            map.insert("sni".into(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.alpn {
            map.insert("alpn".into(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.fp {
            map.insert("fp".into(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.tls {
            map.insert("tls".into(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.alter_id {
            map.insert("aid".into(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.remarks {
            map.insert("ps".into(), serde_json::Value::String(v.clone()));
        }

        let json = serde_json::Value::Object(map);
        let json_str = serde_json::to_string(&json)
            .map_err(|e| ParseError::Unknown(e.into()))?;
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        Ok(format!("vmess://{encoded}"))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Vmess
    }

    fn host(&self) -> Option<&str> {
        Some(&self.host)
    }

    fn port(&self) -> Option<&str> {
        Some(&self.port)
    }

    fn remarks(&self) -> Option<&str> {
        self.remarks.as_deref()
    }

    fn cred_hash(&self) -> u64 {
        utils::compute_cred_hash(None, None, &self.uuid, &self.uuid)
    }

    fn sig(&self) -> u64 {
        let v = self.sig_cache.get_or_init(|| {
            let val = self.compute_sig();
            NonZeroU64::new(val).unwrap_or(NonZeroU64::MIN)
        });
        v.get()
    }

    fn set_sig_cache(&self, v: NonZeroU64) {
        _ = self.sig_cache.set(v);
    }
}

impl VmessConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"vmess"];
        if let Some(ref v) = self.security {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.transport {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.alter_id {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.sni {
            parts.push(v.as_bytes());
        }
        rapidhash::v3::rapidhash_v3(&parts.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProtoSpec;
    use crate::urlx::SchemeX;

    #[test]
    fn test_vmess_basic() {
        let url = "vmess://eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VmessConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Vmess);
        assert_eq!(config.host, "192.200.160.16");
    }

    #[test]
    fn test_reconstruct_roundtrip() {
        let input = "vmess://eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = VmessConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = VmessConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    #[test]
    fn test_serde_roundtrip() {
        let input = "vmess://eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==";
        let raw = crate::urlx::RawUrlX::from(input);

        let parsed = VmessConfig::try_parse(&raw).expect("failed to parse");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: VmessConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.host, deserialized.host);
    }

    use super::VmessConfig;
}
