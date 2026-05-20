use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{RawUrlX, SchemeX};

use super::common::TransportConfig;
use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VlessConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub uuid: String,
    pub host: String,
    pub port: String,
    pub security: String,
    pub transport: TransportConfig,
    pub encryption: Option<String>,
    pub flow: Option<String>,
    pub path: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub fp: Option<String>,
    pub pbk: Option<String>,
    pub sid: Option<String>,
    pub splice: Option<bool>,
    pub remarks: Option<String>,
}

impl ProtoSpec for VlessConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let (username, hostport) = if let Some(hostport) = raw.hostport {
            (raw.userinfo, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (username, hostport) = userinfo.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{userinfo}: missing hostport").into())
            })?;
            (username, hostport)
        };

        let (parsed_host, parsed_port) = utils::parse_hostport(hostport)
            .map_err(|e| ParseError::InvalidHostPort(format!("{hostport}: {e}").into()))?;

        uuid::Uuid::parse_str(username).map_err(|_| {
            ParseError::InvalidUserInfo(format!("invalid UUID: {username}").into())
        })?;

        let query = utils::parse_query(raw.query);

        let security = query
            .get("security")
            .map_or("none", |s| s.as_str())
            .to_string();
        let transport_type = query
            .get("type")
            .map_or("tcp", |s| s.as_str())
            .to_string();
        let path = query.get("path").cloned();
        let encryption = query.get("encryption").filter(|v| v != &"none").cloned();
        let flow = query.get("flow").cloned();
        let sni = query.get("sni").cloned();
        let alpn = query.get("alpn").cloned();
        let fp = query.get("fp").cloned();
        let pbk = query.get("pbk").cloned();
        let sid = query.get("sid").cloned();
        let splice = query.get("splice").and_then(|v| match v.as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        });

        let remarks = utils::decode_fragment(raw)?;

        let transport = TransportConfig::from_type_and_path(Some(&transport_type), path.as_deref())
            .ok_or_else(|| ParseError::InvalidConf("type".into(), transport_type.into()))?;

        let path = match transport {
            TransportConfig::Ws(ref ws) => ws.path.clone(),
            TransportConfig::Grpc(ref g) => g.path.clone(),
            TransportConfig::Http(ref h) => h.path.clone(),
            _ => path,
        };

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            uuid: username.to_string(),
            host: parsed_host.to_str().into_owned(),
            port: parsed_port.to_string(),
            transport,
            security,
            encryption,
            flow,
            path,
            sni,
            alpn,
            fp,
            pbk,
            sid,
            splice,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let hostport = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };

        let mut base = url::Url::parse(
            format!("vless://{}@{hostport}", self.uuid).as_str(),
        )
        .map_err(|e| ParseError::Unknown(e.into()))?;

        if let Some(ref path) = self.path {
            base.set_path(path);
        }

        {
            let mut q = base.query_pairs_mut();
            if self.security != "none" {
                q.append_pair("security", &self.security);
            }
            if self.transport.type_str() != "tcp" {
                q.append_pair("type", self.transport.type_str());
            }
            if let Some(ref path) = self.path {
                q.append_pair("path", path);
            }
            if let Some(ref v) = self.encryption {
                q.append_pair("encryption", v);
            }
            if let Some(ref v) = self.flow {
                q.append_pair("flow", v);
            }
            if let Some(ref v) = self.sni {
                q.append_pair("sni", v);
            }
            if let Some(ref v) = self.alpn {
                q.append_pair("alpn", v);
            }
            if let Some(ref v) = self.fp {
                q.append_pair("fp", v);
            }
            if let Some(ref v) = self.pbk {
                q.append_pair("pbk", v);
            }
            if let Some(ref v) = self.sid {
                q.append_pair("sid", v);
            }
            if let Some(v) = self.splice {
                q.append_pair("splice", if v { "true" } else { "false" });
            }
        }

        if let Some(ref remarks) = self.remarks {
            let frag = crate::Unescaper::default()
                .enc_pct()
                .enc_uni(true)
                .chardet(true, true)
                .do_unescape(remarks.as_bytes())
                .unwrap();
            let frag = frag.trim();
            if !frag.is_empty() {
                base.set_fragment(Some(frag));
            }
        }

        Ok(base.to_string())
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Vless
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
        utils::compute_cred_hash(
            None,
            None,
            &self.uuid,
            &self.uuid,
        )
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

impl VlessConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"vless"];
        parts.push(self.security.as_bytes());
        parts.push(self.transport.type_str().as_bytes());
        if let Some(ref path) = self.path {
            parts.push(path.as_bytes());
        }
        if let Some(ref v) = self.encryption {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.sni {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.flow {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.alpn {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.fp {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.pbk {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.sid {
            parts.push(v.as_bytes());
        }
        if let Some(v) = self.splice {
            parts.push(if v { b"true" } else { b"false" });
        }
        rapidhash::v3::rapidhash_v3(&parts.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProtocolConfig;
    use super::super::ProtoSpec;
    use crate::urlx::SchemeX;

    #[test]
    fn test_vless_basic() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Vless);
        assert_eq!(config.host(), Some("159.223.24.65"));
        assert_eq!(config.uuid, "6202b230-417c-4d8e-b624-0f71afa9c75d");
    }

    #[test]
    fn test_vless_reality() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&pbk=abc123";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Vless);
        assert_eq!(config.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(config.pbk.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_reconstruct_vless_roundtrip() {
        let input = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = VlessConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = VlessConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.uuid, reparsed.uuid, "uuid mismatch");
    }

    #[test]
    fn test_vless_serde_roundtrip() {
        let input = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = VlessConfig::try_parse(&raw).expect("failed to parse");

        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: VlessConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.host, deserialized.host, "host mismatch");
        assert_eq!(parsed.port, deserialized.port, "port mismatch");
        assert_eq!(parsed.uuid, deserialized.uuid, "uuid mismatch");
    }

    use super::VlessConfig;
}
