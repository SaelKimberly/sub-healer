use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{RawUrlX, SchemeX};

use super::common::TransportConfig;
use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TrojanConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub password: String,
    pub host: String,
    pub port: String,
    pub security: String,
    pub transport: TransportConfig,
    pub path: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub fp: Option<String>,
    pub remarks: Option<String>,
}

impl ProtoSpec for TrojanConfig {
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

        let query = utils::parse_query(raw.query);

        let security = query
            .get("security")
            .map_or("tls", |s| s.as_str())
            .to_string();
        let transport_type = query
            .get("type")
            .map_or("tcp", |s| s.as_str())
            .to_string();
        let path = query.get("path").cloned();
        let sni = query.get("sni").cloned();
        let alpn = query.get("alpn").cloned();
        let fp = query.get("fp").cloned();

        let remarks = utils::decode_fragment(raw)?;

        let transport =
            TransportConfig::from_type_and_path(Some(&transport_type), path.as_deref())
                .ok_or_else(|| {
                    ParseError::InvalidConf("type".into(), transport_type.into())
                })?;

        let path = match transport {
            TransportConfig::Ws(ref ws) => ws.path.clone(),
            TransportConfig::Grpc(ref g) => g.path.clone(),
            TransportConfig::Http(ref h) => h.path.clone(),
            _ => path,
        };

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            password: username.to_string(),
            host: parsed_host.to_str().into_owned(),
            port: parsed_port.to_string(),
            transport,
            security,
            path,
            sni,
            alpn,
            fp,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let hostport = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };

        let query_string = {
            let mut parts: Vec<String> = Vec::new();
            if self.security != "tls" {
                parts.push(format!("security={}", self.security));
            }
            if self.transport.type_str() != "tcp" {
                parts.push(format!("type={}", self.transport.type_str()));
            }
            if let Some(ref path) = self.path {
                parts.push(format!("path={}", urlencoding::encode(path)));
            }
            if let Some(ref v) = self.sni {
                parts.push(format!("sni={}", urlencoding::encode(v)));
            }
            if let Some(ref v) = self.alpn {
                parts.push(format!("alpn={}", urlencoding::encode(v)));
            }
            if let Some(ref v) = self.fp {
                parts.push(format!("fp={}", urlencoding::encode(v)));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!("?{}", parts.join("&"))
            }
        };

        let fragment = self
            .remarks
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();

        Ok(format!(
            "trojan://{password}@{hostport}{query_string}{fragment}",
            password = self.password,
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Trojan
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
        utils::compute_cred_hash(None, None, &self.password, &self.password)
    }

    fn sig(&self) -> u64 {
        let v = self
            .sig_cache
            .get_or_init(|| {
                let val = self.compute_sig();
                NonZeroU64::new(val).unwrap_or(NonZeroU64::MIN)
            });
        v.get()
    }

    fn set_sig_cache(&self, v: NonZeroU64) {
        _ = self.sig_cache.set(v);
    }
}

impl TrojanConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"trojan"];
        parts.push(self.security.as_bytes());
        parts.push(self.transport.type_str().as_bytes());
        if let Some(ref path) = self.path {
            parts.push(path.as_bytes());
        }
        if let Some(ref v) = self.sni {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.alpn {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.fp {
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
    fn test_trojan_basic() {
        let url = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = TrojanConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Trojan);
        assert_eq!(config.host(), Some("172.64.152.23"));
        assert_eq!(config.password, "humanity");
    }

    #[test]
    fn test_reconstruct_trojan_roundtrip() {
        let input = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = TrojanConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = TrojanConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.password, reparsed.password, "password mismatch");
    }

    #[test]
    fn test_trojan_serde_roundtrip() {
        let input = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = TrojanConfig::try_parse(&raw).expect("failed to parse");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: TrojanConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.host, deserialized.host, "host mismatch");
        assert_eq!(parsed.port, deserialized.port, "port mismatch");
        assert_eq!(parsed.password, deserialized.password, "password mismatch");
    }

    use super::TrojanConfig;
}
