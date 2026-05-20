use std::num::NonZeroU64;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::urlx::{RawUrlX, SchemeX};

use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SsrConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub host: String,
    pub port: String,
    pub protocol: String,
    pub method: String,
    pub obfs: String,
    pub password: String,
    pub params: std::collections::HashMap<String, String>,
    pub remarks: Option<String>,
}

impl ProtoSpec for SsrConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let decoded = utils::decode_base64(raw.userinfo)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::SSR))?;
        let text = String::from_utf8(decoded)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::SSR))?;

        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() < 6 {
            return Err(ParseError::InvalidStructure(SchemeX::SSR));
        }

        let raw_host = parts[0];
        let raw_port = parts[1];
        let protocol = parts[2].to_string();
        let method = parts[3].to_string();
        let obfs = parts[4].to_string();
        let raw_password = parts[5..].join(":");

        let (password, query_part) = raw_password
            .split_once("/?")
            .or_else(|| raw_password.split_once('?'))
            .ok_or_else(|| ParseError::InvalidStructure(SchemeX::SSR))?;

        let mut params = std::collections::HashMap::new();
        params.insert("protocol".into(), protocol.clone());
        params.insert("obfs".into(), obfs.clone());

        if !query_part.is_empty() {
            for pair in query_part.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    params.insert(k.to_string(), v.to_string());
                }
            }
        }

        let remarks = params.remove("remarks").map(|r| {
            base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(r.trim_end_matches('='))
                .ok()
                .and_then(|d| String::from_utf8(d).ok())
                .unwrap_or(r)
        });

        let parsed_host = utils::parse_host(raw_host)
            .map_err(|e| ParseError::InvalidHost(format!("{raw_host}: {e}").into()))?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            host: parsed_host.to_str().into_owned(),
            port: raw_port.to_string(),
            protocol,
            method,
            obfs,
            password: password.to_string(),
            params,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        use base64::Engine as _;

        let mut parts = vec![
            self.host.clone(),
            self.port.clone(),
            self.protocol.clone(),
            self.method.clone(),
            self.obfs.clone(),
            self.password.clone(),
        ];

        let mut query_str = String::new();
        let mut sorted_params: Vec<_> = self.params.iter().collect();
        sorted_params.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in &sorted_params {
            if !query_str.is_empty() {
                query_str.push('&');
            }
            query_str.push_str(format!("{k}={v}").as_str());
        }

        parts.push(format!("/?{query_str}"));

        let raw = parts.join(":");
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(raw.as_bytes());
        Ok(format!("ssr://{encoded}"))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::SSR
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
        utils::compute_cred_hash(None, None, &self.method, &self.password)
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

impl SsrConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"ssr"];
        let mut sorted_keys: Vec<&String> = self.params.keys().collect();
        sorted_keys.sort();
        for k in &sorted_keys {
            if k.as_str() == "remarks" {
                continue;
            }
            parts.push(k.as_bytes());
            if let Some(v) = self.params.get(*k) {
                parts.push(v.as_bytes());
            }
        }
        rapidhash::v3::rapidhash_v3(&parts.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProtoSpec;
    use crate::urlx::SchemeX;

    const SSR_URL: &str = "ssr://ZXhhbXBsZS5jb206NDQzOm9yaWdpbjpyYzQtbWQ1OnBsYWluOmNHRnpjM2R2Y21RLz9ncm91cD1WR1Z6ZEVkeWIzVncmcmVtYXJrcz1WR1Z6ZEZObGNuWmxjZw";

    #[test]
    fn test_ssr_basic() {
        let raw = crate::urlx::RawUrlX::from(SSR_URL);
        let config = SsrConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::SSR);
        assert_eq!(config.method, "rc4-md5");
        assert_eq!(config.host, "example.com");
    }

    #[test]
    fn test_reconstruct_roundtrip() {
        let raw = crate::urlx::RawUrlX::from(SSR_URL);
        let parsed = SsrConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        assert!(
            reconstructed.starts_with("ssr://"),
            "should start with ssr://"
        );

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = SsrConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
    }

    use super::SsrConfig;
}
