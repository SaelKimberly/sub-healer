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
        let clean_userinfo = clean_ssr_userinfo(raw.userinfo);
        let decoded = utils::decode_base64(clean_userinfo)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::SSR))?;
        let text = String::from_utf8(decoded)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::SSR))?;

        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() < 6 {
            return Err(ParseError::InvalidStructure(SchemeX::SSR));
        }

        // Index from end: last 5 are port, protocol, method, obfs, password.
        // Everything before is the host (handles IPv6 with colons).
        let raw_host = parts[..parts.len() - 5].join(":");
        let raw_port = parts[parts.len() - 5];
        let protocol = parts[parts.len() - 4].to_string();
        let method = parts[parts.len() - 3].to_string();
        let obfs = parts[parts.len() - 2].to_string();
        let raw_password = parts[parts.len() - 1..].join(":");

        let (password, query_part) = raw_password
            .split_once("/?")
            .or_else(|| raw_password.split_once('?'))
            .unwrap_or((&raw_password, ""));

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

        let parsed_host = utils::parse_host(&raw_host)
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

        let mut query_str = String::new();
        let mut sorted_params: Vec<_> = self.params.iter().collect();
        sorted_params.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in &sorted_params {
            if !query_str.is_empty() {
                query_str.push('&');
            }
            query_str.push_str(format!("{k}={v}").as_str());
        }

        let raw = format!(
            "{host}:{port}:{proto}:{method}:{obfs}:{password}/?{query_str}",
            host = self.host,
            port = self.port,
            proto = self.protocol,
            method = self.method,
            obfs = self.obfs,
            password = self.password,
            query_str = query_str,
        );
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

/// Strip trailing non-base64 garbage (Telegram annotation text and decorative
/// hyphens) from the SSR userinfo before base64 decoding.
///
/// Strategy:
/// 1. If the base64 has `=` padding, everything after the last `=` that is
///    hyphens followed by non-ASCII is stripped.
/// 2. For no-pad base64, find the first occurrence of 3+ consecutive decorative
///    `-` or `_` that is followed by non-ASCII and truncate there.
/// 3. If neither heuristic triggers, return the string unchanged.
fn clean_ssr_userinfo(s: &str) -> &str {
    // Try padded-base64 heuristic first
    if let Some(last_eq) = s.rfind('=') {
        let after = &s[last_eq + 1..];
        let after_hyphens = after.trim_start_matches(|c: char| c == '-' || c == '_');
        if after_hyphens.is_empty()
            || !after_hyphens.as_bytes().first().map_or(true, |b| b.is_ascii())
        {
            return &s[..=last_eq];
        }
    }

    // For NO_PAD base64: find 3+ consecutive '-' or '_' that are followed
    // by non-ASCII (Telegram annotation text). 3+ consecutive hyphens are
    // virtually never valid URL-safe base64 data.
    let bytes = s.as_bytes();
    let mut hyphen_run: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'-' || b == b'_' {
            hyphen_run += 1;
        } else {
            if hyphen_run >= 3 && (i >= bytes.len() || !bytes[i].is_ascii()) {
                return &s[..i - hyphen_run as usize];
            }
            hyphen_run = 0;
        }
    }
    // Handle case where the run extends to the end
    if hyphen_run >= 3 {
        return &s[..s.len() - hyphen_run as usize];
    }

    s
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
        assert_eq!(config.remarks.as_deref(), Some("TestServer"));
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

    #[test]
    fn test_ssr_trailing_text() {
        // Valid base64 with trailing Chinese annotation text (Telegram pattern)
        let url = "ssr://MTE2LjE2Mi4xMjAuMjY6NTYxOmF1dGhfYWVzMTI4X21kNTpjaGFjaGEyMC1pZXRmOnBsYWluOmJXSnNZVzVyTVhCdmNuUT0vP2dyb3VwPWFIUjBjSE02THk5Mk1uSmhlWE5sTG1OdmJRPT0mcHJvdG9wYXJhbT1OVEUzTmpBNlRFeE1NRGt3ZFdrNGIyeHNPQT0=必进：【全网导航】》下载地址：";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = SsrConfig::try_parse(&raw).expect("failed to parse url with trailing text");
        assert_eq!(config.host, "116.162.120.26");
        assert_eq!(config.port, "561");
        assert_eq!(config.protocol, "auth_aes128_md5");
        assert_eq!(config.method, "chacha20-ietf");
        assert_eq!(config.obfs, "plain");
    }

    #[test]
    fn test_ssr_no_query() {
        // Valid SSR URL with no /? query params and a # fragment
        let url = "ssr://MTMuMzcuMjguMjM6NTk0NzpvcmlnaW46Y2hhY2hhMjAtaWV0ZjpwbGFpbjpOVGswTnc#@dark_telecom";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = SsrConfig::try_parse(&raw).expect("failed to parse url with hash and no query");
        assert_eq!(config.host, "13.37.28.23");
        assert_eq!(config.port, "5947");
        assert_eq!(config.protocol, "origin");
        assert_eq!(config.method, "chacha20-ietf");
        assert_eq!(config.obfs, "plain");
    }

    #[test]
    fn test_ssr_garbage_returns_err() {
        // Chinese text only — not a valid SSR URL
        let url = "ssr://的格式";
        let raw = crate::urlx::RawUrlX::from(url);
        assert!(SsrConfig::try_parse(&raw).is_err());
    }

    #[test]
    fn test_ssr_remarks_decoded() {
        // URL with base64-encoded remarks in query params
        let url = "ssr://MTIzLjQ1LjY3Ljg5OjEwMDA6b3JpZ2luOnBsYWluOnBsYWluOmRHVnpkRjl3WVhOei8_cmVtYXJrcz1jM055WDNSbGMzUT0";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = SsrConfig::try_parse(&raw).expect("failed to parse");
        assert_eq!(config.remarks.as_deref(), Some("ssr_test"));
    }

    use super::SsrConfig;
}
