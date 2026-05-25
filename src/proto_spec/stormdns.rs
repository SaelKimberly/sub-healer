//! StormDNS (`stormdns://`) URL parsing.
//!
//! # Format
//! ```text
//! stormdns://<base64_urlsafe_no_pad(JSON)>
//! ```
//!
//! Base64-decoded JSON payload follows the WhiteDNS profile format:
//! ```json
//! { "schema": "whitedns.profile", "version": 1,
//!   "profile": { "name": "...",
//!     "server": { "domain": "...", "encryption_key": "...", "encryption_method": 1 } } }
//! ```
//!
//! # Fields
//!
//! | JSON Key                       | Purpose                          |
//! |--------------------------------|----------------------------------|
//! | `schema`                       | Must be `"whitedns.profile"`      |
//! | `version`                      | Must be `1`                      |
//! | `profile.name`                 | Profile name (optional, used as remarks) |
//! | `profile.server.domain`        | Server domain (required)         |
//! | `profile.server.encryption_key`| Shared encryption key (required) |
//! | `profile.server.encryption_method`| Encryption method (i64 → `"enc{n}"`) |
//!
//! # Edge Cases
//! - Port is hardcoded to 53 (DNS)
//! - Schema and version are strictly validated (`whitedns.profile`/1)
//! - Encryption method is an integer stored as `"enc{n}"` string
//!
//! # References
//! - StormDNS: `internal/config/client.go`, `cmd/client/main.go`

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{
    host_serde, port_serde, HostSpec, RawUrlX, SchemeX,
};

use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct StormdnsConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    pub encryption_key: String,
    pub encryption_method: Option<String>,
    pub name: Option<String>,
}

impl ProtoSpec for StormdnsConfig {
    /// Parse a StormDNS URL.
    ///
    /// Userinfo is base64-encoded JSON (WhiteDNS profile format).
    /// Schema must be `"whitedns.profile"` and version must be 1.
    /// `encryption_method` is an integer stored as `"enc{n}"` string.
    /// Port is always 53 (DNS).
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let decoded = utils::decode_base64(raw.userinfo)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Stormdns))?;

        let json = crate::utils::permissive_json::permissive_json(decoded.as_slice())
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Stormdns))?;

        // schema must be "whitedns.profile"
        let schema = json
            .get("schema")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::InvalidStructure(SchemeX::Stormdns))?;
        if schema != "whitedns.profile" {
            return Err(ParseError::InvalidStructure(SchemeX::Stormdns));
        }

        // version must be 1
        let version = json
            .get("version")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| ParseError::InvalidStructure(SchemeX::Stormdns))?;
        if version != 1 {
            return Err(ParseError::InvalidStructure(SchemeX::Stormdns));
        }

        let profile = json
            .get("profile")
            .ok_or_else(|| ParseError::MissingConf("profile".into()))?;

        let name = profile
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from);

        let server = profile
            .get("server")
            .ok_or_else(|| ParseError::MissingConf("profile.server".into()))?;

        let domain = server
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::MissingConf("profile.server.domain".into()))?;

        let parsed_host = utils::parse_host(domain)
            .map_err(|e| ParseError::InvalidHost(format!("{domain}: {e}").into()))?;

        let encryption_key = server
            .get("encryption_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::MissingConf("profile.server.encryption_key".into()))?
            .to_string();

        let encryption_method = server
            .get("encryption_method")
            .and_then(serde_json::Value::as_i64)
            .map(|n| format!("enc{n}"));

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            host: parsed_host,
            port: 53,
            encryption_key,
            encryption_method,
            name,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        use base64::Engine as _;

        let mut server = serde_json::Map::new();
        server.insert(
            "domain".into(),
            serde_json::Value::String(self.host.to_str().into_owned()),
        );
        server.insert(
            "encryption_key".into(),
            serde_json::Value::String(self.encryption_key.clone()),
        );
        if let Some(ref v) = self.encryption_method {
            let method_num = v
                .strip_prefix("enc")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            server.insert(
                "encryption_method".into(),
                serde_json::Value::Number(method_num.into()),
            );
        }

        let mut profile = serde_json::Map::new();
        profile.insert("server".into(), serde_json::Value::Object(server));
        if let Some(ref v) = self.name {
            profile.insert("name".into(), serde_json::Value::String(v.clone()));
        }

        let mut root = serde_json::Map::new();
        root.insert(
            "schema".into(),
            serde_json::Value::String("whitedns.profile".into()),
        );
        root.insert("version".into(), serde_json::Value::Number(1.into()));
        root.insert("profile".into(), serde_json::Value::Object(profile));

        let json_str = serde_json::to_string(&serde_json::Value::Object(root))
            .map_err(|e| ParseError::Unknown(e.into()))?;
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        Ok(format!("stormdns://{encoded}"))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Stormdns
    }

    fn host(&self) -> Option<&HostSpec> {
        Some(&self.host)
    }

    fn port(&self) -> Option<u16> {
        Some(self.port)
    }

    fn remarks(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn cred_hash(&self) -> u64 {
        utils::compute_cred_hash(Some(&self.host), Some(self.port), None, "", &self.encryption_key)
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

    fn transport_type(&self) -> Option<&str> {
        None
    }

    fn security_type(&self) -> Option<&str> {
        None
    }
}

impl StormdnsConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"stormdns"];
        if let Some(ref v) = self.encryption_method {
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
    fn test_stormdns_basic() {
        let raw = crate::urlx::RawUrlX::from(
            "stormdns://eyJzY2hlbWEiOiJ3aGl0ZWRucy5wcm9maWxlIiwidmVyc2lvbiI6MSwicHJvZmlsZSI6eyJuYW1lIjoiQ2xvdWRmbGFyZSIsInNlcnZlciI6eyJkb21haW4iOiJleGFtcGxlLmNvbSIsImVuY3J5cHRpb25fa2V5Ijoic29tZS1rZXkiLCJlbmNyeXB0aW9uX21ldGhvZCI6MX19fQ==",
        );
        let config = StormdnsConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Stormdns);
        assert_eq!(config.host.to_str(), "example.com");
    }

    #[test]
    fn test_serde_roundtrip() {
        let raw = crate::urlx::RawUrlX::from(
            "stormdns://eyJzY2hlbWEiOiJ3aGl0ZWRucy5wcm9maWxlIiwidmVyc2lvbiI6MSwicHJvZmlsZSI6eyJuYW1lIjoiQ2xvdWRmbGFyZSIsInNlcnZlciI6eyJkb21haW4iOiJleGFtcGxlLmNvbSIsImVuY3J5cHRpb25fa2V5Ijoic29tZS1rZXkiLCJlbmNyeXB0aW9uX21ldGhvZCI6MX19fQ==",
        );
        let parsed = StormdnsConfig::try_parse(&raw).expect("failed");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: StormdnsConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.host, deserialized.host);
    }

    use super::super::test_helpers::check_roundtrip;
    use super::StormdnsConfig;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<StormdnsConfig>("stormdns://eyJzY2hlbWEiOiJ3aGl0ZWRucy5wcm9maWxlIiwidmVyc2lvbiI6MSwicHJvZmlsZSI6eyJuYW1lIjoiQ2xvdWRmbGFyZSIsInNlcnZlciI6eyJkb21haW4iOiJleGFtcGxlLmNvbSIsImVuY3J5cHRpb25fa2V5Ijoic29tZS1rZXkiLCJlbmNyeXB0aW9uX21ldGhvZCI6MX19fQ==");
    }
}
