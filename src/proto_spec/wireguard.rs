use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{RawUrlX, SchemeX};

use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WireguardConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub private_key: String,
    pub host: String,
    pub port: String,
    pub address: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub reserved: Option<String>,
    pub mtu: Option<String>,
    pub remarks: Option<String>,
}

impl ProtoSpec for WireguardConfig {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let private_key = urlencoding::decode(raw.userinfo)
            .map_err(|_| ParseError::InvalidUserInfo("invalid percent-encoding in private_key".into()))?
            .into_owned();

        let hostport = raw
            .hostport
            .ok_or(ParseError::MissingHost)?;
        let (parsed_host, parsed_port) = utils::parse_hostport(hostport)
            .map_err(|e| ParseError::InvalidHostPort(format!("{hostport}: {e}").into()))?;

        let query = utils::parse_query(raw.query);

        let decode_val = |v: &str| -> String {
            urlencoding::decode(v).map(|c| c.into_owned()).unwrap_or_else(|_| v.to_string())
        };

        let address = query
            .get("address")
            .ok_or_else(|| ParseError::MissingConf("address".into()))
            .map(|s| decode_val(s))?;

        let public_key = query
            .get("publickey")
            .or_else(|| query.get("public_key"))
            .ok_or_else(|| ParseError::MissingConf("publickey".into()))
            .map(|s| decode_val(s))?;

        let preshared_key = query
            .get("presharedkey")
            .or_else(|| query.get("psk"))
            .map(|s| decode_val(s));

        let reserved = query.get("reserved").map(|s| decode_val(s));

        let mtu = query.get("mtu").map(|s| decode_val(s));

        let remarks = utils::decode_fragment(raw)?;

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            private_key,
            host: parsed_host.to_str().into_owned(),
            port: parsed_port.to_string(),
            address,
            public_key,
            preshared_key,
            reserved,
            mtu,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let hostport = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };

        let mut parts: Vec<String> = Vec::new();
        parts.push(format!("address={}", urlencoding::encode(&self.address)));
        parts.push(format!("publickey={}", urlencoding::encode(&self.public_key)));
        if let Some(ref v) = self.preshared_key {
            if !v.is_empty() {
                parts.push(format!("presharedkey={}", urlencoding::encode(v)));
            }
        }
        if let Some(ref v) = self.reserved {
            parts.push(format!("reserved={}", urlencoding::encode(v)));
        }
        if let Some(ref v) = self.mtu {
            parts.push(format!("mtu={}", urlencoding::encode(v)));
        }

        let query_string = if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&"))
        };

        let fragment = self
            .remarks
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();

        Ok(format!(
            "wireguard://{private_key}@{hostport}{query_string}{fragment}",
            private_key = urlencoding::encode(&self.private_key),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::WireGuard
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
        utils::compute_cred_hash(None, None, &self.private_key, &self.private_key)
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

impl WireguardConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"wireguard"];
        parts.push(self.address.as_bytes());
        parts.push(self.public_key.as_bytes());
        if let Some(ref v) = self.preshared_key {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.reserved {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.mtu {
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
    fn test_wireguard_basic() {
        let url = "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&presharedkey=&reserved=236%2C163%2C162&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = WireguardConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::WireGuard);
        assert_eq!(config.host, "162.159.192.1");
        assert_eq!(config.port, "2408");
        assert_eq!(config.address, "172.16.0.2/32");
        assert_eq!(config.mtu.as_deref(), Some("1280"));
        assert_eq!(config.remarks, None);
    }

    #[test]
    fn test_wireguard_with_remarks() {
        let url = "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280#%40V2rayBaaz";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = WireguardConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::WireGuard);
        assert_eq!(config.remarks.as_deref(), Some("@V2rayBaaz"));
    }

    #[test]
    fn test_wireguard_hostname() {
        let url = "wireguard://privatekey==@wg.example.com:51820?address=10.0.0.2%2F32&publickey=serverpubkey==";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = WireguardConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.host, "wg.example.com");
        assert_eq!(config.port, "51820");
        assert_eq!(config.address, "10.0.0.2/32");
    }

    #[test]
    fn test_wireguard_missing_address() {
        let url = "wireguard://key@1.2.3.4:51820?publickey=pubkey";
        let raw = crate::urlx::RawUrlX::from(url);
        let result = WireguardConfig::try_parse(&raw);
        assert!(result.is_err(), "expected error for missing address");
    }

    #[test]
    fn test_wireguard_missing_publickey() {
        let url = "wireguard://key@1.2.3.4:51820?address=10.0.0.1%2F32";
        let raw = crate::urlx::RawUrlX::from(url);
        let result = WireguardConfig::try_parse(&raw);
        assert!(result.is_err(), "expected error for missing publickey");
    }

    #[test]
    fn test_reconstruct_roundtrip() {
        let input = "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&presharedkey=&reserved=236%2C163%2C162&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280#%40V2rayBaaz";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = WireguardConfig::try_parse(&raw).expect("failed to parse");
        let reconstructed = parsed.reconstruct().expect("failed to reconstruct");

        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = WireguardConfig::try_parse(&raw2).expect("failed to re-parse");

        assert_eq!(parsed.host, reparsed.host, "host mismatch");
        assert_eq!(parsed.port, reparsed.port, "port mismatch");
        assert_eq!(parsed.private_key, reparsed.private_key, "private_key mismatch");
        assert_eq!(parsed.address, reparsed.address, "address mismatch");
        assert_eq!(parsed.public_key, reparsed.public_key, "public_key mismatch");
        assert_eq!(parsed.mtu, reparsed.mtu, "mtu mismatch");
        assert_eq!(parsed.remarks, reparsed.remarks, "remarks mismatch");
    }

    #[test]
    fn test_serde_roundtrip() {
        let input = "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280";
        let raw = crate::urlx::RawUrlX::from(input);
        let parsed = WireguardConfig::try_parse(&raw).expect("failed");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: WireguardConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.host, deserialized.host, "host mismatch");
        assert_eq!(parsed.port, deserialized.port, "port mismatch");
        assert_eq!(parsed.private_key, deserialized.private_key, "private_key mismatch");
        assert_eq!(parsed.address, deserialized.address, "address mismatch");
        assert_eq!(parsed.public_key, deserialized.public_key, "public_key mismatch");
    }

    use super::WireguardConfig;
}
