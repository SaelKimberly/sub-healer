//! VMess (`vmess://`) URL parsing.
//!
//! # Format
//! ```text
//! vmess://<base64_urlsafe_no_pad(JSON)>
//! ```
//!
//! The base64-decoded payload is JSON with abbreviated 2–3 char field names
//! (v2rayN `VmessQRCode` format). Canonical reference:
//! `thirdparty/v2rayN/ServiceLib/Models/Dto/VmessQRCode.cs`
//!
//! # JSON Fields
//!
//! | Field | Key | Type    | Purpose                         | Default        |
//! |-------|-----|---------|---------------------------------|----------------|
//! | `v`   | `v` | string  | Config version                  | `"2"`          |
//! | `ps`  | `ps`| string  | Remarks (friendly name)         | `""`           |
//! | `add` | `add`| string | Server address (IP or domain)   | — (required)   |
//! | `port`| `port`| int   | Server port                     | — (required)   |
//! | `id`  | `id` | string  | User UUID                       | — (required)   |
//! | `aid` | `aid`| string  | AlterId (additional IDs)        | `"0"`          |
//! | `scy` | `scy`| string  | Encryption method               | `"auto"`       |
//! | `net` | `net`| string  | Transport type                  | `"tcp"`        |
//! | `type`| `type`| string | TCP/KCP header / gRPC mode      | `"none"`       |
//! | `host`| `host`| string | Host header / gRPC authority    | `""`           |
//! | `path`| `path`| string | WS path / gRPC serviceName / KCP seed | `""`     |
//! | `tls` | `tls`| string  | TLS: `"tls"` or `""`            | `""`           |
//! | `sni` | `sni`| string  | TLS SNI override                | `""`           |
//! | `alpn`| `alpn`| string | ALPN (comma-separated)          | `""`           |
//! | `fp`  | `fp` | string  | uTLS Client Hello fingerprint   | `""`           |
//!
//! # Security (`scy`)
//! - `auto` — auto-select AES-128-GCM or ChaCha20-Poly1305
//! - `aes-128-gcm`, `chacha20-poly1305`, `none` (deprecated), `zero`
//!
//! # Transport (`net`)
//! `tcp`, `ws`, `kcp`, `grpc`, `http` (→ `h2`), `quic`, `httpupgrade`,
//! `splithttp`/`xhttp`
//!
//! # Edge Cases
//! - Port is stored as string in JSON, coerced to u16
//! - Empty/null fields filtered (scy=auto, net stripped if `"null"`)
//! - Trailing Telegram annotation text/emoji after base64 is stripped
//! - `host` starting with `/` treated as path when path empty (v2rayN compat)
//! - Base64 can be URL-safe or standard, with or without padding
//!
//! # References
//! - Xray-core: `proxy/vmess/`
//! - v2rayN: `VmessQRCode.cs`, `VmessFmt.cs`
//! - sing-box: `option/vmess.go`
//! - outbound: `dialer/v2ray/v2ray.go`
//! - subconverter: `subparser.cpp` `explodeVmessConf()`

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText, host_serde, port_serde};

use super::common::{SecurityConfig, TlsConfig, TlsOpts, TransportConfig};
use super::utils;
use super::impl_sig_cache;
use super::{ParseError, ProtoSpec};

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct VmessConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,
    #[serde(skip)]
    cred_hash_cache: std::sync::OnceLock<NonZeroU64>,

    pub uuid: String,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub transport: TransportConfig,
    pub alter_id: Option<TinyText>,
    pub path: Option<TinyText>,
    pub remarks: Option<TinyText>,
}

impl ProtoSpec for VmessConfig {
    /// Parse a VMess URL.
    ///
    /// Decodes the base64 userinfo → parses lenient JSON with abbreviated v2rayN keys.
    /// Trailing non-base64 annotation (Telegram emoji, Persian text, etc.) is stripped
    /// by `decode_base64` before JSON parsing. Empty/null string fields are filtered.
    #[allow(clippy::too_many_lines)]
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        // VMess userinfo is base64-encoded JSON (v2rayN VmessQRCode format).
        // decode_base64 handles trailing annotation text/emoji and stray backticks.
        let decoded = utils::decode_base64(raw.userinfo)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Vmess))?;

        // Permissive JSON parser handles single-quoted keys, trailing commas, etc.
        let json = crate::utils::permissive_json::permissive_json(decoded.as_slice())
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Vmess))?;

        // "add" — server address (IP or domain), required
        let host_str = json
            .get("add")
            .and_then(|v| v.as_str())
            .ok_or(ParseError::MissingHost)?;
        let parsed_host = utils::parse_host(host_str)?;

        // "port" — can be string or number, coerce via coerce_u16
        let port_val = json
            .get("port")
            .ok_or(ParseError::MissingPort)
            .and_then(|v| {
                utils::coerce_u16(v)
                    .ok_or_else(|| ParseError::InvalidPort(format!("cannot parse: {v}").into()))
            })?;

        // "id" — UUID v4 string, required
        let uuid = json
            .get("id")
            .ok_or_else(|| ParseError::MissingConf("id".into()))?
            .as_str()
            .ok_or_else(|| ParseError::InvalidConf("id".into(), "not a string".into()))?
            .to_owned();

        // "net" — transport network type (tcp, ws, kcp, grpc, http/h2, quic, httpupgrade, xhttp/splithttp)
        // Filters empty/null/"null" — absence means tcp
        let net_str = json
            .get("net")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"null")
            .map(String::from);
        
        // "path" — transport-specific path
        let path = json
            .get("path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(TinyText::from);

        let sni = json
            .get("sni")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(TinyText::from);
        let alpn = json
            .get("alpn")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"")
            .map(TinyText::from);
        let fp = json
            .get("fp")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(TinyText::from);
        let tls_str = json
            .get("tls")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"");

        // scy → security.enc (encryption method)
        let scy = json
            .get("scy")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"null")
            .or(Some("auto"))
            .map(String::from);

        let security = SecurityConfig {
            tls: tls_str.map(|_| {
                TlsConfig::Tls(TlsOpts {
                    sni: sni.clone(),
                    alpn,
                    fp,
                    insecure: None,
                })
            }),
            enc: scy.map(|s| crate::urlx::TinyText::from(s.as_str())),
        };

        // "aid" — AlterId (additional IDs), must be 0 for AEAD-only clients
        // Filters empty/escaped-empty/"0" since 0 is the modern AEAD default
        let alter_id = json
            .get("aid")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"" && s != &"0")
            .map(TinyText::from);
        
        // "ps" — remarks/friendly name, also strips wrapping quotes
        let remarks = json
            .get("ps")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| TinyText::from(s.trim_matches(['"', '\''])));
        // Build typed TransportConfig from net field
        let mut transport = TransportConfig::from_type_and_path(
            net_str.as_deref(),
            path.as_deref(),
        )
        .ok_or_else(|| {
            ParseError::InvalidConf("net".into(), net_str.clone().unwrap_or_default().into())
        })?;

        // Resolve host for transport (HttpUpgrade/XHttp): host → sni → server address
        let vmess_host = json
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        let server_addr = Some(parsed_host.to_str().into_owned());
        transport = transport.with_host(vmess_host, sni.map(|s| s.to_string()), server_addr);

        // For XHttp: mode comes from VMess JSON `type` field
        if let TransportConfig::XHttp(ref mut xcfg) = transport
            && let Some(mode) = json.get("type").and_then(|v| v.as_str())
        {
            match mode {
                "auto" | "packet-up" | "stream-up" | "stream-one" => {
                    xcfg.mode = Some(TinyText::from(mode));
                }
                other => {
                    return Err(ParseError::InvalidConf(
                        "type".into(),
                        other.to_string().into(),
                    ));
                }
            }
        }

        // Post-process path: if host starts with "/" and path is empty (v2rayN compat)
        let path = if path.is_none() {
            json.get("host")
                .and_then(|v| v.as_str())
                .filter(|s| s.starts_with('/'))
                .map(TinyText::from)
        } else {
            path
        };

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            cred_hash_cache: std::sync::OnceLock::new(),
            uuid,
            host: parsed_host,
            port: port_val,
            security,
            transport,
            alter_id,
            path,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        use base64::Engine as _;

        let mut map = serde_json::Map::new();
        map.insert(
            "add".into(),
            serde_json::Value::String(self.host.to_str().into_owned()),
        );
        map.insert(
            "port".into(),
            serde_json::Value::String(self.port.to_string()),
        );
        map.insert("id".into(), serde_json::Value::String(self.uuid.clone()));

        if let Some(TlsConfig::Tls(opts)) = &self.security.tls {
            map.insert("tls".into(), serde_json::Value::String("tls".into()));
            if let Some(ref v) = opts.sni {
                map.insert("sni".into(), serde_json::Value::String(v.to_string()));
            }
            if let Some(ref v) = opts.alpn {
                map.insert("alpn".into(), serde_json::Value::String(v.to_string()));
            }
            if let Some(ref v) = opts.fp {
                map.insert("fp".into(), serde_json::Value::String(v.to_string()));
            }
        }
        if let Some(ref v) = self.security.enc {
            map.insert("scy".into(), serde_json::Value::String(v.to_string()));
        }
        if self.transport.type_str() != "tcp" {
            map.insert(
                "net".into(),
                serde_json::Value::String(self.transport.type_str().to_string()),
            );
        }
        if let Some(ref v) = self.path {
            map.insert("path".into(), serde_json::Value::String(v.to_string()));
        }
        if let Some(ref v) = self.alter_id {
            map.insert("aid".into(), serde_json::Value::String(v.to_string()));
        }
        if let Some(ref v) = self.remarks {
            map.insert("ps".into(), serde_json::Value::String(v.to_string()));
        }

        let json = serde_json::Value::Object(map);
        let json_str = serde_json::to_string(&json).map_err(|e| ParseError::Unknown(e.into()))?;
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        Ok(format!("vmess://{encoded}"))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Vmess
    }

    fn host(&self) -> Option<&HostSpec> {
        Some(&self.host)
    }

    fn port(&self) -> Option<u16> {
        Some(self.port)
    }

    fn remarks(&self) -> Option<&str> {
        self.remarks.as_deref()
    }

    fn cred_hash(&self) -> u64 {
        let v = self.cred_hash_cache.get_or_init(|| {
            let val = utils::compute_cred_hash(
                Some(&self.host),
                Some(self.port),
                None,
                &self.uuid,
                &self.uuid,
            );
            NonZeroU64::new(val).unwrap_or(NonZeroU64::MIN)
        });
        v.get()
    }

    fn set_cred_hash_cache(&self, v: NonZeroU64) {
        _ = self.cred_hash_cache.set(v);
    }

    impl_sig_cache!();
    fn transport_type(&self) -> Option<&str> {
        Some(self.transport.type_str())
    }

    fn security(&self) -> Option<&SecurityConfig> {
        Some(&self.security)
    }
}

impl VmessConfig {
    fn compute_sig(&self) -> u64 {
        use rapidhash::v3::RapidStreamHasherV3;
        let mut hasher = RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);
        hasher.write(b"vmess");
        if let Some(ref v) = self.security.enc {
            hasher.write(v.as_bytes());
        }
        hasher.write(self.transport.type_str().as_bytes());
        match &self.transport {
            TransportConfig::HttpUpgrade(cfg) => {
                if let Some(ref v) = cfg.host {
                    hasher.write(v.as_bytes());
                }
            }
            TransportConfig::XHttp(cfg) => {
                if let Some(ref v) = cfg.host {
                    hasher.write(v.as_bytes());
                }
            }
            _ => {}
        }
        if let Some(ref v) = self.alter_id {
            hasher.write(v.as_bytes());
        }
        if let Some(v) = self.security.sni() {
            hasher.write(v.as_bytes());
        }
        hasher.finish()
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
        assert_eq!(config.host.to_str(), "192.200.160.16");
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

    use super::super::test_helpers::check_roundtrip;
    use super::VmessConfig;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<VmessConfig>(
            "vmess://eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==",
        );
    }

    #[test]
    fn test_vmess_httpupgrade() {
        let b64 = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJob3N0Ijoid3MuZXhhbXBsZS5jb20iLCJpZCI6Ijk5OTk5OTk5LTk5OTktOTk5OS05OTk5LTk5OTk5OTk5OTk5OSIsIm5ldCI6Imh0dHB1cGdyYWRlIiwicGF0aCI6Ii92MnJheSIsInBvcnQiOiI4NDQzIiwicHMiOiJ0ZXN0aHR0cHVwZ3JhZGUiLCJzY3kiOiJhdXRvIiwic25pIjoiIiwidGxzIjoidGxzIiwidHlwZSI6IiIsInYiOiIyIn0=";
        let url_str = format!("vmess://{b64}");
        let raw = crate::urlx::RawUrlX::from(url_str.as_str());
        let config = VmessConfig::try_parse(&raw).expect("vmess httpupgrade failed");
        assert_eq!(config.transport.type_str(), "httpupgrade");
    }

    #[test]
    fn test_vmess_splithttp() {
        let b64 = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJob3N0IjoieGh0dHAuZXhhbXBsZS5jb20iLCJpZCI6Ijk5OTk5OTk5LTk5OTktOTk5OS05OTk5LTk5OTk5OTk5OTk5OSIsIm5ldCI6InNwbGl0aHR0cCIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6InRlc3R4aHR0cCIsInNjeSI6ImF1dG8iLCJzbmkiOiIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiYXV0byIsInYiOiIyIn0=";
        let url_str = format!("vmess://{b64}");
        let raw = crate::urlx::RawUrlX::from(url_str.as_str());
        let config = VmessConfig::try_parse(&raw).expect("vmess splithttp failed");
        assert_eq!(config.transport.type_str(), "xhttp");
    }

    #[test]
    fn test_trailing_emoji() {
        let b64 = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiLyIsInBvcnQiOiI4NDQzIiwicHMiOiJ0ZXN0Iiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiIiLCJ2IjoiMiJ9";
        let url = format!("vmess://{b64}💛💜test");
        let raw = crate::urlx::RawUrlX::from(url.as_str());
        let config = VmessConfig::try_parse(&raw).expect("trailing emoji failed");
        assert_eq!(config.host.to_str(), "192.200.160.16");
    }

    #[test]
    fn test_trailing_persian() {
        let b64 = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiLyIsInBvcnQiOiI4NDQzIiwicHMiOiJ0ZXN0Iiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiIiLCJ2IjoiMiJ9";
        let url = format!("vmess://{b64}سرور آلمان");
        let raw = crate::urlx::RawUrlX::from(url.as_str());
        let config = VmessConfig::try_parse(&raw).expect("trailing persian failed");
        assert_eq!(config.host.to_str(), "192.200.160.16");
    }

    #[test]
    fn test_trailing_ascii_after_padding() {
        let b64 = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiLyIsInBvcnQiOiI4NDQzIiwicHMiOiJ0ZXN0Iiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiIiLCJ2IjoiMiJ9=";
        let url = format!("vmess://{b64}Irancell&Mciفوروارد فراموش نشه📌");
        let raw = crate::urlx::RawUrlX::from(url.as_str());
        let config = VmessConfig::try_parse(&raw).expect("trailing ascii after = failed");
        assert_eq!(config.host.to_str(), "192.200.160.16");
    }
}
