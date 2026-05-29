//! VLESS (`vless://`) URL parsing.
//!
//! # Format
//! ```text
//! vless://<uuid>@<host>:<port>?<query_params>#<remarks>
//! ```
//!
//! Standard URI format (NOT base64-encoded). UUID goes in userinfo,
//! all configuration in query parameters, remarks in fragment.
//!
//! # Query Parameters
//!
//! | Key        | Values                                          | Purpose                     | Default   |
//! |------------|-------------------------------------------------|-----------------------------|-----------|
//! | `type`     | tcp, ws, grpc, http, kcp, quic, httpupgrade     | Transport/network type      | `"tcp"`   |
//! | `security` | none, tls, reality                               | TLS/security mode           | `"none"`  |
//! | `encryption`| none                                           | Payload encryption          | `"none"`  |
//! | `flow`     | xtls-rprx-vision, xtls-rprx-vision-udp443       | XTLS flow control           | —         |
//! | `host`     | domain                                          | HTTP Host header            | —         |
//! | `sni`      | domain                                          | TLS SNI override            | —         |
//! | `path`     | URL path                                        | WS path / gRPC serviceName  | —         |
//! | `alpn`     | comma-separated (h2,http/1.1)                   | ALPN list                   | —         |
//! | `fp`       | chrome, firefox, safari, random, randomized       | uTLS fingerprint            | —         |
//! | `pbk`      | base64 key                                      | REALITY public key          | —         |
//! | `sid`      | hex string                                      | REALITY short ID            | —         |
//! | `spx`      | path                                            | REALITY spider X            | —         |
//! | `splice`   | 1/0, true/false                                 | Splice mode                 | —         |
//!
//! # Edge Cases
//! - Userinfo may contain `@` for combined `userinfo@hostport` format
//! - UUID is validated via `uuid::Uuid::parse_str`
//! - For `type=grpc`, path is read from `serviceName` query param
//! - For `type=kcp`/`mkcp`, path is read from `seed` query param
//! - REALITY is VLESS-only (not supported by VMess)
//! - IPv6 addresses must be bracketed `[::1]`
//! - Empty `type` defaults to `"tcp"`, empty `security` to `"none"`
//!
//! # References
//! - Xray-core: `proxy/vless/account.go`, `proxy/vless/encoding/addons.proto`
//! - sing-box: `option/vless.go`
//! - v2rayN: `VLESSFmt.cs`
//! - outbound: `dialer/v2ray/v2ray.go` ParseVlessURL

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText, host_serde, port_serde};

use super::common::{RealityOpts, SecurityConfig, TlsConfig, TlsOpts, TransportConfig};
use super::utils;
use super::{ParseError, ProtoSpec};

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct VlessConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub uuid: String,
    pub uuid_origin: Option<TinyText>,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub transport: TransportConfig,
    pub encryption: Option<TinyText>,
    pub flow: Option<TinyText>,
    pub path: Option<TinyText>,
    pub splice: Option<bool>,
    pub remarks: Option<TinyText>,
}

impl ProtoSpec for VlessConfig {
    /// Parse a VLESS URL (standard URI format).
    ///
    /// UUID is extracted from userinfo, server address from host:port,
    /// all configuration from query parameters, remarks from fragment.
    ///
    /// Supports combined `userinfo@hostport` or separate hostport components.
    /// UUID validated via `uuid::Uuid::parse_str`.
    #[allow(clippy::too_many_lines)]
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

        let (parsed_host, parsed_port) = utils::parse_hostport(hostport)?;
        let parsed_port = parsed_port
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;
        let (uuid, uuid_origin) = match uuid::Uuid::parse_str(username) {
            Ok(_) => (username.to_string(), None),
            Err(_) => {
                let generated =
                    uuid::Uuid::new_v5(&uuid::Uuid::nil(), username.as_bytes()).to_string();
                (generated, Some(TinyText::from(username)))
            }
        };


        let query = utils::parse_query(raw.query);

        // type/transport: tcp/ws/grpc/http/kcp/quic/httpupgrade. Defaults to "tcp".
        let transport_type = query.get("type").map_or("tcp", |s| s.as_str()).to_string();
        let path = query.get("path").cloned().map(TinyText::from);
        // encryption: typically "none" (VLESS relies on TLS, not payload encryption)
        let encryption = query.get("encryption").filter(|v| v != &"none").cloned().map(TinyText::from);
        // flow: xtls-rprx-vision for XTLS direct transmission (TLS 1.3 required)
        let flow = query.get("flow").cloned().map(TinyText::from);
        // splice: boolean splice mode flag
        let splice = query.get("splice").and_then(|v| match v.as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        });

        // TLS/security config
        let security = match query.get("security").map(String::as_str) {
            Some("tls") => SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts {
                    sni: query.get("sni").cloned().map(TinyText::from),
                    alpn: query.get("alpn").cloned().map(TinyText::from),
                    fp: query.get("fp").cloned().map(TinyText::from),
                    insecure: None,
                })),
                enc: None,
            },
            Some("reality") => SecurityConfig {
                tls: Some(TlsConfig::Reality(RealityOpts {
                    sni: query.get("sni").cloned().map(TinyText::from),
                    fp: query.get("fp").cloned().map(TinyText::from),
                    pbk: query.get("pbk").cloned(),
                    sid: query.get("sid").cloned().map(TinyText::from),
                    spx: query.get("spx").cloned().map(TinyText::from),
                })),
                enc: None,
            },
            _ => SecurityConfig::default(),
        };

        let remarks = utils::decode_fragment(raw)?;

        let host = query.get("host").cloned();
        let sni_from_query = query.get("sni").cloned();
        let server_addr = Some(parsed_host.to_str().into_owned());

        let mut transport =
            TransportConfig::from_type_and_path(Some(&transport_type), path.as_deref())
                .ok_or_else(|| ParseError::InvalidConf("type".into(), transport_type.into()))?;
        transport = transport.with_host(host, sni_from_query, server_addr);

        // Extract mode and extra for XHttp, validate mode
        if let TransportConfig::XHttp(ref mut xcfg) = transport {
            if let Some(mode) = query.get("mode") {
                match mode.as_str() {
                    "auto" | "packet-up" | "stream-up" | "stream-one" => {
                        xcfg.mode = Some(TinyText::from(mode.as_str()));
                    }
                    other => {
                        return Err(ParseError::InvalidConf(
                            "mode".into(),
                            other.to_string().into(),
                        ));
                    }
                }
            }
            if let Some(extra) = query.get("extra") {
                match serde_json::from_str(extra) {
                    Ok(v) => xcfg.extra = Some(v),
                    Err(_) => {
                        return Err(ParseError::InvalidConf(
                            "extra".into(),
                            extra.clone().into(),
                        ));
                    }
                }
            }
        }

        let path = match transport {
            TransportConfig::Ws(ref ws) => ws.path.clone(),
            TransportConfig::Grpc(ref g) => g.path.clone(),
            TransportConfig::Http(ref h) => h.path.clone(),
            TransportConfig::HttpUpgrade(ref cfg) => cfg.path.clone(),
            TransportConfig::XHttp(ref cfg) => cfg.path.clone(),
            _ => path,
        };

        Ok(Self {
            sig_cache: std::sync::OnceLock::new(),
            uuid,
            uuid_origin,
            host: parsed_host,
            port: parsed_port,
            transport,
            security,
            encryption,
            flow,
            path,
            splice,
            remarks,
        })
    }

    fn reconstruct(&self) -> Result<String, ParseError> {
        let host = self.host.to_str();
        let hostport = if host.contains(':') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        };

        let userinfo = self.uuid_origin.as_deref().unwrap_or(&self.uuid);
        let mut base = url::Url::parse(format!("vless://{userinfo}@{hostport}").as_str())
            .map_err(|e| ParseError::Unknown(e.into()))?;

        {
            let mut q = base.query_pairs_mut();
            // Security config
            if let Some(ref tls_config) = self.security.tls {
                match tls_config {
                    TlsConfig::Tls(opts) => {
                        q.append_pair("security", "tls");
                        if let Some(ref v) = opts.sni {
                            q.append_pair("sni", v);
                        }
                        if let Some(ref v) = opts.alpn {
                            q.append_pair("alpn", v);
                        }
                        if let Some(ref v) = opts.fp {
                            q.append_pair("fp", v);
                        }
                    }
                    TlsConfig::Reality(opts) => {
                        q.append_pair("security", "reality");
                        if let Some(ref v) = opts.sni {
                            q.append_pair("sni", v);
                        }
                        if let Some(ref v) = opts.fp {
                            q.append_pair("fp", v);
                        }
                        if let Some(ref v) = opts.pbk {
                            q.append_pair("pbk", v);
                        }
                        if let Some(ref v) = opts.sid {
                            q.append_pair("sid", v);
                        }
                        if let Some(ref v) = opts.spx {
                            q.append_pair("spx", v);
                        }
                    }
                }
            }
            if self.transport.type_str() != "tcp" {
                q.append_pair("type", self.transport.type_str());
            }
            match &self.transport {
                TransportConfig::HttpUpgrade(cfg) => {
                    if let Some(ref host) = cfg.host {
                        q.append_pair("host", host);
                    }
                }
                TransportConfig::XHttp(cfg) => {
                    if let Some(ref host) = cfg.host {
                        q.append_pair("host", host);
                    }
                    if let Some(ref mode) = cfg.mode {
                        q.append_pair("mode", mode);
                    }
                    if let Some(ref extra) = cfg.extra {
                        q.append_pair("extra", &extra.to_string());
                    }
                }
                _ => {}
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
        utils::compute_cred_hash(
            Some(&self.host),
            Some(self.port),
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

    fn transport_type(&self) -> Option<&str> {
        Some(self.transport.type_str())
    }

    fn security(&self) -> Option<&SecurityConfig> {
        Some(&self.security)
    }
}

impl VlessConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"vless"];
        let sec_type = self.security.type_str().unwrap_or("none");
        parts.push(sec_type.as_bytes());
        parts.push(self.transport.type_str().as_bytes());
        match &self.transport {
            TransportConfig::HttpUpgrade(cfg) => {
                if let Some(ref v) = cfg.host {
                    parts.push(v.as_bytes());
                }
            }
            TransportConfig::XHttp(cfg) => {
                if let Some(ref v) = cfg.host {
                    parts.push(v.as_bytes());
                }
            }
            _ => {}
        }
        if let Some(ref path) = self.path {
            parts.push(path.as_bytes());
        }
        if let Some(ref v) = self.encryption {
            parts.push(v.as_bytes());
        }
        if let Some(v) = self.security.sni() {
            parts.push(v.as_bytes());
        }
        if let Some(ref v) = self.flow {
            parts.push(v.as_bytes());
        }
        if let Some(v) = self.security.alpn() {
            parts.push(v.as_bytes());
        }
        if let Some(v) = self.security.fp() {
            parts.push(v.as_bytes());
        }
        if let Some(v) = self.security.pbk() {
            parts.push(v.as_bytes());
        }
        if let Some(v) = self.security.sid() {
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
    use super::super::ProtoSpec;
    use crate::urlx::SchemeX;

    #[test]
    fn test_vless_basic() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Vless);
        assert_eq!(
            config.host().map(|h| h.to_str()),
            Some("159.223.24.65".into())
        );
        assert_eq!(config.uuid, "6202b230-417c-4d8e-b624-0f71afa9c75d");
    }

    #[test]
    fn test_vless_reality() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&pbk=abc123";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("failed");
        assert_eq!(config.schema(), SchemeX::Vless);
        assert_eq!(config.flow.as_deref(), Some("xtls-rprx-vision"));
        if let Some(super::TlsConfig::Reality(ref opts)) = config.security.tls {
            assert_eq!(opts.pbk.as_deref(), Some("abc123"));
        } else {
            panic!("expected reality config");
        }
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

    use super::super::test_helpers::check_roundtrip;
    use super::VlessConfig;

    #[test]
    fn test_roundtrip() {
        check_roundtrip::<VlessConfig>(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws",
        );
        check_roundtrip::<VlessConfig>(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host:443?type=ws&path=%2F",
        );
        check_roundtrip::<VlessConfig>("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host:443");
    }

    #[test]
    fn test_vless_httpupgrade() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host.com:443?type=httpupgrade&path=/test&host=myhost.com";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("httpupgrade parse failed");
        assert_eq!(config.transport.type_str(), "httpupgrade");
        check_roundtrip::<VlessConfig>(url);
    }

    #[test]
    fn test_vless_xhttp() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host.com:443?type=xhttp&mode=auto&path=/test&host=myhost.com";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("xhttp parse failed");
        assert_eq!(config.transport.type_str(), "xhttp");
        check_roundtrip::<VlessConfig>(url);
    }

    #[test]
    fn test_vless_xhttp_bad_mode() {
        let url =
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host.com:443?type=xhttp&mode=badmode";
        let raw = crate::urlx::RawUrlX::from(url);
        assert!(VlessConfig::try_parse(&raw).is_err());
    }

    #[test]
    fn test_vless_xhttp_extra() {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host.com:443?type=xhttp&mode=auto&path=/test&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("xhttp+extra parse failed");
        assert_eq!(config.transport.type_str(), "xhttp");
        if let super::TransportConfig::XHttp(ref xcfg) = config.transport {
            assert!(xcfg.extra.is_some());
        } else {
            panic!("expected XHttp transport");
        }
    }

    #[test]
    fn test_vless_httpupgrade_host_fallback() {
        let url =
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@host.com:443?type=httpupgrade&path=/test";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("httpupgrade no host parse failed");
        assert_eq!(config.transport.type_str(), "httpupgrade");
        if let super::TransportConfig::HttpUpgrade(ref cfg) = config.transport {
            assert_eq!(cfg.host.as_deref(), Some("host.com"));
        } else {
            panic!("expected HttpUpgrade transport");
        }
    }


    #[test]
    fn test_vless_short_string_creates_uuidv5() {
        let url = "vless://somechannel@159.223.24.65:443?security=tls&type=tcp";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("short string should parse successfully");
        // uuid must be a valid UUID (generated by UUIDv5)
        assert!(
            uuid::Uuid::parse_str(&config.uuid).is_ok(),
            "generated uuid must be a valid UUID: {}",
            config.uuid
        );
        // uuid_origin must be the original short string
        assert_eq!(
            config.uuid_origin.as_deref(),
            Some("somechannel"),
            "uuid_origin should preserve the original short string"
        );
        // Verify the generated UUID matches UUIDv5 from nil namespace
        let expected = uuid::Uuid::new_v5(&uuid::Uuid::nil(), b"somechannel").to_string();
        assert_eq!(config.uuid, expected, "uuid should be UUIDv5(nil, \"somechannel\")");
    }

    #[test]
    fn test_vless_short_string_roundtrip_preserves_origin() {
        let url = "vless://somechannel@159.223.24.65:443?security=tls&type=tcp";
        let raw = crate::urlx::RawUrlX::from(url);
        let parsed = VlessConfig::try_parse(&raw).expect("parse short string");
        // Reconstruct: the URL should contain the original short string, not the generated UUID
        let reconstructed = parsed.reconstruct().expect("reconstruct");
        assert!(
            reconstructed.contains("somechannel@"),
            "reconstructed URL should contain the original short string: {reconstructed}"
        );
        // Re-parse the reconstructed URL
        let raw2 = crate::urlx::RawUrlX::from(reconstructed.as_str());
        let reparsed = VlessConfig::try_parse(&raw2).expect("reparse");
        // uuid_origin should be preserved through roundtrip
        assert_eq!(
            reparsed.uuid_origin.as_deref(),
            Some("somechannel"),
            "uuid_origin should survive roundtrip"
        );
        assert_eq!(reparsed.uuid, parsed.uuid, "uuid should match");
    }

    #[test]
    fn test_vless_short_string_serde_roundtrip() {
        let url = "vless://somechannel@159.223.24.65:443?security=tls&type=tcp";
        let raw = crate::urlx::RawUrlX::from(url);
        let parsed = VlessConfig::try_parse(&raw).expect("parse short string");

        let json = serde_json::to_string(&parsed).expect("serialize");
        let deserialized: VlessConfig = serde_json::from_str(&json).expect("deserialize");

        // uuid_origin should survive serde
        assert_eq!(
            deserialized.uuid_origin.as_deref(),
            Some("somechannel"),
            "uuid_origin should survive serde roundtrip"
        );
        assert_eq!(deserialized.uuid, parsed.uuid, "uuid should match");

        // Reconstruct from deserialized should also use the original short string
        let reconstructed = deserialized.reconstruct().expect("reconstruct after serde");
        assert!(
            reconstructed.contains("somechannel@"),
            "reconstructed URL after serde should contain original string: {reconstructed}"
        );
    }

    #[test]
    fn test_vless_normal_uuid_has_no_uuid_origin() {
        // Standard UUIDs should have uuid_origin = None
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?type=tcp";
        let raw = crate::urlx::RawUrlX::from(url);
        let config = VlessConfig::try_parse(&raw).expect("normal UUID parse");
        assert!(
            config.uuid_origin.is_none(),
            "normal UUID should not set uuid_origin"
        );
        assert_eq!(config.uuid, "6202b230-417c-4d8e-b624-0f71afa9c75d");
        // Roundtrip should work as before
        let reconstructed = config.reconstruct().expect("reconstruct");
        assert!(
            reconstructed.contains("6202b230-417c-4d8e-b624-0f71afa9c75d@"),
            "reconstructed URL should contain the UUID"
        );
    }
}