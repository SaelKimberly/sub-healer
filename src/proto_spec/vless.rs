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

use crate::urlx::{HostSpec, RawUrlX, SchemeX, host_serde, port_serde};

use super::common::TransportConfig;
use super::utils;
use super::{ParseError, ProtoSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct VlessConfig {
    #[serde(skip)]
    sig_cache: std::sync::OnceLock<NonZeroU64>,

    pub uuid: String,
    #[serde(with = "host_serde")]
    pub host: HostSpec,
    #[serde(with = "port_serde")]
    pub port: u16,
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
    /// Parse a VLESS URL (standard URI format).
    ///
    /// UUID is extracted from userinfo, server address from host:port,
    /// all configuration from query parameters, remarks from fragment.
    ///
    /// Supports combined `userinfo@hostport` or separate hostport components.
    /// UUID validated via `uuid::Uuid::parse_str`.
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

        uuid::Uuid::parse_str(username)
            .map_err(|_| ParseError::InvalidUserInfo(format!("invalid UUID: {username}").into()))?;

        let query = utils::parse_query(raw.query);

        // security: tls/reality/none. Defaults to "none" (no TLS).
        let security = query
            .get("security")
            .map_or("none", |s| s.as_str())
            .to_string();
        // type/transport: tcp/ws/grpc/http/kcp/quic/httpupgrade. Defaults to "tcp".
        let transport_type = query.get("type").map_or("tcp", |s| s.as_str()).to_string();
        let path = query.get("path").cloned();
        // encryption: typically "none" (VLESS relies on TLS, not payload encryption)
        let encryption = query.get("encryption").filter(|v| v != &"none").cloned();
        // flow: xtls-rprx-vision for XTLS direct transmission (TLS 1.3 required)
        let flow = query.get("flow").cloned();
        // sni: TLS SNI override (overrides host for TLS server name)
        // alpn: comma-separated ALPN list (e.g., "h2,http/1.1")
        let alpn = query.get("alpn").cloned();
        // fp: uTLS Client Hello fingerprint (chrome/firefox/safari/random/randomized)
        let fp = query.get("fp").cloned();
        // pbk: REALITY public key (base64-encoded)
        let pbk = query.get("pbk").cloned();
        // sid: REALITY short ID (hex string)
        let sid = query.get("sid").cloned();
        // splice: boolean splice mode flag
        let splice = query.get("splice").and_then(|v| match v.as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        });

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
                        xcfg.mode = Some(mode.clone());
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
            uuid: username.to_string(),
            host: parsed_host,
            port: parsed_port,
            transport,
            security,
            encryption,
            flow,
            path,
            sni: query.get("sni").cloned(),
            alpn,
            fp,
            pbk,
            sid,
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

        let mut base = url::Url::parse(format!("vless://{}@{hostport}", self.uuid).as_str())
            .map_err(|e| ParseError::Unknown(e.into()))?;

        {
            let mut q = base.query_pairs_mut();
            if self.security != "none" {
                q.append_pair("security", &self.security);
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

    fn security_type(&self) -> Option<&str> {
        Some(self.security.as_str())
    }
}

impl VlessConfig {
    fn compute_sig(&self) -> u64 {
        let mut parts: Vec<&[u8]> = vec![b"vless"];
        parts.push(self.security.as_bytes());
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
}
