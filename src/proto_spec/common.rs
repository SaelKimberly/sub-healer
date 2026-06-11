use crate::proto_spec::ParseError;
use serde::{Deserialize, Serialize};

use serde_json::Value;

use crate::urlx::{HostSpec, TinyText};

// ========================================
// Transport Configurations
// ========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportConfig {
    Tcp,
    Ws(WebSocketConfig),
    Grpc(GrpcConfig),
    Http(HttpConfig),
    Quic,
    Kcp(KcpConfig),
    HttpUpgrade(HttpUpgradeConfig),
    XHttp(XHttpConfig),
}

impl TransportConfig {
    #[must_use]
    pub const fn type_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws(_) => "ws",
            Self::Grpc(_) => "grpc",
            Self::Http(_) => "http",
            Self::Quic => "quic",
            Self::Kcp(_) => "kcp",
            Self::HttpUpgrade(_) => "httpupgrade",
            Self::XHttp(_) => "xhttp",
        }
    }
    fn recover_transport_type(input: &str) -> Option<&'static str> {
        // Sorted by length descending, so longest prefix matches first
        const KNOWN: &[&str] = &[
            "httpupgrade",
            "splithttp",
            "websocket",
            "https",
            "xhttp",
            "grpc",
            "http",
            "mkcp",
            "quic",
            "kcp",
            "raw",
            "tcp",
            "h2",
            "ws",
        ];
        let lower = input.to_ascii_lowercase();
        // Exact match (case-insensitive) via eq_ignore_ascii_case
        for &known in KNOWN {
            if known.eq_ignore_ascii_case(input) {
                return Some(known);
            }
        }
        // Longest prefix match
        KNOWN
            .iter()
            .find(|&&known| lower.starts_with(known))
            .copied()
            .map(|v| v as _)
    }

    /// # Errors
    ///
    /// Return ParseError, if protocol_type is invalid and could not be recovered.
    pub fn from_type_and_path(
        protocol_type: Option<&str>,
        path: Option<&str>,
    ) -> Result<Option<Self>, ParseError> {
        match protocol_type {
            None | Some("") => Ok(None),
            // "auto"/"none" on `net` field are common mistakes from share link
            // generators confusing `net` (transport) with `scy` (security) or
            // `type` (header type). Default to TCP like mihomo does.
            Some("tcp" | "raw" | "auto" | "none") => Ok(Some(Self::Tcp)),
            Some("ws" | "websocket") => Ok(Some(Self::Ws(WebSocketConfig {
                path: path.map(TinyText::from),
                ..WebSocketConfig::default()
            }))),
            Some("grpc") => Ok(Some(Self::Grpc(GrpcConfig {
                path: path.map(TinyText::from),
                ..GrpcConfig::default()
            }))),
            Some("http" | "h2" | "https") => Ok(Some(Self::Http(HttpConfig {
                path: path.map(TinyText::from),
                ..HttpConfig::default()
            }))),
            Some("quic") => Ok(Some(Self::Quic)),
            Some("kcp" | "mkcp") => Ok(Some(Self::Kcp(KcpConfig::default()))),
            Some("httpupgrade") => Ok(Some(Self::HttpUpgrade(HttpUpgradeConfig {
                path: Some(TinyText::from(path.unwrap_or("/"))),
                ..HttpUpgradeConfig::default()
            }))),
            Some("xhttp" | "splithttp") => Ok(Some(Self::XHttp(XHttpConfig {
                path: Some(TinyText::from(path.unwrap_or("/"))),
                mode: Some(TinyText::from("auto")),
                ..XHttpConfig::default()
            }))),

            Some(other) =>  Self::recover_transport_type(other).map_or_else(
                ||Err(ParseError::InvalidConf(
                    "type".into(),
                    other.to_string().into(),
                )), |recovered| {
                    tracing::warn!(target: "proto_spec", transport = %other, recovered = %recovered, "Recovered transport type");
                    Self::from_type_and_path(Some(recovered), path)
                })

        }
    }

    #[must_use]
    pub fn with_host(
        self,
        host: Option<String>,
        sni: Option<String>,
        server_addr: Option<String>,
    ) -> Self {
        let resolved: Option<TinyText> = host.or(sni).or(server_addr).map(TinyText::from);
        match self {
            Self::HttpUpgrade(cfg) => Self::HttpUpgrade(HttpUpgradeConfig {
                host: cfg.host.or(resolved),
                ..cfg
            }),
            Self::XHttp(cfg) => Self::XHttp(XHttpConfig {
                host: cfg.host.or(resolved),
                ..cfg
            }),
            other => other,
        }
    }
}

/// Returns `true` when `value` equals the server's DNS name (case-insensitive).
/// When the server is an IP address, always returns `false` — sni/host must be
/// emitted because the IP address cannot serve as a TLS SNI/HTTP Host value.
pub(crate) fn should_skip_param(host: &HostSpec, value: &str) -> bool {
    match host {
        HostSpec::DnsName(name) => name.as_ref().eq_ignore_ascii_case(value),
        _ => false,
    }
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct WebSocketConfig {
    pub path: Option<TinyText>,
    pub host: Option<TinyText>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<TinyText>,
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct GrpcConfig {
    pub path: Option<TinyText>,
    pub authority: Option<TinyText>,
    pub service_name: Option<TinyText>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct HttpConfig {
    pub path: Option<TinyText>,
    pub host: Option<TinyText>,
    pub method: Option<TinyText>,
    pub headers: Option<std::collections::HashMap<String, String>>,
}
/// `HTTPUpgrade` transport config (fake WebSocket upgrade).
///
/// Sends HTTP GET with `Upgrade: websocket` → `101 Switching Protocols`,
/// then pipes raw bytes. No actual WebSocket framing.
///
/// Reference: `thirdparty/Xray-core/transport/internet/httpupgrade/config.proto`
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct HttpUpgradeConfig {
    pub path: Option<TinyText>,
    pub host: Option<TinyText>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub ed: Option<u32>,
}
/// SplitHTTP/XHTTP transport config — full HTTP-based transport.
///
/// Supports 4 modes (`auto`, `packet-up`, `stream-up`, `stream-one`),
/// session-based multiplexing, `XPadding` obfuscation, separate download paths.
/// Extra fields from share link `extra=` JSON blob are stored raw.
///
/// Reference config proto: `thirdparty/Xray-core/transport/internet/splithttp/config.proto`
/// Reference client config: `thirdparty/mihomo/transport/xhttp/config.go`
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct XHttpConfig {
    pub path: Option<TinyText>,
    pub host: Option<TinyText>,
    pub mode: Option<TinyText>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub extra: Option<Value>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct KcpConfig {
    pub mtu: Option<u32>,
    pub tti: Option<u32>,
    pub uplink_capacity: Option<u32>,
    pub downlink_capacity: Option<u32>,
    pub congestion: Option<bool>,
    pub read_buffer: Option<u32>,
    pub write_buffer: Option<u32>,
    pub seed: Option<TinyText>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    #[serde(flatten)]
    pub tls: Option<TlsConfig>,
    pub enc: Option<TinyText>,
}

impl SecurityConfig {
    #[must_use]
    pub const fn type_str(&self) -> Option<&'static str> {
        match self.tls {
            None => None,
            Some(ref c @ (TlsConfig::Reality(_) | TlsConfig::Tls(_))) => Some(c.type_str()),
        }
    }
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        match self.tls {
            Some(
                TlsConfig::Tls(TlsOpts {
                    sni: Some(ref sni), ..
                })
                | TlsConfig::Reality(RealityOpts {
                    sni: Some(ref sni), ..
                }),
            ) => Some(sni.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub fn alpn(&self) -> Option<&str> {
        if let Some(TlsConfig::Tls(TlsOpts {
            alpn: Some(ref alpn),
            ..
        })) = self.tls
        {
            Some(alpn.as_str())
        } else {
            None
        }
    }

    #[must_use]
    pub fn fp(&self) -> Option<&str> {
        match self.tls {
            Some(
                TlsConfig::Tls(TlsOpts {
                    fp: Some(ref fp), ..
                })
                | TlsConfig::Reality(RealityOpts {
                    fp: Some(ref fp), ..
                }),
            ) => Some(fp.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub const fn insecure(&self) -> Option<bool> {
        if let Some(TlsConfig::Tls(TlsOpts { insecure, .. })) = self.tls {
            insecure
        } else {
            None
        }
    }

    #[must_use]
    pub const fn pbk(&self) -> Option<&str> {
        if let Some(TlsConfig::Reality(RealityOpts {
            pbk: Some(ref pbk), ..
        })) = self.tls
        {
            Some(pbk.as_str())
        } else {
            None
        }
    }

    #[must_use]
    pub fn sid(&self) -> Option<&str> {
        if let Some(TlsConfig::Reality(RealityOpts {
            sni: Some(ref sni), ..
        })) = self.tls
        {
            Some(sni.as_str())
        } else {
            None
        }
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tls.is_none() && self.enc.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TlsConfig {
    Tls(TlsOpts),
    Reality(RealityOpts),
}

impl TlsConfig {
    #[must_use]
    pub const fn type_str(&self) -> &'static str {
        match self {
            Self::Tls(_) => "tls",
            Self::Reality(_) => "reality",
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct TlsOpts {
    pub sni: Option<TinyText>,
    pub alpn: Option<TinyText>,
    pub fp: Option<TinyText>,
    pub insecure: Option<bool>,
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RealityOpts {
    pub sni: Option<TinyText>,
    pub fp: Option<TinyText>,
    pub pbk: Option<String>,
    pub sid: Option<TinyText>,
    pub spx: Option<TinyText>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_config_default_is_empty() {
        let sc = SecurityConfig::default();
        assert!(sc.tls.is_none());
        assert!(sc.enc.is_none());
    }

    #[test]
    fn security_config_type_str() {
        let tls = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts::default())),
            enc: None,
        };
        assert_eq!(tls.type_str(), Some("tls"));

        let reality = SecurityConfig {
            tls: Some(TlsConfig::Reality(RealityOpts::default())),
            enc: None,
        };
        assert_eq!(reality.type_str(), Some("reality"));

        let none = SecurityConfig::default();
        assert_eq!(none.type_str(), None);
    }

    #[test]
    fn security_config_serde_empty() {
        let sc = SecurityConfig::default();
        let json = serde_json::to_string(&sc).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn security_config_serde_tls() {
        let sc = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: Some("example.com".into()),
                ..TlsOpts::default()
            })),
            enc: None,
        };
        let json = serde_json::to_string(&sc).unwrap();
        assert!(json.contains("\"tls\""));
        assert!(json.contains("\"sni\""));
        assert!(json.contains("\"example.com\""));
        assert!(!json.contains("\"enc\""));
    }

    #[test]
    fn should_skip_param_skips_matching_dns() {
        let host =
            HostSpec::DnsName(rustls::pki_types::DnsName::try_from_str("example.com").unwrap());
        assert!(should_skip_param(&host, "example.com"));
        assert!(should_skip_param(&host, "EXAMPLE.COM"));
        assert!(!should_skip_param(&host, "other.com"));
        assert!(!should_skip_param(&host, "example.org"));
    }

    #[test]
    fn should_skip_param_never_skips_for_ip() {
        let host_v4 = HostSpec::IpAddress(rustls::pki_types::IpAddr::V4(
            rustls::pki_types::Ipv4Addr::from(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        ));
        assert!(!should_skip_param(&host_v4, "anything"));
        assert!(!should_skip_param(&host_v4, "1.2.3.4"));

        let host_v6 = HostSpec::IpAddress(rustls::pki_types::IpAddr::V6(
            rustls::pki_types::Ipv6Addr::from(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ));
        assert!(!should_skip_param(&host_v6, "::1"));
        assert!(!should_skip_param(&host_v6, "anything"));
    }
}
