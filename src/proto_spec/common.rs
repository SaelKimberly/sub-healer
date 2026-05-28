use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::urlx::TinyText;

// ========================================
// Transport Configurations
// ========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

    pub fn from_type_and_path(protocol_type: Option<&str>, path: Option<&str>) -> Option<Self> {
        match protocol_type {
            None | Some("tcp") => Some(Self::Tcp),
            Some("ws" | "websocket") => Some(Self::Ws(WebSocketConfig {
                path: path.map(std::string::ToString::to_string),
                ..WebSocketConfig::default()
            })),
            Some("grpc") => Some(Self::Grpc(GrpcConfig {
                path: path.map(std::string::ToString::to_string),
                ..GrpcConfig::default()
            })),
            Some("http" | "h2" | "https") => Some(Self::Http(HttpConfig {
                path: path.map(std::string::ToString::to_string),
                ..HttpConfig::default()
            })),
            Some("quic") => Some(Self::Quic),
            Some("kcp" | "mkcp") => Some(Self::Kcp(KcpConfig::default())),
            Some("httpupgrade") => Some(Self::HttpUpgrade(HttpUpgradeConfig {
                path: Some(path.unwrap_or("/").to_string()),
                ..HttpUpgradeConfig::default()
            })),
            Some("xhttp" | "splithttp") => Some(Self::XHttp(XHttpConfig {
                path: Some(path.unwrap_or("/").to_string()),
                mode: Some("auto".into()),
                ..XHttpConfig::default()
            })),
            Some(other) => {
                tracing::warn!(target: "proto_spec", transport = %other, "Unknown transport type, falling back to tcp");
                Some(Self::Tcp)
            }
        }
    }

    #[must_use]
    pub fn with_host(
        self,
        host: Option<String>,
        sni: Option<String>,
        server_addr: Option<String>,
    ) -> Self {
        let resolved = host.or(sni).or(server_addr);
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct WebSocketConfig {
    pub path: Option<String>,
    pub host: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct GrpcConfig {
    pub path: Option<String>,
    pub authority: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct HttpConfig {
    pub path: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

/// `HTTPUpgrade` transport config (fake WebSocket upgrade).
///
/// Sends HTTP GET with `Upgrade: websocket` → `101 Switching Protocols`,
/// then pipes raw bytes. No actual WebSocket framing.
///
/// Reference: `thirdparty/Xray-core/transport/internet/httpupgrade/config.proto`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct HttpUpgradeConfig {
    pub path: Option<String>,
    pub host: Option<String>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct XHttpConfig {
    pub path: Option<String>,
    pub host: Option<String>,
    pub mode: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub extra: Option<Value>,
}

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
    pub seed: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
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
    pub const fn sni(&self) -> Option<&str> {
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
    pub const fn alpn(&self) -> Option<&str> {
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
    pub const fn fp(&self) -> Option<&str> {
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
    pub const fn sid(&self) -> Option<&str> {
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
#[serde(rename_all = "snake_case")]
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
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub fp: Option<String>,
    pub insecure: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RealityOpts {
    pub sni: Option<String>,
    pub fp: Option<String>,
    pub pbk: Option<String>,
    pub sid: Option<String>,
    pub spx: Option<String>,
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
}
