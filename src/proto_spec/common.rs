use serde::{Deserialize, Serialize};

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
}

impl TransportConfig {
    pub fn type_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws(_) => "ws",
            Self::Grpc(_) => "grpc",
            Self::Http(_) => "http",
            Self::Quic => "quic",
            Self::Kcp(_) => "kcp",
        }
    }

    pub fn from_type_and_path(
        protocol_type: Option<&str>,
        path: Option<&str>,
    ) -> Option<Self> {
        match protocol_type {
            None | Some("tcp") => Some(Self::Tcp),
            Some("ws" | "websocket") => Some(Self::Ws(WebSocketConfig {
                path: path.map(|s| s.to_string()),
                ..WebSocketConfig::default()
            })),
            Some("grpc") => Some(Self::Grpc(GrpcConfig {
                path: path.map(|s| s.to_string()),
                ..GrpcConfig::default()
            })),
            Some("http" | "h2" | "https") => Some(Self::Http(HttpConfig {
                path: path.map(|s| s.to_string()),
                ..HttpConfig::default()
            })),
            Some("quic") => Some(Self::Quic),
            Some("kcp" | "mkcp") => Some(Self::Kcp(KcpConfig::default())),
            Some(other) => {
                tracing::warn!(target: "proto_spec", transport = %other, "Unknown transport type, falling back to tcp");
                Some(Self::Tcp)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WebSocketConfig {
    pub path: Option<String>,
    pub host: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<String>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: None,
            host: None,
            headers: None,
            max_early_data: None,
            early_data_header_name: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GrpcConfig {
    pub path: Option<String>,
    pub authority: Option<String>,
    pub service_name: Option<String>,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            path: None,
            authority: None,
            service_name: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HttpConfig {
    pub path: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            path: None,
            host: None,
            method: None,
            headers: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            mtu: None,
            tti: None,
            uplink_capacity: None,
            downlink_capacity: None,
            congestion: None,
            read_buffer: None,
            write_buffer: None,
            seed: None,
        }
    }
}
