use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRecord {
    pub id: i64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRecord {
    pub id: i64,
    pub schema: String,
    pub host: String,
    pub port: String,
    pub transport: Option<String>,
    pub security: Option<String>,
    pub remarks: Option<String>,
    pub raw_config: String,
    pub first_seen_ts: i64,
    pub first_seen_source_id: i64,
    pub sig: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SightingRecord {
    pub id: i64,
    pub server_id: i64,
    pub source_id: i64,
    pub seen_ts: i64,
    pub remarks: Option<String>,
}
