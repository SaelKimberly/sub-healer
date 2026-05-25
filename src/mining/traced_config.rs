use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::proto_spec::ProtocolConfig;

use super::registry::SourceMetadata;

/// A parsed protocol config with trace metadata: when and where it was observed.
#[derive(Debug, Clone)]
pub struct TracedProtocolConfig {
    pub config: ProtocolConfig,
    pub timestamp: DateTime<Utc>,
    pub source: Arc<SourceMetadata>,
}
