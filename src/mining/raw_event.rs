use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::registry::SourceMetadata;

/// Batch of decoded-and-normalized raw URL strings from one fetch operation.
///
/// Each batch corresponds to a single fetch boundary:
/// - Telegram: all URLs extracted from one message's HTML
/// - Subscription: all decoded lines from one subscription download
/// - Stdin/Local: all decoded lines from one file or pipe input
///
/// The consumer ([`crate::mining::Pipeline::run`]) iterates over each URL,
/// calls [`crate::proto_spec::ProtocolConfig::try_parse_detailed`], and
/// handles all outcomes (Direct, Fallback, Unparseable) in one place.
#[derive(Debug, Clone)]
pub struct RawSourceItemBatch {
    pub source: Arc<SourceMetadata>,
    pub timestamp: DateTime<Utc>,
    pub raw_urls: Box<[String]>,
}
