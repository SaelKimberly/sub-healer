// Copyright 2024 v2ray-heal authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::db::hash_source_url;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_metadata_creation() {
        let metadata = SourceMetadata::new(
            "https://t.me/test_channel".to_string(),
            SourceType::Telegram,
        );
        
        assert_eq!(metadata.url, "https://t.me/test_channel");
        assert_eq!(metadata.source_type, SourceType::Telegram);
        // ID should be deterministic hash
        assert_ne!(metadata.id, 0);
    }

    #[test]
    fn test_registry_pre_populate_and_lookup() {
        let mut registry = SourceRegistry::new();
        
        // Pre-populate with sources
        registry.pre_populate("https://t.me/channel1", SourceType::Telegram);
        registry.pre_populate("https://example.com/sub.txt", SourceType::Subscription);
        
        // Lookup should work
        let source1 = registry.lookup("https://t.me/channel1");
        assert!(source1.is_some());
        assert_eq!(source1.unwrap().source_type, SourceType::Telegram);
        
        let source2 = registry.lookup("https://example.com/sub.txt");
        assert!(source2.is_some());
        assert_eq!(source2.unwrap().source_type, SourceType::Subscription);
        
        // Non-existent source should return None
        let source3 = registry.lookup("https://nonexistent.com/test");
        assert!(source3.is_none());
    }

    #[test]
    fn test_timestamped_proxy_creation() {
        let mut registry = SourceRegistry::new();
        registry.pre_populate("https://t.me/channel1", SourceType::Telegram);
        let source = registry.lookup("https://t.me/channel1").unwrap();
        
        // Create a simple UrlX by parsing a basic URL
        // This tests that TimestampedProxy can work with real UrlX instances
        let simple_url = "https://example.com";
        let urlx = simple_url.parse::<crate::UrlX>().expect("Should parse simple URL");
        
        let timestamp = Utc::now();
        let raw_content = Some("vless://test@example.com".to_string());
        
        // Create the timestamped proxy
        let proxy = TimestampedProxy::new(urlx, timestamp, source, raw_content);
        
        // Verify all fields are properly set
        assert_eq!(proxy.source.url, "https://t.me/channel1");
        assert_eq!(proxy.timestamp, timestamp);
        assert!(proxy.raw_content.is_some());
        assert_eq!(proxy.raw_content.unwrap(), "vless://test@example.com");
        
        // Verify source metadata is correctly shared via Arc
        assert_eq!(std::sync::Arc::strong_count(&proxy.source), 2); // registry + proxy
    }

    #[test]
    fn test_registry_immutability() {
        let mut registry = SourceRegistry::new();
        registry.pre_populate("https://test.com", SourceType::Subscription);
        
        // Convert to immutable Arc
        let registry = std::sync::Arc::new(registry);
        
        // Multiple threads can safely access
        let registry1 = std::sync::Arc::clone(&registry);
        let registry2 = std::sync::Arc::clone(&registry);
        
        let source1 = registry1.lookup("https://test.com");
        let source2 = registry2.lookup("https://test.com");
        
        assert!(source1.is_some());
        assert!(source2.is_some());
        assert_eq!(source1.unwrap().id, source2.unwrap().id);
    }
}



/// Type of proxy source
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    /// Telegram channel
    Telegram,
    /// Subscription URL
    Subscription,
    /// Other source type
    Other,
}

/// Metadata about a proxy source
#[derive(Debug, Clone)]
pub struct SourceMetadata {
    /// Full source URL (e.g., "https://t.me/proxy_channel" or "https://example.com/sub.txt")
    pub url: String,
    /// Pre-computed hash of URL, used as primary key in database
    pub id: i64,
    /// Type of source
    pub source_type: SourceType,
}

impl SourceMetadata {
    /// Create new source metadata
    pub fn new(url: String, source_type: SourceType) -> Self {
        let id = hash_source_url(&url);
        Self { url, id, source_type }
    }
}

/// Registry of all proxy sources
/// Pre-populated before creating any streams, then becomes immutable
#[derive(Debug, Default)]
pub struct SourceRegistry {
    sources: HashMap<String, Arc<SourceMetadata>>,
}

impl SourceRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
        }
    }

    /// Pre-populate registry with a source
    /// Called during initialization before any streams are created
    pub fn pre_populate(&mut self, url: &str, source_type: SourceType) {
        let metadata = Arc::new(SourceMetadata::new(url.to_string(), source_type));
        self.sources.insert(url.to_string(), metadata);
    }

    /// Lookup source metadata by URL
    /// Returns None if source was not pre-populated
    pub fn lookup(&self, url: &str) -> Option<Arc<SourceMetadata>> {
        self.sources.get(url).map(Arc::clone)
    }

    /// Get all registered sources
    pub fn sources(&self) -> Vec<Arc<SourceMetadata>> {
        self.sources.values().map(Arc::clone).collect()
    }
}

/// Proxy configuration with timestamp and source information
#[derive(Debug, Clone)]
pub struct TimestampedProxy {
    /// Parsed proxy URL
    pub urlx: crate::UrlX,
    /// When this proxy was observed
    /// For Telegram: message timestamp
    /// For subscriptions: download time or Last-Modified header
    pub timestamp: DateTime<Utc>,
    /// Source metadata (shared via Arc for efficiency)
    pub source: Arc<SourceMetadata>,
    /// Original content for debugging (optional)
    pub raw_content: Option<String>,
}

impl TimestampedProxy {
    /// Create new timestamped proxy
    pub fn new(
        urlx: crate::UrlX,
        timestamp: DateTime<Utc>,
        source: Arc<SourceMetadata>,
        raw_content: Option<String>,
    ) -> Self {
        Self {
            urlx,
            timestamp,
            source,
            raw_content,
        }
    }
}
