// Copyright 2024 v2ray-heal authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

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
    /// Full source URL (e.g., "<https://t.me/proxy_channel>" or "<https://example.com/sub.txt>")
    pub url: String,
    /// Pre-computed hash of URL, used as primary key in database
    pub id: i64,
    /// Type of source
    pub source_type: SourceType,
}

impl SourceMetadata {
    /// Create new source metadata
    #[must_use]
    pub fn new(url: String, source_type: SourceType) -> Self {
        let id = hash_source_url(&url);
        Self {
            url,
            id,
            source_type,
        }
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
    #[must_use]
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

    /// Upsert all registered sources to the database
    /// # Errors
    /// Returns error if database operation fails
    pub fn upsert_all(&self, conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        for source in self.sources() {
            crate::db::upsert_source(conn, &source.url)?;
        }
        Ok(())
    }
}


