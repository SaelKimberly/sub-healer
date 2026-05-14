// Copyright 2024 v2ray-heal authors
// SPDX-License-Identifier: MIT OR Apache-2.0

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
        
        // Create a dummy UrlX for testing
        let urlx = UrlX::default();
        let timestamp = Utc::now();
        
        let proxy = TimestampedProxy::new(urlx, timestamp, source, None);
        
        assert_eq!(proxy.source.url, "https://t.me/channel1");
        assert_eq!(proxy.timestamp, timestamp);
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
