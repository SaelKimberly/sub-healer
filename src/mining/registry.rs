use anyhow::Context;
use futures::StreamExt;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::info;
use yaml_rust2::{Yaml, YamlLoader};

use crate::db::hash_source_url;

/// Type of proxy source
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Telegram,
    Subscription,
    Other,
}

/// Metadata about a proxy source
#[derive(Debug, Clone)]
pub struct SourceMetadata {
    pub url: String,
    pub id: i64,
    pub source_type: SourceType,
}

impl SourceMetadata {
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
        }
    }

    /// Pre-populate registry with a source
    pub fn pre_populate(&mut self, url: &str, source_type: SourceType) {
        let metadata = Arc::new(SourceMetadata::new(url.to_string(), source_type));
        self.sources.insert(url.to_string(), metadata);
    }

    /// Add a Telegram channel, normalizing to canonical `https://t.me/s/{name}` form
    pub fn add_telegram_channel(&mut self, raw: &str) {
        let canonical = normalize_channel_url(raw);
        self.pre_populate(&canonical, SourceType::Telegram);
    }

    /// Add a subscription URL as-is
    pub fn add_subscription(&mut self, url: &str) {
        self.pre_populate(url, SourceType::Subscription);
    }

    /// Lookup source metadata by URL
    pub fn lookup(&self, url: &str) -> Option<Arc<SourceMetadata>> {
        self.sources.get(url).map(Arc::clone)
    }

    /// Get all registered sources
    pub fn sources(&self) -> Vec<Arc<SourceMetadata>> {
        self.sources.values().map(Arc::clone).collect()
    }

    /// Upsert all registered sources to the database
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn upsert_all(&self, conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        for source in self.sources() {
            crate::db::upsert_source(conn, &source.url)?;
        }
        Ok(())
    }

    /// Partition sources into (telegram_channels, subscriptions) lists
    fn partition_sources(&self) -> (Vec<String>, Vec<String>) {
        let mut channels = Vec::new();
        let mut subscriptions = Vec::new();
        for meta in self.sources() {
            match meta.source_type {
                SourceType::Telegram => channels.push(meta.url.clone()),
                SourceType::Subscription => subscriptions.push(meta.url.clone()),
                SourceType::Other => {}
            }
        }
        (channels, subscriptions)
    }

    /// Construct registry from channel and subscription URL lists
    pub(crate) fn from_sources(channels: &[String], subscriptions: &[String]) -> Self {
        let mut registry = Self::new();
        for channel in channels {
            registry.add_telegram_channel(channel);
        }
        for sub in subscriptions {
            registry.add_subscription(sub);
        }
        registry
    }

    /// Load config from YAML file, normalize channels, pre-populate registry
    ///
    /// # Errors
    /// - Failed to read config file
    /// - Failed to parse YAML
    /// - Invalid or empty config file
    /// - Invalid or missing tgchannel in config file
    pub fn from_config(path: &Path) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path).context("Failed to read config file")?;
        let docs = YamlLoader::load_from_str(&content).context("Failed to parse YAML")?;

        let Some(Yaml::Hash(h)) = docs.first() else {
            return Err(anyhow::anyhow!("Invalid or empty config file"));
        };

        let channels: Vec<String> = h
            .get(&Yaml::String("tgchannel".into()))
            .and_then(|v| v.as_vec())
            .map(|list| {
                list.iter()
                    .filter_map(|v| match v {
                        Yaml::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let subscriptions: Vec<String> = h
            .get(&Yaml::String("subscriptions".into()))
            .and_then(|v| v.as_vec())
            .map(|list| {
                list.iter()
                    .filter_map(|v| match v {
                        Yaml::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self::from_sources(&channels, &subscriptions))
    }

    /// Run the full mining pipeline with the given fetcher
    ///
    /// # Errors
    ///
    /// Returns an error if the pipeline fails
    pub async fn run_pipeline_with<F: SourceFetcher>(
        self: Arc<Self>,
        client: &reqwest::Client,
        conn: &rusqlite::Connection,
        fetcher: F,
    ) -> Result<(), anyhow::Error> {
        let (channels, subscriptions) = self.partition_sources();
        info!(
            channels = channels.len(),
            subscriptions = subscriptions.len(),
            "Running mining pipeline"
        );
        let stream = fetcher.fetch(client, self, channels, subscriptions);
        let total = super::process_config_stream(stream, conn).await?;
        info!(count = total, "Mining pipeline completed");
        Ok(())
    }

    /// Run the full mining pipeline with the default `LiveFetcher`
    ///
    /// # Errors
    ///
    /// Returns an error if the pipeline fails
    pub async fn run_pipeline(
        self: Arc<Self>,
        client: &reqwest::Client,
        conn: &rusqlite::Connection,
    ) -> Result<(), anyhow::Error> {
        self.run_pipeline_with(client, conn, LiveFetcher::default())
            .await
    }

    /// Run a fetcher stream from the registry sources, returning a boxed stream of traced configs
    pub fn run_fetcher_stream<F: SourceFetcher>(
        self: Arc<Self>,
        client: &reqwest::Client,
        fetcher: F,
    ) -> futures::stream::BoxStream<'static, TracedProtocolConfig> {
        let (channels, subscriptions) = self.partition_sources();
        fetcher.fetch(client, self, channels, subscriptions)
    }
}

pub(super) fn normalize_channel_url(raw: &str) -> String {
    let channel_id = raw
        .strip_prefix("https://t.me/s/")
        .or_else(|| raw.strip_prefix("https://t.me/"))
        .unwrap_or(raw)
        .trim_start_matches('@');
    format!("https://t.me/s/{channel_id}")
}

pub trait SourceFetcher {
    fn fetch(
        &self,
        client: &reqwest::Client,
        registry: Arc<SourceRegistry>,
        channels: Vec<String>,
        subscriptions: Vec<String>,
    ) -> futures::stream::BoxStream<'static, TracedProtocolConfig>;
}

#[derive(Default)]
pub struct LiveFetcher {
    pub tg_config: super::TgConfig,
}

impl SourceFetcher for LiveFetcher {
    fn fetch(
        &self,
        client: &reqwest::Client,
        registry: Arc<SourceRegistry>,
        channels: Vec<String>,
        subscriptions: Vec<String>,
    ) -> futures::stream::BoxStream<'static, TracedProtocolConfig> {
        let tg_stream = if channels.is_empty() {
            None
        } else {
            Some(
                super::telegram::fetch_tg_channels(
                    client.clone(),
                    self.tg_config.concurrency,
                    channels.into_iter(),
                    self.tg_config.timeout,
                    self.tg_config.backfill.clone(),
                    self.tg_config.per_source_backfill.clone(),
                    registry.clone(),
                )
                .boxed(),
            )
        };

        let sub_stream = if subscriptions.is_empty() {
            None
        } else {
            Some(super::sub::fetch_subscriptions(client.clone(), registry, subscriptions).boxed())
        };

        match (tg_stream, sub_stream) {
            (Some(tg), Some(sub)) => futures::stream::select(tg, sub).boxed(),
            (Some(tg), None) => tg,
            (None, Some(sub)) => sub,
            (None, None) => futures::stream::empty().boxed(),
        }
    }
}

use super::TracedProtocolConfig;

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
        assert_ne!(metadata.id, 0);
    }

    #[test]
    fn test_registry_pre_populate_and_lookup() {
        let mut registry = SourceRegistry::new();

        registry.pre_populate("https://t.me/channel1", SourceType::Telegram);
        registry.pre_populate("https://example.com/sub.txt", SourceType::Subscription);

        let source1 = registry.lookup("https://t.me/channel1");
        assert!(source1.is_some());
        assert_eq!(source1.unwrap().source_type, SourceType::Telegram);

        let source2 = registry.lookup("https://example.com/sub.txt");
        assert!(source2.is_some());
        assert_eq!(source2.unwrap().source_type, SourceType::Subscription);

        let source3 = registry.lookup("https://nonexistent.com/test");
        assert!(source3.is_none());
    }

    #[test]
    fn test_registry_immutability() {
        let mut registry = SourceRegistry::new();
        registry.pre_populate("https://test.com", SourceType::Subscription);

        let registry = std::sync::Arc::new(registry);

        let registry1 = std::sync::Arc::clone(&registry);
        let registry2 = std::sync::Arc::clone(&registry);

        let source1 = registry1.lookup("https://test.com");
        let source2 = registry2.lookup("https://test.com");

        assert!(source1.is_some());
        assert!(source2.is_some());
        assert_eq!(source1.unwrap().id, source2.unwrap().id);
    }

    #[test]
    fn test_normalize_channel_url() {
        assert_eq!(
            normalize_channel_url("MyChannel"),
            "https://t.me/s/MyChannel"
        );
        assert_eq!(
            normalize_channel_url("@MyChannel"),
            "https://t.me/s/MyChannel"
        );
        assert_eq!(
            normalize_channel_url("https://t.me/MyChannel"),
            "https://t.me/s/MyChannel"
        );
        assert_eq!(
            normalize_channel_url("https://t.me/s/MyChannel"),
            "https://t.me/s/MyChannel"
        );
    }

    #[test]
    fn test_add_telegram_channel() {
        let mut registry = SourceRegistry::new();
        registry.add_telegram_channel("https://t.me/SomeChannel");
        let meta = registry.lookup("https://t.me/s/SomeChannel");
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().source_type, SourceType::Telegram);
    }

    #[test]
    fn test_add_subscription() {
        let mut registry = SourceRegistry::new();
        registry.add_subscription("https://example.com/sub");
        let meta = registry.lookup("https://example.com/sub");
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().source_type, SourceType::Subscription);
    }

    #[test]
    fn test_from_sources() {
        let channels = vec![
            "Chan1".to_string(),
            "@Chan2".to_string(),
            "https://t.me/Chan3".to_string(),
        ];
        let subs = vec!["https://example.com/sub".to_string()];
        let registry = SourceRegistry::from_sources(&channels, &subs);

        assert!(registry.lookup("https://t.me/s/Chan1").is_some());
        assert!(registry.lookup("https://t.me/s/Chan2").is_some());
        assert!(registry.lookup("https://t.me/s/Chan3").is_some());
        assert!(registry.lookup("https://example.com/sub").is_some());
    }

    #[test]
    fn test_partition_sources() {
        let channels = vec!["Chan1".to_string()];
        let subs = vec!["https://example.com/sub".to_string()];
        let registry = SourceRegistry::from_sources(&channels, &subs);

        let (ch, su) = registry.partition_sources();
        assert_eq!(ch.len(), 1);
        assert_eq!(ch[0], "https://t.me/s/Chan1");
        assert_eq!(su.len(), 1);
        assert_eq!(su[0], "https://example.com/sub");
    }
}
