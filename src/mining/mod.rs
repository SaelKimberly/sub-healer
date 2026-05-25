mod config;
mod registry;
mod sub;
pub mod telegram;
mod traced_config;
mod unparseable_log;
mod writer;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use tracing::info;

pub use config::{load_config, load_subscriptions, ConfigSource, YamlConfigSource};
pub use registry::{SourceMetadata, SourceRegistry, SourceType};
pub use sub::{download_sub_data, fetch_subscriptions, lines_to_traced};
pub use traced_config::TracedProtocolConfig;
pub use unparseable_log::UnparseableLayer;
pub use writer::PipelineLogWriter;

pub const PROXY_URL: &str = "http://127.0.0.1:20172";
pub const SEMAPHORE_PERMITS: usize = 64;
pub const USER_AGENT: &str = "clash-verge/v2.0.2";

/// # Panics
///
/// Will panic if the system time is before the UNIX epoch.
#[must_use]
pub fn get_current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed()
}

/// # Errors
///
/// Will return `Err` if the database cannot be opened or the schema cannot be initialized.
pub fn open_db(path: &Path) -> Result<rusqlite::Connection, anyhow::Error> {
    let conn = rusqlite::Connection::open(path)
        .with_context(|| format!("Failed to open database: {}", path.display()))?;
    crate::db::init_db(&conn).context("Failed to initialize database schema")?;
    Ok(conn)
}

/// # Errors
///
/// Will return `Err` if the proxy URL is invalid or the client cannot be built.
pub fn build_client() -> Result<reqwest::Client, anyhow::Error> {
    Ok(reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(PROXY_URL)?)
        .timeout(Duration::from_secs(30))
        .build()?)
}

/// Process a stream of traced configs, writing each to the database.
/// Returns the number of successfully processed items.
/// Fatal on DB error (aborts pipeline).
async fn process_config_stream(
    mut stream: impl StreamExt<Item = TracedProtocolConfig> + std::marker::Unpin,
    conn: &rusqlite::Connection,
) -> Result<usize, anyhow::Error> {
    let mut count = 0usize;
    while let Some(item) = stream.next().await {
        crate::db::upsert_server(
            &conn,
            &item.config,
            item.source.id,
            item.timestamp.timestamp(),
        )
        .context("upsert failed (aborting)")?;
        count += 1;
    }
    Ok(count)
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

pub struct LiveFetcher;

impl SourceFetcher for LiveFetcher {
    fn fetch(
        &self,
        client: &reqwest::Client,
        registry: Arc<SourceRegistry>,
        channels: Vec<String>,
        subscriptions: Vec<String>,
    ) -> futures::stream::BoxStream<'static, TracedProtocolConfig> {
        let tg_stream = if !channels.is_empty() {
            Some(telegram::fetch_tg_channels(
                client.clone(),
                8,
                channels.into_iter(),
                Duration::from_secs(30),
                None,
                registry.clone(),
            ).boxed())
        } else {
            None
        };

        let sub_stream = if !subscriptions.is_empty() {
            Some(sub::fetch_subscriptions(
                client.clone(),
                registry.clone(),
                subscriptions,
            ).boxed())
        } else {
            None
        };

        match (tg_stream, sub_stream) {
            (Some(tg), Some(sub)) => futures::stream::select(tg, sub).boxed(),
            (Some(tg), None) => tg,
            (None, Some(sub)) => sub,
            (None, None) => futures::stream::empty().boxed(),
        }
    }
}

pub struct Pipeline<C: ConfigSource, F: SourceFetcher> {
    config_source: C,
    fetcher: F,
}

impl<C: ConfigSource, F: SourceFetcher> Pipeline<C, F> {
    #[must_use]
    pub fn new(config_source: C, fetcher: F) -> Self {
        Self { config_source, fetcher }
    }

    /// # Errors
    ///
    /// Will return `Err` if config loading or pipeline processing fails.
    pub async fn run(
        &self,
        client: &reqwest::Client,
        conn: &rusqlite::Connection,
    ) -> Result<(), anyhow::Error> {
        let (channels, subscriptions) = self.config_source.sources()
            .context("Failed to load config")?;
        info!(
            channels = channels.len(),
            subscriptions = subscriptions.len(),
            "Loaded config"
        );

        let mut registry = SourceRegistry::new();
        for channel in &channels {
            registry.pre_populate(channel, SourceType::Telegram);
        }
        for sub in &subscriptions {
            registry.pre_populate(sub, SourceType::Subscription);
        }
        let registry = Arc::new(registry);

        registry
            .upsert_all(conn)
            .context("Failed to upsert sources to database")?;

        info!("Running mining pipeline");
        let stream = self.fetcher.fetch(client, registry, channels, subscriptions);
        let total = process_config_stream(stream, conn).await?;
        info!(count = total, "Mining pipeline completed");
        Ok(())
    }
}

/// # Errors
///
/// Will return `Err` if the config file is invalid or the database cannot be opened.
pub async fn run_with_config(config_path: &Path, db_path: &Path) -> Result<(), anyhow::Error> {
    info!("Starting mining run with config: {}", config_path.display());
    let config_source = YamlConfigSource::from_path(config_path)?;
    let client = build_client()?;
    let conn = open_db(db_path)?;
    let pipeline = Pipeline::new(config_source, LiveFetcher);
    pipeline.run(&client, &conn).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto_spec::ProtocolConfig;
    use crate::urlx::RawUrlX;
    use chrono::DateTime;
    use crate::proto_spec::ProtoSpec;

    struct TestConfigSource {
        channels: Vec<String>,
        subscriptions: Vec<String>,
    }

    impl ConfigSource for TestConfigSource {
        fn sources(&self) -> Result<(Vec<String>, Vec<String>), anyhow::Error> {
            Ok((self.channels.clone(), self.subscriptions.clone()))
        }
    }

    struct StubFetcher {
        items: Vec<TracedProtocolConfig>,
    }

    impl StubFetcher {
        fn new(items: Vec<TracedProtocolConfig>) -> Self {
            Self { items }
        }
    }

    impl SourceFetcher for StubFetcher {
        fn fetch(
            &self,
            _client: &reqwest::Client,
            _registry: Arc<SourceRegistry>,
            _channels: Vec<String>,
            _subscriptions: Vec<String>,
        ) -> futures::stream::BoxStream<'static, TracedProtocolConfig> {
            futures::stream::iter(self.items.clone()).boxed()
        }
    }

    fn make_in_memory_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory()
            .expect("in-memory db");
        crate::db::init_db(&conn).expect("init schema");
        conn
    }

    fn make_vmess_config() -> ProtocolConfig {
        let raw = RawUrlX::from("vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0Ijo4MCwiaWQiOiJhYmNkZS0xMjM0NS02Nzg5MCIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIn0=");
        ProtocolConfig::try_parse(&raw).expect("valid vmess")
    }

    fn make_traced_config(source_id: i64, source_url: &str, ts: i64) -> TracedProtocolConfig {
        TracedProtocolConfig {
            config: make_vmess_config(),
            timestamp: DateTime::from_timestamp(ts, 0).unwrap(),
            source: Arc::new(SourceMetadata {
                url: source_url.to_string(),
                id: source_id,
                source_type: SourceType::Other,
            }),
        }
    }

    #[tokio::test]
    async fn test_pipeline_empty_sources() {
        let config_source = TestConfigSource {
            channels: vec![],
            subscriptions: vec![],
        };
        let fetcher = StubFetcher::new(vec![]);
        let conn = make_in_memory_conn();

        let pipeline = Pipeline::new(config_source, fetcher);
        let client = reqwest::Client::new();
        let result = pipeline.run(&client, &conn).await;
        assert!(result.is_ok());
    }

    fn source_id_for(url: &str) -> i64 {
        crate::db::hash_source_url(url)
    }

    #[tokio::test]
    async fn test_pipeline_registry_upserts_sources() {
        let config_source = TestConfigSource {
            channels: vec![],
            subscriptions: vec!["https://example.com/sub".to_string()],
        };

        let fetcher = StubFetcher::new(vec![]);
        let conn = make_in_memory_conn();

        let pipeline = Pipeline::new(config_source, fetcher);
        let client = reqwest::Client::new();
        pipeline.run(&client, &conn).await.unwrap();

        let sid = source_id_for("https://example.com/sub");
        let server = crate::db::get_server(&conn, sid).unwrap();
        assert!(server.is_none(), "no server for source ID");
    }

    #[tokio::test]
    async fn test_pipeline_upserts_config_to_db() {
        let config = make_vmess_config();
        let source_url = "https://example.com/sub";
        let sid = source_id_for(source_url);

        let config_source = TestConfigSource {
            channels: vec![],
            subscriptions: vec![source_url.to_string()],
        };

        let items = vec![make_traced_config(sid, source_url, 1_700_000_000)];
        let fetcher = StubFetcher::new(items);
        let conn = make_in_memory_conn();

        let pipeline = Pipeline::new(config_source, fetcher);
        let client = reqwest::Client::new();
        pipeline.run(&client, &conn).await.unwrap();

        let server_id = config.uid() as i64;
        let server = crate::db::get_server(&conn, server_id).unwrap();
        assert!(server.is_some(), "server should exist after upsert");
        if let Some(s) = server {
            assert_eq!(s.schema, "vmess");
        }
    }

    #[tokio::test]
    async fn test_pipeline_multiple_configs() {
        let source_url = "https://example.com/sub";
        let sid = source_id_for(source_url);

        let config_source = TestConfigSource {
            channels: vec![],
            subscriptions: vec![source_url.to_string()],
        };

        let items = vec![
            make_traced_config(sid, source_url, 1_700_000_000),
            make_traced_config(sid, source_url, 1_700_000_001),
        ];
        let fetcher = StubFetcher::new(items);
        let conn = make_in_memory_conn();

        let pipeline = Pipeline::new(config_source, fetcher);
        let client = reqwest::Client::new();
        pipeline.run(&client, &conn).await.unwrap();

        let server_id = make_vmess_config().uid() as i64;
        let sightings = crate::db::get_sightings(&conn, server_id).unwrap();
        assert!(sightings.len() >= 2, "should have 2+ sightings for same server");
    }
}
