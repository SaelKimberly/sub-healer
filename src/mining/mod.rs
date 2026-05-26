mod registry;
mod sub;
pub mod telegram;
mod traced_config;
mod unparseable_log;
mod writer;

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use tracing::info;

pub use registry::{LiveFetcher, SourceFetcher, SourceMetadata, SourceRegistry, SourceType};
pub use sub::lines_to_traced;
pub use traced_config::TracedProtocolConfig;
pub use unparseable_log::UnparseableLayer;
pub use writer::PipelineLogWriter;

pub use self::telegram::Backfill;

pub const PROXY_URL: &str = "http://127.0.0.1:20172";
pub const SEMAPHORE_PERMITS: usize = 64;
pub const USER_AGENT: &str = "clash-verge/v2.0.2";

#[derive(Debug, Clone)]
pub struct TgConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub backfill: Option<Backfill>,
}

impl Default for TgConfig {
    fn default() -> Self {
        Self {
            concurrency: 8,
            timeout: Duration::from_secs(30),
            backfill: None,
        }
    }
}

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

/// Process a stream of traced configs, writing each source and server to the database.
/// Sources are upserted lazily on first encounter. Fatal on DB error (aborts pipeline).
///
/// # Errors
///
/// Returns an error if the database connection fails.
pub async fn process_config_stream(
    mut stream: impl StreamExt<Item = TracedProtocolConfig> + std::marker::Unpin,
    conn: &rusqlite::Connection,
) -> Result<usize, anyhow::Error> {
    let mut count = 0usize;
    let mut seen_sources = HashSet::new();
    while let Some(item) = stream.next().await {
        if seen_sources.insert(item.source.id) {
            crate::db::upsert_source(conn, &item.source.url)
                .context("source upsert failed (aborting)")?;
        }
        crate::db::upsert_server(
            conn,
            &item.config,
            item.source.id,
            item.timestamp.timestamp(),
        )
        .context("upsert failed (aborting)")?;
        count += 1;
    }
    Ok(count)
}

/// Emit a single unparseable entry to the NDJSON tracing layer.
/// Filters out promotion URLs. Used by telegram, subscription, and local paths.
pub fn emit_unparseable_entry(
    raw_url: &str,
    scheme: &str,
    error: &str,
    source_id: i64,
    source_type: &str,
    ts: i64,
) {
    if error.contains("promotion") {
        return;
    }
    tracing::warn!(
        target: "mining::unparseable",
        raw_url = %raw_url,
        scheme = %scheme,
        error = error,
        source_id = source_id,
        source_type = source_type,
        timestamp = ts,
    );
}

/// # Errors
///
/// Will return `Err` if the config file is invalid or the database cannot be opened.
pub async fn run_with_config(config_path: &Path, db_path: &Path) -> Result<(), anyhow::Error> {
    info!("Starting mining run with config: {}", config_path.display());
    let client = build_client()?;
    let conn = open_db(db_path)?;
    let registry = Arc::new(SourceRegistry::from_config(config_path)?);
    registry.run_pipeline(&client, &conn).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto_spec::ProtoSpec;
    use crate::proto_spec::ProtocolConfig;
    use crate::urlx::RawUrlX;
    use chrono::DateTime;
    use futures::StreamExt;

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
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
        crate::db::init_db(&conn).expect("init schema");
        conn
    }

    fn make_vmess_config() -> ProtocolConfig {
        let raw = RawUrlX::from(
            "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0Ijo4MCwiaWQiOiJhYmNkZS0xMjM0NS02Nzg5MCIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIn0=",
        );
        ProtocolConfig::try_parse(&raw).expect("valid vmess")
    }

    fn source_id_for(url: &str) -> i64 {
        crate::db::hash_source_url(url)
    }

    fn make_traced_config(source_id: i64, source_url: &str, ts: i64) -> TracedProtocolConfig {
        let source = Arc::new(SourceMetadata::new(
            source_url.to_string(),
            SourceType::Other,
        ));
        // override id since SourceMetadata::new computes hash from url, but test wants specific id
        let source = Arc::new(SourceMetadata {
            id: source_id,
            ..(*source).clone()
        });
        TracedProtocolConfig {
            config: make_vmess_config(),
            timestamp: DateTime::from_timestamp(ts, 0).unwrap(),
            source,
        }
    }

    #[tokio::test]
    async fn test_pipeline_empty_sources() {
        let registry = Arc::new(SourceRegistry::from_sources(&[], &[]));
        let fetcher = StubFetcher::new(vec![]);
        let conn = make_in_memory_conn();

        let client = reqwest::Client::new();
        let result = registry.run_pipeline_with(&client, &conn, fetcher).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pipeline_registry_upserts_sources() {
        let registry = Arc::new(SourceRegistry::from_sources(
            &[],
            &["https://example.com/sub".to_string()],
        ));
        let fetcher = StubFetcher::new(vec![]);
        let conn = make_in_memory_conn();

        let client = reqwest::Client::new();
        registry
            .run_pipeline_with(&client, &conn, fetcher)
            .await
            .unwrap();

        let sid = source_id_for("https://example.com/sub");
        let server = crate::db::get_server(&conn, sid).unwrap();
        assert!(server.is_none(), "no server for source ID");
    }

    #[tokio::test]
    async fn test_pipeline_upserts_config_to_db() {
        let config = make_vmess_config();
        let source_url = "https://example.com/sub";
        let sid = source_id_for(source_url);

        let registry = Arc::new(SourceRegistry::from_sources(&[], &[source_url.to_string()]));
        let items = vec![make_traced_config(sid, source_url, 1_700_000_000)];
        let fetcher = StubFetcher::new(items);
        let conn = make_in_memory_conn();

        let client = reqwest::Client::new();
        registry
            .run_pipeline_with(&client, &conn, fetcher)
            .await
            .unwrap();

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

        let registry = Arc::new(SourceRegistry::from_sources(&[], &[source_url.to_string()]));
        let items = vec![
            make_traced_config(sid, source_url, 1_700_000_000),
            make_traced_config(sid, source_url, 1_700_000_001),
        ];
        let fetcher = StubFetcher::new(items);
        let conn = make_in_memory_conn();

        let client = reqwest::Client::new();
        registry
            .run_pipeline_with(&client, &conn, fetcher)
            .await
            .unwrap();

        let server_id = make_vmess_config().uid() as i64;
        let sightings = crate::db::get_sightings(&conn, server_id).unwrap();
        assert!(
            sightings.len() >= 2,
            "should have 2+ sightings for same server"
        );
    }
}
