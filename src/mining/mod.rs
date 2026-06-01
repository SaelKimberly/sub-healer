mod pipeline;
mod registry;
mod sub;
pub mod telegram;
mod unparseable_log;
mod writer;
pub mod raw_event;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use tracing::info;

pub use pipeline::Pipeline;
pub use raw_event::RawSourceItemBatch;
pub use registry::{SourceMetadata, SourceRegistry, SourceType};
pub use unparseable_log::UnparseableLayer;
pub use writer::PipelineLogWriter;

pub use self::telegram::Backfill;

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
    let mut pipeline = Pipeline::from_config(config_path, db_path)?;
    let count = pipeline.run().await?;
    info!(count, "Mining pipeline completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::proto_spec::{ProtoSpec, ProtocolConfig};
    use crate::urlx::RawUrlX;
    use chrono::DateTime;
    use std::sync::Arc;

    fn vmess_raw_url() -> &'static str {
        "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6ODAsImlkIjoiYWJjZGUtMTIzNDUtNjc4OTAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSJ9"
    }

    fn source_id_for(url: &str) -> i64 {
        Database::hash_source_url(url)
    }

    fn make_raw_batch(source_id: i64, source_url: &str, ts: i64) -> RawSourceItemBatch {
        let source = Arc::new(SourceMetadata::new(
            source_url.to_string(),
            SourceType::Other,
        ));
        let source = Arc::new(SourceMetadata {
            id: source_id,
            ..(*source).clone()
        });
        RawSourceItemBatch {
            source,
            timestamp: DateTime::from_timestamp(ts, 0).unwrap(),
            raw_urls: Box::new([vmess_raw_url().to_string()]),
        }
    }

    #[tokio::test]
    async fn test_pipeline_empty_sources() {
        let mut pipeline = Pipeline::new_test();
        let count = pipeline.run().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_pipeline_upserts_config_to_db() {
        let source_url = "https://example.com/sub";
        let sid = source_id_for(source_url);
        let mut pipeline = Pipeline::new_test();
        pipeline
            .db()
            .upsert_source(source_url)
            .await
            .unwrap();
        pipeline.add_batch_raw(vec![make_raw_batch(sid, source_url, 1_700_000_000)]);
        let count = pipeline.run().await.unwrap();
        assert_eq!(count, 1);
        let raw = RawUrlX::from(vmess_raw_url());
        let config = ProtocolConfig::try_parse(&raw).expect("valid vmess");
        let server_id = config.uid().cast_signed();
        let server = pipeline.db().get_server(server_id).await.unwrap();
        assert!(server.is_some(), "server should exist after upsert");
        if let Some(s) = server {
            assert_eq!(s.schema, "vmess");
        }
    }

    #[tokio::test]
    async fn test_pipeline_multiple_configs() {
        let source_url = "https://example.com/sub";
        let sid = source_id_for(source_url);
        let mut pipeline = Pipeline::new_test();
        pipeline
            .db()
            .upsert_source(source_url)
            .await
            .unwrap();
        pipeline.add_batch_raw(vec![
            make_raw_batch(sid, source_url, 1_700_000_000),
            make_raw_batch(sid, source_url, 1_700_000_001),
        ]);
        let count = pipeline.run().await.unwrap();
        assert_eq!(count, 2);
        let raw = RawUrlX::from(vmess_raw_url());
        let config = ProtocolConfig::try_parse(&raw).expect("valid vmess");
        let server_id = config.uid().cast_signed();
        let sightings = pipeline.db().get_sightings(server_id).await.unwrap();
        assert!(
            sightings.len() >= 2,
            "should have 2+ sightings for same server"
        );
    }
}
