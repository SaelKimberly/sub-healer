use std::sync::OnceLock;
use std::time::Duration;
use std::{pin::Pin, sync::Arc};

use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};

mod pipeline;
mod registry;
mod sub;
pub mod telegram;
mod unparseable_log;
mod writer;

use futures::{Stream, TryStreamExt};
pub use pipeline::Pipeline;
pub use registry::{SourceMetadata, SourceRegistry, SourceType};
use reqwest::NoProxy;
pub use unparseable_log::UnparseableLayer;
use url::Url;
pub use writer::PipelineLogWriter;

pub use self::telegram::Backfill;

/// Batch of decoded-and-normalized raw URL strings from one fetch operation.
///
/// Each batch corresponds to a single fetch boundary:
/// - Telegram: all URLs extracted from one message's HTML
/// - Subscription: all decoded lines from one subscription download
/// - Stdin/Local: all decoded lines from one file or pipe input
///
/// The consumer ([`Pipeline::run`]) iterates over each URL,
/// calls [`crate::proto_spec::ProtocolConfig::try_parse_detailed`], and
/// handles all outcomes (Direct, Fallback, Unparseable) in one place.
#[derive(Debug, Clone)]
pub struct RawSourceItemBatch {
    pub source: Arc<SourceMetadata>,
    pub timestamp: DateTime<Utc>,
    pub raw_urls: Box<[String]>,
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

static WEB_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// # Errors
///
/// Will return `Err` if the proxy URL is invalid or the client cannot be built.
pub fn build_client() -> reqwest::Result<reqwest::Client> {
    if let Some(client) = WEB_CLIENT.get().cloned() {
        return Ok(client);
    }

    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(5));

    if cfg!(test) {
        builder = builder.proxy(reqwest::Proxy::all("http://127.0.0.1:20172")?);
    } else if let Ok(proxy) = std::env::var("HTTP_PROXY")
        && let Ok(url) = url::Url::parse(proxy.as_str())
        && matches!(url.scheme(), "http" | "https")
        && let Some("127.0.0.1" | "localhost") = url.host_str()
        && let Ok(mut proxy) = reqwest::Proxy::all(url.as_str())
    {
        if let Ok(username) = std::env::var("HTTP_PROXY_USERNAME")
            && let Ok(password) = std::env::var("HTTP_PROXY_PASSWORD")
        {
            proxy = proxy.basic_auth(username.as_str(), password.as_str());
        }

        builder = builder.proxy(proxy.no_proxy(NoProxy::from_env()));
    }

    let client = builder.build()?;

    Ok(WEB_CLIENT.get_or_init(|| client).clone())
}

#[derive(Debug, thiserror::Error)]
enum StreamError {
    #[error("Stream error: {0}")]
    Std(#[from] std::io::Error),
    #[error("Stream error: {0}")]
    Web(#[from] reqwest::Error),
    #[error("Stream error: {0}")]
    B64(#[from] base64::DecodeError),
}

async fn create_stream(
    url: &Url,
) -> anyhow::Result<Pin<Box<dyn Stream<Item = Result<Bytes, StreamError>> + Send + Sync>>> {
    match url.scheme() {
        "stdin" => {
            let inner = tokio::io::stdin();
            let outer =
                tokio_util::codec::Framed::new(inner, tokio_util::codec::BytesCodec::default());
            Ok(Box::pin(outer.map_ok(BytesMut::freeze).map_err(Into::into)))
        }
        "http" | "https" => {
            let mut attempt = 0;
            let client = build_client()?;
            let mut inner = client.get(url.as_str());
            if matches!(
                url.host_str(),
                Some("github.com" | "raw.githubusercontent.com")
            ) && let Ok(token) = std::env::var("GITHUB_TOKEN")
            {
                inner = inner.bearer_auth(token);
            }
            let request = inner.build()?;

            let resp = loop {
                match client
                    .execute(request.try_clone().expect("Should be possible"))
                    .await
                {
                    Ok(resp) => break Ok(resp),
                    Err(e) if e.status().is_none() && attempt < 3 => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        attempt += 1;
                    }
                    Err(e) => break Err(e),
                }
            }?;
            Ok(Box::pin(resp.bytes_stream().map_err(Into::into)))
        }
        "file" => {
            let Ok(path) = url.to_file_path() else {
                anyhow::bail!("Invalid URL: {url} (must be absolute path)");
            };
            let inner = tokio::io::BufReader::new(
                tokio::fs::OpenOptions::new().read(true).open(path).await?,
            );
            let outer =
                tokio_util::codec::Framed::new(inner, tokio_util::codec::BytesCodec::default());

            Ok(Box::pin(outer.map_ok(BytesMut::freeze).map_err(Into::into)))
        }
        other => Err(anyhow::anyhow!("Unsupported source scheme: {other}")),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::mining::pipeline::process_single_raw_url;
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

    fn setup_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::schema::init_db(&conn).unwrap();
        conn
    }

    fn setup_source(conn: &rusqlite::Connection, url: &str) -> i64 {
        crate::db::upsert_source(conn, url).unwrap()
    }

    #[test]
    fn test_process_single_raw_url_direct() {
        let conn = setup_db();
        let source_id = setup_source(&conn, "test://source");
        let result = process_single_raw_url(
            "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6ODAsImlkIjoiYWJjZGUifQ==",
            source_id,
            "test",
            1_700_000_000,
            &conn,
        )
        .unwrap();
        assert!(result, "valid vmess URL should parse successfully");
    }

    #[test]
    fn test_process_single_raw_url_unparseable() {
        let conn = setup_db();
        let source_id = setup_source(&conn, "test://source");
        // VMess URL with invalid/corrupted base64 payload — passes RawUrlX parse
        // but fails ProtocolConfig try_parse_detailed
        let result = process_single_raw_url(
            "vmess://!!!invalid-base64!!!",
            source_id,
            "test",
            1_700_000_000,
            &conn,
        )
        .unwrap();
        assert!(!result, "malformed vmess URL should not parse");
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
        pipeline.db().upsert_source(source_url).await.unwrap();
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
        pipeline.db().upsert_source(source_url).await.unwrap();
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
