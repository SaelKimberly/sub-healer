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

pub const PROXY_URL: &str = "http://127.0.0.1:20172";
pub const SEMAPHORE_PERMITS: usize = 64;
pub const USER_AGENT: &str = "clash-verge/v2.0.2";

pub use config::{load_config, load_subscriptions};
pub use registry::{SourceMetadata, SourceRegistry, SourceType};
pub use sub::{download_sub_data, fetch_subscriptions, lines_to_traced};
pub use traced_config::TracedProtocolConfig;
pub use unparseable_log::UnparseableLayer;
pub use writer::PipelineLogWriter;

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

/// # Errors
///
/// Will return `Err` if the config file is invalid or the database cannot be opened.
pub async fn run_with_config(config_path: &Path, db_path: &Path) -> Result<(), anyhow::Error> {
    info!("Starting mining run with config: {}", config_path.display());

    let conn = open_db(db_path)?;

    let channels = config::load_config(config_path)?;
    let subscriptions = config::load_subscriptions(config_path)?;
    info!(
        channels = channels.len(),
        subscriptions = subscriptions.len(),
        "Read config successfully"
    );

    let client = build_client()?;

    let mut registry = SourceRegistry::new();
    for channel in &channels {
        registry.pre_populate(channel, SourceType::Telegram);
    }
    for sub in &subscriptions {
        registry.pre_populate(sub, SourceType::Subscription);
    }
    let registry = Arc::new(registry);

    registry
        .upsert_all(&conn)
        .context("Failed to upsert sources to database")?;

    info!("Running mining pipeline");
    let tg_stream = telegram::fetch_tg_channels(
        client.clone(),
        8,
        channels.into_iter(),
        Duration::from_secs(30),
        None,
        registry.clone(),
    );

    let sub_stream = sub::fetch_subscriptions(
        client.clone(),
        registry.clone(),
        subscriptions,
    );

    let merged = futures::stream::select(tg_stream, sub_stream);
    let total = process_config_stream(merged, &conn).await?;
    info!(count = total, "Mining pipeline completed");
    info!("Done");
    Ok(())
}
