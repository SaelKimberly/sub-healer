mod config;
mod registry;
mod sub;
pub mod telegram;
mod unparseable_log;

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use tracing::info;

pub const PROXY_URL: &str = "http://127.0.0.1:20172";
pub const SEMAPHORE_PERMITS: usize = 64;
pub const USER_AGENT: &str = "clash-verge/v2.0.2";

pub use config::{load_config, load_subscriptions};
pub use registry::{SourceMetadata, SourceRegistry, SourceType, TimestampedProxy};
pub use sub::{download_sub_data, process_sub_lines};
pub use unparseable_log::UnparseableLayer;

pub fn get_current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed()
}

pub fn open_db(path: &Path) -> Result<rusqlite::Connection, anyhow::Error> {
    let conn = rusqlite::Connection::open(path)
        .with_context(|| format!("Failed to open database: {}", path.display()))?;
    crate::db::init_db(&conn)
        .context("Failed to initialize database schema")?;
    Ok(conn)
}

pub fn build_client() -> Result<reqwest::Client, anyhow::Error> {
    Ok(reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(PROXY_URL)?)
        .timeout(Duration::from_secs(30))
        .build()?)
}

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

    registry
        .upsert_all(&conn)
        .context("Failed to upsert sources to database")?;

    // Telegram phase
    info!("Running telegram mining");
    let tg_stream = telegram::fetch_tg_channels(
        client.clone(),
        8,
        channels.into_iter(),
        Duration::from_secs(30),
        None,
    );

    let mut tg_count = 0usize;
    tokio::pin!(tg_stream);
    while let Some(msg) = tg_stream.next().await {
        let Some(source) = registry.lookup(&msg.source_url) else {
            tracing::warn!(
                url = %msg.source_url,
                "Source not found in registry for Telegram message"
            );
            continue;
        };
        let ts = msg.time.timestamp();

        if let Some(ref unparseable) = msg.unparseable_urls {
            for u in unparseable {
                tracing::warn!(
                    target: "mining::unparseable",
                    raw_url = %u.raw_url,
                    scheme = %u.scheme,
                    error = %u.error,
                    source_id = source.id,
                    source_type = "telegram",
                    timestamp = ts,
                );
            }
        }

        if let Some(ref msg_urls) = msg.msg_urls {
            for urlx in msg_urls {
                crate::db::upsert_server(&conn, urlx, source.id, ts)
                    .context("Telegram upsert failed (aborting)")?;
                tg_count += 1;
            }
        }
    }
    info!(count = tg_count, "Telegram mining completed");

    // Subscription phase
    info!("Running subscription mining");
    let sub_count =
        sub::fetch_timestamped_subs(&client, &registry, config_path, &conn).await?;
    info!(count = sub_count, "Subscription mining completed");

    info!("Done");
    Ok(())
}
