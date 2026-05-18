mod config;
mod registry;
mod sub;
mod telegram;
mod unparseable_log;

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use tracing::info;

pub const PROXY_URL: &str = "http://127.0.0.1:20172";
pub const SEMAPHORE_PERMITS: usize = 64;
pub const USER_AGENT: &str = "clash-verge/v2.0.2";

/// Re-export key types for convenience
pub use registry::{SourceMetadata, SourceRegistry, SourceType, TimestampedProxy};
pub use unparseable_log::UnparseableLayer;

fn get_current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed()
}

/// ### Errors
/// - Any error that occurs during the mining process
pub async fn run() -> Result<(), anyhow::Error> {
    info!("Starting mining run");

    // 1. Open DB
    let conn = rusqlite::Connection::open("v2ray-heal.db")?;
    crate::db::init_db(&conn)?;

    // 2. Load config
    let channels = config::load_config(Path::new("config.yaml"))?;
    let subscriptions = config::load_subscriptions(Path::new("config.yaml"))?;
    info!(
        channels = channels.len(),
        subscriptions = subscriptions.len(),
        "Read config successfully"
    );

    // 3. Create HTTP client (shared across Telegram and subscription flows)
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(PROXY_URL)?)
        .timeout(Duration::from_secs(30))
        .build()?;

    // 4. Pre-populate SourceRegistry with all sources
    let mut registry = SourceRegistry::new();
    for channel in &channels {
        registry.pre_populate(channel, SourceType::Telegram);
    }
    for sub in &subscriptions {
        registry.pre_populate(sub, SourceType::Subscription);
    }

    // 5. Batch upsert all sources to DB
    registry
        .upsert_all(&conn)
        .context("Failed to upsert sources to database")?;

    // 6. Telegram phase
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

        // Emit unparseable URL events from this message
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

    // 7. Subscription phase
    info!("Running subscription mining");
    let sub_proxies =
        sub::fetch_timestamped_subs(&client, &registry, Path::new("config.yaml")).await?;

    let mut sub_count = 0usize;
    for tp in &sub_proxies {
        let ts = tp.timestamp.timestamp();
        crate::db::upsert_server(&conn, &tp.urlx, tp.source.id, ts)
            .context("Subscription upsert failed (aborting)")?;
        sub_count += 1;
    }
    info!(count = sub_count, "Subscription mining completed");

    info!("Done");
    Ok(())
}
