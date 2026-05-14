mod config;
mod error;
mod fetcher;
mod registry;
mod extractor;
mod output;
mod sub;
mod telegram;
mod validator;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use chrono::DateTime;
use futures::StreamExt;
use rustc_hash::FxHashSet;
use tokio::sync::Semaphore;
use tracing::info;
use url::Url;

pub const PROXY_URL: &str = "http://127.0.0.1:20172";
pub const SEMAPHORE_PERMITS: usize = 64;
pub const MIN_REMAINING_BYTES: u64 = 1073741824;
pub const USER_AGENT: &str = "clash-verge/v2.0.2";

/// Re-export key types for convenience
pub use error::FetchError;
pub use fetcher::ProxyStream;
pub use registry::{SourceMetadata, SourceRegistry, SourceType, TimestampedProxy};

fn parse_telegram_timestamp(ts: &str) -> i64 {
    DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.timestamp())
        .unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        })
}

fn get_current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub async fn run() -> Result<()> {
    info!("Starting mining run");
    let channels = config::load_config(Path::new("config.yaml"))?;
    info!(count = channels.len(), "Read config successfully");

    let conn = rusqlite::Connection::open("v2ray-heal.db")?;
    crate::db::init_db(&conn)?;

    info!("Running telegram mining");
    run_telegram(&conn, channels.into_iter()).await?;
    info!("Telegram mining completed, running subscription mining");
    run_subscriptions(&conn).await?;

    info!("Done");
    Ok(())
}

async fn run_subscriptions(conn: &rusqlite::Connection) -> Result<()> {
    let subscriptions = config::load_subscriptions(Path::new("config.yaml"))?;
    info!(
        count = subscriptions.len(),
        "Loaded subscriptions from config"
    );
    tracing::debug!("Subscriptions: {:?}", subscriptions);

    if subscriptions.is_empty() {
        info!("No subscriptions configured");
        return Ok(());
    }

    let mut sub_source_ids: HashMap<String, i64> = HashMap::new();
    for sub_url in &subscriptions {
        match crate::db::upsert_source(conn, sub_url) {
            Ok(id) => {
                sub_source_ids.insert(sub_url.clone(), id);
            }
            Err(e) => {
                tracing::warn!(url = %sub_url, error = %e, "Failed to upsert subscription source");
            }
        }
    }

    let current_ts = get_current_timestamp();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(PROXY_URL)?)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut seen_ids: FxHashSet<u64> = FxHashSet::default();
    let mut proxies_count = 0;
    for sub_url in &subscriptions {
        let url = Url::parse(sub_url)?;
        match crate::download_sub_proxies(url).await {
            Ok(proxies) => {
                let source_id = sub_source_ids.get(sub_url).copied();
                if let Some(source_id) = source_id {
                    for urlx in proxies {
                        if seen_ids.insert(urlx.uid) {
                            if let Err(e) =
                                crate::db::upsert_server(conn, &urlx, source_id, current_ts)
                            {
                                tracing::warn!(error = %e, "Failed to upsert server from subscription");
                            } else {
                                proxies_count += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(url = %sub_url, error = %e, "Failed to download subscription");
            }
        }
    }

    info!(count = proxies_count, "Upserted subscription proxies to DB");
    Ok(())
}

async fn run_telegram<S, I>(conn: &rusqlite::Connection, channels: I) -> Result<()>
where
    S: AsRef<str> + Send + 'static,
    I: Iterator<Item = S> + Send + 'static,
{
    // let mut channel_source_ids: HashMap<String, i64> = HashMap::new();
    // for channel in channels {
    //     match crate::db::upsert_source(conn, channel) {
    //         Ok(id) => {
    //             channel_source_ids.insert(channel.clone(), id);
    //         }
    //         Err(e) => {
    //             tracing::warn!(channel = %channel, error = %e, "Failed to upsert channel source");
    //         }
    //     }
    // }

    // let allow_list: HashSet<_> = [
    //     "sub",
    //     "clash",
    //     "paste",
    //     "tt.vg",
    //     "shz.al",
    //     "proxies",
    //     "raw.githubusercontent.com",
    // ]
    // .into_iter()
    // .collect();

    // let deny_list: HashSet<_> = ["https://t.me/"].into_iter().collect();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(PROXY_URL)?)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let messages: Vec<telegram::TgWebMessage> = telegram::fetch_tg_channels(
        client,
        8,
        channels.into_iter(),
        Duration::from_secs(30),
        None,
    )
    .collect()
    .await;

    // info!(
    //     urls_count = timestamped_urls.len(),
    //     proxies_count = timestamped_proxies.len(),
    //     "Fetched from Telegram"
    // );

    // for tp in &timestamped_proxies {
    //     let ts = parse_telegram_timestamp(&tp.timestamp);
    //     let source_id = channel_source_ids.get(&tp.source_url).copied();
    //     if let Some(source_id) = source_id {
    //         if let Err(e) = crate::db::upsert_server(&conn, &tp.urlx, source_id, ts) {
    //             tracing::warn!(error = %e, "Failed to upsert server");
    //         }
    //     } else {
    //         tracing::warn!(source_url = %tp.source_url, "Source URL not found in map");
    //     }
    // }
    // info!(count = timestamped_proxies.len(), "Upserted proxies to DB");

    // let mut url_list: Vec<String> = timestamped_urls.iter().map(|t| t.url.clone()).collect();

    // url_list.retain(|url: &String| {
    //     allow_list.iter().any(|p| url.contains(p)) && deny_list.iter().all(|p| !url.contains(p))
    // });

    // url_list.sort();
    // url_list.dedup();

    // info!(count = url_list.len(), "Filtering subscriptions...");

    // let semaphore = Semaphore::new(SEMAPHORE_PERMITS);
    // let (new_sub_list, new_clash_list, new_v2_list) =
    //     validator::validate_all(&client, &url_list, semaphore).await;

    // for url in &url_list {
    //     let _ = crate::db::upsert_source(&conn, url);
    // }

    // let old_data = output::load_existing(Path::new("latest.yaml")).unwrap_or_default();

    // let mut final_sub_list: Vec<_> = old_data
    //     .airport_sub
    //     .into_iter()
    //     .chain(new_sub_list)
    //     .collect();
    // let mut final_clash_list: Vec<_> = old_data
    //     .clash_sub
    //     .into_iter()
    //     .chain(new_clash_list)
    //     .collect();
    // let mut final_v2_list: Vec<_> = old_data.v2_sub.into_iter().chain(new_v2_list).collect();

    // final_sub_list.sort();
    // final_sub_list.dedup();
    // final_clash_list.sort();
    // final_clash_list.dedup();
    // final_v2_list.sort();
    // final_v2_list.dedup();

    // output::write_yaml(
    //     Path::new("latest.yaml"),
    //     &final_sub_list,
    //     &final_clash_list,
    //     &final_v2_list,
    // )?;
    // output::write_url_txt(Path::new("url.txt"), &url_list)?;

    // let mut seen_ids: FxHashSet<u64> = FxHashSet::default();
    // let mut unique_proxies: Vec<String> = Vec::new();
    // for tp in &timestamped_proxies {
    //     if seen_ids.insert(tp.urlx.id) {
    //         unique_proxies.push(tp.urlx.to_string());
    //     }
    // }
    // output::write_v2ray_txt(Path::new("v2ray.txt"), &unique_proxies)?;

    info!("Done");
    Ok(())
}
