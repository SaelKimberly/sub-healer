mod config;
mod extractor;
mod output;
mod telegram;
mod validator;

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use tokio::sync::Semaphore;
use tracing::info;

pub const PROXY_URL: &str = "http://127.0.0.1:20172";
pub const SEMAPHORE_PERMITS: usize = 64;
pub const MIN_REMAINING_BYTES: u64 = 1073741824;
pub const USER_AGENT: &str = "clash-verge/v2.0.2";

pub async fn run() -> Result<()> {
    let channels = config::load_config(Path::new("config.yaml"))?;
    info!(count = channels.len(), "Read config successfully");

    let allow_list: HashSet<_> = [
        "sub",
        "clash",
        "paste",
        "tt.vg",
        "shz.al",
        "proxies",
        "raw.githubusercontent.com",
    ]
    .into_iter()
    .collect();

    let deny_list: HashSet<_> = ["https://t.me/"].into_iter().collect();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(PROXY_URL)?)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let (mut url_list, proxy_list) = telegram::fetch_all_channels(&client, &channels).await?;

    url_list.retain(|url: &String| {
        allow_list.iter().any(|p| url.contains(p)) && deny_list.iter().all(|p| !url.contains(p))
    });

    url_list.sort();
    url_list.dedup();

    info!(count = url_list.len(), "Filtering subscriptions...");

    let semaphore = Semaphore::new(SEMAPHORE_PERMITS);
    let (new_sub_list, new_clash_list, new_v2_list) =
        validator::validate_all(&client, &url_list, semaphore).await;

    let old_data = output::load_existing(Path::new("latest.yaml")).unwrap_or_default();

    let mut final_sub_list: Vec<_> = old_data
        .airport_sub
        .into_iter()
        .chain(new_sub_list)
        .collect();
    let mut final_clash_list: Vec<_> = old_data
        .clash_sub
        .into_iter()
        .chain(new_clash_list)
        .collect();
    let mut final_v2_list: Vec<_> = old_data.v2_sub.into_iter().chain(new_v2_list).collect();

    final_sub_list.sort();
    final_sub_list.dedup();
    final_clash_list.sort();
    final_clash_list.dedup();
    final_v2_list.sort();
    final_v2_list.dedup();

    output::write_yaml(
        Path::new("latest.yaml"),
        &final_sub_list,
        &final_clash_list,
        &final_v2_list,
    )?;
    output::write_url_txt(Path::new("url.txt"), &url_list)?;
    output::write_v2ray_txt(Path::new("v2ray.txt"), &proxy_list)?;

    info!("Done");
    Ok(())
}
