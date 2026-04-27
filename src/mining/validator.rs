use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine;
use regex::Regex;
use tokio::sync::Semaphore;
use tracing::debug;

const TIMEOUT_SECS: u64 = 5;
const MIN_REMAINING_BYTES: u64 = super::MIN_REMAINING_BYTES;
const USER_AGENT: &str = super::USER_AGENT;

pub async fn validate_all(
    client: &reqwest::Client,
    urls: &[String],
    semaphore: Semaphore,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let client = Arc::new(client.clone());
    let semaphore = Arc::new(semaphore);

    let results: Vec<_> = futures::future::join_all(urls.iter().map(|url| {
        let client = Arc::clone(&client);
        let semaphore = Arc::clone(&semaphore);
        let url = url.clone();
        async move {
            let _permit = semaphore.acquire().await;
            check_subscription(&client, &url).await
        }
    }))
    .await;

    let mut subs = Vec::new();
    let mut clashes = Vec::new();
    let mut v2s = Vec::new();

    for result in results {
        match result {
            SubscriptionType::Airport(url) => subs.push(url),
            SubscriptionType::Clash(url) => clashes.push(url),
            SubscriptionType::V2Ray(url) => v2s.push(url),
            SubscriptionType::Skip => {}
        }
    }

    (subs, clashes, v2s)
}

#[derive(Debug)]
enum SubscriptionType {
    Airport(String),
    Clash(String),
    V2Ray(String),
    Skip,
}

static EXPIRE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"expire=(\d+)").unwrap());
static TRAFFIC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"upload=(\d+); download=(\d+); total=(\d+)").unwrap());
static CLASH_PROXIES_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"proxies:").unwrap());

fn is_future_timestamp(ts: u64) -> bool {
    let ts = if ts > 9999999999 { ts / 1000 } else { ts };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ts > now
}

async fn check_subscription(client: &reqwest::Client, url: &str) -> SubscriptionType {
    let resp = match client
        .get(url)
        .header("User-Agent", USER_AGENT)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            debug!(%url, error = %e, "Request failed");
            return SubscriptionType::Skip;
        }
    };

    if !resp.status().is_success() {
        return SubscriptionType::Skip;
    }

    if let Some(info) = resp.headers().get("subscription-userinfo")
        && let Ok(info_str) = info.to_str()
    {
        let expire = EXPIRE_RE
            .captures(info_str)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u64>().ok());

        let traffic = TRAFFIC_RE.captures(info_str);

        if let (Some(exp), Some(cap)) = (expire, traffic) {
            let upload: u64 = cap
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            let download: u64 = cap
                .get(2)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            let total: u64 = cap
                .get(3)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);

            let remaining = total.saturating_sub(upload + download);

            if is_future_timestamp(exp) && remaining > MIN_REMAINING_BYTES {
                return SubscriptionType::Airport(url.to_string());
            } else {
                return SubscriptionType::Skip;
            }
        }
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return SubscriptionType::Skip,
    };

    if CLASH_PROXIES_RE.is_match(&text) {
        return SubscriptionType::Clash(url.to_string());
    }

    let head = text.chars().take(64).collect::<String>();
    if super::extractor::contains_proxy_prefix(&head)
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&head)
        && let Ok(s) = String::from_utf8(decoded)
        && super::extractor::contains_proxy_prefix(&s)
    {
        return SubscriptionType::V2Ray(url.to_string());
    }

    SubscriptionType::Skip
}
