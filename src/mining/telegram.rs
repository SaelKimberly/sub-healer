use std::sync::Arc;

use anyhow::Result;
use futures::StreamExt;
use scraper::{Html, Selector};
use tracing::{info, warn};

const CONCURRENT_FETCH: usize = 32;

pub async fn fetch_all_channels(
    client: &reqwest::Client,
    channels: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let client = client.clone();
    let channels = Arc::new(channels.to_vec());

    let (tx_url, mut rx_url) = tokio::sync::mpsc::channel::<String>(1024);
    let (tx_proxy, mut rx_proxy) = tokio::sync::mpsc::channel::<String>(4096);

    let channels_clone = Arc::clone(&channels);
    let tx_url_clone = tx_url.clone();
    let tx_proxy_clone = tx_proxy.clone();

    let fetch_task = tokio::spawn(async move {
        futures::stream::iter(channels_clone.iter().cloned())
            .for_each_concurrent(CONCURRENT_FETCH, |channel_url| {
                let client = client.clone();
                let tx_url = tx_url_clone.clone();
                let tx_proxy = tx_proxy_clone.clone();
                async move {
                    match fetch_channel(&client, &channel_url).await {
                        Ok((urls, proxies)) => {
                            info!(%channel_url, "Fetched channel successfully");
                            for url in urls {
                                let _ = tx_url.send(url).await;
                            }
                            for proxy in proxies {
                                let _ = tx_proxy.send(proxy).await;
                            }
                        }
                        Err(e) => {
                            warn!(%channel_url, error = %e, "Failed to fetch channel");
                        }
                    }
                }
            })
            .await;
    });

    let gather_urls = tokio::spawn(async move {
        let mut urls = Vec::new();
        while let Some(url) = rx_url.recv().await {
            urls.push(url);
        }
        urls
    });

    let gather_proxies = tokio::spawn(async move {
        let mut proxies = Vec::new();
        while let Some(proxy) = rx_proxy.recv().await {
            proxies.push(proxy);
        }
        proxies
    });

    let _ = fetch_task.await;
    drop(tx_url);
    drop(tx_proxy);
    let urls = gather_urls.await.unwrap_or_default();
    let proxies = gather_proxies.await.unwrap_or_default();

    Ok((urls, proxies))
}

async fn fetch_channel(
    client: &reqwest::Client,
    channel_url: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let resp = client.get(channel_url).send().await?.error_for_status()?;

    let html = resp.text().await?;
    let document = Html::parse_document(&html);

    let text_selector =
        Selector::parse("body").map_err(|e| anyhow::anyhow!("selector parse failed: {e}"))?;
    let body_html = document
        .select(&text_selector)
        .next()
        .map(|el| el.inner_html())
        .unwrap_or_default();

    let (urls, proxies) = super::extractor::extract_links(&body_html);
    Ok((urls, proxies))
}
