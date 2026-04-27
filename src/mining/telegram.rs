use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use futures::StreamExt;
use scraper::{Html, Selector};
use tracing::{info, warn};

use super::extractor::{extract_links_from_html, unescape_html_entities};
use crate::UrlX;

const CONCURRENT_FETCH: usize = 32;

#[derive(Debug, Clone)]
pub struct TimestampedUrl {
    pub url: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct TimestampedProxy {
    pub urlx: UrlX,
    pub timestamp: String,
}

pub async fn fetch_all_channels(
    client: &reqwest::Client,
    channels: &[String],
) -> Result<(Vec<TimestampedUrl>, Vec<TimestampedProxy>)> {
    let client = client.clone();
    let channels = Arc::new(channels.to_vec());

    let (tx_url, mut rx_url) = tokio::sync::mpsc::channel::<TimestampedUrl>(1024);
    let (tx_proxy, mut rx_proxy) = tokio::sync::mpsc::channel::<TimestampedProxy>(4096);

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

fn is_proxy_url(s: &str) -> bool {
    s.starts_with("vmess://")
        || s.starts_with("vless://")
        || s.starts_with("ss://")
        || s.starts_with("ssr://")
        || s.starts_with("trojan://")
        || s.starts_with("hy2://")
        || s.starts_with("hysteria2://")
        || s.starts_with("hysteria://")
        || s.starts_with("hy://")
        || s.starts_with("warp://")
        || s.starts_with("anytls://")
        || s.starts_with("tuic://")
}

async fn fetch_channel(
    client: &reqwest::Client,
    channel_url: &str,
) -> Result<(Vec<TimestampedUrl>, Vec<TimestampedProxy>)> {
    let resp = client.get(channel_url).send().await?.error_for_status()?;

    let html = resp.text().await?;
    let document = Html::parse_document(&html);

    let message_selector = Selector::parse(".js-widget_message_wrap")
        .map_err(|e| anyhow::anyhow!("selector parse failed: {e}"))?;

    let time_selector = Selector::parse("time.time")
        .map_err(|e| anyhow::anyhow!("time selector parse failed: {e}"))?;

    let text_selector = Selector::parse(".js-message_text")
        .map_err(|e| anyhow::anyhow!("text selector parse failed: {e}"))?;

    let mut urls = Vec::new();
    let mut proxies = Vec::new();

    for msg_elem in document.select(&message_selector) {
        let timestamp = msg_elem
            .select(&time_selector)
            .next()
            .and_then(|el| el.value().attr("datetime"))
            .map(String::from)
            .unwrap_or_default();

        if let Some(text_elem) = msg_elem.select(&text_selector).next() {
            let text_html = text_elem.inner_html();

            let (extracted_urls, extracted_proxies) = extract_links_from_html(&text_html);

            for url in extracted_urls {
                let unescaped = unescape_html_entities(&url);
                urls.push(TimestampedUrl {
                    url: unescaped,
                    timestamp: timestamp.clone(),
                });
            }

            for raw_proxy in extracted_proxies {
                let unescaped = unescape_html_entities(&raw_proxy);
                if !is_proxy_url(&unescaped) {
                    continue;
                }
                let Ok(mut urlx) = UrlX::from_str(&unescaped);
                match urlx.normalize(&mut None) {
                    Ok(()) => {
                        proxies.push(TimestampedProxy {
                            urlx,
                            timestamp: timestamp.clone(),
                        });
                    }

                    Err(e) => {
                        tracing::debug!(url = %unescaped, error = %e, "Failed to parse proxy URL");
                    }
                }
            }
        }
    }

    Ok((urls, proxies))
}
