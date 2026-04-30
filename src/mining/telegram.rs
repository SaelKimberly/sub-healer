#![allow(dead_code)]
use std::sync::Arc;
use std::time::Duration;
use std::{str::FromStr, sync::LazyLock};

use anyhow::Result;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use scraper::{Html, Selector};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::extractor::{extract_links_from_html, unescape_html_entities};
use crate::{UrlX, urlx::TinyText};

const CONCURRENT_FETCH: usize = 32;

#[derive(Debug, Clone)]
pub struct TgWebMessage {
    pub user: TinyText,
    pub time: DateTime<Utc>,
    pub msg_id: u32,
    pub msg_text: TinyText,
}

enum TgEvent {
    Message(TgWebMessage),
    Timeout(TinyText),
    Failure(TinyText, reqwest::Error),
}

struct TgWebMessageStream {
    receiver: Receiver<TgEvent>,
    join_set: JoinSet<()>,
}

impl Stream for TgWebMessageStream {
    type Item = TgWebMessage;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.receiver.poll_recv(cx) {
                std::task::Poll::Ready(Some(TgEvent::Message(msg))) => {
                    return std::task::Poll::Ready(Some(msg));
                }
                std::task::Poll::Ready(Some(TgEvent::Timeout(t))) => {
                    tracing::info!(target: "mining::tg_channel", id=t.as_str(), "Timeout");
                    continue;
                }
                std::task::Poll::Ready(Some(TgEvent::Failure(t, e))) => {
                    tracing::info!(target: "mining::tg_channel", id=t.as_str(), "Failure ({e})");
                    continue;
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

async fn fetch_tg_channel(
    client: reqwest::Client,
    channel: &str,
    sender: tokio::sync::mpsc::Sender<TgEvent>,
    limit: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
) {
    static TG_WEB_MESSAGE_SELECTOR: LazyLock<scraper::Selector> =
        LazyLock::new(|| scraper::Selector::parse("div.tgme_widget_message").unwrap());
    static TG_WEB_USER_SELECTOR: LazyLock<scraper::Selector> =
        LazyLock::new(|| scraper::Selector::parse("div.tgme_widget_message_user > a").unwrap());
    static TG_WEB_TIME_SELECTOR: LazyLock<scraper::Selector> = LazyLock::new(|| {
        scraper::Selector::parse("a.tgme_widget_message_date > time.time").unwrap()
    });
    static TG_WEB_TEXT_SELECTOR: LazyLock<scraper::Selector> =
        LazyLock::new(|| scraper::Selector::parse("div.tgme_widget_message_text").unwrap());

    let channel_id = match channel.rsplit_once('/') {
        Some(("https://t.me/s" | "https://t.me", channel_id)) => channel_id.to_owned(),
        Some((_, _)) => {
            tracing::warn!("Unexpected url: {channel} (should be https://t.me/s/[channel_id])");
            return;
        }
        None => channel.trim_start_matches('@').to_owned(),
    };
    let url = format!("https://t.me/s/{channel_id}");

    tracing::info!(target: "mining::tg_channel", id=channel_id, "Start downloading");
    // tracing::info!(target: "mining::v2ray_subs", id=channel_id, "Start fetching channel");

    let Ok(_permit) = limit.acquire().await else {
        return;
    };

    let fetch_fn = async move || -> reqwest::Result<Bytes> {
        let data = client
            .get(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        Ok(data)
    };

    let data = match tokio::time::timeout(timeout, fetch_fn()).await {
        Ok(Err(e)) => {
            _ = sender.send(TgEvent::Failure(channel_id.into(), e)).await;
            return;
        }
        Err(_) => {
            _ = sender.send(TgEvent::Timeout(channel_id.into())).await;
            return;
        }
        Ok(Ok(resp)) => resp,
    };
    let text = String::from_utf8_lossy(&data).into_owned();

    tracing::info!(target: "mining::tg_channel", id=channel_id, "Downloaded");
    tracing::info!(target: "mining::tg_channel", id=channel_id, "Start parsing");

    let Ok((channel_id, counter)) = tokio::task::spawn_blocking(move || {
        let text = text;
        let html = scraper::Html::parse_document(&text);

        let mut counter = 0;

        for msg in html.select(&TG_WEB_MESSAGE_SELECTOR) {
            let msg =  if let Some(msg_text) = msg.select(&TG_WEB_TEXT_SELECTOR).next()
                .and_then(|msg_text| {
                    let mut areas: Vec<String> = Vec::new();
                    for piece in msg_text.text() {
                        if areas.is_empty() {
                            areas.push(String::new());
                            continue;
                        }

                        if let Some((possible_schema, _)) = piece.split_once("://")
                        && let Some((split_pos, _)) = possible_schema.char_indices().rev().take_while(|c|c.1.is_ascii_alphanumeric()).last() {
                            let (before_schema, after_schema) = piece.split_at(split_pos);
                            areas.last_mut().expect("Should never fail, due to first insertion").push_str(before_schema);
                            areas.push(after_schema.into());
                        } else {
                            areas.last_mut().expect("Should never fail, due to first insertion").push_str(piece);
                        }
                    }

                    match areas.len() {
                        0 => None,
                        1 => areas.pop(),
                        _ => Some(areas.join("\n")),
                    }
                })
            // Extract user
            && let Some((_, user)) = msg.select(&TG_WEB_USER_SELECTOR).next()
                .and_then(|user| user.attr("href"))
                .and_then(|user| user.rsplit_once('/'))
            // Extract time
            &&  let Some(time) = msg.select(&TG_WEB_TIME_SELECTOR).next()
                .and_then(|time| time.attr("datetime"))
                .and_then(|time| DateTime::parse_from_rfc3339(time).inspect_err(
                    |e| tracing::warn!(target: "mining::tg_channel", id=channel_id, "Failed to parse time: {e}"),
                ).map(|dt|dt.to_utc()).ok())
            // Extract message id
            && let Some(msg_id) = msg.attr("data-post")
                .and_then(|msg_id| msg_id.rsplit_once('/'))
                .and_then(|(_, msg_id)| u32::from_str(msg_id).inspect_err(
                    |e| tracing::warn!(target: "mining::tg_channel", id=channel_id, "Failed to parse message id: {e}"),
                ).ok()) {
                TgWebMessage {
                    user: user.into(),
                    time,
                    msg_id,
                    msg_text: msg_text.into()
                }
            } else {
                continue;
            };

            if sender.blocking_send(
                TgEvent::Message(msg)
            ).is_ok() {
                counter += 1;
            } else {
                tracing::warn!(target: "mining::tg_channel", id=channel_id, "Failed to send message");
                break;
            }


        }


        (channel_id, counter)
    }).await else {
        return
    };

    if counter == 0 {
        tracing::warn!(target: "mining::tg_channel", id=channel_id, "No messages found");
    } else {
        tracing::info!(target: "mining::tg_channel", id=channel_id, "Parsed {} messages", counter);
    }
}

pub fn fetch_tg_channels<I, S>(
    client: reqwest::Client,
    parallel: usize,
    channels: I,
    timeout: Duration,
) -> impl Stream<Item = TgWebMessage>
where
    S: AsRef<str> + Send + 'static,
    I: Iterator<Item = S> + Send + 'static,
{
    let limit = Arc::new(tokio::sync::Semaphore::new(parallel));
    let (tx, rx) = tokio::sync::mpsc::channel(1024);

    let channels = channels.into_iter().map(|s| s.as_ref().to_owned());

    let mut task_group = JoinSet::new();
    for channel in channels {
        let client = client.clone();
        let tx = tx.clone();
        let limit = limit.clone();

        task_group.spawn(async move {
            fetch_tg_channel(client, channel.as_ref(), tx, limit, timeout).await
        });
    }
    drop(tx);

    TgWebMessageStream {
        receiver: rx,
        join_set: task_group,
    }
}

#[derive(Debug, Clone)]
pub struct TimestampedUrl {
    pub url: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct TimestampedProxy {
    pub urlx: UrlX,
    pub timestamp: String,
    pub source_url: String,
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
                            source_url: channel_url.to_string(),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[tokio::test]
    async fn test_fetch_tg_channel() -> anyhow::Result<()> {
        tracing_subscriber::fmt().compact().init();

        let client = reqwest::Client::builder().user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/237.84.2.178 Safari/537.36",
        ).build()?;

        let mut tg_messages = fetch_tg_channels(
            client,
            8,
            [
                "ARv2ray",
                "Alfred_Config",
                "Baraye_azadi_Info",
                "BmFt1",
                "Capital_NET",
                "Capoit",
                "CloudCityy",
                "ConfigV2rayNG",
                "Configforvpn01",
                "ConfigsHUB2",
                "v2ray_configs_pool",
            ]
            .into_iter(),
            Duration::from_secs(10),
        );

        let mut per_channel = BTreeMap::<TinyText, Vec<(DateTime<Utc>, TinyText, TinyText)>>::new();

        while let Some(msg) = tg_messages.next().await {
            for line in msg.msg_text.lines() {
                if let Some((
                    schema @ ("vless" | "vmess" | "ss" | "ssr" | "trojan" | "hy2" | "hysteria2"
                    | "hysteria" | "hy" | "warp" | "anytls" | "tuic"),
                    _,
                )) = line.split_once("://")
                {
                    per_channel.entry(msg.user.clone()).or_default().push((
                        msg.time,
                        schema.into(),
                        line.into(),
                    ));
                } else if let Some((schema @ "https", body)) = line.split_once("://")
                    && body.starts_with("t.me/proxy?")
                {
                    per_channel.entry(msg.user.clone()).or_default().push((
                        msg.time,
                        schema.into(),
                        line.into(),
                    ));
                }
            }
        }

        let total = per_channel.values().map(|v| v.len()).sum::<usize>();

        eprintln!(
            "+{:=^100}\n| Alive channels ({} total):\n+{:=^100}",
            "", total, ""
        );
        for (c, lines) in per_channel {
            eprintln!("{:=^100}\n{}: {}\n{:-^100}", "", c, lines.len(), "");
            for (time, schema, line) in lines {
                eprintln!("- [{}] <{}> {}", time, schema, line);
            }
        }
        eprintln!(
            "+{:=^100}\n| Alive channels ({} total):\n+{:=^100}",
            "", total, ""
        );

        Ok(())
    }
}
