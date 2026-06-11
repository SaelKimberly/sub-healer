use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use ego_tree::iter::Edge;
use futures::Stream;
use scraper::{ElementRef, Node};
use std::borrow::Cow;
use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

use crate::urlx::{SchemeX, TinyText};

use super::RawSourceItemBatch;
use super::registry::SourceRegistry;

/// Selector for outer message container
static TG_WEB_MESSAGE_SELECTOR: LazyLock<scraper::Selector> =
    LazyLock::new(|| scraper::Selector::parse("div.tgme_widget_message").unwrap());
/// Selector for user (inside message container)
static TG_WEB_USER_SELECTOR: LazyLock<scraper::Selector> =
    LazyLock::new(|| scraper::Selector::parse("div.tgme_widget_message_user > a").unwrap());
/// Selector for time (inside message container)
static TG_WEB_TIME_SELECTOR: LazyLock<scraper::Selector> =
    LazyLock::new(|| scraper::Selector::parse("a.tgme_widget_message_date > time.time").unwrap());
/// Selector for text (inside message container)
static TG_WEB_TEXT_SELECTOR: LazyLock<scraper::Selector> =
    LazyLock::new(|| scraper::Selector::parse("div.tgme_widget_message_text").unwrap());

#[derive(Debug, Clone)]
pub struct TgWebMessage {
    pub user: TinyText,
    pub time: DateTime<Utc>,
    pub msg_id: u32,
    pub source_url: TinyText,
    pub raw_urls: Option<Vec<String>>,
}

enum TgEvent {
    Backfill(TgChannelFetch),
    Message(TgWebMessage),
    Timeout(TinyText),
    Failure(TinyText, reqwest::Error),
}

struct TracedConfigStream {
    receiver: Receiver<TgEvent>,
    join_set: JoinSet<()>,
    registry: Arc<SourceRegistry>,
}

impl Stream for TracedConfigStream {
    type Item = RawSourceItemBatch;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            match this.receiver.poll_recv(cx) {
                std::task::Poll::Ready(Some(TgEvent::Message(msg))) => {
                    let Some(source) = this.registry.lookup(&msg.source_url) else {
                        tracing::warn!(
                            url = %msg.source_url,
                            "Source not found in registry for Telegram message"
                        );
                        continue;
                    };

                    let raw_urls = msg.raw_urls.unwrap_or_default();
                    if raw_urls.is_empty() {
                        continue;
                    }

                    return std::task::Poll::Ready(Some(RawSourceItemBatch {
                        source,
                        timestamp: msg.time,
                        raw_urls: raw_urls.into_boxed_slice(),
                    }));
                }
                std::task::Poll::Ready(Some(TgEvent::Timeout(t))) => {
                    tracing::info!(target: "mining::tg_channel", id=t.as_str(), "Timeout");
                }
                std::task::Poll::Ready(Some(TgEvent::Failure(t, e))) => {
                    tracing::info!(target: "mining::tg_channel", id=t.as_str(), "Failure ({e})");
                }
                std::task::Poll::Ready(Some(TgEvent::Backfill(task))) => {
                    tracing::info!(
                        target: "mining::tg_channel",
                        id = task.channel.as_str(),
                        backfill = ?task.backfill,
                        oldest_msg_ts = ?task.oldest_msg_ts,
                        "Backfill (up to {before} id)",
                        before = task.before.unwrap(),
                    );
                    this.join_set.spawn(TgChannelFetch::spawn(Box::pin(task)));
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

/// Extract raw URL strings from a Telegram message's HTML.
/// Returns `None` if no text content is found.
fn extract_urls(_channel_id: &str, msg: ElementRef<'_>) -> Option<Vec<String>> {
    let mut msg_text = match msg.select(&TG_WEB_TEXT_SELECTOR).next() {
        Some(t) => t.traverse(),
        None => return None,
    };

    let mut msg_tail = Option::<&str>::None;

    let mut raw_urls = Vec::<String>::new();
    {
        let mut is_found: bool = false;

        let mut curr_url = raw_urls.push_mut(String::new());
        loop {
            let chunk = if let Some(tail) = msg_tail {
                tail
            } else if let Some(edge) = msg_text.next() {
                if let Edge::Open(node) = edge {
                    match node.value() {
                        Node::Text(t) => t.as_ref(),
                        Node::Element(e) if e.name() == "br" => "\n",
                        _ => {
                            continue;
                        }
                    }
                } else {
                    continue;
                }
            } else {
                break;
            };
            if is_found {
                if let Some((eof, new_tail)) = chunk.split_once('\n') {
                    if !new_tail.is_empty() {
                        msg_tail = Some(new_tail);
                    }
                    is_found = false;
                    if !eof.is_empty() {
                        curr_url.push_str(eof);
                    }
                    curr_url = raw_urls.push_mut(String::new());
                } else {
                    curr_url.push_str(chunk);
                }
            } else if let Some((schema, rest)) = chunk.split_once("://") {
                let schema = SchemeX::from_str(schema.trim_start()).unwrap().to_string();
                curr_url.push_str(&schema);
                curr_url.push_str("://");
                if let Some((eof, new_tail)) = rest.split_once('\n') {
                    if !new_tail.is_empty() {
                        msg_tail = Some(new_tail);
                    }
                    is_found = false;
                    if !eof.is_empty() {
                        curr_url.push_str(eof);
                    }
                    curr_url = raw_urls.push_mut(String::new());
                } else {
                    is_found = true;
                    curr_url.push_str(rest);
                }
            }
        }
    }

    // Filter empty URLs and truncated ones, clean trailing backticks, normalize extra= JSON
    let result: Vec<String> = raw_urls
        .into_iter()
        .filter(|s| !s.is_empty() && !s.ends_with('…') && !s.ends_with("…»"))
        .map(|s| {
            let s = if let Some((i, _)) =
                s.char_indices().rev().take_while(|(_, c)| *c == '`').last()
            {
                s[..i].to_string()
            } else {
                s
            };
            // Normalize any `extra=` JSON in the URL (Telegram URLs may have form-urlencoded +).
            // When no extra= present, normalize_extras returns Cow::Borrowed (zero-cost).
            match crate::utils::norm_extras::normalize_extras(s.as_bytes()) {
                Cow::Owned(bytes) => String::from_utf8(bytes).unwrap_or(s),
                Cow::Borrowed(_) => s,
            }
        })
        .collect();

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse a single message
#[inline]
fn parse_message(
    channel_id: &str,
    source_url: &str,
    msg_id: u32,
    msg: ElementRef<'_>,
) -> TgWebMessage {
    let user = msg
        .select(&TG_WEB_USER_SELECTOR)
        .next()
        .expect("Should be presented on every message")
        .attr("href")
        .expect("Should be presented for user")
        .rsplit_once('/')
        .expect("Always presented")
        .1;

    let time = msg
        .select(&TG_WEB_TIME_SELECTOR)
        .next()
        .expect("Should be presented on every message")
        .attr("datetime")
        .expect("Should be presented for time");

    let time = match DateTime::parse_from_rfc3339(time).map(|dt| dt.to_utc()) {
        Ok(time) => time,
        Err(e) => panic!("Failed to parse time: {e}"),
    };

    let raw_urls = extract_urls(channel_id, msg);

    TgWebMessage {
        user: user.into(),
        time,
        msg_id,
        source_url: source_url.into(),
        raw_urls,
    }
}

struct TgChannelFetch {
    client: reqwest::Client,
    channel: TinyText,
    source_url: TinyText,
    sender: tokio::sync::mpsc::Sender<TgEvent>,
    limit: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
    before: Option<u32>,
    backfill: Option<DateTime<Utc>>,
    oldest_msg_ts: Option<DateTime<Utc>>,
}

impl TgChannelFetch {
    #[allow(clippy::too_many_lines)]
    fn spawn(
        mut self: Pin<Box<Self>>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>> {
        Box::pin(async move {
            let this = self.as_mut();
            let Self {
                client,
                channel: channel_id,
                source_url,
                sender,
                limit,
                timeout,
                before,
                backfill,
                oldest_msg_ts: _,
            } = this.get_mut();
            // Reconstruct the web view link
            let url = if let Some(before) = before {
                tracing::info!(target: "mining::tg_channel", id=channel_id.as_str(), "Continue downloading (up to {before} id)");

                // Sleep 0.05 second
                tokio::time::sleep(Duration::from_millis(50)).await;

                format!("https://t.me/s/{channel_id}?before={before}")
            } else {
                format!("https://t.me/s/{channel_id}")
            };

            tracing::info!(target: "mining::tg_channel", id=channel_id.as_str(), "Start downloading");

            // Wait for a permit (rate limit for each channel)
            let Ok(_permit) = limit.acquire().await else {
                return;
            };

            // Closure, that fetch the channel webview page
            let fetch_fn = async || -> reqwest::Result<Bytes> {
                let data = client
                    .get(url.as_str())
                    .send()
                    .await?
                    .error_for_status()?
                    .bytes()
                    .await?;
                Ok(data)
            };

            // Try to fetch data (forward timeout and failure to the upstream).
            let data = match tokio::time::timeout(*timeout, fetch_fn()).await {
                // When there is a failure in the closure, forward it
                Ok(Err(e)) => {
                    _ = sender.send(TgEvent::Failure(channel_id.clone(), e)).await;
                    return;
                }
                // When there is a timeout, forward it
                Err(_) => {
                    _ = sender.send(TgEvent::Timeout(channel_id.clone())).await;
                    return;
                }
                // When there is a success, return the data
                Ok(Ok(resp)) => resp,
            };
            let text = String::from_utf8_lossy(&data).into_owned();

            tracing::info!(target: "mining::tg_channel", id=channel_id.as_str(), "Downloaded");

            let client = client.clone();
            let sender = sender.clone();
            let limit = limit.clone();
            let channel_id = channel_id.clone();
            let source_url = source_url.clone();
            let timeout = *timeout;
            let backfill = *backfill;

            let Ok((channel_id, counter)) = tokio::task::spawn_blocking(move ||
            {
                let html = scraper::Html::parse_document(&text);

                let mut counter = 0;
                let mut has_older = false;
                let mut first_id = None;
                let mut oldest_timestamp: Option<DateTime<Utc>> = None;

                for msg in html.select(&TG_WEB_MESSAGE_SELECTOR) {
                    let Some(msg_id) = msg
                        .attr("data-post")
                        .and_then(|t| t.rsplit_once('/'))
                        .and_then(|p|p.1.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    _ = first_id.get_or_insert(msg_id);

                    let msg = parse_message(&channel_id, source_url.as_str(), msg_id, msg);

                    if backfill.is_some_and(|backfill| msg.time < backfill) {
                        has_older = true;
                        continue;
                    }
                    oldest_timestamp = Some(oldest_timestamp.map_or(msg.time, |oldest| oldest.min(msg.time)));
                    if sender.blocking_send(TgEvent::Message(msg)).is_ok() {
                        counter += 1;
                    } else {
                        tracing::warn!(target: "mining::tg_channel", id=channel_id.as_str(), "Failed to send message");
                        break;
                    }
                }

                if !has_older && let Some(backfill) = backfill && let Some(first_id @ 2..) = first_id
                    && sender.blocking_send(TgEvent::Backfill(Self {
                        client: client.clone(),
                        channel: channel_id.clone(),
                        source_url: source_url.clone(),
                        sender: sender.clone(),
                        limit: limit.clone(),
                        timeout,
                        before: Some(first_id),
                        backfill: Some(backfill),
                        oldest_msg_ts: oldest_timestamp,
                    })).is_err() {
                        tracing::warn!(target: "mining::tg_channel", id=channel_id.as_str(), "Failed to send backfill event");
                    }

                (channel_id, counter)
            }).await else {return;};

            if counter == 0 {
                tracing::warn!(target: "mining::tg_channel", id=channel_id.as_str(), "No messages found");
            } else {
                tracing::info!(target: "mining::tg_channel", id=channel_id.as_str(), "Parsed {} messages", counter);
            }
        })
    }
}

#[derive(Debug, Clone)]
pub enum Backfill {
    Upto(DateTime<Utc>),
    Last(TimeDelta),
}

impl Backfill {
    #[must_use]
    pub fn to_min_datetime(&self) -> DateTime<Utc> {
        match self {
            Self::Upto(datetime) => *datetime,
            Self::Last(time) => Utc::now() - *time,
        }
    }
}

#[allow(clippy::needless_pass_by_value, reason = "Should be owned by task")]
pub(crate) fn fetch_tg_channels<I, S>(
    client: reqwest::Client,
    parallel: usize,
    channels: I,
    timeout: Duration,
    backfill: Option<Backfill>,
    per_source_backfill: HashMap<TinyText, DateTime<Utc>>,
    registry: Arc<SourceRegistry>,
) -> impl Stream<Item = RawSourceItemBatch>
where
    S: AsRef<str> + Send + 'static,
    I: Iterator<Item = S> + Send + 'static,
{
    let limit = Arc::new(tokio::sync::Semaphore::new(parallel));
    let (tx, rx) = tokio::sync::mpsc::channel(1024);

    let mut task_group = JoinSet::new();

    for channel in channels {
        let raw = channel.as_ref();
        // Normalize to canonical source URL: https://t.me/s/{name}
        let channel_id = raw
            .strip_prefix("https://t.me/s/")
            .or_else(|| raw.strip_prefix("https://t.me/"))
            .unwrap_or(raw)
            .trim_start_matches('@');
        let source_url: TinyText = super::registry::normalize_channel_url(raw).into();

        let channel_backfill = per_source_backfill
            .get(&source_url)
            .copied()
            .or_else(|| backfill.as_ref().map(Backfill::to_min_datetime));
        let task = Box::pin(TgChannelFetch {
            client: client.clone(),
            channel: channel_id.into(),
            source_url,
            sender: tx.clone(),
            limit: limit.clone(),
            timeout,
            before: None,
            backfill: channel_backfill,
            oldest_msg_ts: None,
        });

        task_group.spawn(task.spawn());
    }
    drop(tx);

    TracedConfigStream {
        receiver: rx,
        join_set: task_group,
        registry,
    }
}
