use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use ego_tree::iter::Edge;
use futures::Stream;
use scraper::{ElementRef, Node};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

use crate::proto_spec::{ProtoSpec, ProtocolConfig};
use crate::urlx::{RawUrlX, SchemeX, TinyText};

use super::registry::{SourceMetadata, SourceRegistry};
use super::traced_config::TracedProtocolConfig;

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
pub struct UnparseableRecord {
    pub raw_url: String,
    pub scheme: String,
    pub error: String,
}

#[allow(dead_code, reason = "")]
#[derive(Debug, Clone)]
pub struct TgWebMessage {
    pub user: TinyText,
    pub time: DateTime<Utc>,
    pub msg_id: u32,
    pub source_url: TinyText,
    pub msg_urls: Option<Box<[ProtocolConfig]>>,
    pub unparseable_urls: Option<Box<[UnparseableRecord]>>,
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
    pending_iter: std::vec::IntoIter<ProtocolConfig>,
    pending_source: Option<Arc<SourceMetadata>>,
    pending_time: Option<DateTime<Utc>>,
}

impl Stream for TracedConfigStream {
    type Item = TracedProtocolConfig;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Drain any remaining configs from a previous message first
        if let Some(config) = this.pending_iter.next() {
            let source = this
                .pending_source
                .clone()
                .expect("pending_source must be set when pending_iter is non-empty");
            let timestamp = this
                .pending_time
                .expect("pending_time must be set when pending_iter is non-empty");
            return std::task::Poll::Ready(Some(TracedProtocolConfig {
                config,
                timestamp,
                source,
            }));
        }
        this.pending_source = None;
        this.pending_time = None;

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
                    let ts = msg.time.timestamp();

                    if let Some(ref unparseable) = msg.unparseable_urls {
                        for u in unparseable {
                            crate::mining::emit_unparseable_entry(
                                &u.raw_url, &u.scheme, &u.error, source.id, "telegram", ts,
                            );
                        }
                    }

                    if let Some(msg_urls) = msg.msg_urls {
                        let mut iter = msg_urls.into_vec().into_iter();
                        if let Some(first) = iter.next() {
                            this.pending_iter = iter;
                            this.pending_source = Some(source.clone());
                            this.pending_time = Some(msg.time);
                            return std::task::Poll::Ready(Some(TracedProtocolConfig {
                                config: first,
                                timestamp: msg.time,
                                source,
                            }));
                        }
                    }
                    // No parseable configs — continue to next message
                }
                std::task::Poll::Ready(Some(TgEvent::Timeout(t))) => {
                    tracing::info!(target: "mining::tg_channel", id=t.as_str(), "Timeout");
                }
                std::task::Poll::Ready(Some(TgEvent::Failure(t, e))) => {
                    tracing::info!(target: "mining::tg_channel", id=t.as_str(), "Failure ({e})");
                }
                std::task::Poll::Ready(Some(TgEvent::Backfill(task))) => {
                    tracing::info!(target: "mining::tg_channel", id=task.channel.as_str(), "Backfill (up to {} id)", task.before.unwrap());
                    this.join_set.spawn(TgChannelFetch::spawn(Box::pin(task)));
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

#[allow(
    clippy::type_complexity,
    clippy::too_many_lines,
    reason = "This is a core parser function for single message"
)]
fn extract_urls(
    channel_id: &str,
    msg: ElementRef<'_>,
) -> (
    Option<Box<[ProtocolConfig]>>,
    Option<Box<[UnparseableRecord]>>,
) {
    let mut msg_text = match msg.select(&TG_WEB_TEXT_SELECTOR).next() {
        Some(t) => t.traverse(),
        None => return (None, None),
    };

    let mut msg_tail = Option::<&str>::None;

    let mut msg_urls = Vec::<String>::new();
    {
        let mut is_found: bool = false;

        let mut curr_url = msg_urls.push_mut(String::new());
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
                    curr_url = msg_urls.push_mut(String::new());
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
                    curr_url = msg_urls.push_mut(String::new());
                } else {
                    is_found = true;
                    curr_url.push_str(rest);
                }
            }
        }
    }

    let mut parsed: Vec<ProtocolConfig> = Vec::new();
    let mut unparseable: Vec<UnparseableRecord> = Vec::new();

    for s in msg_urls
        .into_iter()
        .filter(|s| !s.is_empty() && !s.ends_with('…') && !s.ends_with("…»"))
    {
        let clean =
            if let Some((i, _)) = s.char_indices().rev().take_while(|(_, c)| *c == '`').last() {
                &s[..i]
            } else {
                &s
            };
        let raw: RawUrlX = clean.into();
        let raw_scheme = raw.schema.to_string();
        match ProtocolConfig::try_parse(&raw) {
            Ok(config) => parsed.push(config),
            Err(e) => {
                tracing::warn!(
                    target: "mining::tg_channel",
                    id = channel_id,
                    "Failed to parse proxy URL: {} ({})",
                    clean,
                    e
                );
                unparseable.push(UnparseableRecord {
                    raw_url: clean.to_string(),
                    scheme: raw_scheme,
                    error: e.to_string(),
                });
            }
        }
    }

    let msg_urls = if parsed.is_empty() {
        None
    } else {
        Some(parsed.into_boxed_slice())
    };
    let unparseable_urls = if unparseable.is_empty() {
        None
    } else {
        Some(unparseable.into_boxed_slice())
    };
    (msg_urls, unparseable_urls)
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

    let (msg_urls, unparseable_urls) = extract_urls(channel_id, msg);

    TgWebMessage {
        user: user.into(),
        time,
        msg_id,
        source_url: source_url.into(),
        msg_urls,
        unparseable_urls,
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
            // tracing::info!(target: "mining::v2ray_subs", id=channel_id, "Start fetching channel");

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
#[allow(dead_code)]
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
) -> impl Stream<Item = TracedProtocolConfig>
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
        });

        task_group.spawn(task.spawn());
    }
    drop(tx);

    TracedConfigStream {
        receiver: rx,
        join_set: task_group,
        registry,
        pending_iter: Vec::new().into_iter(),
        pending_source: None,
        pending_time: None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::OpenOptions;
    use std::path::PathBuf;

    use chrono::Local;
    use futures::StreamExt;
    use serde_json::json;
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry;

    use crate::mining::PipelineLogWriter;
    use crate::mining::UnparseableLayer;
    use crate::mining::registry::{SourceRegistry, SourceType};

    use super::*;

    #[tokio::test]
    #[ignore = "fetches real Telegram data; run manually to diagnose parsing warnings"]
    #[allow(clippy::too_many_lines)]
    async fn test_fetch_tg_channel() -> anyhow::Result<()> {
        // --- Output directory ---
        let ts = Local::now().format("%Y%m%d-%H%M%S");
        let out_dir = PathBuf::from("test-output").join(format!("tg-{ts}"));
        std::fs::create_dir_all(&out_dir)?;

        // --- Set env var for UnparseableLayer ---
        let unparseable_path = out_dir.join("unparseable.ndjson");
        unsafe {
            std::env::set_var(
                "V2RAY_HEAL_UNPARSEABLE_LOG",
                unparseable_path.to_str().unwrap(),
            );
        };

        // --- Tracing layers ---
        let pipeline_writer = PipelineLogWriter::new(out_dir.join("tg-pipeline.log").as_path());

        registry()
            .with(
                fmt::layer()
                    .with_writer(pipeline_writer)
                    .compact()
                    .with_target(true)
                    .with_level(true)
                    .with_filter(filter_fn(|metadata| {
                        metadata.target() == "mining::tg_channel"
                            && *metadata.level() >= tracing::Level::INFO
                    })),
            )
            .with(UnparseableLayer::new())
            .with(
                fmt::layer()
                    .compact()
                    .with_target(true)
                    .with_level(true)
                    .with_filter(filter_fn(|metadata| {
                        *metadata.level() >= tracing::Level::WARN
                    })),
            )
            .init();

        // --- Channels ---
        let channels = [
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
            "DailyV2RY",
            "DigiV2ray",
            "DirectVPN",
            "Easy_Free_VPN",
            "Eleven_vpn",
            "EliV2ray",
            "EuServer",
            "EzNett",
            "FOXNT",
            "FProxies",
            "FalconPolV2rayNG",
            "FreakConfig",
            "Free166",
            "FreeV2rays",
            "FreeVlessVpn",
            "Free_HTTPCustom",
            "Helix_Servers",
            "Hope_Net",
            "Kia_Net",
            "IRANVPNNET",
            "JiedianSsr",
            "Jsnzk",
            "Lockey_vpn",
            "MTConfig",
            "MrV2Ray",
            "MsV2ray",
        ];

        // --- Registry (aligned with canonical https://t.me/s/{name}) ---
        let mut registry = SourceRegistry::new();
        let canonical_urls: Vec<String> = channels
            .iter()
            .map(|name| format!("https://t.me/s/{name}"))
            .collect();
        for url in &canonical_urls {
            registry.pre_populate(url, SourceType::Telegram);
        }
        let registry = Arc::new(registry);

        // --- Client ---
        let client = reqwest::Client::builder()
            .user_agent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/237.84.2.178 Safari/537.36",
            )
            .build()?;

        // --- Fetch (registry handles flattening + unparseable emission) ---
        let mut tg_stream = fetch_tg_channels(
            client,
            16,
            channels.into_iter(),
            Duration::from_secs(10),
            Some(Backfill::Last(TimeDelta::hours(5))),
            HashMap::new(),
            registry.clone(),
        );

        // --- Collect ---
        let mut per_channel = BTreeMap::<TinyText, Vec<(DateTime<Utc>, String, String)>>::new();

        while let Some(item) = tg_stream.next().await {
            per_channel
                .entry(item.source.url.as_str().into())
                .or_default()
                .push((
                    item.timestamp,
                    item.config.schema().to_string(),
                    item.config.reconstruct().unwrap_or_default(),
                ));
        }

        // --- Sort per channel ---
        for v in per_channel.values_mut() {
            v.sort_by_key(|t| t.0);
        }

        // --- Write results JSON ---
        let total: usize = per_channel.values().map(Vec::len).sum();
        let channels_map: serde_json::Map<String, serde_json::Value> = per_channel
            .iter()
            .map(|(channel, entries)| {
                let entries: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|(time, schema, url)| {
                        json!({
                            "time": time.to_rfc3339(),
                            "schema": schema,
                            "url": url,
                        })
                    })
                    .collect();
                (channel.to_string(), json!(entries))
            })
            .collect();

        let results = json!({
            "generated_at": Utc::now().to_rfc3339(),
            "total_channels": per_channel.len(),
            "total_urls": total,
            "channels": channels_map,
        });

        let results_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out_dir.join("tg-results.json"))?;
        serde_json::to_writer_pretty(results_file, &results)?;

        // --- Summary to stderr ---
        eprintln!("Logs written to: {}/", out_dir.display());
        eprintln!("{} URLs from {} channels", total, per_channel.len());

        Ok(())
    }
}
