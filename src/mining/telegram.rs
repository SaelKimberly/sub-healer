use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use ego_tree::iter::Edge;
use futures::Stream;
use scraper::{ElementRef, Node};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

use crate::urlx::{RawUrlX, TinyText, UrlX, try_accept_raw};

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
    pub msg_urls: Option<Box<[UrlX]>>,
    pub unparseable_urls: Option<Box<[UnparseableRecord]>>,
}

enum TgEvent {
    Backfill(TgChannelFetch),
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

/// Parse a single message
#[inline]
#[allow(clippy::too_many_lines, reason = "TODO")]
fn parse_message(
    channel_id: &str,
    source_url: &str,
    msg_id: u32,
    msg: ElementRef<'_>,
) -> TgWebMessage {
    #[allow(clippy::type_complexity)]
    fn extract_urls(
        channel_id: &str,
        msg: ElementRef<'_>,
    ) -> (Option<Box<[UrlX]>>, Option<Box<[UnparseableRecord]>>) {
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
                // while let Some(chunk) = msg_tail.or_else(|| msg_text.next()) {
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
                // 1: If we are already in URL, we should append to it
                if is_found {
                    if let Some((eof, new_tail)) = chunk.split_once('\n') {
                        // 1.1 If we found a new line, there is an EOF
                        // - Save the tail
                        if !new_tail.is_empty() {
                            msg_tail = Some(new_tail);
                        }
                        // - Set is_found to false
                        is_found = false;
                        // - Append eof to the current URL
                        if !eof.is_empty() {
                            curr_url.push_str(eof);
                        }
                        // - Start a new URL
                        curr_url = msg_urls.push_mut(String::new());
                    } else {
                        // 1.2 If we did not found a new line, there is no EOF
                        // - Append to the current URL
                        curr_url.push_str(chunk);
                    }
                } else if let Some((schema, rest)) = chunk.split_once("://") {
                    use std::borrow::Cow;
                    let schema_lower = schema.trim_start().to_ascii_lowercase();
                    let schema: Cow<'static, str> = match schema_lower.as_str() {
                        "vless" => Cow::Borrowed("vless"),
                        "vmess" => Cow::Borrowed("vmess"),
                        "trojan" => Cow::Borrowed("trojan"),
                        "warp" => Cow::Borrowed("warp"),
                        "ss" | "shadowsocks" => Cow::Borrowed("ss"),
                        "ssr" | "shadowsocksr" => Cow::Borrowed("ssr"),
                        "anytls" => Cow::Borrowed("anytls"),
                        "slipnet" => Cow::Borrowed("slipnet"),
                        "slipnet-enc" => Cow::Borrowed("slipnet-enc"),
                        "hy" | "hhy" | "hysteria" | "hhysteria" => Cow::Borrowed("hy"),
                        "hy2" | "hhy2" | "hysteria2" | "hhysteria2" => Cow::Borrowed("hy2"),
                        "https"
                            if rest.starts_with("t.me/socks?")
                                | rest.starts_with("t.me/proxy?") =>
                        {
                            Cow::Borrowed("https")
                        }
                        "tg" => Cow::Borrowed("tg"),
                        "wireguard" => Cow::Borrowed("wireguard"),
                        _ => Cow::Owned(schema_lower),
                    };
                    curr_url.push_str(&schema);
                    curr_url.push_str("://");
                    // 2: If we found a schema, we should start a new URL
                    // - Set is_found to true
                    if let Some((eof, new_tail)) = rest.split_once('\n') {
                        // 2.1 If we found a new line, there is an EOF
                        // - Save the tail
                        if !new_tail.is_empty() {
                            msg_tail = Some(new_tail);
                        }
                        // - Set is_found to false
                        is_found = false;
                        // - Append eof to the current URL
                        curr_url.push_str(eof);
                        // - Start a new URL
                        curr_url = msg_urls.push_mut(String::new());
                    } else {
                        // 2.2 If we did not found a new line, there is a beginning of URL
                        // - Set is_found to true
                        is_found = true;

                        // - Append schema and rest to the current URL
                        curr_url.push_str(rest);
                    }
                }
            }
        }

        let mut parsed: Vec<UrlX> = Vec::new();
        let mut unparseable: Vec<UnparseableRecord> = Vec::new();

        for s in msg_urls
            .into_iter()
            .filter(|s| !s.is_empty() && !s.ends_with('…') && !s.ends_with("…»"))
        {
            let clean = if let Some((i, _)) =
                s.char_indices().rev().take_while(|(_, c)| *c == '`').last()
            {
                &s[..i]
            } else {
                &s
            };
            let raw: RawUrlX = clean.into();
            let raw_scheme = raw.schema.to_string();
            match try_accept_raw(&raw) {
                Ok(urlx) => parsed.push(urlx),
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
    // fn new(
    //     client: reqwest::Client,
    //     channel: &TinyText,
    //     sender: tokio::sync::mpsc::Sender<TgEvent>,
    //     limit: Arc<tokio::sync::Semaphore>,
    //     timeout: Duration,
    //     backfill: Option<DateTime<Utc>>,
    // ) -> Option<Self> {
    //     let channel_id = match channel.rsplit_once('/') {
    //         // Accept both webview link, and raw telegram link
    //         Some(("https://t.me/s" | "https://t.me", channel_id)) => channel_id.to_owned(),
    //         // Another prefixes are not supported
    //         Some((_, _)) => {
    //             tracing::warn!("Unexpected url: {channel} (should be https://t.me/s/[channel_id])");
    //             return None;
    //         }
    //         // When there is no slash in the url, trim the '@' prefix
    //         None => channel.trim_start_matches('@').to_owned(),
    //     };
    //     let source_url = channel.clone();
    //     Some(Self {
    //         client,
    //         channel: channel_id.into(),
    //         source_url,
    //         sender,
    //         limit,
    //         timeout,
    //         before: None,
    //         backfill,
    //     })
    // }

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
pub fn fetch_tg_channels<I, S>(
    client: reqwest::Client,
    parallel: usize,
    channels: I,
    timeout: Duration,
    backfill: Option<Backfill>,
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
        let task = Box::pin(TgChannelFetch {
            client: client.clone(),
            channel: channel.as_str().into(),
            source_url: channel.as_str().into(),
            sender: tx.clone(),
            limit: limit.clone(),
            timeout,
            before: None,
            backfill: backfill.as_ref().map(Backfill::to_min_datetime),
        });

        task_group.spawn(task.spawn());
    }
    drop(tx);

    TgWebMessageStream {
        receiver: rx,
        join_set: task_group,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::OpenOptions;
    use std::io::{BufWriter, Write};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use chrono::Local;
    use futures::StreamExt;
    use serde_json::json;
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry;

    use crate::mining::UnparseableLayer;
    use crate::mining::registry::{SourceRegistry, SourceType};

    use super::*;

    /// Mutex-guarded file writer shared across tracing layer clones.
    #[derive(Clone)]
    struct SharedLogWriter {
        writer: Arc<Mutex<BufWriter<std::fs::File>>>,
    }

    impl SharedLogWriter {
        fn new(path: &Path) -> Self {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("Failed to open pipeline log file");
            Self {
                writer: Arc::new(Mutex::new(BufWriter::new(file))),
            }
        }
    }

    impl Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writer.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.writer.lock().unwrap().flush()
        }
    }

    impl<'a> fmt::MakeWriter<'a> for SharedLogWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    #[ignore = "fetches real Telegram data; run manually to diagnose parsing warnings"]
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
        let pipeline_writer = SharedLogWriter::new(out_dir.join("tg-pipeline.log").as_path());

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

        // --- Registry (aligned with production: https://t.me/s/{name}) ---
        let mut registry = SourceRegistry::new();
        for name in &channels {
            registry.pre_populate(&format!("https://t.me/s/{name}"), SourceType::Telegram);
        }

        // --- Client ---
        let client = reqwest::Client::builder()
            .user_agent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/237.84.2.178 Safari/537.36",
            )
            .build()?;

        // --- Fetch ---
        let mut tg_messages = fetch_tg_channels(
            client,
            16,
            channels.into_iter(),
            Duration::from_secs(10),
            Some(Backfill::Last(TimeDelta::hours(5))),
        );

        // --- Collect ---
        let mut per_channel = BTreeMap::<TinyText, Vec<(DateTime<Utc>, TinyText, String)>>::new();

        while let Some(msg) = tg_messages.next().await {
            // Emit unparseable events (feeds UnparseableLayer → unparseable.ndjson)
            if let Some(ref unparseable) = msg.unparseable_urls {
                let source_url = format!("https://t.me/s/{}", msg.source_url);
                let source = registry.lookup(&source_url);
                let source_id = source.as_ref().map_or(0i64, |s| s.id);
                let ts = msg.time.timestamp();
                for u in unparseable {
                    tracing::warn!(
                        target: "mining::unparseable",
                        raw_url = %u.raw_url,
                        scheme = %u.scheme,
                        error = %u.error,
                        source_id = source_id,
                        source_type = "telegram",
                        timestamp = ts,
                    );
                }
            }

            let Some(msg_urls) = msg.msg_urls.as_deref() else {
                continue;
            };

            per_channel.entry(msg.source_url).or_default().extend(
                msg_urls
                    .iter()
                    .map(|urlx| (msg.time, urlx.schema.as_str().into(), urlx.reconstruct())),
            );
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
