use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use futures::Stream;
use tokio::task::JoinSet;

use crate::mining::registry::SourceRegistry;
use crate::mining::traced_config::TracedProtocolConfig;
use crate::utils::line::{Data, Lines};

/// Events emitted by subscription fetching tasks.
#[allow(clippy::large_enum_variant, reason = "todo: refactor")]
enum SubEvent {
    /// A successfully parsed proxy config.
    Item(TracedProtocolConfig),
    /// A non-fatal error (logged, stream continues).
    Error { url: String, error: String },
}

/// A single subscription fetch task, mirroring `TgChannelFetch`.
struct SubFetcher {
    client: reqwest::Client,
    url: url::Url,
    url_str: String,
    sender: tokio::sync::mpsc::Sender<SubEvent>,
    registry: Arc<SourceRegistry>,
}

impl SubFetcher {
    fn spawn(
        mut self: Pin<Box<Self>>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>> {
        Box::pin(async move {
            let this = self.as_mut();
            let Self {
                client,
                url,
                url_str,
                sender,
                registry,
            } = this.get_mut();

            // Download or read file
            let data = match url.scheme() {
                "https" | "http" => match download_sub_data(client, url).await {
                    Ok(d) => d,
                    Err(e) => {
                        _ = sender
                            .send(SubEvent::Error {
                                url: url_str.clone(),
                                error: e.to_string(),
                            })
                            .await;
                        return;
                    }
                },
                "file" => {
                    let Ok(path) = url.to_file_path() else {
                        tracing::error!(url = %url_str, "Invalid file URL: not an absolute path");
                        return;
                    };
                    match std::fs::read(&path) {
                        Ok(d) => d,
                        Err(e) => {
                            _ = sender
                                .send(SubEvent::Error {
                                    url: url_str.clone(),
                                    error: e.to_string(),
                                })
                                .await;
                            return;
                        }
                    }
                }
                other => {
                    tracing::error!(scheme = %other, url = %url_str, "Unsupported subscription URL scheme");
                    return;
                }
            };

            let download_ts = Utc::now();

            // Clone fields needed inside spawn_blocking
            let url_clone = url.clone();
            let url_str_clone = url_str.clone();
            let registry_clone = registry.clone();

            let result = tokio::task::spawn_blocking(move || {
                let lines = crate::parse_sub(&url_clone, &data);
                let source = registry_clone.lookup(&url_str_clone);
                (lines, source)
            })
            .await;

            let Ok((lines, Some(source))) = result else {
                _ = sender
                    .send(SubEvent::Error {
                        url: url_str.clone(),
                        error: "Source not found in registry".into(),
                    })
                    .await;
                return;
            };

            let ts = download_ts.timestamp();

            // Emit unparseable entries via tracing
            for line in lines.raw_entries() {
                if let Data::Raw { scheme, url } = &line.url {
                    if line.err.as_deref().is_some_and(|e| e.contains("promotion")) {
                        continue;
                    }
                    tracing::warn!(
                        target: "mining::unparseable",
                        raw_url = %url.as_ref(),
                        scheme = %scheme.as_ref(),
                        error = line.err.as_deref().unwrap_or("unknown"),
                        source_id = source.id,
                        source_type = "subscription",
                        timestamp = ts,
                    );
                }
            }

            // Send parsed configs
            for line in lines.iter() {
                let Data::Url(config) = &line.url else {
                    continue;
                };
                let item = SubEvent::Item(TracedProtocolConfig {
                    config: config.clone(),
                    timestamp: download_ts,
                    source: source.clone(),
                });
                if sender.send(item).await.is_err() {
                    break;
                }
            }
        })
    }
}

/// Convert parsed subscription lines into [`TracedProtocolConfig`] items,
/// emitting unparseable entries via the tracing layer.
///
/// Returns an empty vec if the source URL is not found in the registry.
pub fn lines_to_traced(
    lines: &Lines,
    registry: &SourceRegistry,
    url_str: &str,
    ts: i64,
) -> Vec<TracedProtocolConfig> {
    let Some(source) = registry.lookup(url_str) else {
        tracing::warn!(url = %url_str, "Source not found in registry (should not happen)");
        return Vec::new();
    };
    let timestamp = Utc::now();

    for line in lines.raw_entries() {
        if let Data::Raw { scheme, url } = &line.url {
            if line.err.as_deref().is_some_and(|e| e.contains("promotion")) {
                continue;
            }
            tracing::warn!(
                target: "mining::unparseable",
                raw_url = %url.as_ref(),
                scheme = %scheme.as_ref(),
                error = line.err.as_deref().unwrap_or("unknown"),
                source_id = source.id,
                source_type = "local",
                timestamp = ts,
            );
        }
    }

    lines
        .iter()
        .filter_map(|line| {
            let Data::Url(config) = &line.url else {
                return None;
            };
            Some(TracedProtocolConfig {
                config: config.clone(),
                timestamp,
                source: source.clone(),
            })
        })
        .collect()
}

/// # Errors
///
/// Will return `Err` if the request fails.
async fn download_sub_data(client: &reqwest::Client, url: &url::Url) -> Result<Vec<u8>> {
    let req = if matches!(
        url.host_str(),
        Some("raw.githubusercontent.com" | "github.com")
    ) && let Ok(auth) = std::env::var("GITHUB_TOKEN")
    {
        client.get(url.as_str()).bearer_auth(auth)
    } else {
        client.get(url.as_str())
    };

    let resp = req
        .send()
        .await
        .context("Subscription HTTP request failed")?
        .error_for_status()
        .context("Subscription HTTP error status")?;

    Ok(resp
        .bytes()
        .await
        .context("Failed to read subscription response body")?
        .to_vec())
}

/// Fetch all subscriptions as a stream of traced protocol configs.
/// Each subscription URL is spawned as a separate [`SubFetcher`] task.
#[allow(clippy::needless_pass_by_value, reason = "Should be owned by Future")]
pub(super) fn fetch_subscriptions(
    client: reqwest::Client,
    registry: Arc<SourceRegistry>,
    subscriptions: Vec<String>,
) -> impl Stream<Item = TracedProtocolConfig> {
    let (tx, rx) = tokio::sync::mpsc::channel::<SubEvent>(1024);
    let mut join_set = JoinSet::new();

    for sub_url_str in subscriptions {
        let Ok(url) = url::Url::parse(&sub_url_str) else {
            tracing::error!(url = %sub_url_str, "Invalid subscription URL");
            continue;
        };

        let task = Box::pin(SubFetcher {
            client: client.clone(),
            url,
            url_str: sub_url_str,
            sender: tx.clone(),
            registry: registry.clone(),
        });

        join_set.spawn(task.spawn());
    }
    drop(tx);

    SubscriptionStream {
        receiver: rx,
        join_set,
    }
}

#[allow(dead_code, reason = "Drop cancels in-flight tasks")]
struct SubscriptionStream {
    receiver: tokio::sync::mpsc::Receiver<SubEvent>,
    join_set: JoinSet<()>,
}

impl Stream for SubscriptionStream {
    type Item = TracedProtocolConfig;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(SubEvent::Item(item))) => {
                std::task::Poll::Ready(Some(item))
            }
            std::task::Poll::Ready(Some(SubEvent::Error { url, error })) => {
                tracing::warn!(url, error, "Subscription download error");
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
