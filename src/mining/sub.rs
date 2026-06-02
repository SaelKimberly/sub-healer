use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use futures::Stream;
use tokio::task::JoinSet;

use crate::mining::RawSourceItemBatch;
use crate::mining::registry::SourceRegistry;
use crate::urlx::SchemeX;

const BATCH_SIZE: usize = 10_000;

/// Events emitted by subscription fetching tasks.
enum SubEvent {
    /// A batch of raw URL strings from one subscription download.
    Item(RawSourceItemBatch),
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
    #[allow(clippy::too_many_lines, reason = "Entire task for subscription fetch")]
    fn spawn(
        mut self: Pin<Box<Self>>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>> {
        // Per-task safety timeout: reqwest client has 30s timeout, but proxy/DNS/OS
        // edge cases can still stall indefinitely. 90s covers the worst-case download
        // (slow proxy, large response) while preventing hangs.
        const TASK_TIMEOUT: Duration = Duration::from_secs(90);

        Box::pin(async move {
            let url_str = self.url_str.clone();
            let task = async {
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
                let url_str_clone = url_str.clone();
                let registry_clone = registry.clone();
                let sender = sender.clone();
                tokio::task::spawn_blocking(move || {
                    let text = crate::preprocess_sub_data(&data);

                    let Some(source) = registry_clone.lookup(&url_str_clone) else {
                        _ = sender.blocking_send(SubEvent::Error {
                            url: url_str_clone,
                            error: "Source not found in registry".into(),
                        });
                        return;
                    };

                    let mut batch: Vec<String> = Vec::with_capacity(BATCH_SIZE);

                    for line in text.lines() {
                        let s = line.trim_start();
                        if s.starts_with('#') || s.starts_with("//") || s.is_empty() {
                            continue;
                        }
                        for segment in s.split("<br/>") {
                            for (_, url) in SchemeX::slice_input(segment) {
                                batch.push(url.to_string());
                                if batch.len() >= BATCH_SIZE {
                                    let batch_urls = std::mem::take(&mut batch);
                                    let item = SubEvent::Item(RawSourceItemBatch {
                                        source: source.clone(),
                                        timestamp: download_ts,
                                        raw_urls: batch_urls.into_boxed_slice(),
                                    });
                                    if sender.blocking_send(item).is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }

                    if !batch.is_empty() {
                        let item = SubEvent::Item(RawSourceItemBatch {
                            source,
                            timestamp: download_ts,
                            raw_urls: batch.into_boxed_slice(),
                        });
                        _ = sender.blocking_send(item);
                    }
                })
                .await
                .expect("spawn_blocking should not panic on join handle");
            };

            if tokio::time::timeout(TASK_TIMEOUT, task).await.is_err() {
                tracing::warn!(url = %url_str, "Subscription fetch timed out after 90s");
            }
        })
    }
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

/// Fetch all subscriptions as a stream of raw URL batches.
/// Each subscription URL is spawned as a separate [`SubFetcher`] task.
#[allow(clippy::needless_pass_by_value, reason = "Should be owned by Future")]
pub(super) fn fetch_subscriptions(
    client: reqwest::Client,
    registry: Arc<SourceRegistry>,
    subscriptions: Vec<String>,
) -> impl Stream<Item = RawSourceItemBatch> {
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

struct SubscriptionStream {
    receiver: tokio::sync::mpsc::Receiver<SubEvent>,
    join_set: JoinSet<()>,
}

impl Stream for SubscriptionStream {
    type Item = RawSourceItemBatch;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Drain completed tasks — this registers their wakers so the stream
        // gets re-polled when new tasks finish.
        while this.join_set.poll_join_next(cx).is_ready() {}

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
            std::task::Poll::Pending => {
                // All tasks completed but receiver still has items in-flight or
                // is empty — if no tasks remain, no more items will ever arrive.
                if this.join_set.is_empty() {
                    std::task::Poll::Ready(None)
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }
}
