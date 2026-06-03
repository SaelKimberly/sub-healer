use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::Stream;
use tokio::task::JoinSet;

use crate::mining::RawSourceItemBatch;
use crate::mining::registry::SourceRegistry;

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
        const TASK_TIMEOUT: Duration = Duration::from_secs(90);
        const READ_CHUNK_SIZE: usize = 65536;

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

                // Look up source before streaming (registry lookup is cheap)
                let Some(source) = registry.lookup(url_str) else {
                    _ = sender
                        .send(SubEvent::Error {
                            url: url_str.clone(),
                            error: "Source not found in registry".into(),
                        })
                        .await;
                    return;
                };
                let download_ts = Utc::now();

                let mut decoder = crate::decoder::StreamingDecoder::new();
                let mut batch: Vec<String> = Vec::with_capacity(BATCH_SIZE);

                // Flush accumulated URLs as a batch through the channel
                macro_rules! try_flush {
                    () => {
                        if !batch.is_empty() {
                            let item = SubEvent::Item(RawSourceItemBatch {
                                source: source.clone(),
                                timestamp: download_ts,
                                raw_urls: std::mem::take(&mut batch).into_boxed_slice(),
                            });
                            if sender.send(item).await.is_err() {
                                return;
                            }
                        }
                    };
                }

                match url.scheme() {
                    "https" | "http" => {
                        let req = if matches!(
                            url.host_str(),
                            Some("raw.githubusercontent.com" | "github.com")
                        ) && let Ok(auth) = std::env::var("GITHUB_TOKEN")
                        {
                            client.get(url.as_str()).bearer_auth(auth)
                        } else {
                            client.get(url.as_str())
                        };

                        match req
                            .send()
                            .await
                            .and_then(|r| r.error_for_status().map_err(Into::into))
                        {
                            Ok(resp) => {
                                use futures::StreamExt;
                                let mut stream = resp.bytes_stream();
                                while let Some(chunk_result) = stream.next().await {
                                    match chunk_result {
                                        Ok(chunk) => {
                                            for u in decoder.feed(&chunk) {
                                                batch.push(u);
                                                if batch.len() >= BATCH_SIZE {
                                                    try_flush!();
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                url = %url_str, error = %e,
                                                "Subscription stream error"
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
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
                    "file" => {
                        let Ok(path) = url.to_file_path() else {
                            tracing::error!(
                                url = %url_str,
                                "Invalid file URL: not an absolute path"
                            );
                            return;
                        };
                        match tokio::fs::File::open(&path).await {
                            Ok(mut file) => {
                                use tokio::io::AsyncReadExt;
                                let mut buf = vec![0u8; READ_CHUNK_SIZE];
                                loop {
                                    match file.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            for u in decoder.feed(&buf[..n]) {
                                                batch.push(u);
                                                if batch.len() >= BATCH_SIZE {
                                                    try_flush!();
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                url = %url_str, error = %e,
                                                "File read error"
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
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
                        tracing::error!(
                            scheme = %other,
                            url = %url_str,
                            "Unsupported subscription URL scheme"
                        );
                        return;
                    }
                }

                // Process remaining decoder data
                for u in decoder.finalize() {
                    batch.push(u);
                    if batch.len() >= BATCH_SIZE {
                        try_flush!();
                    }
                }

                // Final flush
                if !batch.is_empty() {
                    let item = SubEvent::Item(RawSourceItemBatch {
                        source,
                        timestamp: download_ts,
                        raw_urls: batch.into_boxed_slice(),
                    });
                    _ = sender.send(item).await;
                }
            };

            if tokio::time::timeout(TASK_TIMEOUT, task).await.is_err() {
                tracing::warn!(url = %url_str, "Subscription fetch timed out after 90s");
            }
        })
    }
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
