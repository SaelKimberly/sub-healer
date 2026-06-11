use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::{Stream, StreamExt};
use tokio::task::JoinSet;

use crate::decoder::StreamingDecoder;
use crate::decoder::INPUT_CHUNK_SIZE;
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

        Box::pin(async move {
            let url_str = self.url_str.clone();
            let task = async {
                let this = self.as_mut();
                let Self {
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

                let mut decoder = StreamingDecoder::new();
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

                let mut stream = match super::create_stream(url).await {
                    Ok(s) => s,
                    Err(e) => {
                        _ = sender.send(SubEvent::Error {
                            url: url_str.clone(),
                            error: format!("Cannot create stream ({e})"),
                        });
                        return;
                    }
                };

                loop {
                    let (stops, chunk) = match stream.next().await {
Some(Ok(c)) => {
    let mut urls = Vec::new();
    let mut remaining: &[u8] = &c;
    loop {
        let end = remaining.len().min(INPUT_CHUNK_SIZE);
        let piece = &remaining[..end];
        remaining = &remaining[end..];
        match decoder.feed(piece) {
            Ok(mut u) => urls.append(&mut u),
            Err(e) => {
                _ = sender.send(SubEvent::Error {
                    url: url_str.clone(),
                    error: format!("Stream decoding error ({e})"),
                }).await;
                return;
            }
        }
        if remaining.is_empty() {
            break;
        }
    }
    (false, Ok(urls))
},
                        None => (true, decoder.finalize()),
                        Some(Err(e)) => {
                            _ = sender.send(SubEvent::Error {
                                url: url_str.clone(),
                                error: format!("Stream error ({e})"),
                            });
                            return;
                        }
                    };

                    let data = match chunk {
                        Ok(c) => c,
                        Err(e) => {
                            _ = sender.send(SubEvent::Error {
                                url: url_str.clone(),
                                error: format!("Stream decoding error ({e})"),
                            });
                            return;
                        }
                    };

                    for u in data {
                        batch.push(u);
                        if batch.len() >= BATCH_SIZE {
                            try_flush!();
                        }
                    }

                    if stops {
                        break;
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

            if tokio::time::timeout(TASK_TIMEOUT, Box::pin(task))
                .await
                .is_err()
            {
                tracing::warn!(url = %url_str, "Subscription fetch timed out after 90s");
            }
        })
    }
}
/// Fetch all subscriptions as a stream of raw URL batches.
/// Each subscription URL is spawned as a separate [`SubFetcher`] task.
#[allow(clippy::needless_pass_by_value, reason = "Should be owned by Future")]
pub(super) fn fetch_subscriptions(
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
        while let std::task::Poll::Ready(Some(_)) = this.join_set.poll_join_next(cx) {}

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
