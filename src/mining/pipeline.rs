use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use futures::stream::BoxStream;
use rusqlite::Connection;

use crate::db::{Database, SourceRecord};
use crate::proto_spec::{ParseResult, ProtoSpec, ProtocolConfig};
use crate::urlx::{RawUrlX, TinyText};

use super::RawSourceItemBatch;
use super::registry::{SourceMetadata, SourceRegistry, SourceType};
use super::telegram::Backfill;

fn is_telegram_url_str(url_str: &str) -> bool {
    url::Url::parse(url_str).is_ok_and(|u| u.host_str() == Some("t.me"))
}

/// Central pipeline that owns the database adapter, HTTP client, and source
/// registry. Every entry path (Stdin, Local, Remote, Config, Emit --pull, None)
/// constructs a `Pipeline`, registers sources, and calls [`Pipeline::run`].
pub struct Pipeline {
    db: Database,
    client: reqwest::Client,
    registry: SourceRegistry,
    raw_batch_items: Vec<RawSourceItemBatch>,
    tg_timeout: std::time::Duration,
    tg_concurrency: usize,
    per_source_backfill: HashMap<TinyText, DateTime<Utc>>,
    backfill: Option<Backfill>,
    progress_bar: Option<indicatif::ProgressBar>,
}

impl Pipeline {
    /// Open database at `db_path`, build HTTP client with proxy.
    ///
    /// # Errors
    ///
    /// Delegates to [`Database::open`] and [`super::build_client`].
    pub fn new(db_path: &Path) -> anyhow::Result<Self> {
        let db = Database::open(db_path)?;
        let client = super::build_client()?;
        Ok(Self {
            db,
            client,
            registry: SourceRegistry::new(),
            raw_batch_items: Vec::new(),
            tg_timeout: std::time::Duration::from_secs(30),
            tg_concurrency: 8,
            per_source_backfill: HashMap::new(),
            backfill: None,
            progress_bar: None,
        })
    }

    /// Construct pipeline from config file.
    ///
    /// # Errors
    ///
    /// Delegates to [`Self::new`] and [`SourceRegistry::from_config`].
    pub fn from_config(config_path: &Path, db_path: &Path) -> anyhow::Result<Self> {
        let mut pipeline = Self::new(db_path)?;
        let registry = SourceRegistry::from_config(config_path)?;
        for meta in registry.sources() {
            pipeline.add_source(&meta.url);
        }
        Ok(pipeline)
    }

    // --- Builder helpers ---

    /// Register a source by URL, auto-classifying it as Telegram or subscription.
    pub fn add_source(&mut self, url: &str) {
        if is_telegram_url_str(url) {
            self.registry.add_telegram_channel(url);
        } else {
            self.registry.add_subscription(url);
        }
    }

    /// Add pre-processed raw URL batch items (used by Stdin/Local paths).
    pub fn add_batch_raw(&mut self, items: Vec<RawSourceItemBatch>) {
        self.raw_batch_items = items;
    }

    /// Configure per-source backfill timestamps (used by Emit --pull).
    pub fn set_per_source_backfill(&mut self, map: HashMap<TinyText, DateTime<Utc>>) {
        self.per_source_backfill = map;
    }

    /// Configure global backfill for Telegram fetches.
    pub fn set_backfill(&mut self, backfill: Option<Backfill>) {
        self.backfill = backfill;
    }

    /// Attach an optional progress bar to show URL processing progress.
    pub fn set_progress_bar(&mut self, pb: indicatif::ProgressBar) {
        self.progress_bar = Some(pb);
    }

    // --- Pipeline execution ---

    /// Run the full mining pipeline:
    /// 1. Upsert all registered sources to the DB
    /// 2. Build fetcher streams (Telegram, subscription, batch)
    /// 3. Merge streams with `stream::select`
    /// 4. Process each item through DB upsert
    ///
    /// Returns the number of configs processed.
    ///
    /// # Errors
    ///
    /// Returns an error if the database connection fails or a DB operation fails.
    #[allow(
        clippy::future_not_send,
        reason = "need some research. this is not a problem, as all works fine, but clippy complains"
    )]
    pub async fn run(&mut self) -> anyhow::Result<usize> {
        // 1. Upsert all registered sources
        {
            let reg = &self.registry;
            self.db
                .with_conn(|conn| reg.upsert_all(conn))
                .await
                .context("Failed to upsert registry sources")?;
        }

        // 2. Build fetcher streams (all RawSourceItemBatch)
        let registry = Arc::new(self.registry.clone());
        let (channels, subscriptions) = self.registry.partition_sources();
        let mut streams: Vec<BoxStream<'static, RawSourceItemBatch>> = Vec::new();

        if !channels.is_empty() {
            let tg = super::telegram::fetch_tg_channels(
                self.client.clone(),
                self.tg_concurrency,
                channels.into_iter(),
                self.tg_timeout,
                self.backfill.clone(),
                self.per_source_backfill.clone(),
                registry.clone(),
            );
            streams.push(tg.boxed());
        }

        if !subscriptions.is_empty() {
            let sub = super::sub::fetch_subscriptions(
                self.client.clone(),
                registry.clone(),
                subscriptions,
            );
            streams.push(sub.boxed());
        }

        if !self.raw_batch_items.is_empty() {
            let items = std::mem::take(&mut self.raw_batch_items);
            streams.push(futures::stream::iter(items).boxed());
        }

        // 3. Merge streams
        let combined: BoxStream<'static, RawSourceItemBatch> = if streams.is_empty() {
            futures::stream::empty().boxed()
        } else {
            let mut combined = streams.remove(0);
            for s in streams {
                combined = futures::stream::select(combined, s).boxed();
            }
            combined
        };

        // 4. Process via the unified consumer
        self.run_raw(combined).await
    }

    /// Run a pipeline that consumes a stream of raw URL batches.
    ///
    /// For each batch:
    /// 1. Upsert the source (if not already seen)
    /// 2. For each raw URL, call `ProtocolConfig::try_parse_detailed` and handle
    ///    all three outcomes (Direct, Fallback, Unparseable) in one place.
    ///
    /// Returns the number of successfully parsed configs.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails (aborting the entire pipeline).
    pub async fn run_raw(
        &mut self,
        combined: BoxStream<'static, RawSourceItemBatch>,
    ) -> anyhow::Result<usize> {
        // 1. Upsert all registered sources
        {
            let reg = &self.registry;
            self.db
                .with_conn(|conn| reg.upsert_all(conn))
                .await
                .context("Failed to upsert registry sources")?;
        }

        let mut count = 0usize;
        let mut seen_sources: HashSet<i64> = HashSet::new();
        tokio::pin!(combined);
        while let Some(batch) = combined.next().await {
            if seen_sources.insert(batch.source.id) {
                self.db
                    .upsert_source(&batch.source.url)
                    .await
                    .context("source upsert failed (aborting)")?;
            }

            let source_type = match batch.source.source_type {
                SourceType::Telegram => "telegram",
                SourceType::Subscription => "subscription",
                SourceType::Other => "other",
            };
            let ts = batch.timestamp.timestamp();
            let batch_count = self
                .db
                .with_conn(|conn| -> anyhow::Result<usize> {
                    let tx = conn.transaction()?;
                    let mut local_count = 0;
                    for raw_url in batch.raw_urls.iter() {
                        if process_single_raw_url(
                            raw_url.as_str(),
                            batch.source.id,
                            source_type,
                            ts,
                            &tx,
                        )? {
                            local_count += 1;
                        }
                    }
                    tx.commit()?;
                    Ok(local_count)
                })
                .await
                .context("batch upsert failed (aborting)")?;
            count += batch_count;

            if let Some(pb) = &self.progress_bar {
                pb.inc(batch.raw_urls.len() as u64);
            }
        }

        if let Some(pb) = &self.progress_bar {
            pb.finish_with_message(format!("Parsed {count} proxy configs"));
        }
        Ok(count)
    }
}

/// Process a single raw URL string, attempting to parse and upsert it.
///
/// Returns `true` if the URL was successfully parsed (Direct or Fallback)
/// and upserted into the database, `false` if unparseable.
///
/// # Errors
///
/// Returns `anyhow::Error` if a database operation fails (aborts pipeline).
pub(super) fn process_single_raw_url(
    raw_url: &str,
    source_id: i64,
    source_type: &str,
    ts: i64,
    conn: &Connection,
) -> anyhow::Result<bool> {
    let raw: RawUrlX = RawUrlX::from(raw_url);
    match ProtocolConfig::try_parse_detailed(&raw) {
        Ok(ParseResult::Direct(config)) => {
            crate::db::upsert_server(conn, &config, source_id, ts)?;
            Ok(true)
        }
        Ok(ParseResult::Fallback(config, info)) => {
            let fallback_msg = format!(
                "{} (parsed as {})",
                info.original_error,
                config.schema(),
            );
            super::emit_unparseable_entry(
                &info.raw_url,
                &info.original_scheme.to_string(),
                &fallback_msg,
                source_id,
                source_type,
                ts,
            );
            crate::db::upsert_server(conn, &config, source_id, ts)?;
            Ok(true)
        }
        Err(e) => {
            let raw_scheme = raw.schema.to_string();
            super::emit_unparseable_entry(
                raw_url,
                &raw_scheme,
                &e.to_string(),
                source_id,
                source_type,
                ts,
            );
            Ok(false)
        }
    }
}

impl Pipeline {
    // --- Query / Export ---

    /// Export servers matching filters as subscription text (emit command).
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn export(
        &self,
        protocols: Option<&[String]>,
        min_first_seen: Option<i64>,
        min_last_seen: Option<i64>,
    ) -> anyhow::Result<String> {
        let servers = self
            .db
            .query_servers_filtered(protocols, min_first_seen, min_last_seen)
            .await
            .context("Failed to query servers")?;

        let server_ids: Vec<i64> = servers.iter().map(|s| s.id).collect();
        let sources = if server_ids.is_empty() {
            Vec::new()
        } else {
            self.db
                .query_sources_by_server_ids(&server_ids)
                .await
                .context("Failed to query sources")?
        };

        let mut output = String::new();
        output.push_str(&format!(
            "# v2ray-heal generated at {}\n",
            Utc::now().to_rfc3339()
        ));
        if !sources.is_empty() {
            output.push_str("# Sources:\n");
            for src in &sources {
                output.push_str(&format!("#   - {}\n", src.url));
            }
        }
        output.push('\n');

        for server in &servers {
            let config: crate::proto_spec::ProtocolConfig =
                match serde_json::from_str(&server.raw_config) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(
                            server_id = server.id,
                            error = %e,
                            "Failed to deserialize config"
                        );
                        continue;
                    }
                };
            match config.reconstruct() {
                Ok(url) => {
                    output.push_str(&format!("{url}\n"));
                }
                Err(e) => {
                    tracing::warn!(
                        server_id = server.id,
                        error = %e,
                        "Failed to reconstruct URL"
                    );
                }
            }
        }

        Ok(output)
    }

    /// Query all known sources from the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn all_sources(&self) -> anyhow::Result<Vec<SourceRecord>> {
        self.db.query_all_sources().await.map_err(Into::into)
    }

    // --- Accessors ---

    /// Get a reference to the internal database adapter.
    #[must_use]
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Pre-populate a source in the registry for batch items (Stdin/Local).
    pub fn add_batch_source(&mut self, url: &str) {
        self.registry.pre_populate(url, SourceType::Other);
    }

    /// Look up source metadata for a previously registered URL.
    #[must_use]
    pub fn lookup_source(&self, url: &str) -> Option<Arc<SourceMetadata>> {
        self.registry.lookup(url)
    }

    /// Create a Pipeline wrapping an in-memory database (for tests).
    /// Uses a default `reqwest::Client` (no proxy).
    #[cfg(test)]
    #[must_use]
    pub fn new_test() -> Self {
        let db = Database::in_memory().expect("in-memory db");
        Self {
            db,
            client: reqwest::Client::new(),
            registry: SourceRegistry::new(),
            raw_batch_items: Vec::new(),
            tg_timeout: std::time::Duration::from_secs(30),
            tg_concurrency: 8,
            per_source_backfill: HashMap::new(),
            backfill: None,
            progress_bar: None,
        }
    }
}
