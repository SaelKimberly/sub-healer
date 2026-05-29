use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use futures::stream::BoxStream;
use futures::StreamExt;
use tokio::sync::RwLock;

use crate::db::{self, SourceRecord};
use crate::proto_spec::{ParseResult, ProtoSpec, ProtocolConfig};
use crate::urlx::{RawUrlX, TinyText};

use super::raw_event::RawSourceItemBatch;
use super::registry::{SourceRegistry, SourceType};
use super::telegram::Backfill;

/// Central pipeline that owns the database connection, HTTP client, and source
/// registry. Every entry path (Stdin, Local, Remote, Config, Emit --pull, None)
/// constructs a `Pipeline`, registers sources, and calls [`Pipeline::run`].
pub struct Pipeline {
    conn: Arc<RwLock<rusqlite::Connection>>,
    client: reqwest::Client,
    registry: SourceRegistry,
    raw_batch_items: Vec<RawSourceItemBatch>,
    tg_timeout: std::time::Duration,
    tg_concurrency: usize,
    per_source_backfill: HashMap<TinyText, DateTime<Utc>>,
    backfill: Option<Backfill>,
}

impl Pipeline {
    /// Open database at `db_path`, build HTTP client with proxy.
    ///
    /// # Errors
    ///
    /// Delegates to [`super::open_db`] and [`super::build_client`].
    pub fn new(db_path: &Path) -> anyhow::Result<Self> {
        let conn = super::open_db(db_path)?;
        let client = super::build_client()?;
        Ok(Self {
            conn: Arc::new(RwLock::new(conn)),
            client,
            registry: SourceRegistry::new(),
            raw_batch_items: Vec::new(),
            tg_timeout: std::time::Duration::from_secs(30),
            tg_concurrency: 8,
            per_source_backfill: HashMap::new(),
            backfill: None,
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
            match meta.source_type {
                SourceType::Telegram => pipeline.add_telegram(&meta.url),
                SourceType::Subscription => pipeline.add_subscription(&meta.url),
                SourceType::Other => {}
            }
        }
        Ok(pipeline)
    }

    // --- Builder helpers ---

    /// Register a Telegram channel source.
    pub fn add_telegram(&mut self, url: &str) {
        self.registry.add_telegram_channel(url);
    }

    /// Register a subscription (HTTP) source.
    pub fn add_subscription(&mut self, url: &str) {
        self.registry.add_subscription(url);
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
            let conn = self.conn.write().await;
            self.registry.upsert_all(&*conn)?;
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
            let conn = self.conn.write().await;
            self.registry.upsert_all(&*conn)?;
        }

        let mut count = 0usize;
        let mut seen_sources: HashSet<i64> = HashSet::new();
        tokio::pin!(combined);
        while let Some(batch) = combined.next().await {
            if seen_sources.insert(batch.source.id) {
                let conn = self.conn.write().await;
                crate::db::upsert_source(&*conn, &batch.source.url)
                    .context("source upsert failed (aborting)")?;
            }

            let source_type = match batch.source.source_type {
                SourceType::Telegram => "telegram",
                SourceType::Subscription => "subscription",
                SourceType::Other => "other",
            };
            let ts = batch.timestamp.timestamp();

            for raw_url in batch.raw_urls.iter() {
                let raw: RawUrlX = raw_url.as_str().into();
                match ProtocolConfig::try_parse_detailed(&raw) {
                    Ok(ParseResult::Direct(config)) => {
                        let conn = self.conn.write().await;
                        crate::db::upsert_server(
                            &*conn,
                            &config,
                            batch.source.id,
                            ts,
                        )
                        .context("upsert failed (aborting)")?;
                        count += 1;
                    }
                    Ok(ParseResult::Fallback(config, info)) => {
                        super::emit_unparseable_entry(
                            &info.raw_url,
                            &info.original_scheme.to_string(),
                            &info.original_error,
                            batch.source.id,
                            source_type,
                            ts,
                        );
                        let conn = self.conn.write().await;
                        crate::db::upsert_server(
                            &*conn,
                            &config,
                            batch.source.id,
                            ts,
                        )
                        .context("upsert failed (aborting)")?;
                        count += 1;
                    }
                    Err(e) => {
                        let raw_scheme = raw.schema.to_string();
                        super::emit_unparseable_entry(
                            raw_url,
                            &raw_scheme,
                            &e.to_string(),
                            batch.source.id,
                            source_type,
                            ts,
                        );
                    }
                }
            }
        }

        Ok(count)
    }

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
        let conn = self.conn.write().await;

        let servers =
            db::query_servers_filtered(&*conn, protocols, min_first_seen, min_last_seen)
                .context("Failed to query servers")?;

        let server_ids: Vec<i64> = servers.iter().map(|s| s.id).collect();
        let sources = if server_ids.is_empty() {
            Vec::new()
        } else {
            db::query_sources_by_server_ids(&*conn, &server_ids)
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
        let conn = self.conn.write().await;
        Ok(db::query_all_sources(&*conn)?)
    }

    /// Get a reference to the internal source registry.
    #[must_use]
    pub fn registry_ref(&self) -> &SourceRegistry {
        &self.registry
    }

    /// Pre-populate a source in the registry for batch items (Stdin/Local).
    pub fn add_batch_source(&mut self, url: &str) {
        self.registry.pre_populate(url, SourceType::Other);
    }

    /// Get a reference to the shared database connection.
    #[must_use]
    pub fn conn(&self) -> &Arc<RwLock<rusqlite::Connection>> {
        &self.conn
    }

    /// Create a Pipeline wrapping an existing connection (for tests).
    /// Uses a default `reqwest::Client` (no proxy).
    #[cfg(test)]
    #[must_use]
    pub fn new_test(conn: rusqlite::Connection) -> Self {
        Self {
            conn: Arc::new(RwLock::new(conn)),
            client: reqwest::Client::new(),
            registry: SourceRegistry::new(),
            raw_batch_items: Vec::new(),
            tg_timeout: std::time::Duration::from_secs(30),
            tg_concurrency: 8,
            per_source_backfill: HashMap::new(),
            backfill: None,
        }
    }
}
