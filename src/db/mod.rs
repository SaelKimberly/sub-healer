pub mod models;
pub mod schema;
pub(crate) mod ops;
pub(crate) mod queries;

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, Result};
use tokio::sync::RwLock;

pub use models::{ServerRecord, SightingRecord, SourceRecord};
// Re-export internal functions accessible to other crate modules.
pub(crate) use ops::{upsert_server, upsert_source};
pub(crate) use ops::hash_source_url;
pub(crate) use schema::init_db;
use crate::proto_spec::ProtocolConfig;

/// Database adapter that wraps an `Arc<RwLock<Connection>>`.
/// All methods handle locking internally — callers never touch the lock.
#[derive(Debug, Clone)]
pub struct Database {
    conn: Arc<RwLock<Connection>>,
}

impl Database {
    /// Open or create a database at `path` and initialize the schema.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the database cannot be opened or the
    /// schema cannot be initialized.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        schema::init_db(&conn)?;
        Ok(Self {
            conn: Arc::new(RwLock::new(conn)),
        })
    }

    /// Create an in-memory database for testing.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the database cannot be created.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        schema::init_db(&conn)?;
        Ok(Self {
            conn: Arc::new(RwLock::new(conn)),
        })
    }

    /// Compute deterministic hash for a source URL.
    /// Delegates to [`hash_source_url`].
    #[must_use]
    pub fn hash_source_url(url: &str) -> i64 {
        ops::hash_source_url(url)
    }

    /// Upsert a source by URL, returning its ID.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the operation fails.
    pub async fn upsert_source(&self, url: &str) -> Result<i64> {
        let conn = self.conn.write().await;
        ops::upsert_source(&*conn, url)
    }

    /// Upsert a server config, handling time-travel (sightings) logic.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the operation fails.
    pub async fn upsert_server(
        &self,
        config: &ProtocolConfig,
        source_id: i64,
        incoming_ts: i64,
    ) -> Result<()> {
        let conn = self.conn.write().await;
        ops::upsert_server(&*conn, config, source_id, incoming_ts)
    }

    /// Get a server record by ID.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the query fails.
    pub async fn get_server(&self, id: i64) -> Result<Option<ServerRecord>> {
        self.with_conn_read(|conn| ops::get_server(conn, id)).await
    }

    /// Get all sightings for a server.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the query fails.
    pub async fn get_sightings(&self, server_id: i64) -> Result<Vec<SightingRecord>> {
        self.with_conn_read(|conn| queries::get_sightings(conn, server_id))
            .await
    }

    /// Query servers with optional protocol/backfill filters.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the query fails.
    pub async fn query_servers_filtered(
        &self,
        protocols: Option<&[String]>,
        min_first_seen: Option<i64>,
        min_last_seen: Option<i64>,
    ) -> Result<Vec<ServerRecord>> {
        self.with_conn_read(|conn| {
            queries::query_servers_filtered(conn, protocols, min_first_seen, min_last_seen)
        })
        .await
    }

    /// Get distinct source records for the given server IDs.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the query fails.
    pub async fn query_sources_by_server_ids(
        &self,
        server_ids: &[i64],
    ) -> Result<Vec<SourceRecord>> {
        self.with_conn_read(|conn| queries::query_sources_by_server_ids(conn, server_ids))
            .await
    }

    /// Query all known sources.
    ///
    /// # Errors
    pub async fn query_all_sources(&self) -> Result<Vec<SourceRecord>> {
        self.with_conn_read(|conn| queries::query_all_sources(conn)).await
    }

    /// Query the latest timestamp associated with a source.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the query fails.
    pub async fn query_latest_ts_for_source(&self, source_id: i64) -> Result<Option<i64>> {
        self.with_conn_read(|conn| queries::query_latest_ts_for_source(conn, source_id))
            .await
    }

    /// Run a closure with the underlying `Connection` (write lock held).
    /// Used for operations that need the raw connection, like
    /// [`SourceRegistry::upsert_all`].
    pub async fn with_conn<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut Connection) -> T,
    {
        let mut conn = self.conn.write().await;
        f(&mut *conn)
    }

    /// Run a closure with the underlying `Connection` (read lock held).
    /// Used for read-only queries that don't need a write lock.
    pub async fn with_conn_read<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&Connection) -> T,
    {
        let conn = self.conn.read().await;
        f(&*conn)
    }
}
