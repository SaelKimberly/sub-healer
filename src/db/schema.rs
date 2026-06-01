use rusqlite::{Connection, Result};

pub const SCHEMA_SOURCES: &str = r"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL
);
";

pub const SCHEMA_SERVERS: &str = r"
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY,
    schema TEXT NOT NULL,
    host TEXT NOT NULL,
    port TEXT NOT NULL,
    transport TEXT,
    security TEXT,
    remarks TEXT,
    raw_config TEXT NOT NULL,
    first_seen_ts INTEGER NOT NULL,
    first_seen_source_id INTEGER NOT NULL,
    sig INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (first_seen_source_id) REFERENCES sources(id)
);
";

pub const SCHEMA_SIGHTINGS: &str = r"
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    seen_ts INTEGER NOT NULL,
    remarks TEXT,
    FOREIGN KEY (server_id) REFERENCES servers(id),
    FOREIGN KEY (source_id) REFERENCES sources(id)
);
";

pub const SCHEMA_INDEX_SIGHTINGS: &str =
    "CREATE INDEX IF NOT EXISTS idx_sightings_server_ts ON sightings(server_id, seen_ts);";

pub const SCHEMA_INDEX_SERVERS: &str =
    "CREATE INDEX IF NOT EXISTS idx_servers_schema_security ON servers(schema, security);";

/// # Errors
///
/// Will return `Err` if the database operation fails.
pub(crate) fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        &[
            SCHEMA_SOURCES,
            SCHEMA_SERVERS,
            SCHEMA_SIGHTINGS,
            SCHEMA_INDEX_SIGHTINGS,
            SCHEMA_INDEX_SERVERS,
        ]
        .join("\n"),
    )?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
    Ok(())
}
