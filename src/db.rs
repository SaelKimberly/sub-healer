use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};

use crate::proto_spec::ProtoSpec;
use crate::proto_spec::ProtocolConfig;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRecord {
    pub id: i64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRecord {
    pub id: i64,
    pub schema: String,
    pub host: String,
    pub port: String,
    pub transport: Option<String>,
    pub security: Option<String>,
    pub remarks: Option<String>,
    pub raw_config: String,
    pub first_seen_ts: i64,
    pub first_seen_source_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SightingRecord {
    pub id: i64,
    pub server_id: i64,
    pub source_id: i64,
    pub seen_ts: i64,
    pub remarks: Option<String>,
}

/// # Errors
///
/// Will return `Err` if the database operation fails.
pub fn init_db(conn: &Connection) -> Result<()> {
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
    Ok(())
}

/// Compute deterministic hash for source URL
/// Used as primary key in sources table
#[must_use]
pub fn hash_source_url(url: &str) -> i64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    hasher.finish().cast_signed()
}

/// # Errors
///
/// Will return `Err` if the database operation fails.
pub fn upsert_source(conn: &Connection, url: &str) -> Result<i64> {
    let url_id = hash_source_url(url);

    let existing: Option<i64> = conn
        .query_row("SELECT id FROM sources WHERE id = ?1", [url_id], |row| {
            row.get(0)
        })
        .ok();

    if let Some(id) = existing {
        return Ok(id);
    }

    conn.execute(
        "INSERT INTO sources (id, url) VALUES (?1, ?2)",
        params![url_id, url],
    )?;
    Ok(url_id)
}

/// # Errors
///
/// Will return `Err` if the database operation fails.
///
/// # Panics
///
/// Will panic if the `config` is not a server URL.
pub fn upsert_server(
    conn: &Connection,
    config: &ProtocolConfig,
    source_id: i64,
    incoming_ts: i64,
) -> Result<()> {
    let server_id = config.uid().cast_signed();

    let existing: Option<ServerRecord> = conn
        .query_row(
            "SELECT id, schema, host, port, transport, security, remarks, raw_config, first_seen_ts, first_seen_source_id FROM servers WHERE id = ?1",
            [server_id],
            |row| {
                Ok(ServerRecord {
                    id: row.get(0)?,
                    schema: row.get(1)?,
                    host: row.get(2)?,
                    port: row.get(3)?,
                    transport: row.get(4)?,
                    security: row.get(5)?,
                    remarks: row.get(6)?,
                    raw_config: row.get(7)?,
                    first_seen_ts: row.get(8)?,
                    first_seen_source_id: row.get(9)?,
                })
            },
        )
        .ok();

    match existing {
        None => {
            let schema = config.schema().as_str().to_string();
            let host = config
                .host()
                .map(|h| h.to_str().into_owned())
                .unwrap_or_default();
            let port = config.port().map(|p| p.to_string()).unwrap_or_default();
            let transport = config
                .transport_type()
                .map(std::string::ToString::to_string);
            let security = config.security_type().map(std::string::ToString::to_string);
            let remarks = config.remarks().map(std::string::ToString::to_string);
            let raw_config =
                serde_json::to_string(config).expect("Failed to serialize ProtocolConfig");

            conn.execute(
                "INSERT INTO servers (id, schema, host, port, transport, security, remarks, raw_config, first_seen_ts, first_seen_source_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![server_id, schema, host, port, transport, security, remarks, raw_config, incoming_ts, source_id],
            )?;

            conn.execute(
                "INSERT INTO sightings (server_id, source_id, seen_ts, remarks) VALUES (?1, ?2, ?3, ?4)",
                params![server_id, source_id, incoming_ts, remarks],
            )?;
        }
        Some(existing) => {
            let incoming_remarks = config.remarks().map(std::string::ToString::to_string);

            if incoming_ts < existing.first_seen_ts {
                // Backfill: earlier discovery found — update first_seen, add sighting.
                // The original sighting (created at first insert) already records the
                // old first_seen; no archive copy needed.
                conn.execute(
                    "UPDATE servers SET first_seen_ts = ?1, first_seen_source_id = ?2, remarks = ?3 WHERE id = ?4",
                    params![incoming_ts, source_id, incoming_remarks, server_id],
                )?;

                conn.execute(
                    "INSERT INTO sightings (server_id, source_id, seen_ts, remarks) VALUES (?1, ?2, ?3, ?4)",
                    params![server_id, source_id, incoming_ts, incoming_remarks],
                )?;
            } else {
                conn.execute(
                    "INSERT INTO sightings (server_id, source_id, seen_ts, remarks) VALUES (?1, ?2, ?3, ?4)",
                    params![server_id, source_id, incoming_ts, incoming_remarks],
                )?;
            }
        }
    }

    Ok(())
}

/// # Errors
///
/// Will return `Err` if the database query fails.
pub fn get_server(conn: &Connection, id: i64) -> Result<Option<ServerRecord>> {
    let result = conn.query_row(
        "SELECT id, schema, host, port, transport, security, remarks, raw_config, first_seen_ts, first_seen_source_id FROM servers WHERE id = ?1",
        [id],
        |row| {
            Ok(ServerRecord {
                id: row.get(0)?,
                schema: row.get(1)?,
                host: row.get(2)?,
                port: row.get(3)?,
                transport: row.get(4)?,
                security: row.get(5)?,
                remarks: row.get(6)?,
                raw_config: row.get(7)?,
                first_seen_ts: row.get(8)?,
                first_seen_source_id: row.get(9)?,
            })
        },
    );

    match result {
        Ok(record) => Ok(Some(record)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// # Errors
///
/// Will return `Err` if the query fails.
pub fn get_sightings(conn: &Connection, server_id: i64) -> Result<Vec<SightingRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, server_id, source_id, seen_ts, remarks FROM sightings WHERE server_id = ?1 ORDER BY seen_ts ASC",
    )?;

    let rows = stmt.query_map([server_id], |row| {
        Ok(SightingRecord {
            id: row.get(0)?,
            server_id: row.get(1)?,
            source_id: row.get(2)?,
            seen_ts: row.get(3)?,
            remarks: row.get(4)?,
        })
    })?;

    let mut sightings = Vec::new();
    for row in rows {
        sightings.push(row?);
    }
    Ok(sightings)
}

/// Query servers with optional filters.
///
/// * `protocols` — if `Some`, only include servers with matching schema (case-insensitive)
/// * `min_first_seen` — if `Some`, only servers with `first_seen_ts >=` this value
/// * `min_last_seen` — if `Some`, only servers with at least one sighting at `seen_ts >=` this value
///
/// Results are ordered by `schema ASC, remarks ASC NULLS LAST`.
///
/// # Errors
///
/// Returns `rusqlite::Error` if the query fails.
pub fn query_servers_filtered(
    conn: &Connection,
    protocols: Option<&[String]>,
    min_first_seen: Option<i64>,
    min_last_seen: Option<i64>,
) -> Result<Vec<ServerRecord>> {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(protocols) = protocols
        && !protocols.is_empty()
    {
        let placeholders: Vec<String> = protocols
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", params.len() + i + 1))
            .collect();
        conditions.push(format!("LOWER(schema) IN ({})", placeholders.join(",")));
        for p in protocols {
            params.push(Box::new(p.to_ascii_lowercase()));
        }
    }

    if let Some(ts) = min_first_seen {
        params.push(Box::new(ts));
        conditions.push(format!("first_seen_ts >= ?{}", params.len()));
    }

    if let Some(ts) = min_last_seen {
        params.push(Box::new(ts));
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM sightings WHERE server_id = servers.id AND seen_ts >= ?{})",
            params.len()
        ));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT id, schema, host, port, transport, security, remarks, raw_config, first_seen_ts, first_seen_source_id \
         FROM servers {where_clause} \
         ORDER BY schema ASC, remarks ASC NULLS LAST"
    );

    let mut stmt = conn.prepare(&sql)?;

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(AsRef::as_ref).collect();

    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(ServerRecord {
            id: row.get(0)?,
            schema: row.get(1)?,
            host: row.get(2)?,
            port: row.get(3)?,
            transport: row.get(4)?,
            security: row.get(5)?,
            remarks: row.get(6)?,
            raw_config: row.get(7)?,
            first_seen_ts: row.get(8)?,
            first_seen_source_id: row.get(9)?,
        })
    })?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

/// Get distinct source records that contributed sightings for the given server IDs.
///
/// # Errors
///
/// Returns `rusqlite::Error` if the query fails.
pub fn query_sources_by_server_ids(
    conn: &Connection,
    server_ids: &[i64],
) -> Result<Vec<SourceRecord>> {
    if server_ids.is_empty() {
        return Ok(Vec::new());
    }

    let placeholders: Vec<String> = server_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();

    let sql = format!(
        "SELECT DISTINCT src.id, src.url \
         FROM sources src \
         JOIN sightings si ON si.source_id = src.id \
         WHERE si.server_id IN ({}) \
         ORDER BY src.url",
        placeholders.join(",")
    );

    let mut stmt = conn.prepare(&sql)?;

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = server_ids
        .iter()
        .map(|id| id as &dyn rusqlite::types::ToSql)
        .collect();

    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(SourceRecord {
            id: row.get(0)?,
            url: row.get(1)?,
        })
    })?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

/// Query all known sources from the database.
///
/// # Errors
///
/// Returns `rusqlite::Error` if the query fails.
pub fn query_all_sources(conn: &Connection) -> Result<Vec<SourceRecord>> {
    let mut stmt = conn.prepare("SELECT id, url FROM sources ORDER BY url")?;
    let rows = stmt.query_map([], |row| {
        Ok(SourceRecord {
            id: row.get(0)?,
            url: row.get(1)?,
        })
    })?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

/// Query the latest timestamp associated with a source.
///
/// Combines `servers.first_seen_ts` and `sightings.seen_ts` to find the
/// most recent timestamp for servers linked to this source.
/// Returns `None` if the source has zero server records (inactive).
///
/// # Errors
///
/// Returns `rusqlite::Error` if the query fails.
pub fn query_latest_ts_for_source(conn: &Connection, source_id: i64) -> Result<Option<i64>> {
    let result: Option<i64> = conn.query_row(
        "SELECT MAX(ts) FROM (
            SELECT MAX(seen_ts) AS ts FROM sightings WHERE source_id = ?1
            UNION ALL
            SELECT first_seen_ts AS ts FROM servers WHERE first_seen_source_id = ?2
        )",
        params![source_id, source_id],
        |row| row.get(0),
    )?;
    Ok(result.filter(|&ts| ts > 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto_spec::ProtoSpec;
    use crate::urlx::RawUrlX;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn
    }

    fn setup_source(conn: &Connection, url: &str) -> i64 {
        upsert_source(conn, url).unwrap()
    }

    fn parse_config(url: &str) -> ProtocolConfig {
        let raw = RawUrlX::from(url);
        ProtocolConfig::try_parse(&raw).expect("valid config")
    }

    fn server_id(config: &ProtocolConfig) -> i64 {
        config.uid().cast_signed()
    }

    const CONFIG_A: &str = "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6ODAsImlkIjoiYWJjZGUtMTIzNDUtNjc4OTAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSJ9";
    const CONFIG_B: &str = "vmess://eyJhZGQiOiIxLjIuMy41IiwicG9ydCI6NDQzLCJpZCI6ImZlZGNiYTA5ODc2NTQzMjEiLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIn0=";

    #[test]
    fn test_fresh_insert() {
        let conn = setup_db();
        let source_id = setup_source(&conn, "https://example.com/sub1");
        let config = parse_config(CONFIG_A);

        upsert_server(&conn, &config, source_id, 100).unwrap();

        let sid = server_id(&config);
        let server = get_server(&conn, sid)
            .unwrap()
            .expect("server should exist");
        assert_eq!(server.first_seen_ts, 100);
        assert_eq!(server.first_seen_source_id, source_id);

        let sightings = get_sightings(&conn, sid).unwrap();
        assert_eq!(sightings.len(), 1);
        assert_eq!(sightings[0].seen_ts, 100);
        assert_eq!(sightings[0].source_id, source_id);
    }

    #[test]
    fn test_later_sighting() {
        let conn = setup_db();
        let source_id = setup_source(&conn, "https://example.com/sub1");
        let config = parse_config(CONFIG_A);

        upsert_server(&conn, &config, source_id, 50).unwrap();
        upsert_server(&conn, &config, source_id, 100).unwrap();

        let sid = server_id(&config);
        let server = get_server(&conn, sid)
            .unwrap()
            .expect("server should exist");
        assert_eq!(server.first_seen_ts, 50);

        let sightings = get_sightings(&conn, sid).unwrap();
        assert_eq!(sightings.len(), 2);
    }

    #[test]
    fn test_earlier_archive() {
        let conn = setup_db();
        let source_a = setup_source(&conn, "https://example.com/sub_a");
        let source_b = setup_source(&conn, "https://example.com/sub_b");
        let config = parse_config(CONFIG_A);

        upsert_server(&conn, &config, source_a, 100).unwrap();
        upsert_server(&conn, &config, source_b, 50).unwrap();

        let sid = server_id(&config);
        let server = get_server(&conn, sid)
            .unwrap()
            .expect("server should exist");
        assert_eq!(server.first_seen_ts, 50);
        assert_eq!(server.first_seen_source_id, source_b);

        let sightings = get_sightings(&conn, sid).unwrap();
        assert_eq!(sightings.len(), 2, "original + backfill sighting");
        assert!(
            sightings.iter().any(|s| s.seen_ts == 50),
            "should have sighting at ts=50"
        );
        assert!(
            sightings.iter().any(|s| s.seen_ts == 100),
            "should have sighting at ts=100"
        );
        assert!(
            sightings.iter().any(|s| s.source_id == source_b),
            "should have sighting from source_b"
        );
    }

    #[test]
    fn test_same_timestamp() {
        let conn = setup_db();
        let source_a = setup_source(&conn, "https://example.com/sub_a");
        let source_b = setup_source(&conn, "https://example.com/sub_b");
        let config = parse_config(CONFIG_A);

        upsert_server(&conn, &config, source_a, 100).unwrap();
        upsert_server(&conn, &config, source_b, 100).unwrap();

        let sid = server_id(&config);
        let server = get_server(&conn, sid)
            .unwrap()
            .expect("server should exist");
        assert_eq!(server.first_seen_ts, 100);
        assert_eq!(server.first_seen_source_id, source_a);

        let sightings = get_sightings(&conn, sid).unwrap();
        assert_eq!(sightings.len(), 2);
    }

    #[test]
    fn test_fk_violation() {
        let conn = setup_db();
        let config = parse_config(CONFIG_A);

        let result = upsert_server(&conn, &config, 99999, 100);
        assert!(result.is_err(), "should fail with FK constraint");
    }

    #[test]
    fn test_different_servers() {
        let conn = setup_db();
        let source_id = setup_source(&conn, "https://example.com/sub1");
        let config_a = parse_config(CONFIG_A);
        let config_b = parse_config(CONFIG_B);

        upsert_server(&conn, &config_a, source_id, 100).unwrap();
        upsert_server(&conn, &config_b, source_id, 200).unwrap();

        let sid_a = server_id(&config_a);
        let sid_b = server_id(&config_b);
        assert_ne!(sid_a, sid_b);

        assert!(
            get_server(&conn, sid_a).unwrap().is_some(),
            "server A should exist"
        );
        assert!(
            get_server(&conn, sid_b).unwrap().is_some(),
            "server B should exist"
        );
        assert_eq!(get_sightings(&conn, sid_a).unwrap().len(), 1);
        assert_eq!(get_sightings(&conn, sid_b).unwrap().len(), 1);
    }

    #[test]
    fn test_same_server_different_source() {
        let conn = setup_db();
        let source_a = setup_source(&conn, "https://example.com/sub_a");
        let source_b = setup_source(&conn, "https://example.com/sub_b");
        let config = parse_config(CONFIG_A);

        upsert_server(&conn, &config, source_a, 100).unwrap();
        upsert_server(&conn, &config, source_b, 200).unwrap();

        let sid = server_id(&config);
        let server = get_server(&conn, sid)
            .unwrap()
            .expect("server should exist");
        assert_eq!(server.first_seen_source_id, source_a);

        let sightings = get_sightings(&conn, sid).unwrap();
        assert_eq!(sightings.len(), 2);
        assert!(sightings.iter().any(|s| s.source_id == source_a));
        assert!(sightings.iter().any(|s| s.source_id == source_b));
    }
}
