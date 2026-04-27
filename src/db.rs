use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};

use crate::UrlX;

pub const SCHEMA_SOURCES: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_hash TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL
);
"#;

pub const SCHEMA_SERVERS: &str = r#"
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
"#;

pub const SCHEMA_SIGHTINGS: &str = r#"
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    seen_ts INTEGER NOT NULL,
    remarks TEXT,
    FOREIGN KEY (server_id) REFERENCES servers(id),
    FOREIGN KEY (source_id) REFERENCES sources(id)
);
"#;

pub const SCHEMA_INDEX_SIGHTINGS: &str =
    "CREATE INDEX IF NOT EXISTS idx_sightings_server_ts ON sightings(server_id, seen_ts);";

pub const SCHEMA_INDEX_SERVERS: &str =
    "CREATE INDEX IF NOT EXISTS idx_servers_schema_security ON servers(schema, security);";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRecord {
    pub id: i64,
    pub url_hash: String,
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

fn hash_source_url(url: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

pub fn upsert_source(conn: &Connection, url: &str) -> Result<i64> {
    let url_hash = hash_source_url(url);

    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM sources WHERE url_hash = ?1",
            [&url_hash],
            |row| row.get(0),
        )
        .ok();

    if let Some(id) = existing {
        return Ok(id);
    }

    conn.execute(
        "INSERT INTO sources (url_hash, url) VALUES (?1, ?2)",
        params![url_hash, url],
    )?;
    Ok(conn.last_insert_rowid())
}

#[derive(Serialize, Deserialize)]
struct UrlXForJson {
    id: u64,
    schema: String,
    username: String,
    password: Option<String>,
    host: Option<String>,
    port: Option<String>,
    path: Option<String>,
    query: Vec<(String, Option<String>)>,
    fragment: Option<String>,
    transport: Option<String>,
    security: Option<String>,
}

impl From<&UrlX> for UrlXForJson {
    fn from(urlx: &UrlX) -> Self {
        Self {
            id: urlx.id,
            schema: urlx.schema.as_str().to_string(),
            username: urlx.username.clone(),
            password: urlx.password.as_ref().map(|p| p.to_string()),
            host: Some(urlx.host_str()),
            port: urlx.port.as_ref().map(|p| p.to_string()),
            path: urlx.path.clone(),
            query: urlx
                .query
                .iter()
                .map(|(k, v)| (k.to_string(), v.as_ref().map(|s| s.to_string())))
                .collect(),
            fragment: urlx.fragment.as_ref().map(|f| f.to_string()),
            transport: urlx.transport.as_ref().map(|t| t.to_string()),
            security: urlx.security.as_ref().map(|s| s.to_string()),
        }
    }
}

pub fn upsert_server(
    conn: &Connection,
    urlx: &UrlX,
    source_id: i64,
    incoming_ts: i64,
) -> Result<()> {
    let server_id = urlx.id as i64;

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
            let schema = urlx.schema.as_str().to_string();
            let host = urlx.host_str();
            let port = urlx
                .port
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_default();
            let transport = urlx.transport.as_ref().map(|s| s.to_string());
            let security = urlx.security.as_ref().map(|s| s.to_string());
            let remarks = urlx.fragment.as_ref().map(|f| f.to_string());
            let raw_config =
                serde_json::to_string(&UrlXForJson::from(urlx)).expect("Failed to serialize UrlX");

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
            let incoming_remarks = urlx.fragment.as_ref().map(|f| f.to_string());

            if incoming_ts < existing.first_seen_ts {
                conn.execute(
                    "INSERT INTO sightings (server_id, source_id, seen_ts, remarks) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        server_id,
                        existing.first_seen_source_id,
                        existing.first_seen_ts,
                        existing.remarks
                    ],
                )?;

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
