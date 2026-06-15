use rusqlite::{Connection, Result, params};

use super::models::{ServerRecord, SightingRecord, SourceRecord};

/// Get all sightings for a server.
///
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
    flags_mask: Option<u8>,
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

    if let Some(mask) = flags_mask
        && mask != 0
    {
        params.push(Box::new(i64::from(mask)));
        conditions.push(format!("(flags & ?{}) != 0", params.len()));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT id, schema, host, port, transport, security, remarks, raw_config, first_seen_ts, first_seen_source_id, sig, flags, flags_ts \
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
            sig: row.get(10)?,
            flags: row.get(11)?,
            flags_ts: row.get(12)?,
        })
    })?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

/// Get source records by their IDs (simple PK lookup).
///
/// # Errors
///
/// Returns `rusqlite::Error` if the query fails.
pub fn query_sources_by_ids(conn: &Connection, ids: &[i64]) -> Result<Vec<SourceRecord>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let placeholders: Vec<String> = ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();

    let sql = format!(
        "SELECT id, url FROM sources WHERE id IN ({}) ORDER BY url",
        placeholders.join(",")
    );

    let mut stmt = conn.prepare(&sql)?;

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = ids
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
