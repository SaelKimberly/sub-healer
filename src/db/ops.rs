use rusqlite::{Connection, Result, params};

use crate::proto_spec::ProtoSpec;
use crate::proto_spec::ProtocolConfig;

use super::models::ServerRecord;

/// Compute deterministic hash for source URL.
/// Used as primary key in sources table.
#[must_use]
pub(crate) fn hash_source_url(url: &str) -> i64 {
    let mut hasher =
        rapidhash::v3::RapidStreamHasherV3::new(&rapidhash::v3::DEFAULT_RAPID_SECRETS);
    hasher.write(url.as_bytes());
    hasher.finish().cast_signed()
}

/// # Errors
///
/// Will return `Err` if the database operation fails.
pub(crate) fn upsert_source(conn: &Connection, url: &str) -> Result<i64> {
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
pub(crate) fn upsert_server(
    conn: &Connection,
    config: &ProtocolConfig,
    source_id: i64,
    incoming_ts: i64,
) -> Result<()> {
    let server_id = config.uid().cast_signed();
    let sig_i64 = config.sig().cast_signed();

    let existing: Option<ServerRecord> = conn
        .query_row(
            "SELECT id, schema, host, port, transport, security, remarks, raw_config, first_seen_ts, first_seen_source_id, sig FROM servers WHERE id = ?1",
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
                    sig: row.get(10)?,
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
                "INSERT INTO servers (id, schema, host, port, transport, security, remarks, raw_config, first_seen_ts, first_seen_source_id, sig) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![server_id, schema, host, port, transport, security, remarks, raw_config, incoming_ts, source_id, sig_i64],
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

/// Get a server record by ID.
///
/// # Errors
///
/// Returns `rusqlite::Error` if the query fails.
pub(crate) fn get_server(conn: &Connection, id: i64) -> Result<Option<ServerRecord>> {
    let result = conn.query_row(
        "SELECT id, schema, host, port, transport, security, remarks, raw_config, first_seen_ts, first_seen_source_id, sig FROM servers WHERE id = ?1",
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
                sig: row.get(10)?,
            })
        },
    );

    match result {
        Ok(record) => Ok(Some(record)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use crate::db::schema::init_db;

    use crate::db::ops::get_server;
    use crate::db::ops::upsert_server;
    use crate::db::ops::upsert_source;
    use crate::db::queries::get_sightings;
    use crate::proto_spec::ProtoSpec;
    use crate::urlx::RawUrlX;

    use super::super::ProtocolConfig;

    fn setup_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn
    }

    fn setup_source(conn: &rusqlite::Connection, url: &str) -> i64 {
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
        // Verify stored sigs differ and match computed values
        let server_a = get_server(&conn, sid_a).unwrap().unwrap();
        let server_b = get_server(&conn, sid_b).unwrap().unwrap();
        assert_ne!(server_a.sig, server_b.sig);
        assert_eq!(server_a.sig, config_a.sig().cast_signed());
        assert_eq!(server_b.sig, config_b.sig().cast_signed());

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

    #[test]
    fn test_sig_stored() {
        let conn = setup_db();
        let source_id = setup_source(&conn, "https://example.com/sub1");
        let config = parse_config(CONFIG_A);

        upsert_server(&conn, &config, source_id, 100).unwrap();

        let sid = server_id(&config);
        let server = get_server(&conn, sid)
            .unwrap()
            .expect("server should exist");
        let expected_sig = config.sig().cast_signed();
        assert_eq!(
            server.sig, expected_sig,
            "sig column should match ProtocolConfig::sig()"
        );
        assert_ne!(server.sig, 0, "sig should be non-zero for valid config");
    }
}
