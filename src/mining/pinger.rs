use std::collections::HashSet;
use std::str::FromStr;
use std::time::Instant;

use futures::StreamExt;
use futures::stream::FuturesOrdered;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::db::{Database, ServerRecord};
use indicatif::{ProgressBar, ProgressStyle};

/// The skip set of protocol schemas that are UDP/QUIC/DNS-based and cannot be
/// reached via a plain TCP connect.
const SKIP_SCHEMAS: &[&str] = &[
    "wireguard",
    "tuic",
    "hysteria2",
    "stormdns",
    "slipnet",
    "slipnet-enc",
];

/// Timeout for each individual TCP ping connection (includes DNS + connect).
const PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Maximum number of concurrent in-flight ping connections.
///
/// Choosing this value: system must have enough ephemeral ports and FDs.
/// Rule of thumb: concurrency × (tcp_fin_timeout / PING_TIMEOUT) ≤ ip_local_port_range.
/// - Default Linux: 28,232 ports, 60s fin_timeout → at 3s timeout, max ~470 conns/s.
/// - 200 concurrent × 60/3 = 4,000 ≤ 28,232 → safe.
/// - FD overhead is negligible (1 socket per conn; ulimit is 1M on this system).
const PING_CONCURRENCY: usize = 200;

/// Ping specification: either "ok" (reachability only) or a latency threshold.
#[derive(Debug, Clone)]
pub enum PingSpec {
    /// Check reachability only; no latency filtering.
    Ok,
    /// Ping and only consider servers with RTT ≤ this threshold as passing.
    Threshold(std::time::Duration),
}

impl FromStr for PingSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("ok") {
            return Ok(Self::Ok);
        }
        // Try to parse as a humantime duration
        let dur: std::time::Duration = s
            .parse::<humantime::Duration>()
            .map_err(|e| {
                format!("Invalid ping spec: '{s}' — expected 'ok' or a duration like '15ms': {e}")
            })?
            .into();
        Ok(Self::Threshold(dur))
    }
}

/// Result of pinging a single endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PingResult {
    /// TCP connection result.
    Tcp {
        /// Round-trip latency in milliseconds, if the connection succeeded.
        #[serde(skip_serializing_if = "Option::is_none")]
        latency_ms: Option<f64>,
        /// Error message if the connection failed.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

/// Ping a single `host:port` endpoint via TCP connect with [`PING_TIMEOUT`].
///
/// Returns a [`PingResult::Tcp`] recording either the round-trip latency in
/// milliseconds (on success) or the error message (on failure).
async fn ping_endpoint(host: &str, port: u16) -> PingResult {
    let start = Instant::now();
    let addr = format!("{host}:{port}");
    match timeout(PING_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            PingResult::Tcp {
                latency_ms: Some(latency_ms),
                error: None,
            }
        }
        Ok(Err(e)) => PingResult::Tcp {
            latency_ms: None,
            error: Some(e.to_string()),
        },
        Err(_) => PingResult::Tcp {
            latency_ms: None,
            error: Some(format!("timeout after {}s", PING_TIMEOUT.as_secs())),
        },
    }
}

/// Ping all unique (host, port) pairs from the given server records.
///
/// 1. Filters out servers whose schema is in the skip list (UDP/QUIC/DNS).
/// 2. Skips servers with an empty or "0" port.
/// 3. Deduplicates by lowercased host + port.
/// 4. Pings each unique endpoint concurrently (cap 50 in-flight).
/// 5. Stores results to the database for ALL matching server records.
///
/// Returns the `Vec<(host, port, PingResult)>` of all unique endpoints that
/// were actually pinged (skipped ones are omitted).
///
/// # Errors
///
/// Returns an error if a database write fails (aborts the operation).
#[allow(clippy::future_not_send, reason = "needs research")]
#[allow(
    clippy::missing_panics_doc,
    reason = "only for progressbar template: actually, impossible to reach"
)]
#[allow(clippy::too_many_lines)]
pub async fn ping_and_store(
    db: &Database,
    servers: &[ServerRecord],
    _spec: &PingSpec,
    progress_bar: Option<ProgressBar>,
) -> anyhow::Result<Vec<(String, u16, PingResult)>> {
    // Filter UDP schemas and empty/"0" ports
    let mut seen: HashSet<(String, u16)> = HashSet::new();
    let mut endpoints: Vec<(String, u16)> = Vec::new();

    for srv in servers {
        let schema_lower = srv.schema.to_ascii_lowercase();
        if SKIP_SCHEMAS.iter().any(|skip| *skip == schema_lower) {
            continue;
        }
        let port: u16 = match srv.port.parse() {
            Ok(p) if p != 0 => p,
            _ => continue,
        };
        let key = (srv.host.to_ascii_lowercase(), port);
        if seen.insert(key.clone()) {
            endpoints.push(key);
        }
    }

    if endpoints.is_empty() {
        tracing::warn!("No pingable (TCP) servers after filtering");
        return Ok(Vec::new());
    }
    tracing::info!(target: "ping", count = endpoints.len(), "Pinging {} unique endpoints", endpoints.len());

    if let Some(pb) = &progress_bar {
        pb.set_length(endpoints.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{bar:40.cyan/blue} {pos}/{len} [{elapsed_precise}] {msg}")
                .expect("valid template")
                .progress_chars("=> "),
        );
        pb.set_position(0);
        pb.set_message("Starting...");
    }

    // Ping concurrently with cap 50
    let mut results: Vec<(String, u16, PingResult)> = Vec::with_capacity(endpoints.len());
    let mut in_flight: FuturesOrdered<_> = FuturesOrdered::new();
    let mut endpoint_iter = endpoints.iter().peekable();
    let mut ok_count: u64 = 0;
    let mut fail_count: u64 = 0;

    while let Some((host, port)) = endpoint_iter.next() {
        let h = host.clone();
        let p = *port;

        in_flight.push_back(async move {
            let res = ping_endpoint(&h, p).await;
            (h, p, res)
        });

        // If at capacity or this is the last item, drain one result
        if (in_flight.len() >= PING_CONCURRENCY || endpoint_iter.peek().is_none())
            && let Some((h2, p2, res)) = in_flight.next().await
        {
            if matches!(
                res,
                PingResult::Tcp {
                    latency_ms: Some(_),
                    ..
                }
            ) {
                ok_count += 1;
            } else {
                fail_count += 1;
            }

            let ping_json = serde_json::to_string(&res).ok();
            let ping_ts = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .cast_signed(),
            );
            if let Some(json) = &ping_json {
                db.update_server_ping_by_hostport(&h2, &p2.to_string(), Some(json), ping_ts)
                    .await
                    .ok();
            }
            log_ping_result(&h2, p2, &res);
            if let Some(pb) = &progress_bar {
                pb.inc(1);
                pb.set_message(format!("{h2}:{p2} | OK: {ok_count}, FAIL: {fail_count}"));
            }
            results.push((h2, p2, res));
        }
    }

    // Drain remaining in-flight pings
    while let Some((h, p, res)) = in_flight.next().await {
        if matches!(
            res,
            PingResult::Tcp {
                latency_ms: Some(_),
                ..
            }
        ) {
            ok_count += 1;
        } else {
            fail_count += 1;
        }
        let ping_json = serde_json::to_string(&res).ok();
        let ping_ts = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .cast_signed(),
        );
        if let Some(json) = &ping_json {
            db.update_server_ping_by_hostport(&h, &p.to_string(), Some(json), ping_ts)
                .await
                .ok();
        }
        log_ping_result(&h, p, &res);
        if let Some(pb) = &progress_bar {
            pb.inc(1);
            pb.set_message(format!("{h}:{p} | OK: {ok_count}, FAIL: {fail_count}"));
        }
        results.push((h, p, res));
    }

    // Final status if progress bar was used
    if let Some(pb) = &progress_bar {
        pb.finish_with_message(format!("Done. OK: {ok_count}, FAIL: {fail_count}"));
    }

    Ok(results)
}

/// Log a single ping result via `tracing::info!(target: "ping")`.
fn log_ping_result(host: &str, port: u16, result: &PingResult) {
    match result {
        PingResult::Tcp {
            latency_ms: Some(lat),
            ..
        } => {
            tracing::info!(target: "ping", "{host}:{port} OK {lat:.1}ms");
        }
        PingResult::Tcp { error: Some(e), .. } => {
            tracing::info!(target: "ping", "{host}:{port} FAIL {e}");
        }
        PingResult::Tcp { .. } => {
            unreachable!("Should never be reached")
        }
    }
}
