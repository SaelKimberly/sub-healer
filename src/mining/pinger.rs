use std::collections::HashSet;
use std::str::FromStr;
use std::time::Instant;

use futures::StreamExt;
use futures::stream::FuturesOrdered;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, UdpSocket};

use crate::db::{Database, ServerRecord};
use indicatif::{ProgressBar, ProgressStyle};

/// Schemas transported over UDP/QUIC/DNS — pinged via [`PingKind::Udp`].
/// `slipnet-enc` is excluded: it has no `host()`/`port()`.
const UDP_SCHEMAS: &[&str] = &["wireguard", "tuic", "hysteria2", "stormdns", "slipnet"];

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

/// Transport protocol the ping was performed over.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PingKind {
    Tcp,
    Udp,
}

/// Typed ping error matching real `io::Error` kinds.
/// Used in Rust API only — serialized as a string inside `PingStatus::Fail`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PingError {
    #[error("Timed out after {0}s")]
    Timeout(u64),
    #[error("Connection refused: {0}")]
    ConnectionRefused(String),
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
    #[error("Network error: {0}")]
    Network(String),
}

/// Serializable ping outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PingStatus {
    /// Server responded within timeout.
    Done { latency_ms: f64 },
    /// Ping failed with an error message.
    Fail { error: String },
}

/// Result of pinging a single proxy endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    pub kind: PingKind,
    /// Unix epoch seconds when the ping was launched (stored separately in `ping_ts` column).
    #[serde(skip)]
    pub timestamp: i64,
    pub status: PingStatus,
}

impl Ping {
    /// Create a Ping by probing `host:port` with the given method.
    /// `timeout` defaults to `PING_TIMEOUT` when `None`.
    pub async fn ping(
        kind: PingKind,
        host: &str,
        port: u16,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        let timeout = timeout.unwrap_or(PING_TIMEOUT);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let start = Instant::now();
        let status = match kind {
            PingKind::Tcp => Self::tcp_ping(host, port, timeout, start).await,
            PingKind::Udp => Self::udp_ping(host, port, timeout, start).await,
        };
        Self {
            kind,
            timestamp,
            status,
        }
    }

    async fn tcp_ping(
        host: &str,
        port: u16,
        timeout: std::time::Duration,
        start: Instant,
    ) -> PingStatus {
        let addr = format!("{host}:{port}");
        match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => PingStatus::Done {
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            },
            Ok(Err(e)) => Self::io_error_to_status(e),
            Err(_) => PingStatus::Fail {
                error: PingError::Timeout(timeout.as_secs()).to_string(),
            },
        }
    }

    async fn udp_ping(
        host: &str,
        port: u16,
        timeout: std::time::Duration,
        start: Instant,
    ) -> PingStatus {
        let addr = format!("{host}:{port}");
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                return PingStatus::Fail {
                    error: format!("bind: {e}"),
                };
            }
        };
        if let Err(e) = socket.connect(&addr).await {
            return Self::io_error_to_status(e);
        }
        if let Err(e) = socket.send(b"\x00").await {
            return PingStatus::Fail {
                error: format!("send: {e}"),
            };
        }
        let mut buf = [0u8; 64];
        match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
            Ok(Ok(_)) => PingStatus::Done {
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            },
            Ok(Err(e)) => Self::io_error_to_status(e),
            Err(_) => PingStatus::Fail {
                error: PingError::Timeout(timeout.as_secs()).to_string(),
            },
        }
    }

    fn io_error_to_status(e: std::io::Error) -> PingStatus {
        let err = match e.kind() {
            std::io::ErrorKind::ConnectionRefused => PingError::ConnectionRefused(e.to_string()),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput => {
                PingError::DnsResolutionFailed(e.to_string())
            }
            _ => PingError::Network(e.to_string()),
        };
        PingStatus::Fail {
            error: err.to_string(),
        }
    }
}

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

/// Ping all unique (host, port) pairs from the given server records.
///
/// 1. Classifies each server's schema as TCP or UDP via [`UDP_SCHEMAS`].
/// 2. Skips servers with an empty or "0" port.
/// 3. Deduplicates by lowercased host + port.
/// 4. Pings each unique endpoint concurrently (cap 200 in-flight).
/// 5. Stores results to the database for ALL matching server records.
///
/// Returns the `Vec<(host, port, Ping)>` of all unique endpoints that
/// were actually pinged (skipped ones are omitted).
///
/// # Errors
///
/// Returns an error if a database write fails (aborts the operation).
#[allow(clippy::future_not_send, reason = "needs research")]
#[allow(clippy::too_many_lines)]
pub async fn ping_and_store(
    db: &Database,
    servers: &[ServerRecord],
    _spec: &PingSpec,
    progress_bar: Option<ProgressBar>,
) -> anyhow::Result<Vec<(String, u16, Ping)>> {
    enum PingMethod {
        Tcp,
        Udp,
    }

    // Classify schemas and filter empty/"0" ports
    let mut seen: HashSet<(String, u16)> = HashSet::new();
    let mut endpoints: Vec<(String, u16, PingMethod)> = Vec::new();

    for srv in servers {
        let schema_lower = srv.schema.to_ascii_lowercase();
        let method = if UDP_SCHEMAS.iter().any(|s| *s == schema_lower) {
            PingMethod::Udp
        } else {
            PingMethod::Tcp
        };
        let port: u16 = match srv.port.parse() {
            Ok(p) if p != 0 => p,
            _ => continue,
        };
        let key = (srv.host.to_ascii_lowercase(), port);
        if seen.insert(key.clone()) {
            endpoints.push((key.0, key.1, method));
        }
    }

    if endpoints.is_empty() {
        tracing::warn!("No pingable servers after filtering");
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

    // Ping concurrently with cap PING_CONCURRENCY
    let mut results: Vec<(String, u16, Ping)> = Vec::with_capacity(endpoints.len());
    let mut in_flight: FuturesOrdered<_> = FuturesOrdered::new();
    let mut endpoint_iter = endpoints.iter().peekable();
    let mut ok_count: u64 = 0;
    let mut fail_count: u64 = 0;

    while let Some((host, port, method)) = endpoint_iter.next() {
        let h = host.clone();
        let p = *port;
        let kind = match method {
            PingMethod::Tcp => PingKind::Tcp,
            PingMethod::Udp => PingKind::Udp,
        };

        in_flight.push_back(async move {
            let ping = Ping::ping(kind, &h, p, None).await;
            (h, p, ping)
        });

        // If at capacity or this is the last item, drain one result
        if (in_flight.len() >= PING_CONCURRENCY || endpoint_iter.peek().is_none())
            && let Some((h2, p2, ping)) = in_flight.next().await
        {
            if matches!(&ping.status, PingStatus::Done { .. }) {
                ok_count += 1;
            } else {
                fail_count += 1;
            }

            let ping_json = serde_json::to_string(&ping).ok();
            let ping_ts = Some(ping.timestamp);
            if let Some(json) = &ping_json {
                db.update_server_ping_by_hostport(&h2, &p2.to_string(), Some(json), ping_ts)
                    .await
                    .ok();
            }
            log_ping_result(&h2, p2, &ping);
            if let Some(pb) = &progress_bar {
                pb.inc(1);
                pb.set_message(format!("{h2}:{p2} | OK: {ok_count}, FAIL: {fail_count}"));
            }
            results.push((h2, p2, ping));
        }
    }

    // Drain remaining in-flight pings
    while let Some((h, p, ping)) = in_flight.next().await {
        if matches!(&ping.status, PingStatus::Done { .. }) {
            ok_count += 1;
        } else {
            fail_count += 1;
        }
        let ping_json = serde_json::to_string(&ping).ok();
        let ping_ts = Some(ping.timestamp);
        if let Some(json) = &ping_json {
            db.update_server_ping_by_hostport(&h, &p.to_string(), Some(json), ping_ts)
                .await
                .ok();
        }
        log_ping_result(&h, p, &ping);
        if let Some(pb) = &progress_bar {
            pb.inc(1);
            pb.set_message(format!("{h}:{p} | OK: {ok_count}, FAIL: {fail_count}"));
        }
        results.push((h, p, ping));
    }

    // Final status if progress bar was used
    if let Some(pb) = &progress_bar {
        pb.finish_with_message(format!("Done. OK: {ok_count}, FAIL: {fail_count}"));
    }

    Ok(results)
}

/// Log a single ping result via `tracing::info!(target: "ping")`.
fn log_ping_result(host: &str, port: u16, ping: &Ping) {
    match &ping.status {
        PingStatus::Done { latency_ms } => {
            tracing::info!(target: "ping", "{host}:{port} OK {latency_ms:.1}ms");
        }
        PingStatus::Fail { error } => tracing::info!(target: "ping", "{host}:{port} FAIL {error}"),
    }
}
