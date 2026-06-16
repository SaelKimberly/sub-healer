use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::Context;
use rusqlite::params;

use chrono::{DateTime, Utc};
use clap::Parser;
use indicatif::ProgressBar;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use v2ray_heal::mining;
use v2ray_heal::mining::PingSpec;
use v2ray_heal::mining::RawSourceItemBatch;
use v2ray_heal::proto_spec::ProtoSpec;
use v2ray_heal::urlx::TinyText;

/// Scope of sources to re-fetch when using `--pull` on emit
#[derive(clap::ValueEnum, Clone, Debug)]
enum PullScope {
    /// Only subscription (HTTP) sources
    Sub,
    /// Only Telegram channels
    Tg,
    /// Both subscription and Telegram sources
    All,
}
/// Whitelist flag filter for `--wl`.
#[derive(clap::ValueEnum, Clone, Debug)]
enum WhitelistFlagFilter {
    Sni,
    Ip,
    Cidr,
}

#[derive(Debug, clap::Args)]
pub(crate) struct EmitFilterArgs {
    #[arg(long, value_delimiter = ',', help = "Filter by protocol (repeatable)")]
    protocol: Vec<String>,
    #[arg(
        long,
        help = "Minimum first-seen timestamp (humantime duration, e.g. '7d', '30m')"
    )]
    min_first_seen_ts: Option<humantime::Duration>,
    #[arg(
        long,
        help = "Minimum last-seen timestamp (humantime duration, e.g. '7d', '30m')"
    )]
    min_last_seen_ts: Option<humantime::Duration>,
    /// Re-check all servers against whitelist files and update their flags
    #[arg(long)]
    recheck_whitelist: bool,
    /// Only recheck servers whose flags_ts is older than this duration (e.g. '7d').
    /// 0 (or omitted) = recheck all. Only meaningful with --recheck-whitelist.
    #[arg(long)]
    recheck_max_age: Option<humantime::Duration>,
    /// Filter output by whitelist flag type: sni, ip, cidr (repeatable/comma-separated)
    #[arg(long, value_delimiter = ',')]
    wl: Vec<WhitelistFlagFilter>,
}

/// Emit-on-mine options used by mining subcommands (Stdin, Config, Remote, Local).
#[derive(Debug, clap::Args)]
struct EmitOnMine {
    /// Enable emit-after-mine: produce filtered config output after loading
    #[arg(long, help = "Emit filtered configs after loading into database")]
    emit: bool,
    #[command(flatten)]
    filters: EmitFilterArgs,
    /// Ping servers after emit/mine and optionally filter by latency.
    /// Bare `--ping` or `--ping ok` = check reachability only.
    /// `--ping 15ms` = only emit servers with RTT ≤ 15ms.
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "ok",
        value_parser = parse_ping_spec,
        help = "Ping servers after processing: 'ok' or a duration like '15ms'"
    )]
    ping: Option<PingSpec>,
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    Stdin {
        #[command(flatten)]
        emit_opts: EmitOnMine,
    },
    Config {
        file: Option<PathBuf>,
        #[arg(
            long,
            conflicts_with = "upto",
            help = "Backfill Telegram channels for the last duration (e.g. '5h', '7d')"
        )]
        last: Option<humantime::Duration>,
        #[arg(
            long,
            conflicts_with = "last",
            help = "Backfill Telegram channels up to this RFC 3339 datetime (e.g. '2026-06-01T00:00:00Z')"
        )]
        upto: Option<String>,
        #[command(flatten)]
        emit_opts: EmitOnMine,
    },
    Remote {
        url: Vec<url::Url>,
        #[arg(
            long,
            conflicts_with = "upto",
            help = "Backfill Telegram channels for the last duration (e.g. '5h', '7d')"
        )]
        last: Option<humantime::Duration>,
        #[arg(
            long,
            conflicts_with = "last",
            help = "Backfill Telegram channels up to this RFC 3339 datetime (e.g. '2026-06-01T00:00:00Z')"
        )]
        upto: Option<String>,
        #[command(flatten)]
        emit_opts: EmitOnMine,
    },
    Local {
        file: Vec<PathBuf>,
        #[command(flatten)]
        emit_opts: EmitOnMine,
    },
    Emit {
        #[command(flatten)]
        filters: EmitFilterArgs,
        #[arg(long, value_enum, help = "Scope of sources to pull before emitting")]
        pull: Option<PullScope>,
        /// Ping servers after pull/emit and optionally filter by latency.
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "ok",
            value_parser = parse_ping_spec,
            help = "Ping servers after processing: 'ok' or a duration like '15ms'"
        )]
        ping: Option<PingSpec>,
    },
    /// Ping servers in the database to check reachability and latency.
    Ping {
        #[command(flatten)]
        filters: EmitFilterArgs,
    },
}

#[derive(Debug, clap::Parser)]
#[command(name = "v2ray-heal")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    #[arg(
        long,
        default_value = "v2ray-heal.db",
        help = "Path to the SQLite database"
    )]
    db: PathBuf,
    /// Enable unparseable log file [default: unparseable.ndjson when flag is set]
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "unparseable.ndjson",
        require_equals = true,
    )]
    unparseable_log: Option<PathBuf>,
    /// Path to SNI whitelist file
    #[arg(long, default_value = "whitelist.txt")]
    whitelist_sni: PathBuf,
    /// Path to IP whitelist file
    #[arg(long, default_value = "ipwhitelist.txt")]
    whitelist_ip: PathBuf,
    /// Path to CIDR whitelist file
    #[arg(long, default_value = "cidrwhitelist.txt")]
    whitelist_cidr: PathBuf,
}

/// Parse the `--last` and `--upto` CLI flags into a [`mining::Backfill`] option.
///
/// # Errors
///
/// Parse the `--ping` CLI value into a [`PingSpec`].
///
/// # Errors
///
/// Returns a string error if the value cannot be parsed.
fn parse_ping_spec(s: &str) -> Result<PingSpec, String> {
    s.parse()
}

/// Returns an error if `--upto` cannot be parsed as RFC 3339 or if the duration is out of range.
fn parse_backfill(
    last: Option<humantime::Duration>,
    upto: Option<String>,
) -> anyhow::Result<Option<mining::Backfill>> {
    match (last, upto) {
        (Some(dur), None) => {
            let std_dur: std::time::Duration = dur.into();
            let delta =
                chrono::TimeDelta::from_std(std_dur).context("Backfill duration out of range")?;
            Ok(Some(mining::Backfill::Last(delta)))
        }
        (None, Some(dt_str)) => {
            let dt = chrono::DateTime::parse_from_rfc3339(&dt_str).context(
                "Invalid --upto datetime (expected RFC 3339, e.g. '2026-06-01T00:00:00Z')",
            )?;
            Ok(Some(mining::Backfill::Upto(dt.with_timezone(&chrono::Utc))))
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => unreachable!("clap enforces mutual exclusivity"),
    }
}

/// Create a spinner progress bar (managed by MultiProgress) showing URL count and elapsed time.
fn make_progress_bar(mp: &indicatif::MultiProgress) -> indicatif::ProgressBar {
    let pb = mp.add(indicatif::ProgressBar::new_spinner());
    pb.set_style(
        indicatif::ProgressStyle::default_spinner()
            .template("{spinner:.green} {pos} URLs processed [{elapsed_precise}]")
            .unwrap(),
    );
    pb
}

/// Reconstruct and print server URLs from pre-queried [`ServerRecord`]s.
/// Used by both `emit_after_mine` and the `Emit` subcommand when ping filtering
/// has already narrowed the server set.
async fn reconstruct_servers_to_stdout(
    pipeline: &mining::Pipeline,
    servers: &[v2ray_heal::db::models::ServerRecord],
) -> anyhow::Result<()> {
    use chrono::Utc;
    use std::fmt::Write;

    let mut source_ids: Vec<i64> = servers.iter().map(|s| s.first_seen_source_id).collect();
    let sources = if source_ids.is_empty() {
        Vec::new()
    } else {
        source_ids.sort_unstable();
        source_ids.dedup();
        pipeline
            .db()
            .query_sources_by_ids(&source_ids)
            .await
            .context("Failed to query sources")?
    };

    let mut output = String::new();
    let _ = writeln!(
        output,
        "# v2ray-heal generated at {}",
        Utc::now().to_rfc3339()
    );
    if !sources.is_empty() {
        output.push_str("# Sources:\n");
        for src in &sources {
            let _ = writeln!(output, "#   - {}", src.url);
        }
    }
    output.push('\n');

    for server in servers {
        let mut bytes = server.raw_config.as_bytes().to_vec();
        let config: v2ray_heal::proto_spec::ProtocolConfig = match simd_json::from_slice(&mut bytes)
        {
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
                let _ = writeln!(output, "{url}");
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

    print!("{output}");
    Ok(())
}

/// If `opts.emit` is set or `opts.ping` is set, query servers, optionally ping,
/// then emit filtered results.
async fn emit_after_mine(pipeline: &mining::Pipeline, opts: &EmitOnMine) -> anyhow::Result<()> {
    if !opts.emit && opts.ping.is_none() {
        return Ok(());
    }

    // Re-check whitelist flags if requested
    if opts.filters.recheck_whitelist {
        let max_age = opts.filters.recheck_max_age.map(|d| {
            let std_dur: std::time::Duration = d.into();
            chrono::Duration::from_std(std_dur).unwrap()
        });
        let n = recheck_whitelist(pipeline, max_age).await?;
        tracing::info!(count = n, "Rechecked whitelist flags");
    }

    let unix_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let min_first = opts.filters.min_first_seen_ts.map(|d| {
        let std_dur: std::time::Duration = d.into();
        unix_now.saturating_sub(std_dur.as_secs() as i64)
    });

    let min_last = opts.filters.min_last_seen_ts.map(|d| {
        let std_dur: std::time::Duration = d.into();
        unix_now.saturating_sub(std_dur.as_secs() as i64)
    });

    let protocol_filter = if opts.filters.protocol.is_empty() {
        None
    } else {
        Some(opts.filters.protocol.as_slice())
    };

    let wl_mask: u8 = opts.filters.wl.iter().fold(0u8, |mask, f| {
        mask | match f {
            WhitelistFlagFilter::Sni => v2ray_heal::whitelist::SNI_WHITELISTED,
            WhitelistFlagFilter::Ip => v2ray_heal::whitelist::IP_WHITELISTED,
            WhitelistFlagFilter::Cidr => v2ray_heal::whitelist::CIDR_WHITELISTED,
        }
    });

    // Query servers directly instead of going through pipeline.export()
    let db = pipeline.db();
    let mask = if wl_mask == 0 { None } else { Some(wl_mask) };
    let servers = db
        .query_servers_filtered(protocol_filter, min_first, min_last, mask)
        .await?;

    // Apply ping filter if specified
    let servers: Vec<v2ray_heal::db::models::ServerRecord> = if let Some(spec) = &opts.ping {
        let deduped = v2ray_heal::mining::ping_and_store(db, &servers, spec, None).await?;
        let reachable: HashSet<(String, u16)> = deduped
            .iter()
            .filter(|(_, _, r)| match r {
                v2ray_heal::mining::PingResult::Tcp {
                    latency_ms: Some(lat),
                    ..
                } => match spec {
                    PingSpec::Ok => true,
                    PingSpec::Threshold(dur) => *lat <= dur.as_secs_f64() * 1000.0,
                },
                _ => false,
            })
            .map(|(h, p, _)| (h.to_lowercase(), *p))
            .collect();
        servers
            .into_iter()
            .filter(|s| {
                let port: u16 = match s.port.parse() {
                    Ok(p) if p != 0 => p,
                    _ => return false,
                };
                reachable.contains(&(s.host.to_lowercase(), port))
            })
            .collect()
    } else {
        servers
    };

    if !opts.emit {
        // Ping-only mode: results were stored to DB, nothing to print as URLs
        return Ok(());
    }

    // Reconstruct and print
    reconstruct_servers_to_stdout(pipeline, &servers).await?;
    Ok(())
}

/// Re-check whitelist flags for all servers whose `flags_ts` is older than `max_age`
/// (or never checked). Updates the database in-place.
/// Helper: convert a SQLite row to `ServerRecord`.
fn srv_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<v2ray_heal::db::models::ServerRecord> {
    use v2ray_heal::db::models::ServerRecord;
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
        ping: row.get(13)?,
        ping_ts: row.get(14)?,
    })
}

async fn recheck_whitelist(
    pipeline: &mining::Pipeline,
    max_age: Option<chrono::Duration>,
) -> anyhow::Result<usize> {
    use anyhow::Context;
    use chrono::Utc;
    use v2ray_heal::db::models::ServerRecord;

    let checker =
        mining::whitelist().context("Whitelist not initialized — use --whitelist-* flags")?;
    let now = Utc::now().timestamp();

    let servers = pipeline
        .db()
        .with_conn_read(|conn| -> rusqlite::Result<Vec<ServerRecord>> {
            let (sql, param): (&str, Box<dyn rusqlite::types::ToSql>) = if let Some(max) = max_age {
                let cut_off = now.saturating_sub(max.num_seconds());
                (
                    "SELECT id, schema, host, port, transport, security, remarks, \
                         raw_config, first_seen_ts, first_seen_source_id, sig, flags, flags_ts, ping, ping_ts \
                         FROM servers WHERE flags_ts < ?1 OR flags_ts = 0",
                    Box::new(cut_off) as Box<dyn rusqlite::types::ToSql>,
                )
            } else {
                (
                    "SELECT id, schema, host, port, transport, security, remarks, \
                         raw_config, first_seen_ts, first_seen_source_id, sig, flags, flags_ts, ping, ping_ts \
                         FROM servers",
                    Box::new(0i64) as Box<dyn rusqlite::types::ToSql>,
                )
            };
            let mut stmt = conn.prepare_cached(sql)?;
            let rows: rusqlite::Result<Vec<ServerRecord>> = if max_age.is_some() {
                stmt.query_map([&*param], srv_from_row)?.collect()
            } else {
                stmt.query_map([], srv_from_row)?.collect()
            };
            rows
        })
        .await;

    let servers = servers?;
    let mut update_count = 0usize;

    let _ = pipeline
        .db()
        .with_conn(|conn| -> anyhow::Result<()> {
            let mut stmt =
                conn.prepare_cached("UPDATE servers SET flags = ?1, flags_ts = ?2 WHERE id = ?3")?;
            for server in &servers {
                let mut bytes = server.raw_config.as_bytes().to_vec();
                let config: v2ray_heal::proto_spec::ProtocolConfig =
                    match simd_json::from_slice(&mut bytes) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(server_id = server.id, error = %e, "deser failed");
                            continue;
                        }
                    };
                let flags = checker.check_config(&config);
                stmt.execute(params![flags as i64, now, server.id])?;
                update_count += 1;
            }
            Ok(())
        })
        .await;

    Ok(update_count)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mp = indicatif::MultiProgress::new();

    let indicatif_writer: tracing_indicatif::IndicatifWriter =
        tracing_indicatif::IndicatifWriter::new(mp.clone());
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(indicatif_writer))
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(v2ray_heal::mining::UnparseableLayer::new(
            cli.unparseable_log.clone(),
        ))
        .try_init()
        .ok();
    // Initialize global whitelist checker (graceful if files missing)
    let _ = mining::init_whitelist(&cli.whitelist_sni, &cli.whitelist_ip, &cli.whitelist_cidr)?;

    match cli.command {
        Some(Commands::Config {
            file,
            last,
            upto,
            emit_opts,
        }) => {
            let backfill = parse_backfill(last, upto)?;
            let config_path = file.unwrap_or(PathBuf::from("config.yaml"));
            let mut pipeline = mining::Pipeline::from_config(&config_path, &cli.db)?;
            pipeline.set_backfill(backfill);
            pipeline.set_progress_bar(make_progress_bar(&mp));
            let count = pipeline.run().await?;
            emit_after_mine(&pipeline, &emit_opts).await?;
            tracing::info!(count, "Mining pipeline completed");
        }
        Some(Commands::Stdin { emit_opts }) => {
            use tokio::io::AsyncReadExt;
            let source_url = url::Url::parse("stdin://local")?;
            let url_str = source_url.as_str().to_string();

            let mut pipeline = mining::Pipeline::new(&cli.db)?;
            pipeline.add_batch_source(&url_str);
            let source = pipeline
                .lookup_source(&url_str)
                .expect("source just registered");

            let ts = Utc::now();
            let mut decoder = v2ray_heal::decoder::StreamingDecoder::new();
            let mut raw_urls = Vec::new();
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 65536];
            let mut has_data = false;

            loop {
                let n = stdin.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                has_data = true;
                for url in decoder.feed(&buf[..n])? {
                    raw_urls.push(url);
                }
            }

            if !has_data {
                anyhow::bail!("No data received from stdin");
            }

            for url in decoder.finalize()? {
                raw_urls.push(url);
            }

            if raw_urls.is_empty() {
                tracing::warn!("No proxy URLs found in stdin data");
                return Ok(());
            }

            let batch = RawSourceItemBatch {
                source,
                timestamp: ts,
                raw_urls: raw_urls.into_boxed_slice(),
            };

            pipeline.set_progress_bar(make_progress_bar(&mp));
            pipeline.add_batch_raw(vec![batch]);
            let count = pipeline.run().await?;
            emit_after_mine(&pipeline, &emit_opts).await?;
            tracing::info!(count, "Stdin mining completed");
        }
        Some(Commands::Remote {
            url,
            last,
            upto,
            emit_opts,
        }) => {
            let backfill = parse_backfill(last, upto)?;
            let mut pipeline = mining::Pipeline::new(&cli.db)?;
            for u in &url {
                pipeline.add_source(u.as_str());
            }
            pipeline.set_backfill(backfill);
            pipeline.set_progress_bar(make_progress_bar(&mp));
            pipeline.run().await?;
            emit_after_mine(&pipeline, &emit_opts).await?;
        }

        Some(Commands::Local { file, emit_opts }) => {
            if file.is_empty() {
                anyhow::bail!("No file paths provided");
            }
            use tokio::io::AsyncReadExt;
            let mut pipeline = mining::Pipeline::new(&cli.db)?;
            let mut batches = Vec::new();

            for path in &file {
                let abs = std::fs::canonicalize(path)
                    .with_context(|| format!("Failed to resolve path: {}", path.display()))?;
                let source_url = url::Url::from_file_path(&abs).map_err(|()| {
                    anyhow::anyhow!("Cannot convert path to file URL: {}", abs.display())
                })?;
                let url_str = source_url.as_str().to_string();
                pipeline.add_batch_source(&url_str);

                let source = pipeline
                    .lookup_source(&url_str)
                    .expect("source just registered");
                let ts = Utc::now();
                let mut file = tokio::fs::File::open(&abs)
                    .await
                    .with_context(|| format!("Failed to read file: {}", abs.display()))?;
                let mut decoder = v2ray_heal::decoder::StreamingDecoder::new();
                let mut raw_urls = Vec::new();
                let mut buf = vec![0u8; 65536];

                loop {
                    let n = file.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    for url in decoder.feed(&buf[..n])? {
                        raw_urls.push(url);
                    }
                }

                for url in decoder.finalize()? {
                    raw_urls.push(url);
                }

                if raw_urls.is_empty() {
                    continue;
                }

                batches.push(RawSourceItemBatch {
                    source,
                    timestamp: ts,
                    raw_urls: raw_urls.into_boxed_slice(),
                });
            }

            if batches.is_empty() {
                tracing::warn!("No proxy URLs found in any file");
                return Ok(());
            }
            pipeline.set_progress_bar(make_progress_bar(&mp));
            pipeline.add_batch_raw(batches);
            let count = pipeline.run().await?;
            emit_after_mine(&pipeline, &emit_opts).await?;
            tracing::info!(count, "Local file mining completed");
        }

        Some(Commands::Emit {
            filters,
            pull,
            ping,
        }) => {
            let mut pipeline = mining::Pipeline::new(&cli.db)?;

            if let Some(scope) = pull {
                let sources = pipeline.all_sources().await?;

                if sources.is_empty() {
                    tracing::warn!("--pull: no sources in database, nothing to fetch");
                } else {
                    let mut per_source_backfill: HashMap<TinyText, DateTime<Utc>> = HashMap::new();

                    for source in &sources {
                        let is_tg = source.url.starts_with("https://t.me/")
                            || source.url.starts_with("http://t.me/");
                        match scope {
                            PullScope::Sub => {
                                if !is_tg {
                                    pipeline.add_source(&source.url);
                                }
                            }
                            PullScope::Tg => {
                                if is_tg {
                                    let ts = pipeline
                                        .db()
                                        .query_latest_ts_for_source(source.id)
                                        .await
                                        .context("Failed to query latest ts for source")?;
                                    if let Some(ts) = ts {
                                        pipeline.add_source(&source.url);
                                        per_source_backfill.insert(
                                            TinyText::from(&source.url),
                                            DateTime::from_timestamp(ts, 0).unwrap(),
                                        );
                                    }
                                }
                            }
                            PullScope::All => {
                                if is_tg {
                                    let ts = pipeline
                                        .db()
                                        .query_latest_ts_for_source(source.id)
                                        .await
                                        .context("Failed to query latest ts for source")?;
                                    if let Some(ts) = ts {
                                        pipeline.add_source(&source.url);
                                        per_source_backfill.insert(
                                            TinyText::from(&source.url),
                                            DateTime::from_timestamp(ts, 0).unwrap(),
                                        );
                                    }
                                } else {
                                    pipeline.add_source(&source.url);
                                }
                            }
                        }
                    }

                    pipeline.set_progress_bar(make_progress_bar(&mp));
                    if !per_source_backfill.is_empty() {
                        pipeline.set_per_source_backfill(per_source_backfill);
                    }
                    pipeline.run().await?;
                }
            }
            // Re-check whitelist flags if requested
            if filters.recheck_whitelist {
                let max_age = filters.recheck_max_age.map(|d| {
                    let std_dur: std::time::Duration = d.into();
                    chrono::Duration::from_std(std_dur).unwrap()
                });
                let n = recheck_whitelist(&pipeline, max_age).await?;
                tracing::info!(count = n, "Rechecked whitelist flags");
            }

            use std::time::SystemTime;
            let unix_now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let min_first = filters.min_first_seen_ts.map(|d| {
                let std_dur: std::time::Duration = d.into();
                unix_now.saturating_sub(std_dur.as_secs() as i64)
            });

            let min_last = filters.min_last_seen_ts.map(|d| {
                let std_dur: std::time::Duration = d.into();
                unix_now.saturating_sub(std_dur.as_secs() as i64)
            });

            let protocol_filter = if filters.protocol.is_empty() {
                None
            } else {
                Some(filters.protocol.as_slice())
            };

            let wl_mask: u8 = filters.wl.iter().fold(0u8, |mask, f| {
                mask | match f {
                    WhitelistFlagFilter::Sni => v2ray_heal::whitelist::SNI_WHITELISTED,
                    WhitelistFlagFilter::Ip => v2ray_heal::whitelist::IP_WHITELISTED,
                    WhitelistFlagFilter::Cidr => v2ray_heal::whitelist::CIDR_WHITELISTED,
                }
            });

            let mask = if wl_mask == 0 { None } else { Some(wl_mask) };
            let servers = pipeline
                .db()
                .query_servers_filtered(protocol_filter, min_first, min_last, mask)
                .await
                .context("Failed to query servers")?;

            // Apply ping filter if specified (same logic as emit_after_mine)
            let servers: Vec<v2ray_heal::db::models::ServerRecord> = if let Some(spec) = &ping {
                let db = pipeline.db();
                let deduped = v2ray_heal::mining::ping_and_store(db, &servers, spec, None).await?;
                let reachable: HashSet<(String, u16)> = deduped
                    .iter()
                    .filter(|(_, _, r)| match r {
                        v2ray_heal::mining::PingResult::Tcp {
                            latency_ms: Some(lat),
                            ..
                        } => match spec {
                            PingSpec::Ok => true,
                            PingSpec::Threshold(dur) => *lat <= dur.as_secs_f64() * 1000.0,
                        },
                        _ => false,
                    })
                    .map(|(h, p, _)| (h.to_lowercase(), *p))
                    .collect();
                servers
                    .into_iter()
                    .filter(|s| {
                        let port: u16 = match s.port.parse() {
                            Ok(p) if p != 0 => p,
                            _ => return false,
                        };
                        reachable.contains(&(s.host.to_lowercase(), port))
                    })
                    .collect()
            } else {
                servers
            };

            reconstruct_servers_to_stdout(&pipeline, &servers).await?;
        }
        Some(Commands::Ping { filters }) => {
            use std::time::SystemTime;

            let pipeline = mining::Pipeline::new(&cli.db)?;
            let unix_now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let min_first = filters.min_first_seen_ts.map(|d| {
                let std_dur: std::time::Duration = d.into();
                unix_now.saturating_sub(std_dur.as_secs() as i64)
            });

            let min_last = filters.min_last_seen_ts.map(|d| {
                let std_dur: std::time::Duration = d.into();
                unix_now.saturating_sub(std_dur.as_secs() as i64)
            });

            let protocol_filter = if filters.protocol.is_empty() {
                None
            } else {
                Some(filters.protocol.as_slice())
            };
            use std::fmt::Write;
            let wl_mask: u8 = filters.wl.iter().fold(0u8, |mask, f| {
                mask | match f {
                    WhitelistFlagFilter::Sni => v2ray_heal::whitelist::SNI_WHITELISTED,
                    WhitelistFlagFilter::Ip => v2ray_heal::whitelist::IP_WHITELISTED,
                    WhitelistFlagFilter::Cidr => v2ray_heal::whitelist::CIDR_WHITELISTED,
                }
            });

            let mask = if wl_mask == 0 { None } else { Some(wl_mask) };
            let db = pipeline.db();
            let servers = db
                .query_servers_filtered(protocol_filter, min_first, min_last, mask)
                .await?;

            if servers.is_empty() {
                tracing::warn!("No servers in database matching filters");
                return Ok(());
            }
            // Create progress bar for ping progress
            let pb = mp.add(ProgressBar::new(0));
            let results =
                v2ray_heal::mining::ping_and_store(db, &servers, &PingSpec::Ok, Some(pb)).await?;

            // Print results table
            let mut output = String::new();
            // Count successful vs failed
            let (ok, fail): (Vec<_>, Vec<_>) =
                results.iter().partition::<Vec<_>, _>(|(_, _, r)| {
                    matches!(
                        r,
                        v2ray_heal::mining::PingResult::Tcp {
                            latency_ms: Some(_),
                            ..
                        }
                    )
                });

            output.push_str("# Ping results\n");
            for (host, port, r) in &results {
                let status = match r {
                    v2ray_heal::mining::PingResult::Tcp {
                        latency_ms: Some(lat),
                        ..
                    } => format!("ok {:.1}ms", lat),
                    v2ray_heal::mining::PingResult::Tcp { error: Some(e), .. } => {
                        format!("fail {e}")
                    }
                    _ => "unknown".into(),
                };
                let _ = writeln!(output, "{host}:{port} {status}");
            }
            output.push_str(&format!(
                "\n{} ok, {} failed, {} total\n",
                ok.len(),
                fail.len(),
                results.len()
            ));
            print!("{output}");
        }
        None => {
            let pipeline = mining::Pipeline::new(&cli.db)?;

            let sources = pipeline.all_sources().await?;
            if sources.is_empty() {
                tracing::warn!("No sources found in database");
                return Ok(());
            }

            let mut pipeline = pipeline;
            for source in &sources {
                pipeline.add_source(&source.url);
            }
            pipeline.set_progress_bar(make_progress_bar(&mp));
            pipeline.run().await?;
        }
    }

    Ok(())
}
