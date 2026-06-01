use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Context;

use chrono::{DateTime, Utc};
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use v2ray_heal::mining;
use v2ray_heal::mining::RawSourceItemBatch;
use v2ray_heal::urlx::{SchemeX, TinyText};

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

#[derive(Debug, clap::Subcommand)]
enum Commands {
    Stdin,
    Config {
        file: Option<PathBuf>,
        #[arg(long, conflicts_with = "upto",
              help = "Backfill Telegram channels for the last duration (e.g. '5h', '7d')")]
        last: Option<humantime::Duration>,
        #[arg(long, conflicts_with = "last",
              help = "Backfill Telegram channels up to this RFC 3339 datetime (e.g. '2026-06-01T00:00:00Z')")]
        upto: Option<String>,
    },
    Remote {
        url: Vec<url::Url>,
        #[arg(long, conflicts_with = "upto",
              help = "Backfill Telegram channels for the last duration (e.g. '5h', '7d')")]
        last: Option<humantime::Duration>,
        #[arg(long, conflicts_with = "last",
              help = "Backfill Telegram channels up to this RFC 3339 datetime (e.g. '2026-06-01T00:00:00Z')")]
        upto: Option<String>,
    },
    Local {
        file: Vec<PathBuf>,
    },
    Emit {
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
        #[arg(long, value_enum, help = "Scope of sources to pull before emitting")]
        pull: Option<PullScope>,
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
}

/// Pre-process a raw subscription payload into decoded/normalized text, then
/// extract raw URL strings using SchemeX::slice_input.
fn parse_to_raw_urls(data: &[u8]) -> Vec<String> {
    let text = v2ray_heal::preprocess_sub_data(data);
    text.lines()
        .flat_map(|line| {
            let s = line.trim_start();
            if s.starts_with('#') || s.starts_with("//") || s.is_empty() {
                Vec::new()
            } else {
                s.split("<br/>")
                    .flat_map(|segment| {
                        SchemeX::slice_input(segment)
                            .into_iter()
                            .map(|(_, url)| url.to_string())
                    })
                    .collect()
            }
        })
        .collect()
}

/// Parse the `--last` and `--upto` CLI flags into a [`mining::Backfill`] option.
///
/// # Errors
///
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
            let dt = chrono::DateTime::parse_from_rfc3339(&dt_str)
                .context("Invalid --upto datetime (expected RFC 3339, e.g. '2026-06-01T00:00:00Z')")?;
            Ok(Some(mining::Backfill::Upto(
                dt.with_timezone(&chrono::Utc),
            )))
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mp = indicatif::MultiProgress::new();

    let indicatif_writer: tracing_indicatif::IndicatifWriter =
        tracing_indicatif::IndicatifWriter::new(mp.clone());

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(indicatif_writer))
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(v2ray_heal::mining::UnparseableLayer::new())
        .try_init()
        .ok();

    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Config { file, last, upto }) => {
            let backfill = parse_backfill(last, upto)?;
            let config_path = file.unwrap_or(PathBuf::from("config.yaml"));
            let mut pipeline = mining::Pipeline::from_config(&config_path, &cli.db)?;
            pipeline.set_backfill(backfill);
            pipeline.set_progress_bar(make_progress_bar(&mp));
            let count = pipeline.run().await?;
            tracing::info!(count, "Mining pipeline completed");
        }
        Some(Commands::Stdin) => {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            tokio::io::stdin().read_to_end(&mut buf).await?;
            if buf.is_empty() {
                anyhow::bail!("No data received from stdin");
            }

            let source_url = url::Url::parse("stdin://local")?;
            let url_str = source_url.as_str().to_string();

            let mut pipeline = mining::Pipeline::new(&cli.db)?;
            pipeline.add_batch_source(&url_str);

            let raw_urls = parse_to_raw_urls(&buf);
            if raw_urls.is_empty() {
                tracing::warn!("No proxy URLs found in stdin data");
                return Ok(());
            }

            let source = pipeline
                .lookup_source(&url_str)
                .expect("source just registered");

            let batch = RawSourceItemBatch {
                source,
                timestamp: Utc::now(),
                raw_urls: raw_urls.into_boxed_slice(),
            };

            pipeline.set_progress_bar(make_progress_bar(&mp));
            pipeline.add_batch_raw(vec![batch]);
            let count = pipeline.run().await?;
            tracing::info!(count, "Stdin mining completed");
        }
        Some(Commands::Remote { url, last, upto }) => {
            let backfill = parse_backfill(last, upto)?;
            let mut pipeline = mining::Pipeline::new(&cli.db)?;
            for u in &url {
                pipeline.add_source(u.as_str());
            }
            pipeline.set_backfill(backfill);
            pipeline.set_progress_bar(make_progress_bar(&mp));
            pipeline.run().await?;
        }
        Some(Commands::Local { file }) => {
            if file.is_empty() {
                anyhow::bail!("No file paths provided");
            }

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

                let data = std::fs::read(&abs)
                    .with_context(|| format!("Failed to read file: {}", abs.display()))?;

                let raw_urls = parse_to_raw_urls(&data);
                if raw_urls.is_empty() {
                    continue;
                }

                let source = pipeline
                    .lookup_source(&url_str)
                    .expect("source just registered");

                batches.push(RawSourceItemBatch {
                    source,
                    timestamp: Utc::now(),
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
            tracing::info!(count, "Local file mining completed");
        }
        Some(Commands::Emit {
            protocol,
            min_first_seen_ts,
            min_last_seen_ts,
            pull,
        }) => {
            let mut pipeline = mining::Pipeline::new(&cli.db)?;

            if let Some(scope) = pull {
                let sources = pipeline.all_sources().await?;

                if sources.is_empty() {
                    tracing::warn!("--pull: no sources in database, nothing to fetch");
                } else {
                    let mut per_source_backfill: HashMap<TinyText, DateTime<Utc>> = HashMap::new();

                    for source in &sources {
                        let is_tg = url::Url::parse(&source.url)
                            .is_ok_and(|u| u.host_str() == Some("t.me"));
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

            use std::time::SystemTime;
            let unix_now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let min_first = min_first_seen_ts.map(|d| {
                let std_dur: std::time::Duration = d.into();
                unix_now.saturating_sub(std_dur.as_secs() as i64)
            });

            let min_last = min_last_seen_ts.map(|d| {
                let std_dur: std::time::Duration = d.into();
                unix_now.saturating_sub(std_dur.as_secs() as i64)
            });

            let protocol_filter = if protocol.is_empty() {
                None
            } else {
                Some(protocol.as_slice())
            };

            let output = pipeline
                .export(protocol_filter, min_first, min_last)
                .await?;
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
