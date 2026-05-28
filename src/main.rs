use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;

use chrono::{DateTime, Utc};
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use v2ray_heal::mining;
use v2ray_heal::proto_spec::ProtoSpec;
use v2ray_heal::urlx::TinyText;

fn is_telegram_url(url: &url::Url) -> bool {
    url.host_str() == Some("t.me")
}

fn is_telegram_url_str(url_str: &str) -> bool {
    url::Url::parse(url_str).is_ok_and(|u| u.host_str() == Some("t.me"))
}

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
    },
    Remote {
        url: Vec<url::Url>,
    },
    Local {
        file: Vec<PathBuf>,
    },
    Emit {
        #[arg(long, short)]
        protocol: Vec<String>,
        #[arg(long)]
        min_first_seen_ts: Option<humantime::Duration>,
        #[arg(long)]
        min_last_seen_ts: Option<humantime::Duration>,
        #[arg(long, default_missing_value = "all", num_args = 0..=1)]
        pull: Option<PullScope>,
    },
}

#[derive(Debug, clap::Parser)]
struct Cli {
    #[arg(global = true, default_value = "v2ray-heal.db", long)]
    db: PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(v2ray_heal::mining::UnparseableLayer::new())
        .try_init()
        .ok();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Config { file }) => {
            let config_path = file.unwrap_or(PathBuf::from("config.yaml"));
            mining::run_with_config(&config_path, &cli.db).await?;
        }
        Some(Commands::Stdin) => {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            tokio::io::stdin().read_to_end(&mut buf).await?;
            if buf.is_empty() {
                anyhow::bail!("No data received from stdin");
            }

            let conn = mining::open_db(&cli.db)?;
            let source_url = url::Url::parse("stdin://local")?;

            let mut registry = mining::SourceRegistry::new();
            registry.pre_populate("stdin://local", mining::SourceType::Other);
            registry.upsert_all(&conn)?;

            let lines = v2ray_heal::parse_sub(&source_url, &buf);
            let items = mining::lines_to_traced(
                &lines,
                &registry,
                "stdin://local",
                mining::get_current_timestamp(),
            );
            let count = mining::process_config_stream(futures::stream::iter(items), &conn).await?;
            tracing::info!(count, "Stdin mining completed");
        }
        Some(Commands::Remote { url }) => {
            let conn = mining::open_db(&cli.db)?;
            let client = mining::build_client()?;

            let mut registry = mining::SourceRegistry::new();
            for u in &url {
                if is_telegram_url(u) {
                    registry.add_telegram_channel(u.as_str());
                } else {
                    registry.add_subscription(u.as_str());
                }
            }

            let registry = Arc::new(registry);
            registry.run_pipeline(&client, &conn).await?;
        }
        Some(Commands::Local { file }) => {
            if file.is_empty() {
                anyhow::bail!("No file paths provided");
            }

            let conn = mining::open_db(&cli.db)?;
            let mut registry = mining::SourceRegistry::new();

            let mut resolved: Vec<(PathBuf, url::Url, String)> = Vec::new();
            for path in &file {
                let abs = std::fs::canonicalize(path)
                    .with_context(|| format!("Failed to resolve path: {}", path.display()))?;
                let source_url = url::Url::from_file_path(&abs).map_err(|()| {
                    anyhow::anyhow!("Cannot convert path to file URL: {}", abs.display())
                })?;
                let url_str = source_url.as_str().to_string();
                registry.pre_populate(&url_str, mining::SourceType::Other);
                resolved.push((abs, source_url, url_str));
            }
            registry.upsert_all(&conn)?;

            let ts = mining::get_current_timestamp();
            let mut items = Vec::new();
            for (abs_path, source_url, url_str) in &resolved {
                let data = std::fs::read(abs_path)
                    .with_context(|| format!("Failed to read file: {}", abs_path.display()))?;
                let lines = v2ray_heal::parse_sub(source_url, &data);
                let traced = mining::lines_to_traced(&lines, &registry, url_str, ts);
                items.extend(traced);
            }

            let count = mining::process_config_stream(futures::stream::iter(items), &conn).await?;
            tracing::info!(count, "Local file mining completed");
        }
        Some(Commands::Emit {
            protocol,
            min_first_seen_ts,
            min_last_seen_ts,
            pull,
        }) => {
            let conn = mining::open_db(&cli.db)?;
            if let Some(scope) = pull {
                let sources = v2ray_heal::db::query_all_sources(&conn)
                    .context("Failed to query sources for --pull")?;

                if sources.is_empty() {
                    tracing::warn!("--pull: no sources in database, nothing to fetch");
                } else {
                    let client = mining::build_client()?;
                    let mut registry = mining::SourceRegistry::new();
                    let mut per_source_backfill: HashMap<TinyText, DateTime<Utc>> = HashMap::new();

                    for source in &sources {
                        let is_tg = is_telegram_url_str(&source.url);
                        match scope {
                            PullScope::Sub => {
                                if !is_tg {
                                    registry.add_subscription(&source.url);
                                }
                            }
                            PullScope::Tg => {
                                if is_tg
                                    && let Some(ts) =
                                        v2ray_heal::db::query_latest_ts_for_source(&conn, source.id)
                                            .context("Failed to query latest ts for source")?
                                {
                                    registry.add_telegram_channel(&source.url);
                                    per_source_backfill.insert(
                                        TinyText::from(&source.url),
                                        DateTime::from_timestamp(ts, 0).unwrap(),
                                    );
                                }
                            }
                            PullScope::All => {
                                if is_tg {
                                    if let Some(ts) =
                                        v2ray_heal::db::query_latest_ts_for_source(&conn, source.id)
                                            .context("Failed to query latest ts for source")?
                                    {
                                        registry.add_telegram_channel(&source.url);
                                        per_source_backfill.insert(
                                            TinyText::from(&source.url),
                                            DateTime::from_timestamp(ts, 0).unwrap(),
                                        );
                                    }
                                } else {
                                    registry.add_subscription(&source.url);
                                }
                            }
                        }
                    }
                    registry.upsert_all(&conn)?;

                    let fetcher = if per_source_backfill.is_empty() {
                        mining::LiveFetcher::default()
                    } else {
                        mining::LiveFetcher {
                            tg_config: mining::TgConfig {
                                per_source_backfill,
                                ..Default::default()
                            },
                        }
                    };
                    Arc::new(registry)
                        .run_pipeline_with(&client, &conn, fetcher)
                        .await?;
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

            let servers =
                v2ray_heal::db::query_servers_filtered(&conn, protocol_filter, min_first, min_last)
                    .context("Failed to query servers")?;

            let server_ids: Vec<i64> = servers.iter().map(|s| s.id).collect();
            let sources = v2ray_heal::db::query_sources_by_server_ids(&conn, &server_ids)
                .context("Failed to query sources")?;

            println!("# v2ray-heal generated at {}", Utc::now().to_rfc3339());
            if !sources.is_empty() {
                println!("# Sources:");
                for src in &sources {
                    println!("#   - {}", src.url);
                }
            }
            println!();

            for server in &servers {
                let config: v2ray_heal::proto_spec::ProtocolConfig =
                    match serde_json::from_str(&server.raw_config) {
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
                    Ok(url) => println!("{url}"),
                    Err(e) => {
                        tracing::warn!(
                            server_id = server.id,
                            error = %e,
                            "Failed to reconstruct URL"
                        );
                    }
                }
            }
        }
        None => {
            let conn = mining::open_db(&cli.db)?;
            let client = mining::build_client()?;

            let sources =
                v2ray_heal::db::query_all_sources(&conn).context("Failed to query sources")?;

            if sources.is_empty() {
                tracing::warn!("No sources found in database");
                return Ok(());
            }

            let mut registry = mining::SourceRegistry::new();
            for source in &sources {
                if is_telegram_url_str(&source.url) {
                    registry.add_telegram_channel(&source.url);
                } else {
                    registry.add_subscription(&source.url);
                }
            }
            registry.upsert_all(&conn)?;
            Arc::new(registry).run_pipeline(&client, &conn).await?;
        }
    }

    Ok(())
}
