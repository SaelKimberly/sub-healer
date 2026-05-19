use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use futures::StreamExt;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use v2ray_heal::mining;

fn is_telegram_url(url: &url::Url) -> bool {
    url.host_str().map_or(false, |h| h == "t.me")
}

fn extract_channel_name(url: &url::Url) -> Option<String> {
    let path = url.path().trim_start_matches('/');
    let channel = path.rsplit_once('/').map_or(path, |(_, name)| name);
    if channel.is_empty() { None } else { Some(channel.to_string()) }
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
}

#[derive(Debug, clap::Parser)]
struct Cli {
    #[arg(global = true, default_value = "v2ray-heal.db", long)]
    db: PathBuf,
    #[command(subcommand)]
    command: Commands,
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
        Commands::Config { file } => {
            let config_path = file.unwrap_or(PathBuf::from("config.yaml"));
            mining::run_with_config(&config_path, &cli.db).await?;
        }
        Commands::Stdin => {
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

            let source = registry.lookup("stdin://local").unwrap();
            let lines = v2ray_heal::parse_sub(&source_url, &buf);
            let ts = mining::get_current_timestamp();
            let count = mining::process_sub_lines(&lines, &source, &conn, "stdin", ts)?;
            tracing::info!(count, "Stdin mining completed");
        }
        Commands::Remote { url } => {
            let conn = mining::open_db(&cli.db)?;
            let client = mining::build_client()?;

            let mut tg_urls = Vec::new();
            let mut sub_urls = Vec::new();
            for u in url {
                if is_telegram_url(&u) {
                    tg_urls.push(u);
                } else {
                    sub_urls.push(u);
                }
            }

            if !tg_urls.is_empty() {
                let mut registry = mining::SourceRegistry::new();
                let mut channel_names = Vec::new();
                for u in &tg_urls {
                    let Some(name) = extract_channel_name(u) else {
                        tracing::error!(url = %u, "Cannot extract channel name from Telegram URL");
                        continue;
                    };
                    registry.pre_populate(&name, mining::SourceType::Telegram);
                    channel_names.push(name);
                }
                registry.upsert_all(&conn)?;

                let tg_stream = mining::telegram::fetch_tg_channels(
                    client.clone(),
                    1,
                    channel_names.into_iter(),
                    Duration::from_secs(30),
                    None,
                );

                let mut tg_count = 0usize;
                tokio::pin!(tg_stream);
                while let Some(msg) = tg_stream.next().await {
                    let Some(source) = registry.lookup(&msg.source_url) else {
                        tracing::warn!(url = %msg.source_url, "Source not found in registry");
                        continue;
                    };
                    let ts = msg.time.timestamp();

                    if let Some(ref unparseable) = msg.unparseable_urls {
                        for u in unparseable {
                            tracing::warn!(
                                target: "mining::unparseable",
                                raw_url = %u.raw_url,
                                scheme = %u.scheme,
                                error = %u.error,
                                source_id = source.id,
                                source_type = "telegram",
                                timestamp = ts,
                            );
                        }
                    }

                    if let Some(ref msg_urls) = msg.msg_urls {
                        for urlx in msg_urls {
                            v2ray_heal::db::upsert_server(&conn, urlx, source.id, ts)
                                .context("Telegram upsert failed (aborting)")?;
                            tg_count += 1;
                        }
                    }
                }
                tracing::info!(count = tg_count, "Remote Telegram mining completed");
            }

            if !sub_urls.is_empty() {
                let mut registry = mining::SourceRegistry::new();
                for u in &sub_urls {
                    registry.pre_populate(u.as_str(), mining::SourceType::Subscription);
                }
                registry.upsert_all(&conn)?;

                let ts = mining::get_current_timestamp();
                let mut total = 0usize;

                for u in &sub_urls {
                    let url_str = u.as_str();
                    let data = match mining::download_sub_data(&client, u).await {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!(url = %url_str, error = %e, "Failed to download remote subscription");
                            continue;
                        }
                    };
                    let lines = v2ray_heal::parse_sub(u, &data);
                    let Some(source) = registry.lookup(url_str) else {
                        tracing::warn!(url = %url_str, "Source not found in registry");
                        continue;
                    };
                    let count = mining::process_sub_lines(&lines, &source, &conn, "subscription", ts)?;
                    total += count;
                }
                tracing::info!(count = total, "Remote subscription mining completed");
            }

            if tg_urls.is_empty() && sub_urls.is_empty() {
                tracing::warn!("No valid URLs provided for remote command");
            }
        }
        Commands::Local { file } => {
            if file.is_empty() {
                anyhow::bail!("No file paths provided");
            }

            let conn = mining::open_db(&cli.db)?;
            let mut registry = mining::SourceRegistry::new();

            let mut resolved: Vec<(PathBuf, url::Url, String)> = Vec::new();
            for path in &file {
                let abs = std::fs::canonicalize(path)
                    .with_context(|| format!("Failed to resolve path: {}", path.display()))?;
                let source_url = url::Url::from_file_path(&abs)
                    .map_err(|()| anyhow::anyhow!("Cannot convert path to file URL: {}", abs.display()))?;
                let url_str = source_url.as_str().to_string();
                registry.pre_populate(&url_str, mining::SourceType::Other);
                resolved.push((abs, source_url, url_str));
            }
            registry.upsert_all(&conn)?;

            let ts = mining::get_current_timestamp();
            let mut total = 0usize;

            for (abs_path, source_url, url_str) in &resolved {
                let data = std::fs::read(abs_path)
                    .with_context(|| format!("Failed to read file: {}", abs_path.display()))?;
                let lines = v2ray_heal::parse_sub(source_url, &data);
                let Some(source) = registry.lookup(url_str) else {
                    tracing::warn!(url = %url_str, "Source not found in registry");
                    continue;
                };
                let count = mining::process_sub_lines(&lines, &source, &conn, "local", ts)?;
                total += count;
            }
            tracing::info!(count = total, "Local file mining completed");
        }
    }

    Ok(())
}
