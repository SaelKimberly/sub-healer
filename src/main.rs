use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use futures::StreamExt;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use v2ray_heal::mining;

fn is_telegram_url(url: &url::Url) -> bool {
    url.host_str() == Some("t.me")
}

/// Process a stream of traced configs, writing each to the database.
/// Fatal on DB error (aborts pipeline).
async fn process_stream(
    mut stream: impl StreamExt<Item = mining::TracedProtocolConfig> + std::marker::Unpin,
    conn: &rusqlite::Connection,
) -> Result<usize, anyhow::Error> {
    let mut count = 0usize;
    while let Some(item) = stream.next().await {
        v2ray_heal::db::upsert_server(
            conn,
            &item.config,
            item.source.id,
            item.timestamp.timestamp(),
        )
        .context("upsert failed (aborting)")?;
        count += 1;
    }
    Ok(count)
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    Stdin,
    Config { file: Option<PathBuf> },
    Remote { url: Vec<url::Url> },
    Local { file: Vec<PathBuf> },
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

            let lines = v2ray_heal::parse_sub(&source_url, &buf);
            let items = mining::lines_to_traced(
                &lines,
                &registry,
                "stdin://local",
                mining::get_current_timestamp(),
            );
            let count = process_stream(futures::stream::iter(items), &conn).await?;
            tracing::info!(count, "Stdin mining completed");
        }
        Commands::Remote { url } => {
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

            let count = process_stream(futures::stream::iter(items), &conn).await?;
            tracing::info!(count, "Local file mining completed");
        }
    }

    Ok(())
}
