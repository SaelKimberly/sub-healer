use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use v2ray_heal::mining;

#[derive(Debug, Default, clap::Subcommand)]
enum Commands {
    #[default]
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
    Mine,
}

#[derive(Debug, Default, clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .try_init()
        .ok();

    let cli = Cli::parse();

    if matches!(cli.command, Commands::Mine) {
        mining::run().await?;
        return Ok(());
    }

    if let Commands::Stdin = cli.command {
        todo!()
    }

    if let Commands::Config { .. } = cli.command {
        todo!()
    }

    if let Commands::Remote { .. } = cli.command {
        todo!()
    }

    if let Commands::Local { .. } = cli.command {
        todo!()
    }

    Ok(())
}
