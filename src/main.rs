use std::path::PathBuf;

use clap::Parser;
use tokio::io::AsyncReadExt;

#[derive(Debug, Default, clap::Subcommand)]
enum Commands {
    #[default]
    /// Read from stdin
    Stdin,
    /// Read from multiple sources, based on config
    Config { file: Option<PathBuf> },
    /// Read from a remote url
    Remote { url: Vec<url::Url> },
    /// Read from a local file
    Local { file: Vec<PathBuf> },
}

#[derive(Debug, Default, clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Commands::Stdin = cli.command {
        todo!()
    }

    if let Commands::Config { file: Some(path) } = cli.command {
        todo!()
    }

    if let Commands::Config { file: None } = cli.command {
        todo!()
    }

    if let Commands::Remote { url } = cli.command {
        todo!()
    }

    if let Commands::Local { file } = cli.command {
        todo!()
    }

    Ok(())
}
