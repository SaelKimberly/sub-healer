use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{Local, Utc};
use futures::StreamExt;
use serde_json::json;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use v2ray_heal::mining::{LiveFetcher, SourceRegistry, UnparseableLayer};
use v2ray_heal::proto_spec::ProtoSpec;

fn discover_txt_files(dir: &PathBuf) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();
    files
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ts = Local::now().format("%Y%m%d-%H%M%S");
    let out_dir = PathBuf::from("test-output").join(format!("parse-subs-{ts}"));
    std::fs::create_dir_all(&out_dir)?;

    let unparseable_path = out_dir.join("unparseable.ndjson");
    unsafe {
        std::env::set_var(
            "V2RAY_HEAL_UNPARSEABLE_LOG",
            unparseable_path.to_str().unwrap(),
        );
    }

    tracing_subscriber::registry()
        .with(UnparseableLayer::new())
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .compact()
                .with_target(true)
                .with_level(true)
                .with_filter(tracing_subscriber::filter::EnvFilter::new("warn")),
        )
        .init();

    let goida_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("thirdparty")
        .join("goida-vpn-configs")
        .join("githubmirror");
    let v2ray_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("thirdparty")
        .join("v2ray-configs");

    let mut registry = SourceRegistry::new();
    for file_path in discover_txt_files(&goida_dir)
        .into_iter()
        .chain(discover_txt_files(&v2ray_dir))
    {
        let file_url = url::Url::from_file_path(&file_path)
            .expect("valid file path");
        registry.add_subscription(file_url.as_str());
    }

    eprintln!("Total files discovered: {}", registry.sources().len());

    let registry = Arc::new(registry);
    let client = reqwest::Client::builder()
        .user_agent("v2ray-heal/1.0")
        .build()?;

    let mut stream = registry.run_fetcher_stream(&client, LiveFetcher::default());
    let mut by_scheme_ok = BTreeMap::<String, u64>::new();

    while let Some(item) = stream.next().await {
        let schema = item.config.schema().to_string();
        *by_scheme_ok.entry(schema).or_default() += 1;
    }

    let total_ok: u64 = by_scheme_ok.values().sum();

    let all_schemes: BTreeMap<String, serde_json::Value> = by_scheme_ok
        .iter()
        .map(|(s, count)| (s.clone(), json!({ "ok": count, "total": count })))
        .collect();

    let summary = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "total_urls": total_ok,
        "ok": total_ok,
        "by_scheme": all_schemes,
    });

    let summary_path = out_dir.join("summary.json");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&summary_path)?;
    serde_json::to_writer_pretty(&mut f, &summary)?;

    eprintln!("Results: {} OK", total_ok);
    eprintln!("Unparseable URLs logged to: {}", unparseable_path.display());

    Ok(())
}
