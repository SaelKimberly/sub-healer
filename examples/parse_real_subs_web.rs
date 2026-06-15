use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;

use chrono::{Local, Utc};
use serde_json::json;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use v2ray_heal::mining::{Pipeline, SourceRegistry, UnparseableLayer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ts = Local::now().format("%Y%m%d-%H%M%S");
    let out_dir = PathBuf::from("test-output").join(format!("parse-subs-web-{ts}"));
    std::fs::create_dir_all(&out_dir)?;

    let unparseable_path = out_dir.join("unparseable.ndjson");

    tracing_subscriber::registry()
        .with(UnparseableLayer::new(Some(unparseable_path.clone())))
        .with(
            fmt::layer()
                .compact()
                .with_target(true)
                .with_level(true)
                .with_filter(tracing_subscriber::filter::EnvFilter::new("warn")),
        )
        .init();

    let config_path = PathBuf::from("large.yaml");
    let registry = SourceRegistry::from_config(&config_path)?;
    // Initialize whitelist checker from default file paths
    let whitelist_paths = [
        PathBuf::from("whitelist.txt"),
        PathBuf::from("ipwhitelist.txt"),
        PathBuf::from("cidrwhitelist.txt"),
    ];
    let wl_loaded = v2ray_heal::mining::init_whitelist(
        &whitelist_paths[0],
        &whitelist_paths[1],
        &whitelist_paths[2],
    )?;
    if wl_loaded {
        eprintln!("Whitelist loaded from: {:?}", whitelist_paths);
    }

    // Use a throwaway DB — the example only counts by scheme, not persist.
    let db_path = out_dir.join("pipeline.db");
    let mut pipeline = Pipeline::new(&db_path)?;

    // Add sources from the config registry
    for meta in registry.sources() {
        pipeline.add_source(&meta.url);
    }

    pipeline.run().await?;

    // Count results from DB
    let servers = pipeline
        .db()
        .query_servers_filtered(None, None, None, None)
        .await?;
    let mut by_scheme_ok = BTreeMap::<String, u64>::new();
    for server in &servers {
        *by_scheme_ok.entry(server.schema.clone()).or_default() += 1;
    }

    // Count whitelisted servers (any flag set)
    let wl_servers = pipeline
        .db()
        .query_servers_filtered(None, None, None, Some(0b111u8))
        .await?;
    let wl_count: u64 = wl_servers.len() as u64;

    let total_ok: u64 = by_scheme_ok.values().sum();

    let all_schemes: BTreeMap<String, serde_json::Value> = by_scheme_ok
        .iter()
        .map(|(s, count)| (s.clone(), json!({ "ok": count, "total": count })))
        .collect();

    let summary = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "total_urls": total_ok,
        "ok": total_ok,
        "wl_count": wl_count,
        "by_scheme": all_schemes,
    });

    let summary_path = out_dir.join("summary.json");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&summary_path)?;
    serde_json::to_writer_pretty(&mut f, &summary)?;

    eprintln!("Results: {} OK, {} whitelisted", total_ok, wl_count);

    Ok(())
}
