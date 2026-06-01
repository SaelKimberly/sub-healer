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
                .compact()
                .with_target(true)
                .with_level(true)
                .with_filter(tracing_subscriber::filter::EnvFilter::new("warn")),
        )
        .init();

    let config_path = PathBuf::from("subscriptions-01.yaml");
    let registry = SourceRegistry::from_config(&config_path)?;

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
        .query_servers_filtered(None, None, None)
        .await?;
    let mut by_scheme_ok = BTreeMap::<String, u64>::new();
    for server in &servers {
        *by_scheme_ok.entry(server.schema.clone()).or_default() += 1;
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
