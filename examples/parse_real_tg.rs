use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::Duration;

use chrono::TimeDelta;
use chrono::{Local, Utc};
use serde_json::json;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use v2ray_heal::mining::{self, Backfill, Pipeline, SourceRegistry, SourceType, UnparseableLayer};
use v2ray_heal::proto_spec::ProtoSpec;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ts = Local::now().format("%Y%m%d-%H%M%S");
    let out_dir = PathBuf::from("test-output").join(format!("parse-real-tg-{ts}"));
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

    let config_path = PathBuf::from("channels-collection-01.yaml");
    let registry = SourceRegistry::from_config(&config_path)?;

    // Use a throwaway DB — the example only counts by scheme, not persist.
    let db_path = out_dir.join("pipeline.db");
    let mut pipeline = Pipeline::new(&db_path)?;

    // Add sources from the config registry
    for meta in registry.sources() {
        match meta.source_type {
            SourceType::Telegram => pipeline.add_telegram(&meta.url),
            SourceType::Subscription => pipeline.add_subscription(&meta.url),
            SourceType::Other => {}
        }
    }

    // Set backfill for last 12 hours
    pipeline.set_backfill(Some(Backfill::Last(TimeDelta::hours(12))));

    pipeline.run().await?;

    // Count results from DB
    let guard = pipeline.conn().write().await;
    let servers = v2ray_heal::db::query_servers_filtered(&*guard, None, None, None)?;
    let mut by_scheme_ok = BTreeMap::<String, u64>::new();
    let mut by_channel = BTreeMap::<String, u64>::new();

    for server in &servers {
        *by_scheme_ok.entry(server.schema.clone()).or_default() += 1;
        // Query source for this server
        let sources = v2ray_heal::db::query_sources_by_server_ids(&*guard, &[server.id])?;
        for src in &sources {
            *by_channel.entry(src.url.clone()).or_default() += 1;
        }
    }

    let total_ok: u64 = by_scheme_ok.values().sum();

    let all_schemes: BTreeMap<String, serde_json::Value> = by_scheme_ok
        .iter()
        .map(|(s, count)| (s.clone(), json!({ "ok": count, "total": count })))
        .collect();

    let all_channels: BTreeMap<String, serde_json::Value> = by_channel
        .iter()
        .map(|(ch, count)| (ch.clone(), json!({ "ok": count })))
        .collect();

    let summary = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "total_urls": total_ok,
        "ok": total_ok,
        "by_scheme": all_schemes,
        "by_channel": all_channels,
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
