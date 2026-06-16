use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;

use chrono::TimeDelta;
use chrono::{Local, Utc};
use serde_json::json;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use v2ray_heal::mining::{
    Backfill, PingResult, PingSpec, Pipeline, SourceRegistry, UnparseableLayer, ping_and_store,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ts = Local::now().format("%Y%m%d-%H%M%S");
    let out_dir = PathBuf::from("test-output").join(format!("parse-real-tg-{ts}"));
    std::fs::create_dir_all(&out_dir)?;

    let unparseable_path = out_dir.join("unparseable.ndjson");

    tracing_subscriber::registry()
        .with(UnparseableLayer::new(Some(unparseable_path.clone())))
        .with(
            fmt::layer()
                .compact()
                .with_target(true)
                .with_level(true)
                .with_filter(tracing_subscriber::filter::EnvFilter::new("warn,ping=info")),
        )
        .init();

    // Initialize whitelist checker from default file paths
    let wl_loaded = v2ray_heal::mining::init_whitelist(
        &PathBuf::from("whitelist.txt"),
        &PathBuf::from("ipwhitelist.txt"),
        &PathBuf::from("cidrwhitelist.txt"),
    )?;
    if wl_loaded {
        eprintln!("Whitelist loaded");
    }

    let config_path = PathBuf::from("channels-collection-01.yaml");
    let registry = SourceRegistry::from_config(&config_path)?;

    // Use a throwaway DB — the example only counts by scheme, not persist.
    let db_path = out_dir.join("pipeline.db");
    let mut pipeline = Pipeline::new(&db_path)?;

    // Add sources from the config registry
    for meta in registry.sources() {
        pipeline.add_source(&meta.url);
    }

    // Set backfill for last 12 hours
    pipeline.set_backfill(Some(Backfill::Last(TimeDelta::hours(12))));

    eprintln!("Parsing servers from Telegram channels…");
    pipeline.run().await?;

    // Count results from DB
    let servers = pipeline
        .db()
        .query_servers_filtered(None, None, None, None)
        .await?;
    let mut by_scheme_ok = BTreeMap::<String, u64>::new();
    let mut by_channel = BTreeMap::<String, u64>::new();

    for server in &servers {
        *by_scheme_ok.entry(server.schema.clone()).or_default() += 1;
    }

    // Count whitelisted servers (any flag set)
    let wl_servers = pipeline
        .db()
        .query_servers_filtered(None, None, None, Some(0b111u8))
        .await?;
    let wl_count: u64 = wl_servers.len() as u64;
    eprintln!("Pinging {} unique servers…", servers.len());
    // Query sources for each server
    // Ping all discoverable TCP endpoints and collect statistics
    let ping_results = ping_and_store(pipeline.db(), &servers, &PingSpec::Ok, None).await?;

    // Build (host:port) -> &PingResult lookup
    let ping_map: std::collections::HashMap<(String, u16), &PingResult> = ping_results
        .iter()
        .map(|(h, p, r)| ((h.to_lowercase(), *p), r))
        .collect();

    // Count ping by scheme
    let mut ping_by_scheme: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut ping_ok_total: u64 = 0;
    let mut ping_fail_total: u64 = 0;
    let mut ping_total: u64 = 0;

    for srv in &servers {
        let port: u16 = match srv.port.parse() {
            Ok(p) if p != 0 => p,
            _ => continue,
        };
        let key = (srv.host.to_lowercase(), port);
        let Some(result) = ping_map.get(&key) else {
            continue;
        };
        ping_total += 1;

        let ok_inc = match result {
            PingResult::Tcp {
                latency_ms: Some(_),
                ..
            } => 1u64,
            _ => 0,
        };
        let fail_inc = 1u64 - ok_inc;
        ping_ok_total += ok_inc;
        ping_fail_total += fail_inc;

        let entry = ping_by_scheme
            .entry(srv.schema.clone())
            .or_insert_with(|| json!({ "total": 0u64, "ok": 0u64, "fail": 0u64 }));
        entry["total"] = json!(entry["total"].as_u64().unwrap() + 1);
        entry["ok"] = json!(entry["ok"].as_u64().unwrap() + ok_inc);
        entry["fail"] = json!(entry["fail"].as_u64().unwrap() + fail_inc);
    }

    let ping_stats = json!({
        "total": ping_total,
        "ok": ping_ok_total,
        "fail": ping_fail_total,
        "by_scheme": ping_by_scheme,
    });
    let mut source_ids: Vec<i64> = servers.iter().map(|s| s.first_seen_source_id).collect();
    if !source_ids.is_empty() {
        source_ids.sort_unstable();
        source_ids.dedup();
        let sources = pipeline.db().query_sources_by_ids(&source_ids).await?;
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
        "wl_count": wl_count,
        "by_scheme": all_schemes,
        "by_channel": all_channels,
        "ping": ping_stats,
    });

    let summary_path = out_dir.join("summary.json");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&summary_path)?;
    serde_json::to_writer_pretty(&mut f, &summary)?;

    eprintln!(
        "Results: {} OK, {} whitelisted; Ping: {} ok / {} fail / {} total",
        total_ok, wl_count, ping_ok_total, ping_fail_total, ping_total
    );
    eprintln!("Unparseable URLs logged to: {}", unparseable_path.display());

    Ok(())
}
