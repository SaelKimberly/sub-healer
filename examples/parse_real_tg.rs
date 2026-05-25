use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{Local, Utc};
use chrono::TimeDelta;
use futures::StreamExt;
use serde_json::json;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry;

use v2ray_heal::mining::{PipelineLogWriter, SourceRegistry, SourceType, UnparseableLayer};
use v2ray_heal::mining::telegram::{Backfill, fetch_tg_channels};
use v2ray_heal::proto_spec::ProtoSpec;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- Output directory ---
    let ts = Local::now().format("%Y%m%d-%H%M%S");
    let out_dir = PathBuf::from("test-output").join(format!("parse-real-tg-{ts}"));
    std::fs::create_dir_all(&out_dir)?;

    // --- Set env var for UnparseableLayer ---
    let unparseable_path = out_dir.join("unparseable.ndjson");
    unsafe {
        std::env::set_var(
            "V2RAY_HEAL_UNPARSEABLE_LOG",
            unparseable_path.to_str().unwrap(),
        );
    }

    // --- Tracing layers ---
    let pipeline_writer = PipelineLogWriter::new(out_dir.join("tg-pipeline.log").as_path());

    registry()
        .with(
            fmt::layer()
                .with_writer(pipeline_writer)
                .compact()
                .with_target(true)
                .with_level(true)
                .with_filter(filter_fn(|metadata| {
                    metadata.target() == "mining::tg_channel"
                        && *metadata.level() >= tracing::Level::INFO
                })),
        )
        .with(UnparseableLayer::new())
        .with(
            fmt::layer()
                .compact()
                .with_target(true)
                .with_level(true)
                .with_filter(filter_fn(|metadata| {
                    *metadata.level() >= tracing::Level::WARN
                })),
        )
        .init();

    // --- Channels ---
    let channels = [
        "ARv2ray",
        "Alfred_Config",
        "Baraye_azadi_Info",
        "BmFt1",
        "Capital_NET",
        "Capoit",
        "CloudCityy",
        "ConfigV2rayNG",
        "Configforvpn01",
        "ConfigsHUB2",
        "v2ray_configs_pool",
        "DailyV2RY",
        "DigiV2ray",
        "DirectVPN",
        "Easy_Free_VPN",
        "Eleven_vpn",
        "EliV2ray",
        "EuServer",
        "EzNett",
        "FOXNT",
        "FProxies",
        "FalconPolV2rayNG",
        "FreakConfig",
        "Free166",
        "FreeV2rays",
        "FreeVlessVpn",
        "Free_HTTPCustom",
        "Helix_Servers",
        "Hope_Net",
        "Kia_Net",
        "IRANVPNNET",
        "JiedianSsr",
        "Jsnzk",
        "Lockey_vpn",
        "MTConfig",
        "MrV2Ray",
        "MsV2ray",
    ];

    // --- Registry (aligned with production: https://t.me/s/{name}) ---
    let mut registry = SourceRegistry::new();
    for name in &channels {
        registry.pre_populate(&format!("https://t.me/s/{name}"), SourceType::Telegram);
    }

    // --- Client ---
    let client = reqwest::Client::builder()
        .user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/237.84.2.178 Safari/537.36",
        )
        .build()?;

    // --- Fetch ---
    let mut tg_messages = fetch_tg_channels(
        client,
        16,
        channels.into_iter(),
        Duration::from_secs(10),
        Some(Backfill::Last(TimeDelta::hours(5))),
    );

    // --- Collect ---
    let mut per_channel = BTreeMap::<String, Vec<(chrono::DateTime<Utc>, String, String)>>::new();

    let stats = Arc::new(AggregateStats {
        total_ok: AtomicU64::new(0),
        total_fail: AtomicU64::new(0),
        by_scheme_ok: std::sync::Mutex::new(BTreeMap::new()),
        by_scheme_fail: std::sync::Mutex::new(BTreeMap::new()),
    });

    while let Some(msg) = tg_messages.next().await {
        // Emit unparseable events (feeds UnparseableLayer → unparseable.ndjson)
        if let Some(ref unparseable) = msg.unparseable_urls {
            let source_url = format!("https://t.me/s/{}", msg.source_url);
            let source = registry.lookup(&source_url);
            let source_id = source.as_ref().map_or(0i64, |s| s.id);
            let ts = msg.time.timestamp();
            for u in unparseable {
                stats.total_fail.fetch_add(1, Ordering::Relaxed);
                let mut map = stats.by_scheme_fail.lock().unwrap();
                *map.entry(u.scheme.clone()).or_insert(0) += 1;
                tracing::warn!(
                    target: "mining::unparseable",
                    raw_url = %u.raw_url,
                    scheme = %u.scheme,
                    error = %u.error,
                    source_id = source_id,
                    source_type = "telegram",
                    timestamp = ts,
                );
            }
        }

        let Some(msg_urls) = msg.msg_urls.as_deref() else {
            continue;
        };

        for config in msg_urls {
            stats.total_ok.fetch_add(1, Ordering::Relaxed);
            let schema = config.schema().to_string();
            let mut map = stats.by_scheme_ok.lock().unwrap();
            *map.entry(schema.clone()).or_insert(0) += 1;
        }

        per_channel.entry(msg.source_url.to_string()).or_default().extend(
            msg_urls
                .iter()
                .map(|config| {
                    (
                        msg.time,
                        config.schema().to_string(),
                        config.reconstruct().unwrap_or_default(),
                    )
                }),
        );
    }

    // --- Sort per channel ---
    for v in per_channel.values_mut() {
        v.sort_by_key(|t| t.0);
    }

    // --- Write tg-results.json ---
    let total: usize = per_channel.values().map(Vec::len).sum();
    let channels_map: serde_json::Map<String, serde_json::Value> = per_channel
        .iter()
        .map(|(channel, entries)| {
            let entries: Vec<serde_json::Value> = entries
                .iter()
                .map(|(time, schema, url)| {
                    json!({
                        "time": time.to_rfc3339(),
                        "schema": schema,
                        "url": url,
                    })
                })
                .collect();
            (channel.to_string(), json!(entries))
        })
        .collect();

    let tg_results = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "total_channels": per_channel.len(),
        "total_urls": total,
        "channels": channels_map,
    });

    let results_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out_dir.join("tg-results.json"))?;
    serde_json::to_writer_pretty(results_file, &tg_results)?;

    // --- Write summary.json ---
    let ok = stats.total_ok.load(Ordering::Relaxed);
    let fail = stats.total_fail.load(Ordering::Relaxed);
    let total_urls = ok + fail;
    let by_scheme_ok = stats.by_scheme_ok.lock().unwrap();
    let by_scheme_fail = stats.by_scheme_fail.lock().unwrap();

    let mut seen_schemes: BTreeMap<String, bool> = BTreeMap::new();
    for s in by_scheme_ok.keys() {
        seen_schemes.entry(s.clone()).or_insert(true);
    }
    for s in by_scheme_fail.keys() {
        seen_schemes.entry(s.clone()).or_insert(true);
    }

    let mut all_schemes: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for s in seen_schemes.keys() {
        let ok_count = by_scheme_ok.get(s).copied().unwrap_or(0);
        let fail_count = by_scheme_fail.get(s).copied().unwrap_or(0);
        all_schemes.insert(
            s.clone(),
            json!({
                "ok": ok_count,
                "fail": fail_count,
                "total": ok_count + fail_count,
            }),
        );
    }

    let summary = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "total_urls": total_urls,
        "ok": ok,
        "fail": fail,
        "success_rate_pct": format!("{:.1}", if total_urls > 0 { ok as f64 / total_urls as f64 * 100.0 } else { 0.0 }),
        "by_scheme": all_schemes,
    });

    let summary_path = out_dir.join("summary.json");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&summary_path)?;
    serde_json::to_writer_pretty(&mut f, &summary)?;

    // --- Print summary to stderr ---
    eprintln!("Logs written to: {}/", out_dir.display());
    eprintln!(
        "Results: {}/{} OK ({:.1}%), {} FAIL",
        ok,
        total_urls,
        if total_urls > 0 {
            ok as f64 / total_urls as f64 * 100.0
        } else {
            0.0
        },
        fail,
    );

    Ok(())
}

struct AggregateStats {
    total_ok: AtomicU64,
    total_fail: AtomicU64,
    by_scheme_ok: std::sync::Mutex<BTreeMap<String, u64>>,
    by_scheme_fail: std::sync::Mutex<BTreeMap<String, u64>>,
}
