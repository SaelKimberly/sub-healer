use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;
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

    // --- Registry (canonical https://t.me/s/{name}) ---
    let mut registry = SourceRegistry::new();
    for name in &channels {
        registry.pre_populate(&format!("https://t.me/s/{name}"), SourceType::Telegram);
    }
    let registry = Arc::new(registry);

    // --- Client ---
    let client = reqwest::Client::builder()
        .user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/237.84.2.178 Safari/537.36",
        )
        .build()?;

    // --- Fetch (flattened stream: one TracedProtocolConfig per item) ---
    let mut tg_stream = fetch_tg_channels(
        client,
        16,
        channels.into_iter(),
        Duration::from_secs(10),
        Some(Backfill::Last(TimeDelta::hours(5))),
        registry.clone(),
    );

    // --- Collect ---
    let mut per_channel =
        BTreeMap::<String, Vec<(chrono::DateTime<Utc>, String, String)>>::new();
    let mut by_scheme_ok = BTreeMap::<String, u64>::new();

    while let Some(item) = tg_stream.next().await {
        let schema = item.config.schema().to_string();
        *by_scheme_ok.entry(schema.clone()).or_insert(0) += 1;

        per_channel
            .entry(item.source.url.clone())
            .or_default()
            .push((
                item.timestamp,
                schema,
                item.config.reconstruct().unwrap_or_default(),
            ));
    }

    // --- Sort per channel ---
    for v in per_channel.values_mut() {
        v.sort_by_key(|t| t.0);
    }

    // --- Write tg-results.json ---
    let total_ok: usize = per_channel.values().map(Vec::len).sum();
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
        "total_urls": total_ok,
        "channels": channels_map,
    });

    let results_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out_dir.join("tg-results.json"))?;
    serde_json::to_writer_pretty(results_file, &tg_results)?;

    // --- Write summary.json ---
    let mut all_schemes: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (s, ok_count) in &by_scheme_ok {
        all_schemes.insert(
            s.clone(),
            json!({
                "ok": ok_count,
                "total": ok_count,
            }),
        );
    }

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

    // --- Print summary to stderr ---
    eprintln!("Logs written to: {}/", out_dir.display());
    eprintln!("Results: {} OK", total_ok);
    eprintln!("Unparseable URLs logged to: {}", unparseable_path.display());

    Ok(())
}
