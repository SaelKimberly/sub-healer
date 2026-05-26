use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::TimeDelta;
use chrono::{Local, Utc};
use futures::StreamExt;
use serde_json::json;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use v2ray_heal::mining::{Backfill, LiveFetcher, SourceRegistry, TgConfig, UnparseableLayer};
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

    let mut registry = SourceRegistry::new();
    for name in &channels {
        registry.add_telegram_channel(name);
    }
    let registry = Arc::new(registry);

    let client = reqwest::Client::builder()
        .user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/237.84.2.178 Safari/537.36",
        )
        .build()?;

    let fetcher = LiveFetcher {
        tg_config: TgConfig {
            concurrency: 16,
            timeout: Duration::from_secs(10),
            backfill: Some(Backfill::Last(TimeDelta::hours(5))),
        },
    };
    let mut stream = registry.run_fetcher_stream(&client, fetcher);
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
