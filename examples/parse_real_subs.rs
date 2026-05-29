use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;

use chrono::{Local, Utc};
use serde_json::json;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use v2ray_heal::mining::{self, Pipeline, RawSourceItemBatch, UnparseableLayer};
use v2ray_heal::urlx::SchemeX;

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

/// Pre-process raw subscription data and extract raw URL strings.
fn parse_to_raw_urls(data: &[u8]) -> Vec<String> {
    let text = v2ray_heal::preprocess_sub_data(data);
    text.lines()
        .flat_map(|line| {
            let s = line.trim_start();
            if s.starts_with('#') || s.starts_with("//") || s.is_empty() {
                Vec::new()
            } else {
                s.split("<br/>")
                    .flat_map(|segment| {
                        SchemeX::slice_input(segment)
                            .into_iter()
                            .map(|(_, url)| url.to_string())
                    })
                    .collect()
            }
        })
        .collect()
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

    // Use a throwaway DB — the example only counts by scheme, not persist.
    let db_path = out_dir.join("pipeline.db");
    let mut pipeline = Pipeline::new(&db_path)?;
    let ts_now = Utc::now();
    let mut batches = Vec::new();

    for file_path in discover_txt_files(&goida_dir)
        .into_iter()
        .chain(discover_txt_files(&v2ray_dir))
    {
        let file_url = url::Url::from_file_path(&file_path).expect("valid file path");
        let url_str = file_url.as_str().to_string();
        pipeline.add_batch_source(&url_str);

        let data = std::fs::read(&file_path)?;
        let raw_urls = parse_to_raw_urls(&data);

        if raw_urls.is_empty() {
            continue;
        }

        let source = pipeline
            .registry_ref()
            .lookup(&url_str)
            .expect("source just registered");

        batches.push(RawSourceItemBatch {
            source,
            timestamp: ts_now,
            raw_urls: raw_urls.into_boxed_slice(),
        });
    }

    eprintln!(
        "Total files discovered: {}",
        pipeline.registry_ref().sources().len()
    );

    if !batches.is_empty() {
        pipeline.add_batch_raw(batches);
    }
    pipeline.run().await?;

    // Count results from DB
    let guard = pipeline.conn().write().await;
    use v2ray_heal::proto_spec::ProtoSpec;
    let servers = v2ray_heal::db::query_servers_filtered(&*guard, None, None, None)?;
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
