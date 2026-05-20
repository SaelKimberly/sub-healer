use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::Engine;
use chrono::{Local, Utc};
use rayon::prelude::*;
use serde_json::json;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::prelude::*;
use tracing_subscriber::fmt;

use v2ray_heal::mining::UnparseableLayer;
use v2ray_heal::normalize_extras;
use v2ray_heal::proto_spec::{ProtocolConfig, ProtoSpec};
use v2ray_heal::urlx::{RawUrlX, SchemeX};

fn base64_try_decode(input: &[u8]) -> Cow<'_, [u8]> {
    let mut end = input.len();
    while end > 0 && (input[end - 1] == b'=' || input[end - 1].is_ascii_whitespace()) {
        end -= 1;
    }
    let trimmed = &input[..end];
    base64::prelude::BASE64_STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(trimmed))
        .map(Cow::Owned)
        .unwrap_or(Cow::Borrowed(input))
}

fn discover_txt_files(dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "txt") {
            files.push(path);
        }
    }
    files.sort();
    files
}

struct FileCtx {
    source_id: i64,
}

struct RawUrlEntry {
    file: Arc<FileCtx>,
    raw_url: String,
    scheme: SchemeX,
}

fn load_entries_from_file(path: &PathBuf, source_id: i64) -> Vec<RawUrlEntry> {
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let decoded = base64_try_decode(&content);
    let normalized = normalize_extras(&decoded);
    let Ok(text) = String::from_utf8(normalized.into_owned()) else {
        return Vec::new();
    };

    let file = Arc::new(FileCtx {
        source_id,
    });

    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for segment in line.split("<br/>") {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            for (scheme, url_part) in SchemeX::slice_input(segment) {
                if matches!(scheme, SchemeX::Unknown(_)) {
                    continue;
                }
                entries.push(RawUrlEntry {
                    file: Arc::clone(&file),
                    raw_url: url_part.to_string(),
                    scheme,
                });
            }
        }
    }
    entries
}

struct AggregateStats {
    total_urls: AtomicU64,
    total_ok: AtomicU64,
    total_fail: AtomicU64,
    by_scheme_ok: std::sync::Mutex<BTreeMap<String, u64>>,
    by_scheme_fail: std::sync::Mutex<BTreeMap<String, u64>>,
}

fn main() {
    // --- Output directory ---
    let ts = Local::now().format("%Y%m%d-%H%M%S");
    let out_dir = PathBuf::from("test-output").join(format!("parse-subs-{ts}"));
    std::fs::create_dir_all(&out_dir).expect("create test-output dir");

    // --- Set up tracing: NDJSON via UnparseableLayer + stderr summary ---
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
                .with_filter(filter_fn(|metadata| {
                    *metadata.level() >= tracing::Level::WARN
                })),
        )
        .init();

    // --- Discover files ---
    let goida_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("thirdparty")
        .join("goida-vpn-configs")
        .join("githubmirror");
    let v2ray_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("thirdparty")
        .join("v2ray-configs");

    let mut all_entries: Vec<RawUrlEntry> = Vec::new();

    for file_path in discover_txt_files(&goida_dir.to_string_lossy()) {
        let source_id = rapidhash(file_path.to_string_lossy().as_bytes()) as i64;
        let entries = load_entries_from_file(&file_path, source_id);
        eprintln!(
            "  {}: {} URLs",
            file_path.file_name().unwrap().to_string_lossy(),
            entries.len()
        );
        all_entries.extend(entries);
    }

    for file_path in discover_txt_files(&v2ray_dir.to_string_lossy()) {
        let source_id = rapidhash(file_path.to_string_lossy().as_bytes()) as i64;
        let entries = load_entries_from_file(&file_path, source_id);
        eprintln!(
            "  {}: {} URLs",
            file_path.file_name().unwrap().to_string_lossy(),
            entries.len()
        );
        all_entries.extend(entries);
    }

    eprintln!("Total URLs discovered: {}", all_entries.len());

    // --- Parallel parse phase ---
    let stats = Arc::new(AggregateStats {
        total_urls: AtomicU64::new(0),
        total_ok: AtomicU64::new(0),
        total_fail: AtomicU64::new(0),
        by_scheme_ok: std::sync::Mutex::new(BTreeMap::new()),
        by_scheme_fail: std::sync::Mutex::new(BTreeMap::new()),
    });

    let emit_failure = |entry: &RawUrlEntry, error: &str| {
        tracing::warn!(
            target: "mining::unparseable",
            raw_url = %entry.raw_url,
            scheme = %entry.scheme,
            error = %error,
            source_id = entry.file.source_id,
            source_type = "file",
            timestamp = Utc::now().timestamp(),
        );
    };

    all_entries.par_iter().for_each(|entry| {
        stats.total_urls.fetch_add(1, Ordering::Relaxed);

        let raw = RawUrlX::from(entry.raw_url.as_str());

        // Debug first few vmess failures
        if matches!(entry.scheme, SchemeX::Vmess) {
            let schema_debug = format!("{:?}", raw.schema);
            if schema_debug.contains("Unknown") {
                eprintln!(
                    "DEBUG: vmess URL got Unknown schema: url={}",
                    &entry.raw_url[..80.min(entry.raw_url.len())]
                );
            }
        }

        match ProtocolConfig::try_parse(&raw) {
            Ok(config) => {
                let schema = config.schema().to_string();
                stats.total_ok.fetch_add(1, Ordering::Relaxed);
                let mut map = stats.by_scheme_ok.lock().unwrap();
                *map.entry(schema).or_insert(0) += 1;
            }
            Err(e) => {
                let schema = entry.scheme.to_string();
                stats.total_fail.fetch_add(1, Ordering::Relaxed);
                {
                    let mut map = stats.by_scheme_fail.lock().unwrap();
                    *map.entry(schema.clone()).or_insert(0) += 1;
                }
                emit_failure(entry, &e.to_string());
            }
        }
    });

    // --- Write summary ---
    let total = stats.total_urls.load(Ordering::Relaxed);
    let ok = stats.total_ok.load(Ordering::Relaxed);
    let fail = stats.total_fail.load(Ordering::Relaxed);
    let by_scheme_ok = stats.by_scheme_ok.lock().unwrap();
    let by_scheme_fail = stats.by_scheme_fail.lock().unwrap();

    let mut all_schemes: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    let mut seen_schemes: BTreeMap<String, bool> = BTreeMap::new();
    for (s, _) in by_scheme_ok.iter() {
        seen_schemes.entry(s.clone()).or_insert(true);
    }
    for (s, _) in by_scheme_fail.iter() {
        seen_schemes.entry(s.clone()).or_insert(true);
    }
    for s in seen_schemes.keys() {
        let ok_count = by_scheme_ok.get(s).copied().unwrap_or(0);
        let fail_count = by_scheme_fail.get(s).copied().unwrap_or(0);
        all_schemes.insert(
            s.as_str(),
            json!({
                "ok": ok_count,
                "fail": fail_count,
                "total": ok_count + fail_count,
            }),
        );
    }

    let summary = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "total_urls": total,
        "ok": ok,
        "fail": fail,
        "success_rate_pct": format!("{:.1}", if total > 0 { ok as f64 / total as f64 * 100.0 } else { 0.0 }),
        "by_scheme": all_schemes,
    });

    let summary_path = out_dir.join("summary.json");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&summary_path)
        .expect("open summary.json");
    serde_json::to_writer_pretty(&mut f, &summary).expect("write summary");
    f.flush().ok();

    // --- Print summary to stderr ---
    eprintln!("---");
    eprintln!(
        "Results: {}/{} OK ({:.1}%), {} FAIL",
        ok,
        total,
        if total > 0 {
            ok as f64 / total as f64 * 100.0
        } else {
            0.0
        },
        fail,
    );
    eprintln!("Output: {}/", out_dir.display());
}

fn rapidhash(data: &[u8]) -> u64 {
    rapidhash::v3::rapidhash_v3(data)
}
