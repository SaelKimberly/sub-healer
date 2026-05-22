use std::path::PathBuf;
use std::time::Duration;

use criterion::{Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use v2ray_heal::permissive_json as pj;
use v2ray_heal::permissive_json_core as pj_core;

/// Load a data file, yielding non-empty lines as byte slices.
fn load_lines(basename: &str) -> Vec<Vec<u8>> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "benches",
        "data",
        "permissive_json",
        &format!("{basename}.txt"),
    ]
    .iter()
    .collect();

    let data = std::fs::read_to_string(&path).unwrap_or_default();
    data.lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .map(String::into_bytes)
        .collect()
}

// ── Category benchmark ──────────────────────────────────────────

fn run_category(c: &mut Criterion, name: &str, lines: &[Vec<u8>]) {
    let bytes: usize = lines.iter().map(|l| l.len()).sum();
    let mut group = c.benchmark_group(format!("permissive_json_core/{name}"));
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Bytes(bytes as u64));
    group.bench_function("core", |b| {
        b.iter(|| {
            for line in lines {
                let input = line.as_slice();
                std::hint::black_box(pj_core(input).ok());
            }
        })
    });
    group.finish();
}

fn bench_categories(c: &mut Criterion) {
    let categories = [
        "valid_json",
        "percent_encoded",
        "single_quoted",
        "unquoted_keys",
        "python_dict",
        "leading_plus",
        "trailing_garbage",
        "truncated",
        "bare_bracket",
        "null_literal",
        "xpadding",
        "deeply_nested",
    ];

    for cat in &categories {
        let lines = load_lines(cat);
        if lines.is_empty() {
            eprintln!("WARNING: {cat}.txt is empty, skipping");
            continue;
        }
        run_category(c, cat, &lines);
    }
}

// ── vs serde_json (valid JSON only) ─────────────────────────────

fn bench_vs_serde(c: &mut Criterion) {
    let lines = load_lines("valid_json");
    if lines.is_empty() {
        return;
    }
    let bytes: usize = lines.iter().map(|l| l.len()).sum();

    let mut group = c.benchmark_group("permissive_json_core/vs_serde");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Bytes(bytes as u64));

    group.bench_function("permissive_json_core", |b| {
        b.iter(|| {
            for line in &lines {
                let input = line.as_slice();
                std::hint::black_box(pj_core(input).ok());
            }
        })
    });

    group.bench_function("serde_json_from_slice", |b| {
        b.iter(|| {
            for line in &lines {
                std::hint::black_box(serde_json::from_slice::<serde_json::Value>(line).ok());
            }
        })
    });

    // Also measure permissive_json (the wrapper with fallback) on valid_json
    group.bench_function("permissive_json_wrapper", |b| {
        b.iter(|| {
            for line in &lines {
                let input = line.as_slice();
                std::hint::black_box(pj(input).ok());
            }
        })
    });

    group.finish();
}

// ── Fallback overhead ──────────────────────────────────────────

fn bench_fallback(c: &mut Criterion) {
    let lines = load_lines("bare_bracket");
    if lines.is_empty() {
        return;
    }
    let bytes: usize = lines.iter().map(|l| l.len()).sum();

    let mut group = c.benchmark_group("permissive_json/fallback");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Bytes(bytes as u64));

    group.bench_function("core (first pass)", |b| {
        b.iter(|| {
            for line in &lines {
                let input = line.as_slice();
                std::hint::black_box(pj_core(input).ok());
            }
        })
    });

    group.bench_function("wrapper (with retry)", |b| {
        b.iter(|| {
            for line in &lines {
                let input = line.as_slice();
                std::hint::black_box(pj(input).ok());
            }
        })
    });

    group.finish();
}

criterion_group! {
    name = pj_bench;
    config = Criterion::default()
        .sample_size(500)
        .warm_up_time(Duration::from_secs(3));
    targets =
        bench_categories,
        bench_vs_serde,
        bench_fallback,
}
criterion_main!(pj_bench);
