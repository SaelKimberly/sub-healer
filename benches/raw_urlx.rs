use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use v2ray_heal::urlx::RawUrlX;

macro_rules! bench_protocol {
    ($c:ident, $group_name:expr, $protocol:expr, $urls:ident, $sample_size:expr) => {
        let mut group = $c.benchmark_group(format!("{}/{}", $group_name, $protocol));
        group.sampling_mode(SamplingMode::Flat);
        group.sample_size($sample_size);
        group.warm_up_time(Duration::from_secs(2));
        group.measurement_time(Duration::from_secs(5));
        group.throughput(Throughput::Elements($urls.len() as u64));
        group.bench_function("raw_urlx_from", |b| {
            b.iter(|| {
                for url in &$urls {
                    std::hint::black_box(RawUrlX::from(url.as_str()));
                }
            })
        });
        group.finish();
    };
}

fn load_urls(protocol: &str) -> Vec<String> {
    let path = format!(
        "{}/benches/data/{}.txt",
        env!("CARGO_MANIFEST_DIR"),
        protocol
    );
    let data = std::fs::read_to_string(&path).unwrap_or_default();
    data.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

fn bench_raw_urlx_from_str(c: &mut Criterion) {
    let protocols = [
        ("vless", 500),
        ("vmess", 500),
        ("trojan", 500),
        ("ss", 500),
        ("ssr", 200),
        ("hy2", 500),
        ("tuic", 200),
        ("wireguard", 200),
    ];

    for (protocol, sample_size) in &protocols {
        let urls = load_urls(protocol);
        if urls.is_empty() {
            continue;
        }
        bench_protocol!(c, "raw_urlx_from_str", protocol, urls, *sample_size);
    }
}

fn bench_raw_urlx_userinfo(c: &mut Criterion) {
    let protocols = [
        ("vless", false, 500),
        ("vmess", true, 500),
        ("trojan", false, 500),
        ("ss", true, 500),
        ("ssr", true, 200),
        ("hy2", false, 500),
        ("tuic", false, 200),
        ("wireguard", false, 200),
    ];

    for (protocol, expect_b64, sample_size) in &protocols {
        let urls = load_urls(protocol);
        if urls.is_empty() {
            continue;
        }

        let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

        let mut group = c.benchmark_group(format!("raw_urlx_userinfo/{}", protocol));
        group.sampling_mode(SamplingMode::Flat);
        group.sample_size(*sample_size);
        group.warm_up_time(Duration::from_secs(2));
        group.measurement_time(Duration::from_secs(5));
        group.throughput(Throughput::Elements(raw_urls.len() as u64));
        group.bench_function("userinfo", |b| {
            b.iter(|| {
                for raw in &raw_urls {
                    std::hint::black_box(raw.userinfo(*expect_b64).ok());
                }
            })
        });
        group.finish();
    }
}

fn bench_raw_urlx_hostport(c: &mut Criterion) {
    let protocols = [
        ("vless", 500),
        ("trojan", 500),
        ("ss", 500),
        ("hy2", 500),
        ("tuic", 200),
        ("wireguard", 200),
    ];

    for (protocol, sample_size) in &protocols {
        let urls = load_urls(protocol);
        if urls.is_empty() {
            continue;
        }

        let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

        let mut group = c.benchmark_group(format!("raw_urlx_hostport/{}", protocol));
        group.sampling_mode(SamplingMode::Flat);
        group.sample_size(*sample_size);
        group.warm_up_time(Duration::from_secs(2));
        group.measurement_time(Duration::from_secs(5));
        group.throughput(Throughput::Elements(raw_urls.len() as u64));
        group.bench_function("hostport", |b| {
            b.iter(|| {
                for raw in &raw_urls {
                    std::hint::black_box(raw.hostport().ok());
                }
            })
        });
        group.finish();
    }
}

criterion_group! {
    name = raw_urlx;
    config = Criterion::default()
        .sample_size(500)
        .warm_up_time(Duration::from_secs(3));
    targets = bench_raw_urlx_from_str, bench_raw_urlx_userinfo, bench_raw_urlx_hostport
}
criterion_main!(raw_urlx);
