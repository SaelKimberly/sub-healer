use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use v2ray_heal::proto_spec::{
    Hysteria2Config, ProtocolConfig, ProtoSpec, SsConfig, SsrConfig, TrojanConfig, TuicConfig,
    VlessConfig, VmessConfig, WireguardConfig,
};
use v2ray_heal::urlx::RawUrlX;

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

fn bench_proto_try_parse_vless(c: &mut Criterion) {
    let urls = load_urls("vless");
    if urls.is_empty() {
        return;
    }
    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_try_parse/vless");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("try_parse", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(VlessConfig::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

fn bench_proto_try_parse_vmess(c: &mut Criterion) {
    let urls = load_urls("vmess");
    if urls.is_empty() {
        return;
    }
    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_try_parse/vmess");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("try_parse", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(VmessConfig::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

fn bench_proto_try_parse_trojan(c: &mut Criterion) {
    let urls = load_urls("trojan");
    if urls.is_empty() {
        return;
    }
    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_try_parse/trojan");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("try_parse", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(TrojanConfig::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

fn bench_proto_try_parse_ss(c: &mut Criterion) {
    let urls = load_urls("ss");
    if urls.is_empty() {
        return;
    }
    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_try_parse/ss");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("try_parse", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(SsConfig::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

fn bench_proto_try_parse_ssr(c: &mut Criterion) {
    let urls = load_urls("ssr");
    if urls.is_empty() {
        return;
    }
    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_try_parse/ssr");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(200);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("try_parse", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(SsrConfig::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

fn bench_proto_try_parse_hysteria2(c: &mut Criterion) {
    let urls = load_urls("hy2");
    if urls.is_empty() {
        return;
    }
    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_try_parse/hy2");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("try_parse", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(Hysteria2Config::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

fn bench_proto_try_parse_tuic(c: &mut Criterion) {
    let urls = load_urls("tuic");
    if urls.is_empty() {
        return;
    }
    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_try_parse/tuic");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(200);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("try_parse", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(TuicConfig::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

fn bench_proto_try_parse_wireguard(c: &mut Criterion) {
    let urls = load_urls("wireguard");
    if urls.is_empty() {
        return;
    }
    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_try_parse/wireguard");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(200);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("try_parse", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(WireguardConfig::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

fn bench_proto_config_dispatch(c: &mut Criterion) {
    let data = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/benches/data/mixed.txt"));
    let urls: Vec<String> = data
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();

    if urls.is_empty() {
        return;
    }

    let raw_urls: Vec<RawUrlX> = urls.iter().map(|u| RawUrlX::from(u.as_str())).collect();

    let mut group = c.benchmark_group("proto_config_dispatch");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Elements(raw_urls.len() as u64));
    group.bench_function("mixed", |b| {
        b.iter(|| {
            for raw in &raw_urls {
                std::hint::black_box(ProtocolConfig::try_parse(raw).ok());
            }
        })
    });
    group.finish();
}

criterion_group! {
    name = proto_spec;
    config = Criterion::default()
        .sample_size(500)
        .warm_up_time(Duration::from_secs(3));
    targets =
        bench_proto_try_parse_vless,
        bench_proto_try_parse_vmess,
        bench_proto_try_parse_trojan,
        bench_proto_try_parse_ss,
        bench_proto_try_parse_ssr,
        bench_proto_try_parse_hysteria2,
        bench_proto_try_parse_tuic,
        bench_proto_try_parse_wireguard,
        bench_proto_config_dispatch,
}
criterion_main!(proto_spec);
