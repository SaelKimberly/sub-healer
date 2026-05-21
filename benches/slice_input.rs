use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use v2ray_heal::normalize_extras;
use v2ray_heal::urlx::SchemeX;

fn load_raw_subscription_data() -> Vec<Vec<u8>> {
    let manifest = env!("CARGO_MANIFEST_DIR");

    // Use a few smaller subscription files for realistic mixed input
    let files = [
        format!("{manifest}/thirdparty/v2ray-configs/Sub1.txt"),
        format!("{manifest}/thirdparty/v2ray-configs/Sub2.txt"),
        format!("{manifest}/thirdparty/v2ray-configs/Sub3.txt"),
        format!("{manifest}/thirdparty/v2ray-configs/All_Configs_Sub.txt"),
    ];

    let mut chunks = Vec::new();
    for path in files {
        if let Ok(content) = std::fs::read_to_string(&path) {
            chunks.push(content.into_bytes());
        }
    }
    chunks
}

fn bench_scheme_slice_input(c: &mut Criterion) {
    let raw_data = load_raw_subscription_data();

    // Normalize each chunk
    let normalized: Vec<String> = raw_data
        .into_iter()
        .map(|data| {
            let decoded = base64_decode_or_raw(&data);
            let fixed = normalize_extras(&decoded);
            String::from_utf8_lossy(&fixed).to_string()
        })
        .collect();

    let combined: String = normalized.join("\n");

    let mut group = c.benchmark_group("scheme_slice_input");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(200);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Bytes(combined.len() as u64));
    group.bench_function("mixed", |b| {
        b.iter(|| {
            std::hint::black_box(SchemeX::slice_input(&combined));
        })
    });
    group.finish();
}

fn base64_decode_or_raw(input: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    use base64::Engine;
    let mut end = input.len();
    while end > 0 && (input[end - 1] == b'=' || input[end - 1].is_ascii_whitespace()) {
        end -= 1;
    }
    let trimmed = &input[..end];
    base64::prelude::BASE64_STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(trimmed))
        .map(std::borrow::Cow::Owned)
        .unwrap_or(std::borrow::Cow::Borrowed(input))
}

criterion_group! {
    name = slice_input;
    config = Criterion::default()
        .sample_size(200)
        .warm_up_time(Duration::from_secs(3));
    targets = bench_scheme_slice_input
}
criterion_main!(slice_input);
