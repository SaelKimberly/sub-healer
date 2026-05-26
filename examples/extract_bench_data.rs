use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use base64::Engine;
use v2ray_heal::normalize_extras;
use v2ray_heal::urlx::SchemeX;

const DATA_DIR: &str = "benches/data";
const MAX_PER_PROTOCOL: usize = 200;

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
    let Ok(entries) = fs::read_dir(dir) else {
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

fn extract_urls_from_file(path: &PathBuf) -> Vec<String> {
    let content = match fs::read(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let decoded = base64_try_decode(&content);
    let normalized = normalize_extras(&decoded);
    let Ok(text) = String::from_utf8(normalized.into_owned()) else {
        return Vec::new();
    };

    let mut urls = Vec::new();
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
                urls.push(url_part.to_string());
            }
        }
    }
    urls
}

fn main() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DATA_DIR);
    fs::create_dir_all(&out_dir).expect("create benches/data dir");

    // Discover subscription files from thirdparty directories
    let goida_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("thirdparty")
        .join("goida-vpn-configs")
        .join("githubmirror");
    let v2ray_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("thirdparty")
        .join("v2ray-configs");

    // Also use v2ray.txt from root if it exists
    let root_txt = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("v2ray.txt");

    let mut protocol_urls: BTreeSet<(String, String)> = BTreeSet::new();

    // Source directories
    let source_dirs = vec![goida_dir, v2ray_dir];

    for dir in &source_dirs {
        for file_path in discover_txt_files(&dir.to_string_lossy()) {
            let urls = extract_urls_from_file(&file_path);
            let count = urls.len();
            for url in &urls {
                if let Some(scheme_end) = url.find("://") {
                    let scheme_str = &url[..scheme_end];
                    let scheme: SchemeX = scheme_str.parse().unwrap();
                    if !matches!(scheme, SchemeX::Unknown(_) | SchemeX::Https) {
                        protocol_urls.insert((scheme.as_str().to_string(), url.clone()));
                    }
                }
            }
            eprintln!(
                "  {}: {} URLs",
                file_path.file_name().unwrap().to_string_lossy(),
                count
            );
        }
    }

    // Also process v2ray.txt
    if root_txt.exists() {
        let urls = extract_urls_from_file(&root_txt);
        let count = urls.len();
        for url in &urls {
            if let Some(scheme_end) = url.find("://") {
                let scheme_str = &url[..scheme_end];
                let scheme: SchemeX = scheme_str.parse().unwrap();
                if !matches!(scheme, SchemeX::Unknown(_) | SchemeX::Https) {
                    protocol_urls.insert((scheme.as_str().to_string(), url.clone()));
                }
            }
        }
        eprintln!("  v2ray.txt: {} URLs", count);
    }

    // Group by protocol and write files
    let mut by_protocol: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();

    for (protocol, url) in &protocol_urls {
        by_protocol
            .entry(protocol.clone())
            .or_default()
            .push(url.clone());
    }

    let protocols: &[&str] = &[
        "vless",
        "vmess",
        "trojan",
        "ss",
        "ssr",
        "hy2",
        "tuic",
        "wireguard",
        "slipnet",
        "stormdns",
        "tg",
    ];

    let mut mixed_urls: Vec<String> = Vec::new();

    for protocol in protocols {
        let urls = by_protocol.get(*protocol).cloned().unwrap_or_default();
        let count = urls.len().min(MAX_PER_PROTOCOL);

        let dest = out_dir.join(format!("{protocol}.txt"));
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest)
            .expect("open output file");

        for url in urls.iter().take(count) {
            writeln!(f, "{url}").ok();
            mixed_urls.push(url.clone());
        }

        eprintln!(
            "  -> benches/data/{protocol}.txt: {count} URLs ({} available)",
            urls.len()
        );
    }

    // Write mixed.txt with all protocols interleaved (up to 100 per protocol)
    let mixed_dest = out_dir.join("mixed.txt");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&mixed_dest)
        .expect("open mixed.txt");

    // Shuffle for realistic interleaving: take up to 100 from each protocol round-robin
    let chunk_size = 100;
    let chunks: Vec<Vec<String>> = protocols
        .iter()
        .filter_map(|p| {
            let urls = by_protocol.get(*p)?;
            Some(urls.iter().take(chunk_size).cloned().collect::<Vec<_>>())
        })
        .collect();

    if chunks.is_empty() {
        eprintln!("  -> benches/data/mixed.txt: 0 URLs (no data)");
    } else {
        let max_len = chunks.iter().map(|c| c.len()).max().unwrap_or(0);
        for i in 0..max_len {
            for chunk in &chunks {
                if let Some(url) = chunk.get(i) {
                    writeln!(f, "{url}").ok();
                }
            }
        }
        let total = chunks.iter().map(|c| c.len()).sum::<usize>();
        eprintln!("  -> benches/data/mixed.txt: {total} URLs (round-robin)");
    }

    eprintln!("Done.");
}
