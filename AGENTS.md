# v2ray-heal Agent Instructions

## Project Purpose

**v2ray-heal** is a Rust-based proxy subscription miner and aggregator that:
- Scrapes Telegram channels for V2Ray proxy URLs (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, etc.)
- Downloads and parses v2ray subscription files from URLs
- Parses, normalizes, and deduplicates proxy configurations
- Validates connectivity and outputs curated subscription lists
- Persists data to SQLite with time-travel upsert semantics to track origin and lifetime of every parsed config URL

## Quick Commands

```bash
# Task runner (wraps cargo with config)
rtk cargo check
rtk cargo test
rtk cargo build

# Run specific test (filter by name)
rtk cargo test test_vless
rtk cargo test test_trojan
rtk cargo test test_hysteria2
rtk cargo test test_tg

# Run mining pipeline
cargo run --bin v2ray-heal -- mine

# CPU flamegraph (requires: cargo install flamegraph && sudo apt install linux-tools-common linux-tools-$(uname -r))
cargo flamegraph --bin v2ray-heal -- mine

# With custom frequency or duration
cargo flamegraph -c "freq=100" --bin v2ray-heal -- mine

# Memory flamegraph
cargo flamegraph -m --bin v2ray-heal -- mine
```

## Memory System

The repo uses `memelord` MCP for persistent memory across sessions. Configured in `opencode.json`.

**At session start**: ALWAYS call `memelord_memory_start_task()` with your task description first to retrieve relevant past memories.

**At session end**: Call `memelord_memory_end_task()` to report outcome metrics.

**During work**: Use `memelord_memory_report()` to store insights, corrections, or user-provided knowledge that should persist across sessions.

## CLI Entrypoint

`v2ray-heal mine` — runs the full mining pipeline:
1. Telegram channel scraping (fetch → extract → validate)
2. v2ray subscription file downloading and parsing
3. Output to SQLite database with origin tracking and lifetime analysis

**Note**: Only `mine` subcommand is implemented. Other subcommands (`remote`, `local`, `config`, `stdin`) are `todo!()`.

## Project Structure

- **`src/lib.rs`** — core library: subscription parsing, `UrlX` deduplication, download pipeline
- **`src/urlx/`** — new URL parsing module (in development): `parse_url.rs`, `split_url.rs`, `user_info.rs`, `schemex.rs`, `port_spec.rs`
  - **`src/urlx/mod.rs`** — `UrlX` struct (new, distinct from legacy in utils/urlx.rs), `ProtoVisitor` trait
  - **`src/urlx/proto_vis/`** — protocol implementations: `vmess.rs`, `vless.rs`, `trojan.rs`, `ss.rs`, `ssr.rs`, `hysteria2.rs`, `slipnet.rs`, `tg.rs`
- **`src/utils/`** — `urlx.rs` (legacy URL parse/normalize), `line.rs` (batch processing), `port.rs`, `host_port.rs`, `permissive_json.rs`
- **`src/mining/`** — Telegram channel scraper: `telegram.rs`, `extractor.rs`, `validator.rs`, `output.rs`, `config.rs`
- **`src/db.rs`** — SQLite persistence: `sources`, `servers`, `sightings` tables with time-travel upsert
- **`src/main.rs`** — CLI with `mine`, `remote`, `local`, `config` subcommands

## Database Schema

- **`sources`** — `id` (INTEGER PRIMARY KEY, hash of URL), `url` (TEXT)
- **`servers`** — `id` (u64 rapidhash), schema, host, port, transport, security, remarks (plain UTF-8), raw_config (JSON), first_seen_ts, first_seen_source_id
- **`sightings`** — server_id, source_id, seen_ts, remarks (plain UTF-8)

## Key Technical Details

- **Rust**: Edition 2024, requires Rust 1.95.0+
- **Global Allocator**: `mimalloc`
- **Concurrency**: `tokio` (async I/O) + `rayon` (parallel CPU)
- **Database**: `rusqlite` with `bundled` feature
- **Time**: `chrono` for RFC3339 timestamp parsing

## UrlX Important Notes

- **Fragment storage**: Stored as plain UTF-8 in `UrlX` and DB. Percent-encoded only in `Display` impl.
- **Normalization**: Must call `normalize(&mut None)` to compute `id` (rapidhash) and validate host+port
- **ServerName**: Use `host_str()` method to get string representation (not `to_str()` directly)

## Sig/Uid Computation

- **`sig`** (signature): u64 rapidhash v3 of non-credential connection parameters (schema + transport + security + query). Computed in `visit()` function of each `ProtoVisitor` implementation.
- **`uid`** (unique ID): XOR of `sig` and rapidhash v3 of server credentials (host + port + username + password). For `SlipnetEnc`, `uid == sig` since there are no exposed credentials.
- **Location**: Each protocol's `visit()` in `src/urlx/proto_vis/*.rs` computes its own sig/uid per protocol-specific rules.

## ProtoVisitor Trait

```rust
pub trait ProtoVisitor {
    fn parse(raw: &RawUrlX<'_>) -> Result<UrlX, ParseError>;
    fn build(url: &UrlX) -> Result<String, ParseError>;
    fn visit(url: &mut UrlX) -> Result<(), ParseError>;  // computes sig/uid
}
```

All 9 protocols implement this: Vmess, Vless, Trojan, Hysteria2, SS, SSR, Slipnet, SlipnetEnc, Tg.

## Mining Pipeline

```
fetch_all_channels() 
    → scraper iterates .js-widget_message_wrap
    → TimestampedProxy { urlx, timestamp, source_url }
    → upsert_source() per channel (cache to HashMap)
    → upsert_server() with correct source_id from HashMap
```

## Reference Sources

- `src/utils/urlx.rs` — proxy URL parsing, normalization, fragment handling
- `src/urlx/` — new URL parsing module (replaces utils/urlx.rs)
- `src/urlx/proto_vis/mod.rs` — protocol visitor trait, helper functions for sig/uid
- `src/urlx/proto_vis/*.rs` — protocol-specific implementations with visit() for sig/uid
- `src/db.rs` — SQLite schema, time-travel upsert logic
- `src/mining/mod.rs` — DB integration flow
