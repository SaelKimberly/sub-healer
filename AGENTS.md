# v2ray-heal Agent Instructions

## Project

Rust proxy subscription miner/aggregator: scrapes Telegram channels + downloads subscription files → normalizes, deduplicates, validates → persists to SQLite with time-travel upsert.

## Quick Commands

```bash
rtk cargo check          # lint
rtk cargo test           # all tests
rtk cargo test registry  # SourceRegistry tests
cargo run -- mine        # run full pipeline (needs config.yaml)
```

## Memory System

`memelord` MCP configured in `opencode.json`. Call `memory_start_task()` at session start, `memory_end_task()` at end, `memory_report()` to persist insights.

## CLI

Only `mine` subcommand implemented. Others (`stdin`, `config`, `remote`, `local`) are `todo!()`.

**config.yaml** must have `tgchannel:` (list). Optional `subscriptions:` list — supports `https://` (HTTP download, GITHUB_TOKEN env for github.com) and `file://` (filesystem). Unsupported schemes → `tracing::error!` + skip.

**Unparseable URL log**: Set `V2RAY_HEAL_UNPARSEABLE_LOG` env var to path (default `unparseable.ndjson`). Captures all parse failures (unknown schemes + structurally-invalid known schemes) as NDJSON via tracing layer.

## Project Structure

- **`src/lib.rs`** — public API: `parse_sub()`, `UrlX`, `Lines`, subscription decoding
- **`src/urlx/`** — `UrlX` struct, `RawUrlX` parser, `SchemeX`, protocol visitors, `try_accept_raw()` dispatcher
  - **`src/urlx/proto_vis/`** — 9 protocol implementations: Vmess, Vless, Trojan, SS, SSR, Hysteria2, Slipnet, SlipnetEnc, Tg
- **`src/db.rs`** — SQLite persistence: `sources`, `servers`, `sightings` tables. `upsert_server()` serializes `UrlX` directly to JSON (no wrapper struct). Time-travel upsert: if incoming timestamp is earlier than `first_seen_ts`, archives current record to `sightings` and replaces.
- **`src/mining/`** — pipeline modules:
  - `config.rs` — load `tgchannel:` + `subscriptions:` from config.yaml
  - `registry.rs` — `SourceRegistry` (pre-populate, upsert_all, lookup), `SourceMetadata`, `TimestampedProxy`
  - `telegram.rs` — Telegram web scraper: `TgWebMessage` carries both `msg_urls: Option<Box<[UrlX]>>` and `unparseable_urls: Option<Box<[UnparseableRecord]>>`
  - `sub.rs` — subscription fetcher: `fetch_timestamped_subs(client, registry, config_path)`
  - `unparseable_log.rs` — `UnparseableLayer` (tracing_subscriber::Layer, filters `target == "mining::unparseable"`)
  - `mod.rs` — `run()` orchestrator, shared reqwest::Client, consumer loop, re-exports key types
  - `fetcher.rs`, `extractor.rs`, `validator.rs`, `output.rs`, `error.rs` — old pipeline code (unchanged, some unused)

## Mining Pipeline

```
run():
  1. Open DB → init_db
  2. Load config (channels + subscriptions from config.yaml)
  3. Create reqwest::Client (shared, proxy via PROXY_URL, 30s timeout)
  4. Pre-populate SourceRegistry from channels + subscriptions
  5. registry.upsert_all(&conn) — batch upsert sources
  6. Telegram phase: consume fetch_tg_channels() stream
       → per message: registry.lookup(source_url) → emit unparseable events → db::upsert_server (fatal on failure)
  7. Subscription phase: fetch_timestamped_subs()
       → per parsed line: emit unparseable events → db::upsert_server (fatal on failure)
```

**DB failures are fatal** — `upsert_server` uses `.context("... (aborting)")?`.

No in-memory dedup — `servers.id` (= `urlx.uid`) PRIMARY KEY handles uniqueness at DB level.

## Telegram Stream

- `TgWebMessage.msg_urls`: already-parsed `UrlX` values (parse failures captured as `UnparseableRecord`)
- URL strings parsed via `try_accept_raw()`
- Parse failures: `tracing::warn!` at detection, `tracing::warn!(target: "mining::unparseable")` at emission
- Schema whitelist removed — all `*://` patterns flow to `try_accept_raw`

## Subscriptions

- `parse_sub()` (lib.rs) → base64 decode → `Lines::new_raw().processed()`
- `Lines.raw_entries()` — `Data::Raw` entries preserved (not silently dropped by `_visit_line`)
- `file://` paths via `url.to_file_path()`, `https://` via shared client with optional `GITHUB_TOKEN` bearer auth

## Unparseable URL Capture

NDJSON log via tracing layer (`target: "mining::unparseable"`). Fields: `raw_url`, `scheme`, `error`, `source_id` (DB pk), `source_type` ("telegram"|"subscription"), `timestamp`. Emission happens at consumer level (where `source_id` from registry is available), not in parsing layer.

## Database Schema

- **`sources`** — `id` (INTEGER PRIMARY KEY, hash of URL), `url` (TEXT)
- **`servers`** — `id` (u64 rapidhash as i64), schema, host, port, transport, security, remarks, `raw_config` (UrlX JSON), `first_seen_ts`, `first_seen_source_id` → FK sources(id)
- **`sightings`** — server_id, source_id, seen_ts, remarks

## Key Technical Details

- **Rust**: Edition 2024, requires 1.95.0+
- **Global Allocator**: `mimalloc`
- **Concurrency**: `tokio` (async I/O) + `rayon` (parallel CPU for line processing)
- **Database**: `rusqlite` bundled
- **Proxy**: HTTP proxy at `http://127.0.0.1:20172` (PROXY_URL constant)
- **User-Agent**: `"clash-verge/v2.0.2"`

## UrlX Notes

- Fragment stored as plain UTF-8; percent-encoded only in `Display`
- Call `normalize(&mut None)` to compute `id` (rapidhash) and validate host+port
- Use `host_str()` for string representation (not `to_str()` directly)
- `Data::Raw.scheme` is `Cow<'static, str>` (not `&'static str`) — allows dynamic unknown schemes

## Sig/Uid

- **`sig`**: rapidhash v3 of non-credential params (schema + transport + security + query)
- **`uid`**: `sig ^ rapidhash_v3(host:port:username:password)`. For SlipnetEnc, `uid == sig`.
- Each protocol's `visit()` in `proto_vis/*.rs` computes own sig/uid.

## ProtoVisitor

```rust
pub trait ProtoVisitor {
    fn parse(raw: &RawUrlX<'_>) -> Result<UrlX, ParseError>;
    fn build(url: &UrlX) -> Result<String, ParseError>;
    fn visit(url: &mut UrlX) -> Result<(), ParseError>;  // computes sig/uid
}
```

9 implementations: Vmess, Vless, Trojan, SS, SSR, Hysteria2, Slipnet, SlipnetEnc, Tg. WireGuard and Hysteria are recognized by `SchemeX` but have no working parser (fall back to other visitors or return `UnsupportedScheme`).

## Pre-existing Test Failures (8 tests)

Known failures not related to pipeline changes:
- VMess→SS fallback mismatch
- SSR InvalidStructure
- SlipnetEnc InvalidUserInfo
- WireGuard stub (`UnsupportedScheme`)
- Warp not implemented (affects `test_download_sub`)
