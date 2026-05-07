# v2ray-heal Agent Instructions

## Quick Commands

```bash
# Task runner (wraps cargo with config)
rtk cargo check
rtk cargo test
rtk cargo build

# Run specific test
rtk cargo test permissive_json

# Run mining pipeline
cargo run --bin v2ray-heal -- mine
```

## Memory System

The repo uses `memelord` MCP for persistent memory across sessions. Configured in `opencode.json`.

**At session start**: ALWAYS call `memelord_memory_start_task()` with your task description first to retrieve relevant past memories.

**At session end**: Call `memelord_memory_end_task()` to report outcome metrics.

**During work**: Use `memelord_memory_report()` to store insights, corrections, or user-provided knowledge that should persist across sessions.

## CLI Entrypoint

`v2ray-heal mine` — runs the Telegram channel mining pipeline (fetch → extract → validate → output to DB + files).

**Note**: Only `mine` subcommand is implemented. Other subcommands (`remote`, `local`, `config`, `stdin`) are `todo!()`.

## Project Structure

- **`src/lib.rs`** — core library: subscription parsing, `UrlX` deduplication, download pipeline
- **`src/urlx/`** — new URL parsing module (in development): `parse_url.rs`, `split_url.rs`, `user_info.rs`, `schemex.rs`, `port_spec.rs`
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
- `src/db.rs` — SQLite schema, time-travel upsert logic
- `src/mining/mod.rs` — DB integration flow
