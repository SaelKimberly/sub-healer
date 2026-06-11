# v2ray-heal

Rust proxy subscription miner/aggregator: scrapes Telegram channels + downloads subscription files → normalizes, deduplicates, validates → persists to SQLite with time-travel upsert.

## Quick Commands

```bash
rtk cargo check                 # lint
rtk cargo test                  # all tests (155 pass, 3 ignored)
rtk cargo test registry         # SourceRegistry tests
cargo run -- config              # full pipeline from config.yaml
cargo run -- config path.yaml   # full pipeline from custom config
cargo run -- remote https://t.me/s/channel  # scrape telegram channel
cargo run -- remote https://example.com/sub.txt  # download sub URL
cargo run -- local ./file.txt   # parse local file
cat sub.txt | cargo run -- stdin # parse from pipe
cargo run -- emit --protocol vmess  # export filtered servers
cargo bench                      # criterion benchmarks
```

## CLI

- **`config`**: Full pipeline from YAML. Optional `tgchannel:` (list) and `subscriptions:` list — supports `https://` (HTTP download, GITHUB_TOKEN env for github.com) and `file://`. Unsupported schemes → skip with `tracing::error!`.
- **`stdin`**: Pipe → `parse_to_raw_urls()` → DB upsert. Source type: `Other`, registry key `stdin://local`.
- **`remote`**: Download subs from URLs or scrape Telegram (t.me auto-detected via host check). Mixed batch OK.
- **`local`**: Filesystem → `parse_to_raw_urls()` → DB upsert. Source URL = `file://` absolute path.
- **`emit`**: Filtered server export. `--protocol` (repeatable, case-insensitive), `--min-first-seen-ts`, `--min-last-seen-ts` (humantime durations), `--pull` (re-mine all DB sources, optionally with per-source Telegram backfill). Reconstructs native URLs from stored `ProtocolConfig` JSON.

Global `--db` flag (default `v2ray-heal.db`). Unparseable log: `V2RAY_HEAL_UNPARSEABLE_LOG` env (default `unparseable.ndjson`).

## Architecture

**Two-layer pipeline** — `urlx/` splits URI → `proto_spec/` parses into typed configs:

1. `SchemeX::slice_input()` / `RawUrlX::from(str)` splits URI → schema/userinfo/hostport/path/query/fragment
2. `ProtocolConfig::try_parse_detailed(&raw)` dispatches by `SchemeX` → three-outcome result (Direct / Fallback / Unparseable)
3. On `Fallback` result, retry chain: SS→SSR→VMess→VLESS→Trojan→Hysteria2→Slipnet→TG
4. `reconstruct()` builds canonical URL back from parsed fields

`dispatch!` macro delegates all `ProtoSpec` trait methods across 12 `ProtocolConfig` variants.

## Streaming Decoder (`src/decoder.rs`)

Chunked base64 decoder that processes subscription data incrementally:

- `feed(chunk) → anyhow::Result<Vec<String>>` — align input to 4-byte base64 boundaries,
  auto-detect encoding (Standard/UrlSafe/Raw), decode and split on `\n`
- `finalize() → anyhow::Result<Vec<String>>` — flush remaining input
- `reset()` — clear state for re-use
- `INPUT_CHUNK_SIZE = 65536` — chunks larger than this cause a hard error

Callers MUST pre-slice to ≤ `INPUT_CHUNK_SIZE`; passing a larger chunk causes a hard error.

## Mining Pipeline

```
Pipeline::new(db_path)
  .add_source(url) or .add_batch_raw(items)
  .set_backfill(Backfill::Last(duration))
  .run()
  → Upsert registered sources to DB
  → Build fetcher streams (Telegram fetch_tg_channels, Subscription fetch_subscriptions, batch items)
  → Merge via futures::stream::select
  → For each RawSourceItemBatch: lazy source upsert → try_parse_detailed → upsert_server
```

Fetchers use `create_stream(url)` which returns `Pin<Box<dyn Stream<Item = Result<Bytes, StreamError>> + Send + Sync>>`
handling `stdin`, `http`/`https` (with up to 3 retries), and `file` schemes. Subscription fetching eliminates
per-scheme dispatch — all schemes flow through `create_stream`.

**DB failures are fatal** — `upsert_server` uses `.context("... (aborting)")?`. No in-memory dedup — `servers.id` (= `ProtocolConfig::uid()`) PK handles uniqueness.

## Unparseable URL Capture

NDJSON via tracing layer (`target: "mining::unparseable"`). Fields: `raw_url`, `scheme`, `error`, `source_id`, `source_type`, `timestamp`. Emitted at consumer level (where `source_id` from registry is available), not in parsing layer.

## Database Schema

- **`sources`** — `id` (INTEGER PK, hash of URL via RapidStreamHasherV3), `url` (TEXT)
- **`servers`** — `id` (i64 = ProtocolConfig::uid), schema, host, port, transport, security, remarks, `raw_config` (ProtocolConfig JSON), first_seen_ts, first_seen_source_id → FK sources(id)
- **`sightings`** — server_id, source_id, seen_ts, remarks

Time-travel: if incoming_ts < first_seen_ts, archive current to sightings + replace.

## Key Technical Details

- **Rust**: Edition 2024, requires 1.96.0+ (stable, rustfmt + clippy in toolchain)
- **Global Allocator**: `mimalloc` (via `#[global_allocator]`)
- **Linker**: `clang` + `mold` (`.cargo/config.toml`)
- **Concurrency**: `tokio` (async I/O) + `rayon` (parallel CPU for line processing)
- **Database**: `rusqlite` bundled
- **Proxy**: Environment-based HTTP proxy (`HTTP_PROXY` env var, restricted to 127.0.0.1/localhost);
  basic auth via `HTTP_PROXY_USERNAME`/`HTTP_PROXY_PASSWORD`; `127.0.0.1:20172` fallback only in `#[cfg(test)]`.
  Connect timeout 30s, read timeout 5s.
- **GITHUB_TOKEN**: env var for bearer auth on `raw.githubusercontent.com` / `github.com` requests
- **ProtocolConfig.uid**: `uid = sig ^ rapidhash_v3(host:port:username:password)`. SlipnetEnc: `uid == sig`.
- **ProtoSpec**: `try_parse()`, `reconstruct()`, `schema()`, `host()`, `port()`, `uid()` (= `sig() ^ cred_hash()`). 12 impls: Vless, Vmess, Trojan, Hysteria2, Ss, Ssr, Tg, Slipnet, SlipnetEnc, Stormdns, Tuic, Wireguard.
- **sig_cache**: `OnceLock<NonZeroU64>` per config instance — computed once, cached forever.
- **`thirdparty/`**: vendored upstream proxy projects (sing-box, Xray, hysteria, etc.) — not part of build
- **`benches/`**: Criterion benchmarks (`cargo bench`) with test data per protocol: raw_urlx, proto_spec, slice_input, permissive_json
- **`normalize_extras`**: Uses `simd_json::to_string` (not `serde_json`) and parallelizes `extra=` segments via `rayon`

## Pre-existing Test Status

**0 failures**. Test suite: 155 passed, 3 ignored (manual integration tests that fetch real Telegram data). Previous 5 failures (VMess→SS fallback, SSR InvalidStructure, SlipnetEnc, WireGuard, Warp) were fixed during the proto_spec unification.

## Tools

- **memelord** MCP memory system (`memory_start_task` / `memory_end_task` / `memory_report`).
