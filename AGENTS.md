# v2ray-heal

Rust proxy subscription miner/aggregator: scrapes Telegram channels + downloads subscription files → normalizes, deduplicates, validates → persists to SQLite with time-travel upsert.

## Quick Commands

```bash
rtk cargo check                 # lint
rtk cargo test                  # all tests (98 pass, 3 ignored)
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

- **`config`**: Full pipeline from YAML. `config.yaml` must have `tgchannel:` (list). Optional `subscriptions:` list — supports `https://` (HTTP download, GITHUB_TOKEN env for github.com) and `file://`. Unsupported schemes → skip with `tracing::error!`.
- **`stdin`**: Pipe → `parse_sub()` → DB upsert. Source type: `Other`, registry key `stdin://local`.
- **`remote`**: Download subs from URLs or scrape Telegram (t.me auto-detected via host check). Mixed batch OK.
- **`local`**: Filesystem → `parse_sub()` → DB upsert. Source URL = `file://` absolute path.
- **`emit`**: Filtered server export. `--protocol` (repeatable, case-insensitive), `--min-first-seen-ts`, `--min-last-seen-ts` (humantime durations). Reconstructs native URLs from stored `ProtocolConfig` JSON.

Global `--db` flag (default `v2ray-heal.db`). Unparseable log: `V2RAY_HEAL_UNPARSEABLE_LOG` env (default `unparseable.ndjson`).

## Architecture

**Single parser layer** — `proto_spec/` (11 typed config parsers):

1. `RawUrlX::from(str)` splits URI → schema/userinfo/hostport/path/query/fragment
2. `ProtocolConfig::try_parse(&raw)` dispatches by `SchemeX` → protocol-specific parse
3. On recoverable error, fallback chain: SS→SSR→VMess→VLESS→Trojan→Hysteria2→Slipnet→TG
4. `reconstruct()` builds canonical URL back from parsed fields

`dispatch!` macro delegates all `ProtoSpec` trait methods across 12 `ProtocolConfig` variants.

## Mining Pipeline

```
run_with_config(path, db_path):
  1. build_client() → reqwest::Client (proxy PROXY_URL, 30s timeout)
  2. open_db(db_path) → init_db schema
  3. SourceRegistry::from_config(config_path) → pre-populate + upsert_all
  4. registry.run_pipeline(client, conn)
     → LiveFetcher::fetch() merges Telegram + subscription streams
     → process_config_stream() upserts sources + servers
```

**DB failures are fatal** — `upsert_server` uses `.context("... (aborting)")?`. No in-memory dedup — `servers.id` (= `ProtocolConfig::uid()`) PK handles uniqueness.

## Unparseable URL Capture

NDJSON via tracing layer (`target: "mining::unparseable"`). Fields: `raw_url`, `scheme`, `error`, `source_id`, `source_type`, `timestamp`. Emitted at consumer level (where `source_id` from registry is available), not in parsing layer.

## Database Schema

- **`sources`** — `id` (INTEGER PK, hash of URL via DefaultHasher), `url` (TEXT)
- **`servers`** — `id` (i64 = ProtocolConfig::uid), schema, host, port, transport, security, remarks, `raw_config` (ProtocolConfig JSON), first_seen_ts, first_seen_source_id → FK sources(id)
- **`sightings`** — server_id, source_id, seen_ts, remarks

Time-travel: if incoming_ts < first_seen_ts, archive current to sightings + replace.

## Key Technical Details

- **Rust**: Edition 2024, requires 1.95.0+ (stable, rustfmt + clippy in toolchain)
- **Global Allocator**: `mimalloc` (via `#[global_allocator]`)
- **Linker**: `clang` + `mold` (`.cargo/config.toml`)
- **Concurrency**: `tokio` (async I/O) + `rayon` (parallel CPU for line processing)
- **Database**: `rusqlite` bundled
- **Proxy**: HTTP proxy at `http://127.0.0.1:20172` (`PROXY_URL` constant)
- **User-Agent**: `"clash-verge/v2.0.2"`
- **GITHUB_TOKEN**: env var for bearer auth on `raw.githubusercontent.com` / `github.com` requests
- **ProtocolConfig.uid**: `uid = sig ^ rapidhash_v3(host:port:username:password)`. SlipnetEnc: `uid == sig`.
- **ProtoSpec**: `try_parse()`, `reconstruct()`, `schema()`, `host()`, `port()`, `uid()` (= `sig() ^ cred_hash()`). 12 impls: Vless, Vmess, Trojan, Hysteria2, Ss, Ssr, Tg, Slipnet, SlipnetEnc, Stormdns, Tuic, Wireguard.
- **sig_cache**: `OnceLock<NonZeroU64>` per config instance — computed once, cached forever.
- **`thirdparty/`**: vendored upstream proxy projects (sing-box, Xray, hysteria, etc.) — not part of build
- **`benches/`**: Criterion benchmarks (`cargo bench`) with test data per protocol: raw_urlx, proto_spec, slice_input, permissive_json

## Pre-existing Test Status

**0 failures**. Test suite: 98 passed, 3 ignored (manual integration tests that fetch real Telegram data). Previous 5 failures (VMess→SS fallback, SSR InvalidStructure, SlipnetEnc, WireGuard, Warp) were fixed during the proto_spec unification.

## Tools

- **memelord** MCP memory system (`memory_start_task` / `memory_end_task` / `memory_report`).
