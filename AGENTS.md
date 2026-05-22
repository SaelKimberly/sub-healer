# v2ray-heal

Rust proxy subscription miner/aggregator: scrapes Telegram channels + downloads subscription files → normalizes, deduplicates, validates → persists to SQLite with time-travel upsert.

## Quick Commands

```bash
rtk cargo check          # lint
rtk cargo test           # all tests (30 pass, 5 pre-existing fail)
rtk cargo test registry  # SourceRegistry tests only
cargo run -- config              # full pipeline from config.yaml
cargo run -- config path.yaml    # full pipeline from custom config
cargo run -- remote https://t.me/s/channel  # scrape telegram channel
cargo run -- remote https://example.com/sub.txt  # download sub URL
cargo run -- local ./file.txt    # parse local file
cat sub.txt | cargo run -- stdin # parse from pipe
cargo run --example parse_real_subs  # coverage test against thirdparty data
cargo bench                     # criterion benchmarks (raw_urlx, proto_spec, slice_input)
```

## CLI

- **`config`**: Full pipeline from YAML. `config.yaml` must have `tgchannel:` (list). Optional `subscriptions:` list — supports `https://` (HTTP download, GITHUB_TOKEN env for github.com) and `file://`. Unsupported schemes → skip with `tracing::error!`.
- **`stdin`**: Pipe → `parse_sub()` → DB upsert. Source type: `Other`, registry key `stdin://local`.
- **`remote`**: Download subs from URLs or scrape Telegram (t.me auto-detected via host check). Mixed batch OK.
- **`local`**: Filesystem → `parse_sub()` → DB upsert. Source URL = `file://` absolute path.

Global `--db` flag (default `v2ray-heal.db`). Unparseable log: `V2RAY_HEAL_UNPARSEABLE_LOG` env (default `unparseable.ndjson`).

## Architecture

**Two parser layers:**

1. **`urlx/proto_vis/`** (9 visitors) — raw string → `UrlX` (generic URL struct with uid/sig). Dispatched via `try_accept_raw()`. Fallback chain: SS→SSR→Vmess→Vless→Trojan→Hysteria2→Slipnet→Tg.
2. **`proto_spec/`** (11 config parsers) — `RawUrlX` → `ProtocolConfig` (typed config enum with host/port/transport/security). Fallback same order. Adds Stormdns, Tuic, WireGuard parsers.

`src/proto_spec/mod.rs` has `ProtocolConfig` enum with all 11 variants and the fallback dispatch. `src/proto_spec/common.rs` defines transport config types (TCP, WS, gRPC, HTTP, QUIC, KCP).

`src/urlx/mod.rs` — `UrlX` struct (uid, sig, schema, host, port, username, password, path, query, fragment, transport, security). `reconstruct()` builds URL string back.

`src/utils/line.rs` — `Lines` / `Line` / `Data` types. `split_at_scheme()` handles concatenated URLs. `parse_sub()` (lib.rs) → base64 decode → `normalize_extras()` → `Lines::new_raw().processed()`.

## Mining Pipeline

```
run_with_config(path, db_path):
  1. open_db() → init_db (rusqlite bundled)
  2. load_config() → channels + subscriptions from YAML
  3. build_client() → reqwest::Client (proxy PROXY_URL, 30s timeout)
  4. SourceRegistry pre-populate → upsert_all (batch upsert sources)
  5. Telegram: fetch_tg_channels() stream → per msg: lookup registry → emit unparseable → upsert_server
  6. Subscription: fetch_timestamped_subs() → per url: download/read → parse_sub → process_sub_lines
```

**DB failures are fatal** — `upsert_server` uses `.context("... (aborting)")?`. No in-memory dedup — `servers.id` (= `urlx.uid`) PK handles uniqueness.

## Unparseable URL Capture

NDJSON via tracing layer (`target: "mining::unparseable"`). Fields: `raw_url`, `scheme`, `error`, `source_id`, `source_type`, `timestamp`. Emitted at consumer level (where `source_id` from registry is available), not in parsing layer.

## Database Schema

- **`sources`** — `id` (INTEGER PK, hash of URL), `url` (TEXT)
- **`servers`** — `id` (i64 = urlx.uid), schema, host, port, transport, security, remarks, `raw_config` (UrlX JSON), first_seen_ts, first_seen_source_id → FK sources(id)
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
- **UrlX.uid**: `uid = sig ^ rapidhash_v3(host:port:username:password)`. SlipnetEnc: `uid == sig`.
- **ProtoVisitor**: `parse()`, `build()`, `visit()` (computes sig/uid). 9 impls: Vmess, Vless, Trojan, SS, SSR, Hysteria2, Slipnet, SlipnetEnc, Tg. WireGuard/Hysteria recognized by `SchemeX` but no working parser.
- **`thirdparty/`**: vendored upstream proxy projects (sing-box, Xray, hysteria, etc.) — not part of build
- **`benches/`**: Criterion benchmarks (`cargo bench`) with test data per protocol

## Pre-existing Test Failures (5)

Known, not related to recent changes:
- VMess→SS fallback mismatch
- SSR InvalidStructure
- SlipnetEnc InvalidUserInfo
- WireGuard stub (`UnsupportedScheme`)
- Warp not implemented (affects `test_download_sub`)

## Tools

- **graphify** knowledge graph at `graphify-out/`. Use `graphify query/path/explain` for codebase questions. Run `graphify update .` after modifications.
- **memelord** MCP memory system (`memory_start_task` / `memory_end_task` / `memory_report`).
