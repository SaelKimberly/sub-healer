# v2ray-heal

Rust proxy subscription miner/aggregator: scrapes Telegram channels + downloads subscription files → normalizes, deduplicates, validates → persists to SQLite with time-travel upsert.

## Quick Commands

```bash
rtk cargo check                 # lint
rtk cargo test                  # all tests (180 pass, 0 ignored)
cat sub.txt | cargo run -- stdin              # parse from pipe
cargo run -- config --emit --protocol vmess   # mine then emit filtered
cargo run -- --db ":memory:" local ./file.txt --emit   # ephemeral mine+emit
cargo run -- remote https://example.com/sub.txt  # download sub URL
cargo run -- local ./file.txt                 # parse local file
cargo run -- emit --protocol vmess            # export filtered servers
cargo run -- ping --protocol vmess             # ping all vmess servers and store results
```

## CLI

- **`config`**: Full pipeline from YAML. Optional `tgchannel:` (list) and `subscriptions:` list — supports `https://` (HTTP download, GITHUB_TOKEN env for github.com) and `file://`. Unsupported schemes → skip with `tracing::error!`. Supports `--emit` (with `--protocol`, `--min-first-seen-ts`, `--min-last-seen-ts`, `--wl`, `--recheck-whitelist`) for post-mining filtered export.
- **`stdin`**: Pipe → `parse_to_raw_urls()` → DB upsert. Source type: `Other`, registry key `stdin://local`. Supports `--emit` + `--ping` flags.
- **`remote`**: Download subs from URLs or scrape Telegram (t.me auto-detected via host check). Mixed batch OK. Supports `--emit` + `--ping` flags.
- **`local`**: Filesystem → `parse_to_raw_urls()` → DB upsert. Source URL = `file://` absolute path. Supports `--emit` + `--ping` flags.
- **`emit`**: Filtered server export. `--protocol` (repeatable, case-insensitive), `--min-first-seen-ts`, `--min-last-seen-ts` (humantime durations), `--pull` (re-mine all DB sources, optionally with per-source Telegram backfill). `--wl` (comma-separated: sni,ip,cidr) to filter by whitelist flags. `--recheck-whitelist` re-runs whitelist checking on all (or outdated) servers. `--recheck-max-age` (humantime) limits recheck to servers not checked within the duration. `--ping` (value: `ok` or duration like `15ms`) — pings servers and filters by reachability before export. `--ping` bare (= `ok`) supported. Reconstructs native URLs from stored `ProtocolConfig` JSON.
- **`ping`**: Standalone ping subcommand. `--protocol`, `--min-first-seen-ts`, `--min-last-seen-ts`, `--wl` filters. Pings all matching servers via TCP connect or UDP knock and stores results in DB. Prints results table with per-endpoint ok/fail status. Progress bar shows real-time progress with OK/FAIL counters.

Global `--db` flag (default `v2ray-heal.db`) must appear before the subcommand — not marked `global = true` in clap. Combined with `--db ":memory:"` and `--emit` on any mining subcommand, enables a fully ephemeral pipeline: mine → filter → output → discard, with zero disk persistence. `--emit` is available on `config`, `remote`, `local`, and `stdin`; the standalone `emit` subcommand remains for querying an existing database. `--unparseable-log` enables the unparseable log file (default: `unparseable.ndjson`); `--unparseable-log=<PATH>` overrides the path. `--whitelist-sni`, `--whitelist-ip`, `--whitelist-cidr` load SNI/IP/CIDR whitelist files (default: `whitelist.txt`, `ipwhitelist.txt`, `cidrwhitelist.txt`) for bloom-filter-based flagging on insert and `--wl` filtering on export.

## Architecture

**Two-layer pipeline** — `urlx/` splits URI → `proto_spec/` parses into typed configs:

1. `SchemeX::slice_input()` / `RawUrlX::from(str)` splits URI → schema/userinfo/hostport/path/query/fragment
2. `ProtocolConfig::try_parse_detailed(&raw)` dispatches by `SchemeX` → three-outcome result (Direct / Fallback / Unparseable)
3. On `Fallback` result, retry chain: SS→SSR→VMess→VLESS→Trojan→Hysteria2→Slipnet→TG
4. `reconstruct()` builds canonical URL back from parsed fields

`dispatch!` macro delegates all `ProtoSpec` trait methods across 12 `ProtocolConfig` variants. Whitelist checking (`src/whitelist/`) uses BloomFilter (fastbloom) for SNI/IP and binary-search CIDR intervals to compute flags bitmask during pipeline insert; `--wl` filters on export.

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
## Pinger (`src/mining/pinger.rs`)

TCP/UDP/QUIC ping module for reachability checking:

- `PingSpec` — `Ok` (reachability only) or `Threshold(duration)` for latency filtering. Parsed from CLI via `FromStr`: bare `--ping` → `Ok`, `--ping 15ms` → `Threshold`.
- `Ping` / `PingStatus` / `PingKind` — typed ping result (`Done { latency_ms }` or `Fail { error }`), tagged `#[serde(tag = "type")]`. `PingKind` distinguishes `Tcp`, `Udp`, or `Quic`. Stored as JSON in `servers.ping`.
- `ping_and_store(db, servers, spec, progress_bar)` — classifies schemas as TCP, UDP, or QUIC via `QUIC_SCHEMAS` and `UDP_SCHEMAS` constants, deduplicates by `LOWER(host):port`, pings each unique endpoint via TCP connect, 1-byte UDP knock, or quinn QUIC handshake, stores JSON result to ALL matching server rows with `LOWER(host) = LOWER(?3)` (case-insensitive match), returns results.
- `PING_TIMEOUT = 3s` per endpoint, `PING_CONCURRENCY = 200` in-flight.
- Progress bar: `indicatif::ProgressBar` with OK/FAIL counters, integrates with `MultiProgress` in main.rs.
- Tracing: `target: "ping"` for start count and per-result logs.
- Schema classification: `QUIC_SCHEMAS = ["tuic", "hysteria2"]` → `PingKind::Quic` (QUIC handshake via quinn, `PermissiveVerifier` skips cert validation). `UDP_SCHEMAS = ["wireguard", "stormdns", "slipnet"]` → `PingKind::Udp` (1-byte UDP knock). All others → `PingKind::Tcp`. `slipnet-enc` is excluded (no `host()`/`port()`).

## Unparseable URL Capture

NDJSON via tracing layer (`target: "mining::unparseable"`). Fields: `raw_url`, `scheme`, `error`, `source_id`, `source_type`, `timestamp`. Emitted at consumer level (where `source_id` from registry is available), not in parsing layer. `PromotionUrl` and `InvalidPrivateHost` errors are silently dropped before emission (the latter are permanently irrecoverable — thirdparty engines never use host/sni as dial targets).

## Database Schema

- **`sources`** — `id` (INTEGER PK, hash of URL via RapidStreamHasherV3), `url` (TEXT)
- **`servers`** — `id` (i64 = ProtocolConfig::uid), schema, host, port, transport, security, remarks, `raw_config` (ProtocolConfig JSON), first_seen_ts, first_seen_source_id → FK sources(id), `flags` (i64 bitmask: 0b001=SNI, 0b010=IP, 0b100=CIDR), `flags_ts` (unix timestamp of last whitelist check), `ping` (TEXT nullable — JSON Ping), `ping_ts` (INTEGER nullable — unix timestamp of last ping)
- **`sightings`** — server_id, source_id, seen_ts, remarks

Time-travel: if incoming_ts < first_seen_ts, archive current to sightings + replace.

## Key Technical Details

- **Rust**: Edition 2024, requires 1.96.0+ (stable, rustfmt + clippy in toolchain)
- **Global Allocator**: `mimalloc` (via `#[global_allocator]`)
- **Linker**: `clang` + `mold` (`.cargo/config.toml`)
- **Concurrency**: `tokio` (async I/O) + `rayon` (parallel CPU for line processing)
- **Database**: `rusqlite` bundled; `conn.prepare_cached()` for prepared statement reuse; `PRAGMA wal_autocheckpoint=2000` and `PRAGMA journal_size_limit=0` to reduce WAL checkpoint frequency
- **Proxy**: Environment-based HTTP proxy (`HTTP_PROXY` env var, restricted to 127.0.0.1/localhost);
  basic auth via `HTTP_PROXY_USERNAME`/`HTTP_PROXY_PASSWORD`; `127.0.0.1:20172` fallback only in `#[cfg(test)]`.
  Connect timeout 30s, read timeout 5s.
- **GITHUB_TOKEN**: env var for bearer auth on `raw.githubusercontent.com` / `github.com` requests
- **ProtocolConfig.uid**: `uid = sig ^ rapidhash_v3(host:port:username:password)`. SlipnetEnc: `uid == sig`. Credential hash uses streaming `RapidStreamHasherV3` (`finish()` directly, no intermediate `format!()` String).
- **ProtoSpec**: `try_parse()`, `reconstruct()`, `schema()`, `host()`, `port()`, `uid()` (= `sig() ^ cred_hash()`). 12 impls: Vless, Vmess, Trojan, Hysteria2, Ss, Ssr, Tg, Slipnet, SlipnetEnc, Stormdns, Tuic, Wireguard.
- **sig_cache**: `OnceLock<NonZeroU64>` per config instance — computed once, cached forever.
- **`thirdparty/`**: vendored upstream proxy projects (sing-box, Xray, hysteria, etc.) — not part of build
- **`benches/`**: Criterion benchmarks (`cargo bench`) with test data per protocol: raw_urlx, proto_spec, slice_input, permissive_json
- **`normalize_extras`**: Uses `simd_json::to_string` (not `serde_json`) and parallelizes `extra=` segments via `rayon`
- **`nom_locate` removed**: Parser `Span<'a>` is bare `&'a [u8]` instead of `LocatedSpan`; saves a dependency with no loss of error precision
- **`base64-simd`**: Runtime-detected SSSE3/AVX2/NEON base64 decode in `process_aligned()`; 65KB work buffer uses `MaybeUninit` to avoid zero-init
- **`itoa`**: Zero-alloc u16 formatting for port fields, replaces `to_string()`
- **`parse_query` returns `Vec<(String,String)>`**: Linear scan for ≤5 entries instead of `HashMap`; `query_get()` / `query_get_multi()` helpers for lookups
- **`idna` for hostname fallback**: `dns_name()` in `src/utils/host_port.rs` accepts non-ASCII bytes, falls back to `idna::domain_to_ascii()` for Punycode conversion when hostname contains Unicode characters. Returns `DnsName<'static>` via `.to_owned()` inside the `map_res` closure — coerces cleanly through all callers via lifetime covariance. `idna` v1.1.0 direct dependency.
- **`fastbloom`**: `fastbloom = "0.17.0"` for bloom-filter fast-negative guard in whitelist checking. Three independent `BloomFilter` + `HashSet` pairs (SNI, IP) and a sorted `Vec<(u32,u32)>` CIDR interval list with `partitions_point()` binary search. `WhitelistChecker::new(sni_path, ip_path, cidr_path)` loads all three. Global `OnceLock` in `mining::` module, initialized via `init_whitelist()`.

## Pre-existing Test Status

**180 passed, 0 ignored**. Previous 5 failures (VMess→SS fallback, SSR InvalidStructure, SlipnetEnc, WireGuard, Warp) were fixed during the proto_spec unification.

## Tools

- **memelord** MCP memory system (`memory_start_task` / `memory_end_task` / `memory_report`).
