# CONTEXT.md — v2ray-heal Project Context

> Architecture reference. Last updated: 2026-06-16.

---

## 1. Project Overview

**v2ray-heal** is a Rust-based proxy subscription miner and aggregator. It:
- Scrapes Telegram channels for proxy configuration URLs (VMess, VLESS, Trojan, Shadowsocks, Hysteria2, etc.)
- Downloads and parses v2ray subscription files from HTTP/HTTPS URLs
- Parses, normalizes, and deduplicates proxy configurations using typed protocol parsers
- Persists data to SQLite with time-travel upsert semantics to track origin and lifetime of every observed config
- Exports filtered server lists via the `emit` CLI subcommand

**Stack**: Rust 2024 edition (1.96.0+), `tokio` (async I/O) + `rayon` (parallel CPU for line processing), `rusqlite` (SQLite with bundled feature, `prepare_cached` for statement reuse), `mimalloc` (global allocator), `reqwest` (HTTP client with proxy support), `scraper` (HTML), `rapidhash` (hashing), `serde`/`serde_json` (serialization), `base64-simd` (SIMD-accelerated decode), `itoa` (zero-alloc int formatting), `clap` (CLI), `idna` (IDNA/Punycode hostname conversion).

**Entry points**: `cargo run -- config`, `cargo run -- remote <url>`, `cargo run -- local <file>`, `cargo run -- emit`, `cat sub.txt | cargo run -- stdin`

---

## 2. Project Structure
See workspace tree in `AGENTS.md` or use `find src/` for the current layout.

Key modules:
- `src/main.rs` — CLI: clap-based subcommands (Stdin, Config, Remote, Local, Emit)
- `src/lib.rs` — Core library: `preprocess_sub_data()`, global allocator, re-exports
- `src/db/` — SQLite: `Database` struct in `mod.rs`, upserts (`ops.rs`), queries (`queries.rs`), models (`models.rs`), schema (`schema.rs`)
- `src/mining/` — Pipeline orchestration: `Pipeline`, `RawSourceItemBatch`, `SourceRegistry`, Telegram scraper, subscription downloader, unparseable log, writer
- `src/proto_spec/` — Protocol parsing: `ProtocolConfig` enum, `ProtoSpec` trait, `dispatch!` macro, 12 config parsers
- `src/urlx/` — URL splitter: `SchemeX`, `RawUrlX`, `PortSpec`, `HostSpec`
- `src/utils/` — Utilities: line processing, host/port parsing, permissive JSON (`PermissiveJsonError` via `thiserror::Error` derive), unescaping; `normalize_extras` uses `simd_json::to_string` + `rayon` parallelism
- `src/whitelist/` — Whitelist checking: `WhitelistChecker` with bloom-filter fast-negative guard + exact HashSet for SNI/IP and binary-search CIDR interval lookup. Used by `mining::init_whitelist()` global OnceLock, flags computed during pipeline insert.

---

## 3. Core Data Model

### ProtocolConfig Enum (`src/proto_spec/mod.rs:89-105`)

The central typed representation of a parsed proxy configuration:

```rust
pub enum ProtocolConfig {
    Vless(VlessConfig),
    Vmess(VmessConfig),
    Trojan(TrojanConfig),
    Hysteria2(Hysteria2Config),
    Ss(SsConfig),
    Ssr(SsrConfig),
    Tg(TgConfig),
    Slipnet(SlipnetConfig),
    SlipnetEnc(SlipnetEncConfig),
    Stormdns(StormdnsConfig),
    Tuic(TuicConfig),
    Wireguard(WireguardConfig),
}
```

Serde is `#[serde(tag = "schema")]` — stored in DB as JSON with a `"schema"` discriminator.

### ProtoSpec Trait (`src/proto_spec/mod.rs:66-87`)

Every protocol config implements this trait:

```rust
pub trait ProtoSpec: Serialize + DeserializeOwned + Debug + Clone {
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError>;
    fn reconstruct(&self) -> Result<String, ParseError>;
    fn schema(&self) -> SchemeX;
    fn host(&self) -> Option<&HostSpec>;
    fn port(&self) -> Option<u16>;
    fn remarks(&self) -> Option<&str>;
    fn cred_hash(&self) -> u64;
    fn sig(&self) -> u64;
    fn set_sig_cache(&self, v: NonZeroU64);
    fn set_cred_hash_cache(&self, v: NonZeroU64);
    fn uid(&self) -> u64 { self.sig() ^ self.cred_hash() }
    fn security(&self) -> Option<&SecurityConfig> { None }
    fn transport_type(&self) -> Option<&str>;
    fn security_type(&self) -> Option<&str> { self.security().and_then(SecurityConfig::type_str) }
}
```

### SecurityConfig / TransportConfig (`src/proto_spec/common.rs`)

Unified security and transport model used across protocol configs:

- **SecurityConfig**: enum with `Tls`, `Reality`, `None`, or protocol-specific encryption
  (e.g. SS method). Supports `.type_str()` → `"tls"`, `"reality"`, `"none"`, etc.
- **TransportConfig**: enum with 8 variants — `Tcp`, `Raw` (= `"tcp"` alias), `WebSocket`,
  `HttpUpgrade`, `XHttp`, `Grpc`, `QUIC`, `FakeHttp`. Serde tag `transport`.
```

### SchemeX Enum (`src/urlx/schemex.rs`)

All supported URI schemes: `Vless`, `Vmess`, `Hysteria`, `Hysteria2`, `SS`, `SSR`, `Trojan`, `TUIC`, `Warp`, `AnyTLS`, `Https`, `Tg`, `SlipnetEnc`, `Slipnet`, `Stormdns`, `WireGuard`, `Undefined`, `Unknown(TinyText)`.

`SchemeX::from_str()` normalizes scheme strings (e.g., `"shadowsocks"` → `SS`). `SchemeX::slice_input()` uses Aho-Corasick to split concatenated subscription data into separate URLs.

### RawUrlX Struct (`src/urlx/split_url.rs`)

Pre-protocol-split representation from a raw URI string:

```rust
pub struct RawUrlX<'a> {
    pub schema: SchemeX,
    pub userinfo: &'a str,
    pub hostport: Option<&'a str>,
    pub path: Option<&'a str>,
    pub query: Option<&'a str>,
    pub fragment: Option<&'a str>,
}
```

Constructed via `RawUrlX::from(url_str)`. Splits left-to-right from the `://` boundary: schema → userinfo (before `@`) → fragment (`#`) → query (`?`) → path (`/`) → hostport. Handles Trojan `#`-in-password edge case.

### RawSourceItemBatch (`src/mining/mod.rs`)

The core mining event type, replacing the old `TracedProtocolConfig`:

```rust
pub struct RawSourceItemBatch {
    pub source: Arc<SourceMetadata>,
    pub timestamp: DateTime<Utc>,
    pub raw_urls: Box<[String]>,
}
```

Created by telegram/subscription fetchers. Each batch carries source metadata and a boxed slice of raw URLs to parse. The pipeline processes each batch lazily: upserts the source on first encounter, then runs each raw URL through the parser.

### ParseResult / FallbackInfo

Three-outcome parsing via `try_parse_detailed()`:

```rust
pub enum ParseResult {
    Direct(ProtocolConfig),                       // parsed on first try
    Fallback(ProtocolConfig, FallbackInfo),        // parsed after fallback chain
}

pub struct FallbackInfo {
    pub original_scheme: SchemeX,
    pub attempts: Vec<(SchemeX, ParseError)>,
}
```

`Direct` = parsed by the matching protocol parser. `Fallback` = recovered via the fallback chain (SS→SSR→VMess→VLESS→Trojan→Hysteria2→Slipnet→TG), with details about which parsers were tried. `ParseError` on unrecoverable errors.

---

## 4. Protocol Parsing

### Dispatch Macro (`src/proto_spec/mod.rs:107-124`)

The `dispatch!` macro generates a match expression across all 12 `ProtocolConfig` variants, delegating to the inner config's method. Replaced 172 lines of hand-written match arms.

```rust
dispatch!(self, method, args...)  // expands to match self { Vless(c) => c.method(args...), Vmess(c) => ... }
```

### Parsing Flow

```
RawUrlX::from(url_str)              // Split URI into components
  → ProtocolConfig::try_parse_detailed(&raw)
    → ParseResult::Direct(config)     // parsed by matching protocol
    → ParseResult::Fallback(config, FallbackInfo)  // recovered via fallback chain
    → Err(ParseError)                 // unrecoverable
```

### Parsing by Protocol

| Protocol  | Format | Key Extraction |
|-----------|--------|---------------|
| **VMess** | `vmess://<base64(JSON)>` | Base64-decode userinfo, permissive JSON parse, extract v2rayN QRCode fields (`add`, `port`, `id`, `scy`, `net`, etc.) |
| **VLESS** | `vless://<uuid>@<host>:<port>?params#remarks` | Standard URI: UUID from userinfo, params from query, remarks from fragment |
| **Trojan** | `trojan://<password>@<host>:<port>?params#remarks` | Password from userinfo (may contain `#`), params from query |
| **Hysteria2** | `hy2://<auth>@<host>:<port>?params#remarks` | Auth from userinfo, params from query (up/down, obfs, etc.) |
| **SS** | `ss://<base64(method:password)>@<host>:<port>#remarks` | Base64-decode userinfo, split method:password |
| **SSR** | `ssr://<base64(host:port:protocol:method:obfs:password)>?params` | Base64-decode userinfo, colon-delimited params |
| **TG** | `tg://proxy?server=<host>&port=<port>&secret=<secret>` (or `https://t.me/proxy`) | Query params |
| **Slipnet** | `slipnet://<base64(config)>` | Base64 pipe-delimited config body |
| **SlipnetEnc** | `slipnet-enc://<encrypted>` | No exposed credentials |
| **Stormdns** | `stormdns://...` | Protocol-specific |
| **TUIC** | `tuic://...` | Protocol-specific |
| **WireGuard** | `wireguard://<private_key>@<host>:<port>?address=...` | Standard URI |

### Reconstruct

Each protocol's `reconstruct()` builds the canonical URL string from the parsed config fields. Used for round-trip verification and export.

---

## 4.5. Streaming Decoder (`src/decoder.rs`)

Chunked base64 decoder for incremental subscription data processing. Architecture:

- `feed(chunk) → anyhow::Result<Vec<String>>` — align input to 4-byte base64 boundaries,
  auto-detect encoding (Standard/UrlSafe/Raw), decode via `base64-simd` (runtime SSSE3/AVX2/NEON), and split on `\n`
- `finalize() → anyhow::Result<Vec<String>>` — flush remaining input
- `reset()` — clear state for re-use
- `INPUT_CHUNK_SIZE = 65536` — chunks exceeding this cause a hard error

Callers MUST pre-slice to ≤ `INPUT_CHUNK_SIZE`; passing a larger chunk triggers a `bail!()` error. Internal buffers are heap-allocated,
pre-allocated via `Box::new_uninit_slice`. The 65KB stack work buffer uses `[MaybeUninit<u8>; 65540]` to avoid zero-init memset.
Decoded URL output Vec is pre-sized to `text.len() / 80 + 1` to prevent reallocation during collection.

---


## 5. sig/uid Computation

### Signature (`sig`)

A `u64` rapidhash v3 hash of **non-credential** connection parameters. Purpose: group servers by connection configuration regardless of server location or credentials. Cached in a `OnceLock<NonZeroU64>` per config instance.

Per-protocol sig composition:

| Protocol     | sig includes                                                                 | Excludes                          |
|-------------|----------------------------------------------------------------------------|-----------------------------------|
| **VMess**   | `vmess` + security + transport_type + [HttpUpgrade host] + [XHttp host] + alter_id + sni | `add`, `port`, `id`, `ps`         |
| **VLESS**   | `vless` + security + transport_type + [HttpUpgrade host] + [XHttp host+mode+extra] + path + encryption + sni + flow + alpn + fp + pbk + sid + splice | `uuid`, `host`, `port`            |
| **Trojan**  | `trojan` + security + transport_type + [HttpUpgrade/XHttp host] + path + sni + alpn + fp | `password`, `host`, `port`        |
| **Hysteria2**| `hy2` + transport_type + auth_str (if no userinfo) / username + port + obfs + obfs-password + insecure + sni + up + down + fast_open | `host`, `password`                |
| **SS**      | `ss` + method                                                                 | `password`, `host`, `port`        |
| **SSR**     | `ssr` + all params except remarks                                           | `remarks` (fragment)              |
| **Slipnet** | `slipnet` + transport + pk + type                                           | —                                 |
| **SlipnetEnc**| `uid == sig` (no exposed credentials)                                      | All (encrypted config)            |
| **TG**      | `tg` + transport (socks/mtproto) + secret (beginning only) + server + port  | —                                 |
| **Stormdns**| `stormdns` + sni + transport                                                | `host`, `port`                    |
| **TUIC**    | `tuic` + congestion_control + uuid + password + sni + alpn + quic_hints     | `host`, `port`                    |
| **WireGuard**| `wireguard` + address + dns + mtu + public_key + allowed_ips | `private_key`, `host`, `port` |

### Credential Hash

`cred_hash = rapidhash_v3("host:port:username:password")`, computed via streaming `RapidStreamHasherV3`:

```rust
let mut hasher = RapidStreamHasherV3::new(&DEFAULT_RAPID_SECRETS);
if let Some(h) = host { hasher.write(h.as_bytes()) }
hasher.write(b":");
// port via itoa::Buffer for zero-alloc u16 formatting
hasher.write(b":").write(username.as_bytes()).write(b":").write(password.as_bytes());
hasher.finish()
```

No intermediate `format!()` or String allocation — fields stream directly through the hasher.

- If all credential fields are empty, `cred_hash = 0`, so `uid == sig`.
- For SlipnetEnc, `uid = sig` explicitly (no credentials exposed).
- For SS, the `method` field is stored in `security` (not `password`), so the credential hash only includes the actual password portion of the userinfo.
### Unique ID (`uid`)

`uid = sig ^ cred_hash`

The XOR ensures two servers with the same connection config but different credentials get different `uid` values while sharing the same `sig`.

### Helper Functions (`src/proto_spec/utils.rs`)

```rust
fn compute_cred_hash(host, port, port_spec, username, password) -> u64  // streaming hasher, no String alloc
fn decode_base64(data: &str) -> Result<Vec<u8>, DecodeError>  // strips trailing annotation, filters backticks on bytes
The `Database` struct (`src/db/mod.rs`) wraps a `rusqlite::Connection` behind `Arc<RwLock<Connection>>` with
WAL mode, `PRAGMA wal_autocheckpoint=2000` (reduced checkpoint frequency), and `PRAGMA journal_size_limit=0`:
fn parse_query(query: Option<&str>) -> Vec<(String, String)>  // linear-scan Vec, not HashMap
fn query_get<'a>(params: &[(String,String)], key: &str) -> Option<&'a str>  // linear lookup
fn query_get_multi<'a>(params: &[(String,String)], keys: &[&str]) -> Option<&'a str>  // first match
fn decode_fragment(raw: &RawUrlX) -> Result<Option<String>, ParseError>
```

---

## 6. Database Schema (`src/db/`)

### Database Adapter

The `Database` struct (`src/db/mod.rs`) wraps a `rusqlite::Connection` behind `Arc<RwLock<Connection>>`
with WAL mode, `PRAGMA wal_autocheckpoint=2000` (reduced checkpoint frequency),
`PRAGMA journal_size_limit=0`, and `busy_timeout=5000`:

```rust
pub struct Database {
    conn: Arc<RwLock<Connection>>,
}
```

All database operations are methods on `Database`: `open()`, `init_db()`, `upsert_source()`, `upsert_server()`, `get_sightings()`, `query_servers_filtered()`, `query_sources_by_ids()`, `query_latest_ts_for_source()`. Internal methods use `with_conn()` for safe read/write access.

### Tables

- **`sources`** — Deduplication of source URLs (Telegram channels, subscription links)
  - `id` INTEGER PRIMARY KEY (hash of URL via `rapidhash::v3::RapidStreamHasherV3`), `url` TEXT NOT NULL

- **`servers`** — Deduplicated proxy server records (upserted by `uid`)
  - `id` INTEGER PRIMARY KEY (= `ProtocolConfig::uid()` cast to i64)
  - `raw_config` TEXT NOT NULL (JSON-serialized `ProtocolConfig` via `simd_json::to_string`)
  - `transport` TEXT, `security` TEXT, `remarks` TEXT
  - `sig` INTEGER NOT NULL DEFAULT 0 (= `ProtocolConfig::sig()` cast to i64)
  - `flags` INTEGER NOT NULL DEFAULT 0 (bitmask: 0b001=SNI whitelisted, 0b010=IP whitelisted, 0b100=CIDR whitelisted)
  - `flags_ts` INTEGER NOT NULL DEFAULT 0 (unix timestamp of last whitelist check)
  - `first_seen_ts` INTEGER NOT NULL, `first_seen_source_id` INTEGER NOT NULL REFERENCES sources(id)
  - `ping` TEXT (nullable — JSON-serialized `PingResult`, e.g. `{"type":"tcp","latency_ms":12.5}`)
  - `ping_ts` INTEGER (nullable — unix timestamp of last ping attempt)

- **`sightings`** — Time-travel tracking of when each server was observed from each source
  - `id` INTEGER PRIMARY KEY AUTOINCREMENT
  - `server_id` INTEGER NOT NULL REFERENCES servers(id)
  - `source_id` INTEGER NOT NULL REFERENCES sources(id)
  - `seen_ts` INTEGER NOT NULL, `remarks` TEXT

### Indexes
- `idx_sightings_server_ts` on `sightings(server_id, seen_ts)`
- `idx_servers_schema_security` on `servers(schema, security)`

### Upsert Logic (`upsert_server()`)

Time-travel upsert with three cases (all SQL uses `conn.prepare_cached()` to avoid re-preparing statements):

1. **New server** (no existing row): INSERT into `servers` + INSERT first sighting
2. **Existing server, later timestamp**: INSERT sighting only, keep `first_seen_ts` unchanged
3. **Existing server, earlier timestamp** (backfill): UPDATE `first_seen_ts`/`first_seen_source_id`/`remarks`, INSERT sighting. No archive copy needed — the original INSERT's implicit sighting already records the old first_seen.

**FK enforcement**: `upsert_server` fails if `source_id` doesn't reference an existing `sources` row. Sources must be upserted first (handled by the Pipeline with lazy source upsert tracking via `HashSet`).

### Query Functions

- `query_servers_filtered(conn, protocols, min_first_seen, min_last_seen, flags_mask)` — filtered export with dynamic WHERE clause building. `flags_mask: Option<u8>` adds `AND (flags & ?) != 0` when Some.
- `query_sources_by_ids(conn, ids)` — source URL lookup by primary key (used in emit export to resolve `first_seen_source_id`)

---

## 7. Mining Pipeline (`src/mining/`)

### Flow

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

Fetchers use `create_stream(url)` (`mining/mod.rs`) which returns a
`Pin<Box<dyn Stream<Item = Result<Bytes, StreamError>> + Send + Sync>>` handling `stdin`, `http`/`https`
(with up to 3 retries), and `file` schemes. Subscription fetching eliminates per-scheme dispatch — all schemes
flow through `create_stream`.

### Pipeline Builder API (`src/mining/pipeline.rs:76-104`)

Pipeline exposes builder methods for configuration before `.run()`:

- `add_source(url)` — register a URL, auto-classifying as Telegram or subscription
- `add_batch_raw(items)` — inject pre-processed `RawSourceItemBatch` items (Stdin/Local paths)
- `set_backfill(Option<Backfill>)` — global Telegram backfill (Last duration or Upto datetime)
- `set_per_source_backfill(map)` — per-source timestamps for Emit `--pull`
- `set_progress_bar(pb)` — attach an `indicatif::ProgressBar` for URL processing progress

### SourceRegistry (`src/mining/registry.rs`)
A `HashMap<String, Arc<SourceMetadata>>` pre-populated before any data flow:

```rust
pub struct SourceRegistry {
    sources: HashMap<String, Arc<SourceMetadata>>,
}
```

Key operations:
- `pre_populate(url, source_type)` / `add_telegram_channel(raw)` / `add_subscription(url)`
- `lookup(url)` → `Option<Arc<SourceMetadata>>`
- `upsert_all(conn)` — batch upsert all registered sources to DB
- `from_config(path)` — load from YAML (`tgchannel` and `subscriptions` lists)
- `partition_sources()` — split into (channels, subscriptions) by `SourceType`

### Telegram Mining (`src/mining/telegram.rs`)

1. `fetch_tg_channels()` spawns a `TgChannelFetch` per channel
2. Each fetcher downloads `https://t.me/s/{channel_id}` optionally with `?before=N` pagination
3. HTML parsed with `scraper::Html::parse_document()`, messages selected via `div.tgme_widget_message`
4. `extract_urls()` traverses text nodes inside each message, detects `scheme://` patterns
5. Each extracted URL goes through `ProtocolConfig::try_parse_detailed()`
6. Parsed configs: grouped into `RawSourceItemBatch` → streamed via `TgEvent::Batch(BatchResult)`
7. Failed parses: emitted as `UnparseableRecord` → logged via `emit_unparseable_entry()`
8. Backfill: optional `Backfill::Upto(date)` or `Backfill::Last(duration)` — paginates backwards in time

### Subscription Mining (`src/mining/sub.rs`)

1. `fetch_subscriptions()` spawns a `SubFetcher` per subscription URL via `JoinSet`
2. Each `SubFetcher`:
   - `https://`/`http://`: HTTP download via shared client cached in `OnceLock` (`build_client()` in `mod.rs`); GITHUB_TOKEN for github.com, 90s timeout
   - `file://`: `std::fs::read()` from filesystem
3. Streaming decoder auto-detects base64 encoding and decodes incrementally; `normalize_extras()` → lines → `SchemeX::slice_input()` per segment
4. Returns `RawSourceItemBatch` items, emits unparseable entries

### Pipeline Processing (`Pipeline::run`)

The pipeline's main processing method (`run`) accepts a stream of `RawSourceItemBatch`:

- Lazily upserts sources on first encounter (tracked by `HashSet`)
- Fatal on DB error (aborts pipeline)
- Each batch: `upsert_source` (if new) → for each URL: `try_parse_detailed` → `upsert_server`

Raw URL parsing per item uses `process_single_raw_url(raw_url, source_id, source_type, ts, conn)`
(`pipeline.rs`), a free function that handles all three parse outcomes (Direct, Fallback, Unparseable)
and emits unparseable entries from the consumer level (where `source_id` is known).

### Key Constants
- **Proxy**: Environment-based HTTP proxy (`HTTP_PROXY` env var restricted to 127.0.0.1/localhost);
  basic auth via `HTTP_PROXY_USERNAME`/`HTTP_PROXY_PASSWORD`; `127.0.0.1:20172` fallback only in `#[cfg(test)]`.
  Connect timeout 30s, read timeout 5s.
- `TgConfig`: concurrency=8, timeout=30s
- Subscription task timeout: 90s per `SubFetcher`
- Ping: `PING_TIMEOUT=3s` per endpoint, `PING_CONCURRENCY=200` in-flight

### Pinger (`src/mining/pinger.rs`)

Pinger module for TCP reachability checking, added to the pipeline's post-mining phase:

```rust
// Architecture
ping_and_store(db, &servers, &spec, progress_bar) -> Vec<(String, u16, PingResult)>
```

**Flow**:
1. Filters out UDP/QUIC schemas: wireguard, tuic, hysteria2, stormdns, slipnet, slipnet-enc
2. Deduplicates by `(host.to_ascii_lowercase(), port)` — one TCP connect per unique endpoint
3. Pings concurrently via `FuturesOrdered` capped at `PING_CONCURRENCY` (200)
4. Stores JSON `PingResult` to ALL server rows sharing that `(host, port)` using `LOWER(host) = LOWER(?3)` to handle mixed-case hostnames
5. Returns results vector and optional progress bar with real-time OK/FAIL counters

**PingResult** (`#[serde(tag = "type")]`):
```json
{"type":"tcp","latency_ms":12.5}        // success
{"type":"tcp","error":"timeout after 3s"}  // failure
```

**CLI integration**: `--ping ok` (or bare `--ping`) / `--ping 15ms` on `emit`/mining subcommands; standalone `ping` subcommand for querying existing DB. Progress bar + `target: "ping"` tracing provide real-time feedback.

**Case-sensitivity fix**: The UPDATE query originally used `WHERE host = ?3` (binary comparison) but the pinger lowercased hosts for dedup — rows with mixed-case hosts kept NULL ping fields. Fixed to `WHERE LOWER(host) = LOWER(?3)`.

---

## 8. Unparseable URL Capture

NDJSON via tracing-subscriber layer at `target: "mining::unparseable"`.

### UnparseableLayer (`src/mining/unparseable_log.rs`)

A `tracing_subscriber::Layer` that:
1. Filters events by target `"mining::unparseable"`
2. Serializes fields to JSON: `raw_url`, `scheme`, `error`, `source_id`, `source_type`, `timestamp`
3. Appends to a file (controlled by `--unparseable-log` flag; default `unparseable.ndjson`, overridable with `--unparseable-log=<PATH>`)

### Emission Point

`emit_unparseable_entry()` in `mining/mod.rs` — called from telegram, subscription, and local paths. Filters out promotion/navigation and private/loopback-host URLs before logging. Consumer-level emission (where `source_id` from registry is available).

---

## 9. CLI Architecture

### Struct Hierarchy (`src/main.rs`)
| **`Emit`** | Filtered server export. `--protocol` filter (repeatable), `--min-first-seen-ts`/`--min-last-seen-ts` (humantime duration), `--pull` (re-mine all DB sources with optional `Backfill`), `--ping` (value: `ok` or duration — pings before export, filters by reachability). Reconstructs URLs from stored `ProtocolConfig` JSON via `simd_json::from_slice` (not `serde_json`). Uses `EmitFilterArgs` flattened. |
| **`Ping`** | Standalone ping. `--protocol`, `--min-first-seen-ts`, `--min-last-seen-ts`, `--wl` filters. Pings all matching servers via TCP connect, stores results in DB, prints results table. Progress bar shows real-time OK/FAIL. |
```rust
// Shared filter flags for both standalone emit and emit-on-mine
#[derive(Debug, clap::Args)]
pub(crate) struct EmitFilterArgs {
    #[arg(long, value_delimiter = ',')]
    protocol: Vec<String>,
    #[arg(long)]
    min_first_seen_ts: Option<humantime::Duration>,
    #[arg(long)]
    min_last_seen_ts: Option<humantime::Duration>,
}

// Wraps filter args behind a --emit gate for mining subcommands
struct EmitOnMine {
    emit: bool,
    #[command(flatten)]
    filters: EmitFilterArgs,
}
```

### Subcommands (`src/main.rs`)

| Subcommand | Description |
|-----------|-------------|
| **`Stdin`** | Pipe → `parse_to_raw_urls()` → DB upsert. Source type: `Other`, registry key `stdin://local`. Supports `--emit` flag for post-mining export. |
| **`Config`** | Full pipeline from YAML. Channels + subscriptions from `config.yaml`. Uses `Pipeline::from_config()` + `.run()`. Supports `--last` (humantime duration) / `--upto` (RFC 3339) for Telegram backfill. Supports `--emit` flag. |
| **`Remote`** | Download subs from URLs or scrape Telegram (t.me auto-detected). Mixed batch OK. Supports `--last` / `--upto` Telegram backfill flags. Supports `--emit` flag. |
| **`Local`** | Filesystem → `parse_to_raw_urls()` → DB upsert. Source URL = `file://` absolute path. Supports `--emit` flag. |
| **`Emit`** | Filtered server export. `--protocol` filter (repeatable), `--min-first-seen-ts`/`--min-last-seen-ts` (humantime duration), `--pull` (re-mine all DB sources with optional `Backfill`). Reconstructs URLs from stored `ProtocolConfig` JSON via `simd_json::from_slice` (not `serde_json`). Uses `EmitFilterArgs` flattened. |

### Global Flags
- `--db <path>` — SQLite database path (default: `v2ray-heal.db`). Must appear **before** the subcommand — not marked `global = true` in clap.
- `--unparseable-log` [=<path>] — enable unparseable URL log (default path: `unparseable.ndjson`). Value must follow `=`.
### Config File Format (`config.yaml`)
```yaml
tgchannel:
  - ChannelName
  - "@ChannelName"
  - https://t.me/ChannelName
subscriptions:
  - https://example.com/sub
  - file:///path/to/local/sub.txt
```

---

## 10. Key Design Decisions & Rationale

1. **`dispatch!` macro** over manual match arms: Eliminated 172 lines of repetitive code. Compile-time expansion with no runtime overhead.

2. **`sig_cache` with `OnceLock<NonZeroU64>`**: sig computation is deterministic but may be called multiple times (during parse, serialization, display). Lazy caching avoids redundant rapidhash calls while staying thread-safe.

3. **`decode_base64` strips trailing annotation** (emoji, Persian/Arabic text, backticks): Telegram channels frequently append decoration after base64 payloads. Silently stripping at decode time avoids parse failures upstream.

4. **Host validation rejects private/loopback**: `validate_host_not_private()` in `proto_spec/utils.rs` rejects localhost, 10.x, 192.168.x, 127.x, etc. Prevents misconfigured or internal-only URLs from entering the database. These errors are silently filtered from the unparseable NDJSON log — they are permanently irrecoverable (thirdparty engines never use `host`/`sni` fields as dial targets).

5. **Separate `sig` from `uid`**: `sig` groups servers by connection configuration (useful for statistical analysis — frequency per hour/day, signature lifetime). `uid` uniquely identifies each server instance via XOR with credential hash.

6. **FK enforcement in upsert**: `upsert_server()` fails if `source_id` is invalid. Sources must exist before servers. Pipeline handles this with lazy source upsert + `HashSet` tracking.

7. **GITHUB_TOKEN for github.com**: Bearer auth on `raw.githubusercontent.com` / `github.com` requests. Avoids rate limiting on raw content fetches.

8. **IDNA fallback in `dns_name()`**: The `dns_name` parser in `src/utils/host_port.rs` originally accepted only ASCII alphanumeric + `.` `-` `_` via `nom` combinators. Subscription entries with Chinese hostnames (e.g. `例子.测试`) were rejected. Changed to `take_while1(|c| ... || c > 127)` to accept any byte, then fall back to `idna::domain_to_ascii()` for Punycode conversion. Fast path (pure ASCII) stays zero-alloc — the `.to_owned()` moved inside `map_res` returns `DnsName<'static>` which coerces through all callers via lifetime covariance. No caller changes needed, no measurable perf impact (isolated benchmarks within ±1% noise). Verified: 120171 real-world URLs parsed, 54 fewer unparseable entries.

9. **Case-insensitive host matching in ping update**: `update_server_ping()` originally used `WHERE host = ?3` (SQLite binary comparison). The pinger deduplicates endpoints via `host.to_ascii_lowercase()` — mixed-case stored hosts (e.g., `Example.Host.Com`) never matched the lowercased query parameter, leaving `ping`/`ping_ts` NULL. Fixed with `LOWER(host) = LOWER(?3)`. The deduplication already ensures one ping per unique host:port, and `LOWER()` on both sides updates all server rows sharing that endpoint regardless of stored casing.

---

## 11. Quick Reference: Protocol → Credential / sig Fields

| Protocol   | Credentials (for uid)                                  | sig Key Fields                     |
|-----------|--------------------------------------------------------|------------------------------------|
| **VMess** | `host`, `port`, `uuid` (id)                            | security, transport, sni, aid      |
| **VLESS** | `host`, `port`, `uuid`                                 | security, transport, encryption, path, sni, flow, alpn, fp, pbk, sid, splice |
| **Trojan** | `host`, `port`, `password`                            | security, transport, path, sni, alpn, fp |
| **Hysteria2** | `host`, `port` (auth may be in userinfo)          | transport, obfs, insecure, sni, up/down |
| **SS**    | `host`, `port`, `password` (from userinfo)             | method                              |
| **SSR**   | `host`, `port`, `password`                             | all params except remarks           |
| **Slipnet** | `host` (domain), `port` (local_port)                | transport, pk, type                 |
| **SlipnetEnc** | None (uid == sig)                                | N/A (encrypted)                     |
| **TG**    | `secret`, `host`, `port`                               | transport, secret (first bytes)     |
| **Stormdns** | `host`, `port`                                     | sni, transport                      |
| **TUIC**  | `host`, `port`, `uuid`, `password`                     | congestion_control, sni, alpn, quic_hints |
| **WireGuard** | `host`, `port`, `private_key`                      | address, dns, mtu, public_key, allowed_ips |

---

## 12. Common Test Commands

```bash
# Run all tests (180 pass, 0 ignored)
rtk cargo test

# Run specific protocol tests
rtk cargo test test_vless
rtk cargo test test_vmess
rtk cargo test test_trojan
rtk cargo test test_hysteria2
rtk cargo test test_ss
rtk cargo test test_ssr
rtk cargo test test_slipnet
rtk cargo test test_tg
rtk cargo test test_wireguard

# Run mining pipeline
cargo run -- config
cargo run -- config path.yaml

# Run specific file pipelines
cargo run -- remote https://example.com/sub.txt
cargo run -- local ./file.txt
cat sub.txt | cargo run -- stdin

# Ephemeral mine+emit (no DB file left behind)
cargo run -- --db ":memory:" local ./file.txt --emit
cat sub.txt | cargo run -- stdin --emit --protocol vmess

# Filtered export
cargo run -- emit --protocol vmess --protocol vless

# Ping servers from existing DB
cargo run -- ping
cargo run -- ping --protocol vmess
cargo run -- ping --min-first-seen-ts 1h

# Mine and emit with ping filter
cargo run -- config --emit --ping ok
cargo run -- --db ":memory:" local ./file.txt --emit --ping 15ms

# Run examples with visible ping progress
RUST_LOG=warn,ping=info cargo run --example parse_real_subs
RUST_LOG=warn,ping=info cargo run --example parse_real_tg
RUST_LOG=warn,ping=info cargo run --example parse_real_subs_web

# Criterion benchmarks
cargo bench  # raw_urlx, proto_spec, slice_input, permissive_json
```

---

## 13. Rapidhash Usage

All hashing uses `rapidhash::v3::rapidhash_v3()`:
- **sig**: Hash of protocol-specific non-credential fields concatenated as byte slices (per-protocol in each `compute_sig()` method)
- **credential hash**: `rapidhash_v3("host:port:username:password")` via `compute_cred_hash()`
- **uid**: `sig XOR cred_hash`

Source URL hashing (for `sources.id` PK) uses `rapidhash::v3::RapidStreamHasherV3`, not `std::hash::DefaultHasher`.
