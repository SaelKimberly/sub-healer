# CONTEXT.md — v2ray-heal Project Context

> Auto-generated for AI agent sessions. Last updated: 2026-05-27.

---

## 1. Project Overview

**v2ray-heal** is a Rust-based proxy subscription miner and aggregator. It:
- Scrapes Telegram channels for proxy configuration URLs (VMess, VLESS, Trojan, Shadowsocks, Hysteria2, etc.)
- Downloads and parses v2ray subscription files from HTTP/HTTPS URLs
- Parses, normalizes, and deduplicates proxy configurations using typed protocol parsers
- Persists data to SQLite with time-travel upsert semantics to track origin and lifetime of every observed config
- Exports filtered server lists via the `emit` CLI subcommand

**Stack**: Rust 2024 edition (1.95.0+), `tokio` (async I/O) + `rayon` (parallel CPU for line processing), `rusqlite` (SQLite with bundled feature), `mimalloc` (global allocator), `reqwest` (HTTP client with proxy support), `scraper` (HTML), `rapidhash` (hashing), `serde`/`serde_json` (serialization), `clap` (CLI).

**Entry points**: `cargo run -- config`, `cargo run -- remote <url>`, `cargo run -- local <file>`, `cargo run -- emit`, `cat sub.txt | cargo run -- stdin`

---

## 2. Project Structure

```
src/
├── main.rs                       # CLI: clap-based subcommands (Stdin, Config, Remote, Local, Emit)
├── lib.rs                        # Core library: parse_sub(), global allocator, re-exports
├── db.rs                         # SQLite: init_db, upsert_source, upsert_server, get_server, get_sightings, query_servers_filtered, query_sources_by_server_ids
├── mining/
│   ├── mod.rs                    # Pipeline: open_db, build_client, process_config_stream, emit_unparseable_entry, run_with_config
│   ├── registry.rs               # SourceRegistry, SourceMetadata, SourceType, SourceFetcher trait, LiveFetcher, normalize_channel_url
│   ├── sub.rs                    # Subscription download: SubFetcher, fetch_subscriptions, lines_to_traced, download_sub_data
│   ├── telegram.rs               # Telegram scraper: fetch_tg_channels, TgChannelFetch, TracedConfigStream, extract_urls, Backfill
│   ├── traced_config.rs          # TracedProtocolConfig struct (config + timestamp + source)
│   ├── unparseable_log.rs        # UnparseableLayer (tracing-subscriber Layer → NDJSON)
│   └── writer.rs                 # PipelineLogWriter (mutex-guarded file writer for tracing)
├── proto_spec/
│   ├── mod.rs                    # ProtoSpec trait, ProtocolConfig enum, dispatch! macro, fallback try_parse
│   ├── common.rs                 # TransportConfig enum + typed configs (Ws, Grpc, Http, Kcp, HttpUpgrade, XHttp)
│   ├── utils.rs                  # parse_hostport, parse_host, parse_port, decode_base64, parse_query, compute_cred_hash, decode_fragment, coercion helpers
│   ├── vmess.rs                  # VmessConfig (base64 JSON userinfo)
│   ├── vless.rs                  # VlessConfig (standard URI with query params)
│   ├── trojan.rs                 # TrojanConfig (password in userinfo)
│   ├── hysteria2.rs              # Hysteria2Config (hy2:// URI)
│   ├── ss.rs                     # SsConfig (shadowsocks base64 userinfo)
│   ├── ssr.rs                    # SsrConfig (SSR colon-delimited params)
│   ├── tg.rs                     # TgConfig (t.me/proxy MTProto format)
│   ├── slipnet.rs                # SlipnetConfig + SlipnetEncConfig
│   ├── stormdns.rs               # StormdnsConfig
│   ├── tuic.rs                   # TuicConfig
│   └── wireguard.rs              # WireguardConfig
├── urlx/
│   ├── mod.rs                    # Re-exports: HostSpec, PortSpec, SchemeX, RawUrlX, serde helpers
│   ├── schemex.rs                # SchemeX enum + from_str + slice_input (aho-corasick-based URL splitter)
│   ├── split_url.rs              # RawUrlX struct (schema, userinfo, hostport, path, query, fragment) with parsing
│   ├── port_spec.rs              # PortSpec (u16 port or range)
│   └── serde_util.rs             # host_serde, port_serde, port_spec_serde custom serializers
└── utils/
    ├── mod.rs                    # Re-exports from submodules
    ├── line.rs                   # Lines/Line/Data types, split_at_scheme for concatenated URLs
    ├── host_port.rs              # host_port_spec() parser (nom-based)
    ├── norm_extras.rs            # normalize_extras() — fix malformed proxy strings
    ├── permissive_json.rs        # Permissive JSON parser (tolerant of malformed input)
    ├── unescaper.rs              # Unescaper for URL-encoded strings
    └── fast_perc.rs              # Fast percent-decoding DFA (used by permissive_json)
```

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
    fn uid(&self) -> u64 { self.sig() ^ self.cred_hash() }
    fn transport_type(&self) -> Option<&str>;
    fn security_type(&self) -> Option<&str>;
}
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

### TracedProtocolConfig Struct (`src/mining/traced_config.rs`)

Wraps a parsed config with trace metadata:

```rust
pub struct TracedProtocolConfig {
    pub config: ProtocolConfig,
    pub timestamp: DateTime<Utc>,
    pub source: Arc<SourceMetadata>,
}
```

---

## 4. Protocol Parsing

### Dispatch Macro (`src/proto_spec/mod.rs:107-124`)

The `dispatch!` macro generates a match expression across all 12 `ProtocolConfig` variants, delegating to the inner config's method. Replaced 172 lines of hand-written match arms.

```rust
dispatch!(self, method, args...)  // expands to match self { Vless(c) => c.method(args...), Vmess(c) => ... }
```

### Parsing Flow

```
RawUrlX::from(url_str)           // Split URI into components
  → ProtocolConfig::try_parse(&raw)
    → dispatch by SchemeX variant  // VmessConfig::try_parse, VlessConfig::try_parse, etc.
    → On recoverable error (InvalidStructure, MissingHost, MissingPort,
       InvalidUserInfo, InvalidHostPort, InvalidHost, Unknown):
      Fallback chain: SS → SSR → VMess → VLESS → Trojan → Hysteria2
                      → Slipnet → TG
    → On unrecoverable error (UnsupportedScheme, PromotionUrl, etc.): return error
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

`cred_hash = rapidhash_v3("host:port:username:password")`

- If all credential fields are empty, `cred_hash = 0`, so `uid == sig`.
- For SlipnetEnc, `uid = sig` explicitly (no credentials exposed).
- For SS, the `method` field is stored in `security` (not `password`), so the credential hash only includes the actual password portion of the userinfo.

### Unique ID (`uid`)

`uid = sig ^ cred_hash`

The XOR ensures two servers with the same connection config but different credentials get different `uid` values while sharing the same `sig`.

### Helper Functions (`src/proto_spec/utils.rs`)

```rust
fn compute_cred_hash(host, port, port_spec, username, password) -> u64
fn decode_base64(data: &str) -> Result<Vec<u8>, DecodeError>  // strips trailing annotation
fn parse_hostport(s: &str) -> Result<(HostSpec, PortSpec), ParseError>
fn parse_host(s: &str) -> Result<HostSpec, ParseError>
fn parse_port(s: &str) -> Result<PortSpec, ParseError>
fn parse_query(query: Option<&str>) -> HashMap<String, String>
fn decode_fragment(raw: &RawUrlX) -> Result<Option<String>, ParseError>
```

---

## 6. Database Schema (`src/db.rs`)

### Tables

- **`sources`** — Deduplication of source URLs (Telegram channels, subscription links)
  - `id` INTEGER PRIMARY KEY (hash of URL via `std::hash::DefaultHasher`), `url` TEXT NOT NULL

- **`servers`** — Deduplicated proxy server records (upserted by `uid`)
  - `id` INTEGER PRIMARY KEY (= `ProtocolConfig::uid()` cast to i64)
  - `schema` TEXT NOT NULL, `host` TEXT NOT NULL, `port` TEXT NOT NULL
  - `transport` TEXT, `security` TEXT, `remarks` TEXT
  - `raw_config` TEXT NOT NULL (JSON-serialized `ProtocolConfig` via `serde_json`)
  - `first_seen_ts` INTEGER NOT NULL, `first_seen_source_id` INTEGER NOT NULL REFERENCES sources(id)

- **`sightings`** — Time-travel tracking of when each server was observed from each source
  - `id` INTEGER PRIMARY KEY AUTOINCREMENT
  - `server_id` INTEGER NOT NULL REFERENCES servers(id)
  - `source_id` INTEGER NOT NULL REFERENCES sources(id)
  - `seen_ts` INTEGER NOT NULL, `remarks` TEXT

### Indexes
- `idx_sightings_server_ts` on `sightings(server_id, seen_ts)`
- `idx_servers_schema_security` on `servers(schema, security)`

### Upsert Logic (`upsert_server()`)

Time-travel upsert with three cases:

1. **New server** (no existing row): INSERT into `servers` + INSERT first sighting
2. **Existing server, later timestamp**: INSERT sighting only, keep `first_seen_ts` unchanged
3. **Existing server, earlier timestamp** (backfill): UPDATE `first_seen_ts`/`first_seen_source_id`/`remarks`, INSERT sighting. No archive copy needed — the original INSERT's implicit sighting already records the old first_seen.

**FK enforcement**: `upsert_server` fails if `source_id` doesn't reference an existing `sources` row. Sources must be upserted first (handled by `process_config_stream` with lazy source upsert tracking via `HashSet`).

### Query Functions

- `query_servers_filtered(conn, protocols, min_first_seen, min_last_seen)` — filtered export with dynamic WHERE clause building
- `query_sources_by_server_ids(conn, server_ids)` — distinct sources that contributed sightings for given servers

---

## 7. Mining Pipeline (`src/mining/`)

### Flow

```
run_with_config(path, db_path):
  1. build_client()          → reqwest::Client (proxy PROXY_URL, 30s timeout)
  2. open_db(db_path)        → init_db schema
  3. SourceRegistry::from_config(config_path)
     → YAML parsing: tgchannel[] + subscriptions[]
     → Normalize channel URLs to https://t.me/s/{name}
  4. registry.run_pipeline(client, conn).await
     → LiveFetcher::fetch(client, registry, channels, subscriptions)
       → Telegram: fetch_tg_channels() stream
       → Subscription: fetch_subscriptions() stream
       → futures::stream::select(tg, sub) — merged stream
     → process_config_stream(stream, conn) — upsert sources + servers
```

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

### SourceFetcher Trait

```rust
pub trait SourceFetcher {
    fn fetch(&self, client, registry, channels, subscriptions) -> BoxStream<TracedProtocolConfig>;
}
```

Default impl: `LiveFetcher` — merges Telegram + subscription streams via `futures::stream::select`.

### Telegram Mining (`src/mining/telegram.rs`)

1. `fetch_tg_channels()` spawns a `TgChannelFetch` per channel
2. Each fetcher downloads `https://t.me/s/{channel_id}` optionally with `?before=N` pagination
3. HTML parsed with `scraper::Html::parse_document()`, messages selected via `div.tgme_widget_message`
4. `extract_urls()` traverses text nodes inside each message, detects `scheme://` patterns
5. Each extracted URL goes through `ProtocolConfig::try_parse()`
6. Parsed configs: emitted as `TgEvent::Message(TgWebMessage)` → streamed as `TracedProtocolConfig`
7. Failed parses: emitted as `UnparseableRecord` → logged via `emit_unparseable_entry()`
8. Backfill: optional `Backfill::Upto(date)` or `Backfill::Last(duration)` — paginates backwards in time

### Subscription Mining (`src/mining/sub.rs`)

1. `fetch_subscriptions()` spawns a `SubFetcher` per subscription URL via `JoinSet`
2. Each `SubFetcher`:
   - `https://`/`http://`: HTTP download via shared client (GITHUB_TOKEN for github.com, 90s timeout)
   - `file://`: `std::fs::read()` from filesystem
3. `parse_sub()` → base64 decode → `normalize_extras()` → `Lines::new_raw().processed()`
4. `lines_to_traced()` maps `Lines` to `TracedProtocolConfig` items, emits unparseable entries

### Batch Processing (`process_config_stream`)

```rust
pub async fn process_config_stream(
    stream: impl StreamExt<Item = TracedProtocolConfig>,
    conn: &rusqlite::Connection,
) -> Result<usize, Error>
```

- Lazily upserts sources on first encounter (tracked by `HashSet`)
- Fatal on DB error (aborts pipeline)
- Each item: `upsert_source` (if new) → `upsert_server`

### Key Constants
- `PROXY_URL`: `http://127.0.0.1:20172` (local proxy for outbound requests)
- `USER_AGENT`: `clash-verge/v2.0.2`
- `TgConfig`: concurrency=8, timeout=30s
- Subscription task timeout: 90s per `SubFetcher`

---

## 8. Unparseable URL Capture

NDJSON via tracing-subscriber layer at `target: "mining::unparseable"`.

### UnparseableLayer (`src/mining/unparseable_log.rs`)

A `tracing_subscriber::Layer` that:
1. Filters events by target `"mining::unparseable"`
2. Serializes fields to JSON: `raw_url`, `scheme`, `error`, `source_id`, `source_type`, `timestamp`
3. Appends to a file (`V2RAY_HEAL_UNPARSEABLE_LOG` env var, default `unparseable.ndjson`)

### Emission Point

`emit_unparseable_entry()` in `mining/mod.rs` — called from telegram, subscription, and local paths. Filters out promotion/navigation URLs. Consumer-level emission (where `source_id` from registry is available).

---

## 9. CLI Architecture

### Subcommands (`src/main.rs`)

| Subcommand | Description |
|-----------|-------------|
| **`Stdin`** | Pipe data → `parse_sub()` → DB upsert. Source type: `Other`, registry key `stdin://local` |
| **`Config`** | Full pipeline from YAML. Channels + subscriptions from `config.yaml`. Uses `run_with_config()` |
| **`Remote`** | Download subs from URLs or scrape Telegram (t.me auto-detected). Mixed batch OK. |
| **`Local`** | Filesystem → `parse_sub()` → DB upsert. Source URL = `file://` absolute path |
| **`Emit`** | Filtered server export. `--protocol` filter (repeatable), `--min-first-seen-ts`/`--min-last-seen-ts` (humantime duration). Reconstructs URLs from stored `ProtocolConfig` JSON. |

### Global Flags
- `--db <path>` — SQLite database path (default: `v2ray-heal.db`)

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

4. **Host validation rejects private/loopback**: `validate_host_not_private()` in `proto_spec/utils.rs` rejects localhost, 10.x, 192.168.x, 127.x, etc. Prevents misconfigured or internal-only URLs from entering the database.

5. **Separate `sig` from `uid`**: `sig` groups servers by connection configuration (useful for statistical analysis — frequency per hour/day, signature lifetime). `uid` uniquely identifies each server instance via XOR with credential hash.

6. **FK enforcement in upsert**: `upsert_server()` fails if `source_id` is invalid. Sources must exist before servers. Pipeline handles this with lazy source upsert + `HashSet` tracking.

7. **Stream-based mining with `SourceFetcher` trait**: The trait decouples data source (Telegram, subscriptions) from pipeline orchestration. `LiveFetcher` merges via `futures::stream::select`. Testable via `StubFetcher` with in-memory DB.

8. **GITHUB_TOKEN for github.com**: Bearer auth on `raw.githubusercontent.com` / `github.com` requests. Avoids rate limiting on raw content fetches.

---

## 11. Quick Reference: Protocol → Credential / sig Fields

| Protocol   | Credentials (for uid)                                  | sig Key Fields                     |
|-----------|--------------------------------------------------------|------------------------------------|
| **VMess** | `host`, `port`, `uuid` (id)                            | security, transport, sni, aid      |
| **VLESS** | `host`, `port`, `uuid`                                 | security, transport, path, sni, flow, alpn, fp, pbk, sid, splice |
| **Trojan** | `host`, `port`, `password`                            | security, transport, path, sni, alpn, fp |
| **Hysteria2** | `host`, `port` (auth may be in userinfo)          | transport, obfs, insecure, sni, up/down |
| **SS**    | `host`, `port`, `password` (from userinfo)             | method                              |
| **SSR**   | `host`, `port`, `password`                             | all params except remarks           |
| **Slipnet** | `host` (domain), `port` (local_port)                | transport, pk, type                 |
| **SlipnetEnc** | None (uid == sig)                                | N/A (encrypted)                     |
| **TG**    | `secret`, `host`, `port`                               | transport, secret (first bytes)     |
| **Stormdns** | `host`, `port`                                     | sni, transport                      |
| **TUIC**  | `host`, `port`, `uuid`, `password`                     | congestion_control, sni, alpn       |
| **WireGuard** | `host`, `port`, `private_key`                      | address, dns, mtu, public_key, allowed_ips |

---

## 12. Common Test Commands

```bash
# Run all tests (98 pass, 3 ignored)
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

# Filtered export
cargo run -- emit --protocol vmess --protocol vless

# Criterion benchmarks
cargo bench  # raw_urlx, proto_spec, slice_input, permissive_json
```

---

## 13. Rapidhash Usage

All hashing uses `rapidhash::v3::rapidhash_v3()`:
- **sig**: Hash of protocol-specific non-credential fields concatenated as byte slices (per-protocol in each `compute_sig()` method)
- **credential hash**: `rapidhash_v3("host:port:username:password")` via `compute_cred_hash()`
- **uid**: `sig XOR cred_hash`

Source URL hashing (for `sources.id` PK) uses `std::hash::DefaultHasher`, not rapidhash.
