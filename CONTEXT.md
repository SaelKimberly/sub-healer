# CONTEXT.md — v2ray-heal Project Context

> Auto-generated for AI agent sessions. Last updated: 2026-05-14.

---

## 1. Project Overview

**v2ray-heal** is a Rust-based proxy subscription miner and aggregator. It:
- Scrapes Telegram channels for V2Ray proxy URLs (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, etc.)
- Downloads and parses v2ray subscription files from URLs
- Parses, normalizes, and deduplicates proxy configurations
- Validates connectivity and outputs curated subscription lists
- Persists data to SQLite with time-travel upsert semantics to track origin and lifetime of every parsed config URL

**Stack**: Rust 2024 edition, `tokio` (async I/O) + `rayon` (parallel CPU), `rusqlite` (SQLite with bundled feature), `mimalloc` (global allocator), `reqwest` (HTTP), `scraper` (HTML), `rapidhash` (hashing), `serde`/`simd-json` (serialization).

**Entry point**: `cargo run --bin v2ray-heal -- mine`

---

## 2. Project Structure

```
src/
├── main.rs                      # CLI: mine, remote, local, config subcommands
├── lib.rs                       # Core library: parse_sub, download_sub, download_sub_proxies
├── db.rs                        # SQLite: init_db, upsert_source, upsert_server, get_server, get_sightings
├── error.rs                     # Error types (CutResult, NomError, RawResult, Span)
├── urlx/
│   ├── mod.rs                   # UrlX struct, try_accept(), reconstruct(), ProtoVisitor re-exports
│   ├── proto_vis/
│   │   ├── mod.rs               # ProtoVisitor trait, _compute_uid(), _compute_credential_hash(), try_accept_raw() fallback dispatcher
│   │   ├── vmess.rs             # VMess protocol (JSON in userinfo)
│   │   ├── vless.rs             # VLESS protocol (query params)
│   │   ├── trojan.rs            # Trojan protocol (query params)
│   │   ├── hysteria2.rs         # Hysteria2 protocol (query params)
│   │   ├── ss.rs                # Shadowsocks protocol (base64 userinfo)
│   │   ├── ssr.rs               # SSR protocol (base64-encoded colon-delimited userinfo)
│   │   ├── slipnet.rs           # SlipNet / SlipNet-enc (base64 body, no query params)
│   │   ├── tg.rs                # Telegram MTProto proxy (t.me/proxy format)
│   │   └── wireguard.rs         # WireGuard (stub — falls through to fallback)
│   ├── schemex.rs               # SchemeX enum (all supported URI schemes)
│   ├── split_url.rs             # RawUrlX struct (parsed URI components before protocol-specific parsing)
│   ├── user_info.rs             # UserInfo enum (Text, Json, B64) with encoding/decoding
│   ├── port_spec.rs             # PortSpec (u16 port or string range)
│   ├── serde_util.rs            # host_serde, port_serde custom serializers
│   ├── valid_url.rs             # URL validation utilities
│   └── sanitize.rs              # (if exists) sanitization logic
├── mining/
│   ├── mod.rs                   # Main mining pipeline: run() → run_telegram() + run_subscriptions()
│   ├── telegram.rs              # Telegram channel scraper (JS widget parsing)
│   ├── extractor.rs             # Proxy URL extraction from HTML/JS
│   ├── validator.rs             # Proxy connectivity validation
│   ├── output.rs                # YAML/TXT output generation
│   ├── sub.rs                   # Subscription download handling
│   └── config.rs                # YAML config loading (channels, subscriptions)
└── utils/
    ├── mod.rs                   # Re-exports from submodules
    ├── urlx.rs                  # Legacy URL parsing/normalization (being replaced by urlx/)
    ├── line.rs                  # Line/LineBatch processing for subscription parsing
    ├── host_port.rs             # host_port_spec() parser (nom-based)
    ├── port.rs                  # Port parsing utilities
    ├── norm_extras.rs           # normalize_extras() — fix malformed proxy strings
    ├── percent_encoding.rs      # Percent encoding/decoding helpers
    ├── permissive_json.rs       # Permissive JSON parser (tolerant of malformed input)
    └── unescaper.rs             # Unescaper for URL-encoded strings
```

---

## 3. Core Data Model

### UrlX Struct (`src/urlx/mod.rs:30-64`)
The central parsed representation of a proxy URL:

```rust
pub struct UrlX {
    pub(crate) uid: u64,                    // Unique ID (sig XOR cred_hash)
    pub(crate) sig: u64,                    // Signature (non-credential params hash)
    pub(crate) schema: SchemeX,             // Protocol scheme
    pub(crate) host: Option<HostSpec>,      // Hostname/IP (ServerName)
    pub(crate) port: Option<PortSpec>,      // Port or range
    pub(crate) username: UserInfo,          // Username field (varies by protocol)
    pub(crate) password: Option<TinyText>,  // Password/key
    pub(crate) path: Option<TinyText>,      // URL path
    pub(crate) query: Vec<(TinyText, Option<TinyText>)>,  // Query params
    pub(crate) fragment: Option<TinyText>,  // Fragment (#remarks)
    pub(crate) transport: Option<TinyText>, // Transport (tcp, ws, grpc, etc.)
    pub(crate) security: Option<TinyText>,  // Security (tls, reality, none, etc.)
}
```

**Important**: `uid` and `sig` are set to `0` during `parse()`, then computed in `visit()`. They must NOT be relied upon until after the visitor runs.

### SchemeX Enum (`src/urlx/schemex.rs`)
All supported URI schemes: `Vmess`, `Vless`, `Trojan`, `SS`, `SSR`, `Hysteria`, `Hysteria2`, `Tg`, `Https`, `Slipnet`, `SlipnetEnc`, `WireGuard`.

### RawUrlX Struct (`src/urlx/split_url.rs`)
Pre-protocol-split representation from a raw URI string. Contains: `schema`, `userinfo`, `hostport`, `path`, `query`, `fragment`.

### UserInfo Enum (`src/urlx/user_info.rs`)
Three variants:
- **Text** — plain string (VLESS user UUID, Trojan password, etc.)
- **Json** — decoded JSON object (VMess `id`/`aid`/`net`/`scy`/etc.)
- **B64** — base64-encoded blob (SS/SSR/Sslipnet userinfo)

---

## 4. ProtoVisitor Trait (`src/urlx/proto_vis/mod.rs:46-51`)

```rust
pub trait ProtoVisitor {
    fn parse(raw: &RawUrlX<'_>) -> Result<UrlX, ParseError>;   // Protocol-specific parsing
    fn build(url: &UrlX) -> Result<String, ParseError>;         // Reconstruct URL from UrlX
    fn visit(url: &mut UrlX) -> Result<(), ParseError>;         // Compute sig/uid (POST-parse)
}
```

Each protocol implements this trait. The `visit()` method is called **after** `parse()` completes and is responsible for computing `sig` and `uid`.

### Parsing Flow
```
UrlX::try_accept::<MyProto>(url_str)
  → RawUrlX::from(url_str)          // Split URI into components
  → MyProto::parse(&raw)            // Protocol-specific extraction → UrlX (uid/sig = 0)
  → MyProto::visit(&mut parsed)     // Compute sig, then uid
  → Return UrlX with uid/sig populated
```

### Fallback Dispatcher (`try_accept_raw`, lines 142-209)
If the primary protocol parse fails with certain errors (`InvalidStructure`, `MissingHost`, `MissingPort`, `InvalidUserInfo`, `Unknown`), the dispatcher tries **all other protocols** in sequence. This handles mislabeled or ambiguous proxy URLs.

---

## 5. sig/uid Computation (CRITICAL — Step 6 Implementation)

### Signature (`sig`)
A `u64` rapidhash v3 hash of **non-credential** connection parameters. Purpose: identify servers by their connection configuration regardless of server location or credentials.

Per-protocol sig composition:

| Protocol     | sig includes                                                                 | Excludes                          |
|-------------|----------------------------------------------------------------------------|-----------------------------------|
| **VMess**   | `schema:scy:net:aid:sni:ves:seq`                                             | `add`, `port`, `id`, `ps`         |
| **VLESS**   | `schema:security:type:path:encryption:sni:flow:alpn:fp:pbk:sid:splice`      | `encryption=none`, `type=tcp`     |
| **Trojan**  | `schema:security:type:path:sni:alpn:fp`                                      | `password` (in userinfo)          |
| **Hysteria2**| `schema:security:obfs:obfs-password:insecure:sni:up:down`                   | —                                 |
| **SS**      | `schema:method` (e.g. `aes-256-gcm`)                                         | `password`, `host`, `port`        |
| **SSR**     | `schema` + all query params except `remarks`                                 | `remarks` (fragment)              |
| **Slipnet** | `schema:transport:pk:type`                                                   | —                                 |
| **SlipnetEnc**| `uid == sig` (no exposed credentials)                                      | All (encrypted config)            |
| **TG**      | `schema:transport` (e.g. `socks` or `mtproto`)                               | `secret`, `server`, `port`        |

### Unique ID (`uid`)
`uid = sig XOR rapidhash_v3(credential_hash)`

Where `credential_hash = rapidhash_v3(host:port:username:password)`.

- If all credential fields are empty, `credential_hash = 0`, so `uid == sig`.
- For **SlipnetEnc**, `uid = sig` explicitly (no credentials exposed in config).
- For **SS**, the `method` field is stored in `security` (not `password`), so the credential hash only includes the actual password portion of the userinfo.

### Helper Functions (`src/urlx/proto_vis/mod.rs`)
```rust
fn _host_str(url: &UrlX) -> String       // Extract host as String
fn _port_str(url: &UrlX) -> String       // Extract port as String
fn _username_str(url: &UrlX) -> String   // Extract username as String
fn _password_str(url: &UrlX) -> String   // Extract password as String
fn _compute_credential_hash(url: &UrlX) -> u64  // rapidhash of host:port:user:pass
fn _compute_uid(url: &UrlX) -> (u64, u64)        // Returns (uid, sig)
```

---

## 6. Database Schema (`src/db.rs`)

### Tables
- **`sources`** — Deduplication of source URLs (Telegram channels, subscription links)
  - `id` (INTEGER PRIMARY KEY, hash of URL), `url` (TEXT)
  
- **`servers`** — Deduplicated proxy server records (upserted by `uid`)
  - `id` (INTEGER PRIMARY KEY = `uid as i64`), `schema`, `host`, `port`, `transport`, `security`, `remarks`, `raw_config` (JSON), `first_seen_ts`, `first_seen_source_id`

- **`sightings`** — Time-travel tracking of when each server was observed from each source
  - `id` (AUTOINCREMENT), `server_id`, `source_id`, `seen_ts`, `remarks`

### Indexes
- `idx_sightings_server_ts` on `sightings(server_id, seen_ts)`
- `idx_servers_schema_security` on `servers(schema, security)`

### Upsert Logic
`upsert_server()` implements time-travel upsert:
- **New server**: INSERT into `servers` + INSERT first sighting
- **Existing server**: If incoming timestamp is *earlier* than `first_seen_ts`, backfill the old record as a sighting and update `first_seen_ts`/`first_seen_source_id`/`remarks`. Always INSERT a new sighting for the current observation.

---

## 7. Mining Pipeline (`src/mining/`)

### Flow
1. **Config** (`config.rs`): Load `config.yaml` with Telegram channels + subscription URLs
2. **Telegram** (`telegram.rs`): Fetch channel messages, parse `.js-widget_message_wrap` for proxy links
3. **Extractor** (`extractor.rs`): Extract URLs from HTML/JS content
4. **Validator** (`validator.rs`): Test proxy connectivity (not yet fully wired)
5. **Output** (`output.rs`): Generate YAML/TXT subscription files
6. **DB Integration** (`mod.rs`): `run_subscriptions()` downloads sub URLs, parses proxies, upserts to DB with `urlx.uid` deduplication

### Key Constants
- `PROXY_URL`: `http://127.0.0.1:20172` (local proxy for outbound requests)
- `SEMAPHORE_PERMITS`: 64 concurrent requests
- `MIN_REMAINING_BYTES`: 1GB minimum disk space
- `USER_AGENT`: `clash-verge/v2.0.2`

**Note**: The Telegram mining pipeline is partially commented out in `mod.rs`. The `v2ray-heal mine` command calls `run()` which executes `run_telegram()` then `run_subscriptions()`.

---

## 8. Duplicate Architecture: Two UrlX Types

**Critical context for contributors:**

| Location             | Type         | Status     |
|---------------------|-------------|------------|
| `src/urlx/mod.rs`   | New `UrlX`  | **Active** — used by proto_vis, db, lib |
| `src/utils/urlx.rs`  | Legacy `UrlX` | **Deprecated** — re-exported via `lib.rs` for backward compat |

The `db.rs` and `lib.rs` re-export the legacy `UrlX` from `utils/urlx.rs` but internally use the new `UrlX` from `urlx/mod.rs`. The `UrlXForJson` struct in `db.rs:120-132` handles serialization for the DB `raw_config` column using the new `UrlX`'s fields via `host_str()` method.

---

## 9. Known Issues & Pre-existing Failures

### Test Failures (NOT caused by sig/uid changes)
These failures exist in the fallback parsing logic (`try_accept_raw`):
- **VMess → SS fallback**: Some VMess URLs fail primary parse and get mis-parsed as SS
- **SSR `InvalidStructure`**: Certain SSR URLs with non-standard encoding fail
- **WireGuard**: Stub implementation — always falls through to fallback

### Root Cause
`try_accept_raw()` catches `InvalidStructure`/`MissingHost`/`MissingPort` errors and retries all protocols. Some VMess URLs (which embed everything in base64 JSON userinfo) fail the VMess parse if the JSON is slightly malformed, then accidentally succeed as SS or another protocol. This is **pre-existing behavior**, not a regression.

### Workaround
Tests that fail on the first `visit_basic()` call may pass on the fallback — this is expected. The round-trip tests (`test_reconstruct_*_roundtrip`) for VLESS, Trojan, Hysteria2, SS, SSR, and Slipnet all pass correctly.

---

## 10. Key Design Decisions & Rationale

1. **Vec<String> for sig_parts** (instead of `Vec<&[u8]>`): Avoids lifetime issues with temporary `to_string()` values. Small performance trade-off for correctness.

2. **SlipnetEnc `uid == sig`**: The encrypted config contains no exposed credentials (host/port are inside the encrypted blob). Setting `uid = sig` ensures unique identification without credential-derived entropy.

3. **_compute_credential_hash() returns 0 when all fields empty**: Ensures `uid == sig` for credential-less configs (e.g., Hysteria2 with auth via `auth_str` in query rather than userinfo).

4. **Separate `sig` from `uid`**: `sig` groups servers by connection configuration (useful for statistical analysis — frequency per hour/day, signature lifetime). `uid` uniquely identifies each server instance.

5. **`visit()` as post-parse hook**: sig/uid depend on the fully-parsed UrlX struct (they need host, port, username, password, query params, and schema). Computing them during `parse()` would require redundant extraction logic.

---

## 11. Quick Reference: Protocol → Credential Fields

| Protocol   | Credentials (for uid)                          |
|-----------|------------------------------------------------|
| VMess     | `host`, `port`, `id` (UUID in password field)  |
| VLESS     | `uuid` (password), `host`, `port`              |
| Trojan    | `username` (from userinfo), `password`, `host`, `port` |
| Hysteria2 | `username` (from userinfo), `host`, `port`      |
| SS        | `username` (method:password in userinfo), `password`, `host`, `port` |
| SSR       | `host`, `port`, `password`                      |
| Slipnet   | `host` (domain), `port` (local_port)           |
| SlipnetEnc| None (uid == sig)                               |
| TG        | `secret` (username/password), `host`, `port`    |

---

## 12. Common Test Commands

```bash
# Run all tests
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
cargo run --bin v2ray-heal -- mine

# CPU profiling
cargo flamegraph --bin v2ray-heal -- mine
```

---

## 13. Rapidhash Usage

All hashing uses `rapidhash::v3::rapidhash_v3()`:
- **sig**: Hash of concatenated non-credential field values joined with `:` (VMess) or raw bytes concatenated (VLESS/Trojan/Hysteria2/SS/SSR/Slipnet/TG)
- **credential hash**: Hash of `host:port:username:password` string
- **uid**: `sig XOR credential_hash`

The XOR operation ensures that two servers with the same connection config but different credentials get different `uid` values while sharing the same `sig`.