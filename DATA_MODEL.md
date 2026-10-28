# Gyges Data Model (`DATA_MODEL.md`)

Everything `gygesd` writes to disk: the directory layout, `config.toml`, `profile.json`, `seed.age`, the Gyges-owned SQLite tables that sit beside the upstream `zcash_client_sqlite` schema, the shared block cache, and the migration and backup policy. Derived from the proposals under Q-C2, Q-S5…S7, Q-T1, Q-K4 and Q-Y3 in `OVERVIEW.md`.

---

## 1. Directory Layout

One home per network (Q-C2). `GYGES_HOME` (default `~/.gyges`) is the root.

```text
~/.gyges/
└── mainnet/                     # or testnet/, regtest/
    ├── config.toml              # Daemon configuration (§2)
    ├── gygesd.sock              # Unix Domain Socket
    ├── gygesd.pid               # PID of the running daemon, advisory-locked
    ├── tor_cache/               # Arti directory and consensus cache
    ├── fallback_trust.json      # Only after a failed handoff: the untrusted endpoint and why (SYNC.md §5.2)
    ├── cache/
    │   └── blocks.sqlite        # Shared CompactBlock cache (§6)
    ├── logs/
    │   ├── gygesd.YYYY-MM-DD.log  # tracing-appender, daily rotation, 7 kept
    │   └── audit.log            # Security-relevant events as JSON lines, key id + time only; never rotated
    └── keys/
        └── <key_id>/
            ├── profile.json     # KeyProfile metadata (§3)
            ├── wallet.sqlite    # zcash_client_sqlite WalletDb + Gyges tables (§5)
            ├── backfill.json    # Only while a Case B backfill awaits its handoff (SYNC.md §5)
            ├── transparent_recovery.json  # After a validated backfill: what GetAddressUtxos gave and what was kept (SYNC.md §5.3)
            └── seed.age         # Only for local-seed and signer-only (§4)
```

`key_id` matches `^[a-z0-9][a-z0-9_-]{0,31}$`.

### Permissions (Q-S7)

| Path | Mode | Enforced |
|---|---|---|
| every directory under `GYGES_HOME` | `0700` | daemon refuses to start on anything wider |
| every file | `0600` | same |
| `gygesd.sock` | `0600` (`0660` with `daemon.socket_group` set) | checked after bind |

The refusal message names the path and the one-line `chmod` that fixes it. Tilde in any configured path is expanded by the daemon; the CLI never reads these files.

---

## 2. `config.toml`

Complete schema with defaults. Every key is optional except `fallback_lightwalletd.grpc_url` when `fallback_lightwalletd.enabled = true`. On first start, when the file is missing, `gygesd` writes a commented template (`gyges_core::config::template`, 0600): every line is a comment, so it changes nothing, and on mainnet it lists the public endpoints below, with the advice to prefer an operator's `.onion` address.

```toml
# ~/.gyges/mainnet/config.toml
network = "mainnet"              # optional; when set it must match the directory, else the daemon refuses to start
default_key = "main"             # substituted by the daemon when a request has an empty key_id
airgapped = false                # true disables every network interface (Tor, RPC, indexer)

[daemon]
socket_group = ""                # non-empty: socket mode 0660 owned by this group (name or numeric gid)
allowed_uids = []                # peer uids besides the daemon's own that may connect (API.md §1.2)
log_level = "info"               # tracing filter; overridden by RUST_LOG
offline_grace = "2m"             # node unreachable longer than this -> Stalled(Offline)
shutdown_grace = "30s"           # bound on how long `daemon stop` waits for in-flight proving and broadcasts

[zakura_rpc]
url = "http://127.0.0.1:8232"
cookie_path = "~/.cache/zakura/.cookie"   # HTTP Basic from the cookie; "" for an unauthenticated listener
indexer_url = ""                 # gRPC indexer (zakurad [rpc] indexer_listen_addr); "" = poll JSON-RPC
poll_interval_secs = 15
min_retention_blocks = 10000     # warn at startup if the node retains fewer blocks than this

[fallback_lightwalletd]
enabled = false
grpc_url = ""                    # REQUIRED when enabled. No default; see the commented examples below.
use_tor = true                   # false only for regtest/CI
broadcast_via_tor = false        # `--via-tor` for every broadcast; needs enabled and use_tor
overlap_blocks = 10              # k in SYNC.md §5
# Public archival endpoints, operator named. Uncomment one deliberately:
# grpc_url = "https://zec.rocks:443"                     # operated by zec.rocks
# grpc_url = "https://mainnet.lightwalletd.com:9067"     # operated by Electric Coin Co.

[vault]
unlock_ttl = "5m"                # idle timer for `gyges key unlock`; single source of truth
signing_session_ttl = "24h"      # persisted Keystone / non-interactive sessions
allow_seed_export = true         # false disables ExportSeed entirely
unlock_backoff_max = "30s"       # exponential back-off cap on failed unlocks, per key
scrypt_work_factor = 20          # log2(N) for age passphrase recipients; ~1 s on a 2024 laptop

[cache]
retain_blocks = 1000             # kept behind the slowest key for cheap rewinds
max_mb = 2048
keep_historical = false          # true keeps Tor-fetched ranges after they are scanned
fetch_batch = 100
scan_batch = 1000

[mempool]
scan = true

[tex]
rebroadcast_interval = "60s"     # how often non-terminal tex_queue rows are re-checked
max_attempts = 0                 # 0 = retry until expiry_height

[policy]
min_confirmations = 10           # anchor depth used for "Spendable" and note selection
```

Rules:

- Durations are `humantime` strings (`60s`, `5m`, `24h`).
- `fallback_lightwalletd.grpc_url` must be `https://` or an `.onion` host; `http://` is rejected unless `network = "regtest"`.
- Unknown keys are an error (`serde(deny_unknown_fields)`), so a typo cannot silently fall back to a default.
- `gyges daemon start --zakura-rpc`, `--zakura-cookie`, `--fallback-lwd`, `--no-tor`, `--airgapped` override the corresponding keys for that process only.

---

## 3. `profile.json`

```json
{
  "schema_version": 1,
  "key_id": "main",
  "network": "mainnet",
  "signing_mode": "local-seed",
  "birthday_height": 2650000,
  "created_at": "2026-10-20T10:00:00Z",
  "spend_pools": ["orchard", "ironwood", "sapling", "transparent"],
  "receive_pools": ["orchard", "ironwood", "sapling", "transparent"],
  "seed_format": "age-scrypt-v1",
  "seed_fingerprint": "f0a1…",
  "account_index": 0,
  "label": "Main wallet"
}
```

| Field | Type | Modes | Notes |
|---|---|---|---|
| `schema_version` | int | all | Bumped with the file format; migrations in §7 |
| `key_id` | string | all | Equals the directory name |
| `network` | `mainnet` \| `testnet` \| `regtest` | all | Must equal the home's network |
| `signing_mode` | `local-seed` \| `keystone-qr` \| `watch-only` \| `signer-only` | all | |
| `birthday_height` | int | all except `signer-only` | Required; see defaults below |
| `spend_pools` | list | all | Input selection is restricted to these; `[]` for `watch-only`. A `local-seed` profile written before M6 holds exactly `["orchard", "ironwood", "transparent"]` (no command could change it); the daemon adds `sapling` when it loads one and saves the file (`KeyProfile::upgrade`), and leaves any other list alone |
| `receive_pools` | list | all with a wallet | Default receivers for `address new` |
| `seed_format` | string | `local-seed`, `signer-only` | `age-scrypt-v1` today |
| `seed_fingerprint` | hex | `local-seed`, `keystone-qr`, `signer-only` | ZIP 32 seed fingerprint |
| `device_version` | string | `keystone-qr` | From `zcash-accounts`, as the pairing QR reports it (raw `MAJOR.MINOR.BUILD`, `13.2.0` for the device's v3.2.0); minimum 13.0.2 enforced at import; `"unknown"` when the device reported none and the user passed `--allow-unknown-firmware` |
| `account_index` | int | all | ZIP 32 account; `0` unless imported otherwise |
| `ufvk` | string | `keystone-qr`, `watch-only` | Also stored in `wallet.sqlite`; kept here so a profile is readable without SQLite |
| `label` | string | all | Optional |

Mode examples (fields that differ from the `local-seed` example above):

```json
{ "signing_mode": "keystone-qr", "spend_pools": ["orchard", "ironwood", "transparent"],
  "receive_pools": ["orchard", "ironwood", "transparent"], "device_version": "13.2.0",
  "ufvk": "uview1…", "birthday_height": 1687104 }
```

```json
{ "signing_mode": "watch-only", "spend_pools": [],
  "receive_pools": ["orchard", "ironwood", "sapling", "transparent"], "ufvk": "uview1…" }
```

```json
{ "signing_mode": "signer-only", "spend_pools": ["orchard", "ironwood", "sapling", "transparent"],
  "seed_format": "age-scrypt-v1", "seed_fingerprint": "f0a1…" }
```

A `signer-only` profile has no `wallet.sqlite` and no `birthday_height`; it exists only to prove and sign PCZTs that already contain anchors and witnesses (Q-K5), and is what `key init` creates on a `--airgapped` daemon. `watch-only` has no `seed.age`. `keystone-qr` has neither. `gyges_core::profile::KeyProfile::validate` enforces this table; a profile that breaks it, names another network, or has a `schema_version` newer than the daemon refuses the daemon's start with the key id and the rule in the message.

Birthday defaults when the user does not know it: `key restore` falls back to Sapling activation (419,200 mainnet) with a warning that a full Tor backfill follows; `key import-keystone` defaults to NU5 activation (1,687,104 mainnet) because an Orchard-only key cannot have received shielded funds earlier.

---

## 4. `seed.age`

An ordinary age file (`rage` can decrypt it) with a single scrypt passphrase recipient, armored (`age-encryption.org/v1` ASCII), holding the 32-byte BIP-39 **entropy** of the 24-word mnemonic, not the 64-byte derived seed. Exporting the backup therefore yields the same words the user wrote down.

- Work factor: `vault.scrypt_work_factor`, recorded alongside the file as `profile.json.seed_format` so it can be raised by a migration that re-encrypts.
- Decryption produces `secrecy::Secret<[u8; 32]>` (`gyges_core::vault::Entropy`); the mnemonic and the `UnifiedSpendingKey` derived from it are zeroized on drop.
- The file is written with `O_EXCL` and `0600`, then renamed into place; it is never rewritten except by `gyges key passphrase` (change passphrase) and migrations.

Argon2id is not used; see Q-S5 for the compatible construction if it is ever required.

---

## 5. `wallet.sqlite`

The upstream `zcash_client_sqlite` schema is created and migrated by upstream's `WalletMigrator` and is not modified. Gyges adds its own tables to the same database, so a key directory is self-contained and Gyges' writes are transactional with the wallet state.

**All of it lives in `gyges_core::db`** (`crates/gyges-core/src/db/`). `zcash_client_sqlite` reserves the `ext_` prefix for application tables, so every Gyges table is `ext_gyges_*`. One external migration (`db::MIGRATION`, registered with `WalletMigrator::with_external_migrations` when the registry opens a wallet) creates them from `db/schema.sql`. Every statement runs through `WalletDb::transactionally_with_extension`, whose SQLite authorizer allows reads of any table but writes only to `ext_*` tables, and refuses schema changes and transaction control.

Rules the module enforces:

* **Static SQL, bound values.** Its `Db` wrapper accepts only `&'static str` statements, so SQL cannot be assembled at run time. Every value is a named parameter, and a set is bound as a JSON array and read with `json_each(:param)`. Enums bind through `ToSql`/`FromSql` as their `as_str()` spelling, and an unknown stored value is an error, never a default.
* **One row per statement.** The extension handle offers only `execute` and `query_row`, so a read of many rows is one `json_group_array(...)` cell decoded with serde, or a list of ids followed by one read per id inside the same transaction. BLOB columns go through `hex()` inside JSON.
* **No `AUTOINCREMENT`.** It writes `sqlite_sequence`, which the authorizer refuses.

The CHECK lists in `schema.sql` repeat the enums' spellings, and `db` tests insert every variant so the two cannot drift apart.

### 5.1 `ext_gyges_tex_queue` (Q-T1)

`gyges_core::db::tex`. One row per ZIP 320 transfer, holding both signed steps.

```sql
CREATE TABLE ext_gyges_tex_queue (
    step1_txid       BLOB NOT NULL PRIMARY KEY,
    step2_txid       BLOB NOT NULL,
    proposal         BLOB NOT NULL,
    step1_raw        BLOB NOT NULL,
    step2_raw        BLOB NOT NULL,
    ephemeral_addr   TEXT NOT NULL,
    recipient        TEXT NOT NULL,
    amount           INTEGER NOT NULL,
    expiry_height    INTEGER NOT NULL,
    state            TEXT NOT NULL CHECK (state IN (
                         'built', 'step1_broadcast', 'step2_broadcast',
                         'step1_mined', 'step2_mined', 'step2_failed',
                         'expired', 'failed', 'aborted')),
    created_at       INTEGER NOT NULL,
    last_attempt_at  INTEGER,
    attempts         INTEGER NOT NULL DEFAULT 0,
    last_error       TEXT
);
CREATE INDEX ext_gyges_tex_queue_state ON ext_gyges_tex_queue (state);
```

State machine: `built → step1_broadcast → step2_broadcast → step1_mined → step2_mined` (terminal). The other terminals:
* `expired`: both steps unmined at `expiry_height`.
* `failed`: the node refused Step 1 for a reason other than already having it; its text is in `last_error`.
* `aborted`: `tx abort`, allowed only in `built`.

`step2_failed` means Step 1 is mined but Step 2 was unmined at `expiry_height`; `tx resume` stores a new Step 2 and puts the row back to `step1_mined`.

The row is inserted as `built` before the first broadcast, so a crash between the two leaves something the queue finishes. A node that will not take Step 2 while Step 1 is unmined leaves the row in `step1_broadcast` with its text in `last_error`; the queue offers Step 2 again on every pass and keeps `step1_mined` as the furthest state once the node has Step 1 in a block. Mined heights are recorded in the upstream `transactions` table through `set_transaction_status`.

### 5.2 `ext_gyges_signing_sessions` (Q-K4, Q-C4)

`gyges_core::db::sessions`. One row per signing session that outlives a connection: a PCZT file (`file`) or a Keystone session (`keystone-batch`, `keystone-pczt`). Passphrase sessions of `tx send` are memory-only (API.md §6.1).

```sql
CREATE TABLE ext_gyges_signing_sessions (
    session_id     TEXT NOT NULL PRIMARY KEY,
    protocol       TEXT NOT NULL CHECK (protocol IN ('keystone-batch', 'keystone-pczt', 'file')),
    status         TEXT NOT NULL CHECK (status IN (
                       'awaiting-signature', 'signed', 'broadcast', 'aborted', 'expired')),
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    proposal       BLOB NOT NULL,
    expected       BLOB NOT NULL,
    txid           BLOB,
    last_error     TEXT,
    pczt           BLOB,
    payload        BLOB,
    request_id     BLOB,
    via_tor        INTEGER,
    expiry_height  INTEGER,
    -- A Keystone session always carries its device-side half; a file one never does.
    CHECK ((protocol = 'file') = (pczt IS NULL)),
    CHECK ((pczt IS NULL) = (payload IS NULL)
       AND (pczt IS NULL) = (via_tor IS NULL)
       AND (pczt IS NULL) = (expiry_height IS NULL))
);
CREATE INDEX ext_gyges_signing_sessions_status
    ON ext_gyges_signing_sessions (status, expires_at);
```

* `expires_at` is `created_at + vault.signing_session_ttl`.
* `expected` is `gyges_core::tx::Expected` as JSON: what the Verifier checks the signed PCZT against.
* The nullable columns are a Keystone session's device-side half:
  * `pczt`: the proven, unsigned PCZT the answer is applied to.
  * `payload`: the CBOR shown to the device, for `pczt qr-export --session`.
  * `request_id`: echoed by `zcash-batch-sig-result`.
  * `via_tor`: broadcast through the fallback endpoint.
  * `expiry_height`: completing at or past it is refused.
* The CHECKs make them present exactly for the Keystone protocols.

A file session is inserted as `awaiting-signature` by `CreatePczt` and moved to `broadcast` by `BroadcastPczt`; a second broadcast of the same session is refused.

A Keystone completion moves the row from `awaiting-signature` to `signed` with a conditional update, which is how a session is claimed exactly once, and then to `broadcast` with the txid.
* A node refusal leaves it `signed` with `last_error`.
* A refused device answer leaves it `awaiting-signature` with `last_error`, so the user can scan again.
* Abort and expiry also update only a row still awaiting.

The connection-scoped unlock token from Q-S1 is **not** stored here: it lives only in daemon memory and dies with the connection.

### 5.3 `ext_gyges_address_labels`

`gyges_core::db::labels`. Written by `address new --label` (an upsert keyed on the address as handed out) and read back by `GetCurrentAddress` / `NewAddress`.

```sql
CREATE TABLE ext_gyges_address_labels (
    address     TEXT NOT NULL PRIMARY KEY,
    label       TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
```

### 5.4 Reads of upstream views

`gyges_core::db::history` reads upstream's documented views (`v_received_outputs`, `v_received_output_spends`, `v_tx_outputs`) for `ListNotes` and the outputs of `ListTransactions`, since upstream has no production API for either. These are reads only, through the same handle.

### 5.5 What is not in SQLite

The audit trail is `logs/audit.log` (Q-O1), not a table: it must survive a database wipe, and it must be appendable while a migration holds the database. Decrypted spending keys, passphrases and session tokens are never written anywhere.

---

## 6. Block Cache (`cache/blocks.sqlite`)

Shared by every key on the network (Q-Y3). Implements `zcash_client_backend::data_api::chain::BlockCache`.

```sql
CREATE TABLE compact_blocks (
    height     INTEGER NOT NULL PRIMARY KEY,
    hash       BLOB NOT NULL,
    prev_hash  BLOB NOT NULL,
    source     TEXT NOT NULL CHECK (source IN ('node', 'tor-lwd')),
    data       BLOB NOT NULL,          -- protobuf CompactBlock
    fetched_at INTEGER NOT NULL
);
CREATE TABLE cache_meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL                 -- ('network', 'mainnet')
);
-- The schema version is `PRAGMA user_version` (currently 1).
```

Eviction policy and privacy trade-off are in `SYNC.md` §2.2: `source = 'tor-lwd'` rows reveal an approximate birthday, so the file is `0600` and those rows are dropped once consumed unless `cache.keep_historical = true`. The cache is disposable; deleting it costs a refetch, never wallet state. `data` is the lightwalletd `CompactBlock` protobuf including `vin`/`vout` for every transaction (the Case A transparent index, SYNC.md §2.1), so a cached mainnet block is tens of kilobytes rather than a few. The daemon refuses to open a cache whose `cache_meta.network` is another network or whose `user_version` is newer than its own, naming the file (`gyges_chain::cache::BlockDb::open`).

---

## 7. Migrations

| Store | Mechanism | Trigger |
|---|---|---|
| upstream wallet tables | `WalletMigrator` (schemerz migrations shipped by `zcash_client_sqlite`) | every wallet open, with the Gyges migration |
| `ext_gyges_*` tables | one external `schemerz-rusqlite` migration, `gyges_core::db::MIGRATION` (`db/schema.sql`), run by upstream's `WalletMigrator` with its own; later changes are new migrations depending on it | every wallet open |
| `blocks.sqlite` | `PRAGMA user_version` checked against `gyges_chain::cache::SCHEMA_VERSION`; the file is disposable | every daemon start |
| `profile.json` | `schema_version` switch in `gyges-core::profile`; rewritten atomically after a successful upgrade | profile load |
| `seed.age` | re-encryption only when `seed_format` changes, which requires the passphrase and therefore runs lazily on the next unlock | unlock |
| `config.toml` | never rewritten by the daemon; removed keys produce a startup error naming the replacement | startup |

Downgrades are not supported: a daemon older than the schema version it finds refuses to start (exit 1, message names both versions). Migrations run inside one SQLite transaction per database and are tested in `TESTING.md` §4 by opening fixture databases from every released version.

---

## 8. Backup and Restore (Q-S7)

The minimal backup is the 24-word mnemonic plus `birthday_height`. Everything in `wallet.sqlite` is derived state: notes, witnesses and ZIP 320 ephemeral addresses are all recovered by rescanning from the seed (the "this was a TEX payment" label may be lost, which ZIP 320 accepts).

Convenience commands:

```bash
gyges key backup --id main -o main.tar            # profile.json + seed.age; --with-wallet adds wallet.sqlite
gyges key import-backup main.tar
```

`key backup` runs `PRAGMA wal_checkpoint(TRUNCATE)` on the key's database before archiving, so the archive is consistent. Copying `keys/<id>/` by hand is supported only while the daemon is stopped, because of the WAL files. `gyges key delete --wipe` overwrites `seed.age` and `wallet.sqlite` best-effort before unlinking; on copy-on-write filesystems this is advisory only and the docs say so.
