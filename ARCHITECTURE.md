# Gyges Architecture Specification (`gygesd` & `gyges`)

> Revision 2 (2026-10-20). Incorporates the corrections from `OVERVIEW.md` §2.1 and the proposals in §6. Companion documents: `API.md` (gRPC contract), `SYNC.md` (sync state machine), `DATA_MODEL.md` (on-disk schema), `THREAT_MODEL.md`, `TESTING.md`, `ROADMAP.md`, `GLOSSARY.md`.

## 1. Overview
**Gyges** is a pure-Rust Zcash wallet daemon (`gygesd`) and CLI (`gyges`) built on the **Zakura** common and wallet-libraries stack (`zakura-core/common`, `zakura-core/wallet-libraries`), consumed under the upstream library-target names (`zcash_client_backend`, `zcash_client_sqlite`, `pczt`, `orchard`, …) via `package =` renames in `Cargo.toml`.

### Core Capabilities
1. **Direct-to-`zakurad` operation.** Syncs recent blocks, tree states (`z_gettreestate`) and subtree roots (`z_getsubtreesbyindex`), and broadcasts raw transactions (`sendrawtransaction`) against a local or remote pruned `zakurad` JSON-RPC endpoint, with no `lightwalletd` in between. Zakura has one JSON-RPC dialect (zcashd-style, Zebra-derived); its "zcashd-compat mode" is a `zcashd` sidecar for other tools and is not used by Gyges.
2. **Embedded Tor historical backfill.** When a key's `birthday_height` is below the node's `pruneheight` (the lowest height whose block body is still stored; `retained_from` in Gyges), `gygesd` streams `CompactBlock`s for `[birthday, retained_from + k]` over an embedded Tor client (`zcash_client_backend::tor`, backed by `arti-client`) from a user-configured archival `lightwalletd`/`zaino` gRPC endpoint, validates the result against the local node, then continues from the local node. No endpoint is hard-coded.
3. **Independent multi-key profiles.** Each key (`KeyId`) has an isolated `zcash_client_sqlite` database under `~/.gyges/<network>/keys/<key_id>/` with its own ShardTree witnesses, birthday, `scanned_tip` and signing mode (`local-seed`, `keystone-qr`, `watch-only`, `signer-only`).
4. **Daemon-only key material and air-gapped mode.** Key material and SQLite state live only inside `gygesd`. `gygesd --airgapped` disables every network interface and serves `signer-only` profiles over the Unix socket for PCZT proving and signing.
5. **Full address and ZIP 320 (`tex1`) send support.** Sends to Unified (`u1`), Sapling (`zs1`), transparent (`t1`/`t3`) and ZIP 320 TEX (`tex1`/`textest1`) recipients. TEX payments use the upstream two-step proposal plus a durable `TexQueue` broadcaster. Gyges does not *issue* `tex1` receive addresses (OVERVIEW.md Q-T5).
6. **Keystone 3 Pro hardware signing.** Pairs from `ur:zcash-accounts` (CBOR tag 49201) and signs over animated terminal QR codes using the batch protocol (`ur:zcash-sign-batch` 49205 / `ur:zcash-batch-sig-result` 49207) for shielded sends and the single-PCZT protocol (`ur:zcash-pczt` 49204) when transparent inputs are present.

### Pools
Pool support is data, not code paths: `profile.json` carries `spend_pools` and `receive_pools`, and `balance`, `notes` and `address new --receivers` are pool-generic. The node, wallet libraries and Keystone firmware all expose an **Ironwood** pool alongside Sapling and Orchard, and after NU6.3 (regtest height 1, mainnet 3,428,143) the wallet libraries build every shielded output there while the ZIP 318 turnstile keeps value out of Orchard (`OVERVIEW.md` §4.3). MVP policy (ROADMAP.md): spend Orchard, Ironwood and transparent; receive Ironwood, Sapling and transparent; Orchard notes are spent, never created. Since M6 `local-seed` profiles spend Sapling too (§3.2 item 1); Keystone profiles never do.

---

## 2. Workspace Layout

```text
gyges/
├── Cargo.toml                   # workspace; exact `=` pins on every zakura-* crate (Q-D3)
├── Cargo.lock                   # committed; CI builds --locked
├── proto/gyges.proto            # tonic UDS gRPC contract (see API.md)
├── crates/
│   ├── gyges-proto/             # tonic-prost-build output, proto3 JSON impls, GygesError <-> Status, UDS connector, API version constants
│   ├── gyges-qr/                # UTF-8 half-block QR renderer, BC-UR codec, registry tags 49201-49207
│   ├── gyges-chain/             # ChainBackend (node bounds, tree state) + CompactBlockSource: ZakuraRpcBackend (Case A), ArtiTorLwdBackend (Case B)
│   ├── gyges-core/              # config.toml, paths, permission sweep; KeyRegistry, VaultManager, SyncScheduler, TxEngine, TexQueue
│   ├── gygesd/                  # daemon: library (startup checks, pid lock, UDS server, policy layer, service) + thin binary
│   └── gyges-cli/               # `gyges` binary: command router, handshake, exit codes, prompts, QR TUI
└── tests/regtest/               # gyges-regtest: end-to-end harness and scenarios (TESTING.md §2)
```

### 2.1 `gyges-core` components

| Component | Responsibility | Persistent state |
|---|---|---|
| `KeyRegistry` | Enumerates `keys/<id>/profile.json`, opens one `WalletDb` per key, enforces 0700/0600 permissions at startup, resolves `default_key` for requests with an empty `key_id`. | `profile.json` per key |
| `VaultManager` | Encrypts/decrypts `seed.age`, derives the `UnifiedSpendingKey`, owns signing sessions (connection-scoped tokens or daemon-scoped idle TTL), rate-limits failed unlocks per key id, zeroizes on expiry and on `daemon stop`. | `seed.age`; `gyges_signing_sessions` table |
| `SyncScheduler` | Per-key state machine over `gyges-chain` (SYNC.md): node bounds, route selection, shared block cache, reorg truncation, handoff validation, mempool scan. | upstream `WalletDb` tables; `cache/blocks.sqlite` |
| `TxEngine` | Proposal (`propose_transfer`, `propose_standard_transfer_to_address`), PCZT construction (`create_pczt_from_proposal`) and the PCZT role pipeline: Updater → Prover → (Redactor →) Signer → Combiner → Verifier → Spend Finalizer → Tx Extractor. | `gyges_signing_sessions` |
| `TexQueue` | Durable broadcaster for ZIP 320 two-step proposals: persists both raw transactions, re-checks every non-terminal row against the node (`getrawtransaction`) every `tex.rebroadcast_interval` and after each send, rebroadcasts whichever is missing, builds a fresh Step 2 when Step 1 is mined but Step 2 expired (`gyges_core::db::tex`, `gygesd::tex`). | `ext_gyges_tex_queue` table |

---

## 3. Component Data-Flow & State Machines

### 3.1 Hybrid synchronisation pipeline (`SyncScheduler`)
Full detail in `SYNC.md`; summary:

1. **Node bounds.** `ZakuraRpcBackend` calls `getblockchaininfo` and derives `NodeBounds { tip_height, tip_hash, retained_from }`, where `retained_from = pruneheight` when `pruned == true` and `0` otherwise. When the optional indexer gRPC (`[rpc] indexer_listen_addr`) is enabled, `chain_tip_change` and `mempool_change` streams replace polling.
2. **Route selection per key.**
   - **Case A** (`scanned_tip + 1 >= retained_from`): a single `BlockFetcher` fetches `getblock(h, 0)` (plus `getblock(h, 1)` for the tree sizes) once per height through `ZakuraRpcBackend::compact_blocks`, builds synthetic `CompactBlock`s with `zcash_primitives`, and writes them to the shared cache at `cache/blocks.sqlite` (`gyges_chain::cache::BlockDb`, an implementation of `zcash_client_backend::data_api::chain::BlockCache`). Each key runs `scan_cached_blocks` over the cache. The synthetic compact blocks carry every transparent input and output of the raw block, so the cache doubles as the transparent index that a pruned node no longer maintains; the scheduler matches those outputs against each key's receivers.
   - **Case B** (`scanned_tip + 1 < retained_from`, historical restore): `ArtiTorLwdBackend` bootstraps Tor, calls `GetSubtreeRoots` to seed the Sapling and Orchard ShardTrees (`put_sapling_subtree_roots` / `put_orchard_subtree_roots`), streams `GetBlockRange(scanned_tip + 1 .. retained_from + k)` with `k = 10`, and at `V = retained_from + k` validates the stream against the trusted local node: tree roots and leaf counts from `z_gettreestate(V)`, the `prev_hash` chain against `getblockhash`, and completed subtree roots against `z_getsubtreesbyindex`. On any mismatch the key is truncated to its birthday and the endpoint is marked untrusted. On success the key continues in Case A.
3. **Reorgs.** Each poll compares the stored hash at `scanned_tip` with `getblockhash`; the scanner's `PrevHashMismatch` is the second detector. The fork point is found by walking back at most 100 blocks (the node's finality depth, needs verification), `truncate_to_height(f)` rewinds notes, nullifiers and ShardTree checkpoints, and scanning resumes from `f + 1`. Deeper inconsistency puts the key in `Stalled(ChainInconsistent)`.
4. **Pruning race.** The Case A invariant is checked before every batch and on a "block not available" error; on violation the key falls back to Case B when a fallback endpoint is configured, else `Stalled(PrunedPastScanTip)`. `gygesd` warns at startup if the node's `tx_retention` is below `min_retention_blocks`.
5. **"Synced".** *scanned*: `scanned_tip >= tip_height`. *spendable*: additionally `suggest_scan_ranges()` returns nothing above priority `Ignored`. Both are returned by `GetSyncStatus`; `sync wait` defaults to spendable.

Reuse: `zcash_client_backend`'s `sync::run` is bound to a lightwalletd gRPC client and is not used for Case A; everything beneath it (`BlockSource`, `BlockCache`, `scan_cached_blocks`, `suggest_scan_ranges`, `update_chain_tip`, the continuity-error truncation loop) is, and the `spend-index` feature routes transparent spent-ness checks to the node.

### 3.2 Vault lifecycle and inline unlock
1. **Locked by default.** On startup `gygesd` loads only the `UnifiedFullViewingKey` from each key's `accounts` table. Scanning, proposal creation, PCZT construction and **Orchard and transparent** proving work while locked. **Sapling spends cannot be proven while locked**: the Sapling prover needs the proof generation key (`ak`, `nsk`), which is derived from the spending key and is not part of any viewing key. For a proposal with Sapling inputs the daemon requests the unlock *before* proving and uses the PCZT **Updater** role to insert each spend's `proof_generation_key` (ZIP 374 field), then proves, signs and drops the key. `watch-only` profiles are therefore "Orchard proving-only". As built (ROADMAP.md M6, first item): `gyges_core::tx::insert_proof_generation_keys` picks each spend's key by recomputing the note's nullifier under the external and the internal key (Sapling change lands at internal addresses, whose `nsk` differs), `gygesd::tx` obtains the key before `Proving` only when the proposal has Sapling spends, and the PCZT goes from the Updater to the extractor in memory. Files never carry a Sapling spend: `pczt create` leaves Sapling notes out, and `pczt prove` / `pczt sign` refuse one.
2. **Encrypted entropy on disk.** For `local-seed` profiles the 32-byte BIP 39 entropy (not the derived 64-byte seed, so the backup words round-trip) is encrypted with an `age` **scrypt** passphrase recipient at `keys/<key_id>/seed.age`. `age` has no Argon2id mode; the work factor is tuned to about one second and recorded as `seed_format = "age-scrypt-v1"` in `profile.json` so it can be raised by migration. A `rage`-compatible file is a deliberate recovery property.
3. **Inline unlock flow.**
   - `gyges tx send --key main --to u1… --amount 1.0` opens the `SendTransaction` server stream.
   - The daemon emits `Proposed`, proves what it can while locked, then emits `SignatureRequired { key_id, kind: PASSPHRASE, session_id }`.
   - `gyges-cli` prompts `Enter passphrase to unlock key 'main':` (only on a TTY; otherwise exit 4, see CLI_SPEC.md §1.2), calls `UnlockKey { key_id, passphrase, scope: CONNECTION }`, receives a `session_token` bound to that connection, and continues the stream with it.
   - Inside `gygesd` the 32-byte entropy lives in `secrecy::Secret` (zeroized on drop); the `UnifiedSpendingKey` is derived from it for the signing step alone, moved into the signing task and out of scope before verification and broadcast (the upstream type does not zeroize on drop, `THREAT_MODEL.md` §6 item 10). The explicit `gyges key unlock --timeout` path creates a daemon-scoped session with an idle TTL (`vault.unlock_ttl`, default `5m`) instead; it is the weaker mode and documented as such in `API.md`.
   - Errors are typed: `failed_precondition` with a `GygesError { reason: VAULT_LOCKED, key_id }` detail, never a string the client has to parse.

### 3.3 ZIP 320 (`tex1`) two-step orchestration
When the recipient parses as a TEX address (`zcash_address::ZcashAddress::try_from_tex` on the decoded form; there is no `kind::tex` module):
1. **Proposal.** `propose_standard_transfer_to_address` returns a two-step `Proposal`.
2. **Plan.** *Step 1* spends shielded notes to an ephemeral transparent P2PKH address derived from the ZIP 32 ephemeral chain, for exactly `amount + fee₂` with no change on that address. *Step 2* spends that single output to the 20-byte pubkey hash of the `tex1` address in a pure transparent transaction (one input, one output, so `fee₂` is the ZIP 317 minimum and fixed at proposal time). ZIP 320 mandates the two-transaction structure and seed-recoverable, unlinkable ephemeral addresses; the exact output value, derivation path and gap limit are `zcash_client_backend` implementation behaviour, not ZIP text.
3. **Execution.** `create_proposed_transactions` builds, proves, signs and stores both steps with a shared `expiry_height`; both are signed in the same session (one passphrase, obtained *before* proving because the builder needs the key for both at once; upstream's PCZT path takes single-step proposals only, API.md §9). `TexQueue` persists both raw transactions in `ext_gyges_tex_queue` (DATA_MODEL.md §5.1), broadcasts Step 1 then Step 2 immediately (Zakura's mempool accepts a transaction spending an unconfirmed transparent output of another mempool transaction, verified on v1.6.0, and evicts descendants with their parent), and drives the row through `built → step1_broadcast → step2_broadcast → step1_mined → step2_mined` on what `getrawtransaction` says. Reorg, eviction or a node restart (which empties Zakura's mempool) loses Step 1 and with it Step 2; the queue rebroadcasts both from the stored bytes, without the key. Shared expiry means both expire together (`expired`) and funds never leave the shielded pool; Step 1 mined with Step 2 unmined at the expiry height is `step2_failed`, and `gyges tx resume` builds a new Step 2 (`gyges_core::tx::build_tex_step2`: a hand-made single-step proposal spending the ephemeral output, after telling the wallet the output was seen unspent past the old expiry) through a fresh signing session. Seed-only recovery finds a stranded ephemeral UTXO through the ephemeral-receiver gap scan and it reappears as transparent balance.
4. **Dry run.** `--dry-run` returns the full proposal, rendered one block per step with `Total debit: amount + fee₁ + fee₂`; `--json` emits the upstream proposal protobuf as proto3 JSON.

### 3.4 Keystone 3 Pro hardware signing (`keystone-qr`)
1. **Import (`gyges key import-keystone`).** Parses `ur:zcash-accounts` (49201): `seed_fingerprint`, `accounts: [{ufvk, index, name?}]`, `device_version?`. The payload carries **no birthday**; `--birthday` is required or prompted, defaulting to the NU5 activation height (1,687,104 on mainnet) because the exported UFVK has only transparent and Orchard components and cannot have received shielded funds earlier. `profile.json` records `spend_pools` and `receive_pools` `["orchard", "ironwood", "transparent"]` and `device_version`; firmware older than the minimum Zodl requires for Ironwood (v3.0.2, which the pairing QR reports as `13.0.2`) is refused. Keystone does not sign Sapling spends.

   *Landed (ROADMAP.md M5, second item)* as `gygesd::keys::import_keystone` and `KeyRegistry::create_keystone`. Only `ur:zcash-accounts` is accepted, since a lone UFVK has no seed fingerprint. The UFVK is imported with `import_account_ufvk` as a spending account whose ZIP 32 derivation is the device's seed fingerprint and account index, so every PCZT the wallet builds carries the BIP 44 / ZIP 32 paths the device needs to find its key. The firmware floor and its numbering live in `gyges_qr::firmware`; an export without a version is imported only with `--allow-unknown-firmware`.
2. **Signing (`gyges tx send` or `gyges pczt sign`).**
   - `gygesd` builds the PCZT and proves it on the host (`pczt::roles::prover::Prover` with `zcash_proofs::prover::LocalTxProver`), then stores the proven PCZT in a `gyges_signing_sessions` row and emits `SignatureRequired { kind: KEYSTONE, session_id }`.
   - **Shielded-only sends** use the batch protocol: the daemon runs `redact_pczt_for_batch_signer`, `gyges-cli` encodes `ur:zcash-sign-batch` (49205) as fountain frames and renders an 8 FPS UTF-8 half-block QR loop; the device returns `ur:zcash-batch-sig-result` (49207), a single frame of `(pool, action_index, signature)` tuples with the echoed `request_id`, which the daemon applies to its stored proven PCZT. No Combiner is needed.
   - **Sends with transparent inputs** (shielding, ZIP 320 Step 2) use the single-PCZT protocol: `Redactor` strips proofs, witnesses and the Gyges `proprietary` map but **never** amounts, recipients or memos the device displays; the device returns the signed `ur:zcash-pczt` (49204); the daemon runs **Combiner** on (proven ⊕ signed), which rejects structurally different PCZTs and is the correlation check. TEX Step 2 on Keystone is **needs verification on hardware**.
   - Both paths then run **Verifier** against the stored proposal (refusing to broadcast if any output, amount, fee or anchor differs), **Spend Finalizer**, **Tx Extractor**, and broadcast. `tx send` prints the same summary the device shows.
   - *Landed (ROADMAP.md M5, third item)* as `gyges_core::keystone` and `gygesd::keystone`, with one change from the steps above: the device is shown the PCZT **before** it is proven, as Zodl does. Proofs are not signed over, so this keeps the QR loop shorter. The proven copy is what is stored and what the answer is applied to. **What the device is shown (the Redactor's field list, THREAT_MODEL.md §5 row 9):**
     - **Both protocols:** the `gyges.*` tags are removed from the global proprietary map (`keystone::strip_gyges_tags`), then upstream's redaction applies.
     - **Batch:** `redact_pczt_for_batch_signer`, the compact view.
       - Removed: upstream's proposal, one-time-spend and output proprietary entries; spend witnesses; dummy spending keys; proofs; `bsk`; v6 anchors; spend FVKs; existing signatures; and the randomizer of actions already signed.
       - Fields the device can recompute are compacted.
     - **Single PCZT:** `redact_pczt_for_signer(SignerView::Full)`.
       - Removed: the same upstream proprietary entries, spend witnesses and dummy spending keys.
       - Kept: FVKs, randomizers and derivation paths.
     - **Never removed:** values, recipients, `user_address` and the encrypted memos.

     `CompleteKeystoneSign` applies the answer (batch signatures through `Signer::apply_orchard_spend_auth_signature`, which verifies each one; the single PCZT through the Combiner), requires every signature, runs the Verifier against the approved proposal, and only then claims the session and broadcasts.
   - *Camera (ROADMAP.md M5, fourth item):* `gyges_qr::scan` (always built) decodes frames with `rqrr`, keeps only `ur:` frames of the expected answer type, and drops a re-read of the request. `gyges_qr::camera` (feature `camera`, off by default) is the `nokhwa` frame source. `tx send` uses it by itself when the build has it, falling back to pasted frames.
   - Host ingestion of the device's QR: `gyges pczt qr-scan` (laptop camera, used automatically when present), `gyges pczt qr-import --from-file` / stdin (one `ur:` frame per line), or positional frames for single-frame payloads. Sessions survive restarts, expire after `vault.signing_session_ttl` (default `24h`), and can be completed later with `--session <id>` (CLI_SPEC.md §2.6).

### 3.5 Air-gapped PCZT flow (`signer-only`, `gygesd --airgapped`)
A PCZT produced online after the Constructor and Updater roles carries, per spend, the note, `rseed`, Merkle witness and anchor, so the offline box needs no chain state and no `wallet.sqlite`. Transport is a binary `.pczt` file (postcard serialization) on removable media: `gyges pczt create … -o tx.pczt` online → `gyges pczt prove tx.pczt | gyges pczt sign -o tx.signed.pczt` offline → `gyges pczt broadcast tx.signed.pczt` online, where the online side runs Verifier first. QR transport works but a proven Orchard action is several kilobytes, so it is documented as slow. PCZTs carry `gyges.key_id`, `gyges.network` and `gyges.session_id` in the ZIP 374 global `proprietary` map; `--key` is only an assertion.

*Landed (ROADMAP.md M4, first item) as `gygesd::roles`, `gyges_core::pczt_io` and `gyges_core::db::sessions`.* `CreatePczt` writes the tags through the Updater role and stores the approved proposal, reduced to what the Verifier checks, in the key's `ext_gyges_signing_sessions` row under the session id (DATA_MODEL.md §5.2); `BroadcastPczt` finds that row by the tag and runs the Verifier against it before the Spend Finalizer and Transaction Extractor, so the online side never trusts the file's own amounts. The file gets `target + 1152` blocks of expiry (about a day), since it waits for a person; the anchors it carries stay valid. `InspectPczt` works from the file alone: the amounts, recipients, fee and expiry it implies, and the roles whose footprints are present (proofs, signatures, finalised inputs), read through the Verifier role's parsed bundles. The `signer-only` half landed with the second M4 item: `SignPczt` on an `--airgapped` daemon resolves each transparent input's key from the BIP 44 derivation the file carries (upstream writes one on every input of an HD account), checked against the profile's seed fingerprint and account, so no wallet is needed; the Signer role then refuses a key that does not match the input's script.

### 3.6 Daemon lifecycle
- **Start.** `gyges daemon start` (or the `launchd`/`systemd --user` unit written by `gyges daemon install`, `gyges_cli::service`, which restarts the daemon only after a failure; reinstalling is the upgrade step). The CLI does not auto-start the daemon (exit 3 with the fix) unless `GYGES_AUTOSTART=1`. Startup refuses to run if `~/.gyges/<network>` has permissions wider than 0700/0600. Before anything else the daemon sets its umask to 077 and `RLIMIT_CORE` to zero (a core dump would hold key material; `THREAT_MODEL.md` §6 item 10). The first successful node poll warns once when `zakura_rpc.url` is not `localhost` or a loopback address (§6 item 12).
- **Connections.** One UDS per network at `~/.gyges/<network>/gygesd.sock`, mode 0600 (0660 with a `gyges` group in the hardened deployment). Every accepted connection is checked with `SO_PEERCRED`/`LOCAL_PEERCRED` against the daemon's uid (or an allow-list).
- **Stop.** `gyges daemon stop` finishes the current scan batch (at most one `scan_cached_blocks` call), checkpoints SQLite WAL, leaves `ext_gyges_tex_queue` and `gyges_signing_sessions` rows in place to resume on next start, aborts in-progress proving, and zeroizes every unlocked key.
- **Logs.** `logs/gygesd.<date>.log` (daily rotation, seven files, filtered by `daemon.log_level` or `RUST_LOG`) and `logs/audit.log` (one JSON object per line for every `gyges::audit` event, whatever the configured level: unlock, lock, export, session created/completed/aborted, sign, broadcast and rewind, with key id and time only; never rotated). `gyges daemon logs [--audit]` reads the daemon's in-memory tail of either log through the `StreamLogs` RPC (`gygesd::logs`). Sensitive values are wrapped in `gyges_core::Sensitive<T>` whose `Debug`/`Display` print `[redacted]`.

### 3.7 Performance features
Every build proves and trial-decrypts on all cores: `multicore` is a default feature of the upstream crates, and `RAYON_NUM_THREADS` caps it. On aarch64 (Apple Silicon, aarch64 Linux) every build also uses `zakura-pasta-curves`' assembly field arithmetic, which `zakura-halo2-proofs` turns on for those targets. On x86-64 the assembly is the opt-in feature `perf-asm-x86_64` (on `gygesd` and `gyges-core`): it needs BMI2 and ADX and has no runtime fallback (`THREAT_MODEL.md` §6 item 2), so default and release builds use the portable code. `Provers::orchard` builds the Orchard/Ironwood proving key once per daemon and prepares its commitment tables (`ProvingKey::prepare_proving`, about 30 MiB), which upstream uses on pools of at most eight threads (ten on AArch64 macOS). Timings belong in `docs/BENCHMARKS.md`, not here.

---

## 4. Directory & Configuration Layout (`~/.gyges/<network>/`)

One directory per network so mainnet, testnet and regtest daemons coexist (full schema in `DATA_MODEL.md`):

```text
~/.gyges/
└── mainnet/                     # 0700
    ├── config.toml              # daemon configuration (the CLI never reads it)
    ├── gygesd.sock              # Unix Domain Socket, 0600
    ├── gygesd.pid
    ├── tor_cache/               # arti directory and consensus cache
    ├── cache/blocks.sqlite      # shared CompactBlock cache, 0600
    ├── logs/{gygesd.log,audit.log}
    └── keys/
        ├── main/
        │   ├── profile.json     # id, signing_mode, birthday_height, spend_pools, receive_pools, seed_format
        │   ├── wallet.sqlite    # zcash_client_sqlite WalletDb + gyges_* tables
        │   └── seed.age         # age-scrypt encrypted BIP 39 entropy (local-seed, signer-only only)
        └── keystone-vault/
            ├── profile.json
            └── wallet.sqlite
```

### Example `config.toml`
Valid TOML; `~` is expanded by the daemon in every path value.

```toml
network = "mainnet"
default_key = "main"
airgapped = false
min_retention_blocks = 10000

[zakura_rpc]
url = "http://127.0.0.1:8232"
cookie_path = "~/.cache/zakura/.cookie"
poll_interval_secs = 15
# indexer_grpc_url = "http://127.0.0.1:8233"   # optional zakurad indexer gRPC

[fallback_lightwalletd]
enabled = false
# grpc_url is required when enabled = true; there is no default (Q-D5).
# grpc_url = "https://example-archival-endpoint:9067"
use_tor = true
broadcast_via_tor = false

[vault]
unlock_ttl = "5m"
signing_session_ttl = "24h"
allow_seed_export = true

[cache]
retain_blocks = 1000
max_mb = 2048
keep_historical = false

[mempool]
scan = true
```
