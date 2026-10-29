# Gyges Architecture

How `gygesd` and `gyges` are put together. The document has three parts:

- [Components](#components): the workspace, the data flow and state machines of each component, and the directory layout.
- [Sync](#sync): how each key syncs against a pruned Zakura node, backfills older history from an archival endpoint, and handles reorgs.
- [Data model](#data-model): every file the daemon writes, `config.toml`, `profile.json`, the `wallet.sqlite` extension tables, the block cache, migrations and backups.

Section numbers restart in each part. A bare § refers to the part it appears in; a reference into another part names it (for example "Sync §4.2").

## Components

### 1. Overview
**Gyges** is a pure-Rust Zcash wallet daemon (`gygesd`) and CLI (`gyges`) built on the **Zakura** common and wallet-libraries stack (`zakura-core/common`, `zakura-core/wallet-libraries`), consumed under the upstream library-target names (`zcash_client_backend`, `zcash_client_sqlite`, `pczt`, `orchard`, …) via `package =` renames in `Cargo.toml`.

#### Core Capabilities
1. **Direct-to-`zakurad` operation.** Syncs recent blocks, tree states (`z_gettreestate`) and subtree roots (`z_getsubtreesbyindex`), and broadcasts raw transactions (`sendrawtransaction`) against a local or remote pruned `zakurad` JSON-RPC endpoint, with no `lightwalletd` in between. Zakura has one JSON-RPC dialect (zcashd-style, Zebra-derived); its "zcashd-compat mode" is a `zcashd` sidecar for other tools and is not used by Gyges.
2. **Embedded Tor historical backfill.** When a key's `birthday_height` is below the node's `pruneheight` (the lowest height whose block body is still stored; `retained_from` in Gyges), `gygesd` streams `CompactBlock`s for `[birthday, retained_from + k]` over an embedded Tor client (`zcash_client_backend::tor`, backed by `arti-client`) from a user-configured archival `lightwalletd`/`zaino` gRPC endpoint, validates the result against the local node, then continues from the local node. No endpoint is hard-coded.
3. **Independent multi-key profiles.** Each key (`KeyId`) has an isolated `zcash_client_sqlite` database under `~/.gyges/<network>/keys/<key_id>/` with its own ShardTree witnesses, birthday, `scanned_tip` and signing mode (`local-seed`, `keystone-qr`, `watch-only`, `signer-only`).
4. **Daemon-only key material and air-gapped mode.** Key material and SQLite state live only inside `gygesd`. `gygesd --airgapped` disables every network interface and serves `signer-only` profiles over the Unix socket for PCZT proving and signing.
5. **Full address and ZIP 320 (`tex1`) send support.** Sends to Unified (`u1`), Sapling (`zs1`), transparent (`t1`/`t3`) and ZIP 320 TEX (`tex1`/`textest1`) recipients. TEX payments use the upstream two-step proposal plus a durable `TexQueue` broadcaster. Gyges does not *issue* `tex1` receive addresses (decisions.md Q-T5).
6. **Keystone 3 Pro hardware signing.** Pairs from `ur:zcash-accounts` (CBOR tag 49201) and signs over animated terminal QR codes using the batch protocol (`ur:zcash-sign-batch` 49205 / `ur:zcash-batch-sig-result` 49207) for shielded sends and the single-PCZT protocol (`ur:zcash-pczt` 49204) when transparent inputs are present.

#### Pools
Pool support is data, not code paths: `profile.json` carries `spend_pools` and `receive_pools`, and `balance`, `notes` and `address new --receivers` are pool-generic. The node, wallet libraries and Keystone firmware all expose an **Ironwood** pool alongside Sapling and Orchard, and after NU6.3 (regtest height 1, mainnet 3,428,143) the wallet libraries build every shielded output there while the ZIP 318 turnstile keeps value out of Orchard (`decisions.md` §2.3). MVP policy: spend Orchard, Ironwood and transparent; receive Ironwood, Sapling and transparent; Orchard notes are spent, never created. Since M6 `local-seed` profiles spend Sapling too (§3.2 item 1); Keystone profiles never do.

---

### 2. Workspace Layout

```text
gyges/
├── Cargo.toml                   # workspace; exact `=` pins on every zakura-* crate (Q-D3)
├── Cargo.lock                   # committed; CI builds --locked
├── proto/gyges.proto            # tonic UDS gRPC contract (see interface.md API)
├── crates/
│   ├── gyges-proto/             # tonic-prost-build output, proto3 JSON impls, GygesError <-> Status, UDS connector, API version constants
│   ├── gyges-qr/                # UTF-8 half-block QR renderer, BC-UR codec, registry tags 49201-49207
│   ├── gyges-chain/             # ChainBackend (node bounds, tree state) + CompactBlockSource: ZakuraRpcBackend (Case A), ArtiTorLwdBackend (Case B)
│   ├── gyges-core/              # config.toml, paths, permission sweep; KeyRegistry, VaultManager, SyncScheduler, TxEngine, TexQueue
│   ├── gygesd/                  # daemon: library (startup checks, pid lock, UDS server, policy layer, service) + thin binary
│   └── gyges-cli/               # `gyges` binary: command router, handshake, exit codes, prompts, QR TUI
└── tests/regtest/               # gyges-regtest: end-to-end harness and scenarios (testing.md §2)
```

#### 2.1 `gyges-core` components

| Component | Responsibility | Persistent state |
|---|---|---|
| `KeyRegistry` | Enumerates `keys/<id>/profile.json`, opens one `WalletDb` per key, enforces 0700/0600 permissions at startup, resolves `default_key` for requests with an empty `key_id`. | `profile.json` per key |
| `VaultManager` | Encrypts/decrypts `seed.age`, derives the `UnifiedSpendingKey`, owns signing sessions (connection-scoped tokens or daemon-scoped idle TTL), rate-limits failed unlocks per key id, zeroizes on expiry and on `daemon stop`. | `seed.age`; `gyges_signing_sessions` table |
| `SyncScheduler` | Per-key state machine over `gyges-chain` (the Sync part): node bounds, route selection, shared block cache, reorg truncation, handoff validation, mempool scan. | upstream `WalletDb` tables; `cache/blocks.sqlite` |
| `TxEngine` | Proposal (`propose_transfer`, `propose_standard_transfer_to_address`), PCZT construction (`create_pczt_from_proposal`) and the PCZT role pipeline: Updater → Prover → (Redactor →) Signer → Combiner → Verifier → Spend Finalizer → Tx Extractor. | `gyges_signing_sessions` |
| `TexQueue` | Durable broadcaster for ZIP 320 two-step proposals: persists both raw transactions, re-checks every non-terminal row against the node (`getrawtransaction`) every `tex.rebroadcast_interval` and after each send, rebroadcasts whichever is missing, builds a fresh Step 2 when Step 1 is mined but Step 2 expired (`gyges_core::db::tex`, `gygesd::tex`). | `ext_gyges_tex_queue` table |

---

### 3. Component Data-Flow & State Machines

#### 3.1 Hybrid synchronisation pipeline (`SyncScheduler`)
Full detail in the Sync part; summary:

1. **Node bounds.** `ZakuraRpcBackend` calls `getblockchaininfo` and derives `NodeBounds { tip_height, tip_hash, retained_from }`, where `retained_from = pruneheight` when `pruned == true` and `0` otherwise. When the optional indexer gRPC (`[rpc] indexer_listen_addr`) is enabled, `chain_tip_change` and `mempool_change` streams replace polling.
2. **Route selection per key.**
   - **Case A** (`scanned_tip + 1 >= retained_from`): a single `BlockFetcher` fetches `getblock(h, 0)` (plus `getblock(h, 1)` for the tree sizes) once per height through `ZakuraRpcBackend::compact_blocks`, builds synthetic `CompactBlock`s with `zcash_primitives`, and writes them to the shared cache at `cache/blocks.sqlite` (`gyges_chain::cache::BlockDb`, an implementation of `zcash_client_backend::data_api::chain::BlockCache`). Each key runs `scan_cached_blocks` over the cache. The synthetic compact blocks carry every transparent input and output of the raw block, so the cache doubles as the transparent index that a pruned node no longer maintains; the scheduler matches those outputs against each key's receivers.
   - **Case B** (`scanned_tip + 1 < retained_from`, historical restore): `ArtiTorLwdBackend` bootstraps Tor, calls `GetSubtreeRoots` to seed the Sapling and Orchard ShardTrees (`put_sapling_subtree_roots` / `put_orchard_subtree_roots`), streams `GetBlockRange(scanned_tip + 1 .. retained_from + k)` with `k = 10`, and at `V = retained_from + k` validates the stream against the trusted local node: tree roots and leaf counts from `z_gettreestate(V)`, the `prev_hash` chain against `getblockhash`, and completed subtree roots against `z_getsubtreesbyindex`. On any mismatch the key is truncated to its birthday and the endpoint is marked untrusted. On success the key continues in Case A.
3. **Reorgs.** Each poll compares the stored hash at `scanned_tip` with `getblockhash`; the scanner's `PrevHashMismatch` is the second detector. The fork point is found by walking back at most 100 blocks (the node's finality depth, needs verification), `truncate_to_height(f)` rewinds notes, nullifiers and ShardTree checkpoints, and scanning resumes from `f + 1`. Deeper inconsistency puts the key in `Stalled(ChainInconsistent)`.
4. **Pruning race.** The Case A invariant is checked before every batch and on a "block not available" error; on violation the key falls back to Case B when a fallback endpoint is configured, else `Stalled(PrunedPastScanTip)`. `gygesd` warns at startup if the node's `tx_retention` is below `min_retention_blocks`.
5. **"Synced".** *scanned*: `scanned_tip >= tip_height`. *spendable*: additionally `suggest_scan_ranges()` returns nothing above priority `Ignored`. Both are returned by `GetSyncStatus`; `sync wait` defaults to spendable.

Reuse: `zcash_client_backend`'s `sync::run` is bound to a lightwalletd gRPC client and is not used for Case A; everything beneath it (`BlockSource`, `BlockCache`, `scan_cached_blocks`, `suggest_scan_ranges`, `update_chain_tip`, the continuity-error truncation loop) is, and the `spend-index` feature routes transparent spent-ness checks to the node.

#### 3.2 Vault lifecycle and inline unlock
1. **Locked by default.** On startup `gygesd` loads only the `UnifiedFullViewingKey` from each key's `accounts` table. Scanning, proposal creation, PCZT construction and **Orchard and transparent** proving work while locked. **Sapling spends cannot be proven while locked**: the Sapling prover needs the proof generation key (`ak`, `nsk`), which is derived from the spending key and is not part of any viewing key. For a proposal with Sapling inputs the daemon requests the unlock *before* proving and uses the PCZT **Updater** role to insert each spend's `proof_generation_key` (ZIP 374 field), then proves, signs and drops the key. `watch-only` profiles are therefore "Orchard proving-only". As built: `gyges_core::tx::insert_proof_generation_keys` picks each spend's key by recomputing the note's nullifier under the external and the internal key (Sapling change lands at internal addresses, whose `nsk` differs), `gygesd::tx` obtains the key before `Proving` only when the proposal has Sapling spends, and the PCZT goes from the Updater to the extractor in memory. Files never carry a Sapling spend: `pczt create` leaves Sapling notes out, and `pczt prove` / `pczt sign` refuse one.
2. **Encrypted entropy on disk.** For `local-seed` profiles the 32-byte BIP 39 entropy (not the derived 64-byte seed, so the backup words round-trip) is encrypted with an `age` **scrypt** passphrase recipient at `keys/<key_id>/seed.age`. `age` has no Argon2id mode; the work factor is tuned to about one second and recorded as `seed_format = "age-scrypt-v1"` in `profile.json` so it can be raised by migration. A `rage`-compatible file is a deliberate recovery property.
3. **Inline unlock flow.**
   - `gyges tx send --key main --to u1… --amount 1.0` opens the `SendTransaction` server stream.
   - The daemon emits `Proposed`, proves what it can while locked, then emits `SignatureRequired { key_id, kind: PASSPHRASE, session_id }`.
   - `gyges-cli` prompts `Enter passphrase to unlock key 'main':` (only on a TTY; otherwise exit 4, see interface.md CLI §1.2), calls `UnlockKey { key_id, passphrase, scope: CONNECTION }`, receives a `session_token` bound to that connection, and continues the stream with it.
   - Inside `gygesd` the 32-byte entropy lives in `secrecy::Secret` (zeroized on drop); the `UnifiedSpendingKey` is derived from it for the signing step alone, moved into the signing task and out of scope before verification and broadcast (the upstream type does not zeroize on drop, `security.md` §6 item 10). The explicit `gyges key unlock --timeout` path creates a daemon-scoped session with an idle TTL (`vault.unlock_ttl`, default `5m`) instead; it is the weaker mode and documented as such in `interface.md` API.
   - Errors are typed: `failed_precondition` with a `GygesError { reason: VAULT_LOCKED, key_id }` detail, never a string the client has to parse.

#### 3.3 ZIP 320 (`tex1`) two-step orchestration
When the recipient parses as a TEX address (`zcash_address::ZcashAddress::try_from_tex` on the decoded form; there is no `kind::tex` module):
1. **Proposal.** `propose_standard_transfer_to_address` returns a two-step `Proposal`.
2. **Plan.** *Step 1* spends shielded notes to an ephemeral transparent P2PKH address derived from the ZIP 32 ephemeral chain, for exactly `amount + fee₂` with no change on that address. *Step 2* spends that single output to the 20-byte pubkey hash of the `tex1` address in a pure transparent transaction (one input, one output, so `fee₂` is the ZIP 317 minimum and fixed at proposal time). ZIP 320 mandates the two-transaction structure and seed-recoverable, unlinkable ephemeral addresses; the exact output value, derivation path and gap limit are `zcash_client_backend` implementation behaviour, not ZIP text.
3. **Execution.** `create_proposed_transactions` builds, proves, signs and stores both steps with a shared `expiry_height`; both are signed in the same session (one passphrase, obtained *before* proving because the builder needs the key for both at once; upstream's PCZT path takes single-step proposals only, interface.md API §9). `TexQueue` persists both raw transactions in `ext_gyges_tex_queue` (Data model §5.1), broadcasts Step 1 then Step 2 immediately (Zakura's mempool accepts a transaction spending an unconfirmed transparent output of another mempool transaction, verified on v1.6.0, and evicts descendants with their parent), and drives the row through `built → step1_broadcast → step2_broadcast → step1_mined → step2_mined` on what `getrawtransaction` says. Reorg, eviction or a node restart (which empties Zakura's mempool) loses Step 1 and with it Step 2; the queue rebroadcasts both from the stored bytes, without the key. Shared expiry means both expire together (`expired`) and funds never leave the shielded pool; Step 1 mined with Step 2 unmined at the expiry height is `step2_failed`, and `gyges tx resume` builds a new Step 2 (`gyges_core::tx::build_tex_step2`: a hand-made single-step proposal spending the ephemeral output, after telling the wallet the output was seen unspent past the old expiry) through a fresh signing session. Seed-only recovery finds a stranded ephemeral UTXO through the ephemeral-receiver gap scan and it reappears as transparent balance.
4. **Dry run.** `--dry-run` returns the full proposal, rendered one block per step with `Total debit: amount + fee₁ + fee₂`; `--json` emits the upstream proposal protobuf as proto3 JSON.

#### 3.4 Keystone 3 Pro hardware signing (`keystone-qr`)
1. **Import (`gyges key import-keystone`).** Parses `ur:zcash-accounts` (49201): `seed_fingerprint`, `accounts: [{ufvk, index, name?}]`, `device_version?`. The payload carries **no birthday**; `--birthday` is required or prompted, defaulting to the NU5 activation height (1,687,104 on mainnet) because the exported UFVK has only transparent and Orchard components and cannot have received shielded funds earlier. `profile.json` records `spend_pools` and `receive_pools` `["orchard", "ironwood", "transparent"]` and `device_version`; firmware older than the minimum Zodl requires for Ironwood (v3.0.2, which the pairing QR reports as `13.0.2`) is refused. Keystone does not sign Sapling spends.

   *Landed* as `gygesd::keys::import_keystone` and `KeyRegistry::create_keystone`. Only `ur:zcash-accounts` is accepted, since a lone UFVK has no seed fingerprint. The UFVK is imported with `import_account_ufvk` as a spending account whose ZIP 32 derivation is the device's seed fingerprint and account index, so every PCZT the wallet builds carries the BIP 44 / ZIP 32 paths the device needs to find its key. The firmware floor and its numbering live in `gyges_qr::firmware`; an export without a version is imported only with `--allow-unknown-firmware`.
2. **Signing (`gyges tx send` or `gyges pczt sign`).**
   - `gygesd` builds the PCZT and proves it on the host (`pczt::roles::prover::Prover` with `zcash_proofs::prover::LocalTxProver`), then stores the proven PCZT in a `gyges_signing_sessions` row and emits `SignatureRequired { kind: KEYSTONE, session_id }`.
   - **Shielded-only sends** use the batch protocol: the daemon runs `redact_pczt_for_batch_signer`, `gyges-cli` encodes `ur:zcash-sign-batch` (49205) as fountain frames and renders an 8 FPS UTF-8 half-block QR loop; the device returns `ur:zcash-batch-sig-result` (49207), a single frame of `(pool, action_index, signature)` tuples with the echoed `request_id`, which the daemon applies to its stored proven PCZT. No Combiner is needed.
   - **Sends with transparent inputs** (shielding, ZIP 320 Step 2) use the single-PCZT protocol: `Redactor` strips proofs, witnesses and the Gyges `proprietary` map but **never** amounts, recipients or memos the device displays; the device returns the signed `ur:zcash-pczt` (49204); the daemon runs **Combiner** on (proven ⊕ signed), which rejects structurally different PCZTs and is the correlation check. TEX Step 2 on Keystone is **needs verification on hardware**.
   - Both paths then run **Verifier** against the stored proposal (refusing to broadcast if any output, amount, fee or anchor differs), **Spend Finalizer**, **Tx Extractor**, and broadcast. `tx send` prints the same summary the device shows.
   - *Landed* as `gyges_core::keystone` and `gygesd::keystone`, with one change from the steps above: the device is shown the PCZT **before** it is proven, as Zodl does. Proofs are not signed over, so this keeps the QR loop shorter. The proven copy is what is stored and what the answer is applied to. **What the device is shown (the Redactor's field list, security.md §5 row 9):**
     - **Both protocols:** the `gyges.*` tags are removed from the global proprietary map (`keystone::strip_gyges_tags`), then upstream's redaction applies.
     - **Batch:** `redact_pczt_for_batch_signer`, the compact view.
       - Removed: upstream's proposal, one-time-spend and output proprietary entries; spend witnesses; dummy spending keys; proofs; `bsk`; v6 anchors; spend FVKs; existing signatures; and the randomizer of actions already signed.
       - Fields the device can recompute are compacted.
     - **Single PCZT:** `redact_pczt_for_signer(SignerView::Full)`.
       - Removed: the same upstream proprietary entries, spend witnesses and dummy spending keys.
       - Kept: FVKs, randomizers and derivation paths.
     - **Never removed:** values, recipients, `user_address` and the encrypted memos.

     `CompleteKeystoneSign` applies the answer (batch signatures through `Signer::apply_orchard_spend_auth_signature`, which verifies each one; the single PCZT through the Combiner), requires every signature, runs the Verifier against the approved proposal, and only then claims the session and broadcasts.
   - *Camera:* `gyges_qr::scan` (always built) decodes frames with `rqrr`, keeps only `ur:` frames of the expected answer type, and drops a re-read of the request. `gyges_qr::camera` (feature `camera`, off by default) is the `nokhwa` frame source. `tx send` uses it by itself when the build has it, falling back to pasted frames.
   - Host ingestion of the device's QR: `gyges pczt qr-scan` (laptop camera, used automatically when present), `gyges pczt qr-import --from-file` / stdin (one `ur:` frame per line), or positional frames for single-frame payloads. Sessions survive restarts, expire after `vault.signing_session_ttl` (default `24h`), and can be completed later with `--session <id>` (interface.md CLI §2.6).

#### 3.5 Air-gapped PCZT flow (`signer-only`, `gygesd --airgapped`)
A PCZT produced online after the Constructor and Updater roles carries, per spend, the note, `rseed`, Merkle witness and anchor, so the offline box needs no chain state and no `wallet.sqlite`. Transport is a binary `.pczt` file (postcard serialization) on removable media: `gyges pczt create … -o tx.pczt` online → `gyges pczt prove tx.pczt | gyges pczt sign -o tx.signed.pczt` offline → `gyges pczt broadcast tx.signed.pczt` online, where the online side runs Verifier first. QR transport works but a proven Orchard action is several kilobytes, so it is documented as slow. PCZTs carry `gyges.key_id`, `gyges.network` and `gyges.session_id` in the ZIP 374 global `proprietary` map; `--key` is only an assertion.

*Landed as `gygesd::roles`, `gyges_core::pczt_io` and `gyges_core::db::sessions`.* `CreatePczt` writes the tags through the Updater role and stores the approved proposal, reduced to what the Verifier checks, in the key's `ext_gyges_signing_sessions` row under the session id (Data model §5.2); `BroadcastPczt` finds that row by the tag and runs the Verifier against it before the Spend Finalizer and Transaction Extractor, so the online side never trusts the file's own amounts. The file gets `target + 1152` blocks of expiry (about a day), since it waits for a person; the anchors it carries stay valid. `InspectPczt` works from the file alone: the amounts, recipients, fee and expiry it implies, and the roles whose footprints are present (proofs, signatures, finalised inputs), read through the Verifier role's parsed bundles. The `signer-only` half landed with the second M4 item: `SignPczt` on an `--airgapped` daemon resolves each transparent input's key from the BIP 44 derivation the file carries (upstream writes one on every input of an HD account), checked against the profile's seed fingerprint and account, so no wallet is needed; the Signer role then refuses a key that does not match the input's script.

#### 3.6 Daemon lifecycle
- **Start.** `gyges daemon start` (or the `launchd`/`systemd --user` unit written by `gyges daemon install`, `gyges_cli::service`, which restarts the daemon only after a failure; reinstalling is the upgrade step). The CLI does not auto-start the daemon (exit 3 with the fix) unless `GYGES_AUTOSTART=1`. Startup refuses to run if `~/.gyges/<network>` has permissions wider than 0700/0600. Before anything else the daemon sets its umask to 077 and `RLIMIT_CORE` to zero (a core dump would hold key material; `security.md` §6 item 10). The first successful node poll warns once when `zakura_rpc.url` is not `localhost` or a loopback address (§6 item 12).
- **Connections.** One UDS per network at `~/.gyges/<network>/gygesd.sock`, mode 0600. In the hardened deployment (`gyges daemon install --hardened`) it is 0660 with a `gyges` group at `/run/gyges/<network>/gygesd.sock` (`daemon.socket_path`): a group member cannot search the 0700 network directory, so the socket lives in a directory of its own, which the daemon accepts only if it owns it and it is 0750 or narrower. Every accepted connection is checked with `SO_PEERCRED`/`LOCAL_PEERCRED` against the daemon's uid (or an allow-list).
- **Stop.** `gyges daemon stop` finishes the current scan batch (at most one `scan_cached_blocks` call), checkpoints SQLite WAL, leaves `ext_gyges_tex_queue` and `gyges_signing_sessions` rows in place to resume on next start, aborts in-progress proving, and zeroizes every unlocked key.
- **Logs.** `logs/gygesd.<date>.log` (daily rotation, seven files, filtered by `daemon.log_level` or `RUST_LOG`) and `logs/audit.log` (one JSON object per line for every `gyges::audit` event, whatever the configured level: unlock, lock, export, session created/completed/aborted, sign, broadcast and rewind, with key id and time only; never rotated). `gyges daemon logs [--audit]` reads the daemon's in-memory tail of either log through the `StreamLogs` RPC (`gygesd::logs`). Sensitive values are wrapped in `gyges_core::Sensitive<T>` whose `Debug`/`Display` print `[redacted]`.

#### 3.7 Performance features
Every build proves and trial-decrypts on all cores: `multicore` is a default feature of the upstream crates, and `RAYON_NUM_THREADS` caps it. On aarch64 (Apple Silicon, aarch64 Linux) every build also uses `zakura-pasta-curves`' assembly field arithmetic, which `zakura-halo2-proofs` turns on for those targets. On x86-64 the assembly is the opt-in feature `perf-asm-x86_64` (on `gygesd` and `gyges-core`): it needs BMI2 and ADX and has no runtime fallback (`security.md` §6 item 2), so default and release builds use the portable code. `Provers::orchard` builds the Orchard/Ironwood proving key once per daemon and prepares its commitment tables (`ProvingKey::prepare_proving`, about 30 MiB), which upstream uses on pools of at most eight threads (ten on AArch64 macOS). Timings belong in `testing.md` §9, not here.

---

### 4. Directory & Configuration Layout (`~/.gyges/<network>/`)

One directory per network so mainnet, testnet and regtest daemons coexist (full schema in the Data model part):

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

#### Example `config.toml`
Valid TOML, checked by a `gyges-core` config test; `~` is expanded by the daemon in every path value. Data model §2 lists every key.

```toml
network = "mainnet"
default_key = "main"
airgapped = false

[zakura_rpc]
url = "http://127.0.0.1:8232"
cookie_path = "~/.cache/zakura/.cookie"
poll_interval_secs = 15
min_retention_blocks = 10000

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

## Sync

The per-key sync state machine run by `gygesd`. This document turns the proposals under Q-D1, Q-D4 and Q-Y1…Y6 in `decisions.md` into one description. Items marked **needs verification** rest on a fact that must be confirmed against the Zakura node or the upstream crates before the code is written.

Upstream library paths use the library target names (`zcash_client_backend`, `zcash_client_sqlite`, `shardtree`), consumed via `package = "zakura-…"` renames; see `Cargo.toml`.

---

### 1. Node Bounds

Every sync decision starts from one struct, refreshed on each poll tick (`zakura_rpc.poll_interval_secs`) or on each `chain_tip_change` event when the node's indexer gRPC is enabled:

```rust
pub struct NodeBounds {
    /// Height of the node's best chain tip.
    pub tip_height: BlockHeight,
    /// Hash of the block at `tip_height`.
    pub tip_hash: BlockHash,
    /// Lowest height whose block *body* the node still stores.
    /// `pruneheight` from `getblockchaininfo` when `pruned == true`, else 0.
    pub retained_from: BlockHeight,
}
```

Source: `getblockchaininfo` returns `pruned: bool` and, only when pruned, `pruneheight` ("the lowest height whose block body this node still stores"). Zakura prunes transaction bodies only; headers, txids and consensus state are kept at every height, so `getblockhash(h)` works below `retained_from` while `getblock(h, 0)` does not. `z_gettreestate(h)` returns `HistoricalTreeUnavailable` for pruned heights.

Retention is `state.storage_mode.pruned.tx_retention` in the node config (default and minimum 10,000 blocks on mainnet and testnet). At startup `gygesd` warns when `tip_height - retained_from < min_retention_blocks` (config, default 10,000).

The `pruneheight` field is authoritative. As a defensive measure, a "block not available" error from `getblock` inside the supposed window triggers a bounds re-poll, never a binary search.

---

### 2. Block Sources and the Shared Cache

#### 2.1 `ChainBackend` as the compact block source

Both routes feed the same scanner through one trait, `gyges_chain::ChainBackend` (the design's `CompactBlockSource`, merged into the trait the key registry already used for node bounds and tree states):

```rust
pub trait ChainBackend: Send + Sync + Debug {
    /// `getblockchaininfo` → NodeBounds; also refreshes `status()`.
    fn node_bounds(&self) -> BoxFuture<'_, Result<NodeBounds, ChainError>>;
    /// Outcome of the last poll, never touching the network (feeds GetInfo.node).
    fn status(&self) -> NodeStatus;
    /// `z_gettreestate(height)` as the ChainState an account born at height + 1 starts from.
    fn chain_state(&self, height: BlockHeight) -> BoxFuture<'_, Result<ChainState, ChainError>>;
    /// `getblockhash(height)`, internal byte order; works below retained_from too.
    fn block_hash(&self, height: BlockHeight) -> BoxFuture<'_, Result<[u8; 32], ChainError>>;
    /// Compact blocks for `range`, ascending, contiguous, linked by prev_hash.
    /// The caller bounds the range to `cache.fetch_batch`.
    fn compact_blocks(&self, range: Range<BlockHeight>)
        -> BoxFuture<'_, Result<Vec<CompactBlock>, ChainError>>;
}
```

Subtree roots are on the trait as `subtree_roots(pool, start_index, max_entries)` (`z_getsubtreesbyindex` on the node, `GetSubtreeRoots` on lightwalletd), each root a `gyges_chain::SubtreeRoot` (pool, index, raw root bytes, completing height, and the completing hash where the source gives one) with `sapling()` / `orchard()` conversions to the `CommitmentTreeRoot` that `put_sapling_subtree_roots` / `put_orchard_subtree_roots` / `put_ironwood_subtree_roots` take; `route()` says which route a backend is. A bounded `Vec` per batch replaced the stream of the first draft: the fetcher works in `fetch_batch`-sized ranges anyway, and a `Vec` lets the backend check that the batch links end to end before anything is cached. `gyges_chain::fill_cache(backend, cache, range, batch)` is that loop for either backend: each chunk is fetched, its first block checked against the cached block below it, and the rows tagged with `route().source()`; a chunk that does not link is refused whole.

| Implementation | Crate | Backing calls | Used for |
|---|---|---|---|
| `ZakuraRpcBackend` (landed) | `gyges-chain` | per height, concurrently and in order: `getblock(h, 0)` parsed with `zcash_primitives::block::Block::read`, plus `getblock(h, 1)` for the hash, txids and `trees` (the note commitment tree sizes the scanner needs as `ChainMetadata`); the two are cross-checked and the batch is checked for `prev_hash` links; `getblockchaininfo`; `getblockhash`; `z_gettreestate` | Case A: `[retained_from, tip]` |
| `ArtiTorLwdBackend` (landed) | `gyges-chain` | lightwalletd / zaino `GetLightdInfo` (chain check, once per connection), `GetLatestBlock` (`retained_from = 0`), `GetBlock`, `GetTreeState`, `GetBlockRange` (one call per batch, collected under an idle timeout, checked for the exact heights and `prev_hash` links), `GetSubtreeRoots`, `SendTransaction`; over `zcash_client_backend::tor` (arti, `.onion` as onion services, `https://` under rustls with webpki roots) or directly when `use_tor = false` | Case B: `[birthday, retained_from + k)` |

Per transaction the compact form keeps: txid, Sapling spends' nullifiers, Sapling outputs' `(cmu, ephemeral_key, enc_ciphertext[..52])`, Orchard and Ironwood actions' `(nullifier, cmx, ephemeral_key, enc_ciphertext[..52])`, and, because the raw block is at hand, every transparent input (`prevout`) and output (`value`, `scriptPubKey`) in the `CompactTx.vin` / `vout` fields the lightwalletd protobuf already defines. The format is `zcash_client_backend::proto::compact_formats`, so `scan_cached_blocks` sees no difference between the two sources; it ignores `vin`/`vout`. The indexer gRPC (`[rpc] indexer_listen_addr`, `get_block_range` of raw blocks) is not used yet; when it is, it replaces the `getblock` pair, not the parser.

The cache is therefore also the transparent index for Case A: the scheduler reads `vout` from cached blocks (`gyges_chain::compact::transparent_outputs`), matches `scriptPubKey`s against the key's transparent and ephemeral receivers and hands hits straight to `put_received_transparent_utxo` (`gyges_core::sync::credit_transparent`; the per-key `gyges_transparent_received_outputs` staging table of the first draft was never needed, since the upstream insert is an upsert). Blocks from the Tor route carry no transparent outputs (`GetBlockRange` is asked without `pool_types`, the legacy answer), so below `retained_from` transparent history comes only from `GetAddressUtxos` over Tor (§5.3).

The lightwalletd backend treats the endpoint as untrusted at the transport level only: every `GetBlockRange` answer must carry exactly the heights asked for, 32-byte hashes and a `prev_hash` chain, a stream that ends early is `BlockUnavailable` for the first missing height, and one that goes silent for `LwdTimeouts::stream_idle` (60 s) is reported as unreachable and its connection dropped so the next call reconnects (Tor circuits half-close without a reset). Whether the chain it serves is *the* chain is the handoff validation's job (§5.2). `GetLightdInfo` is checked once per connection so an endpoint for another network is refused before a block is taken from it. Nothing is contacted at construction: the connection, and with `use_tor = true` the Tor bootstrap (arti state under `tor_cache/`, `0700`), happen on the first request, so a daemon starts with the endpoint down and `--airgapped` never touches it.

The cookie file is re-read on every request: `zakurad` rewrites `~/.cache/zakura/.cookie` at each start, so a daemon that cached it would lose the node at the first node restart. A missing or stale cookie is reported as `NODE_UNREACHABLE` with the path and the fix.

#### 2.2 `BlockCache` and `BlockFetcher`

One cache per network at `~/.gyges/<network>/cache/blocks.sqlite` (schema in Data model §6) implements the upstream `zcash_client_backend::data_api::chain::BlockCache` trait, so `scan_cached_blocks` reads from it unchanged. Landed as `gyges_chain::cache::BlockDb`: `BlockSource::with_blocks` stops at the first missing height, `BlockCache::read` reports a hole inside the requested range as an error, rows are tagged `source = 'node' | 'tor-lwd'`, and `evict_below` / `evict_source_below` / `checkpoint` are what the fetcher below and the daemon's stop path call. The daemon opens it at start (refusing a file from another network or a newer schema) and checkpoints it on stop.

A single `BlockFetcher` task per daemon:

1. Computes `lo = min(scanned_tip over all keys) + 1`, `hi = tip_height`.
2. Fills `[max(lo, retained_from), hi]` from `ZakuraRpcSource` in batches of `cache.fetch_batch` (default 100) blocks.
3. Fills any sub-`retained_from` range a key needs from the fallback endpoint (`ArtiTorLwdBackend` through `fill_cache`, one `cache.scan_batch` per key per tick), tagging rows `source = 'tor-lwd'` (§5).
4. Evicts a block once every registered key has scanned past it, keeping `cache.retain_blocks` (default 1000) behind the slowest key for cheap rewinds, bounded by `cache.max_mb` (default 2048). With `cache.keep_historical = false` (default) Tor-fetched rows are dropped as soon as the key that requested them has scanned them.

The node is asked for each block once regardless of how many key profiles exist.

---

### 3. Per-Key State Machine

```rust
pub enum SyncState {
    /// Profile exists, scan range not yet computed.
    Initializing,
    /// Streaming [scanned_tip + 1, retained_from + k) from the Tor fallback.
    Backfilling { via_tor: bool, from: BlockHeight, to: BlockHeight },
    /// Scanning from the shared cache (Case A).
    Scanning { from: BlockHeight, to: BlockHeight },
    /// scanned_tip >= tip_height and no open scan range above Ignored.
    Synced { spendable: bool },
    /// Cannot proceed without operator action; see `StallReason`.
    Stalled(StallReason),
}

pub enum StallReason {
    /// Case A invariant broken and no fallback endpoint usable.
    PrunedPastScanTip,
    /// No fork point found within 100 blocks (Q-Y1).
    ChainInconsistent,
    /// Handoff validation failed (Q-Y5); endpoint marked untrusted.
    UntrustedBackfill,
    /// The fallback endpoint could not serve the backfill; retried each tick.
    FallbackUnreachable,
    /// `--airgapped` or node unreachable for longer than `zakura_rpc.offline_grace`.
    Offline,
}
```

```text
                 ┌──────────────┐
      profile    │ Initializing │
      created ──▶│              │
                 └──────┬───────┘
          need < retained_from?     need >= retained_from?
                 │                          │
                 ▼                          ▼
      ┌────────────────────┐      ┌────────────────────┐
      │ Backfilling (Tor)  │─────▶│      Scanning      │◀──────┐
      └────────┬───────────┘ V ok └─────────┬──────────┘       │
               │ V fails                    │ scanned_tip >=   │ new tip /
               ▼                            │ tip_height       │ reorg /
      ┌────────────────────┐                ▼                  │ prune race
      │ Stalled(Untrusted) │      ┌────────────────────┐       │ w/ fallback
      └────────────────────┘      │       Synced       │───────┘
                                  └────────────────────┘
                 any state ──▶ Stalled(PrunedPastScanTip | ChainInconsistent | Offline)
                 Stalled ──▶ Initializing on `sync run --from <h>` or config change
```

| From | Event | To | Side effects |
|---|---|---|---|
| `Initializing` | `scanned_tip + 1 >= retained_from` | `Scanning` | `update_chain_tip(tip_height)`; `suggest_scan_ranges()` |
| `Initializing` | `scanned_tip + 1 < retained_from`, fallback configured, not air-gapped | `Backfilling` | Open Tor circuit; `put_*_subtree_roots` from the `GetSubtreeRoots` the node confirms (§5.2 check 3) |
| `Initializing` | `scanned_tip + 1 < retained_from`, no fallback or air-gapped | `Stalled(PrunedPastScanTip)` | `daemon status` explains the fix |
| `Backfilling` | Stream reaches `V = retained_from + k`, §5 checks pass | `Scanning` | Close Tor stream; log handoff |
| `Backfilling` | §5 check fails | `Stalled(UntrustedBackfill)` | truncate to the block before the backfill began (`birthday - 1` for a restore); endpoint marked untrusted |
| `Backfilling` | endpoint unreachable, behind, or missing a block | `Stalled(FallbackUnreachable)` | Retries every poll tick; auto-resumes |
| `Scanning` | `scanned_tip >= tip_height` | `Synced` | `spendable` = no range above `Ignored` |
| `Scanning` | `getblock` pruned error or invariant check fails | `Backfilling` or `Stalled(PrunedPastScanTip)` | §4 |
| `Scanning`/`Synced` | `PrevHashMismatch` or tip-hash mismatch | `Scanning` | §4.2 truncation to fork point |
| `Synced` | `tip_height` advances | `Scanning` | `update_chain_tip`; one more batch |
| any | node unreachable > `offline_grace` | `Stalled(Offline)` | Retries every poll tick; auto-resumes |
| `Stalled` | `sync run --from <h>` | `Initializing` | `truncate_to_height(h)` first |

Each key's `SyncState` is held in memory and summarised in `GetSyncStatus`; `scanned_tip` itself is whatever `WalletRead::block_fully_scanned()` reports from the key's `wallet.sqlite` (or `birthday - 1` before the first batch), so the daemon never persists a second copy of it.

**Status:** `gyges_core::sync::SyncState` has `Initializing`, `Backfilling { via_tor, from, to }`, `Scanning`, `Rewinding`, `Synced` and `Stalled(PrunedPastScanTip | ChainInconsistent | UntrustedBackfill | FallbackUnreachable | Offline)`. `UntrustedBackfill` carries no endpoint: there is one per daemon, and the endpoint and failed check are in the key's `detail` and in `GetInfo.fallback.trust`. The entry condition is the Case A invariant of §4.2 (`scanned_tip < retained_from`, one block stricter than the table), checked before upstream's queue is consulted, so a restore backfills from its birthday up before the chain-tip range: the wallet's trees are then built in order, which the root check of §5.2 relies on. Without an endpoint (or air-gapped) a broken invariant stalls with `PrunedPastScanTip` and the `daemon status` / `sync status` text above. On the wire `Backfilling` is `SYNC_STATE_VALIDATING_HANDOFF` (the CLI's `backfilling`) with `backend` `SYNC_BACKEND_TOR_LWD_FALLBACK` or `SYNC_BACKEND_DIRECT_LWD_FALLBACK`; `FallbackUnreachable` is `STALL_REASON_FALLBACK_UNREACHABLE`. A stalled key is re-evaluated every tick and leaves `Stalled` by itself once the cause is gone (node back, window widened, `sync run --from`). On the wire `Initializing` and `Synced` are both `SYNC_STATE_IDLE`, told apart by `scanned` / `spendable`; the CLI prints the words above.

---

### 4. Case A Scanning

#### 4.1 Steps per batch

1. `update_chain_tip(&mut db, bounds.tip_height)` so the upstream scan-queue logic knows the tip.
2. `suggest_scan_ranges(&db)` returns prioritised ranges (`ChainTip`, `FoundNote`, `Historic`, `Verify`, …). Take the highest-priority range, bounded to `cache.scan_batch` (default 1000) blocks.
3. Ensure the `BlockFetcher` has those heights; wait on its notify if not.
4. `scan_cached_blocks(&params, &cache, &mut db, from, &prior_chain_state, limit)`.
5. On `ScanError::PrevHashMismatch { at_height }` go to §4.2.
6. Repeat until `suggest_scan_ranges` has nothing above `Ignored`.

Subtree roots are refreshed from `z_getsubtreesbyindex` whenever `tip_height` crosses a new 2^16 commitment boundary and passed to `put_sapling_subtree_roots` / `put_orchard_subtree_roots`.

#### 4.2 Invariant and prune race

**Invariant:** while in `Scanning`, `scanned_tip + 1 >= retained_from`. The implementation is one block stricter: the next batch starts at `s = scanned_tip + 1` and needs `z_gettreestate(s - 1)` as its prior chain state, which a pruned node serves only for `s - 1 >= retained_from`, so `s - 1 < retained_from` stalls as well (unless `retained_from = 0`).

It is checked before every batch and whenever `getblock` returns the pruned error. On violation:

- if `fallback_lightwalletd.enabled` and the daemon is not air-gapped: switch the key to `Backfilling` for `[scanned_tip + 1, retained_from + k]`, log at `warn`, continue (a `getblock` pruned error or `TreeStateUnavailable` in the middle of a batch only re-polls the bounds; the next tick finds the invariant broken and backfills);
- otherwise `Stalled(PrunedPastScanTip)`; `sync wait` exits 7 and `daemon status` prints: "node pruned past key 'main' (scanned 2,100,000, node retains from 2,105,000); enable `fallback_lightwalletd` or increase the node's `tx_retention`".

The daemon keeps every key at the tip while it runs, so this race only matters after downtime longer than the node's retention window.

#### 4.3 Reorg detection and truncation

Detection, in order of cheapness:

1. Every poll tick compares `getblockhash(scanned_tip)` with the hash stored in the key's `blocks` table.
2. The scanner reports `ScanError::PrevHashMismatch` when a batch's first block does not link to the stored tip.

Handling:

1. Walk back from `scanned_tip` comparing `getblockhash(h)` against stored hashes, at most 100 blocks (the finality depth on the Zebra lineage; **needs verification** that Zakura keeps 100), to find the fork point `f`.
2. `WalletWrite::truncate_to_height(&mut db, f)` rewinds notes, nullifiers, received outputs and ShardTree checkpoints; unmined transactions remain in `transactions` and are re-evaluated against `expiry_height`.
3. Resume `Scanning` from `f + 1`. If `f < retained_from`, the resume goes through `Backfilling`.
4. No fork point within 100 blocks → `Stalled(ChainInconsistent)`; fix with `sync run --from <h>`.

The `BlockCache` rows above `f` are deleted at the same time so no key re-reads stale blocks.

**Status:** detector 1 runs once per tick on the *shared cache* (`cache tip` versus `getblockhash`, walking back to the fork point and truncating the cache) and once per key (the hash the wallet holds at `block_fully_scanned` versus the reconciled cache, falling back to the node); detector 2 is the scanner's continuity error. The fork search walks the wallet's own `blocks` hashes against the cache (or node) and calls `truncate_to_height`, which may truncate lower than asked; the key then rescans from there on the next tick. When the wallet has scanned nothing at or below the fork (a key born in a reorged block, or whose first scanned block was), `truncate_to_height` answers `RequestedRewindInvalid` and the scheduler instead resets the wallet to the node's tree state at the fork (`z_gettreestate(f)` → `WalletWrite::rewind_to_chain_state`, lowering the account birthday to `f + 1` where the fork is below it); verified by a three-block reorg against a real `zakurad` in `tests/regtest/scenarios/node.rs` and by the fake-node scheduler test. The subtree-root refresh (`z_getsubtreesbyindex`) is not implemented yet; witnesses are built from the scanned blocks alone, which is sufficient inside the retention window.

---

### 5. Case B Backfill and Handoff Validation

#### 5.1 Range

A key with `scanned_tip + 1 < retained_from` streams `[scanned_tip + 1, V]` from `TorLwdSource`, where `V = retained_from + k`, `k = 10` (config `fallback_lightwalletd.overlap_blocks`). The overlap exists because a pruned node answers `z_gettreestate` only for heights whose bodies it still has, so validation must happen inside the node's window, not at its edge.

Before streaming, `GetSubtreeRoots` for Sapling and Orchard populate the ShardTree via `put_*_subtree_roots`, so witnesses for notes found during backfill can be completed without every historical block.

The first backfill that a restore needs prompts once in the CLI: "N blocks below the node's retention height must be fetched over Tor from `<url>`; continue? [y/N]" (`--yes` for scripts).

**Status:** `gygesd::backfill`. `V = min(retained_from + k, tip)`, recomputed every tick from the current bounds, so a node that keeps pruning moves the handoff with it. A *session* opens when a key enters `Backfilling`: check 3 runs first (below), then one `cache.scan_batch` per tick is fetched with `fill_cache` from the endpoint (tagged `tor-lwd`), checked at its last block against `getblockhash` (check 2 at every batch boundary, so a fork is refused before anything from it is scanned) and scanned from `[scanned_tip + 1, min(scanned_tip + 1 + scan_batch, V + 1))`. The prior chain state of a batch is the node's `z_gettreestate` where the node still serves it and the endpoint's `GetTreeState` below that; the root check covers the latter. When the key's scanned tip reaches `V` the session is validated, and only then does the key return to Case A. The session is recorded in `keys/<id>/backfill.json`, so that a daemon restarted between the last batch and the handoff still validates before scanning on from the node. A restore below the window takes its birthday's tree state from the endpoint's `GetTreeState(birthday - 1)`, refused unless its block hash equals the node's `getblockhash(birthday - 1)`; `RestoreKeyResponse.backfill_blocks` is `V + 1 - birthday`. With `cache.keep_historical = false` the endpoint's rows are evicted as soon as the slowest key has scanned them. The restore prompt asks for consent (`--yes` skips it) and prefers `.onion` endpoints.

#### 5.2 Three checks at `V`

| # | Check | Against | Defeats |
|---|---|---|---|
| 1 | Sapling and Orchard ShardTree root and leaf count built from the stream equal the `finalState` frontiers of `z_gettreestate(V)` | local node | omitted, injected or reordered commitments |
| 2 | Stream links by `prev_hash` end to end, and the stream's hash at `V` and at `retained_from` equal `getblockhash` | local node | a stream from a different chain |
| 3 | Every completed subtree root from `GetSubtreeRoots` equals `z_getsubtreesbyindex(pool, index, 1)` for the same index | local node | forged subtree roots (**needs verification** that `z_getsubtreesbyindex` serves indices whose blocks are pruned) |

Pass: close the Tor stream, enter `Scanning` at `V + 1`. The blocks `[retained_from, V]` were already scanned from the Tor stream and are not rescanned.

Fail: `truncate_to_height(birthday - 1)`, mark the endpoint `untrusted` in daemon state (shown by `daemon status`, cleared only by a config change), enter `Stalled(UntrustedBackfill)`, log at `error` with which check failed and the two values.

**As implemented** (`gyges_core::handoff`, `gygesd::backfill`):

- Check 1 compares, per pool (Sapling, Orchard and Ironwood), the tree size the wallet recorded for block `V` (`block_metadata(V)`, which the scanner has already checked against each block's commitments) with the frontier size of `z_gettreestate(V)`, and the wallet's ShardTree root over that many leaves (`ShardTree::root` truncated at the size, not a checkpoint, since upstream checkpoints only blocks with commitments) with the frontier's root. The root commits to every leaf before `V`, including the frontier a restore's birthday took from the endpoint, which settles the **needs verification** of §9: a forged birthday tree state fails here. A block the scanner refuses during a backfill (tree sizes that do not add up, bad encoding, a block that does not link to the wallet's) fails the check too, since every block of the batch came from the endpoint. So does a batch whose insertion the wallet's ShardTree refuses (`gyges_core::sync::tree_refusal`: `SqliteClientError::PutBlocksCommitmentTree` or `CommitmentTree` carrying `ShardTreeError::Insert`, apart from `MarkedRetentionInvalid`, or a `CheckpointConflict`): below the window each batch's prior tree state is the endpoint's `GetTreeState`, so a frontier with the right size and hash but other leaves conflicts with the leaves the wallet already holds, and retrying would refuse it again every tick. Storage errors of the tree (a busy database, an unreadable shard) are not the endpoint's and are retried; on the node (Case A) a refusal is retried like any wallet error.
- Check 2 runs at every batch boundary (above) and at the handoff on the wallet's own recorded hashes at `V`, at `retained_from` and at the first backfilled block, against `getblockhash`. A chunk that does not link to the cached block below it (`FillError::Unlinked`) also fails it.
- Check 3 runs when the session opens, before anything from the endpoint reaches the wallet: every root `GetSubtreeRoots` serves must equal `z_getsubtreesbyindex` for the same pool and index (root and completing height), and only the run the node confirms is handed to `put_*_subtree_roots`; an index the node does not report is left out with every later one of that pool. A node that cannot answer `z_getsubtreesbyindex` confirms nothing, which costs only witness completeness during the backfill, not correctness.
- Fail truncates to the block before the session began (`birthday - 1` for a restore, the old scanned tip for the pruning race), through `truncate_to_chain_state` where the wallet has no block row there (a restore's `birthday - 1`); drops every `tor-lwd` row from the cache; and persists the mark in `<network>/fallback_trust.json` with the endpoint and the reason, so a restart with the same endpoint keeps it and configuring another clears it. `GetInfo.fallback.trust` is `UNTESTED` until a handoff passes (`VERIFIED`) or fails (`UNTRUSTED`); `GetInfo.tor` reflects the endpoint's Tor client (`DISABLED` for `use_tor = false`, unset until the first backfill bootstraps it). `RestoreKey` below the window is refused with `FALLBACK_UNAVAILABLE` while the endpoint is untrusted.
- An endpoint that is unreachable, behind or missing a block stalls the key with `FallbackUnreachable`, retried every tick.

#### 5.3 Transparent history below `retained_from`

Compact blocks carry no transparent outputs and a pruned node stops maintaining address indexes, so the only source is lightwalletd `GetAddressUtxos` for the key's transparent and ephemeral receivers (gap-limit scan). Each returned UTXO's transaction is fetched with `GetTransaction`, its txid recomputed, and its block hash compared with `getblockhash(height)` from the node. A UTXO that cannot be placed in a node-confirmed block is discarded and logged. This is a weaker guarantee than the shielded checks and `security.md` says so.

**Status:** built as `gyges_core::recovery` and `gygesd::backfill::recover_transparent`, run once a session's handoff has validated and before it closes (an endpoint that drops out is retried on the next tick). The endpoint is asked about every receiver the wallet has (external, change, ephemeral) for `[from, V]`; crediting can advance the gap limit, so new receivers are asked about in further passes (at most 16). For each reported output:

1. `GetTransaction` must return bytes that hash to the reported txid, at the reported height, with the reported script and value at the reported index.
2. The node must have a block at that height (`getblockhash`).
3. Where the node still holds the block (`height >= retained_from`), the transaction and output must be in the node's own block. This covers `[retained_from, V]`, which the backfill took from the endpoint without transparent outputs, so nothing else credits outputs there.
4. Below the window, the endpoint's compact block at that height must hash to the node's, and a transaction with shielded parts must be listed in it. A transparent-only transaction cannot be placed (compact blocks list only transactions with shielded parts and carry no Merkle proof), so it is accepted as best-effort and counted as `unplaced`.

A failure discards the output with a log line naming the height and the reason, never the address or amount; it does not mark the endpoint untrusted. What passes goes straight into the upstream UTXO table through `put_received_transparent_utxo` (an upsert), with no `gyges_transparent_received_outputs` staging table (see below). The counts are kept in `keys/<id>/transparent_recovery.json`. An output the endpoint omits, or one spent above the window that it still reports, cannot be detected. A fabricated transparent-only output with a self-consistent transaction would be credited too; spending it fails at the node.

---

### 6. Scanned versus Spendable

| Term | Definition | Source of truth |
|---|---|---|
| **scanned** | `block_fully_scanned().height >= bounds.tip_height` | `WalletRead::block_fully_scanned` |
| **spendable** | scanned, and `suggest_scan_ranges()` returns no range with priority above `Ignored` | `WalletRead::suggest_scan_ranges` |

`GetSyncStatus` returns both booleans plus `scanned_tip`, `tip_height`, the `SyncState`, blocks per second over the last minute, the blocks remaining across open ranges and the active source (`retained_from` is in `GetInfo.node`). The CLI never computes them itself. `WaitSync` wakes the scheduler and reports `done` only from a tick that began after the request, so a `sync wait` issued right after new blocks never returns a stale "spendable"; a stalled key fails the stream at once with `NOT_SYNCED` (interface.md API §4.4).

`gyges sync wait` defaults to `--until spendable`; `--until scanned` is cheaper for scripts that only need the tip. `--confirmations N --txid T` waits until `T` has `N` confirmations.

---

### 7. Mempool

Runs continuously inside the daemon when `mempool.scan = true` (default):

- With the indexer gRPC: subscribe to `mempool_change` (`Added`, `Invalidated`, `Mined` with txid) and `getrawtransaction` only added txids. *Not built: there is no Zakura indexer (`decisions.md` §2.5).*
- Without: `getrawmempool`, diff against the seen set, fetch only new txids with `getrawtransaction(txid, 1)`. *Built (`gygesd::sync::Scheduler::mempool_pass`).* A pass runs at most once per `poll_interval_secs`, and only on a tick that scanned no batch, so a key catching up is not slowed down. At most 500 new transactions are fetched per pass; the rest are fetched on the next one. Only the node is asked (`ChainBackend::mempool_txids` / `fetch_transaction`); the fallback endpoint has no mempool listing.

Each new transaction is fetched once, whatever the number of keys, and trial-decrypted for every key with `zcash_client_backend::decrypt_transaction` (the Sapling, Orchard and Ironwood outputs). What it finds is stored unmined via `WalletWrite::store_decrypted_tx` (`gyges_core::mempool::scan_tx`, which follows upstream's `decrypt_and_store_transaction`). That is what `balance` shows under *pending*: upstream's summary counts unmined received value as pending and the notes it spends as spent, so no balance code is involved. A key without a chain tip yet is skipped.

Nothing has to be done about txids that vanish from `getrawmempool`:
- the wallet's own sends get their mined status from the status work (`decisions.md` §2.3) or from scanning;
- an incoming transaction that never gets mined stops counting once the tip passes its expiry height, because upstream's balance ignores expired unmined transactions;
- `tex_queue` polls the node itself.

`gyges sync mempool` (`ScanMempool`) forces one immediate full pass for every key, even with `mempool.scan = false`. It covers every transaction in the mempool, seen before or not, up to the same 500.

The request pattern is identical whether or not the wallet has activity, so mempool polling leaks nothing beyond the block requests. Upstream logs every txid `store_decrypted_tx` stores at `info`, and some of its warnings and `zcash_client_sqlite`'s messages name txids too. Under `daemon.log_level` those targets are capped (`gygesd::logs::QUIET_UPSTREAM`), so the main log keeps no txid.

---

### 8. Daemon Stop

On `daemon stop` or `SIGTERM`:

1. Stop the scheduler at the next batch boundary. A batch is at most `cache.scan_batch` blocks, and `scan_cached_blocks` commits per batch, so no partial batch is ever visible. Shutdown sets a stop flag on the `SyncHub`. The scheduler finishes the batch in hand, its fetch from the node and its scan, and then returns. Shutdown waits up to 30 s for it and cancels it after that; a cancelled batch commits nothing.
2. Close Tor streams; the Arti cache under `tor_cache/` is kept.
3. Run `PRAGMA wal_checkpoint(TRUNCATE)` on `blocks.sqlite`. The `wallet.sqlite` files use upstream's default rollback journal, not WAL, so they have nothing to checkpoint.
4. Zeroize unlocked keys and destroy signing sessions held in memory (persisted sessions in `signing_sessions` survive).
5. Leave `ext_gyges_tex_queue` rows as they are; the queue resumes on next start (it re-checks every active row against the node, so a step the node lost while the daemon was down is simply rebroadcast).
6. Unlink the socket last, after every step above. `gyges daemon stop` waits for the file to go, so it returns only once the batch is committed, the keys are zeroized and the cache is checkpointed.

On restart every key begins in `Initializing`, which re-derives its state from `block_fully_scanned` and `NodeBounds`, so an interrupted scan simply continues.

---

### 9. Upstream Calls by Step

| Step | Function (`zcash_client_backend::data_api` unless noted) |
|---|---|
| New or restored key | `WalletWrite::create_account` / `import_account_ufvk` with `AccountBirthday::from_treestate(z_gettreestate(birthday - 1))` when `birthday - 1 >= retained_from`, else `AccountBirthday` built from the lightwalletd `GetTreeState` over Tor, whose block hash must equal the node's and whose frontier is validated at `V` with the rest of the stream (the §5.2 root at `V` commits to every leaf before the birthday, so a forged frontier fails it) |
| Tip update | `chain::update_chain_tip` |
| Subtree roots | `WalletCommitmentTrees::put_sapling_subtree_roots`, `put_orchard_subtree_roots` |
| Range selection | `WalletRead::suggest_scan_ranges` |
| Scan | `chain::scan_cached_blocks` over the `BlockCache` impl |
| Reorg | `WalletWrite::truncate_to_height` |
| Mempool | `decrypt_transaction`, `WalletWrite::store_decrypted_tx` |
| Status | `WalletRead::block_fully_scanned`, `chain_height`, `suggest_scan_ranges` |

What Gyges writes itself: `NodeBounds` polling, `CompactBlockSource` and its two implementations, the `BlockCache` implementation and `BlockFetcher`, the compact-block builder from raw blocks, the handoff validator, the state machine in §3, and the mempool diff loop. The loop body is a port of upstream `sync::run` onto `CompactBlockSource`, since `sync::run` is bound to a lightwalletd `CompactTxStreamerClient` and cannot be fed from node RPC.

## Data model

Everything `gygesd` writes to disk: the directory layout, `config.toml`, `profile.json`, `seed.age`, the Gyges-owned SQLite tables that sit beside the upstream `zcash_client_sqlite` schema, the shared block cache, and the migration and backup policy. Derived from the proposals under Q-C2, Q-S5…S7, Q-T1, Q-K4 and Q-Y3 in `decisions.md`.

---

### 1. Directory Layout

One home per network (Q-C2). `GYGES_HOME` (default `~/.gyges`) is the root.

```text
~/.gyges/
└── mainnet/                     # or testnet/, regtest/
    ├── config.toml              # Daemon configuration (§2)
    ├── gygesd.sock              # Unix Domain Socket
    ├── gygesd.pid               # PID of the running daemon, advisory-locked
    ├── tor_cache/               # Arti directory and consensus cache
    ├── fallback_trust.json      # Only after a failed handoff: the untrusted endpoint and why (Sync §5.2)
    ├── cache/
    │   └── blocks.sqlite        # Shared CompactBlock cache (§6)
    ├── logs/
    │   ├── gygesd.YYYY-MM-DD.log  # tracing-appender, daily rotation, 7 kept
    │   └── audit.log            # Security-relevant events as JSON lines, key id + time only; never rotated
    └── keys/
        └── <key_id>/
            ├── profile.json     # KeyProfile metadata (§3)
            ├── wallet.sqlite    # zcash_client_sqlite WalletDb + Gyges tables (§5)
            ├── backfill.json    # Only while a Case B backfill awaits its handoff (Sync §5)
            ├── transparent_recovery.json  # After a validated backfill: what GetAddressUtxos gave and what was kept (Sync §5.3)
            └── seed.age         # Only for local-seed and signer-only (§4)
```

`key_id` matches `^[a-z0-9][a-z0-9_-]{0,31}$`.

#### Permissions (Q-S7)

| Path | Mode | Enforced |
|---|---|---|
| every directory under `GYGES_HOME` | `0700` | daemon refuses to start on anything wider |
| every file | `0600` | same |
| `gygesd.sock` | `0600` (`0660` with `daemon.socket_group` set) | set after bind |
| directory of `daemon.socket_path`, when set | owned by the daemon's uid, no bits beyond `0750` | daemon refuses to start otherwise (`perms::check_socket_dir`) |

The refusal message names the path and the one-line `chmod` that fixes it. Tilde in any configured path is expanded by the daemon; the CLI never reads these files.

---

### 2. `config.toml`

Complete schema with defaults. Every key is optional except `fallback_lightwalletd.grpc_url` when `fallback_lightwalletd.enabled = true`. On first start, when the file is missing, `gygesd` writes a commented template (`gyges_core::config::template`, 0600): every line is a comment, so it changes nothing, and on mainnet it lists the public endpoints below, with the advice to prefer an operator's `.onion` address.

```toml
# ~/.gyges/mainnet/config.toml
network = "mainnet"              # optional; when set it must match the directory, else the daemon refuses to start
default_key = "main"             # substituted by the daemon when a request has an empty key_id
airgapped = false                # true disables every network interface (Tor, RPC, indexer)

[daemon]
socket_path = ""                 # non-empty: absolute socket path instead of <network dir>/gygesd.sock (hardened: /run/gyges/<network>/gygesd.sock)
socket_group = ""                # non-empty: socket mode 0660 owned by this group (name or numeric gid)
allowed_uids = []                # peer uids besides the daemon's own that may connect (interface.md API §1.2)
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
overlap_blocks = 10              # k in Sync §5
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

### 3. `profile.json`

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

### 4. `seed.age`

An ordinary age file (`rage` can decrypt it) with a single scrypt passphrase recipient, armored (`age-encryption.org/v1` ASCII), holding the 32-byte BIP-39 **entropy** of the 24-word mnemonic, not the 64-byte derived seed. Exporting the backup therefore yields the same words the user wrote down.

- Work factor: `vault.scrypt_work_factor`, recorded alongside the file as `profile.json.seed_format` so it can be raised by a migration that re-encrypts.
- Decryption produces `secrecy::Secret<[u8; 32]>` (`gyges_core::vault::Entropy`); the mnemonic and the `UnifiedSpendingKey` derived from it are zeroized on drop.
- The file is written with `O_EXCL` and `0600`, then renamed into place; it is never rewritten except by `gyges key passphrase` (change passphrase) and migrations.

Argon2id is not used; see Q-S5 for the compatible construction if it is ever required.

---

### 5. `wallet.sqlite`

The upstream `zcash_client_sqlite` schema is created and migrated by upstream's `WalletMigrator` and is not modified. Gyges adds its own tables to the same database, so a key directory is self-contained and Gyges' writes are transactional with the wallet state.

**All of it lives in `gyges_core::db`** (`crates/gyges-core/src/db/`). `zcash_client_sqlite` reserves the `ext_` prefix for application tables, so every Gyges table is `ext_gyges_*`. One external migration (`db::MIGRATION`, registered with `WalletMigrator::with_external_migrations` when the registry opens a wallet) creates them from `db/schema.sql`. Every statement runs through `WalletDb::transactionally_with_extension`, whose SQLite authorizer allows reads of any table but writes only to `ext_*` tables, and refuses schema changes and transaction control.

Rules the module enforces:

* **Static SQL, bound values.** Its `Db` wrapper accepts only `&'static str` statements, so SQL cannot be assembled at run time. Every value is a named parameter, and a set is bound as a JSON array and read with `json_each(:param)`. Enums bind through `ToSql`/`FromSql` as their `as_str()` spelling, and an unknown stored value is an error, never a default.
* **One row per statement.** The extension handle offers only `execute` and `query_row`, so a read of many rows is one `json_group_array(...)` cell decoded with serde, or a list of ids followed by one read per id inside the same transaction. BLOB columns go through `hex()` inside JSON.
* **No `AUTOINCREMENT`.** It writes `sqlite_sequence`, which the authorizer refuses.

The CHECK lists in `schema.sql` repeat the enums' spellings, and `db` tests insert every variant so the two cannot drift apart.

#### 5.1 `ext_gyges_tex_queue` (Q-T1)

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

#### 5.2 `ext_gyges_signing_sessions` (Q-K4, Q-C4)

`gyges_core::db::sessions`. One row per signing session that outlives a connection: a PCZT file (`file`) or a Keystone session (`keystone-batch`, `keystone-pczt`). Passphrase sessions of `tx send` are memory-only (interface.md API §6.1).

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

#### 5.3 `ext_gyges_address_labels`

`gyges_core::db::labels`. Written by `address new --label` (an upsert keyed on the address as handed out) and read back by `GetCurrentAddress` / `NewAddress`.

```sql
CREATE TABLE ext_gyges_address_labels (
    address     TEXT NOT NULL PRIMARY KEY,
    label       TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
```

#### 5.4 Reads of upstream views

`gyges_core::db::history` reads upstream's documented views (`v_received_outputs`, `v_received_output_spends`, `v_tx_outputs`) for `ListNotes` and the outputs of `ListTransactions`, since upstream has no production API for either. These are reads only, through the same handle.

#### 5.5 What is not in SQLite

The audit trail is `logs/audit.log` (Q-O1), not a table: it must survive a database wipe, and it must be appendable while a migration holds the database. Decrypted spending keys, passphrases and session tokens are never written anywhere.

---

### 6. Block Cache (`cache/blocks.sqlite`)

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

Eviction policy and privacy trade-off are in Sync §2.2: `source = 'tor-lwd'` rows reveal an approximate birthday, so the file is `0600` and those rows are dropped once consumed unless `cache.keep_historical = true`. The cache is disposable; deleting it costs a refetch, never wallet state. `data` is the lightwalletd `CompactBlock` protobuf including `vin`/`vout` for every transaction (the Case A transparent index, Sync §2.1), so a cached mainnet block is tens of kilobytes rather than a few. The daemon refuses to open a cache whose `cache_meta.network` is another network or whose `user_version` is newer than its own, naming the file (`gyges_chain::cache::BlockDb::open`).

---

### 7. Migrations

| Store | Mechanism | Trigger |
|---|---|---|
| upstream wallet tables | `WalletMigrator` (schemerz migrations shipped by `zcash_client_sqlite`) | every wallet open, with the Gyges migration |
| `ext_gyges_*` tables | one external `schemerz-rusqlite` migration, `gyges_core::db::MIGRATION` (`db/schema.sql`), run by upstream's `WalletMigrator` with its own; later changes are new migrations depending on it | every wallet open |
| `blocks.sqlite` | `PRAGMA user_version` checked against `gyges_chain::cache::SCHEMA_VERSION`; the file is disposable | every daemon start |
| `profile.json` | `schema_version` switch in `gyges-core::profile`; rewritten atomically after a successful upgrade | profile load |
| `seed.age` | re-encryption only when `seed_format` changes, which requires the passphrase and therefore runs lazily on the next unlock | unlock |
| `config.toml` | never rewritten by the daemon; removed keys produce a startup error naming the replacement | startup |

Downgrades are not supported: a daemon older than the schema version it finds refuses to start (exit 1, message names both versions). Migrations run inside one SQLite transaction per database and are tested in `testing.md` §4 by opening fixture databases from every released version.

---

### 8. Backup and Restore (Q-S7)

The minimal backup is the 24-word mnemonic plus `birthday_height`. Everything in `wallet.sqlite` is derived state: notes, witnesses and ZIP 320 ephemeral addresses are all recovered by rescanning from the seed (the "this was a TEX payment" label may be lost, which ZIP 320 accepts).

Convenience commands:

```bash
gyges key backup --id main -o main.tar            # profile.json + seed.age; --with-wallet adds wallet.sqlite
gyges key import-backup main.tar
```

`key backup` runs `PRAGMA wal_checkpoint(TRUNCATE)` on the key's database before archiving, so the archive is consistent. Copying `keys/<id>/` by hand is supported only while the daemon is stopped, because of the WAL files. `gyges key delete --wipe` overwrites `seed.age` and `wallet.sqlite` best-effort before unlinking; on copy-on-write filesystems this is advisory only and the docs say so.
