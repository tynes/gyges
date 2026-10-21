# Gyges Roadmap

> Drafted 2026-10-20 from `OVERVIEW.md` §7. Milestones are ordered by risk retired per unit of work; each later milestone has its own design note before code starts.

## Principles

- **Core loop first.** Nothing ships until init → sync → send → confirm works end to end on regtest against a real `zakurad`. Everything else is layered on top of that loop.
- **Track Zakura deliberately.** Exact pins, `Cargo.lock` committed, one PR per upstream release, regtest suite green before merge (`OVERVIEW.md` Q-D3).
- **Pools are data.** Orchard, Ironwood and transparent spend in the MVP; Sapling receive-only. Ironwood cannot be "off": after NU6.3 (regtest height 1, mainnet 3,428,143) the wallet libraries build every shielded output in the Ironwood pool and the ZIP 318 turnstile keeps value out of Orchard, so Orchard is spend-only there (Q-D7, `OVERVIEW.md` §4.3).
- **Security claims are tested.** Every control in `THREAT_MODEL.md` names the test that proves it (`TESTING.md`).

## M0 — Honest repository (this milestone)

- [x] `Cargo.toml` resolves against the published crates with `package =` renames and exact pins; `Cargo.lock` committed.
- [x] Six empty crates; `cargo check --workspace` passes; upstream module paths cited in the docs are compile-checked.
- [x] `proto/gyges.proto` validates with `protoc`; `API.md` written.
- [x] `THREAT_MODEL.md`, `SYNC.md`, `DATA_MODEL.md`, `TESTING.md`, `GLOSSARY.md`, `README.md`, licences, CI workflow, `deny.toml`.
- [x] `ARCHITECTURE.md` and `CLI_SPEC.md` corrected per the review.
- [x] Review the Q-S1…S7 / Q-K7 proposals and promote `THREAT_MODEL.md` from draft. Landed 2026-10-21 as a **Decision** paragraph under each of those questions in `OVERVIEW.md` §6, and `THREAT_MODEL.md` at status "reviewed": §1 and §5 corrected against the code (the spending key is a plain upstream value for one signing task, not a `SecretBox`; the CLI never requests connection tokens; passphrase sessions are memory-only; the non-interactive, `cache` mode and USK rows checked off with their tests), §6 turned into decisions with four items still needing verification (asm CPU detection, the Keystone display, `z_getsubtreesbyindex` on pruned ranges, TLS in the `tor` feature), each assigned to a milestone. Code the decisions asked for: `RLIMIT_CORE = 0` at daemon start (`gygesd::disable_core_dumps`), a one-time warning when `zakura_rpc.url` is not this machine (`gygesd::node::is_local_host`), a policy-layer test with foreign and missing credentials, and a test of the 0660 socket-group mode.

## M1 — MVP: local-seed, Orchard + transparent, local node

Scope: `local-seed` profiles only; Case A sync against a local Zakura node; `tx send` to `u1` and `t1`; `balance`, `notes`, `tx list`; inline unlock; `daemon start/stop/status`.

- [x] `gyges-proto` build, UDS server in `gygesd` with `SO_PEERCRED` check, UDS client in `gyges-cli`, `GetInfo` handshake and version check. Also landed with it: `config.toml` loading with the documented defaults, the 0700/0600 permission sweep, the `gygesd.pid` lock, `--airgapped` RPC gating, `Shutdown`, and `gyges daemon start/stop/status`.
- [x] `KeyRegistry` + `profile.json` + permission enforcement; `key init`, `key restore` (birthday inside retention window only), `key list`. Landed as `gyges_core::{profile, registry, birthday, vault}` plus the `ChainBackend` trait in `gyges-chain` (node bounds and tree state; a fixed fake until the RPC backend exists). `key init` on a `--airgapped` daemon creates a `signer-only` profile; on a networked daemon it takes the birthday from the node's tip (`NODE_UNREACHABLE` while the node is down). `key restore` works without a node only at the default (Sapling activation) birthday. `--set-default` lasts for one daemon run because the daemon never rewrites `config.toml`.
- [x] `VaultManager`: `seed.age` (age scrypt), connection-scoped and daemon-scoped sessions, rate limiting, zeroize on stop. Landed as `gyges_core::vault::manager::VaultManager` (unlocks keyed by connection id + 32-byte token or daemon-wide, idle TTL refreshed on use, per-key back-off 1 s doubling to `vault.unlock_backoff_max`, `lock_all` on stop and a 5 s sweep) and `gygesd::conn::Conn` (per-connection id carried in request extensions, unlocks dropped when the socket closes). RPCs: `UnlockKey` (no `session_id` form; the session-bound form waits for `TxEngine`), `LockKey`, `ExportUfvk`, `ExportSeed`; CLI: `key unlock/lock/export-ufvk/export-seed`. Audit events go to the `gyges::audit` tracing target until the audit log item routes them to a file.
- [x] `ZakuraRpcBackend`: `getblockchaininfo` bounds, `getblock(h,0)` → `CompactBlock`, shared `cache/blocks.sqlite` implementing `BlockCache`, transparent output indexing from raw blocks. Landed as `gyges_chain::{rpc::ZakuraRpcBackend, compact, cache::BlockDb}`: JSON-RPC with the cookie re-read per request (the node rotates it at every start), `ChainBackend` extended with `status()`, `block_hash()` and `compact_blocks(range)` (ordered concurrent `getblock(h, 0)` + `getblock(h, 1)` pairs, cross-checked on hash and txids, linked by `prev_hash`), compact blocks that carry every transparent `vin`/`vout` so the cache is the transparent index, and `BlockDb` implementing `BlockSource` + `BlockCache` with source tagging and eviction helpers. `gygesd` builds the backend and opens the cache unless `--airgapped`, polls the node once before binding the socket and then every `poll_interval_secs`, reports it in `GetInfo.node`, warns when the retention window is below `min_retention_blocks`, and checkpoints the cache on stop. Tests run against an in-process fake `zakurad` (`gyges-chain` feature `test-util`), not a real node; the response shapes it mimics are recorded in `OVERVIEW.md` §4.3. Not done: `z_getsubtreesbyindex`, the indexer gRPC, `node_version`/`tx_retention` in `NodeStatus` (no RPC exposes them).
- [x] `SyncScheduler` Case A only: `scan_cached_blocks`, `suggest_scan_ranges`, reorg truncation, `sync status` / `sync wait`. Landed as `gyges_core::sync` (state machine types, `WalletView` over `update_chain_tip` / `suggest_scan_ranges` / `block_fully_scanned`, the `scan_range` step over the shared cache, transparent-output crediting through `put_received_transparent_utxo`, fork search and `truncate_to_height`) and `gygesd::sync` (one scheduler task per daemon: node poll, per-tick cache reconciliation against `getblockhash`, per-key batch fetch → `z_gettreestate(start-1)` → scan, reorg rewind within 100 blocks, eviction behind the slowest key, `Stalled(PrunedPastScanTip | ChainInconsistent | Offline)`), plus `GetSyncStatus`, `WaitSync` and `RunSync` (rewind with `confirm_rewind`) and `gyges sync status / wait / run`. Verified against the fake node only (scan to tip, new blocks, a 2-block reorg, rewind, prune stall and recovery, offline grace); shielded notes are not exercised because the fake mines transparent-only blocks. Not done: `Backfilling` (M2), `z_getsubtreesbyindex` subtree roots, `TransactionDataRequest` handling (mined status of fully transparent transactions, needed by the TxEngine item), the per-key `gyges_transparent_received_outputs` staging table (outputs go straight into the upstream UTXO table until the `gyges_` migrations exist), `sync mempool`, and the indexer gRPC.
- [x] `TxEngine`: `propose_transfer` → `create_pczt_from_proposal` → Prover → Signer → Verifier → Spend Finalizer → Tx Extractor → `sendrawtransaction`; `--dry-run`; typed `GygesError` and exit codes. Landed as `gyges_core::tx` (recipient and memo rules, `propose_send` with `max`, `propose_shield`, `summarize`, `build_pczt`, `prove` for Orchard, Ironwood and Sapling outputs, `sign` for Orchard, Ironwood and BIP 44 transparent inputs, `verify` against the approved proposal, `extract_and_store`, `balance`) and `gygesd::tx` (`SendTransaction` / `ShieldFunds` streams that prove while locked, then take the key from a connection token, a daemon unlock, or an in-memory passphrase signing session satisfied by `UnlockKey { session_id }`; `ListSigningSessions`, `AbortSigningSession`, `GetBalance`), `ChainBackend::send_raw_transaction` over `sendrawtransaction` (`NODE_REJECTED` carries the node's text), and `gyges tx send / shield / sessions / abort`, `gyges balance` with the amount grammar, memo rules and the dry-run-then-confirm flow. Verified against the fake node only (it now has a mempool, mines broadcast transactions and keeps the Sapling, Orchard and Ironwood trees): fund → shield → Ironwood self-send through the session flow → `max` to a transparent address, plus every documented refusal. Not done: `wait_for_mined` for fully transparent transactions without change (no `TransactionDataRequest::GetStatus` in rc9.1, see `OVERVIEW.md` §4.3), the Sapling spend path (Q-K3), `--via-tor` (M2), the Keystone and watch-only paths (M4/M5), `tx list` / `tx status`, and the persisted `gyges_signing_sessions` table (passphrase sessions are memory-only by design, API.md §6.1).
- [x] Regtest harness (`tests/regtest/`): pinned `zakurad`, generate, init → mine → send → reorg of 3 blocks. CI job added. Landed as `tests/regtest/versions.toml` (tag `v1.6.0` and the sha256 of both Linux release assets), `gyges_regtest::Node` (downloads and verifies the pinned release on Linux, honours `ZAKURAD_BIN` elsewhere, skips with a message otherwise; writes `zakura.toml` with proof of work off, every upgrade through NU6.3 at height 1, a zero-value NU6.1 lockbox disbursement, cookie auth and `tx_retention = 1001`; drives `generate`, `invalidateblock`, `getrawtransaction`, `sendrawtransaction` and a restart that waits for the node's non-finalized backup), `scenarios/node.rs` (TESTING.md §3 rows 1–4: restore a fixed mnemonic, coinbases to its transparent address, shield, pay a second key's `u1` and the wallet's own `t1`, invalidate the three blocks holding those transactions, re-mine them, balances back) and the `regtest` CI job. Verified against `zakurad` v1.6.0 built from source on macOS; findings recorded in `OVERVIEW.md` §4.3 (regtest reports chain `"test"`, so `ZakuraRpcBackend` now accepts it and compares the node's `getblockchaininfo.upgrades` against the daemon's activation heights instead, which is also what refuses a testnet daemon on a regtest node). Fixed on the way: a key born in a reorged block could not be rewound (`truncate_to_height` has nothing at or below the fork); the scheduler now resets such a wallet to the node's tree state at the fork (`rewind_to_chain_state`). Not done: `zaino` and the prune-race rows (M2), the planned `tex` / `airgap` / `backfill` tag filters, `--release` builds of the binaries in CI.
- [x] Log redaction test; audit log. Landed as `gyges_core::log::Sensitive<T>` (`Debug`/`Display` print `[redacted]`; the value is reachable only through `expose()`), `gygesd::logs` (one layer stack: the daily `gygesd.<date>.log` filtered by `daemon.log_level`/`RUST_LOG`, `audit.log` as JSON lines taking every `gyges::audit` event regardless of the level and never rotated, and an in-memory tail of 1,000 entries per log behind `StreamLogs`), the `StreamLogs` RPC (replay, `follow`, `min_level`, `audit`) and `gyges daemon logs [--follow] [--lines N] [--audit]`. Audit events: `unlock` (with scope), `lock`, `export_seed`, `session_created`, `session_completed`, `session_aborted`, `sign` (with `via`), `broadcast`, `rewind` (with `from`). Tested at the three levels of `TESTING.md` §5: the wrapper, the production layers over in-memory writers, and the fake-node send scenario sweeping both files and both streams for the address, txid, amounts and passphrase. Not done: the `trybuild` compile-fail test for `Debug` on upstream key types (no lint can deny a derive in another crate; review enforces it), and the retention question for `audit.log` (`THREAT_MODEL.md` §6 item 11).

Exit criterion: a fresh user can run a regtest node, `gyges key init`, mine, `gyges tx send`, and see the balance move, with CI proving it.

## M2 — Historical restore over Tor

Design note: `SYNC.md` §Case B.

- [ ] `ArtiTorLwdBackend` on `zcash_client_backend::tor`; `GetSubtreeRoots`, `GetBlockRange` streaming into the shared cache.
- [ ] Handoff validation at `retained_from + k` (tree roots, hash chain, subtree roots); endpoint trust state in `daemon status`.
- [ ] Pruning-race fallback (Case A → Case B) and `Stalled` states.
- [ ] Transparent recovery below `retained_from` via `GetAddressUtxos` with per-UTXO inclusion checks; every restore with a birthday below `retained_from` warns that transparent history there is best-effort (`THREAT_MODEL.md` §6 item 9).
- [ ] Restore prompt and `--yes`; no default endpoint; `.onion` preference.
- [ ] Regtest: small retention window with local `zaino`, `use_tor = false` in CI; nightly job through a local Tor network.

## M3 — ZIP 320 (`tex1`) sends

Design note: `ARCHITECTURE.md` §3.3, `DATA_MODEL.md` `gyges_tex_queue`.

- [ ] `propose_standard_transfer_to_address` multi-step proposals; `--dry-run` rendering of both steps.
- [ ] `TexQueue` broadcaster with persisted raw transactions and state machine; `tx sessions` / `tx abort` / `tx resume`.
- [ ] Regtest: with and without mempool chaining, node restart between broadcasts, crash-restart with a pending row.

## M4 — PCZT pipeline and air-gapped signing

- [ ] `gyges pczt create/inspect/prove/sign/combine/broadcast` over files and pipes; `proprietary` map with key id, network, session id.
- [ ] `signer-only` profiles and `gygesd --airgapped` with the RPC allow-list from `API.md`.
- [ ] Verifier before broadcast; `pczt sign` checks that every change output belongs to the signer's own keys, since the upstream Signer role does not (`THREAT_MODEL.md` §6 item 8); property tests for the role pipeline.

## M5 — Keystone 3 Pro

Design note: `ARCHITECTURE.md` §3.4; recorded UR fixtures in `TESTING.md`.

- [ ] `gyges-qr`: half-block renderer, fountain encoder/decoder, registry types 49201/49203/49204/49205/49207.
- [ ] `key import-keystone` with required birthday and `device_version` check.
- [ ] Batch protocol for shielded sends; single-PCZT protocol with Combiner for transparent inputs; signing sessions that survive restarts; `qr-import --from-file` and `--session`.
- [ ] `qr-scan` camera path.
- [ ] Verify on hardware: TEX Step 2 signing, which PCZT fields the device displays.

## M6 — Hardening and release

- [ ] Sapling spending for `local-seed` profiles (Updater inserts the proof generation key before proving; proven and signed inside the one stream, nothing persisted, `THREAT_MODEL.md` §6 item 1).
- [ ] `perf` features with benchmarks in `docs/BENCHMARKS.md`; decide the release default once runtime CPU detection is confirmed.
- [ ] `daemon install/uninstall` units; hardened deployment (dedicated user, 0660 socket, `gyges` group, `daemon install --hardened`, `THREAT_MODEL.md` §6 item 4) documented and tested.
- [ ] Optional SQLCipher for `wallet.sqlite` (database key in the OS keychain only, `THREAT_MODEL.md` §6 item 3); `key delete --wipe`; `key backup` / `import-backup`.
- [ ] Release pipeline: `rust-toolchain.toml`-pinned matrix builds, `SHA256SUMS`, `minisign`, SLSA attestation.
- [ ] `tx status --pir` leaves experimental only with a documented server set and privacy guarantee.

## Deferred and out of scope

- Ironwood spending and receiving until upstream wallet support is stable.
- Issuing `tex1` receive addresses (dropped, `OVERVIEW.md` Q-T5).
- Windows (needs named pipes with ACLs and a different hardening story).
- `cargo vet` until the Zakura stack stabilises.
