# Gyges Roadmap

> Drafted 2026-10-20 from `OVERVIEW.md` §7. Milestones are ordered by risk retired per unit of work; each later milestone has its own design note before code starts.

## Principles

- **Core loop first.** Nothing ships until init → sync → send → confirm works end to end on regtest against a real `zakurad`. Everything else is layered on top of that loop.
- **Track Zakura deliberately.** Exact pins, `Cargo.lock` committed, one PR per upstream release, regtest suite green before merge (`OVERVIEW.md` Q-D3).
- **Pools are data.** Orchard and transparent spend in the MVP; Sapling receive-only; Ironwood off until the upstream APIs leave `-rc` (Q-D7).
- **Security claims are tested.** Every control in `THREAT_MODEL.md` names the test that proves it (`TESTING.md`).

## M0 — Honest repository (this milestone)

- [x] `Cargo.toml` resolves against the published crates with `package =` renames and exact pins; `Cargo.lock` committed.
- [x] Six empty crates; `cargo check --workspace` passes; upstream module paths cited in the docs are compile-checked.
- [x] `proto/gyges.proto` validates with `protoc`; `API.md` written.
- [x] `THREAT_MODEL.md`, `SYNC.md`, `DATA_MODEL.md`, `TESTING.md`, `GLOSSARY.md`, `README.md`, licences, CI workflow, `deny.toml`.
- [x] `ARCHITECTURE.md` and `CLI_SPEC.md` corrected per the review.
- [ ] Review the Q-S1…S7 / Q-K7 proposals and promote `THREAT_MODEL.md` from draft.

## M1 — MVP: local-seed, Orchard + transparent, local node

Scope: `local-seed` profiles only; Case A sync against a local Zakura node; `tx send` to `u1` and `t1`; `balance`, `notes`, `tx list`; inline unlock; `daemon start/stop/status`.

- [x] `gyges-proto` build, UDS server in `gygesd` with `SO_PEERCRED` check, UDS client in `gyges-cli`, `GetInfo` handshake and version check. Also landed with it: `config.toml` loading with the documented defaults, the 0700/0600 permission sweep, the `gygesd.pid` lock, `--airgapped` RPC gating, `Shutdown`, and `gyges daemon start/stop/status`.
- [x] `KeyRegistry` + `profile.json` + permission enforcement; `key init`, `key restore` (birthday inside retention window only), `key list`. Landed as `gyges_core::{profile, registry, birthday, vault}` plus the `ChainBackend` trait in `gyges-chain` (node bounds and tree state; a fixed fake until the RPC backend exists). `key init` on a `--airgapped` daemon creates a `signer-only` profile; on a networked daemon it needs the node for the birthday, so until the next item lands it answers `NODE_UNREACHABLE`. `key restore` works without a node only at the default (Sapling activation) birthday. `--set-default` lasts for one daemon run because the daemon never rewrites `config.toml`.
- [ ] `VaultManager`: `seed.age` (age scrypt) *(done: `gyges_core::vault` seals the 32-byte entropy in an armored age file at `vault.scrypt_work_factor`)*, connection-scoped and daemon-scoped sessions, rate limiting, zeroize on stop.
- [ ] `ZakuraRpcBackend`: `getblockchaininfo` bounds, `getblock(h,0)` → `CompactBlock`, shared `cache/blocks.sqlite` implementing `BlockCache`, transparent output indexing from raw blocks.
- [ ] `SyncScheduler` Case A only: `scan_cached_blocks`, `suggest_scan_ranges`, reorg truncation, `sync status` / `sync wait`.
- [ ] `TxEngine`: `propose_transfer` → `create_pczt_from_proposal` → Prover → Signer → Verifier → Spend Finalizer → Tx Extractor → `sendrawtransaction`; `--dry-run`; typed `GygesError` and exit codes.
- [ ] Regtest harness (`tests/regtest/`): pinned `zakurad`, generate, init → mine → send → reorg of 3 blocks. CI job added. *(The harness and the daemon-lifecycle scenarios exist and run in the ordinary `test` job; the node is not wired in yet.)*
- [ ] Log redaction test; audit log.

Exit criterion: a fresh user can run a regtest node, `gyges key init`, mine, `gyges tx send`, and see the balance move, with CI proving it.

## M2 — Historical restore over Tor

Design note: `SYNC.md` §Case B.

- [ ] `ArtiTorLwdBackend` on `zcash_client_backend::tor`; `GetSubtreeRoots`, `GetBlockRange` streaming into the shared cache.
- [ ] Handoff validation at `retained_from + k` (tree roots, hash chain, subtree roots); endpoint trust state in `daemon status`.
- [ ] Pruning-race fallback (Case A → Case B) and `Stalled` states.
- [ ] Transparent recovery below `retained_from` via `GetAddressUtxos` with per-UTXO inclusion checks.
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
- [ ] Verifier before broadcast; property tests for the role pipeline.

## M5 — Keystone 3 Pro

Design note: `ARCHITECTURE.md` §3.4; recorded UR fixtures in `TESTING.md`.

- [ ] `gyges-qr`: half-block renderer, fountain encoder/decoder, registry types 49201/49203/49204/49205/49207.
- [ ] `key import-keystone` with required birthday and `device_version` check.
- [ ] Batch protocol for shielded sends; single-PCZT protocol with Combiner for transparent inputs; signing sessions that survive restarts; `qr-import --from-file` and `--session`.
- [ ] `qr-scan` camera path.
- [ ] Verify on hardware: TEX Step 2 signing, which PCZT fields the device displays.

## M6 — Hardening and release

- [ ] Sapling spending for `local-seed` profiles (Updater inserts the proof generation key before proving).
- [ ] `perf` features with benchmarks in `docs/BENCHMARKS.md`; decide the release default once runtime CPU detection is confirmed.
- [ ] `daemon install/uninstall` units; hardened deployment (dedicated user, 0660 socket, `gyges` group) documented and tested.
- [ ] Optional SQLCipher for `wallet.sqlite`; `key delete --wipe`; `key backup` / `import-backup`.
- [ ] Release pipeline: `rust-toolchain.toml`-pinned matrix builds, `SHA256SUMS`, `minisign`, SLSA attestation.
- [ ] `tx status --pir` leaves experimental only with a documented server set and privacy guarantee.

## Deferred and out of scope

- Ironwood spending and receiving until upstream wallet support is stable.
- Issuing `tex1` receive addresses (dropped, `OVERVIEW.md` Q-T5).
- Windows (needs named pipes with ACLs and a different hardening story).
- `cargo vet` until the Zakura stack stabilises.
