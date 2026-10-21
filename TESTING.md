# Gyges Testing Strategy (`TESTING.md`)

How Gyges is tested, from unit tests to a nightly run through a real Tor network. Derived from the Q-O1, Q-O2 and Q-O5 proposals in `OVERVIEW.md`. Nothing described here exists yet; paths and commands are the planned ones and are marked as such where it matters.

---

## 1. Test Tiers

| Tier | Where | Runs on | Needs | Blocks merge |
|---|---|---|---|---|
| Unit | `#[cfg(test)]` in each crate | every PR | nothing | yes |
| Crate integration | `crates/*/tests/` | every PR | in-process SQLite, recorded fixtures | yes |
| Regtest end-to-end | `tests/regtest/` (planned) | every PR | pinned `zakurad` + local `zaino`, no Tor | yes |
| Nightly Tor | same scenarios, `use_tor = true` against a local Tor test network | nightly | `chutney`-style test network | no (opens an issue on failure) |
| Benchmarks | `crates/gyges-core/benches/` (planned, Criterion) | manual and on release tags | release build with `perf` | no |

---

## 2. Regtest Harness (`tests/regtest/`)

**Status:** the crate exists. `harness/lib.rs` runs `gygesd` and `gyges` against a temporary `GYGES_HOME` (building both binaries once per test process so they are never stale); `scenarios/daemon.rs` covers the daemon lifecycle, the handshake and the permission and single-instance refusals; `scenarios/keys.rs` covers `key list / init / restore / unlock / lock / export-ufvk / export-seed` without a node (scripted `--json` init on an air-gapped daemon, restore from stdin at the default birthday, the exit-4 and exit-7 refusals, the permission re-check on restart, a log grep for the passphrase and mnemonic, the rate-limited wrong passphrase, the daemon-scoped unlock window in `key list`, and the terminal-only rule of `export-seed`). The node and archival processes below are not wired in yet. Until they are, `gyges_chain::testing::FakeNode` (feature `test-util`) is an in-process `zakurad` stand-in serving `getblockchaininfo`, `getblockhash`, `getblock` (verbosity 0 and 1) and `z_gettreestate` with the shapes recorded in `OVERVIEW.md` §4.3, over synthetic transparent-only blocks that `Block::read` accepts; it can prune, rotate its cookie, reorg and report tree sizes. `gyges-chain`'s tests and `gygesd`'s `tests/rpc.rs` run the real `ZakuraRpcBackend` against it (bounds, hashes, tree states, compact blocks with transparent outputs, cookie failures, wrong chain, `key init` taking its birthday from the live tip, cache creation and checkpoint), and the `SyncScheduler` through it (a new key scanned to the tip, a transparent payment credited from a raw block, a two-block reorg detected and rewound, `RunSync` rewind, the prune-race stall and its recovery, `Stalled(Offline)` after `daemon.offline_grace`). `scenarios/sync.rs` drives the same fake node from the harness with the binaries: `sync status` / `sync wait` / `sync run --from` including the exit-4 confirmation and the exit-7 stall and timeout (rows 4–6 of §3 in miniature; the real-node versions wait for the harness item).

### 2.1 Components

```text
tests/regtest/
├── Cargo.toml          # package gyges-regtest; `autotests = false`, one [[test]] per scenario file
├── harness/lib.rs      # Rust library: spawns the processes below, exposes a Fixture (today: gygesd + gyges only)
├── zakurad.toml        # (planned) regtest config: tx_retention = 200, indexer enabled, cookie auth on
├── zaino.toml          # (planned) lightwalletd-compatible gRPC against the same node
├── fixtures/           # (planned) Keystone UR recordings (§4), schema fixtures (§6)
└── scenarios/          # one file per group of rows in §3 (today: daemon.rs)
```

- **Node:** a pinned `zakurad` release downloaded by tag (or built in a cached CI layer), started in regtest with `state.storage_mode.pruned.tx_retention = 200` so that Case B is exercised after mining a few hundred blocks. Blocks are produced with the regtest `generate` RPC.
- **Archival source:** `zaino` pointed at the same node, serving `CompactTxStreamer` for the backfill path. It is "archival" by construction because it indexes blocks before the node prunes them.
- **Daemon:** `gygesd` in the foreground with `GYGES_HOME` set to a temporary directory, `network = "regtest"`, `fallback_lightwalletd.use_tor = false` (direct gRPC) in CI. Tor bootstrap is slow and non-deterministic; it belongs to the nightly tier.
- **CLI:** every scenario drives the daemon through the `gyges` binary with `--json`, so the regtest suite doubles as the JSON schema test.

### 2.2 Fixture API

```rust
let fx = Fixture::start(RegtestOpts { tx_retention: 200, indexer: true }).await?;
fx.mine(10).await?;
let pw = fx.passphrase_file("test");                                   // today: GYGES_PASSPHRASE_FILE
let key = fx.gyges(&["key", "init", "--id", "main", "--json"]).env("GYGES_PASSPHRASE_FILE", &pw).run().json();
fx.fund_shielded(&key.address, Zatoshis::from_u64(1_000_000_000)).await?;   // coinbase -> shield -> mine
fx.gyges(["sync", "wait", "--until", "spendable"]).run().await?;
```

`Fixture` kills every child on drop and keeps the temporary directory when `GYGES_TEST_KEEP=1`.

---

## 3. End-to-End Scenarios

Each scenario is one test; the invariant column is what the assertion checks, beyond "exit code 0".

| # | Scenario | Invariant asserted |
|---|---|---|
| 1 | `key init` → mine → receive to `u1` → `balance` | Orchard balance equals funded amount after `sync wait --until spendable`; `notes` shows witness ready |
| 2 | `tx send` to `u1` (inline unlock) | Recipient key sees the note; sender fee equals ZIP 317 computed by `--dry-run`; `audit.log` has `unlock`, `broadcast` entries and nothing else |
| 3 | `tx send` to `t1`, then `tx shield` | Transparent UTXO appears in Case A via raw blocks (no address index); shield sweeps it; balances reconcile |
| 4 | 3-block reorg (`invalidateblock` on the node, mine 4) | Daemon detects via tip-hash mismatch, `truncate_to_height(f)`, rescans; balances reconcile; reorged-out tx is unmined and later re-mined |
| 5 | Prune race: stop daemon, mine 300 (> `tx_retention`), start | Key enters `Backfilling` with `via_tor = false`, handoff validation at `retained_from + 10` passes, state ends `Synced` |
| 6 | Prune race with fallback disabled | Key enters `Stalled(PrunedPastScanTip)`; `sync wait` exits 7; `daemon status` names the fix |
| 7 | Restore from mnemonic with birthday below `retained_from` | Full backfill over `zaino`; balance equals the original key's; `GetSubtreeRoots` roots equal `z_getsubtreesbyindex` |
| 8 | Handoff validation failure (zaino fixture that omits one output) | `Stalled(UntrustedBackfill)`, key truncated to birthday, endpoint marked untrusted in `daemon status`, no further requests to the endpoint |
| 9 | ZIP 320 send to `textest1…` with mempool chaining | Both txids returned, both in the next block, `tex_queue` row ends `step2_mined`, exchange-side key sees a transparent payment of exactly `amount` |
| 10 | ZIP 320 with node restart between Step 1 and Step 2 broadcast | Step 2 gets `MissingOutput`, row stays `step1_broadcast`, queue rebroadcasts Step 1 then Step 2 after restart, ends `step2_mined` |
| 11 | ZIP 320 with Step 1 mined and Step 2 expired (mine past expiry with Step 2 held back) | Row ends `step2_failed`; `tx resume` builds a new Step 2 through a fresh session; funds arrive at recipient |
| 12 | Crash-restart with a pending `tex_queue` row (SIGKILL the daemon after Step 1 broadcast) | On restart the queue finishes without re-signing; raw bytes unchanged |
| 13 | Air-gapped PCZT round trip (`create` online → `prove`/`sign` on a `signer-only` profile with `--airgapped` → `broadcast` online) | Verifier passes; tampered file (one output value changed) is refused with exit 6 |
| 14 | Non-interactive send with locked vault (`stdin` not a TTY) | Exit 4 within 1 s, no prompt, JSON carries `reason = VAULT_LOCKED`; `--passphrase-fd` variant succeeds |
| 15 | Network mismatch: `gyges -n testnet balance` against a regtest daemon | Exit 6 before any RPC other than `GetInfo` |
| 16 | `daemon stop` mid-scan | WAL checkpointed, `scanned_tip` at a batch boundary, restart resumes without rescanning scanned blocks |
| 17 | Multi-key cache sharing: three keys, one node | Node `getblock` call count equals block count, not 3× (counted via a proxy in the harness) |
| 18 | Log redaction sweep (§5) | No address, memo, amount or txid used in scenarios 1–13 appears in `gygesd.log` at `info` |

Scenarios 9–12 are tagged `tex`, 13 `airgap`, 5–8 `backfill`, so a subset can be run locally.

---

## 4. Keystone Without Hardware

Keystone transport is QR in both directions, so tests replay recorded UR payloads captured once from a real Keystone 3 Pro (Cypherpunk firmware) and committed under `tests/regtest/fixtures/keystone/`:

| Fixture | Content |
|---|---|
| `accounts.ur` | `ur:zcash-accounts` export (tag 49201) for a known test seed |
| `batch_request.ur` / `batch_result.ur` | `zcash-sign-batch` (49205) sent for a 2-action Orchard spend and the `zcash-batch-sig-result` (49207) returned |
| `pczt_request.ur` / `pczt_result.ur` | single-PCZT flow (49204) for a transaction with a transparent input |
| `firmware_old.ur` | accounts export with `device_version` below the minimum, expected to be refused |

The test seed's `UnifiedSpendingKey` is also known, so each recorded signature is checked against a locally computed one; a fixture that fails this check is a corrupted recording, not a code bug.

Unit tests in `gyges-qr`:

- `registry_tags`: asserts the seven constants from `ur-registry` (`49201`, `49202`, `49203`, `49204`, `49205`, `49206`, `49207`) so a registry change fails CI.
- fountain round trip: encode a 12 KiB PCZT as `ur:zcash-pczt` frames at several frame sizes, shuffle and drop 20 % of frames, decode, compare bytes.
- Redactor: the redacted PCZT contains no proof, witness or `proprietary` bytes and every output value, recipient and memo of the original.

The `CompleteKeystoneSign` path is tested in-process by feeding `batch_result.ur` to the daemon against the matching stored session, and by feeding it to a *different* session to assert the `request_id` mismatch is refused.

---

## 5. Log Redaction

Scenario 18 is the enforcement; the mechanism is tested at three levels:

1. **Type level:** `Sensitive<T>` `Debug`/`Display` print `[redacted]`; a compile-fail test (`trybuild`) shows that `UnifiedSpendingKey`, `Mnemonic` and `SecretBox` cannot be formatted with `{:?}` under the workspace clippy configuration (`disallowed_methods` / `missing_debug_implementations` denied for key types).
2. **Subscriber level:** a unit test installs the production `tracing` layer stack, emits events with every sensitive field type, and asserts the rendered lines.
3. **System level:** after scenarios 1–13 the harness greps `gygesd.log` and `audit.log` for every address, memo, amount (as decimal and zatoshi) and txid the scenarios used. `audit.log` may contain key ids and session ids only.

---

## 6. Property and Migration Tests

- **PCZT pipeline** (`gyges-core`, `proptest`): for random proposals over a fixture wallet, `create → prove → sign → combine(proven, signed) → verify → extract` yields a transaction whose effects equal the proposal; `combine` of structurally different PCZTs is rejected; `verify` rejects any single-field mutation of outputs, fee or anchor.
- **Amount grammar** (`gyges-cli`): `"1.25"`, `"125000000z"`, `"max"` parse; round-trips `Zatoshis → String → Zatoshis`; more than eight decimals, negative values and overflow are rejected. Shared by `tx send`, `pczt create` and `tx shield --threshold`.
- **Config:** `config.toml` with every key set and with none set deserialise to the documented defaults; an unknown key is an error.
- **Migrations:** `tests/regtest/fixtures/schema/` keeps one `wallet.sqlite` and one `profile.json` from every released version; a test opens each with the current daemon and asserts the migration chain runs to the current version and balances are unchanged.
- **Exit codes:** a table-driven test maps every `GygesError.reason` to its documented exit code and fails if a new enum variant has no row.

---

## 7. CI

Every pull request (all must pass to merge):

| Job | Command |
|---|---|
| build | `cargo build --locked --workspace` |
| lint | `cargo clippy --locked --workspace --all-targets -- -D warnings` and `cargo fmt --check` |
| test | `cargo test --locked --workspace` |
| deny | `cargo deny check` (advisories, licenses, bans, sources) |
| regtest | `cargo test --locked -p gyges-regtest` with the pinned `zakurad` and `zaino` from a cached layer (the node-free daemon scenarios already run inside `test`) |
| docs | `cargo doc --no-deps` with `-D warnings` |

Nightly:

| Job | Purpose |
|---|---|
| audit | `cargo audit` against the day's advisory database |
| tor | regtest scenarios 5–8 with `use_tor = true` through a local Tor test network |
| msrv | build on the `rust-version` from `Cargo.toml` (currently 1.97, dictated by the Zakura crates) |

Release tags additionally run the Tier 1 build matrix (Linux x86_64 and aarch64, macOS aarch64), `SHA256SUMS`, `minisign` signatures and GitHub artifact attestation (Q-O5).

---

## 8. Running Locally

The first two commands work today (the second runs the daemon-only scenarios); the rest are planned.

```bash
cargo test --workspace
```

```bash
cargo test -p gyges-regtest -- --test-threads=1
```

```bash
GYGES_TEST_KEEP=1 cargo test -p gyges-regtest tex -- --nocapture
```

```bash
cargo test -p gyges-regtest --features tor -- backfill
```

The regtest crate downloads `zakurad` and `zaino` into `target/regtest-bin/` on first use, keyed by the versions in `tests/regtest/versions.toml` (planned). Setting `ZAKURAD_BIN` and `ZAINO_BIN` skips the download.
