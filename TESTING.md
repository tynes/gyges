# Gyges Testing Strategy (`TESTING.md`)

How Gyges is tested, from unit tests to a nightly run through a real Tor network. Derived from the Q-O1, Q-O2 and Q-O5 proposals in `OVERVIEW.md`. Most of what it describes exists (§2 says what runs today); what does not is marked planned where it matters: the archival `zaino` and the Tor tier (M2), the Keystone fixtures (M5), the migration fixtures and the benchmarks (M6).

---

## 1. Test Tiers

| Tier | Where | Runs on | Needs | Blocks merge |
|---|---|---|---|---|
| Unit | `#[cfg(test)]` in each crate | every PR | nothing | yes |
| Crate integration | `crates/*/tests/` | every PR | in-process SQLite, recorded fixtures | yes |
| Regtest end-to-end | `tests/regtest/` | every PR | pinned `zakurad` (`versions.toml`); local `zaino` arrives with M2; no Tor | yes |
| Nightly Tor | same scenarios, `use_tor = true` against a local Tor test network | nightly | `chutney`-style test network | no (opens an issue on failure) |
| Benchmarks | `crates/gyges-core/benches/` (planned, Criterion) | manual and on release tags | release build with `perf` | no |

---

## 2. Regtest Harness (`tests/regtest/`)

**Status:** the crate exists and the real node is wired in. `harness/lib.rs` runs `gygesd` and `gyges` against a temporary `GYGES_HOME` (building both binaries once per test process so they are never stale); `harness/node.rs` runs the `zakurad` pinned in `versions.toml` (downloaded into `target/regtest-bin/` and checked against its sha256 on Linux, `ZAKURAD_BIN` elsewhere, otherwise the node scenarios skip with a message) in regtest from a temporary directory and drives it over JSON-RPC (`generate`, `invalidateblock`, `getrawtransaction`, `sendrawtransaction`, a restart that waits for the node's non-finalized backup first); `scenarios/node.rs` runs rows 1–4 of §3 against it (see the table). The archival `zaino` is not wired in (M2). `scenarios/daemon.rs` covers the daemon lifecycle, the handshake and the permission and single-instance refusals; `scenarios/keys.rs` covers `key list / init / restore / unlock / lock / export-ufvk / export-seed` without a node (scripted `--json` init on an air-gapped daemon, restore from stdin at the default birthday, the exit-4 and exit-7 refusals, the permission re-check on restart, a log grep for the passphrase and mnemonic, the rate-limited wrong passphrase, the daemon-scoped unlock window in `key list`, and the terminal-only rule of `export-seed`). Everything else runs against `gyges_chain::testing::FakeNode` (feature `test-util`), an in-process `zakurad` stand-in serving `getblockchaininfo`, `getblockhash`, `getblock` (verbosity 0 and 1) and `z_gettreestate` with the shapes recorded in `OVERVIEW.md` §4.3, over synthetic transparent-only blocks that `Block::read` accepts; it can prune, rotate its cookie, reorg and report tree sizes. `gyges-chain`'s tests and `gygesd`'s `tests/rpc.rs` run the real `ZakuraRpcBackend` against it (bounds, hashes, tree states, compact blocks with transparent outputs, cookie failures, wrong chain, `key init` taking its birthday from the live tip, cache creation and checkpoint), and the `SyncScheduler` through it (a new key scanned to the tip, a transparent payment credited from a raw block, a two-block reorg detected and rewound, `RunSync` rewind, the prune-race stall and its recovery, `Stalled(Offline)` after `daemon.offline_grace`). `scenarios/sync.rs` drives the same fake node from the harness with the binaries: `sync status` / `sync wait` / `sync run --from` including the exit-4 confirmation and the exit-7 stall and timeout (rows 4–6 of §3 in miniature; the real-node versions wait for the harness item). The fake node also has a mempool (`sendrawtransaction`, drained by the next mined block, with a switch to refuse broadcasts) and keeps the Sapling, Orchard and Ironwood commitment trees so that `getblock(h, 1).trees` and `z_gettreestate` match what it mined; `tests/rpc.rs` runs the transaction engine through it (fund a transparent receiver, `ShieldFunds` under a daemon unlock, an Ironwood self-send through the passphrase session with a wrong passphrase and the rate limit on the way, `NODE_REJECTED`, an aborted session, `max` to a transparent address, and the balance after every step), and `scenarios/tx.rs` does rows 1–3 and 14 in miniature with the binaries (`balance`, `tx send --dry-run --json`, exit 4/5/6 refusals, `tx shield` with `GYGES_PASSPHRASE_FILE`, `sync wait --txid`).

### 2.1 Components

```text
tests/regtest/
├── Cargo.toml          # package gyges-regtest; `autotests = false`, one [[test]] per scenario file
├── versions.toml       # the pinned zakurad tag and the sha256 of its Linux release assets
├── harness/lib.rs      # Rust library: the Fixture (gygesd + gyges in a temporary GYGES_HOME)
├── harness/node.rs     # the Node: pinned zakurad in regtest, written zakura.toml, JSON-RPC driver
├── zaino.toml          # (planned, M2) lightwalletd-compatible gRPC against the same node
├── fixtures/           # (planned) Keystone UR recordings (§4), schema fixtures (§6)
└── scenarios/          # one file per group of rows in §3 (daemon, keys, sync, tx against the fake node; node against zakurad)
```

- **Node:** the `zakurad` release pinned in `versions.toml`, downloaded by tag and verified, started in regtest with proof of work disabled, every upgrade through NU6.3 at height 1 (a regtest node activates only Canopy unless `[network.testnet_parameters.activation_heights]` says otherwise), a zero-value lockbox disbursement (the NU6.1 activation block must pay one), cookie authentication and `state.storage_mode.pruned.tx_retention = 1001`, the smallest the node accepts on regtest (`MAX_BLOCK_REORG_HEIGHT + 1`; the 200 of the original plan is refused), so Case B needs a thousand-odd blocks to exercise. Blocks are produced with the `generate` RPC (instant). Coinbases to a transparent address need 100 blocks of maturity before the wallet may spend them, so the harness mines a few blocks to the wallet's own address, then restarts the node with Zakura's default regtest miner address and mines a hundred more; the restart waits for the node's non-finalized block backup (written at most every five seconds, never at shutdown) or the blocks would be lost.
- **Archival source:** `zaino` pointed at the same node, serving `CompactTxStreamer` for the backfill path. It is "archival" by construction because it indexes blocks before the node prunes them.
- **Daemon:** `gygesd` in the foreground with `GYGES_HOME` set to a temporary directory, `network = "regtest"`, `fallback_lightwalletd.use_tor = false` (direct gRPC) in CI. Tor bootstrap is slow and non-deterministic; it belongs to the nightly tier.
- **CLI:** every scenario drives the daemon through the `gyges` binary with `--json`, so the regtest suite doubles as the JSON schema test.

### 2.2 Fixture API

```rust
let Some(mut node) = Node::start_or_skip(NodeOpts { miner_address: wallet_taddr, ..NodeOpts::default() }) else { return };
node.mine(2);                                   // two coinbases to the wallet
node.restart(NodeOpts::default())?;             // then a hundred to nobody, so they mature
node.mine(100);
let mut fx = Fixture::new("regtest");
fx.start_daemon(&["--zakura-rpc", &node.url(), "--zakura-cookie", &node.cookie_path().display().to_string()])?;
let pw = fx.passphrase_file("test");
fx.gyges(&["key", "restore", "--id", "main", "--stdin", "--json"]).env("GYGES_PASSPHRASE_FILE", &pw).stdin(mnemonic).run();
fx.gyges(&["-k", "main", "sync", "wait", "--until", "spendable"]).run();
node.invalidate_block(&node.block_hash(103)); node.mine(4);   // a 3-block reorg
```

`Fixture` and `Node` kill their children on drop and keep their directories when `GYGES_TEST_KEEP=1`. `Node::rpc` is the escape hatch for anything the typed helpers do not cover.

---

## 3. End-to-End Scenarios

Each scenario is one test; the invariant column is what the assertion checks, beyond "exit code 0".

| # | Scenario | Invariant asserted |
|---|---|---|
| 1 | `key init` → mine → receive to `u1` → `balance` | Orchard balance equals funded amount after `sync wait --until spendable`; `notes` shows witness ready. *Done against `zakurad` (`scenarios/node.rs`), with a twist: the coinbase is mined to the wallet's transparent address (shielded coinbase would change the commitment trees in every re-mined block and break row 4), restored from a fixed mnemonic so the address is known before the key exists; the transparent balance equals the coinbases' `valueDeltaZat`, then `tx shield` moves it to Ironwood. `notes` is not implemented.* |
| 2 | `tx send` to `u1` (inline unlock) | Recipient key sees the note; sender fee equals ZIP 317 computed by `--dry-run`; `audit.log` has `unlock`, `broadcast` entries and nothing else. *Done: a second key born at the tip is paid 1 ZEC at its default unified address (derived from `key init --json`'s UFVK) and sees exactly that in Ironwood; the audit log carries three `broadcast` events and the session events of the passphrase path (`GYGES_PASSPHRASE_FILE`), no `unlock`.* |
| 3 | `tx send` to `t1`, then `tx shield` | Transparent UTXO appears in Case A via raw blocks (no address index); shield sweeps it; balances reconcile. *Done (shield first from the coinbases, then 0.5 ZEC to the wallet's own `t1`).* |
| 4 | 3-block reorg (`invalidateblock` on the node, mine 4) | Daemon detects via tip-hash mismatch, `truncate_to_height(f)`, rescans; balances reconcile; reorged-out tx is unmined and later re-mined. *Done: the three blocks holding the shield, the `u1` payment and the `t1` payment are invalidated, four mined, and the harness re-mines the three transactions in dependency order (the node does not return them to its mempool; each later one needs the earlier one's anchor back in the chain); both keys end at the new tip with the balances of before, and the recipient key, born in a reorged block, is reset to the node's tree state at the fork (SYNC.md §4.3) because it has nothing to truncate to.* |
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

1. **Type level:** `gyges_core::log::Sensitive<T>` `Debug`/`Display` print `[redacted]` (`log::tests`, including a derived `Debug` on a container and width/padding specifiers). *Not done:* the planned `trybuild` compile-fail test that `UnifiedSpendingKey`, `Mnemonic` and `SecretBox` cannot be formatted; those types derive `Debug` upstream and no clippy configuration can deny a derive in another crate, so this is enforced by review.
2. **Subscriber level:** `gygesd::logs::tests` install the production layer stack (`gygesd::logs::layers`, the same function `main` uses) over in-memory writers, emit events with `%Sensitive` and `?Sensitive` fields and assert the rendered main-log lines, the `audit.log` JSON lines (keys, independence from the configured level) and the `StreamLogs` entries (replay, `min_level`, a follower joining during a replay).
3. **System level:** `scenarios/tx.rs` runs the fake-node send and then sweeps every file in `logs/` and both `gyges daemon logs` streams for the recipient address, the txid, the amounts (as zatoshis and decimal) and the passphrase, parses `audit.log` line by line (allowed keys: `timestamp`, `level`, `event`, `key_id`, `scope`, `via`, `from`) and checks the event order of a passphrase-session send; `scenarios/keys.rs` greps for the passphrase and every mnemonic word. The real-node version over scenarios 1–13 waits for the harness item.

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
| regtest | `cargo test --locked -p gyges-regtest --test node`: the harness downloads the pinned `zakurad` into `target/regtest-bin/` (cached on the hash of `versions.toml`) and verifies it; the node-free scenarios of the crate already run inside `test`, where the node scenarios skip |
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

The first two commands work today; the node scenarios inside them download the pinned `zakurad` on Linux and skip elsewhere unless `ZAKURAD_BIN` points at one (a source build takes a few minutes: `cargo install --git https://github.com/zakura-core/zakura --tag <tag from versions.toml> --locked zakura`). `GYGES_TEST_KEEP=1` keeps the daemon's home and the node's directory (its `zakurad.log` and `zakura.toml`) for inspection. The tag filters are planned.

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

The regtest crate downloads `zakurad` (and, from M2, `zaino`) into `target/regtest-bin/` on first use, keyed by the versions in `tests/regtest/versions.toml`; Zakura publishes Linux x86_64 and aarch64 binaries only. Setting `ZAKURAD_BIN` (and `ZAINO_BIN`) skips the download.
