# Gyges Testing Strategy (`TESTING.md`)

How Gyges is tested, from unit tests to a nightly run through a real Tor network. Derived from the Q-O1, Q-O2 and Q-O5 proposals in `OVERVIEW.md`. Most of what it describes exists (§2 says what runs today); what does not is marked planned where it matters: the Tor tier (M2, deferred: see §1), the Keystone fixtures (M5), the migration fixtures and the benchmarks (M6).

---

## 1. Test Tiers

| Tier | Where | Runs on | Needs | Blocks merge |
|---|---|---|---|---|
| Unit | `#[cfg(test)]` in each crate | every PR | nothing | yes |
| Crate integration | `crates/*/tests/` | every PR | in-process SQLite, recorded fixtures | yes |
| Regtest end-to-end | `tests/regtest/` | every PR | pinned `zakurad` and `zainod` (`versions.toml`); no Tor | yes |
| Nightly Tor | same scenarios, `use_tor = true` against a local Tor test network | nightly | `chutney`-style test network | no (opens an issue on failure) |
| Benchmarks | `crates/gyges-core/benches/` (planned, Criterion) | manual and on release tags | release build with `perf` | no |

---

## 2. Regtest Harness (`tests/regtest/`)

**Status:** the crate exists and the real node is wired in. `harness/lib.rs` runs `gygesd` and `gyges` against a temporary `GYGES_HOME` (building both binaries once per test process so they are never stale); `harness/node.rs` runs the `zakurad` pinned in `versions.toml` (downloaded into `target/regtest-bin/` and checked against its sha256 on Linux, `ZAKURAD_BIN` elsewhere, otherwise the node scenarios skip with a message) in regtest from a temporary directory and drives it over JSON-RPC (`generate`, `invalidateblock`, `getrawtransaction`, `sendrawtransaction`, a restart that waits for the node's non-finalized backup first); `scenarios/node.rs` runs rows 1–4 and the real-node halves of rows 9, 10 and 12 of §3 against it (see the table). `harness/zaino.rs` adds the archival endpoint: `Fallback` runs the pruned node, an archive-mode node that receives every block by `submitblock`, and `zainod` (pinned in `versions.toml` as a crates.io `.crate` with its sha256 and built with `cargo install --locked` on Linux when `GYGES_BUILD_ZAINOD` is set, as in the CI `regtest` job; `ZAINOD_BIN` elsewhere, otherwise the backfill scenarios skip) in front of the archive node, restarted with it because zaino keeps the node's old cookie (`OVERVIEW.md` §4.5); `scenarios/backfill.rs` runs against it. `scenarios/daemon.rs` covers the daemon lifecycle, the handshake and the permission and single-instance refusals; `scenarios/keys.rs` covers `key list / init / restore / unlock / lock / export-ufvk / export-seed` without a node (scripted `--json` init on an air-gapped daemon, restore from stdin at the default birthday, the exit-4 and exit-7 refusals, the permission re-check on restart, a log grep for the passphrase and mnemonic, the rate-limited wrong passphrase, the daemon-scoped unlock window in `key list`, and the terminal-only rule of `export-seed`). Everything else runs against `gyges_chain::testing::FakeNode` (feature `test-util`), an in-process `zakurad` stand-in serving `getblockchaininfo`, `getblockhash`, `getblock` (verbosity 0 and 1) and `z_gettreestate` with the shapes recorded in `OVERVIEW.md` §4.3, over synthetic transparent-only blocks that `Block::read` accepts; it can prune, rotate its cookie, reorg and report tree sizes. `gyges-chain`'s tests and `gygesd`'s `tests/rpc.rs` run the real `ZakuraRpcBackend` against it (bounds, hashes, tree states, compact blocks with transparent outputs, cookie failures, wrong chain, `key init` taking its birthday from the live tip, cache creation and checkpoint), and the `SyncScheduler` through it (a new key scanned to the tip, a transparent payment credited from a raw block, a two-block reorg detected and rewound, `RunSync` rewind, the prune-race stall and its recovery, `Stalled(Offline)` after `daemon.offline_grace`). `scenarios/sync.rs` drives the same fake node from the harness with the binaries: `sync status` / `sync wait` / `sync run --from` including the exit-4 confirmation and the exit-7 stall and timeout (rows 4–6 of §3 in miniature; row 4 also runs against the real node in `scenarios/node.rs`, rows 5 and 6 also against the real node and `zainod` in `scenarios/backfill.rs`). The fake node also has a mempool (`sendrawtransaction`, drained by the next mined block, with a switch to refuse broadcasts) and keeps the Sapling, Orchard and Ironwood commitment trees so that `getblock(h, 1).trees` and `z_gettreestate` match what it mined; `tests/rpc.rs` runs the transaction engine through it (fund a transparent receiver, `ShieldFunds` under a daemon unlock, an Ironwood self-send through the passphrase session with a wrong passphrase and the rate limit on the way, `NODE_REJECTED`, an aborted session, `max` to a transparent address, and the balance after every step), and `scenarios/tx.rs` does rows 1–3 and 14 in miniature with the binaries (`balance`, `tx send --dry-run --json`, exit 4/5/6 refusals, `tx shield` with `GYGES_PASSPHRASE_FILE`, `sync wait --txid`). The archival endpoint has a stand-in of the same kind: `gyges_chain::testing::FakeLightwalletd`, an in-process `CompactTxStreamer` gRPC server (its server side generated by `gyges-chain`'s `build.rs` from `proto/service.proto` onto the upstream message types, so `protoc` is needed with `test-util` as it is for `gyges-proto`) serving `GetLightdInfo`, `GetLatestBlock`, `GetBlock`, `GetBlockRange`, `GetTreeState`, `GetSubtreeRoots` and `SendTransaction` from a snapshot of a `FakeNode`'s chain (compact blocks without the transparent fields, the tree state at every height) or from blocks a test hands it, with switches to omit a block, serve a fork from a height, hang a stream after *n* blocks, serve configured subtree roots per pool and refuse broadcasts. `gyges-chain`'s `lwd` tests run `ArtiTorLwdBackend` against it with `use_tor = false` (streaming into the cache in `fetch_batch` chunks tagged `tor-lwd` and equal to the node route's blocks, a skipped block, a fork inside a batch and one at the batch's start that `fill_cache` refuses without caching, a hung stream timing out and the reconnect after it, the subtree roots of every pool with their upstream conversions, the wrong chain, an unreachable endpoint, a broadcast and a refused one); `FakeNode` answers `z_getsubtreesbyindex` from configured roots for the node side of the same trait method. The Tor transport is only exercised up to its bootstrap (a directory that cannot be created fails with `TorState::Failed`); the bootstrap itself is the nightly tier (§1).

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

- **Node:** the `zakurad` release pinned in `versions.toml`, downloaded by tag and verified, started in regtest with proof of work disabled, every upgrade through NU6.3 at height 1 (a regtest node activates only Canopy unless `[network.testnet_parameters.activation_heights]` says otherwise), a zero-value lockbox disbursement (the NU6.1 activation block must pay one), cookie authentication and `state.storage_mode.pruned.tx_retention = 1001`, the smallest the node accepts on regtest (`MAX_BLOCK_REORG_HEIGHT + 1`; the 200 of the original plan is refused), and since the node counts the window from its finalized tip (1,000 blocks deep), it prunes block 1 only at tip 2,002, so Case B needs some 2,100 blocks to exercise (`OVERVIEW.md` §4.5). Blocks are produced with the `generate` RPC (instant). Coinbases to a transparent address need 100 blocks of maturity before the wallet may spend them, so the harness mines a few blocks to the wallet's own address, then restarts the node with Zakura's default regtest miner address and mines a hundred more; the restart waits for the node's non-finalized block backup (written at most every five seconds, never at shutdown) or the blocks would be lost, and starts the node again (up to four times) when zakurad 1.6.0 dies with `genesis apply handoff failed: illegal sync lifecycle transition`, a startup race over a restored backup seen on about one CI run in three.
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
| 1 | `key init` → mine → receive to `u1` → `balance` | Orchard balance equals funded amount after `sync wait --until spendable`; `notes` shows witness ready. *Done against `zakurad` (`scenarios/node.rs`), with a twist: the coinbase is mined to the wallet's transparent address (shielded coinbase would change the commitment trees in every re-mined block and break row 4), restored from a fixed mnemonic so the address is known before the key exists; the transparent balance equals the coinbases' `valueDeltaZat`, then `tx shield` moves it to Ironwood. `notes` is implemented: the real-node scenario lists the second key's note by pool, value and txid (`gyges notes --json`, row 2's payment), and `witness_ready` is asserted against the fake node (`rpc.rs::addresses_notes_and_history_through_the_fake_node`, `scenarios/tx.rs::addresses_notes_and_history_through_the_binaries`); the real node does not check it.* |
| 2 | `tx send` to `u1` (inline unlock) | Recipient key sees the note; sender fee equals ZIP 317 computed by `--dry-run`; `audit.log` has `unlock`, `broadcast` entries and nothing else. *Done: a second key born at the tip is paid 1 ZEC at its default unified address (derived from `key init --json`'s UFVK) and sees exactly that in Ironwood; the audit log carries three `broadcast` events and the session events of the passphrase path (`GYGES_PASSPHRASE_FILE`), no `unlock`.* |
| 3 | `tx send` to `t1`, then `tx shield` | Transparent UTXO appears in Case A via raw blocks (no address index); shield sweeps it; balances reconcile. *Done (shield first from the coinbases, then 0.5 ZEC to the wallet's own `t1`).* |
| 4 | 3-block reorg (`invalidateblock` on the node, mine 4) | Daemon detects via tip-hash mismatch, `truncate_to_height(f)`, rescans; balances reconcile; reorged-out tx is unmined and later re-mined. *Done: the three blocks holding the shield, the `u1` payment and the `t1` payment are invalidated, four mined, and the harness re-mines the three transactions in dependency order (the node does not return them to its mempool; each later one needs the earlier one's anchor back in the chain); both keys end at the new tip with the balances of before, and the recipient key, born in a reorged block, is reset to the node's tree state at the fork (SYNC.md §4.3) because it has nothing to truncate to.* |
| 5 | Prune race: stop daemon, mine past the node's pruning depth (`tx_retention` + 1,000 on regtest), start | Key enters `Backfilling` with `via_tor = false`, handoff validation at `retained_from + 10` passes, state ends `Synced`. *Fake-node half done in-process (`gygesd/tests/rpc.rs::node_pruning_past_the_scan_tip_mid_scan_falls_back_and_recovers`): the fake node prunes past the key after one batch of a scan (not stop, mine 300, start), the endpoint is a `FakeLightwalletd` reached directly (`no_tor`), the key ends spendable at the tip on the node backend, the endpoint was asked for `GetBlockRange` and `GetInfo` shows it `Verified`. The `Backfilling` state itself is not asserted. Real-node half done (`scenarios/backfill.rs::prune_race_stalls_without_a_fallback_then_backfills_through_zaino`, against a pruned `zakurad`, an archive node and `zainod`, ROADMAP.md M2 sixth item): the daemon is stopped, 2,199 blocks are mined (the node prunes about 2,000 deep, `OVERVIEW.md` §4.5) and the daemon restarted with zaino configured; both keys backfill and end synced on the node backend, `daemon status` shows `trust: verified`, and the second key holds a payment mined in a block the node has pruned.* |
| 6 | Prune race with fallback disabled | Key enters `Stalled(PrunedPastScanTip)`; `sync wait` exits 7; `daemon status` names the fix. *Fake-node half done, through the binaries (`scenarios/sync.rs::a_new_key_syncs_to_the_tip_and_sync_wait_follows_new_blocks`: the fake node prunes past the key, `sync wait` exits 7 with `pruned-past-scan-tip`, `sync status` prints `stalled(pruned-past-scan-tip)` and "node pruned past key 'main'") and in-process (`rpc.rs::scheduler_scans_to_the_tip_credits_transparent_outputs_and_survives_a_reorg`: `StallReason::PrunedPastScanTip`, "retains from 18"). Real-node half done in the same scenario as row 5 (`scenarios/backfill.rs::prune_race_stalls_without_a_fallback_then_backfills_through_zaino`): before zaino is configured, both keys stall with `pruned-past-scan-tip`, `sync wait` exits 7, and `sync status` names each key.* |
| 7 | Restore from mnemonic with birthday below `retained_from` | Full backfill over `zaino`; balance equals the original key's; `GetSubtreeRoots` roots equal `z_getsubtreesbyindex`. *Fake-node half done against a `FakeLightwalletd`, not `zaino`: in-process (`gygesd/tests/rpc.rs::restore_below_the_window_backfills_from_the_fallback_and_a_wrong_root_is_refused`: the restore backfills from the endpoint, the handoff validates at `retained_from + k` against the node's tree sizes and subtree roots, the note below the window is found, the endpoint is `Verified`, `GetBlockRange`, `GetTreeState` and `GetSubtreeRoots` were called, and the endpoint's blocks are evicted afterwards) and through the binaries with the consent prompt (`scenarios/sync.rs::restore_below_the_window_asks_consent_warns_and_backfills`). The transparent half is `rpc.rs::restore_below_the_window_recovers_transparent_outputs_and_discards_fabricated_ones`. Real-node half done (`scenarios/backfill.rs::prune_race_stalls_without_a_fallback_then_backfills_through_zaino`): a second daemon restores the funded mnemonic at birthday 1 with `--yes`, prints the backfill note and the best-effort warning, backfills from `zainod` and ends with the original key's pools. The subtree-root comparison runs but is empty on both sides: no subtree completes on a chain this size. Running it found that the default birthday skipped the below-window path entirely; fixed in `gyges_core::birthday::resolve`.* |
| 8 | Handoff validation failure (zaino fixture that omits one output) | `Stalled(UntrustedBackfill)`, key truncated to birthday, endpoint marked untrusted in `daemon status`, no further requests to the endpoint. *Fake-node half done in-process, with a lying endpoint of two kinds instead of one that omits an output (an omitted shielded output changes the commitment tree, so it surfaces as the wrong root; an omitted transparent output is undetectable by design, Q-Y5). `rpc.rs::restore_below_the_window_backfills_from_the_fallback_and_a_wrong_root_is_refused`: one commitment changed with hashes and sizes intact, refused at the handoff, the key stalls and the endpoint is untrusted. `rpc.rs::a_fallback_serving_a_fork_is_refused_and_marked_untrusted`: the hash-chain check, the key stalls with `FallbackUntrusted` at a `scanned_tip` below 25, `GetInfo` shows `Untrusted`, `fallback_trust.json` is written and a later restore below the window is refused with `FALLBACK_UNAVAILABLE`. `lwd::tests::a_skipped_forked_or_overlong_stream_is_refused` covers a skipped block at the backend. `rpc.rs::a_fallback_whose_tree_state_the_wallet_refuses_is_marked_untrusted`: the node's blocks with a forged Ironwood frontier (same size, other leaves) at the batch boundaries below the window, so the wallet's ShardTree refuses the next batch; the key stalls with `FallbackUntrusted` (not a wallet error retried each tick), `GetInfo` shows `Untrusted`, `fallback_trust.json` is written, the wallet is truncated to `birthday - 1`, the cache holds no `tor-lwd` rows and the endpoint gets no further `GetBlockRange`. Not asserted: that the key is truncated to its birthday and that the endpoint receives no further requests. Fake-only by design: a real `zaino` serves the node's chain faithfully, so a lying endpoint exists only as `FakeLightwalletd`.* |
| 9 | ZIP 320 send to `textest1…` with mempool chaining | Both txids returned, both in the next block, `tex_queue` row ends `step2_mined`, exchange-side key sees a transparent payment of exactly `amount`. *Done against `zakurad` (`scenarios/node.rs::zip320_against_the_real_node`): the recipient is the wallet's own pubkey hash as a `texregtest1` address, so the payment comes back as transparent balance of exactly the amount (and, being spendable, may fund the next payment's step 1 in place of shielded notes, so the final check is on the total minus fees); also in-process against the fake node (`gygesd/tests/rpc.rs::zip320_sends_through_the_fake_node`), where step 2 is decoded from its block: one input spending step 1, one output of the amount to the hash.* |
| 10 | ZIP 320 with node restart between Step 1 and Step 2 broadcast | Step 2 gets `MissingOutput`, row stays `step1_broadcast`, queue rebroadcasts Step 1 then Step 2 after restart, ends `step2_mined`. *Done in two halves: the fake node's `set_reject_transparent_only` plays a node that refuses step 2 while step 1 is unmined (row stays `step1_broadcast` with the node's text, `step1_mined` once mined, step 2 in once accepted; in-process and through the binaries); the real node is restarted after both steps were accepted, which empties its mempool, and the queue puts both back with unchanged txids.* |
| 11 | ZIP 320 with Step 1 mined and Step 2 expired (mine past expiry with Step 2 held back) | Row ends `step2_failed`; `tx resume` builds a new Step 2 through a fresh session; funds arrive at recipient. *Done in-process against the fake node (step 2 held back by `set_reject_transparent_only`, mined past the expiry, `ResumeTexTransfer` → `SIGNATURE_REQUIRED` → `UnlockKey { session_id }` → a new step 2 with a later expiry, mined with the amount at the recipient). Not on the real node: nothing holds step 2 back there.* |
| 12 | Crash-restart with a pending `tex_queue` row (SIGKILL the daemon after Step 1 broadcast) | On restart the queue finishes without re-signing; raw bytes unchanged. *Done through the binaries against the fake node (`scenarios/tx.rs::zip320_send_survives_a_daemon_crash`: SIGKILL with step 2 refused, step 1 mined while the daemon is down, the restarted queue broadcasts step 2 with the same txid, no passphrase in play) and on the real node together with row 10.* |
| 13 | Air-gapped PCZT round trip (`create` online → `prove`/`sign` on a `signer-only` profile with `--airgapped` → `broadcast` online) | Verifier passes; tampered file (one output value changed) is refused with exit 6. *Online half done against the fake node (`scenarios/pczt.rs::pczt_pipeline_over_files_and_pipes_through_the_binaries`, and in-process `gygesd/tests/rpc.rs::pczt_pipeline_round_trips_and_the_verifier_refuses_a_tampered_file`): `create -o` / `prove -o` / `sign -o` / `broadcast` over files with a daemon restart in between, then `create \| prove \| sign \| broadcast` over a pipe; the tampered file is the created one with the payment's varint changed by one zatoshi, which `inspect` shows and `broadcast` refuses with exit 6 after `prove` and `sign` went through. Air-gapped half done against the fake node (`scenarios/pczt.rs::airgapped_signer_only_daemon_signs_a_transparent_funded_file`, and in-process `rpc.rs::an_airgapped_signer_only_daemon_signs_transparent_inputs`): the `--airgapped` daemon makes the seed, the online daemon restores it, a transparent-funded file is created online, proven and signed on the `signer-only` key (no `wallet.sqlite`), and broadcast online; a file whose inputs name another seed is refused by the offline signer.* |
| 14 | Non-interactive send with locked vault (`stdin` not a TTY) | Exit 4 within 1 s, no prompt, JSON carries `reason = VAULT_LOCKED`; `--passphrase-fd` variant succeeds |
| 15 | Network mismatch: `gyges -n testnet balance` against a regtest daemon | Exit 6 before any RPC other than `GetInfo`. *Done (`scenarios/daemon.rs::network_mismatch_exits_6_before_any_other_rpc`: `-n testnet` against a regtest daemon exits 6 naming both networks, and with `--json` carries `ERROR_REASON_NETWORK_MISMATCH`; the command is `daemon status`, not `balance`, and "no other RPC" rests on the CLI's handshake, whose check is `gyges-cli` `client::tests::network_checked_only_when_given`).* |
| 16 | `daemon stop` mid-scan | WAL checkpointed, `scanned_tip` at a batch boundary, restart resumes without rescanning scanned blocks. *Done in-process against the fake node (`gygesd/tests/rpc.rs::daemon_stop_mid_scan_finishes_the_batch_and_restart_does_not_rescan`). `FakeNode::hold_after_raw_blocks` holds the scheduler's next fetch, so the stop lands inside a batch. Shutdown waits for that batch, and exactly one more batch is committed after the stop is asked for. The wallet's `block_max_scanned` equals the end of the last logged "batch scanned" range, so no batch was cut off between its commit and its log line. The cache WAL is empty. After a restart on the same home, the key reaches the tip with no range overlapping one scanned before the stop. "A batch boundary" is the end of a logged batch, not a multiple of `scan_batch`: upstream's scan ranges are priority-ordered.* |
| 17 | Multi-key cache sharing: three keys, one node | Node `getblock` call count equals block count, not 3× (counted via a proxy in the harness). *Done in-process (`gygesd/tests/rpc.rs::three_keys_fetch_each_block_from_the_node_once`), counted by the fake node's own call log instead of a proxy: three keys restored at birthday 1 over a 60-block chain cost exactly 120 `getblock` calls. A block is two calls (verbosity 0 for the body, 1 for the tree sizes), so "equals block count" means twice the block count.* |
| 18 | Log redaction sweep (§5) | No address, memo, amount or txid used in scenarios 1–13 appears in `gygesd.log` at `info`. *Partly done, by §5 level 3: the sweep (`sweep_logs` in `scenarios/node.rs`, the same loop inline in `scenarios/tx.rs`) runs over the real-node rows 1–4 (`restore_mine_shield_send_and_reorg_against_the_real_node`) and 9, 10 and 12 (`zip320_against_the_real_node`), and over the fake-node sends (`scenarios/tx.rs::balance_send_and_shield_through_the_binaries`, `zip320_send_survives_a_daemon_crash`, `addresses_notes_and_history_through_the_binaries`). Also swept: rows 5–7 on the real node (`scenarios/backfill.rs::prune_race_stalls_without_a_fallback_then_backfills_through_zaino`, both daemons). Not swept: rows 8, 11 and 13 (the PCZT scenarios in `scenarios/pczt.rs` read no log).* |

Scenarios 9–12 are tagged `tex`, 13 `airgap`, 5–8 `backfill`, so a subset can be run locally. (The tag filters are not implemented; the real-node rows 5–7 are their own test target, `cargo test -p gyges-regtest --test backfill` with `ZAKURAD_BIN` and `ZAINOD_BIN` set; the ZIP 320 tests all have `zip320` in their names, so `cargo test -p gyges-regtest zip320` and `cargo test -p gygesd zip320` run them, the real-node one with `ZAKURAD_BIN` set.)

---

## 4. Keystone Without Hardware

Keystone transport is QR in both directions, so tests replay recorded UR payloads captured once from a real Keystone 3 Pro (Cypherpunk firmware) and committed under `tests/regtest/fixtures/keystone/`:

| Fixture | Content |
|---|---|
| `accounts.ur` | `ur:zcash-accounts` export (tag 49201) for a known test seed |
| `batch_request.ur` / `batch_result.ur` | `zcash-sign-batch` (49205) sent for a 2-action Orchard spend and the `zcash-batch-sig-result` (49207) returned |
| `pczt_request.ur` / `pczt_result.ur` | single-PCZT flow (49204) for a transaction with a transparent input |
| `firmware_old.ur` | accounts export with `device_version` below the minimum, expected to be refused. *Covered synthetically until a recording exists (ROADMAP.md M5, second item): `rpc.rs::keystone_import_refusals_and_account_choice` builds exports of the abandon mnemonic with `gyges-qr` (13.0.1, none, two accounts over several frames, a mainnet UFVK, a 16-byte fingerprint).* |

The test seed's `UnifiedSpendingKey` is also known, so each recorded signature is checked against a locally computed one; a fixture that fails this check is a corrupted recording, not a code bug.

Unit tests in `gyges-qr`:

- `registry_tags`: asserts the seven constants from `ur-registry` (`49201`, `49202`, `49203`, `49204`, `49205`, `49206`, `49207`) so a registry change fails CI.
- fountain round trip: encode a 12 KiB PCZT as `ur:zcash-pczt` frames at several frame sizes, shuffle and drop 20 % of frames, decode, compare bytes.

*Done (ROADMAP.md M5, first item):* both, as `tests::registry_tags_are_stable` / `registry_tags_match_ur_registry` and `fountain::tests::fountain_round_trip_survives_shuffling_and_loss` (fragment sizes 100, 200 and 400; any fragments still missing after the loss are filled from fresh fountain parts, as a camera's next loop would). Also there: every registry type through CBOR, frames and back; `ur-registry`'s own `zcash-accounts` CBOR vector; single-frame payloads, uppercase frames, mixed types and malformed frames; the half-block renderer's shape and its alphanumeric mode for `ur:` frames; the animation's redraw. Until a device is available, these synthetic round trips stand in for the recorded fixtures above; they check the framing and the codecs, not what a real device sends.

The Redactor test belongs to the signing protocols (M5, third item) in `gygesd`, since `gyges-qr` has no PCZT dependency: the redacted PCZT contains no proof, witness or `proprietary` bytes and every output value, recipient and memo of the original.

The `CompleteKeystoneSign` path is tested in-process by feeding `batch_result.ur` to the daemon against the matching stored session, and by feeding it to a *different* session to assert the `request_id` mismatch is refused.

---

## 5. Log Redaction

Scenario 18 is the enforcement; the mechanism is tested at three levels:

1. **Type level:** `gyges_core::log::Sensitive<T>` `Debug`/`Display` print `[redacted]` (`log::tests`, including a derived `Debug` on a container and width/padding specifiers). *Not done:* the planned `trybuild` compile-fail test that `UnifiedSpendingKey`, `Mnemonic` and `SecretBox` cannot be formatted; those types derive `Debug` upstream and no clippy configuration can deny a derive in another crate, so this is enforced by review.
2. **Subscriber level:** `gygesd::logs::tests` install the production layer stack (`gygesd::logs::layers`, the same function `main` uses) over in-memory writers, emit events with `%Sensitive` and `?Sensitive` fields and assert the rendered main-log lines, the `audit.log` JSON lines (keys, independence from the configured level) and the `StreamLogs` entries (replay, `min_level`, a follower joining during a replay).
3. **System level:** `scenarios/tx.rs` runs the fake-node send and then sweeps every file in `logs/` and both `gyges daemon logs` streams for the recipient address, the txid, the amounts (as zatoshis and decimal) and the passphrase, parses `audit.log` line by line (allowed keys: `timestamp`, `level`, `event`, `key_id`, `scope`, `via`, `from`) and checks the event order of a passphrase-session send; `scenarios/keys.rs` greps for the passphrase and every mnemonic word. `scenarios/node.rs` runs the same sweep against the real node over scenarios 1–4 and 9, 10 and 12 (the other rows are not swept; see §3 row 18).

---

## 6. Property and Migration Tests

- **PCZT pipeline** (`proptest`): for random proposals over a fixture wallet, `create → prove → sign → combine(proven, signed) → verify → extract` yields a transaction whose effects equal the proposal; `combine` of structurally different PCZTs is rejected; `verify` rejects any single-field mutation of outputs, fee or anchor. *Partly done (ROADMAP.md M4, third item):* `gygesd/tests/rpc.rs::redirected_change_is_refused_at_sign_and_at_broadcast` builds one transparent-funded PCZT through the daemon and runs 24 cases of random mutations of the proven file against `SignPczt` (the change to another key's Orchard address at a random index and scope, the change value, the payment script under its label) and 48 of the signed file against `BroadcastPczt` (also the payment and input values), each refused with `INVALID_ARGUMENT` and the expected reason and none reaching the node; a targeted case swaps the change action's `cmx` under its unchanged address, which the note commitment check refuses. Random proposals and `combine` are not covered: each proposal needs a funded wallet and proving, which this tier keeps to one.
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
| tor | regtest scenarios 5–8 with `use_tor = true` through a local Tor test network. *Deferred (ROADMAP.md M2, last item, step 4): upstream's `tor::Client` builds its arti config from a data directory only, so it cannot be given a test network's directory authorities.* |
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
ZAKURAD_BIN=/path/to/zakurad ZAINOD_BIN=/path/to/zainod cargo test -p gyges-regtest --test backfill -- --nocapture
```

The regtest crate downloads `zakurad` into `target/regtest-bin/` on first use, keyed by the versions in `tests/regtest/versions.toml`; Zakura publishes Linux x86_64 and aarch64 binaries only. `zainod` is built there from its pinned `.crate` on Linux when `GYGES_BUILD_ZAINOD=1`. Setting `ZAKURAD_BIN` (and `ZAINOD_BIN`) skips the download and the build.
