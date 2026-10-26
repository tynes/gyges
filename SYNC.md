# Gyges Synchronisation Design (`SYNC.md`)

The per-key sync state machine run by `gygesd`. This document turns the proposals under Q-D1, Q-D4 and Q-Y1…Y6 in `OVERVIEW.md` into one description. Items marked **needs verification** rest on a fact that must be confirmed against the Zakura node or the upstream crates before the code is written.

Upstream library paths use the library target names (`zcash_client_backend`, `zcash_client_sqlite`, `shardtree`), consumed via `package = "zakura-…"` renames; see `Cargo.toml`.

---

## 1. Node Bounds

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

## 2. Block Sources and the Shared Cache

### 2.1 `ChainBackend` as the compact block source

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

### 2.2 `BlockCache` and `BlockFetcher`

One cache per network at `~/.gyges/<network>/cache/blocks.sqlite` (schema in `DATA_MODEL.md` §6) implements the upstream `zcash_client_backend::data_api::chain::BlockCache` trait, so `scan_cached_blocks` reads from it unchanged. Landed as `gyges_chain::cache::BlockDb`: `BlockSource::with_blocks` stops at the first missing height, `BlockCache::read` reports a hole inside the requested range as an error, rows are tagged `source = 'node' | 'tor-lwd'`, and `evict_below` / `evict_source_below` / `checkpoint` are what the fetcher below and the daemon's stop path call. The daemon opens it at start (refusing a file from another network or a newer schema) and checkpoints it on stop.

A single `BlockFetcher` task per daemon:

1. Computes `lo = min(scanned_tip over all keys) + 1`, `hi = tip_height`.
2. Fills `[max(lo, retained_from), hi]` from `ZakuraRpcSource` in batches of `cache.fetch_batch` (default 100) blocks.
3. Fills any sub-`retained_from` range a key needs from the fallback endpoint (`ArtiTorLwdBackend` through `fill_cache`, one `cache.scan_batch` per key per tick), tagging rows `source = 'tor-lwd'` (§5).
4. Evicts a block once every registered key has scanned past it, keeping `cache.retain_blocks` (default 1000) behind the slowest key for cheap rewinds, bounded by `cache.max_mb` (default 2048). With `cache.keep_historical = false` (default) Tor-fetched rows are dropped as soon as the key that requested them has scanned them.

The node is asked for each block once regardless of how many key profiles exist.

---

## 3. Per-Key State Machine

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

**Status (ROADMAP.md M1, M2):** `gyges_core::sync::SyncState` has `Initializing`, `Backfilling { via_tor, from, to }`, `Scanning`, `Rewinding`, `Synced` and `Stalled(PrunedPastScanTip | ChainInconsistent | UntrustedBackfill | FallbackUnreachable | Offline)`. `UntrustedBackfill` carries no endpoint: there is one per daemon, and the endpoint and failed check are in the key's `detail` and in `GetInfo.fallback.trust`. The entry condition is the Case A invariant of §4.2 (`scanned_tip < retained_from`, one block stricter than the table), checked before upstream's queue is consulted, so a restore backfills from its birthday up before the chain-tip range: the wallet's trees are then built in order, which the root check of §5.2 relies on. Without an endpoint (or air-gapped) a broken invariant stalls with `PrunedPastScanTip` and the `daemon status` / `sync status` text above. On the wire `Backfilling` is `SYNC_STATE_VALIDATING_HANDOFF` (the CLI's `backfilling`) with `backend` `SYNC_BACKEND_TOR_LWD_FALLBACK` or `SYNC_BACKEND_DIRECT_LWD_FALLBACK`; `FallbackUnreachable` is `STALL_REASON_FALLBACK_UNREACHABLE`. A stalled key is re-evaluated every tick and leaves `Stalled` by itself once the cause is gone (node back, window widened, `sync run --from`). On the wire `Initializing` and `Synced` are both `SYNC_STATE_IDLE`, told apart by `scanned` / `spendable`; the CLI prints the words above.

---

## 4. Case A Scanning

### 4.1 Steps per batch

1. `update_chain_tip(&mut db, bounds.tip_height)` so the upstream scan-queue logic knows the tip.
2. `suggest_scan_ranges(&db)` returns prioritised ranges (`ChainTip`, `FoundNote`, `Historic`, `Verify`, …). Take the highest-priority range, bounded to `cache.scan_batch` (default 1000) blocks.
3. Ensure the `BlockFetcher` has those heights; wait on its notify if not.
4. `scan_cached_blocks(&params, &cache, &mut db, from, &prior_chain_state, limit)`.
5. On `ScanError::PrevHashMismatch { at_height }` go to §4.2.
6. Repeat until `suggest_scan_ranges` has nothing above `Ignored`.

Subtree roots are refreshed from `z_getsubtreesbyindex` whenever `tip_height` crosses a new 2^16 commitment boundary and passed to `put_sapling_subtree_roots` / `put_orchard_subtree_roots`.

### 4.2 Invariant and prune race

**Invariant:** while in `Scanning`, `scanned_tip + 1 >= retained_from`. The implementation is one block stricter: the next batch starts at `s = scanned_tip + 1` and needs `z_gettreestate(s - 1)` as its prior chain state, which a pruned node serves only for `s - 1 >= retained_from`, so `s - 1 < retained_from` stalls as well (unless `retained_from = 0`).

It is checked before every batch and whenever `getblock` returns the pruned error. On violation:

- if `fallback_lightwalletd.enabled` and the daemon is not air-gapped: switch the key to `Backfilling` for `[scanned_tip + 1, retained_from + k]`, log at `warn`, continue (a `getblock` pruned error or `TreeStateUnavailable` in the middle of a batch only re-polls the bounds; the next tick finds the invariant broken and backfills);
- otherwise `Stalled(PrunedPastScanTip)`; `sync wait` exits 7 and `daemon status` prints: "node pruned past key 'main' (scanned 2,100,000, node retains from 2,105,000); enable `fallback_lightwalletd` or increase the node's `tx_retention`".

The daemon keeps every key at the tip while it runs, so this race only matters after downtime longer than the node's retention window.

### 4.3 Reorg detection and truncation

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

## 5. Case B Backfill and Handoff Validation

### 5.1 Range

A key with `scanned_tip + 1 < retained_from` streams `[scanned_tip + 1, V]` from `TorLwdSource`, where `V = retained_from + k`, `k = 10` (config `fallback_lightwalletd.overlap_blocks`). The overlap exists because a pruned node answers `z_gettreestate` only for heights whose bodies it still has, so validation must happen inside the node's window, not at its edge.

Before streaming, `GetSubtreeRoots` for Sapling and Orchard populate the ShardTree via `put_*_subtree_roots`, so witnesses for notes found during backfill can be completed without every historical block.

The first backfill that a restore needs prompts once in the CLI: "N blocks below the node's retention height must be fetched over Tor from `<url>`; continue? [y/N]" (`--yes` for scripts).

**Status (ROADMAP.md M2, second and third items):** `gygesd::backfill`. `V = min(retained_from + k, tip)`, recomputed every tick from the current bounds, so a node that keeps pruning moves the handoff with it. A *session* opens when a key enters `Backfilling`: check 3 runs first (below), then one `cache.scan_batch` per tick is fetched with `fill_cache` from the endpoint (tagged `tor-lwd`), checked at its last block against `getblockhash` (check 2 at every batch boundary, so a fork is refused before anything from it is scanned) and scanned from `[scanned_tip + 1, min(scanned_tip + 1 + scan_batch, V + 1))`. The prior chain state of a batch is the node's `z_gettreestate` where the node still serves it and the endpoint's `GetTreeState` below that; the root check covers the latter. When the key's scanned tip reaches `V` the session is validated, and only then does the key return to Case A. The session is recorded in `keys/<id>/backfill.json`, so that a daemon restarted between the last batch and the handoff still validates before scanning on from the node. A restore below the window takes its birthday's tree state from the endpoint's `GetTreeState(birthday - 1)`, refused unless its block hash equals the node's `getblockhash(birthday - 1)`; `RestoreKeyResponse.backfill_blocks` is `V + 1 - birthday`. With `cache.keep_historical = false` the endpoint's rows are evicted as soon as the slowest key has scanned them. The CLI prompt and `--yes` predate this (M1); the `.onion` preference is ROADMAP.md M2's fifth item.

### 5.2 Three checks at `V`

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

### 5.3 Transparent history below `retained_from`

Compact blocks carry no transparent outputs and a pruned node stops maintaining address indexes, so the only source is lightwalletd `GetAddressUtxos` for the key's transparent and ephemeral receivers (gap-limit scan). Each returned UTXO's transaction is fetched with `GetTransaction`, its txid recomputed, and its block hash compared with `getblockhash(height)` from the node. A UTXO that cannot be placed in a node-confirmed block is discarded and logged. This is a weaker guarantee than the shielded checks and `THREAT_MODEL.md` says so.

**Status (ROADMAP.md M2, fourth item):** built as `gyges_core::recovery` and `gygesd::backfill::recover_transparent`, run once a session's handoff has validated and before it closes (an endpoint that drops out is retried on the next tick). The endpoint is asked about every receiver the wallet has (external, change, ephemeral) for `[from, V]`; crediting can advance the gap limit, so new receivers are asked about in further passes (at most 16). For each reported output:

1. `GetTransaction` must return bytes that hash to the reported txid, at the reported height, with the reported script and value at the reported index.
2. The node must have a block at that height (`getblockhash`).
3. Where the node still holds the block (`height >= retained_from`), the transaction and output must be in the node's own block. This covers `[retained_from, V]`, which the backfill took from the endpoint without transparent outputs, so nothing else credits outputs there.
4. Below the window, the endpoint's compact block at that height must hash to the node's, and a transaction with shielded parts must be listed in it. A transparent-only transaction cannot be placed (compact blocks list only transactions with shielded parts and carry no Merkle proof), so it is accepted as best-effort and counted as `unplaced`.

A failure discards the output with a log line naming the height and the reason, never the address or amount; it does not mark the endpoint untrusted. What passes goes straight into the upstream UTXO table through `put_received_transparent_utxo` (an upsert), with no `gyges_transparent_received_outputs` staging table (see below). The counts are kept in `keys/<id>/transparent_recovery.json`. An output the endpoint omits, or one spent above the window that it still reports, cannot be detected. A fabricated transparent-only output with a self-consistent transaction would be credited too; spending it fails at the node.

---

## 6. Scanned versus Spendable

| Term | Definition | Source of truth |
|---|---|---|
| **scanned** | `block_fully_scanned().height >= bounds.tip_height` | `WalletRead::block_fully_scanned` |
| **spendable** | scanned, and `suggest_scan_ranges()` returns no range with priority above `Ignored` | `WalletRead::suggest_scan_ranges` |

`GetSyncStatus` returns both booleans plus `scanned_tip`, `tip_height`, the `SyncState`, blocks per second over the last minute, the blocks remaining across open ranges and the active source (`retained_from` is in `GetInfo.node`). The CLI never computes them itself. `WaitSync` wakes the scheduler and reports `done` only from a tick that began after the request, so a `sync wait` issued right after new blocks never returns a stale "spendable"; a stalled key fails the stream at once with `NOT_SYNCED` (API.md §4.4).

`gyges sync wait` defaults to `--until spendable`; `--until scanned` is cheaper for scripts that only need the tip. `--confirmations N --txid T` waits until `T` has `N` confirmations.

---

## 7. Mempool

Runs continuously inside the daemon when `mempool.scan = true` (default):

- With the indexer gRPC: subscribe to `mempool_change` (`Added`, `Invalidated`, `Mined` with txid) and `getrawtransaction` only added txids. *Not built: there is no Zakura indexer (`OVERVIEW.md` §4.5).*
- Without: `getrawmempool`, diff against the seen set, fetch only new txids with `getrawtransaction(txid, 1)`. *Built (`gygesd::sync::Scheduler::mempool_pass`).* A pass runs at most once per `poll_interval_secs`, and only on a tick that scanned no batch, so a key catching up is not slowed down. At most 500 new transactions are fetched per pass; the rest are fetched on the next one. Only the node is asked (`ChainBackend::mempool_txids` / `fetch_transaction`); the fallback endpoint has no mempool listing.

Each new transaction is fetched once, whatever the number of keys, and trial-decrypted for every key with `zcash_client_backend::decrypt_transaction` (the Sapling, Orchard and Ironwood outputs). What it finds is stored unmined via `WalletWrite::store_decrypted_tx` (`gyges_core::mempool::scan_tx`, which follows upstream's `decrypt_and_store_transaction`). That is what `balance` shows under *pending*: upstream's summary counts unmined received value as pending and the notes it spends as spent, so no balance code is involved. A key without a chain tip yet is skipped.

Nothing has to be done about txids that vanish from `getrawmempool`:
- the wallet's own sends get their mined status from the status work (`OVERVIEW.md` §4.3) or from scanning;
- an incoming transaction that never gets mined stops counting once the tip passes its expiry height, because upstream's balance ignores expired unmined transactions;
- `tex_queue` polls the node itself.

`gyges sync mempool` (`ScanMempool`) forces one immediate full pass for every key, even with `mempool.scan = false`. It covers every transaction in the mempool, seen before or not, up to the same 500.

The request pattern is identical whether or not the wallet has activity, so mempool polling leaks nothing beyond the block requests. Upstream logs every txid `store_decrypted_tx` stores at `info`, and some of its warnings and `zcash_client_sqlite`'s messages name txids too. Under `daemon.log_level` those targets are capped (`gygesd::logs::QUIET_UPSTREAM`), so the main log keeps no txid.

---

## 8. Daemon Stop

On `daemon stop` or `SIGTERM`:

1. Stop the scheduler at the next batch boundary. A batch is at most `cache.scan_batch` blocks, and `scan_cached_blocks` commits per batch, so no partial batch is ever visible. Shutdown sets a stop flag on the `SyncHub`. The scheduler finishes the batch in hand, its fetch from the node and its scan, and then returns. Shutdown waits up to 30 s for it and cancels it after that; a cancelled batch commits nothing.
2. Close Tor streams; the Arti cache under `tor_cache/` is kept.
3. Run `PRAGMA wal_checkpoint(TRUNCATE)` on `blocks.sqlite`. The `wallet.sqlite` files use upstream's default rollback journal, not WAL, so they have nothing to checkpoint.
4. Zeroize unlocked keys and destroy signing sessions held in memory (persisted sessions in `signing_sessions` survive).
5. Leave `ext_gyges_tex_queue` rows as they are; the queue resumes on next start (it re-checks every active row against the node, so a step the node lost while the daemon was down is simply rebroadcast).
6. Unlink the socket last, after every step above. `gyges daemon stop` waits for the file to go, so it returns only once the batch is committed, the keys are zeroized and the cache is checkpointed.

On restart every key begins in `Initializing`, which re-derives its state from `block_fully_scanned` and `NodeBounds`, so an interrupted scan simply continues.

---

## 9. Upstream Calls by Step

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
