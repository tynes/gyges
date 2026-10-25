//! Per-key synchronisation primitives for Case A (SYNC.md §3–§4, §6).
//!
//! Everything here runs against one key's `WalletDb` and the shared
//! `BlockDb`, synchronously and under the key's wallet lock; the daemon's
//! `SyncScheduler` (in `gygesd`) decides *when* to call it, talks to the
//! node, and publishes the resulting [`KeyProgress`]. Keeping the two apart
//! lets this part be tested with a wallet, an in-memory cache and no node.
//!
//! Terms (SYNC.md §6): a key is **scanned** when `block_fully_scanned()` has
//! reached the node's tip, and **spendable** when, in addition,
//! `suggest_scan_ranges()` returns nothing above priority `Ignored`.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::time::SystemTime;

use gyges_chain::{BlockDb, CacheError, ChainError, compact};
use transparent::bundle::OutPoint;
use zcash_client_backend::data_api::chain::error::Error as ScanChainError;
use zcash_client_backend::data_api::chain::{
    BlockSource as _, ChainState, ScanSummary, scan_cached_blocks,
};
use zcash_client_backend::data_api::error::RewindError;
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_client_backend::data_api::{WalletRead as _, WalletWrite as _};
use zcash_client_backend::wallet::WalletTransparentOutput;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_protocol::consensus::BlockHeight;

use crate::network::ConsensusParams;
use crate::registry::Wallet;

/// How far back a fork point is searched (OVERVIEW.md Q-Y1: the Zebra
/// lineage's finality depth, **needs verification** against Zakura).
pub const FINALITY_DEPTH: u32 = 100;

/// Why a key cannot make progress without operator action (SYNC.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StallReason {
    /// Case A invariant broken (`scanned_tip + 1 < retained_from`) and no
    /// fallback endpoint is configured (or the daemon is air-gapped).
    PrunedPastScanTip,
    /// No fork point within [`FINALITY_DEPTH`] blocks.
    ChainInconsistent,
    /// Handoff validation failed (SYNC.md §5.2) and the endpoint is marked
    /// untrusted; cleared only by configuring another endpoint. The
    /// endpoint and the failed check are in `KeyProgress.detail` and
    /// `GetInfo.fallback`.
    UntrustedBackfill,
    /// The fallback endpoint could not serve the backfill (unreachable,
    /// behind, or missing a block); retried every tick.
    FallbackUnreachable,
    /// Node unreachable for longer than `daemon.offline_grace`.
    Offline,
}

impl StallReason {
    pub const fn name(self) -> &'static str {
        match self {
            StallReason::PrunedPastScanTip => "pruned-past-scan-tip",
            StallReason::ChainInconsistent => "chain-inconsistent",
            StallReason::UntrustedBackfill => "fallback-untrusted",
            StallReason::FallbackUnreachable => "fallback-unreachable",
            StallReason::Offline => "offline",
        }
    }
}

/// The per-key state machine (SYNC.md §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Profile loaded, nothing decided yet.
    Initializing,
    /// Case B: scanning `[from, to)` from blocks the fallback endpoint
    /// served (over Tor unless `via_tor` is false), below the node's
    /// retention window; handed back to Case A once the handoff checks of
    /// SYNC.md §5.2 pass at `to - 1`.
    Backfilling {
        via_tor: bool,
        from: BlockHeight,
        to: BlockHeight,
    },
    /// Scanning `[from, to)` from the shared cache.
    Scanning {
        from: BlockHeight,
        to: BlockHeight,
    },
    /// A reorg was detected; the wallet is being truncated to `to`.
    Rewinding {
        to: BlockHeight,
    },
    /// `scanned_tip >= tip_height`.
    Synced {
        spendable: bool,
    },
    Stalled(StallReason),
}

impl SyncState {
    /// The CLI's state word: `initializing`, `backfilling`, `scanning`,
    /// `rewinding`, `synced`, `stalled(<reason>)`.
    pub fn name(&self) -> String {
        match self {
            SyncState::Initializing => "initializing".into(),
            SyncState::Backfilling { .. } => "backfilling".into(),
            SyncState::Scanning { .. } => "scanning".into(),
            SyncState::Rewinding { .. } => "rewinding".into(),
            SyncState::Synced { .. } => "synced".into(),
            SyncState::Stalled(r) => format!("stalled({})", r.name()),
        }
    }

    pub fn is_stalled(&self) -> bool {
        matches!(self, SyncState::Stalled(_))
    }
}

/// What `GetSyncStatus` reports for one key (SYNC.md §6).
#[derive(Clone, Debug, PartialEq)]
pub struct KeyProgress {
    pub key_id: String,
    pub state: SyncState,
    /// `block_fully_scanned()`, or `birthday - 1` before the first batch.
    pub scanned_tip: u32,
    /// The node's tip as of the last poll; 0 while unknown.
    pub chain_tip: u32,
    pub scanned: bool,
    pub spendable: bool,
    /// Blocks across every open scan range above `Ignored`.
    pub blocks_remaining: u32,
    /// Over the last minute of scanning.
    pub blocks_per_sec: f64,
    /// One line for humans: what is happening, or why it stopped.
    pub detail: String,
    pub updated_at: SystemTime,
}

impl KeyProgress {
    pub fn initializing(key_id: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            state: SyncState::Initializing,
            scanned_tip: 0,
            chain_tip: 0,
            scanned: false,
            spendable: false,
            blocks_remaining: 0,
            blocks_per_sec: 0.0,
            detail: String::new(),
            updated_at: SystemTime::now(),
        }
    }
}

/// Why a step failed.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("wallet: {0}")]
    Wallet(String),
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// The fallback endpoint could not answer during a backfill
    /// (`Stalled(FallbackUnreachable)`, retried).
    #[error("fallback endpoint: {0}")]
    Fallback(ChainError),
    /// What the fallback endpoint served failed a handoff check
    /// (`Stalled(UntrustedBackfill)`).
    #[error("{0}")]
    Untrusted(crate::handoff::Mismatch),
    /// A scan error that is not a continuity error (bad encoding, tree size
    /// overflow): the cache holds something the wallet cannot digest.
    #[error("scan: {0}")]
    Scan(String),
    /// `truncate_to_height` has no scanned block at or below the fork point
    /// to truncate to (a reorg at or below the key's first scanned block):
    /// the wallet must be reset to the node's tree state at the fork
    /// instead ([`rewind_to_chain_state`]).
    #[error(
        "wallet cannot be truncated to {requested}: no scanned block at or below it (safe: {safe:?})"
    )]
    RewindInvalid {
        requested: BlockHeight,
        safe: Option<BlockHeight>,
    },
}

fn wallet_err(e: impl std::fmt::Display) -> SyncError {
    SyncError::Wallet(e.to_string())
}

/// The wallet's own view of its progress, read under the lock.
#[derive(Clone, Debug)]
pub struct WalletView {
    pub birthday: BlockHeight,
    /// Height and hash of `block_fully_scanned()`.
    pub fully_scanned: Option<(BlockHeight, [u8; 32])>,
    /// `suggest_scan_ranges()`, highest priority first.
    pub ranges: Vec<ScanRange>,
}

impl WalletView {
    /// Tell the wallet the node's tip (when known) and read back its scan
    /// position and queue. `update_chain_tip` is what lets upstream
    /// prioritise the ranges (SYNC.md §4.1 step 1).
    pub fn read(wallet: &mut Wallet, chain_tip: Option<BlockHeight>) -> Result<Self, SyncError> {
        if let Some(tip) = chain_tip {
            wallet.update_chain_tip(tip).map_err(wallet_err)?;
        }
        let birthday = wallet
            .get_wallet_birthday()
            .map_err(wallet_err)?
            .unwrap_or(BlockHeight::from_u32(0));
        let fully_scanned = wallet
            .block_fully_scanned()
            .map_err(wallet_err)?
            .map(|m| (m.block_height(), m.block_hash().0));
        let ranges = wallet.suggest_scan_ranges().map_err(wallet_err)?;
        Ok(Self {
            birthday,
            fully_scanned,
            ranges,
        })
    }

    /// The highest block every earlier block of which is scanned, or the
    /// block before the birthday when nothing is yet.
    pub fn scanned_tip(&self) -> BlockHeight {
        match self.fully_scanned {
            Some((h, _)) => h,
            None => self.birthday.saturating_sub(1),
        }
    }

    /// Ranges still to scan, in the order upstream wants them.
    pub fn pending(&self) -> impl Iterator<Item = &ScanRange> {
        self.ranges
            .iter()
            .filter(|r| r.priority() > ScanPriority::Ignored && !r.is_empty())
    }

    pub fn blocks_remaining(&self) -> u32 {
        self.pending()
            .map(|r| u32::try_from(r.len()).unwrap_or(u32::MAX))
            .fold(0u32, u32::saturating_add)
    }

    /// The next batch: the highest-priority pending range, cut to `batch`
    /// blocks (SYNC.md §4.1 step 2).
    pub fn next_range(&self, batch: usize) -> Option<ScanRange> {
        let first = self.pending().next()?;
        if first.len() <= batch {
            return Some(first.clone());
        }
        let cut = first.block_range().start + u32::try_from(batch).unwrap_or(u32::MAX);
        Some(
            first
                .split_at(cut)
                .map_or_else(|| first.clone(), |(head, _)| head),
        )
    }

    pub fn is_scanned(&self, chain_tip: BlockHeight) -> bool {
        self.scanned_tip() >= chain_tip
    }

    pub fn is_spendable(&self, chain_tip: BlockHeight) -> bool {
        self.is_scanned(chain_tip) && self.pending().next().is_none()
    }
}

/// What one scan batch did.
#[derive(Debug)]
pub enum ScanOutcome {
    Scanned {
        summary: ScanSummary,
        /// Transparent outputs credited to this key from the batch.
        transparent_outputs: usize,
    },
    /// A continuity check failed at `at_height`: the wallet's view has
    /// diverged from the cached chain (SYNC.md §4.3). Nothing was written.
    Reorg { at_height: BlockHeight },
}

/// SYNC.md §4.1 step 4: scan `range` from the cache, starting from the chain
/// state as of `range.start - 1`, then credit the key's transparent
/// receivers from the same blocks.
pub fn scan_range(
    params: &ConsensusParams,
    cache: &BlockDb,
    wallet: &mut Wallet,
    range: &ScanRange,
    prior: &ChainState,
) -> Result<ScanOutcome, SyncError> {
    let start = range.block_range().start;
    assert_eq!(
        prior.block_height() + 1,
        start,
        "prior chain state must be for range.start - 1"
    );
    let summary = match scan_cached_blocks(params, cache, wallet, start, prior, range.len()) {
        Ok(summary) => summary,
        Err(ScanChainError::Scan(err)) if err.is_continuity_error() => {
            return Ok(ScanOutcome::Reorg {
                at_height: err.at_height(),
            });
        }
        Err(ScanChainError::Scan(err)) => return Err(SyncError::Scan(err.to_string())),
        Err(ScanChainError::Wallet(e)) => return Err(wallet_err(e)),
        Err(ScanChainError::BlockSource(e)) => return Err(SyncError::Cache(e)),
        Err(other) => return Err(SyncError::Scan(other.to_string())),
    };
    let transparent_outputs = index_transparent(cache, wallet, summary.scanned_range())?;
    Ok(ScanOutcome::Scanned {
        summary,
        transparent_outputs,
    })
}

/// Credit every transparent output in the cached blocks of `range` that pays
/// one of the key's receivers (external, change and ephemeral) through
/// `put_received_transparent_utxo` (SYNC.md §2.1). Finding an output can
/// advance the gap limit and reveal new receivers, so the pass repeats
/// until a pass finds nothing new.
pub fn index_transparent(
    cache: &BlockDb,
    wallet: &mut Wallet,
    range: Range<BlockHeight>,
) -> Result<usize, SyncError> {
    if range.is_empty() {
        return Ok(0);
    }
    // Collect once; blocks are small relative to the wallet work.
    let mut outputs = Vec::new();
    let len = usize::try_from(u32::from(range.end) - u32::from(range.start)).unwrap_or(usize::MAX);
    cache
        .with_blocks::<_, ()>(Some(range.start), Some(len), |block| {
            outputs.extend(compact::transparent_outputs(&block));
            Ok(())
        })
        .map_err(|e| match e {
            ScanChainError::BlockSource(e) => SyncError::Cache(e),
            ScanChainError::Scan(e) => SyncError::Scan(e.to_string()),
            _ => SyncError::Scan("reading cached blocks failed".into()),
        })?;
    credit_transparent(wallet, &outputs)
}

/// Credit every output of `outputs` that pays one of the key's receivers
/// (external, change and ephemeral) through `put_received_transparent_utxo`.
/// Finding an output can advance the gap limit and reveal new receivers, so
/// the pass repeats until a pass finds nothing new. Used for the node's
/// blocks ([`index_transparent`]) and for outputs recovered below the
/// node's window (`crate::recovery`).
pub fn credit_transparent(
    wallet: &mut Wallet,
    outputs: &[compact::TransparentOutput],
) -> Result<usize, SyncError> {
    let outputs: Vec<&compact::TransparentOutput> =
        outputs.iter().filter(|o| o.address.is_some()).collect();
    if outputs.is_empty() {
        return Ok(0);
    }

    let accounts = wallet.get_account_ids().map_err(wallet_err)?;
    let mut credited = 0usize;
    let mut known_receivers = 0usize;
    // `put_received_transparent_utxo` records the transaction's locator,
    // which is unique per (height, index): never put one outpoint twice.
    let mut done: HashSet<([u8; 32], u32)> = HashSet::new();
    // Repeat while the receiver set grows (gap limit advanced); bounded so a
    // hostile block cannot loop us.
    for pass in 0..16 {
        let mut receivers = HashMap::new();
        for account in &accounts {
            for (addr, meta) in wallet
                .get_transparent_receivers(*account, true, true)
                .map_err(wallet_err)?
            {
                receivers.insert(addr, (*account, meta.scope()));
            }
        }
        if receivers.is_empty() || (pass > 0 && receivers.len() == known_receivers) {
            break;
        }
        known_receivers = receivers.len();
        let mut found_this_pass = 0usize;
        for o in &outputs {
            let Some((account, scope)) = o.address.and_then(|a| receivers.get(&a)) else {
                continue;
            };
            if done.contains(&(o.txid, o.index)) {
                continue;
            }
            let Some(txout) = compact::txout_of(o) else {
                continue;
            };
            let Some(wto) = WalletTransparentOutput::from_parts(
                OutPoint::new(o.txid, o.index),
                txout,
                Some(o.height),
                Some(*account),
                *scope,
                None,
            ) else {
                continue;
            };
            wallet
                .put_received_transparent_utxo(&wto)
                .map_err(wallet_err)?;
            done.insert((o.txid, o.index));
            found_this_pass += 1;
        }
        credited += found_this_pass;
        if found_this_pass == 0 {
            break;
        }
    }
    Ok(credited)
}

/// `(height, stored hash)` pairs, highest first; see [`wallet_hashes`].
pub type WalletHashes = Vec<(BlockHeight, Option<[u8; 32]>)>;

/// The wallet's stored block hashes from `from` downwards, at most
/// [`FINALITY_DEPTH`] of them, for the fork search (SYNC.md §4.3). `None`
/// where the wallet has no block at that height (below its history), which
/// ends the search: there is nothing to rewind beyond it.
pub fn wallet_hashes(wallet: &Wallet, from: BlockHeight) -> Result<WalletHashes, SyncError> {
    let mut out = Vec::new();
    let mut h = from;
    for _ in 0..FINALITY_DEPTH {
        let hash = wallet
            .block_metadata(h)
            .map_err(wallet_err)?
            .map(|m| m.block_hash().0);
        let done = hash.is_none() || h == BlockHeight::from_u32(0);
        out.push((h, hash));
        if done {
            break;
        }
        h = h - 1;
    }
    Ok(out)
}

/// SYNC.md §4.3 step 2: rewind notes, nullifiers, received outputs and
/// ShardTree checkpoints to `fork_point`. Returns the height actually
/// truncated to, which upstream may choose lower. Fails with
/// [`SyncError::RewindInvalid`] when the wallet has scanned nothing at or
/// below `fork_point` (a reorg at or below its birthday), in which case the
/// caller resets it with [`rewind_to_chain_state`].
pub fn rewind(wallet: &mut Wallet, fork_point: BlockHeight) -> Result<BlockHeight, SyncError> {
    match wallet.truncate_to_height(fork_point) {
        Ok(h) => Ok(h),
        Err(SqliteClientError::RequestedRewindInvalid {
            safe_rewind_height,
            requested_height,
        }) => Err(SyncError::RewindInvalid {
            requested: requested_height,
            safe: safe_rewind_height,
        }),
        Err(e) => Err(wallet_err(e)),
    }
}

/// Truncate to `state`'s height when [`rewind`] cannot (no block row at
/// that height, e.g. the block before a restore's birthday): upstream
/// inserts the frontier as a checkpoint there and truncates to it. Used to
/// drop what an untrusted endpoint served (SYNC.md §5.2).
pub fn truncate_to_chain_state(wallet: &mut Wallet, state: &ChainState) -> Result<(), SyncError> {
    wallet
        .truncate_to_chain_state(state.clone())
        .map_err(wallet_err)
}

/// The highest block the wallet has scanned, contiguous or not.
pub fn max_scanned(wallet: &Wallet) -> Result<Option<BlockHeight>, SyncError> {
    Ok(wallet
        .block_max_scanned()
        .map_err(wallet_err)?
        .map(|m| m.block_height()))
}

/// SYNC.md §4.3 step 2 when the fork is at or below the key's first scanned
/// block: reset the wallet's trees to the node's state at the end of the
/// fork block (`z_gettreestate(fork)`), lowering account birthdays to
/// `fork + 1` where the fork is below them. Scan ranges from `fork + 1`
/// are requeued by the wallet. Returns the fork height.
pub fn rewind_to_chain_state(
    wallet: &mut Wallet,
    state: &ChainState,
) -> Result<BlockHeight, SyncError> {
    let height = state.block_height();
    match wallet.rewind_to_chain_state(state.clone(), HashSet::new()) {
        Ok(()) => Ok(height),
        Err(RewindError::RewindBeyondBirthdays(birthdays)) => {
            let all: HashSet<_> = birthdays.keys().copied().collect();
            wallet
                .rewind_to_chain_state(state.clone(), all)
                .map_err(wallet_err)?;
            Ok(height)
        }
        Err(e) => Err(wallet_err(e)),
    }
}

/// Height of the block containing `txid`, if the wallet has seen it mined.
pub fn tx_height(wallet: &Wallet, txid: [u8; 32]) -> Result<Option<BlockHeight>, SyncError> {
    wallet
        .get_tx_height(zcash_protocol::TxId::from_bytes(txid))
        .map_err(wallet_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::scanning::ScanPriority;

    fn r(start: u32, end: u32, p: ScanPriority) -> ScanRange {
        ScanRange::from_parts(BlockHeight::from_u32(start)..BlockHeight::from_u32(end), p)
    }

    fn view(ranges: Vec<ScanRange>, fully_scanned: Option<u32>) -> WalletView {
        WalletView {
            birthday: BlockHeight::from_u32(100),
            fully_scanned: fully_scanned.map(|h| (BlockHeight::from_u32(h), [0; 32])),
            ranges,
        }
    }

    #[test]
    fn state_names_match_the_cli_spec() {
        assert_eq!(SyncState::Initializing.name(), "initializing");
        assert_eq!(
            SyncState::Scanning {
                from: BlockHeight::from_u32(1),
                to: BlockHeight::from_u32(2)
            }
            .name(),
            "scanning"
        );
        assert_eq!(SyncState::Synced { spendable: true }.name(), "synced");
        assert_eq!(
            SyncState::Stalled(StallReason::PrunedPastScanTip).name(),
            "stalled(pruned-past-scan-tip)"
        );
        assert!(SyncState::Stalled(StallReason::Offline).is_stalled());
    }

    #[test]
    fn scanned_tip_defaults_to_the_block_before_the_birthday() {
        let v = view(vec![], None);
        assert_eq!(v.scanned_tip(), BlockHeight::from_u32(99));
        let v = view(vec![], Some(150));
        assert_eq!(v.scanned_tip(), BlockHeight::from_u32(150));
    }

    #[test]
    fn next_range_takes_the_first_pending_range_cut_to_the_batch() {
        let v = view(
            vec![
                r(300, 310, ScanPriority::Ignored),
                r(100, 5000, ScanPriority::Historic),
                r(5000, 5001, ScanPriority::ChainTip),
            ],
            None,
        );
        assert_eq!(v.blocks_remaining(), 4901);
        let next = v.next_range(1000).unwrap();
        assert_eq!(
            next.block_range(),
            &(BlockHeight::from_u32(100)..BlockHeight::from_u32(1100))
        );
        assert_eq!(next.priority(), ScanPriority::Historic);
        // A range shorter than the batch is taken whole.
        let v = view(vec![r(100, 105, ScanPriority::ChainTip)], None);
        assert_eq!(v.next_range(1000).unwrap().len(), 5);
        // Only Ignored left: nothing to do and spendable at the tip.
        let v = view(vec![r(300, 310, ScanPriority::Ignored)], Some(400));
        assert!(v.next_range(1000).is_none());
        assert!(v.is_scanned(BlockHeight::from_u32(400)));
        assert!(v.is_spendable(BlockHeight::from_u32(400)));
        assert!(!v.is_scanned(BlockHeight::from_u32(401)));
        // Scanned at the tip but a FoundNote range open: not spendable.
        let v = view(vec![r(200, 250, ScanPriority::FoundNote)], Some(400));
        assert!(v.is_scanned(BlockHeight::from_u32(400)));
        assert!(!v.is_spendable(BlockHeight::from_u32(400)));
    }
}
