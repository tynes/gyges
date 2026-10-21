//! The `SyncScheduler` for Case A (SYNC.md §2.2, §3, §4, §6) and the sync
//! RPCs (`GetSyncStatus`, `WaitSync`, `RunSync`; API.md §4.4).
//!
//! One task per daemon. Each tick: poll the node, reconcile the shared block
//! cache with the node's chain (the cheap per-tick reorg detector), then for
//! every key with a wallet: apply a requested rewind, check the wallet's own
//! chain view against the cache, enforce the Case A invariant, fetch the
//! next batch into the cache if needed, fetch the prior tree state, scan,
//! and publish [`KeyProgress`]. Ticks run back to back while any key has
//! work and every `zakura_rpc.poll_interval_secs` otherwise, or sooner when
//! an RPC wakes the scheduler.
//!
//! The wallet work (`scan_cached_blocks`, truncation) is synchronous SQLite
//! and CPU and runs under `spawn_blocking`, holding the key's wallet lock for
//! one batch of at most `cache.scan_batch` blocks.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use gyges_chain::{BlockDb, CacheError, ChainBackend, ChainError, NodeBounds, Source};
use gyges_core::KeyEntry;
use gyges_core::sync::{
    self as core_sync, FINALITY_DEPTH, KeyProgress, ScanOutcome, StallReason, SyncError, SyncState,
    WalletView,
};
use gyges_proto::v1::{
    self, ErrorReason, GetSyncStatusRequest, GetSyncStatusResponse, GygesError, KeySyncStatus,
    RunSyncRequest, SyncProgress, SyncTarget, WaitSyncRequest,
};
use tokio::sync::{Notify, mpsc, watch};
use tonic::Status;
use zcash_client_backend::data_api::chain::BlockCache as _;
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_protocol::consensus::BlockHeight;

use crate::keys::registry_error;
use crate::node;
use crate::service::DaemonState;

/// What the RPC handlers and the scheduler share: the latest progress per
/// key, a change counter for streams to wait on, a wake-up for the
/// scheduler, and pending rewind requests.
#[derive(Debug)]
pub struct SyncHub {
    progress: RwLock<BTreeMap<String, KeyProgress>>,
    generation: watch::Sender<u64>,
    wake: Notify,
    /// `key_id` → first height to rescan (`RunSync.from_height`).
    rewinds: Mutex<BTreeMap<String, BlockHeight>>,
    /// Scheduler ticks `(begun, completed)`. A stream that wants a view of
    /// the node newer than its own start waits for a tick that *began*
    /// after it woke the scheduler (see [`SyncHub::ticks`]).
    ticks: Mutex<(u64, u64)>,
}

impl Default for SyncHub {
    fn default() -> Self {
        Self {
            progress: RwLock::new(BTreeMap::new()),
            generation: watch::Sender::new(0),
            wake: Notify::new(),
            rewinds: Mutex::new(BTreeMap::new()),
            ticks: Mutex::new((0, 0)),
        }
    }
}

impl SyncHub {
    pub fn get(&self, key_id: &str) -> Option<KeyProgress> {
        self.progress
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key_id)
            .cloned()
    }

    pub fn snapshot(&self) -> Vec<KeyProgress> {
        self.progress
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Replace a key's progress and notify waiters.
    pub fn publish(&self, mut progress: KeyProgress) {
        progress.updated_at = SystemTime::now();
        self.progress
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(progress.key_id.clone(), progress);
        self.generation.send_modify(|g| *g += 1);
    }

    /// Edit a key's progress in place (creating it as `Initializing`).
    pub fn update(&self, key_id: &str, f: impl FnOnce(&mut KeyProgress)) {
        let mut p = self
            .get(key_id)
            .unwrap_or_else(|| KeyProgress::initializing(key_id));
        f(&mut p);
        self.publish(p);
    }

    pub fn forget(&self, key_id: &str) {
        self.progress
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key_id);
        self.generation.send_modify(|g| *g += 1);
    }

    /// A receiver that wakes whenever any progress changes.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// Run a tick now rather than at the next poll interval.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// `RunSync.from_height`: rescan from `from` (truncating to `from - 1`)
    /// at the next tick.
    pub fn request_rewind(&self, key_id: &str, from: BlockHeight) {
        self.rewinds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key_id.to_string(), from);
        self.wake();
    }

    pub fn rewind_pending(&self, key_id: &str) -> bool {
        self.rewinds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(key_id)
    }

    fn take_rewind(&self, key_id: &str) -> Option<BlockHeight> {
        self.rewinds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key_id)
    }

    /// `(ticks begun, ticks completed)`.
    pub fn ticks(&self) -> (u64, u64) {
        *self.ticks.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tick_begun(&self) {
        self.ticks.lock().unwrap_or_else(|e| e.into_inner()).0 += 1;
    }

    fn tick_completed(&self) {
        self.ticks.lock().unwrap_or_else(|e| e.into_inner()).1 += 1;
        self.generation.send_modify(|g| *g += 1);
    }
}

/// Blocks scanned per key over the last minute.
#[derive(Debug, Default)]
struct Rate {
    samples: VecDeque<(Instant, u32)>,
}

impl Rate {
    const WINDOW: Duration = Duration::from_secs(60);

    fn record(&mut self, blocks: u32) {
        let now = Instant::now();
        self.samples.push_back((now, blocks));
        while self
            .samples
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > Self::WINDOW)
        {
            self.samples.pop_front();
        }
    }

    fn per_sec(&self) -> f64 {
        let Some((first, _)) = self.samples.front() else {
            return 0.0;
        };
        let total: u64 = self.samples.iter().map(|(_, b)| u64::from(*b)).sum();
        let elapsed = first.elapsed().as_secs_f64().max(1.0);
        total as f64 / elapsed
    }
}

/// The scheduler task's state.
pub struct Scheduler {
    state: Arc<DaemonState>,
    chain: Arc<dyn ChainBackend>,
    cache: Arc<BlockDb>,
    link: node::Link,
    rates: BTreeMap<String, Rate>,
    started: Instant,
    last_connected: Option<Instant>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler").finish_non_exhaustive()
    }
}

/// Start the scheduler. The first node poll has already happened in
/// `Daemon::serve`; the first tick follows at once.
pub fn spawn(
    state: Arc<DaemonState>,
    chain: Arc<dyn ChainBackend>,
    cache: Arc<BlockDb>,
    link: node::Link,
) -> tokio::task::JoinHandle<()> {
    let scheduler = Scheduler {
        state,
        chain,
        cache,
        link,
        rates: BTreeMap::new(),
        started: Instant::now(),
        last_connected: None,
    };
    tokio::spawn(scheduler.run())
}

impl Scheduler {
    async fn run(mut self) {
        let poll = Duration::from_secs(u64::from(
            self.state.config.zakura_rpc.poll_interval_secs.max(1),
        ));
        loop {
            self.hub().tick_begun();
            let did_work = self.tick().await;
            self.hub().tick_completed();
            if did_work {
                // Let RPC handlers in between batches.
                tokio::task::yield_now().await;
            } else {
                tokio::select! {
                    () = self.state.sync.wake.notified() => {}
                    () = tokio::time::sleep(poll) => {}
                }
            }
        }
    }

    fn hub(&self) -> &SyncHub {
        &self.state.sync
    }

    /// One pass over the node and every key. Returns whether any key
    /// scanned a batch (so the next tick should follow immediately).
    async fn tick(&mut self) -> bool {
        let connected = node::poll_once(&self.state, self.chain.as_ref(), &self.link).await;
        let status = self.chain.status();
        if connected {
            self.last_connected = Some(Instant::now());
        }
        let keys: Vec<Arc<KeyEntry>> = self
            .state
            .registry
            .list()
            .into_iter()
            .filter(|k| k.profile().has_wallet())
            .collect();

        if !connected {
            let down_for = self
                .last_connected
                .map_or_else(|| self.started.elapsed(), |t| t.elapsed());
            let stalled = down_for > self.state.config.daemon.offline_grace;
            for key in &keys {
                let err = status.last_error.clone();
                self.hub().update(key.key_id(), |p| {
                    if stalled {
                        p.state = SyncState::Stalled(StallReason::Offline);
                        p.detail = format!("node unreachable for {}s: {err}", down_for.as_secs());
                    } else {
                        p.detail = format!("node unreachable, retrying: {err}");
                    }
                    p.blocks_per_sec = 0.0;
                });
            }
            return false;
        }
        let Some(bounds) = status.bounds else {
            return false;
        };

        if let Err(e) = self.reconcile_cache(&bounds).await {
            tracing::warn!(error = %e, "block cache reconciliation failed; retrying next tick");
            return false;
        }

        let mut did_work = false;
        let mut slowest: Option<BlockHeight> = None;
        for key in &keys {
            match self.step_key(key, &bounds).await {
                Ok((worked, scanned_tip)) => {
                    did_work |= worked;
                    slowest = Some(slowest.map_or(scanned_tip, |s| s.min(scanned_tip)));
                }
                Err(e) => self.report_step_error(key.key_id(), &bounds, e),
            }
        }
        if let Err(e) = self.evict(slowest) {
            tracing::warn!(error = %e, "block cache eviction failed");
        }
        did_work
    }

    /// Step errors that are not stalls leave the state alone and are
    /// retried next tick; the detail says what happened.
    fn report_step_error(&self, key_id: &str, bounds: &NodeBounds, e: SyncError) {
        let retained_from = bounds.retained_from;
        match &e {
            SyncError::Chain(ChainError::BlockUnavailable { height })
                if *height < retained_from =>
            {
                self.stall_pruned(key_id, u32::from(*height), bounds);
            }
            SyncError::Chain(ChainError::TreeStateUnavailable { height, .. }) => {
                self.stall_pruned(key_id, u32::from(*height) + 1, bounds);
            }
            SyncError::Chain(ChainError::Unreachable(_)) => {
                self.hub().update(key_id, |p| p.detail = e.to_string());
            }
            _ => {
                tracing::warn!(key_id, error = %e, "sync step failed; retrying next tick");
                self.hub().update(key_id, |p| p.detail = e.to_string());
            }
        }
    }

    /// SYNC.md §4.2: the Case A invariant is broken and no fallback route
    /// exists yet.
    fn stall_pruned(&self, key_id: &str, needed: u32, bounds: &NodeBounds) {
        let retained_from = u32::from(bounds.retained_from);
        let detail = format!(
            "node pruned past key '{key_id}' (needs block {needed}, node retains from {retained_from}); \
             enable fallback_lightwalletd (ROADMAP.md M2) or increase the node's tx_retention"
        );
        tracing::warn!(
            key_id,
            needed,
            retained_from,
            "key stalled: pruned past scan tip"
        );
        self.hub().update(key_id, |p| {
            p.state = SyncState::Stalled(StallReason::PrunedPastScanTip);
            p.detail = detail;
            p.blocks_per_sec = 0.0;
        });
    }

    /// Per-tick reorg detector on the shared cache (SYNC.md §4.3 step 1,
    /// applied to the cache so that every key benefits from one
    /// `getblockhash` per tick): drop cached blocks the node no longer has.
    async fn reconcile_cache(&self, bounds: &NodeBounds) -> Result<(), SyncError> {
        let Some((lo, hi)) = self.cache.bounds()? else {
            return Ok(());
        };
        if hi > bounds.tip_height {
            tracing::info!(
                cached_tip = u32::from(hi),
                node_tip = u32::from(bounds.tip_height),
                "node chain is shorter than the cache; truncating"
            );
            self.cache.truncate(bounds.tip_height).await?;
        }
        let top = hi.min(bounds.tip_height);
        let mut h = top;
        loop {
            if h < lo {
                tracing::warn!("every cached block is off the node's chain; clearing the cache");
                self.cache.delete(whole(lo, hi)).await?;
                return Ok(());
            }
            let cached = self.cache.hash_at(h)?;
            let node = self.chain.block_hash(h).await?;
            if cached == Some(node) {
                if h < top {
                    tracing::info!(
                        fork_point = u32::from(h),
                        dropped = u32::from(top) - u32::from(h),
                        "reorg: cache truncated to the fork point"
                    );
                    self.cache.truncate(h).await?;
                }
                return Ok(());
            }
            if u32::from(top) - u32::from(h) >= FINALITY_DEPTH {
                tracing::warn!(
                    depth = FINALITY_DEPTH,
                    "no fork point within the finality depth; clearing the cache"
                );
                self.cache.delete(whole(lo, hi)).await?;
                return Ok(());
            }
            h = h - 1;
        }
    }

    /// SYNC.md §2.2 step 4: keep `cache.retain_blocks` behind the slowest key.
    fn evict(&self, slowest: Option<BlockHeight>) -> Result<(), CacheError> {
        let Some(slowest) = slowest else {
            return Ok(());
        };
        let cfg = &self.state.config.cache;
        let keep_from = (u32::from(slowest) + 1).saturating_sub(cfg.retain_blocks);
        let removed = self.cache.evict_below(BlockHeight::from_u32(keep_from))?;
        if removed > 0 {
            tracing::debug!(removed, keep_from, "block cache evicted");
        }
        let budget = u64::from(cfg.max_mb) * 1024 * 1024;
        if self.cache.size_bytes()? > budget {
            let removed = self.cache.evict_below(slowest + 1)?;
            tracing::warn!(
                removed,
                max_mb = cfg.max_mb,
                "block cache over budget; dropped everything behind the slowest key"
            );
        }
        Ok(())
    }

    /// The hash the node agrees with at `h`: the cache's (already
    /// reconciled this tick), else the node's.
    async fn trusted_hash(&self, h: BlockHeight) -> Result<Option<[u8; 32]>, SyncError> {
        if let Some(cached) = self.cache.hash_at(h)? {
            return Ok(Some(cached));
        }
        match self.chain.block_hash(h).await {
            Ok(hash) => Ok(Some(hash)),
            Err(ChainError::BlockUnavailable { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// One key, one batch at most. Returns `(scanned a batch, scanned_tip)`.
    async fn step_key(
        &mut self,
        key: &Arc<KeyEntry>,
        bounds: &NodeBounds,
    ) -> Result<(bool, BlockHeight), SyncError> {
        let key_id = key.key_id().to_string();
        let tip = bounds.tip_height;

        if let Some(from) = self.hub().take_rewind(&key_id) {
            let to = from.saturating_sub(1);
            self.hub().update(&key_id, |p| {
                p.state = SyncState::Rewinding { to };
                p.detail = format!("rewinding to {} on request", u32::from(to));
            });
            let actual = with_wallet(key, move |w| core_sync::rewind(w, to)).await?;
            tracing::info!(
                key_id,
                requested = u32::from(to),
                actual = u32::from(actual),
                "wallet rewound on request"
            );
        }

        let view = with_wallet(key, move |w| WalletView::read(w, Some(tip))).await?;
        let scanned_tip = view.scanned_tip();

        // SYNC.md §4.3 detector 1: does the node still have the block the
        // wallet considers fully scanned?
        if let Some((h, wallet_hash)) = view.fully_scanned
            && self.trusted_hash(h).await? != Some(wallet_hash)
        {
            self.handle_reorg(key, h + 1).await?;
            return Ok((true, scanned_tip));
        }

        // SYNC.md §4.2 invariant: the next batch starts at a height whose
        // body the node has, and its prior tree state is still served.
        let Some(range) = view.next_range(self.state.config.cache.scan_batch as usize) else {
            let spendable = view.is_spendable(tip);
            self.publish_view(
                &key_id,
                &view,
                bounds,
                SyncState::Synced { spendable },
                String::new(),
            );
            return Ok((false, scanned_tip));
        };
        let start = range.block_range().start;
        let retained_from = bounds.retained_from;
        if start < retained_from
            || (retained_from > BlockHeight::from_u32(0) && start.saturating_sub(1) < retained_from)
        {
            self.stall_pruned(&key_id, u32::from(start), bounds);
            return Ok((false, scanned_tip));
        }

        let range = clamp_end(&range, tip + 1);
        if range.is_empty() {
            let spendable = view.is_spendable(tip);
            self.publish_view(
                &key_id,
                &view,
                bounds,
                SyncState::Synced { spendable },
                String::new(),
            );
            return Ok((false, scanned_tip));
        }
        let Range { start, end } = range.block_range().clone();
        self.publish_view(
            &key_id,
            &view,
            bounds,
            SyncState::Scanning {
                from: start,
                to: end,
            },
            format!(
                "scanning {}..{} ({:?})",
                u32::from(start),
                u32::from(end) - 1,
                range.priority()
            ),
        );

        self.ensure_cached(&range, bounds).await?;
        let prior = self.chain.chain_state(start - 1).await?;

        let params = self.state.registry.params();
        let cache = self.cache.clone();
        let scan_range = range.clone();
        let t0 = Instant::now();
        let outcome = with_wallet(key, move |w| {
            core_sync::scan_range(&params, &cache, w, &scan_range, &prior)
        })
        .await?;

        match outcome {
            ScanOutcome::Scanned {
                summary,
                transparent_outputs,
            } => {
                let scanned = summary.scanned_range();
                let n = u32::from(scanned.end).saturating_sub(u32::from(scanned.start));
                self.rates.entry(key_id.clone()).or_default().record(n);
                tracing::info!(
                    key_id,
                    from = u32::from(scanned.start),
                    to = u32::from(scanned.end) - 1,
                    sapling_received = summary.received_sapling_note_count(),
                    orchard_received = summary.received_orchard_note_count(),
                    transparent_outputs,
                    ms = t0.elapsed().as_millis(),
                    "batch scanned"
                );
                let view = with_wallet(key, move |w| WalletView::read(w, None)).await?;
                let new_tip = view.scanned_tip();
                let state = if view.next_range(1).is_none() {
                    SyncState::Synced {
                        spendable: view.is_spendable(tip),
                    }
                } else {
                    SyncState::Scanning {
                        from: start,
                        to: end,
                    }
                };
                self.publish_view(&key_id, &view, bounds, state, String::new());
                Ok((true, new_tip))
            }
            ScanOutcome::Reorg { at_height } => {
                self.handle_reorg(key, at_height).await?;
                Ok((true, scanned_tip))
            }
        }
    }

    /// Make sure every block of `range` is in the cache, fetching in
    /// `cache.fetch_batch` chunks and checking each chunk links to what the
    /// cache already holds.
    async fn ensure_cached(&self, range: &ScanRange, bounds: &NodeBounds) -> Result<(), SyncError> {
        let Range { start, end } = range.block_range().clone();
        let have = match self.cache.read(range).await {
            Ok(blocks) => blocks.len() as u32,
            Err(CacheError::Gap { .. }) => {
                self.cache.delete(range.clone()).await?;
                0
            }
            Err(e) => return Err(e.into()),
        };
        let fetch_batch = self.state.config.cache.fetch_batch.max(1);
        let mut next = start + have;
        while next < end {
            let chunk_end = (next + fetch_batch).min(end);
            let blocks = self.chain.compact_blocks(next..chunk_end).await?;
            let Some(first) = blocks.first() else {
                return Err(SyncError::Chain(ChainError::BlockUnavailable {
                    height: next,
                }));
            };
            if next > BlockHeight::from_u32(0)
                && let Some(prev) = self.cache.hash_at(next - 1)?
                && first.prev_hash != prev
            {
                // The cache's block at `next - 1` is off the node's chain.
                // Drop it and let the next tick's reconciliation find the
                // fork point.
                self.cache.truncate((next - 1).saturating_sub(1)).await?;
                return Err(SyncError::Scan(format!(
                    "cached block {} is not on the node's chain; re-syncing",
                    u32::from(next) - 1
                )));
            }
            let fetched = blocks.len() as u32;
            self.cache.insert_from(Source::Node, &blocks)?;
            tracing::debug!(
                from = u32::from(next),
                to = u32::from(next) + fetched - 1,
                tip = u32::from(bounds.tip_height),
                "blocks cached"
            );
            next = next + fetched;
        }
        Ok(())
    }

    /// SYNC.md §4.3: find the fork point by walking back from `at_height - 1`
    /// over the wallet's stored hashes, truncate the wallet to it, and let
    /// the next tick rescan from there.
    async fn handle_reorg(
        &self,
        key: &Arc<KeyEntry>,
        at_height: BlockHeight,
    ) -> Result<(), SyncError> {
        let key_id = key.key_id().to_string();
        let from = at_height.saturating_sub(1);
        self.hub().update(&key_id, |p| {
            p.state = SyncState::Rewinding { to: from };
            p.detail = format!(
                "reorg detected at {}; searching for the fork point",
                u32::from(at_height)
            );
        });
        let hashes = with_wallet(key, move |w| core_sync::wallet_hashes(w, from)).await?;
        let mut fork = None;
        for (h, wallet_hash) in hashes {
            match wallet_hash {
                // The wallet has nothing at `h`: nothing older to disagree about.
                None => {
                    fork = Some(h);
                    break;
                }
                Some(wh) => {
                    if self.trusted_hash(h).await? == Some(wh) {
                        fork = Some(h);
                        break;
                    }
                }
            }
        }
        match fork {
            Some(f) => {
                let actual = with_wallet(key, move |w| core_sync::rewind(w, f)).await?;
                tracing::warn!(
                    key_id,
                    detected_at = u32::from(at_height),
                    fork_point = u32::from(f),
                    truncated_to = u32::from(actual),
                    "reorg: wallet rewound"
                );
                self.hub().update(&key_id, |p| {
                    p.state = SyncState::Rewinding { to: actual };
                    p.scanned_tip = u32::from(actual);
                    p.detail =
                        format!("rewound to {} after a reorg; rescanning", u32::from(actual));
                });
                Ok(())
            }
            None => {
                let detail = format!(
                    "no fork point within {FINALITY_DEPTH} blocks below {}; the wallet's chain view is inconsistent with the node; \
                     fix with `gyges sync run --from <height>`",
                    u32::from(at_height)
                );
                tracing::error!(
                    key_id,
                    detected_at = u32::from(at_height),
                    "key stalled: chain inconsistent"
                );
                self.hub().update(&key_id, |p| {
                    p.state = SyncState::Stalled(StallReason::ChainInconsistent);
                    p.detail = detail;
                });
                Ok(())
            }
        }
    }

    fn publish_view(
        &self,
        key_id: &str,
        view: &WalletView,
        bounds: &NodeBounds,
        state: SyncState,
        detail: String,
    ) {
        let tip = bounds.tip_height;
        let rate = self.rates.get(key_id).map_or(0.0, Rate::per_sec);
        self.hub().publish(KeyProgress {
            key_id: key_id.to_string(),
            state,
            scanned_tip: u32::from(view.scanned_tip()),
            chain_tip: u32::from(tip),
            scanned: view.is_scanned(tip),
            spendable: view.is_spendable(tip),
            blocks_remaining: view.blocks_remaining(),
            blocks_per_sec: rate,
            detail,
            updated_at: SystemTime::now(),
        });
    }
}

fn whole(lo: BlockHeight, hi: BlockHeight) -> ScanRange {
    ScanRange::from_parts(lo..hi + 1, ScanPriority::Ignored)
}

fn clamp_end(range: &ScanRange, max_end: BlockHeight) -> ScanRange {
    let Range { start, end } = range.block_range().clone();
    ScanRange::from_parts(start..end.min(max_end).max(start), range.priority())
}

/// Run `f` with the key's wallet on a blocking thread.
async fn with_wallet<T: Send + 'static>(
    key: &Arc<KeyEntry>,
    f: impl FnOnce(&mut gyges_core::registry::Wallet) -> Result<T, SyncError> + Send + 'static,
) -> Result<T, SyncError> {
    let key = key.clone();
    tokio::task::spawn_blocking(move || {
        let mut guard = key
            .wallet()
            .ok_or_else(|| SyncError::Wallet("this profile has no wallet".into()))?;
        f(&mut guard)
    })
    .await
    .map_err(|e| SyncError::Wallet(format!("scan task failed: {e}")))?
}

// ---------------------------------------------------------------------------
// RPC side
// ---------------------------------------------------------------------------

/// `gyges_core` state → wire enums.
pub fn proto_state(state: &SyncState) -> (v1::SyncState, v1::StallReason) {
    match state {
        SyncState::Initializing | SyncState::Synced { .. } => {
            (v1::SyncState::Idle, v1::StallReason::Unspecified)
        }
        SyncState::Scanning { .. } => (v1::SyncState::Scanning, v1::StallReason::Unspecified),
        SyncState::Rewinding { .. } => (v1::SyncState::Rewinding, v1::StallReason::Unspecified),
        SyncState::Stalled(reason) => (
            v1::SyncState::Stalled,
            match reason {
                StallReason::PrunedPastScanTip => v1::StallReason::PrunedPastScanTip,
                StallReason::ChainInconsistent => v1::StallReason::ChainInconsistent,
                StallReason::Offline => v1::StallReason::NodeUnreachable,
            },
        ),
    }
}

/// One `KeySyncStatus` row.
pub fn to_proto(p: &KeyProgress) -> KeySyncStatus {
    let (state, stall_reason) = proto_state(&p.state);
    KeySyncStatus {
        key_id: p.key_id.clone(),
        state: state as i32,
        stall_reason: stall_reason as i32,
        backend: v1::SyncBackend::ZakuraRpc as i32,
        scanned_tip: p.scanned_tip,
        chain_tip: p.chain_tip,
        scanned: p.scanned,
        spendable: p.spendable,
        blocks_per_sec: p.blocks_per_sec,
        blocks_remaining: p.blocks_remaining,
        // ShardTree witness health arrives with `ListNotes`.
        notes_awaiting_witness: 0,
        detail: if p.detail.is_empty() {
            p.state.name()
        } else {
            format!("{}: {}", p.state.name(), p.detail)
        },
    }
}

/// Resolve a request's key to one that has a wallet (sync is meaningless
/// for `signer-only`).
fn resolve_synced_key(state: &DaemonState, key_id: &str) -> Result<Arc<KeyEntry>, Status> {
    let key = state
        .registry
        .resolve(key_id)
        .map_err(|e| registry_error(e).into_status())?;
    if !key.profile().has_wallet() {
        return Err(GygesError::new(
            ErrorReason::InvalidArgument,
            "a signer-only profile has no wallet to synchronise",
        )
        .with_key(key.key_id())
        .into_status());
    }
    Ok(key)
}

fn progress_of(state: &DaemonState, key_id: &str) -> KeyProgress {
    state
        .sync
        .get(key_id)
        .unwrap_or_else(|| KeyProgress::initializing(key_id))
}

/// `GetSyncStatus`: every wallet-bearing key, or one.
pub fn get_sync_status(
    state: &DaemonState,
    req: GetSyncStatusRequest,
) -> Result<GetSyncStatusResponse, Status> {
    let keys = if req.key_id.is_empty() && state.registry.default_key().is_empty() {
        state
            .registry
            .list()
            .into_iter()
            .filter(|k| k.profile().has_wallet())
            .map(|k| to_proto(&progress_of(state, k.key_id())))
            .collect()
    } else if req.key_id.is_empty() {
        // An empty key_id with a default configured still means "all keys"
        // for status (CLI_SPEC.md §2.3 `--all`), unlike the other RPCs.
        state
            .registry
            .list()
            .into_iter()
            .filter(|k| k.profile().has_wallet())
            .map(|k| to_proto(&progress_of(state, k.key_id())))
            .collect()
    } else {
        let key = resolve_synced_key(state, &req.key_id)?;
        vec![to_proto(&progress_of(state, key.key_id()))]
    };
    Ok(GetSyncStatusResponse { keys })
}

/// The server-streaming response type for `WaitSync` and `RunSync` (what
/// `tonic`'s default stubs use).
pub type ProgressStream = tonic::codegen::BoxStream<SyncProgress>;

/// When a progress stream ends.
#[derive(Clone, Debug)]
enum Until {
    Scanned,
    Spendable,
    /// `txid` (internal order) has at least this many confirmations.
    Confirmations {
        txid: [u8; 32],
        wanted: u32,
    },
}

fn stalled_status(p: &KeyProgress) -> Status {
    GygesError::new(ErrorReason::NotSynced, to_proto(p).detail)
        .with_key(&p.key_id)
        .into_status()
}

/// `WaitSync` (API.md §4.4): stream progress until the target holds; a
/// stalled key fails the stream at once with `NOT_SYNCED`.
pub fn wait_sync(state: Arc<DaemonState>, req: WaitSyncRequest) -> Result<ProgressStream, Status> {
    let key = resolve_synced_key(&state, &req.key_id)?;
    let until = if req.txid.is_empty() {
        match req.until() {
            SyncTarget::Scanned => Until::Scanned,
            SyncTarget::Spendable | SyncTarget::Unspecified => Until::Spendable,
        }
    } else {
        let txid = gyges_chain::parse_display_hash(&req.txid).map_err(|e| {
            GygesError::new(ErrorReason::InvalidArgument, format!("txid: {e}")).into_status()
        })?;
        Until::Confirmations {
            txid,
            wanted: req.confirmations.max(1),
        }
    };
    Ok(progress_stream(state, key, until, false))
}

/// `RunSync` (API.md §4.4): wake the scheduler, optionally after queueing a
/// rewind, and stream until the key is spendable at the tip.
pub fn run_sync(state: Arc<DaemonState>, req: RunSyncRequest) -> Result<ProgressStream, Status> {
    let key = resolve_synced_key(&state, &req.key_id)?;
    if req.to_height != 0 || req.force_tor_lwd {
        return Err(GygesError::new(
            ErrorReason::InvalidArgument,
            "--to and --force-tor-lwd are not supported in this milestone (ROADMAP.md M2)",
        )
        .into_status());
    }
    if req.from_height != 0 {
        let current = progress_of(&state, key.key_id()).scanned_tip;
        let birthday = key.profile().birthday_height.unwrap_or(0);
        if req.from_height <= current {
            if !req.confirm_rewind {
                return Err(GygesError::new(
                    ErrorReason::ConfirmationRequired,
                    format!(
                        "rescanning from {} rewinds the wallet from {current}; notes, nullifiers and witnesses above {} are rebuilt; confirm with --yes",
                        req.from_height,
                        req.from_height.saturating_sub(1)
                    ),
                )
                .with_key(key.key_id())
                .into_status());
            }
            let from = req.from_height.max(birthday);
            state
                .sync
                .request_rewind(key.key_id(), BlockHeight::from_u32(from));
            tracing::info!(target: crate::keys::AUDIT_TARGET, key_id = key.key_id(), event = "rewind", from);
        }
    }
    state.sync.wake();
    Ok(progress_stream(
        state,
        key,
        Until::Spendable,
        req.from_height != 0,
    ))
}

fn progress_stream(
    state: Arc<DaemonState>,
    key: Arc<KeyEntry>,
    until: Until,
    wait_for_rewind: bool,
) -> ProgressStream {
    let (tx, rx) = mpsc::channel::<Result<SyncProgress, Status>>(8);
    tokio::spawn(async move {
        let key_id = key.key_id().to_string();
        let mut changes = state.sync.subscribe();
        // The snapshot in the hub may predate blocks the node has since
        // mined, and a tick already in flight polled the node before now:
        // ask for a tick and only call it done once a tick that began after
        // this point has completed.
        let need_completed = state.sync.ticks().0 + 1;
        state.sync.wake();
        let mut rewind_seen_applied = !wait_for_rewind;
        loop {
            let p = progress_of(&state, &key_id);
            let fresh = state.sync.ticks().1 >= need_completed;
            if !rewind_seen_applied && !state.sync.rewind_pending(&key_id) {
                rewind_seen_applied = true;
            }
            if p.state.is_stalled() {
                let _ = tx.send(Err(stalled_status(&p))).await;
                return;
            }
            let ready = fresh && rewind_seen_applied && p.chain_tip > 0;
            let (confirmations, done) = match &until {
                Until::Scanned => (0, ready && p.scanned),
                Until::Spendable => (0, ready && p.spendable),
                Until::Confirmations { txid, wanted } => {
                    let txid = *txid;
                    let height = tokio::task::spawn_blocking({
                        let key = key.clone();
                        move || {
                            key.wallet()
                                .and_then(|w| core_sync::tx_height(&w, txid).ok().flatten())
                        }
                    })
                    .await
                    .ok()
                    .flatten();
                    let confs =
                        height.map_or(0, |h| (p.chain_tip + 1).saturating_sub(u32::from(h)));
                    (confs, ready && confs >= *wanted)
                }
            };
            let item = SyncProgress {
                status: Some(to_proto(&p)),
                confirmations,
                done,
            };
            if tx.send(Ok(item)).await.is_err() || done {
                return;
            }
            // Wake on a change, or heartbeat once per second when idle.
            tokio::select! {
                _ = changes.changed() => {}
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    });
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_averages_over_the_window() {
        let mut r = Rate::default();
        assert_eq!(r.per_sec(), 0.0);
        r.record(600);
        r.record(600);
        // Elapsed is clamped to at least one second.
        assert!(r.per_sec() <= 1200.0 && r.per_sec() > 0.0);
    }

    #[test]
    fn proto_mapping_covers_every_state() {
        assert_eq!(proto_state(&SyncState::Initializing).0, v1::SyncState::Idle);
        assert_eq!(
            proto_state(&SyncState::Stalled(StallReason::Offline)),
            (v1::SyncState::Stalled, v1::StallReason::NodeUnreachable)
        );
        let mut p = KeyProgress::initializing("k");
        p.state = SyncState::Stalled(StallReason::ChainInconsistent);
        p.detail = "x".into();
        let row = to_proto(&p);
        assert_eq!(row.stall_reason, v1::StallReason::ChainInconsistent as i32);
        assert_eq!(row.detail, "stalled(chain-inconsistent): x");
        assert_eq!(row.backend, v1::SyncBackend::ZakuraRpc as i32);
    }

    #[test]
    fn hub_publishes_and_bumps_generation() {
        let hub = SyncHub::default();
        let rx = hub.subscribe();
        assert_eq!(*rx.borrow(), 0);
        hub.update("a", |p| p.scanned_tip = 5);
        assert_eq!(hub.get("a").unwrap().scanned_tip, 5);
        assert_eq!(*rx.borrow(), 1);
        hub.request_rewind("a", BlockHeight::from_u32(3));
        assert!(hub.rewind_pending("a"));
        assert_eq!(hub.take_rewind("a"), Some(BlockHeight::from_u32(3)));
        assert!(!hub.rewind_pending("a"));
        hub.forget("a");
        assert!(hub.snapshot().is_empty());
    }

    #[test]
    fn clamp_end_never_inverts() {
        let r = ScanRange::from_parts(
            BlockHeight::from_u32(10)..BlockHeight::from_u32(20),
            ScanPriority::Historic,
        );
        assert_eq!(clamp_end(&r, BlockHeight::from_u32(15)).len(), 5);
        assert!(clamp_end(&r, BlockHeight::from_u32(5)).is_empty());
        assert_eq!(clamp_end(&r, BlockHeight::from_u32(50)).len(), 10);
    }
}
