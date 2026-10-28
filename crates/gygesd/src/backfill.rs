//! Case B: backfill below the node's retention window from the fallback
//! endpoint, and the handoff back to Case A (SYNC.md §3, §4.2, §5).
//!
//! A key whose next scan range starts below `retained_from` (a restore
//! with an old birthday, or the pruning race after a long downtime) opens a
//! *backfill session*: the endpoint's subtree roots are checked against the
//! node's and handed to the wallet (check 3), then each tick fetches one
//! `cache.scan_batch` of blocks through [`gyges_chain::fill_cache`] (tagged
//! with the endpoint's source), checks the batch's last hash against the
//! node's `getblockhash` (check 2) and scans it. Once the key has scanned
//! `V = min(retained_from + overlap_blocks, tip)`, the wallet's note
//! commitment trees and recorded hashes are compared with the node at `V`
//! (checks 1 and 2); only then does the key return to Case A.
//!
//! The session is recorded in `keys/<id>/backfill.json` so that a daemon
//! restarted between the last backfilled batch and the handoff still
//! validates before scanning on. A failed check marks the endpoint
//! untrusted in `fallback_trust.json` (shown in `GetInfo.fallback`, cleared
//! only by configuring another endpoint), truncates the key to the block
//! before the session began, and stalls it with `UntrustedBackfill`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use gyges_chain::{
    ArtiTorLwdBackend, ChainBackend, ChainError, FillError, NodeBounds, Source, TorState,
};
use gyges_core::KeyEntry;
use gyges_core::handoff::{self, Check, Mismatch};
use gyges_core::network::ConsensusParams;
use gyges_core::recovery::{self, Placement, Report};
use gyges_core::sync::{self as core_sync, ScanOutcome, StallReason, SyncError, SyncState};
use gyges_proto::v1;
use serde::{Deserialize, Serialize};
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;

use crate::service::DaemonState;
use crate::sync::Scheduler;
use crate::with_wallet;

/// What the daemon knows about the fallback endpoint (`GetInfo.fallback`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Trust {
    /// No backfill has been validated against the node yet.
    #[default]
    Untested,
    /// A backfill from it passed the handoff checks.
    Verified,
    /// A handoff check failed; backfill from it is refused.
    Untrusted { reason: String },
}

/// The persisted form of an untrusted mark (`<network>/fallback_trust.json`).
#[derive(Debug, Serialize, Deserialize)]
struct TrustFile {
    endpoint: String,
    reason: String,
    marked_at: i64,
}

#[derive(Debug, Default)]
struct TrustInner {
    trust: Trust,
    endpoint: String,
    path: Option<PathBuf>,
}

/// The endpoint's trust state, shared by the scheduler and `GetInfo`.
#[derive(Debug, Default)]
pub struct TrustHub {
    inner: Mutex<TrustInner>,
}

impl TrustHub {
    /// Read the persisted mark at `path`. A mark for another endpoint is a
    /// config change, which clears it.
    pub fn load(&self, path: PathBuf, endpoint: &str) {
        let mut inner = self.lock();
        inner.endpoint = endpoint.to_string();
        inner.trust = Trust::Untested;
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<TrustFile>(&bytes) {
                Ok(f) if f.endpoint == endpoint => {
                    tracing::warn!(
                        endpoint,
                        reason = %f.reason,
                        "fallback endpoint is marked untrusted; configure another to backfill"
                    );
                    inner.trust = Trust::Untrusted { reason: f.reason };
                }
                Ok(f) => {
                    tracing::info!(
                        previous = %f.endpoint,
                        endpoint,
                        "fallback endpoint changed; the untrusted mark is cleared"
                    );
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "unreadable fallback trust file ignored");
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read the fallback trust file");
            }
        }
        inner.path = Some(path);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TrustInner> {
        crate::lock(&self.inner)
    }

    pub fn get(&self) -> Trust {
        self.lock().trust.clone()
    }

    fn mark_verified(&self) {
        let mut inner = self.lock();
        if inner.trust == Trust::Untested {
            inner.trust = Trust::Verified;
        }
    }

    fn mark_untrusted(&self, reason: String) {
        let mut inner = self.lock();
        if let Some(path) = &inner.path {
            let file = TrustFile {
                endpoint: inner.endpoint.clone(),
                reason: reason.clone(),
                marked_at: crate::service::unix_now(),
            };
            if let Err(e) = write_private_json(path, &file) {
                tracing::error!(path = %path.display(), error = %e, "cannot persist the untrusted mark");
            }
        }
        inner.trust = Trust::Untrusted { reason };
    }
}

/// `GetInfo.fallback.trust`.
pub fn proto_trust(state: &DaemonState) -> v1::FallbackTrust {
    if state.fallback.is_none() {
        return v1::FallbackTrust::Unspecified;
    }
    match state.fallback_trust.get() {
        Trust::Untested => v1::FallbackTrust::Untested,
        Trust::Verified => v1::FallbackTrust::Verified,
        Trust::Untrusted { .. } => v1::FallbackTrust::Untrusted,
    }
}

/// `GetInfo.tor`: the embedded Tor client behind the fallback endpoint.
pub fn tor_status(state: &DaemonState) -> v1::TorStatus {
    let Some(fallback) = &state.fallback else {
        return v1::TorStatus {
            state: v1::TorState::Disabled as i32,
            ..Default::default()
        };
    };
    let (s, last_error) = match fallback.tor_state() {
        TorState::Disabled => (v1::TorState::Disabled, String::new()),
        // Not bootstrapped yet: arti starts on the first backfill.
        TorState::NotStarted => (v1::TorState::Unspecified, String::new()),
        TorState::Bootstrapping => (v1::TorState::Bootstrapping, String::new()),
        TorState::Ready => (v1::TorState::Ready, String::new()),
        TorState::Failed(e) => (v1::TorState::Failed, e),
    };
    v1::TorStatus {
        state: s as i32,
        bootstrap_percent: if s == v1::TorState::Ready { 100 } else { 0 },
        last_error,
    }
}

/// A key's open backfill (`keys/<id>/backfill.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// First height scanned from the endpoint; a failed handoff truncates
    /// the key to `from - 1`.
    pub from: u32,
    pub endpoint: String,
}

fn session_path(key: &KeyEntry) -> PathBuf {
    key.dir().join("backfill.json")
}

/// The persisted session of `key`, if one is open.
pub fn load_session(key: &KeyEntry) -> Option<Session> {
    let path = session_path(key);
    let bytes = std::fs::read(&path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "unreadable backfill marker ignored");
            None
        }
    }
}

/// Write `value` as pretty JSON to a new owner-only file at `path`.
fn write_private_json(path: &Path, value: &impl Serialize) -> std::io::Result<()> {
    use std::io::Write as _;
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    gyges_core::perms::create_private_file(path)?.write_all(&bytes)
}

fn report_path(key: &KeyEntry) -> PathBuf {
    key.dir().join("transparent_recovery.json")
}

/// The key's last transparent recovery (`keys/<id>/transparent_recovery.json`),
/// if it was ever backfilled below the node's window.
pub fn load_report(key: &KeyEntry) -> Option<Report> {
    serde_json::from_slice(&std::fs::read(report_path(key)).ok()?).ok()
}

fn save_report(key: &KeyEntry, report: &Report) {
    if let Err(e) = write_private_json(&report_path(key), report) {
        tracing::warn!(error = %e, "cannot record the transparent recovery");
    }
}

fn clear_session(key: &KeyEntry) {
    let path = session_path(key);
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), error = %e, "cannot remove the backfill marker");
    }
}

/// Where the untrusted mark lives.
pub fn trust_path(network_dir: &Path) -> PathBuf {
    network_dir.join("fallback_trust.json")
}

/// The handoff height for the current bounds.
fn handoff_height(bounds: &NodeBounds, overlap: u32) -> BlockHeight {
    (bounds.retained_from + overlap).min(bounds.tip_height)
}

/// `FillError` from the endpoint → what the scheduler does with it.
fn fill_error(e: FillError) -> SyncError {
    match e {
        FillError::Chain(e) => SyncError::Fallback(e),
        FillError::Cache(e) => SyncError::Cache(e),
        unlinked @ FillError::Unlinked { .. } => {
            SyncError::Untrusted(Mismatch::new(Check::HashChain, unlinked.to_string()))
        }
    }
}

/// Subtree roots of every pool from one source. The node's errors are not
/// fatal (a node without the index, or one still building it, confirms
/// nothing); the endpoint being unreachable is.
async fn subtree_roots(
    source: &dyn ChainBackend,
    is_fallback: bool,
) -> Result<Vec<gyges_chain::SubtreeRoot>, SyncError> {
    let mut out = Vec::new();
    for pool in [
        ShieldedPool::Sapling,
        ShieldedPool::Orchard,
        ShieldedPool::Ironwood,
    ] {
        match source.subtree_roots(pool, 0, 0).await {
            Ok(roots) => out.extend(roots),
            Err(e @ ChainError::Unreachable(_)) if is_fallback => {
                return Err(SyncError::Fallback(e));
            }
            Err(e) => {
                tracing::debug!(
                    pool = gyges_chain::pool_name(pool),
                    fallback = is_fallback,
                    error = %e,
                    "no subtree roots"
                );
            }
        }
    }
    Ok(out)
}

impl Scheduler {
    /// The key's open session, read from disk the first time it is asked.
    fn session(&mut self, key: &KeyEntry) -> Option<Session> {
        self.backfills
            .entry(key.key_id().to_string())
            .or_insert_with(|| load_session(key))
            .clone()
    }

    fn set_session(&mut self, key: &KeyEntry, session: Option<Session>) {
        match &session {
            Some(s) => {
                if let Err(e) = write_private_json(&session_path(key), s) {
                    tracing::error!(key_id = key.key_id(), error = %e, "cannot write the backfill marker");
                }
            }
            None => clear_session(key),
        }
        self.backfills.insert(key.key_id().to_string(), session);
    }

    /// Whether `key` is in a backfill session (checked before Case A, so
    /// that a key never scans on from the node before its handoff).
    pub(crate) fn in_backfill(&mut self, key: &KeyEntry) -> bool {
        self.session(key).is_some()
    }

    /// The fallback endpoint if the key may backfill from it; otherwise the
    /// key is stalled. Without an endpoint (removed from the config with a
    /// session open) the key waits for the node to serve its next block.
    fn usable_fallback(
        &self,
        key_id: &str,
        scanned_tip: BlockHeight,
        bounds: &NodeBounds,
    ) -> Option<Arc<ArtiTorLwdBackend<ConsensusParams>>> {
        let Some(fallback) = self.state.fallback.clone() else {
            self.stall_pruned(key_id, u32::from(scanned_tip) + 1, bounds);
            return None;
        };
        if let Trust::Untrusted { reason } = self.state.fallback_trust.get() {
            self.stall_untrusted(key_id, &reason);
            return None;
        }
        Some(fallback)
    }

    /// SYNC.md §4.2: the next range starts below the node's window. With a
    /// usable endpoint, open a session (check 3 first) and backfill;
    /// otherwise stall.
    pub(crate) async fn enter_backfill(
        &mut self,
        key: &Arc<KeyEntry>,
        bounds: &NodeBounds,
        scanned_tip: BlockHeight,
    ) -> Result<(bool, BlockHeight), SyncError> {
        let key_id = key.key_id().to_string();
        let Some(fallback) = self.usable_fallback(&key_id, scanned_tip, bounds) else {
            return Ok((false, scanned_tip));
        };
        let session = Session {
            from: u32::from(scanned_tip) + 1,
            endpoint: fallback.endpoint(),
        };
        tracing::warn!(
            key_id,
            scanned_tip = u32::from(scanned_tip),
            retained_from = u32::from(bounds.retained_from),
            endpoint = %fallback.endpoint(),
            "node pruned past the key's scan position; backfilling from the fallback endpoint"
        );

        // Check 3, before anything from the endpoint reaches the wallet.
        let fb_roots = subtree_roots(fallback.as_ref(), true).await?;
        let node_roots = subtree_roots(self.chain.as_ref(), false).await?;
        let agreed = match handoff::agreed_subtree_roots(&fb_roots, &node_roots) {
            Ok(a) => a,
            Err(m) => {
                self.refuse(key, &session, m).await;
                return Ok((false, scanned_tip));
            }
        };
        if !agreed.is_empty() {
            let n = agreed.len();
            with_wallet(key, move |w| handoff::put_subtree_roots(w, &agreed)).await?;
            tracing::info!(key_id, roots = n, "node-confirmed subtree roots added");
        }
        self.set_session(key, Some(session));
        self.step_backfill(key, bounds, scanned_tip).await
    }

    /// One tick of an open session: validate if the key has reached the
    /// handoff height, else backfill one batch.
    pub(crate) async fn step_backfill(
        &mut self,
        key: &Arc<KeyEntry>,
        bounds: &NodeBounds,
        scanned_tip: BlockHeight,
    ) -> Result<(bool, BlockHeight), SyncError> {
        let Some(session) = self.session(key) else {
            return Ok((false, scanned_tip));
        };
        let result = self.backfill_or_validate(key, bounds, scanned_tip).await;
        match result {
            Err(SyncError::Untrusted(m)) => {
                self.refuse(key, &session, m).await;
                Ok((false, scanned_tip))
            }
            other => other,
        }
    }

    async fn backfill_or_validate(
        &mut self,
        key: &Arc<KeyEntry>,
        bounds: &NodeBounds,
        scanned_tip: BlockHeight,
    ) -> Result<(bool, BlockHeight), SyncError> {
        let key_id = key.key_id().to_string();
        let overlap = self.state.config.fallback_lightwalletd.overlap_blocks;
        let v = handoff_height(bounds, overlap);
        if scanned_tip >= v {
            return self.validate(key, bounds, scanned_tip).await;
        }

        let Some(fallback) = self.usable_fallback(&key_id, scanned_tip, bounds) else {
            return Ok((false, scanned_tip));
        };
        let via_tor = !matches!(fallback.transport(), gyges_chain::Transport::Direct);
        let start = scanned_tip + 1;
        let batch = self.state.config.cache.scan_batch.max(1);
        let end = (start + batch).min(v + 1);
        self.hub().update(&key_id, |p| {
            p.state = SyncState::Backfilling {
                via_tor,
                from: start,
                to: end,
            };
            p.scanned_tip = u32::from(scanned_tip);
            p.chain_tip = u32::from(bounds.tip_height);
            p.detail = format!(
                "backfilling {}..{} from {}; handoff at {}",
                u32::from(start),
                u32::from(end) - 1,
                fallback.endpoint(),
                u32::from(v)
            );
        });

        // Fetch what the cache does not already hold.
        let range = ScanRange::from_parts(start..end, ScanPriority::Historic);
        let have = self.cached_prefix(&range).await?;
        if start + have < end {
            gyges_chain::fill_cache(
                fallback.as_ref(),
                &self.cache,
                start + have..end,
                self.state.config.cache.fetch_batch,
            )
            .await
            .map_err(fill_error)?;
        }

        // Check 2 at every batch boundary: the endpoint's last block is the
        // node's, so a fork never reaches the wallet.
        let last = end - 1;
        let cached = self.cache.hash_at(last)?;
        let node = self.chain.block_hash(last).await?;
        if cached != Some(node) {
            return Err(SyncError::Untrusted(Mismatch::new(
                Check::HashChain,
                format!(
                    "block {} from the endpoint is {}, the node's is {}",
                    u32::from(last),
                    cached.map_or_else(|| "missing".into(), |h| gyges_chain::display_hash(&h)),
                    gyges_chain::display_hash(&node)
                ),
            )));
        }

        // The prior tree state: the node's where it still has it, else the
        // endpoint's (checked at the handoff through the root).
        let prior = if scanned_tip >= bounds.retained_from {
            self.chain.chain_state(scanned_tip).await?
        } else {
            fallback
                .chain_state(scanned_tip)
                .await
                .map_err(SyncError::Fallback)?
        };

        let outcome = match self.scan(key, &range, prior).await {
            Ok(o) => o,
            // Every block of the batch came from the endpoint: a block the
            // scanner refuses (tree sizes that do not add up, bad encoding)
            // is the endpoint's.
            Err(SyncError::Scan(detail)) => {
                return Err(SyncError::Untrusted(Mismatch::new(
                    Check::TreeRoots,
                    format!("the endpoint's blocks do not scan: {detail}"),
                )));
            }
            // The wallet's tree refused the batch's commitments or its
            // prior frontier. The batch and, below the window, its prior
            // tree state are the endpoint's, and the tree holds only what
            // the node or earlier batches put there, which the handoff
            // would check: the conflict is the endpoint's. Retrying would
            // fail the same way every tick.
            Err(SyncError::TreeRefused(detail)) => {
                return Err(SyncError::Untrusted(Mismatch::new(
                    Check::TreeRoots,
                    format!("the wallet's commitment tree refused the endpoint's data: {detail}"),
                )));
            }
            Err(e) => return Err(e),
        };
        match outcome {
            ScanOutcome::Scanned { summary, .. } => {
                let scanned = summary.scanned_range();
                let n = u32::from(scanned.end).saturating_sub(u32::from(scanned.start));
                self.record_rate(&key_id, n);
                tracing::info!(
                    key_id,
                    from = u32::from(scanned.start),
                    to = u32::from(scanned.end) - 1,
                    sapling_received = summary.received_sapling_note_count(),
                    orchard_received = summary.received_orchard_note_count(),
                    "backfill batch scanned"
                );
                let rate = self.rate(&key_id);
                let new_tip = end - 1;
                self.hub().update(&key_id, |p| {
                    p.scanned_tip = u32::from(new_tip);
                    p.blocks_per_sec = rate;
                });
                Ok((true, new_tip))
            }
            ScanOutcome::Reorg { at_height } => Err(SyncError::Untrusted(Mismatch::new(
                Check::HashChain,
                format!(
                    "block {} from the endpoint does not link to the wallet's block below it",
                    u32::from(at_height)
                ),
            ))),
        }
    }

    /// Checks 1 and 2 at `height` (the key's scanned tip, inside the node's
    /// window). On success the session closes and the key is back in
    /// Case A.
    async fn validate(
        &mut self,
        key: &Arc<KeyEntry>,
        bounds: &NodeBounds,
        height: BlockHeight,
    ) -> Result<(bool, BlockHeight), SyncError> {
        let key_id = key.key_id().to_string();
        let Some(session) = self.session(key) else {
            return Ok((false, height));
        };
        let from = BlockHeight::from_u32(session.from);

        // Check 2: the wallet's recorded hashes at the handoff height, at
        // the window's edge and at the first backfilled block are the
        // node's.
        let mut heights = vec![height];
        for h in [bounds.retained_from, from] {
            if h >= from && h < height && !heights.contains(&h) {
                heights.push(h);
            }
        }
        for h in heights {
            let wallet = with_wallet(key, move |w| handoff::wallet_hash(w, h)).await?;
            let node = self.chain.block_hash(h).await?;
            match wallet {
                Some(w) if w == node => {}
                // The wallet keeps no row for some blocks it scanned; only
                // the handoff block itself must be there.
                None if h != height => {}
                other => {
                    return Err(SyncError::Untrusted(Mismatch::new(
                        Check::HashChain,
                        format!(
                            "block {} in the wallet is {}, the node's is {}",
                            u32::from(h),
                            other.map_or_else(
                                || "missing".into(),
                                |w| gyges_chain::display_hash(&w)
                            ),
                            gyges_chain::display_hash(&node)
                        ),
                    )));
                }
            }
        }

        // Check 1: tree sizes and roots at the handoff height.
        let node_state = self.chain.chain_state(height).await?;
        let verdict =
            with_wallet(key, move |w| handoff::check_trees(w, height, &node_state)).await?;
        if let Err(m) = verdict {
            return Err(SyncError::Untrusted(m));
        }

        // Transparent history from the endpoint, before the session closes,
        // so an endpoint that drops out retries it on the next tick.
        let report = self
            .recover_transparent(key, session.from, height, bounds)
            .await?;
        save_report(key, &report);
        tracing::info!(
            key_id,
            credited = report.credited,
            unplaced = report.unplaced,
            discarded = report.discarded,
            best_effort_below = report.best_effort_below,
            "transparent outputs below the node's window recovered from the fallback endpoint (best-effort)"
        );

        self.set_session(key, None);
        self.state.fallback_trust.mark_verified();
        if !self.state.config.cache.keep_historical {
            let dropped = self.cache.evict_source_below(Source::TorLwd, height + 1)?;
            tracing::debug!(dropped, "fallback blocks dropped after the handoff");
        }
        tracing::info!(
            key_id,
            handoff = u32::from(height),
            from = session.from,
            endpoint = %session.endpoint,
            "backfill validated against the node; back to the node (Case A)"
        );
        self.hub().update(&key_id, |p| {
            p.state = SyncState::Scanning {
                from: height + 1,
                to: bounds.tip_height + 1,
            };
            p.scanned_tip = u32::from(height);
            p.detail = format!("handoff validated at {}", u32::from(height));
        });
        Ok((true, height))
    }

    /// SYNC.md §5.3: ask the endpoint for the unspent outputs of the key's
    /// transparent receivers mined in `[from, to]`, check each against its
    /// raw transaction and the node's chain (`gyges_core::recovery`), and
    /// credit the ones that pass. Crediting can reveal new receivers (the
    /// gap limit), which are asked about in the next pass.
    async fn recover_transparent(
        &self,
        key: &Arc<KeyEntry>,
        from: u32,
        to: BlockHeight,
        bounds: &NodeBounds,
    ) -> Result<Report, SyncError> {
        let mut report = Report {
            from,
            to: u32::from(to),
            best_effort_below: u32::from(bounds.retained_from),
            ..Report::default()
        };
        let Some(fallback) = self.state.fallback.clone() else {
            return Ok(report);
        };
        let key_id = key.key_id().to_string();
        let params = self.state.registry.params();
        let network = zcash_protocol::consensus::Parameters::network_type(&params);
        let mut asked = std::collections::HashSet::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            let receivers = with_wallet(key, move |w| recovery::receivers(w, network)).await?;
            let new: Vec<String> = receivers
                .into_iter()
                .map(|(_, s)| s)
                .filter(|s| !asked.contains(s))
                .collect();
            if new.is_empty() {
                break;
            }
            asked.extend(new.iter().cloned());
            let utxos = fallback
                .address_utxos(new, BlockHeight::from_u32(from))
                .await
                .map_err(SyncError::Fallback)?;
            let mut verified = Vec::new();
            for u in utxos {
                if u.height > to || u32::from(u.height) < from || !seen.insert((u.txid, u.index)) {
                    continue;
                }
                match self.place_utxo(&fallback, &params, &u, bounds).await? {
                    Ok((out, placement)) => {
                        if placement == Placement::Unplaced {
                            report.unplaced += 1;
                        }
                        verified.push(out);
                    }
                    Err(reason) => {
                        report.discarded += 1;
                        tracing::warn!(
                            key_id,
                            height = u32::from(u.height),
                            reason,
                            "a transparent output reported by the fallback endpoint was discarded"
                        );
                    }
                }
            }
            if verified.is_empty() {
                continue;
            }
            let n = with_wallet(key, move |w| core_sync::credit_transparent(w, &verified)).await?;
            report.credited += u32::try_from(n).unwrap_or(u32::MAX);
        }
        Ok(report)
    }

    /// The checks of `gyges_core::recovery` for one reported output: the
    /// outer error is a failure to ask (retried), the inner one the reason
    /// to discard the output.
    async fn place_utxo(
        &self,
        fallback: &gyges_chain::ArtiTorLwdBackend<gyges_core::ConsensusParams>,
        params: &gyges_core::ConsensusParams,
        u: &gyges_chain::AddressUtxo,
        bounds: &NodeBounds,
    ) -> Result<Result<(gyges_chain::compact::TransparentOutput, Placement), String>, SyncError>
    {
        let Some((raw, raw_height)) = fallback
            .raw_transaction(u.txid)
            .await
            .map_err(SyncError::Fallback)?
        else {
            return Ok(Err("the endpoint does not have the transaction".into()));
        };
        let (out, shielded) = match recovery::check_utxo(params, u, &raw, raw_height) {
            Ok(x) => x,
            Err(reason) => return Ok(Err(reason)),
        };
        let node_hash = match self.chain.block_hash(u.height).await {
            Ok(h) => h,
            Err(ChainError::BlockUnavailable { .. }) => {
                return Ok(Err("the node has no block at the reported height".into()));
            }
            Err(e) => return Err(e.into()),
        };
        // Where the node still has the block, it decides.
        if u.height >= bounds.retained_from {
            match self.chain.compact_blocks(u.height..u.height + 1).await {
                Ok(blocks) => {
                    return Ok(match blocks.first() {
                        Some(b)
                            if b.hash[..] == node_hash[..] && recovery::block_holds(b, &out) =>
                        {
                            Ok((out, Placement::Node))
                        }
                        _ => Err(
                            "the node's block at the reported height does not hold the output"
                                .into(),
                        ),
                    });
                }
                Err(ChainError::BlockUnavailable { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let blocks = fallback
            .block_range(u.height..u.height + 1)
            .await
            .map_err(SyncError::Fallback)?;
        let Some(b) = blocks.first() else {
            return Ok(Err(
                "the endpoint has no block at the reported height".into()
            ));
        };
        if b.hash[..] != node_hash[..] {
            return Ok(Err(
                "the endpoint's block at the reported height is not the node's".into(),
            ));
        }
        if recovery::block_holds(b, &out) {
            return Ok(Ok((out, Placement::EndpointBlock)));
        }
        if shielded {
            return Ok(Err(
                "a transaction with shielded parts is missing from the endpoint's block".into(),
            ));
        }
        Ok(Ok((out, Placement::Unplaced)))
    }

    /// A failed check: mark the endpoint untrusted, drop what came from it
    /// and stall the key.
    async fn refuse(&mut self, key: &Arc<KeyEntry>, session: &Session, m: Mismatch) {
        let key_id = key.key_id().to_string();
        tracing::error!(
            key_id,
            endpoint = %session.endpoint,
            check = m.check.name(),
            detail = %m.detail,
            "handoff validation failed; fallback endpoint marked untrusted"
        );
        let reason = format!("{}: {m}", session.endpoint);
        self.state.fallback_trust.mark_untrusted(reason.clone());

        let to = BlockHeight::from_u32(session.from.saturating_sub(1));
        match self.truncate_untrusted(key, to).await {
            Ok(Some(actual)) => tracing::warn!(
                key_id,
                truncated_to = u32::from(actual),
                "blocks scanned from the untrusted endpoint removed from the wallet"
            ),
            Ok(None) => {}
            Err(e) => tracing::error!(
                key_id,
                error = %e,
                "cannot truncate the blocks scanned from the untrusted endpoint"
            ),
        }
        if let Err(e) = self
            .cache
            .evict_source_below(Source::TorLwd, BlockHeight::from_u32(u32::MAX))
        {
            tracing::warn!(error = %e, "cannot drop the untrusted endpoint's blocks from the cache");
        }
        self.set_session(key, None);
        self.stall_untrusted(&key_id, &reason);
    }

    /// Remove everything above `to` from the wallet. `Ok(None)`: nothing
    /// was scanned above it. Below the window there is usually no block row
    /// at `to` (the block before a restore's birthday), so the wallet is cut
    /// at a chain state instead: the node's where it still serves one, else
    /// the endpoint's, which only seeds the checkpoint that everything
    /// above is dropped to.
    async fn truncate_untrusted(
        &self,
        key: &Arc<KeyEntry>,
        to: BlockHeight,
    ) -> Result<Option<BlockHeight>, SyncError> {
        if with_wallet(key, |w| core_sync::max_scanned(w))
            .await?
            .is_none_or(|h| h <= to)
        {
            return Ok(None);
        }
        match with_wallet(key, move |w| core_sync::rewind(w, to)).await {
            Ok(actual) => return Ok(Some(actual)),
            Err(SyncError::RewindInvalid { .. }) => {}
            Err(e) => return Err(e),
        }
        let state = match self.chain.chain_state(to).await {
            Ok(s) => s,
            Err(_) => match &self.state.fallback {
                Some(f) => f.chain_state(to).await.map_err(SyncError::Fallback)?,
                None => {
                    return Err(SyncError::Wallet(format!(
                        "no chain state at {} to truncate to",
                        u32::from(to)
                    )));
                }
            },
        };
        with_wallet(key, move |w| core_sync::truncate_to_chain_state(w, &state)).await?;
        Ok(Some(to))
    }

    pub(crate) fn stall_untrusted(&self, key_id: &str, reason: &str) {
        let detail = format!(
            "the fallback endpoint failed handoff validation against the node ({reason}); \
             set another fallback_lightwalletd.grpc_url to backfill"
        );
        self.hub()
            .stall(key_id, StallReason::UntrustedBackfill, detail);
    }

    /// The endpoint failed to answer (`SyncError::Fallback`): stalled
    /// until the next tick tries again.
    pub(crate) fn stall_fallback(&self, key_id: &str, e: &ChainError) {
        tracing::warn!(key_id, error = %e, "fallback endpoint unavailable; retrying next tick");
        let detail = format!("fallback endpoint unavailable, retrying: {e}");
        self.hub()
            .stall(key_id, StallReason::FallbackUnreachable, detail);
    }
}

/// `KeySyncStatus.backend` for a key's state.
pub fn proto_backend(state: &SyncState) -> v1::SyncBackend {
    match state {
        SyncState::Backfilling { via_tor: true, .. } => v1::SyncBackend::TorLwdFallback,
        SyncState::Backfilling { via_tor: false, .. } => v1::SyncBackend::DirectLwdFallback,
        _ => v1::SyncBackend::ZakuraRpc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_survives_a_restart_and_is_cleared_by_another_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = trust_path(dir.path());
        let hub = TrustHub::default();
        hub.load(path.clone(), "http://a");
        assert_eq!(hub.get(), Trust::Untested);
        hub.mark_verified();
        assert_eq!(hub.get(), Trust::Verified);
        hub.mark_untrusted("http://a: bad root".into());
        // Verified never overrides an untrusted mark.
        hub.mark_verified();
        assert!(matches!(hub.get(), Trust::Untrusted { .. }));

        let again = TrustHub::default();
        again.load(path.clone(), "http://a");
        assert_eq!(
            again.get(),
            Trust::Untrusted {
                reason: "http://a: bad root".into()
            }
        );
        let other = TrustHub::default();
        other.load(path.clone(), "http://b");
        assert_eq!(other.get(), Trust::Untested);
        assert!(!path.exists());
    }

    #[test]
    fn handoff_height_is_capped_at_the_tip() {
        let b = NodeBounds {
            tip_height: BlockHeight::from_u32(100),
            tip_hash: [0; 32],
            retained_from: BlockHeight::from_u32(50),
        };
        assert_eq!(handoff_height(&b, 10), BlockHeight::from_u32(60));
        assert_eq!(handoff_height(&b, 80), BlockHeight::from_u32(100));
    }
}
