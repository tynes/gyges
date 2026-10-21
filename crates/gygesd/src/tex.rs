//! The `TexQueue` driver (ARCHITECTURE.md §2.1, §3.3; API.md §6.5;
//! OVERVIEW.md Q-T1…T3) and the `ResumeTexTransfer` / `AbortTexTransfer`
//! RPCs.
//!
//! One task per daemon. Every `tex.rebroadcast_interval`, and whenever a
//! send or a resume wakes it, it asks the node about both transactions of
//! every non-terminal row (`getrawtransaction`) and acts on the answer:
//!
//! * step 2 mined: the transfer is complete (`step2_mined`);
//! * step 1 mined, step 2 missing: rebroadcast step 2 from the stored bytes,
//!   or, past the expiry height, `step2_failed` for `tx resume` to rebuild;
//! * step 1 in the mempool, step 2 missing: offer step 2 again (the node may
//!   not chain mempool transactions; it will take it once step 1 is mined);
//! * step 1 missing: rebroadcast it (a restart or a reorg lost it), or,
//!   past the expiry height, `expired`; a rejection the node explains is
//!   `failed` with its text.
//!
//! Mined heights are also handed to the wallet (`set_transaction_status`),
//! which is how a fully transparent step 2 is ever marked mined: the
//! scanner cannot see it (no `TransactionDataRequest` handling yet,
//! ROADMAP.md M1). Nothing here signs: both transactions were signed in the
//! send's session, and a restart replays bytes, never keys (TESTING.md §3
//! row 12).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gyges_chain::{ChainBackend, ChainError, TxStatus, display_hash, parse_display_hash};
use gyges_core::tex::{self as core_tex, TexQueueError, TexRow};
use gyges_core::tx::{self as core_tx, TxError};
use gyges_core::{KeyEntry, TexState};
use gyges_proto::v1::{
    self, AbortTexTransferRequest, ErrorReason, GygesError, ResumeTexTransferRequest,
    SessionStatus, TexQueueEntry,
};
use prost::Message as _;
use tokio::sync::Notify;
use tonic::Status;
use zcash_client_backend::data_api::{TransactionStatus, WalletWrite as _};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::conn::ConnInfo;
use crate::keys::{AUDIT_TARGET, registry_error};
use crate::service::{DaemonState, unix_now};
use crate::tx::{self, tx_error};

/// The queue's wake-up and the rows a `tx resume` is rebuilding.
#[derive(Debug, Default)]
pub struct TexHub {
    wake: Notify,
    rebuilding: Mutex<BTreeSet<[u8; 32]>>,
}

impl TexHub {
    /// Run a pass now rather than at the next interval.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    fn rebuilding(&self) -> std::sync::MutexGuard<'_, BTreeSet<[u8; 32]>> {
        self.rebuilding.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Rows the periodic pass looks at. `step2_failed` waits for `tx resume`
/// and terminal rows are done.
const ACTIVE: [TexState; 4] = [
    TexState::Built,
    TexState::Step1Broadcast,
    TexState::Step2Broadcast,
    TexState::Step1Mined,
];

/// Start the queue task.
pub fn spawn(state: Arc<DaemonState>, chain: Arc<dyn ChainBackend>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = state
            .config
            .tex
            .rebroadcast_interval
            .max(Duration::from_secs(1));
        loop {
            tick(&state, chain.as_ref()).await;
            tokio::select! {
                () = state.tex.wake.notified() => {}
                () = tokio::time::sleep(interval) => {}
            }
        }
    })
}

/// One pass over every key's active rows.
pub async fn tick(state: &Arc<DaemonState>, chain: &dyn ChainBackend) {
    if !chain.status().connected {
        return;
    }
    let keys: Vec<Arc<KeyEntry>> = state
        .registry
        .list()
        .into_iter()
        .filter(|k| k.profile().has_wallet())
        .collect();
    for key in keys {
        let ids = match tx::with_wallet(&key, |w| {
            core_tex::list_ids(w, &ACTIVE).map_err(queue_error)
        })
        .await
        {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(key_id = key.key_id(), error = %e, "tex queue: cannot list rows");
                continue;
            }
        };
        for id in ids {
            if state.tex.rebuilding().contains(&id) {
                continue;
            }
            if let Err(e) = drive(state, chain, &key, id).await {
                tracing::warn!(key_id = key.key_id(), error = %e, "tex queue: row not advanced");
            }
        }
    }
}

fn queue_error(e: TexQueueError) -> TxError {
    TxError::Internal(e.to_string())
}

/// Why one row could not be driven this pass; retried next pass.
#[derive(Debug, thiserror::Error)]
enum DriveError {
    #[error("{0}")]
    Wallet(#[from] TxError),
    #[error("{0}")]
    Node(#[from] ChainError),
}

/// Whether a node's rejection text says it already has the transaction
/// (`-27 transaction already in mempool`, `-27 transaction already in block
/// chain`): a success for our purposes.
pub(crate) fn already_known(text: &str) -> bool {
    text.contains("already")
}

/// Record a mined height in the wallet. Failures are logged only: the
/// wallet may learn it from the scanner too.
async fn mark_mined(key: &Arc<KeyEntry>, txid: [u8; 32], height: BlockHeight) {
    let outcome = tx::with_wallet(key, move |w| {
        w.set_transaction_status(TxId::from_bytes(txid), TransactionStatus::Mined(height))
            .map_err(|e| TxError::Internal(e.to_string()))
    })
    .await;
    if let Err(e) = outcome {
        tracing::debug!(key_id = key.key_id(), error = %e, "could not record a mined height");
    }
}

async fn set_state(
    key: &Arc<KeyEntry>,
    id: [u8; 32],
    state: TexState,
    error: Option<String>,
) -> Result<(), DriveError> {
    tx::with_wallet(key, move |w| {
        core_tex::set_state(w, id, state, error.as_deref()).map_err(queue_error)
    })
    .await?;
    tracing::info!(
        key_id = key.key_id(),
        state = state.as_str(),
        "tex transfer state"
    );
    Ok(())
}

async fn record_attempt(
    key: &Arc<KeyEntry>,
    id: [u8; 32],
    error: Option<String>,
) -> Result<(), DriveError> {
    let now = unix_now();
    tx::with_wallet(key, move |w| {
        core_tex::record_attempt(w, id, now, error.as_deref()).map_err(queue_error)
    })
    .await?;
    Ok(())
}

/// What one broadcast attempt came to.
enum Offered {
    Accepted,
    /// The node explained its refusal (`last_error` carries the text).
    Refused(String),
}

/// Hand `raw` to the node and record the attempt on the row.
async fn offer(
    chain: &dyn ChainBackend,
    key: &Arc<KeyEntry>,
    id: [u8; 32],
    raw: Vec<u8>,
    step: u32,
) -> Result<Offered, DriveError> {
    match chain.send_raw_transaction(raw).await {
        Ok(_) => {
            record_attempt(key, id, None).await?;
            tracing::info!(target: AUDIT_TARGET, key_id = key.key_id(), event = "broadcast");
            tracing::info!(
                key_id = key.key_id(),
                step,
                "tex step broadcast by the queue"
            );
            Ok(Offered::Accepted)
        }
        Err(ChainError::Rejected(text)) if already_known(&text) => {
            record_attempt(key, id, None).await?;
            Ok(Offered::Accepted)
        }
        Err(ChainError::Rejected(text)) => {
            record_attempt(key, id, Some(text.clone())).await?;
            tracing::debug!(key_id = key.key_id(), step, error = %text, "tex step refused");
            Ok(Offered::Refused(text))
        }
        Err(other) => {
            record_attempt(key, id, Some(other.to_string())).await?;
            Err(other.into())
        }
    }
}

/// Advance one row by what the node says (module docs).
async fn drive(
    state: &Arc<DaemonState>,
    chain: &dyn ChainBackend,
    key: &Arc<KeyEntry>,
    id: [u8; 32],
) -> Result<(), DriveError> {
    let Some(row) =
        tx::with_wallet(key, move |w| core_tex::get(w, id).map_err(queue_error)).await?
    else {
        return Ok(());
    };
    if row.state.is_terminal() || row.state == TexState::Step2Failed {
        return Ok(());
    }
    let tip = chain.status().bounds.map_or(0, |b| u32::from(b.tip_height));
    let s1 = chain.transaction_status(row.step1_txid).await?;
    let s2 = chain.transaction_status(row.step2_txid).await?;
    match (s1, s2) {
        (_, TxStatus::Mined(h2)) => {
            if let TxStatus::Mined(h1) = s1 {
                mark_mined(key, row.step1_txid, h1).await;
            }
            mark_mined(key, row.step2_txid, h2).await;
            set_state(key, id, TexState::Step2Mined, None).await?;
            tracing::info!(key_id = key.key_id(), "zip 320 transfer complete");
            state.sync.wake();
        }
        (TxStatus::Mined(h1), s2) => {
            mark_mined(key, row.step1_txid, h1).await;
            if row.state != TexState::Step1Mined {
                set_state(key, id, TexState::Step1Mined, row.last_error.clone()).await?;
            }
            match s2 {
                TxStatus::InMempool => {}
                TxStatus::Unknown if tip >= row.expiry_height => {
                    set_state(
                        key,
                        id,
                        TexState::Step2Failed,
                        Some(format!(
                            "step 2 was not mined before its expiry height {}; run `gyges tx resume` to build a new one",
                            row.expiry_height
                        )),
                    )
                    .await?;
                    tracing::warn!(
                        key_id = key.key_id(),
                        "zip 320 step 2 expired after step 1 was mined; `gyges tx resume` builds a new one"
                    );
                }
                TxStatus::Unknown => {
                    offer(chain, key, id, row.step2_raw.clone(), 2).await?;
                }
                TxStatus::Mined(_) => unreachable!("handled above"),
            }
        }
        (TxStatus::InMempool, s2) => {
            if row.state == TexState::Built {
                set_state(key, id, TexState::Step1Broadcast, None).await?;
            }
            match s2 {
                TxStatus::InMempool => {
                    if row.state != TexState::Step2Broadcast {
                        set_state(key, id, TexState::Step2Broadcast, None).await?;
                    }
                }
                TxStatus::Unknown => {
                    if let Offered::Accepted =
                        offer(chain, key, id, row.step2_raw.clone(), 2).await?
                    {
                        set_state(key, id, TexState::Step2Broadcast, None).await?;
                    }
                }
                TxStatus::Mined(_) => unreachable!("handled above"),
            }
        }
        (TxStatus::Unknown, _) => {
            if tip >= row.expiry_height {
                set_state(
                    key,
                    id,
                    TexState::Expired,
                    Some(format!(
                        "neither step was mined before the expiry height {}; nothing left the shielded pool",
                        row.expiry_height
                    )),
                )
                .await?;
                tracing::warn!(key_id = key.key_id(), "zip 320 transfer expired unmined");
                return Ok(());
            }
            match offer(chain, key, id, row.step1_raw.clone(), 1).await? {
                Offered::Accepted => {
                    set_state(key, id, TexState::Step1Broadcast, None).await?;
                    if let Offered::Accepted =
                        offer(chain, key, id, row.step2_raw.clone(), 2).await?
                    {
                        set_state(key, id, TexState::Step2Broadcast, None).await?;
                    }
                }
                Offered::Refused(text) => {
                    set_state(key, id, TexState::Failed, Some(text)).await?;
                    tracing::warn!(
                        key_id = key.key_id(),
                        "the node refused zip 320 step 1; the transfer is failed (its text is in `tx sessions`)"
                    );
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Proto conversion and listing
// ---------------------------------------------------------------------------

pub fn proto_state(s: TexState) -> v1::TexState {
    match s {
        TexState::Built => v1::TexState::Built,
        TexState::Step1Broadcast => v1::TexState::Step1Broadcast,
        TexState::Step2Broadcast => v1::TexState::Step2Broadcast,
        TexState::Step1Mined => v1::TexState::Step1Mined,
        TexState::Step2Mined => v1::TexState::Step2Mined,
        TexState::Step2Failed => v1::TexState::Step2Failed,
        TexState::Expired => v1::TexState::Expired,
        TexState::Failed => v1::TexState::Failed,
        TexState::Aborted => v1::TexState::Aborted,
    }
}

pub fn to_proto(key_id: &str, row: &TexRow) -> TexQueueEntry {
    TexQueueEntry {
        step1_txid: display_hash(&row.step1_txid),
        step2_txid: display_hash(&row.step2_txid),
        state: proto_state(row.state) as i32,
        created_at: row.created_at,
        last_attempt_at: row.last_attempt_at.unwrap_or(0),
        attempts: row.attempts,
        last_error: row.last_error.clone().unwrap_or_default(),
        recipient: row.recipient.clone(),
        amount: i64::try_from(row.amount).unwrap_or(i64::MAX),
        expiry_height: row.expiry_height,
        key_id: key_id.to_string(),
    }
}

/// Every transfer of `key_id` (all keys when empty), for `tx sessions`.
pub async fn list(state: &DaemonState, key_id: &str, include_finished: bool) -> Vec<TexQueueEntry> {
    let mut out = Vec::new();
    for key in state.registry.list() {
        if !key.profile().has_wallet() || (!key_id.is_empty() && key.key_id() != key_id) {
            continue;
        }
        let rows = tx::with_wallet(&key, move |w| {
            core_tex::list(w, include_finished).map_err(queue_error)
        })
        .await;
        match rows {
            Ok(rows) => out.extend(rows.iter().map(|r| to_proto(key.key_id(), r))),
            Err(e) => tracing::warn!(key_id = key.key_id(), error = %e, "cannot list tex rows"),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The RPCs
// ---------------------------------------------------------------------------

fn parse_txid(s: &str) -> Result<[u8; 32], Status> {
    parse_display_hash(s).map_err(|_| {
        GygesError::new(
            ErrorReason::InvalidArgument,
            "step1_txid must be the 64-hex txid `tx send` printed",
        )
        .into_status()
    })
}

async fn load_row(key: &Arc<KeyEntry>, id: [u8; 32]) -> Result<TexRow, Status> {
    let key_id = key.key_id().to_string();
    tx::with_wallet(key, move |w| core_tex::get(w, id).map_err(queue_error))
        .await
        .map_err(|e| tx_error(e, &key_id).into_status())?
        .ok_or_else(|| {
            GygesError::new(
                ErrorReason::InvalidArgument,
                "no ZIP 320 transfer of this key has that step-1 txid",
            )
            .with_key(key_id)
            .into_status()
        })
}

/// `AbortTexTransfer` (API.md §4.3): allowed while the row is still
/// `built`, i.e. before either transaction reached the node.
pub async fn abort_tex_transfer(
    state: Arc<DaemonState>,
    req: AbortTexTransferRequest,
) -> Result<TexQueueEntry, Status> {
    let key = state
        .registry
        .resolve(&req.key_id)
        .map_err(|e| registry_error(e).into_status())?;
    let key_id = key.key_id().to_string();
    let id = parse_txid(&req.step1_txid)?;
    let row = load_row(&key, id).await?;
    if row.state != TexState::Built {
        return Err(GygesError::new(
            ErrorReason::InvalidArgument,
            format!(
                "only a transfer still `built` can be aborted; this one is `{}`",
                row.state.as_str()
            ),
        )
        .with_key(&key_id)
        .into_status());
    }
    tx::with_wallet(&key, move |w| {
        core_tex::set_state(w, id, TexState::Aborted, Some("aborted by the client"))
            .map_err(queue_error)
    })
    .await
    .map_err(|e| tx_error(e, &key_id).into_status())?;
    tracing::info!(target: AUDIT_TARGET, key_id, event = "tex_aborted");
    let row = load_row(&key, id).await?;
    Ok(to_proto(&key_id, &row))
}

/// `ResumeTexTransfer` (API.md §6.5): on a `step2_failed` row, build a new
/// step 2 with the key (from the request's token, a daemon unlock, or a
/// signing session the client satisfies; the RPC is unary, so with a
/// session it answers `SIGNATURE_REQUIRED` and the rebuild finishes in the
/// background). On any other live row it is a nudge: the queue re-checks
/// the node now.
pub async fn resume_tex_transfer(
    state: Arc<DaemonState>,
    conn: Option<ConnInfo>,
    req: ResumeTexTransferRequest,
) -> Result<TexQueueEntry, Status> {
    let prepared = tx::prepare(
        &state,
        conn,
        &req.key_id,
        &req.session_token,
        0,
        tx::Purpose::Spend,
    )?;
    let key = prepared.key.clone();
    let key_id = key.key_id().to_string();
    let id = parse_txid(&req.step1_txid)?;
    let row = load_row(&key, id).await?;
    match row.state {
        TexState::Step2Failed => {}
        s if s.is_terminal() => {
            return Err(GygesError::new(
                ErrorReason::InvalidArgument,
                format!(
                    "this transfer is `{}`; there is nothing to resume",
                    s.as_str()
                ),
            )
            .with_key(&key_id)
            .into_status());
        }
        _ => {
            state.tex.wake();
            return Ok(to_proto(&key_id, &row));
        }
    }
    if state.tex.rebuilding().contains(&id) {
        // A session for this row is already pending or being applied.
        return Ok(to_proto(&key_id, &row));
    }

    let summary = v1::Proposal::decode(row.proposal.as_slice()).unwrap_or_default();
    match tx::key_from_unlock(&state, &prepared)? {
        Some(usk) => {
            state.tex.rebuilding().insert(id);
            let outcome = rebuild(&state, &key, &row, usk).await;
            state.tex.rebuilding().remove(&id);
            outcome?;
            let row = load_row(&key, id).await?;
            Ok(to_proto(&key_id, &row))
        }
        None => {
            let ttl = state.config.vault.signing_session_ttl;
            let (session_id, _expires_at, rx) = state.sessions.create(&key_id, 2, ttl, summary);
            tracing::info!(target: AUDIT_TARGET, key_id, event = "session_created");
            state.tex.rebuilding().insert(id);
            let st = state.clone();
            let sid = session_id.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(ttl, rx).await {
                    Ok(Ok(usk)) => {
                        tracing::info!(target: AUDIT_TARGET, key_id = key.key_id(), event = "sign", via = "session");
                        if let Err(status) = rebuild(&st, &key, &row, usk).await {
                            st.sessions.fail(&sid, status.message());
                        }
                    }
                    Ok(Err(_)) => {
                        // Aborted: the hub already holds the status.
                    }
                    Err(_elapsed) => {
                        st.sessions.finish(
                            &sid,
                            SessionStatus::Expired,
                            "no passphrase arrived in time",
                        );
                    }
                }
                st.tex.rebuilding().remove(&id);
            });
            Err(GygesError::new(
                ErrorReason::SignatureRequired,
                "a passphrase is needed to sign the new step 2; satisfy the session with UnlockKey { session_id }",
            )
            .with_key(&key_id)
            .with_session(session_id)
            .into_status())
        }
    }
}

/// Build and store the fresh step 2, then put the row back on the queue.
async fn rebuild(
    state: &Arc<DaemonState>,
    key: &Arc<KeyEntry>,
    row: &TexRow,
    usk: UnifiedSpendingKey,
) -> Result<(), Status> {
    let key_id = key.key_id().to_string();
    let params = state.registry.params();
    let provers = state.provers.clone();
    let min_confirmations = state.config.policy.min_confirmations;
    // The evidence that the ephemeral output is free again: the node has
    // no step 2, and the chain is past the height where one could still be
    // mined (both steps share the expiry; nobody else holds the ephemeral
    // key).
    let chain = state.chain.clone().ok_or_else(|| {
        GygesError::new(ErrorReason::Airgapped, "an air-gapped daemon cannot resume")
            .with_key(&key_id)
            .into_status()
    })?;
    let tip = chain.status().bounds.map(|b| b.tip_height).ok_or_else(|| {
        GygesError::new(ErrorReason::NodeUnreachable, "the node's tip is not known")
            .with_key(&key_id)
            .into_status()
    })?;
    let s2 = chain
        .transaction_status(row.step2_txid)
        .await
        .map_err(|e| tx::broadcast_error(e, &key_id).into_status())?;
    if s2 != TxStatus::Unknown || u32::from(tip) < row.expiry_height {
        return Err(GygesError::new(
            ErrorReason::InvalidArgument,
            format!(
                "step 2 can still be mined (node status {s2:?}, expiry {}, tip {}); nothing to rebuild yet",
                row.expiry_height, tip
            ),
        )
        .with_key(&key_id)
        .into_status());
    }
    let r = row.clone();
    let built = tx::with_wallet(key, move |w| {
        let (txid, raw, expiry) = core_tx::build_tex_step2(
            w,
            &params,
            usk,
            &provers,
            r.step1_txid,
            &r.ephemeral_addr,
            &r.recipient,
            r.amount,
            min_confirmations,
            tip,
        )?;
        core_tex::replace_step2(w, r.step1_txid, *txid.as_ref(), &raw, expiry)
            .map_err(queue_error)?;
        Ok(())
    })
    .await;
    match built {
        Ok(()) => {
            tracing::info!(target: AUDIT_TARGET, key_id, event = "tex_resumed");
            tracing::info!(key_id, "zip 320 step 2 rebuilt");
            state.tex.wake();
            Ok(())
        }
        Err(e) => {
            let detail = e.to_string();
            let id = row.step1_txid;
            let _ = tx::with_wallet(key, move |w| {
                core_tex::set_state(w, id, TexState::Step2Failed, Some(&detail))
                    .map_err(queue_error)
            })
            .await;
            Err(tx_error(e, &key_id).into_status())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_texts_for_a_known_transaction_count_as_accepted() {
        assert!(already_known("transaction already in mempool (code -27)"));
        assert!(already_known(
            "transaction already in block chain (code -27)"
        ));
        assert!(!already_known("bad-txns-inputs-missingorspent (code -25)"));
    }

    #[test]
    fn states_map_one_to_one() {
        for s in TexState::ALL {
            assert_ne!(proto_state(s), v1::TexState::Unspecified);
        }
    }
}
