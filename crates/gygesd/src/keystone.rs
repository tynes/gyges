//! Keystone signing sessions (API.md §6, ROADMAP.md M5 third item).
//!
//! A `tx send` or `tx shield` from a `keystone-qr` key proves the PCZT,
//! persists a session (`gyges_core::sessions::insert_keystone`) holding the
//! proven copy and what the device was shown, and emits `SignatureRequired`
//! with that payload. `CompleteKeystoneSign` does the rest from any
//! connection, after a restart too: apply the device's answer
//! (`gyges_core::keystone`), check every signature is there, run the
//! Verifier against the approved proposal, extract, record, broadcast. If
//! the stream that created the session is still open it is told the txid
//! and emits `Signed` and `Broadcast` as for a passphrase.
//!
//! A refused answer leaves the session awaiting, with `last_error`, so the
//! user can scan the device again. A session is claimed exactly once: an
//! in-memory guard keeps two completions from running together, and the
//! row leaves `awaiting-signature` with a conditional update before
//! anything is extracted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use gyges_core::keystone::{self as core_keystone, DeviceRequest};
use gyges_core::profile::unix_now;
use gyges_core::registry::Wallet;
use gyges_core::sessions::{self, KeystoneRow, Protocol, SessionRow, SessionState};
use gyges_core::tx::{self as core_tx, Expected, TxError};
use gyges_core::{KeyEntry, SigningMode, pczt_io};
use gyges_proto::v1::{
    self, CompleteKeystoneSignRequest, CompleteKeystoneSignResponse, ErrorReason, GygesError,
    SessionPurpose, SessionStatus, SignatureKind, SignatureRequired, SigningSession, TxidList,
    complete_keystone_sign_response,
};
use pczt::Pczt;
use prost::Message as _;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;
use zcash_protocol::TxId;

use crate::keys::AUDIT_TARGET;
use crate::service::DaemonState;
use crate::tx::{self, Prepared, tx_error, with_wallet};

/// What a waiting stream is told when its session ends.
type Outcome = Result<TxId, GygesError>;

/// Streams waiting on their session, and the sessions being completed.
#[derive(Default)]
pub struct KeystoneHub {
    waiters: Mutex<BTreeMap<String, oneshot::Sender<Outcome>>>,
    completing: Mutex<BTreeSet<String>>,
}

impl std::fmt::Debug for KeystoneHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeystoneHub")
            .field("waiters", &crate::lock(&self.waiters).len())
            .field("completing", &crate::lock(&self.completing).len())
            .finish()
    }
}

impl KeystoneHub {
    fn wait(&self, session_id: &str) -> oneshot::Receiver<Outcome> {
        let (tx, rx) = oneshot::channel();
        crate::lock(&self.waiters).insert(session_id.to_string(), tx);
        rx
    }

    fn forget(&self, session_id: &str) {
        crate::lock(&self.waiters).remove(session_id);
    }

    /// Tell the stream waiting on `session_id`, if any.
    fn notify(&self, session_id: &str, outcome: Outcome) {
        if let Some(tx) = crate::lock(&self.waiters).remove(session_id) {
            let _ = tx.send(outcome);
        }
    }

    /// Claim `session_id` for one completion; `None` when another is
    /// running. Released when the guard drops.
    fn claim(self: &Arc<Self>, session_id: &str) -> Option<Claim> {
        crate::lock(&self.completing)
            .insert(session_id.to_string())
            .then(|| Claim {
                hub: self.clone(),
                session_id: session_id.to_string(),
            })
    }
}

struct Claim {
    hub: Arc<KeystoneHub>,
    session_id: String,
}

impl Drop for Claim {
    fn drop(&mut self) {
        crate::lock(&self.hub.completing).remove(&self.session_id);
    }
}

fn session_error(e: impl std::fmt::Display) -> TxError {
    TxError::Internal(e.to_string())
}

fn kind_of(protocol: Protocol) -> SignatureKind {
    match protocol {
        Protocol::KeystoneBatch => SignatureKind::KeystoneBatch,
        _ => SignatureKind::KeystoneSinglePczt,
    }
}

fn status_of(state: SessionState) -> SessionStatus {
    match state {
        SessionState::AwaitingSignature => SessionStatus::AwaitingSignature,
        SessionState::Signed | SessionState::Broadcast => SessionStatus::Completed,
        SessionState::Aborted => SessionStatus::Aborted,
        SessionState::Expired => SessionStatus::Expired,
    }
}

/// A persisted Keystone session as the API shows it.
fn proto_session(key_id: &str, row: &SessionRow, payload: Vec<u8>) -> SigningSession {
    SigningSession {
        session_id: row.session_id.clone(),
        key_id: key_id.to_string(),
        kind: kind_of(row.protocol) as i32,
        purpose: SessionPurpose::Send as i32,
        status: status_of(row.state) as i32,
        created_at: row.created_at,
        expires_at: row.expires_at,
        summary: v1::Proposal::decode(row.proposal.as_slice()).ok(),
        step: 1,
        last_error: row.last_error.clone().unwrap_or_default(),
        payload,
    }
}

/// Mark a row expired once its time is up. `true` when it was.
fn expire_if_due(wallet: &mut Wallet, row: &SessionRow) -> Result<bool, TxError> {
    if row.state != SessionState::AwaitingSignature || row.expires_at > unix_now() {
        return Ok(false);
    }
    sessions::leave_awaiting(
        wallet,
        &row.session_id,
        SessionState::Expired,
        Some("no answer from the device in time"),
    )
    .map_err(session_error)?;
    Ok(true)
}

/// The key's Keystone sessions, oldest expiry applied first; only those
/// awaiting a signature unless `include_finished`.
fn key_sessions(
    wallet: &mut Wallet,
    key_id: &str,
    include_finished: bool,
) -> Result<Vec<SigningSession>, TxError> {
    let mut out = Vec::new();
    for mut row in sessions::list(wallet, true).map_err(session_error)? {
        if !matches!(
            row.protocol,
            Protocol::KeystoneBatch | Protocol::KeystonePczt
        ) {
            continue;
        }
        if expire_if_due(wallet, &row)? {
            row.state = SessionState::Expired;
        }
        if !include_finished && row.state != SessionState::AwaitingSignature {
            continue;
        }
        let payload = sessions::get_keystone(wallet, &row.session_id)
            .map_err(session_error)?
            .map(|k| k.payload)
            .unwrap_or_default();
        out.push(proto_session(key_id, &row, payload));
    }
    Ok(out)
}

/// The Keystone keys `key_id` selects (every one when empty).
fn keystone_keys(state: &DaemonState, key_id: &str) -> Vec<Arc<KeyEntry>> {
    state
        .registry
        .list()
        .into_iter()
        .filter(|k| k.profile().signing_mode == SigningMode::KeystoneQr)
        .filter(|k| key_id.is_empty() || k.key_id() == key_id)
        .collect()
}

/// `ListSigningSessions`' persisted half.
pub async fn list(
    state: &DaemonState,
    key_id: &str,
    include_finished: bool,
) -> Vec<SigningSession> {
    let mut out = Vec::new();
    for key in keystone_keys(state, key_id) {
        let kid = key.key_id().to_string();
        let id = kid.clone();
        match with_wallet(&key, move |w| key_sessions(w, &id, include_finished)).await {
            Ok(rows) => out.extend(rows),
            Err(e) => tracing::warn!(key_id = kid, error = %e, "cannot list Keystone sessions"),
        }
    }
    out
}

/// A pending session that blocks another spend from the same key: until
/// it is completed or aborted, a second proposal could pick the same notes.
pub(crate) fn pending_for(key: &KeyEntry) -> Result<Option<String>, Status> {
    let Some(mut wallet) = key.wallet() else {
        return Ok(None);
    };
    let pending = key_sessions(&mut wallet, key.key_id(), false)
        .map_err(|e| tx_error(e, key.key_id()).into_status())?;
    Ok(pending.into_iter().next().map(|s| s.session_id))
}

/// Find the key holding Keystone session `session_id`.
async fn find(
    state: &DaemonState,
    session_id: &str,
) -> Result<Option<(Arc<KeyEntry>, SessionRow, KeystoneRow)>, Status> {
    for key in keystone_keys(state, "") {
        let sid = session_id.to_string();
        let kid = key.key_id().to_string();
        let found = with_wallet(&key, move |w| {
            let row = sessions::get(w, &sid).map_err(session_error)?;
            let ks = sessions::get_keystone(w, &sid).map_err(session_error)?;
            Ok(row.zip(ks))
        })
        .await
        .map_err(|e| tx_error(e, &kid).into_status())?;
        if let Some((row, ks)) = found {
            return Ok(Some((key, row, ks)));
        }
    }
    Ok(None)
}

/// `AbortSigningSession` for a persisted Keystone session; `None` when no
/// key holds it. The waiting stream, if any, ends with `CANCELLED`.
pub async fn abort(
    state: &DaemonState,
    session_id: &str,
) -> Result<Option<SigningSession>, Status> {
    let Some((key, row, ks)) = find(state, session_id).await? else {
        return Ok(None);
    };
    let kid = key.key_id().to_string();
    let sid = session_id.to_string();
    let left = with_wallet(&key, move |w| {
        sessions::leave_awaiting(
            w,
            &sid,
            SessionState::Aborted,
            Some("aborted by the client"),
        )
        .map_err(session_error)
    })
    .await
    .map_err(|e| tx_error(e, &kid).into_status())?;
    let mut row = row;
    if left {
        row.state = SessionState::Aborted;
        row.last_error = Some("aborted by the client".into());
        state.keystone.notify(
            session_id,
            Err(
                GygesError::new(ErrorReason::Cancelled, "the signing session was aborted")
                    .with_key(&kid)
                    .with_session(session_id),
            ),
        );
        tracing::info!(target: AUDIT_TARGET, key_id = kid, event = "session_aborted");
    }
    Ok(Some(proto_session(&kid, &row, ks.payload)))
}

/// Step 5 of the send pipeline for a Keystone key: persist the session,
/// emit `SignatureRequired`, and wait. `Ok(Some(txid))` once a completion
/// broadcast it; `Ok(None)` when the client left (the session lives on and
/// is completed with `CompleteKeystoneSign`).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn await_device<E: Send + 'static>(
    state: &Arc<DaemonState>,
    prepared: &Prepared,
    summary: &v1::Proposal,
    expected: &Expected,
    proven: Pczt,
    request: DeviceRequest,
    via_tor: bool,
    tx: &mpsc::Sender<Result<E, Status>>,
    wrap: impl Fn(SignatureRequired) -> E,
) -> Result<Option<TxId>, Status> {
    let key = &prepared.key;
    let key_id = key.key_id().to_string();
    let err = |e: TxError| tx_error(e, &key_id).into_status();
    let session_id = pczt_io::new_session_id();
    let ttl = state.config.vault.signing_session_ttl;
    let now = unix_now();
    let expires_at = now.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX));
    let row = SessionRow {
        session_id: session_id.clone(),
        protocol: request.protocol,
        state: SessionState::AwaitingSignature,
        created_at: now,
        expires_at,
        proposal: summary.encode_to_vec(),
        expected: expected.to_json(),
        txid: None,
        last_error: None,
    };
    let ks = KeystoneRow {
        session_id: session_id.clone(),
        pczt: pczt_io::serialize(proven).map_err(err)?,
        payload: request.payload.clone(),
        request_id: request.request_id.clone(),
        via_tor,
        expiry_height: summary.expiry_height,
    };
    // Registered before the row exists, so a completion that races the
    // event below still finds the stream.
    let rx = state.keystone.wait(&session_id);
    with_wallet(key, move |w| {
        sessions::insert_keystone(w, &row, &ks).map_err(session_error)
    })
    .await
    .map_err(err)?;
    tracing::info!(target: AUDIT_TARGET, key_id, event = "session_created");
    tracing::info!(
        key_id,
        session_id,
        protocol = request.protocol.as_str(),
        "awaiting the Keystone"
    );
    let required = SignatureRequired {
        key_id: key_id.clone(),
        kind: kind_of(request.protocol) as i32,
        session_id: session_id.clone(),
        expires_at,
        payload: request.payload,
        step: 1,
        summary: Some(summary.clone()),
    };
    if tx::send(tx, wrap(required)).await.is_err() {
        state.keystone.forget(&session_id);
        return Ok(None);
    }
    tokio::select! {
        got = tokio::time::timeout(ttl, rx) => match got {
            Ok(Ok(Ok(txid))) => Ok(Some(txid)),
            Ok(Ok(Err(e))) => Err(e.into_status()),
            // The hub dropped the sender without an outcome.
            Ok(Err(_)) => Err(tx::cancelled()),
            Err(_elapsed) => {
                state.keystone.forget(&session_id);
                let sid = session_id.clone();
                let _ = with_wallet(key, move |w| {
                    sessions::leave_awaiting(
                        w,
                        &sid,
                        SessionState::Expired,
                        Some("no answer from the device in time"),
                    )
                    .map_err(session_error)
                })
                .await;
                Err(GygesError::new(
                    ErrorReason::SessionNotFound,
                    "the Keystone session expired before the device's answer arrived; start over",
                )
                .with_key(&key_id)
                .with_session(session_id)
                .into_status())
            }
        },
        () = tx.closed() => {
            state.keystone.forget(&session_id);
            Ok(None)
        }
    }
}

/// `CompleteKeystoneSign` (API.md §6.2).
pub async fn complete_keystone_sign(
    state: Arc<DaemonState>,
    req: CompleteKeystoneSignRequest,
) -> Result<CompleteKeystoneSignResponse, Status> {
    let session_id = req.session_id.clone();
    let not_found = |detail: &str| {
        GygesError::new(ErrorReason::SessionNotFound, detail)
            .with_session(&session_id)
            .into_status()
    };
    let Some(_claim) = state.keystone.claim(&session_id) else {
        return Err(not_found(
            "this session is being completed by another request",
        ));
    };
    let Some((key, row, ks)) = find(&state, &session_id).await? else {
        return Err(not_found("no Keystone signing session has this id"));
    };
    let key_id = key.key_id().to_string();
    let err = |e: TxError| tx_error(e, &key_id).into_status();
    let typed = |reason, detail: String| {
        GygesError::new(reason, detail)
            .with_key(&key_id)
            .with_session(&session_id)
    };
    {
        let r = row.clone();
        if with_wallet(&key, move |w| expire_if_due(w, &r))
            .await
            .map_err(err)?
        {
            state.keystone.notify(
                &session_id,
                Err(typed(
                    ErrorReason::SessionNotFound,
                    "the Keystone session expired".into(),
                )),
            );
            return Err(not_found("the Keystone session expired; start over"));
        }
    }
    if row.state != SessionState::AwaitingSignature {
        return Err(not_found(&format!(
            "the Keystone session is {}, not awaiting a signature",
            row.state.as_str()
        )));
    }

    // Past the transaction's expiry nothing can be mined: refuse before
    // anything is recorded.
    let chain = tx::connected_chain(&state, &key_id)?;
    let tip = chain.status().bounds.map_or(0, |b| u32::from(b.tip_height));
    if ks.expiry_height > 0 && tip >= ks.expiry_height {
        let detail = format!(
            "the transaction expires at height {} and the chain is at {tip}; it can no longer be \
             mined, start over",
            ks.expiry_height
        );
        let sid = session_id.clone();
        let d = detail.clone();
        let _ = with_wallet(&key, move |w| {
            sessions::leave_awaiting(w, &sid, SessionState::Expired, Some(&d))
                .map_err(session_error)
        })
        .await;
        state.keystone.notify(
            &session_id,
            Err(typed(ErrorReason::NotSynced, detail.clone())),
        );
        return Err(typed(ErrorReason::NotSynced, detail).into_status());
    }
    let route = tx::broadcast_route(&state, ks.via_tor, &key_id)?;

    // The device's answer, then every signature, then the Verifier. A
    // refusal here leaves the session awaiting another scan.
    let refuse = |detail: String| {
        let key = key.clone();
        let sid = session_id.clone();
        let error = typed(ErrorReason::HardwareSigner, detail.clone());
        async move {
            let _ = with_wallet(&key, move |w| {
                sessions::note_error(w, &sid, &detail).map_err(session_error)
            })
            .await;
            error.into_status()
        }
    };
    let proven = pczt_io::parse(&ks.pczt).map_err(err)?;
    let signed = match core_keystone::apply_answer(
        row.protocol,
        proven,
        ks.request_id.as_deref(),
        req.payload,
    ) {
        Ok(p) => p,
        Err(e) => return Err(refuse(e.to_string()).await),
    };
    let insp = pczt_io::inspect(&state.registry.params(), &signed).map_err(err)?;
    if !insp.is_signed() {
        let missing: Vec<String> = insp
            .pools
            .iter()
            .filter(|p| p.signatures_present < p.signatures_required)
            .map(|p| {
                format!(
                    "{:?} {}/{}",
                    p.pool, p.signatures_present, p.signatures_required
                )
            })
            .collect();
        return Err(refuse(format!(
            "the device's answer leaves signatures missing ({})",
            missing.join(", ")
        ))
        .await);
    }
    let expected = Expected::from_json(&row.expected).map_err(err)?;
    let owner_params = state.registry.params();
    let owner = with_wallet(&key, move |w| core_tx::Owner::of_wallet(&owner_params, w))
        .await
        .map_err(err)?;
    let verified = match core_tx::verify(signed, &expected, &owner) {
        Ok(p) => p,
        Err(e) => {
            return Err(refuse(format!(
                "the signed transaction differs from the approved one: {e}"
            ))
            .await);
        }
    };

    // Claim the row for good, then extract, record and broadcast.
    let sid = session_id.clone();
    let claimed = with_wallet(&key, move |w| {
        sessions::leave_awaiting(w, &sid, SessionState::Signed, None).map_err(session_error)
    })
    .await
    .map_err(err)?;
    if !claimed {
        return Err(not_found(
            "the Keystone session was aborted or completed meanwhile",
        ));
    }
    let provers = state.provers.clone();
    let extracted = with_wallet(&key, move |w| {
        core_tx::extract_and_store(w, verified, &provers)
    })
    .await;
    let (txid, raw) = match extracted {
        Ok(t) => t,
        Err(e) => {
            // Claimed but not recorded: say so on the row and to the stream,
            // which would otherwise wait for an answer that already came.
            let error = tx_error(e, &key_id).with_session(&session_id);
            let text = error.detail.clone();
            let sid = session_id.clone();
            let _ = with_wallet(&key, move |w| {
                sessions::set_state(w, &sid, SessionState::Signed, None, Some(&text))
                    .map_err(session_error)
            })
            .await;
            state.keystone.notify(&session_id, Err(error.clone()));
            return Err(error.into_status());
        }
    };
    tracing::info!(target: AUDIT_TARGET, key_id, event = "sign", via = "keystone");
    let raw_txid = *txid.as_ref();
    if let Err(e) = route.send(&chain, raw, &key_id).await {
        let text = if e.node_error.is_empty() {
            e.detail.clone()
        } else {
            e.node_error.clone()
        };
        let sid = session_id.clone();
        let _ = with_wallet(&key, move |w| {
            sessions::set_state(w, &sid, SessionState::Signed, None, Some(&text))
                .map_err(session_error)
        })
        .await;
        state.keystone.notify(&session_id, Err(e.clone()));
        return Err(e.into_status());
    }
    let sid = session_id.clone();
    with_wallet(&key, move |w| {
        sessions::set_state(w, &sid, SessionState::Broadcast, Some(raw_txid), None)
            .map_err(session_error)
    })
    .await
    .map_err(err)?;
    tracing::info!(target: AUDIT_TARGET, key_id, event = "broadcast", via = route.name());
    tracing::info!(
        key_id,
        session_id,
        via = route.name(),
        "Keystone transaction broadcast"
    );
    state.sync.wake();
    state.keystone.notify(&session_id, Ok(txid));
    let mut done = row;
    done.state = SessionState::Broadcast;
    Ok(CompleteKeystoneSignResponse {
        session: Some(proto_session(&key_id, &done, ks.payload)),
        result: Some(complete_keystone_sign_response::Result::Broadcast(
            TxidList {
                txids: vec![txid.to_string()],
            },
        )),
    })
}
