//! Signing sessions. The passphrase sessions behind `UnlockKey { session_id }`,
//! `ListSigningSessions` and `AbortSigningSession` (API.md §6) live in
//! memory only (API.md §6.1): the stream that created one is gone after a
//! restart. The rows of `pczt create` and Keystone sessions live in the
//! key's `ext_gyges_signing_sessions` table; the helpers at the end move
//! them between states.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use age::secrecy::SecretString;
use gyges_core::KeyEntry;
use gyges_core::db::sessions::{self, SessionState};
use gyges_core::tx::{self as core_tx, TxError};
use gyges_proto::v1::{
    self, AbortSigningSessionRequest, ErrorReason, GygesError, ListSigningSessionsRequest,
    ListSigningSessionsResponse, SessionPurpose, SessionStatus, SignatureKind, SigningSession,
    UnlockKeyResponse,
};
use tokio::sync::oneshot;
use tonic::Status;
use zcash_keys::keys::UnifiedSpendingKey;

use crate::errors::{tx_error, vault_error};
use crate::keys::AUDIT_TARGET;
use crate::service::{DaemonState, unix_now};
use crate::with_wallet;

/// One pending (or finished) passphrase session.
struct Session {
    key_id: String,
    step: u32,
    created_at: i64,
    expires_at: i64,
    summary: v1::Proposal,
    status: SessionStatus,
    last_error: String,
    /// Present while awaiting a signature; the stream task holds the other
    /// end. Dropped on abort, which the task sees as `CANCELLED`.
    deliver: Option<oneshot::Sender<UnifiedSpendingKey>>,
}

impl Session {
    fn to_proto(&self, session_id: &str) -> SigningSession {
        SigningSession {
            session_id: session_id.to_string(),
            key_id: self.key_id.clone(),
            kind: SignatureKind::Passphrase as i32,
            purpose: SessionPurpose::Send as i32,
            status: self.status as i32,
            created_at: self.created_at,
            expires_at: self.expires_at,
            summary: Some(self.summary.clone()),
            step: self.step,
            last_error: self.last_error.clone(),
            payload: Vec::new(),
        }
    }
}

/// Finished sessions kept for `tx sessions --include-finished`, newest
/// first, bounded.
const FINISHED_KEPT: usize = 64;

/// The daemon's in-memory signing sessions (API.md §6.1: passphrase kinds
/// are not persisted).
#[derive(Default)]
pub(crate) struct SessionHub {
    sessions: Mutex<BTreeMap<String, Session>>,
}

impl std::fmt::Debug for SessionHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHub")
            .field("sessions", &self.lock().len())
            .finish()
    }
}

impl SessionHub {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Session>> {
        crate::lock(&self.sessions)
    }

    /// Create a session awaiting a passphrase for `key_id`. Returns its id
    /// and the receiver the stream task waits on.
    pub(crate) fn create(
        &self,
        key_id: &str,
        step: u32,
        ttl: Duration,
        summary: v1::Proposal,
    ) -> (String, i64, oneshot::Receiver<UnifiedSpendingKey>) {
        let session_id = gyges_core::pczt_io::new_session_id();
        let (tx, rx) = oneshot::channel();
        let now = unix_now();
        let expires_at = now + i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
        let mut all = self.lock();
        all.insert(
            session_id.clone(),
            Session {
                key_id: key_id.to_string(),
                step,
                created_at: now,
                expires_at,
                summary,
                status: SessionStatus::AwaitingSignature,
                last_error: String::new(),
                deliver: Some(tx),
            },
        );
        prune(&mut all);
        (session_id, expires_at, rx)
    }

    /// The key a pending session belongs to.
    fn key_of(&self, session_id: &str) -> Option<String> {
        self.lock()
            .get(session_id)
            .filter(|s| s.status == SessionStatus::AwaitingSignature)
            .map(|s| s.key_id.clone())
    }

    /// Hand the derived key to the waiting stream and mark the session
    /// completed. `false` when the session is gone or no longer pending.
    fn complete(&self, session_id: &str, usk: UnifiedSpendingKey) -> bool {
        let mut all = self.lock();
        let Some(s) = all.get_mut(session_id) else {
            return false;
        };
        let Some(tx) = s.deliver.take() else {
            return false;
        };
        if tx.send(usk).is_err() {
            // The stream went away; nothing to sign for.
            s.status = SessionStatus::Failed;
            s.last_error = "the client disconnected before signing".into();
            return false;
        }
        s.status = SessionStatus::Completed;
        true
    }

    /// A session whose key was delivered but whose work then failed
    /// (`tx resume` building step 2): `Completed` becomes `Failed` with the
    /// reason, so `tx sessions --include-finished` shows it.
    pub(crate) fn fail(&self, session_id: &str, error: &str) {
        let mut all = self.lock();
        if let Some(s) = all.get_mut(session_id) {
            s.status = SessionStatus::Failed;
            s.last_error = error.to_string();
            s.deliver = None;
        }
    }

    /// Mark a session finished (expired, failed, aborted) without
    /// delivering a key; dropping the sender wakes the task.
    pub(crate) fn finish(
        &self,
        session_id: &str,
        status: SessionStatus,
        error: &str,
    ) -> Option<SigningSession> {
        let mut all = self.lock();
        let s = all.get_mut(session_id)?;
        if s.status == SessionStatus::AwaitingSignature {
            s.status = status;
            s.last_error = error.to_string();
            s.deliver = None;
        }
        Some(s.to_proto(session_id))
    }

    fn list(&self, key_id: &str, include_finished: bool) -> Vec<SigningSession> {
        self.lock()
            .iter()
            .filter(|(_, s)| key_id.is_empty() || s.key_id == key_id)
            .filter(|(_, s)| include_finished || s.status == SessionStatus::AwaitingSignature)
            .map(|(id, s)| s.to_proto(id))
            .collect()
    }
}

/// Drop the oldest finished sessions beyond [`FINISHED_KEPT`].
fn prune(all: &mut BTreeMap<String, Session>) {
    let mut finished: Vec<(i64, String)> = all
        .iter()
        .filter(|(_, s)| s.status != SessionStatus::AwaitingSignature)
        .map(|(id, s)| (s.created_at, id.clone()))
        .collect();
    if finished.len() > FINISHED_KEPT {
        finished.sort();
        for (_, id) in finished.iter().take(finished.len() - FINISHED_KEPT) {
            all.remove(id);
        }
    }
}

/// Finishes a session as failed when the waiting task goes away (client
/// disconnect, error) before the key arrived.
pub(crate) struct SessionGuard {
    hub: Arc<DaemonState>,
    session_id: String,
}

impl SessionGuard {
    pub(crate) fn new(state: &Arc<DaemonState>, session_id: &str) -> Self {
        Self {
            hub: state.clone(),
            session_id: session_id.to_string(),
        }
    }

    pub(crate) fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.hub.sessions.finish(
            &self.session_id,
            SessionStatus::Failed,
            "the send was abandoned before a passphrase arrived",
        );
    }
}

/// `UnlockKey { session_id, passphrase }` (API.md §6.2): verify the
/// passphrase, derive the key, hand it to the stream. No token is returned
/// and no unlock is created.
pub(crate) async fn satisfy_session(
    state: Arc<DaemonState>,
    session_id: String,
    passphrase: SecretString,
) -> Result<UnlockKeyResponse, Status> {
    let not_found = || {
        GygesError::new(
            ErrorReason::SessionNotFound,
            "no such pending signing session",
        )
        .with_session(&session_id)
        .into_status()
    };
    let key_id = state.sessions.key_of(&session_id).ok_or_else(not_found)?;
    let key = state.resolve_key(&key_id)?;
    let params = state.registry.params();
    let account_index = key.profile().account_index;
    let st = state.clone();
    let k = key.clone();
    let usk = tokio::task::spawn_blocking(move || {
        let entropy = st.vault.verify_passphrase(&k, passphrase)?;
        Ok::<_, gyges_core::vault::VaultError>(core_tx::spending_key(
            &params,
            &entropy,
            account_index,
        ))
    })
    .await
    .map_err(|e| Status::internal(e.to_string()))?
    .map_err(|e| vault_error(e, &key_id).into_status())?
    .map_err(|e| tx_error(e, &key_id).into_status())?;
    if !state.sessions.complete(&session_id, usk) {
        return Err(not_found());
    }
    tracing::info!(target: AUDIT_TARGET, key_id, event = "session_completed");
    Ok(UnlockKeyResponse {
        session_token: Vec::new(),
        expires_at: 0,
        scope: v1::UnlockScope::Unspecified as i32,
    })
}

/// `ListSigningSessions`: the passphrase sessions held here, then the
/// Keystone sessions and the ZIP 320 transfers from each key's wallet.
pub(crate) async fn list_signing_sessions(
    state: &DaemonState,
    req: &ListSigningSessionsRequest,
) -> ListSigningSessionsResponse {
    let mut sessions = state.sessions.list(&req.key_id, req.include_finished);
    sessions.extend(crate::keystone::list(state, &req.key_id, req.include_finished).await);
    ListSigningSessionsResponse {
        sessions,
        tex_transfers: crate::tex::list(state, &req.key_id, req.include_finished).await,
    }
}

/// `AbortSigningSession`: a Keystone session's row is aborted; a passphrase
/// session's waiting stream ends with `CANCELLED`.
pub(crate) async fn abort_signing_session(
    state: &DaemonState,
    req: AbortSigningSessionRequest,
) -> Result<SigningSession, Status> {
    if let Some(session) = crate::keystone::abort(state, &req.session_id).await? {
        return Ok(session);
    }
    let session = state
        .sessions
        .finish(
            &req.session_id,
            SessionStatus::Aborted,
            "aborted by the client",
        )
        .ok_or_else(|| {
            GygesError::new(ErrorReason::SessionNotFound, "no such signing session")
                .with_session(&req.session_id)
                .into_status()
        })?;
    tracing::info!(target: AUDIT_TARGET, key_id = session.key_id, event = "session_aborted");
    Ok(session)
}

/// [`sessions::set_state`] on the key's wallet.
pub(crate) async fn set_session_state(
    key: &Arc<KeyEntry>,
    session_id: &str,
    to: SessionState,
    txid: Option<[u8; 32]>,
    error: Option<&str>,
) -> Result<(), TxError> {
    let sid = session_id.to_string();
    let error = error.map(str::to_string);
    with_wallet(key, move |w| {
        Ok(sessions::set_state(w, &sid, to, txid, error.as_deref())?)
    })
    .await
}

/// [`sessions::leave_awaiting`] on the key's wallet: `true` when the row
/// was still awaiting a signature.
pub(crate) async fn leave_awaiting(
    key: &Arc<KeyEntry>,
    session_id: &str,
    to: SessionState,
    error: Option<&str>,
) -> Result<bool, TxError> {
    let sid = session_id.to_string();
    let error = error.map(str::to_string);
    with_wallet(key, move |w| {
        Ok(sessions::leave_awaiting(w, &sid, to, error.as_deref())?)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_hub_lifecycle() {
        let hub = SessionHub::default();
        let (id, _, rx) = hub.create("main", 1, Duration::from_secs(60), v1::Proposal::default());
        assert_eq!(hub.key_of(&id).as_deref(), Some("main"));
        assert_eq!(hub.list("", false).len(), 1);
        assert!(hub.list("other", false).is_empty());
        let s = hub.finish(&id, SessionStatus::Aborted, "aborted").unwrap();
        assert_eq!(s.status(), SessionStatus::Aborted);
        assert!(hub.key_of(&id).is_none());
        assert!(hub.list("", false).is_empty());
        assert_eq!(hub.list("", true).len(), 1);
        // The receiver sees the drop.
        assert!(rx.blocking_recv().is_err());
        // Finishing twice keeps the first status.
        let s = hub.finish(&id, SessionStatus::Failed, "x").unwrap();
        assert_eq!(s.status(), SessionStatus::Aborted);
    }
}
