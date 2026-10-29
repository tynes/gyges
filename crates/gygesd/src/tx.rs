//! The spending RPCs: `SendTransaction`, `ShieldFunds`, `GetBalance`, the
//! passphrase signing sessions behind `UnlockKey { session_id }`,
//! `ListSigningSessions` and `AbortSigningSession` (API.md §4.1, §6).
//!
//! A send is one task per stream that walks `gyges_core::tx` step by step
//! and emits an event after each (`Proposed`, `Proving`,
//! `SignatureRequired`, `Signed`, `Broadcast`, `Mined`). The wallet work
//! runs under `spawn_blocking` holding the key's wallet lock for one step at
//! a time, so the sync scheduler interleaves with it.
//!
//! Prove before unlock (Q-S3): the proposal is built and proven while the
//! vault is locked, except when it spends Sapling notes, whose proofs need
//! the proof generation key: then the key is obtained first, inserted by
//! the Updater role, and the PCZT is proven and signed in this stream
//! without ever being written (THREAT_MODEL.md §6 item 1). The spending
//! key is obtained from, in order, the
//! connection-scoped token the request carries, a daemon-scoped unlock, or
//! a **signing session**: the stream pauses on `SignatureRequired` and the
//! client answers with `UnlockKey { session_id, passphrase }`, which
//! verifies the passphrase (per-key back-off included), derives the
//! spending key and hands it to the waiting task through a channel. The key
//! is used for the signing step and dropped. Passphrase sessions live in
//! memory only (API.md §6.1): the stream that created one is gone after a
//! restart.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use age::secrecy::SecretString;
use gyges_chain::{ChainBackend, ChainError};
use gyges_core::db::sessions::{self, SessionState};
use gyges_core::tx::{self as core_tx, AmountSpec, Expected, ProposalSummary, TxError};
use gyges_core::vault::manager::{Auth, Token};
use gyges_core::{KeyEntry, SigningMode};
use gyges_proto::v1::{
    self, AbortSigningSessionRequest, ErrorReason, GetBalanceRequest, GetBalanceResponse,
    GygesError, ListSigningSessionsRequest, ListSigningSessionsResponse, SendEvent,
    SendTransactionRequest, SessionPurpose, SessionStatus, ShieldFundsRequest, SignatureKind,
    SignatureRequired, SigningSession, UnlockKeyResponse, send_event,
};
use pczt::Pczt;
use prost::Message as _;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::conn::ConnInfo;
use crate::keys::{AUDIT_TARGET, proto_pool, vault_error};
use crate::service::{DaemonState, invalid, unix_now};
use crate::tex::{self, DriveError, Offered};
use crate::with_wallet;

/// The server-streaming response type for `SendTransaction` / `ShieldFunds`.
pub(crate) type SendStream = tonic::codegen::BoxStream<SendEvent>;

// ---------------------------------------------------------------------------
// Signing sessions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// `TxError` → the typed error (API.md §3).
pub(crate) fn tx_error(e: TxError, key_id: &str) -> GygesError {
    let err = match e {
        TxError::InsufficientFunds {
            available,
            required,
        } => GygesError::new(
            ErrorReason::InsufficientFunds,
            format!("insufficient funds: {available} zatoshis spendable, {required} needed"),
        ),
        TxError::NotSynced(detail) => GygesError::new(ErrorReason::NotSynced, detail),
        TxError::InvalidArgument(detail) => GygesError::new(ErrorReason::InvalidArgument, detail),
        TxError::UnsupportedPool(detail) => GygesError::new(ErrorReason::UnsupportedPool, detail),
        // A tampered or stale PCZT is the client's problem (exit 6), not a
        // daemon failure.
        TxError::Verifier(detail) => GygesError::new(ErrorReason::InvalidArgument, detail),
        TxError::Internal(detail) => {
            // Upstream error texts can quote addresses or values, so the
            // detail goes to the client and to `debug` only (API.md §4.5).
            tracing::error!(key_id, "transaction engine failure");
            tracing::debug!(key_id, error = %detail, "transaction engine failure detail");
            GygesError::new(ErrorReason::Internal, detail)
        }
    };
    err.with_key(key_id)
}

/// [`with_wallet`] for an RPC: a failure is the key's typed error.
pub(crate) async fn wallet_rpc<T: Send + 'static>(
    key: &Arc<KeyEntry>,
    f: impl FnOnce(&mut gyges_core::registry::Wallet) -> Result<T, TxError> + Send + 'static,
) -> Result<T, Status> {
    with_wallet(key, f)
        .await
        .map_err(|e| tx_error(e, key.key_id()).into_status())
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

/// Broadcast a signed session's transaction over `route`. A failure is
/// recorded on the row (still `Signed`, with the node's text when it gave
/// one) and returned.
pub(crate) async fn broadcast_signed(
    key: &Arc<KeyEntry>,
    chain: &Arc<dyn ChainBackend>,
    route: &Route,
    session_id: &str,
    raw: Vec<u8>,
) -> Result<(), GygesError> {
    let Err(e) = route.send(chain, raw, key.key_id()).await else {
        return Ok(());
    };
    let text = if e.node_error.is_empty() {
        &e.detail
    } else {
        &e.node_error
    };
    let _ = set_session_state(key, session_id, SessionState::Signed, None, Some(text)).await;
    Err(e)
}

pub(crate) fn broadcast_error(e: ChainError, key_id: &str) -> GygesError {
    match e {
        ChainError::Rejected(text) => {
            let mut err = GygesError::new(
                ErrorReason::NodeRejected,
                "the node rejected the transaction; it stays in the wallet as unmined until it expires",
            )
            .with_key(key_id);
            err.node_error = text;
            err
        }
        ChainError::Unreachable(detail) => {
            GygesError::new(ErrorReason::NodeUnreachable, detail).with_key(key_id)
        }
        other => GygesError::new(ErrorReason::Internal, other.to_string()).with_key(key_id),
    }
}

/// Where a transaction goes: the node's `sendrawtransaction`, or the
/// fallback endpoint's `SendTransaction` for `--via-tor` and
/// `broadcast_via_tor` (THREAT_MODEL.md §3 row 10).
#[derive(Clone)]
pub(crate) enum Route {
    Node,
    Endpoint(Arc<dyn gyges_chain::ChainBackend>),
}

impl Route {
    /// The `via` field of the `broadcast` audit event.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Route::Node => "node",
            Route::Endpoint(_) => "fallback",
        }
    }

    /// Broadcast `raw` over this route; `node` is used for [`Route::Node`].
    pub(crate) async fn send(
        &self,
        node: &Arc<dyn gyges_chain::ChainBackend>,
        raw: Vec<u8>,
        key_id: &str,
    ) -> Result<(), GygesError> {
        match self {
            Route::Node => node
                .send_raw_transaction(raw)
                .await
                .map_err(|e| broadcast_error(e, key_id)),
            Route::Endpoint(endpoint) => {
                endpoint
                    .send_raw_transaction(raw)
                    .await
                    .map_err(|e| match e {
                        ChainError::Unreachable(detail) => GygesError::new(
                            ErrorReason::FallbackUnavailable,
                            format!(
                                "the fallback endpoint could not be reached for the --via-tor broadcast \
                                 (it stays in the wallet as unmined until it expires): {detail}"
                            ),
                        )
                        .with_key(key_id),
                        other => broadcast_error(other, key_id),
                    })
            }
        }
    }
}

/// The route for a broadcast, decided before anything is proven or signed.
/// `requested` is the request's `via_tor`; `broadcast_via_tor` in
/// `config.toml` turns it on for every broadcast. Asking for Tor never falls
/// back to the node: without a Tor endpoint the request is refused. A
/// `use_tor = false` endpoint stands in on regtest only, as it does for
/// backfill in CI (TESTING.md §2).
pub(crate) fn broadcast_route(
    state: &DaemonState,
    requested: bool,
    key_id: &str,
) -> Result<Route, Status> {
    if !(requested || state.config.fallback_lightwalletd.broadcast_via_tor) {
        return Ok(Route::Node);
    }
    let refuse = |detail: &str| {
        GygesError::new(ErrorReason::FallbackUnavailable, detail)
            .with_key(key_id)
            .into_status()
    };
    let Some(endpoint) = state.fallback.clone() else {
        return Err(refuse(
            "--via-tor broadcasts through the fallback endpoint's Tor client, and none is configured \
             ([fallback_lightwalletd] enabled = true with a grpc_url); nothing was broadcast",
        ));
    };
    match endpoint.transport() {
        gyges_chain::Transport::Tor { .. } => {}
        gyges_chain::Transport::Direct if state.network == gyges_core::Network::Regtest => {
            tracing::warn!(
                key_id,
                "--via-tor on regtest with fallback_lightwalletd.use_tor = false: broadcasting to the endpoint directly"
            );
        }
        gyges_chain::Transport::Direct => {
            return Err(refuse(
                "--via-tor needs fallback_lightwalletd.use_tor = true; the configured endpoint is reached \
                 directly, which would show it this host's address; nothing was broadcast",
            ));
        }
    }
    Ok(Route::Endpoint(endpoint))
}

// ---------------------------------------------------------------------------
// Proto conversion
// ---------------------------------------------------------------------------

pub(crate) fn proto_proposal(s: &ProposalSummary) -> v1::Proposal {
    v1::Proposal {
        steps: s
            .steps
            .iter()
            .enumerate()
            .map(|(i, step)| v1::ProposalStep {
                index: i as u32 + 1,
                inputs: step
                    .inputs
                    .iter()
                    .map(|inp| v1::ProposedInput {
                        pool: proto_pool(inp.pool) as i32,
                        count: inp.count,
                        value: i64::try_from(inp.value).unwrap_or(i64::MAX),
                    })
                    .collect(),
                outputs: step
                    .outputs
                    .iter()
                    .map(|o| v1::ProposedOutput {
                        address: o.address.clone(),
                        pool: proto_pool(o.pool) as i32,
                        value: i64::try_from(o.value).unwrap_or(i64::MAX),
                        is_change: o.is_change,
                        is_ephemeral: o.is_ephemeral,
                        has_memo: o.has_memo,
                    })
                    .collect(),
                fee: i64::try_from(step.fee).unwrap_or(i64::MAX),
                transparent_only: step.transparent_only,
            })
            .collect(),
        total_debit: i64::try_from(s.total_debit).unwrap_or(i64::MAX),
        total_fee: i64::try_from(s.total_fee).unwrap_or(i64::MAX),
        anchor_height: s.anchor_height,
        expiry_height: s.expiry_height,
        min_confirmations: s.min_confirmations,
        upstream_proposal: s.upstream.clone(),
    }
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

/// What every spending RPC checks before its stream starts, so that the
/// errors arrive as the RPC's status rather than as the first stream item.
pub(crate) struct Prepared {
    pub(crate) key: Arc<KeyEntry>,
    /// `None` for `SignPczt`, which needs no node (and runs air-gapped).
    pub(crate) chain: Option<Arc<dyn gyges_chain::ChainBackend>>,
    auth: PreAuth,
    pub(crate) min_confirmations: u32,
}

impl Prepared {
    fn chain(&self) -> Result<&Arc<dyn gyges_chain::ChainBackend>, Status> {
        self.chain
            .as_ref()
            .ok_or_else(|| Status::internal("this request was prepared without a node"))
    }
}

/// What a spending RPC is for, which decides the profiles it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// `SendTransaction` / `ShieldFunds`: the daemon signs (`local-seed`)
    /// or the Keystone does, through a persisted session.
    Spend,
    /// `CreatePczt`: nothing is signed here, so a watch-only or Keystone
    /// profile qualifies too.
    CreatePczt,
    /// `SignPczt`: a profile that holds a seed (`local-seed` or
    /// `signer-only`); no node and no sync state needed.
    SignPczt,
}

/// How the key may be obtained without a session.
#[derive(Clone)]
enum PreAuth {
    Token { conn: ConnInfo, token: Token },
    None,
}

pub(crate) fn prepare(
    state: &DaemonState,
    conn: Option<ConnInfo>,
    key_id: &str,
    session_token: &[u8],
    min_confirmations: u32,
    purpose: Purpose,
) -> Result<Prepared, Status> {
    let key = state.resolve_key(key_id)?;
    let kid = key.key_id().to_string();
    let typed = |reason, detail: &str| GygesError::new(reason, detail).with_key(&kid).into_status();
    let refused = match (key.profile().signing_mode, purpose) {
        (SigningMode::LocalSeed, _)
        | (SigningMode::KeystoneQr, Purpose::Spend)
        | (SigningMode::WatchOnly | SigningMode::KeystoneQr, Purpose::CreatePczt)
        | (SigningMode::SignerOnly, Purpose::SignPczt) => None,
        (SigningMode::KeystoneQr, _) => Some((
            ErrorReason::HardwareSigner,
            "`pczt sign` cannot sign with a Keystone; send with `gyges tx send`, which shows the \
             device its QR request",
        )),
        (SigningMode::WatchOnly, Purpose::SignPczt) => Some((
            ErrorReason::InvalidArgument,
            "a watch-only profile holds no seed and cannot sign",
        )),
        (SigningMode::WatchOnly, _) => Some((
            ErrorReason::InvalidArgument,
            "a watch-only profile cannot sign; use `gyges pczt create` and sign elsewhere",
        )),
        (SigningMode::SignerOnly, _) => Some((
            ErrorReason::InvalidArgument,
            "a signer-only profile has no wallet to spend from; use `gyges pczt sign` on it",
        )),
    };
    if let Some((reason, detail)) = refused {
        return Err(typed(reason, detail));
    }
    let chain = if purpose == Purpose::SignPczt {
        None
    } else {
        let chain = connected_chain(state, &kid)?;
        match state.sync.get(&kid) {
            Some(p) if p.spendable => {}
            Some(p) => {
                return Err(typed(
                    ErrorReason::NotSynced,
                    &format!(
                        "key '{kid}' is not spendable yet ({}); run `gyges sync wait`",
                        crate::sync::to_proto(&p).detail
                    ),
                ));
            }
            None => {
                return Err(typed(
                    ErrorReason::NotSynced,
                    "synchronisation has not started for this key yet; run `gyges sync wait`",
                ));
            }
        }
        Some(chain)
    };
    let auth = parse_auth(conn, session_token, &kid)?;
    Ok(Prepared {
        key,
        chain,
        auth,
        min_confirmations: state.min_confirmations(min_confirmations),
    })
}

fn parse_auth(conn: Option<ConnInfo>, session_token: &[u8], kid: &str) -> Result<PreAuth, Status> {
    if session_token.is_empty() {
        return Ok(PreAuth::None);
    }
    let token = Token::from_slice(session_token).ok_or_else(|| {
        GygesError::new(
            ErrorReason::InvalidArgument,
            "session_token must be the 32 bytes UnlockKey returned",
        )
        .with_key(kid)
        .into_status()
    })?;
    let conn = conn.ok_or_else(|| Status::internal("no connection info on this request"))?;
    Ok(PreAuth::Token { conn, token })
}

pub(crate) fn parse_amount(amount: Option<v1::Amount>) -> Result<AmountSpec, Status> {
    match amount.and_then(|a| a.value) {
        Some(v1::amount::Value::Zatoshis(z)) => {
            let z = u64::try_from(z).map_err(|_| invalid("the amount must be positive"))?;
            if z == 0 {
                return Err(invalid("the amount must be positive"));
            }
            Zatoshis::from_u64(z)
                .map(AmountSpec::Zatoshis)
                .map_err(|_| invalid("the amount exceeds the money supply"))
        }
        Some(v1::amount::Value::Max(true)) => Ok(AmountSpec::Max),
        Some(v1::amount::Value::Max(false)) | None => Err(invalid("an amount is required")),
    }
}

// ---------------------------------------------------------------------------
// The RPCs
// ---------------------------------------------------------------------------

/// What the proposing step built, unless dry-run.
enum Built {
    /// A single-step proposal as its PCZT, with what the Verifier checks.
    Pczt(Expected, Box<Pczt>),
    /// A two-step ZIP 320 proposal; the builder takes it whole once the key
    /// is there (ARCHITECTURE.md §3.3).
    Tex(Box<core_tx::SendProposal>),
}

/// What the proposing step produces: the summary for `Proposed`, and, unless
/// dry-run, what the rest of the pipeline needs.
type Proposed = (ProposalSummary, Option<Built>);

/// `SendTransaction` (API.md §4.1).
pub(crate) fn send_transaction(
    state: Arc<DaemonState>,
    conn: Option<ConnInfo>,
    req: SendTransactionRequest,
) -> Result<SendStream, Status> {
    let prepared = prepare(
        &state,
        conn,
        &req.key_id,
        &req.session_token,
        req.min_confirmations,
        Purpose::Spend,
    )?;
    let key_id = prepared.key.key_id().to_string();
    let params = state.registry.params();
    let to = core_tx::parse_recipient(&params, &req.to)
        .map_err(|e| tx_error(e, &key_id).into_status())?;
    let memo = core_tx::memo_for(&to, &req.memo).map_err(|e| tx_error(e, &key_id).into_status())?;
    let amount = parse_amount(req.amount)?;
    let route = broadcast_route(&state, req.via_tor, &key_id)?;
    if matches!(route, Route::Endpoint(_)) && matches!(to, zcash_keys::address::Address::Tex(_)) {
        // The TexQueue broadcasts and rebroadcasts both steps through the
        // node; a per-row route is not persisted yet.
        return Err(GygesError::new(
            ErrorReason::InvalidArgument,
            "--via-tor (or broadcast_via_tor) is not supported for tex1 recipients yet: the ZIP 320 \
             queue broadcasts both steps through the node; nothing was broadcast",
        )
        .with_key(&key_id)
        .into_status());
    }
    let keystone = is_keystone(&prepared);
    if keystone && matches!(to, zcash_keys::address::Address::Tex(_)) {
        // THREAT_MODEL.md §6 item 7: how the device shows ZIP 320's
        // transparent step 2 needs verification on hardware, and upstream
        // builds a PCZT from a single-step proposal only.
        return Err(GygesError::new(
            ErrorReason::HardwareSigner,
            "a tex1 recipient cannot be paid from a Keystone yet: its two-step transfer needs \
             verification on the device (THREAT_MODEL.md §6 item 7); nothing was sent",
        )
        .with_key(&key_id)
        .into_status());
    }
    if keystone && !req.dry_run {
        refuse_if_pending(&prepared)?;
    }
    let spend_pools = prepared.key.profile().spend_pools.clone();
    let min_confirmations = prepared.min_confirmations;
    let dry_run = req.dry_run;
    let propose = move |wallet: &mut gyges_core::registry::Wallet| -> Result<Proposed, TxError> {
        let account = core_tx::account_of(wallet)?;
        let proposal = core_tx::propose_send(
            wallet,
            &params,
            account,
            &spend_pools,
            &to,
            amount,
            memo,
            min_confirmations,
        )?;
        let mut summary = core_tx::summarize(&params, &proposal, min_confirmations);
        let expiry = keystone_expiry(keystone, proposal.min_target_height(), &mut summary);
        if dry_run {
            return Ok((summary, None));
        }
        if core_tx::is_two_step(&proposal) {
            return Ok((summary, Some(Built::Tex(Box::new(proposal)))));
        }
        let expected = Expected::from_proposal(&params, &proposal, expiry)?;
        let pczt = core_tx::build_pczt(wallet, &params, account, &proposal, expiry)?;
        Ok((summary, Some(Built::Pczt(expected, Box::new(pczt)))))
    };
    Ok(run(
        state,
        prepared,
        Box::new(propose),
        route,
        req.dry_run,
        req.wait_for_mined,
    ))
}

/// Whether the key signs on a Keystone.
fn is_keystone(prepared: &Prepared) -> bool {
    prepared.key.profile().signing_mode == SigningMode::KeystoneQr
}

/// A Keystone send waits for a person and a device, possibly across a
/// restart, for up to `vault.signing_session_ttl`; it gets the expiry a
/// PCZT file gets (`target + 1152`, about a day) instead of `tx send`'s 40
/// blocks. Returns the override and updates the summary to match.
fn keystone_expiry(
    keystone: bool,
    min_target: impl Into<BlockHeight>,
    summary: &mut ProposalSummary,
) -> Option<BlockHeight> {
    if !keystone {
        return None;
    }
    let expiry = min_target.into() + crate::roles::PCZT_EXPIRY_BLOCKS;
    summary.expiry_height = u32::from(expiry);
    Some(expiry)
}

/// One Keystone session per key at a time: until it is completed or
/// aborted, another proposal could pick the same notes.
fn refuse_if_pending(prepared: &Prepared) -> Result<(), Status> {
    if let Some(session_id) = crate::keystone::pending_for(&prepared.key)? {
        let key_id = prepared.key.key_id();
        return Err(GygesError::new(
            ErrorReason::SignatureRequired,
            format!(
                "key '{key_id}' already has a Keystone signing session awaiting the device \
                 ({session_id}); complete it with `gyges pczt qr-import --session {session_id}` \
                 or abort it with `gyges tx abort {session_id}` first"
            ),
        )
        .with_key(key_id)
        .with_session(session_id)
        .into_status());
    }
    Ok(())
}

/// `ShieldFunds` (API.md §4.1): the same stream for a transparent → Orchard
/// proposal.
pub(crate) fn shield_funds(
    state: Arc<DaemonState>,
    conn: Option<ConnInfo>,
    req: ShieldFundsRequest,
) -> Result<SendStream, Status> {
    let prepared = prepare(
        &state,
        conn,
        &req.key_id,
        &req.session_token,
        0,
        Purpose::Spend,
    )?;
    // No per-request flag: `broadcast_via_tor` decides.
    let route = broadcast_route(&state, false, prepared.key.key_id())?;
    let params = state.registry.params();
    let threshold =
        u64::try_from(req.threshold).map_err(|_| invalid("the threshold must not be negative"))?;
    let keystone = is_keystone(&prepared);
    if keystone && !req.dry_run {
        refuse_if_pending(&prepared)?;
    }
    let min_confirmations = prepared.min_confirmations;
    let dry_run = req.dry_run;
    let propose = move |wallet: &mut gyges_core::registry::Wallet| -> Result<Proposed, TxError> {
        let account = core_tx::account_of(wallet)?;
        let proposal =
            core_tx::propose_shield(wallet, &params, account, threshold, min_confirmations)?;
        let mut summary = core_tx::summarize(&params, &proposal, min_confirmations);
        let expiry = keystone_expiry(keystone, proposal.min_target_height(), &mut summary);
        if dry_run {
            return Ok((summary, None));
        }
        let expected = Expected::from_proposal(&params, &proposal, expiry)?;
        let pczt = core_tx::build_pczt(wallet, &params, account, &proposal, expiry)?;
        Ok((summary, Some(Built::Pczt(expected, Box::new(pczt)))))
    };
    Ok(run(
        state,
        prepared,
        Box::new(propose),
        route,
        req.dry_run,
        req.wait_for_mined,
    ))
}

type ProposeFn =
    Box<dyn FnOnce(&mut gyges_core::registry::Wallet) -> Result<Proposed, TxError> + Send>;

/// Spawn the pipeline task and return its stream.
fn run(
    state: Arc<DaemonState>,
    prepared: Prepared,
    propose: ProposeFn,
    route: Route,
    dry_run: bool,
    wait_for_mined: bool,
) -> SendStream {
    let (tx, rx) = mpsc::channel::<Result<SendEvent, Status>>(16);
    tokio::spawn(async move {
        let key_id = prepared.key.key_id().to_string();
        let outcome = pipeline(
            &state,
            &prepared,
            propose,
            &route,
            dry_run,
            wait_for_mined,
            &tx,
        )
        .await;
        if let Err(status) = outcome {
            tracing::debug!(key_id, error = %status.message(), "send stream ended with an error");
            let _ = tx.send(Err(status)).await;
        }
    });
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// Step 1's `Proving` event for each pool, before (`done = false`) or
/// after proving.
async fn emit_proving(
    tx: &mpsc::Sender<Result<SendEvent, Status>>,
    pools: &[(v1::Pool, u32)],
    done: bool,
) -> Result<(), Status> {
    for &(pool, total) in pools {
        let progress = v1::ProvingProgress {
            step: 1,
            pool: pool as i32,
            actions_done: if done { total } else { 0 },
            actions_total: total,
        };
        emit(tx, send_event::Event::Proving(progress)).await?;
    }
    Ok(())
}

async fn emit(
    tx: &mpsc::Sender<Result<SendEvent, Status>>,
    event: send_event::Event,
) -> Result<(), Status> {
    send(tx, SendEvent { event: Some(event) }).await
}

async fn emit_broadcast(
    tx: &mpsc::Sender<Result<SendEvent, Status>>,
    step: u32,
    txid: String,
) -> Result<(), Status> {
    emit(
        tx,
        send_event::Event::Broadcast(v1::StepBroadcast { step, txid }),
    )
    .await
}

async fn emit_mined(
    tx: &mpsc::Sender<Result<SendEvent, Status>>,
    step: u32,
    txid: String,
    height: u32,
) -> Result<(), Status> {
    let mined = v1::StepMined { step, txid, height };
    emit(tx, send_event::Event::Mined(mined)).await
}

/// Send one stream item; `CANCELLED` once the client went away.
pub(crate) async fn send<E>(tx: &mpsc::Sender<Result<E, Status>>, item: E) -> Result<(), Status> {
    tx.send(Ok(item)).await.map_err(|_| cancelled())
}

pub(crate) fn cancelled() -> Status {
    Status::cancelled("client disconnected")
}

/// Wait a second between polls; `CANCELLED` once the client went away.
async fn idle_or_closed<E>(tx: &mpsc::Sender<E>) -> Result<(), Status> {
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(1)) => Ok(()),
        () = tx.closed() => Err(cancelled()),
    }
}

/// The node backend for a broadcast, refused when air-gapped or offline.
pub(crate) fn connected_chain(
    state: &DaemonState,
    key_id: &str,
) -> Result<Arc<dyn ChainBackend>, Status> {
    let refuse = |reason, detail: &str| GygesError::new(reason, detail).with_key(key_id);
    let chain = state.chain.clone().ok_or_else(|| {
        refuse(
            ErrorReason::Airgapped,
            "an air-gapped daemon cannot broadcast",
        )
    })?;
    if !chain.status().connected {
        return Err(refuse(
            ErrorReason::NodeUnreachable,
            "the node is not connected; the transaction could not be broadcast",
        )
        .into());
    }
    Ok(chain)
}

pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, TxError> + Send + 'static,
) -> Result<T, TxError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| TxError::Internal(format!("task failed: {e}")))?
}

/// The pipeline proper (API.md §4.1 event order for `n = 1`).
async fn pipeline(
    state: &Arc<DaemonState>,
    prepared: &Prepared,
    propose: ProposeFn,
    route: &Route,
    dry_run: bool,
    wait_for_mined: bool,
    tx: &mpsc::Sender<Result<SendEvent, Status>>,
) -> Result<(), Status> {
    let key = &prepared.key;
    let key_id = key.key_id().to_string();
    let err = |e: TxError| tx_error(e, &key_id).into_status();

    // 1–3. Propose (and, unless dry-run, build the PCZT) under the wallet lock.
    let (summary, rest) = wallet_rpc(key, propose).await?;
    let proto = proto_proposal(&summary);
    emit(tx, send_event::Event::Proposed(proto.clone())).await?;
    let (expected, pczt) = match rest {
        None => {
            debug_assert!(dry_run);
            return Ok(());
        }
        Some(Built::Tex(proposal)) => {
            return tex_pipeline(state, prepared, *proposal, proto, wait_for_mined, tx).await;
        }
        Some(Built::Pczt(expected, pczt)) => (expected, *pczt),
    };
    // A Keystone is shown the PCZT before it is proven (as Zodl does); the
    // proven copy is what its answer is applied to.
    let device_request = if is_keystone(prepared) {
        Some(gyges_core::keystone::device_request(&pczt).map_err(|e| {
            GygesError::new(ErrorReason::Internal, e.to_string())
                .with_key(&key_id)
                .into_status()
        })?)
    } else {
        None
    };

    // 4. Prove: one `Proving` per shielded pool with work before the
    // proofs, one after. Orchard, Ironwood and transparent need no secret,
    // so the vault stays locked (Q-S3). A Sapling spend needs its proof
    // generation key, derived from the seed, so the spending key comes
    // first and the PCZT is keyed, proven and signed here in memory
    // (THREAT_MODEL.md §6 item 1); `SignatureRequired` then precedes
    // `Proving`.
    let work = core_tx::proving_work(&pczt);
    let early_key = if work.sapling_spends == 0 {
        None
    } else if device_request.is_some() {
        return Err(GygesError::new(
            ErrorReason::UnsupportedPool,
            "a Keystone does not sign Sapling spends",
        )
        .with_key(&key_id)
        .into_status());
    } else {
        Some(obtain_key(state, prepared, &proto, tx, 1, signature_required).await?)
    };
    let pools: Vec<(v1::Pool, u32)> = [
        (v1::Pool::Orchard, work.orchard_actions),
        (v1::Pool::Ironwood, work.ironwood_actions),
        (
            v1::Pool::Sapling,
            work.sapling_outputs + work.sapling_spends,
        ),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .collect();
    emit_proving(tx, &pools, false).await?;
    let provers = state.provers.clone();
    let t0 = std::time::Instant::now();
    let (pczt, early_key) = blocking(move || {
        let pczt = match &early_key {
            Some(usk) => core_tx::insert_proof_generation_keys(pczt, usk)?,
            None => pczt,
        };
        Ok((core_tx::prove(pczt, &provers)?, early_key))
    })
    .await
    .map_err(err)?;
    emit_proving(tx, &pools, true).await?;
    tracing::info!(
        key_id,
        orchard_actions = work.orchard_actions,
        ironwood_actions = work.ironwood_actions,
        sapling_spends = work.sapling_spends,
        sapling_outputs = work.sapling_outputs,
        ms = t0.elapsed().as_millis(),
        "proposal proven"
    );

    let txid = if let Some(request) = device_request {
        // 5 (Keystone). A persisted session; the completion broadcasts.
        let via_tor = matches!(route, Route::Endpoint(_));
        let Some(txid) = crate::keystone::await_device(
            state, prepared, &proto, &expected, pczt, request, via_tor, tx,
        )
        .await?
        else {
            return Ok(());
        };
        emit(tx, send_event::Event::Signed(v1::StepSigned { step: 1 })).await?;
        txid
    } else {
        // 5. The spending key: token, daemon unlock, or a session (already
        // in hand when the proposal spends Sapling).
        let usk = match early_key {
            Some(usk) => usk,
            None => obtain_key(state, prepared, &proto, tx, 1, signature_required).await?,
        };
        let signer = core_tx::SignerId::of(key.profile(), &state.registry.params()).map_err(err)?;
        let pczt = wallet_rpc(key, move |w| core_tx::sign(Some(&*w), pczt, &usk, &signer)).await?;
        // `usk` was moved into the signing task and dropped there.

        // 6. Verify against the approved proposal (Q-K7).
        let owner_params = state.registry.params();
        let owner = wallet_rpc(key, move |w| core_tx::Owner::of_wallet(&owner_params, w)).await?;
        let pczt = core_tx::verify(pczt, &expected, &owner).map_err(err)?;

        // 7. Extract, record in the wallet, and broadcast.
        let provers = state.provers.clone();
        let (txid, raw) =
            wallet_rpc(key, move |w| core_tx::extract_and_store(w, pczt, &provers)).await?;
        emit(tx, send_event::Event::Signed(v1::StepSigned { step: 1 })).await?;
        route.send(prepared.chain()?, raw, &key_id).await?;
        tracing::info!(target: AUDIT_TARGET, key_id, event = "broadcast", via = route.name());
        tracing::info!(key_id, via = route.name(), "transaction broadcast");
        state.sync.wake();
        txid
    };
    let txid_hex = txid.to_string();
    emit_broadcast(tx, 1, txid_hex.clone()).await?;

    if wait_for_mined {
        let raw_txid = *txid.as_ref();
        loop {
            if let Some(h) = crate::sync::mined_height(key, raw_txid).await {
                return emit_mined(tx, 1, txid_hex, u32::from(h)).await;
            }
            state.sync.wake();
            idle_or_closed(tx).await?;
        }
    }
    Ok(())
}

/// The spending key from the request's token on this connection or from a
/// live daemon-scoped unlock; `Ok(None)` when neither applies and a
/// signing session is the way forward. A token that does not unlock is an
/// error (the client meant to use it).
pub(crate) fn key_from_unlock(
    state: &Arc<DaemonState>,
    prepared: &Prepared,
) -> Result<Option<UnifiedSpendingKey>, Status> {
    let key = &prepared.key;
    let key_id = key.key_id().to_string();
    let params = state.registry.params();
    let account_index = key.profile().account_index;
    let derive = |auth: Auth<'_>| {
        state.vault.with_entropy(&key_id, auth, |e| {
            core_tx::spending_key(&params, e, account_index)
        })
    };
    let from_unlock = match &prepared.auth {
        PreAuth::Token { conn, token } => derive(Auth::Token {
            conn: conn.id,
            token,
        }),
        PreAuth::None => derive(Auth::Daemon),
    };
    match from_unlock {
        Ok(usk) => {
            let usk = usk.map_err(|e| tx_error(e, &key_id).into_status())?;
            tracing::info!(target: AUDIT_TARGET, key_id, event = "sign", via = "unlock");
            Ok(Some(usk))
        }
        Err(gyges_core::vault::VaultError::Locked) => {
            if matches!(prepared.auth, PreAuth::Token { .. }) {
                return Err(GygesError::new(
                    ErrorReason::VaultLocked,
                    "the session token is not valid on this connection (expired, or from another connection)",
                )
                .with_key(&key_id)
                .into_status());
            }
            Ok(None)
        }
        Err(e) => Err(vault_error(e, &key_id).into_status()),
    }
}

/// `SignatureRequired` as a `tx send` stream event.
pub(crate) fn signature_required(r: SignatureRequired) -> SendEvent {
    SendEvent {
        event: Some(send_event::Event::SignatureRequired(r)),
    }
}

/// Step 5's key: the request's token on this connection, else a live
/// daemon-scoped unlock, else a signing session the client satisfies with
/// `UnlockKey { session_id }`. A session that times out is replaced by a
/// fresh `SignatureRequired` while the proposal can still be mined
/// (API.md §4.1), and ends the stream with `NOT_SYNCED` otherwise (without
/// a node, as in `SignPczt`, the file's expiry is the client's to watch, so
/// a fresh session always follows). `wrap` makes the stream's event type
/// out of the `SignatureRequired`.
pub(crate) async fn obtain_key<E: Send + 'static>(
    state: &Arc<DaemonState>,
    prepared: &Prepared,
    summary: &v1::Proposal,
    tx: &mpsc::Sender<Result<E, Status>>,
    step: u32,
    wrap: impl Fn(SignatureRequired) -> E,
) -> Result<UnifiedSpendingKey, Status> {
    let key = &prepared.key;
    let key_id = key.key_id().to_string();
    if let Some(usk) = key_from_unlock(state, prepared)? {
        return Ok(usk);
    }

    let ttl = state.config.vault.signing_session_ttl;
    loop {
        let (session_id, expires_at, rx) =
            state.sessions.create(&key_id, step, ttl, summary.clone());
        tracing::info!(target: AUDIT_TARGET, key_id, event = "session_created");
        let required = SignatureRequired {
            key_id: key_id.clone(),
            kind: SignatureKind::Passphrase as i32,
            session_id: session_id.clone(),
            expires_at,
            payload: Vec::new(),
            step,
            summary: Some(summary.clone()),
        };
        send(tx, wrap(required)).await?;
        let guard = SessionGuard {
            hub: state.clone(),
            session_id: session_id.clone(),
        };
        tokio::select! {
            got = tokio::time::timeout(ttl, rx) => match got {
                Ok(Ok(usk)) => {
                    guard.disarm();
                    tracing::info!(target: AUDIT_TARGET, key_id, event = "sign", via = "session");
                    return Ok(usk);
                }
                Ok(Err(_)) => {
                    // The sender was dropped without a key: aborted.
                    guard.disarm();
                    return Err(GygesError::new(
                        ErrorReason::Cancelled,
                        "the signing session was aborted",
                    )
                    .with_key(&key_id)
                    .with_session(session_id)
                    .into_status());
                }
                Err(_elapsed) => {
                    state
                        .sessions
                        .finish(&session_id, SessionStatus::Expired, "no passphrase arrived in time");
                    guard.disarm();
                    let tip = prepared
                        .chain
                        .as_ref()
                        .and_then(|c| c.status().bounds)
                        .map_or(0, |b| u32::from(b.tip_height));
                    if summary.expiry_height > 0 && tip >= summary.expiry_height {
                        return Err(GygesError::new(
                            ErrorReason::NotSynced,
                            "the signing session expired and the proposal can no longer be mined; start over",
                        )
                        .with_key(&key_id)
                        .into_status());
                    }
                    // Otherwise: a fresh session, same proposal.
                }
            },
            () = tx.closed() => return Err(cancelled()),
        }
    }
}

/// The ZIP 320 branch of the pipeline (ARCHITECTURE.md §3.3, API.md §4.1
/// for `n = 2`): the key comes first, because `create_proposed_transactions`
/// proves and signs both steps in one go; then both are stored, the row is
/// inserted, step 1 and step 2 are offered to the node, and the queue owns
/// the rest.
async fn tex_pipeline(
    state: &Arc<DaemonState>,
    prepared: &Prepared,
    proposal: core_tx::SendProposal,
    proto: v1::Proposal,
    wait_for_mined: bool,
    tx: &mpsc::Sender<Result<SendEvent, Status>>,
) -> Result<(), Status> {
    use gyges_core::TexState;
    use gyges_core::db::tex::{self as core_tex, TexRow};

    let key = &prepared.key;
    let key_id = key.key_id().to_string();
    let err = |e: TxError| tx_error(e, &key_id).into_status();

    // One signature prompt per send: the key is obtained once and used for
    // both steps inside the builder.
    let usk = obtain_key(state, prepared, &proto, tx, 1, signature_required).await?;
    let chain = prepared.chain()?.clone();
    let pools: Vec<(v1::Pool, u32)> = proto
        .steps
        .first()
        .map(|s| {
            s.inputs
                .iter()
                .filter(|i| i.pool() != v1::Pool::Transparent)
                .map(|i| (i.pool(), i.count))
                .collect()
        })
        .unwrap_or_default();
    emit_proving(tx, &pools, false).await?;
    let params = state.registry.params();
    let provers = state.provers.clone();
    let t0 = std::time::Instant::now();
    let built = wallet_rpc(key, move |w| {
        let account = core_tx::account_of(w)?;
        core_tx::create_tex_transactions(w, &params, account, &proposal, usk, &provers)
    })
    .await?;
    emit_proving(tx, &pools, true).await?;
    tracing::info!(
        key_id,
        ms = t0.elapsed().as_millis(),
        "zip 320 transactions built"
    );
    emit(tx, send_event::Event::Signed(v1::StepSigned { step: 1 })).await?;
    emit(tx, send_event::Event::Signed(v1::StepSigned { step: 2 })).await?;

    // Persist before the first broadcast, so a crash between the two leaves
    // a row the queue finishes (TESTING.md §3 row 12).
    let id = *built.step1_txid.as_ref();
    let row = TexRow {
        step1_txid: id,
        step2_txid: *built.step2_txid.as_ref(),
        proposal: proto.encode_to_vec(),
        step1_raw: built.step1_raw.clone(),
        step2_raw: built.step2_raw.clone(),
        ephemeral_addr: built.ephemeral_addr.clone(),
        recipient: built.recipient.clone(),
        amount: built.amount,
        expiry_height: built.expiry_height,
        state: TexState::Built,
        created_at: unix_now(),
        last_attempt_at: None,
        attempts: 0,
        last_error: None,
    };
    wallet_rpc(key, move |w| Ok(core_tex::insert(w, &row)?)).await?;
    tracing::info!(target: AUDIT_TARGET, key_id, event = "tex_queued");
    let step1_hex = built.step1_txid.to_string();
    let step2_hex = built.step2_txid.to_string();

    // Both steps go through the queue's broadcast, so a node that already
    // has a step counts as having taken it, as it does for the queue.
    let drive = |e: DriveError| match e {
        DriveError::Wallet(e) => err(e),
        DriveError::Node(e) => broadcast_error(e, &key_id).into_status(),
    };
    let offer = |raw, step| tex::offer(chain.as_ref(), key, id, raw, step, "transaction broadcast");

    // Step 1: a refusal fails the transfer (nothing left the shielded pool).
    let refused = match offer(built.step1_raw, 1).await {
        Ok(Offered::Accepted) => None,
        Ok(Offered::Refused(text)) => {
            let _ = tex::set_state(key, id, TexState::Failed, Some(text.clone())).await;
            Some(DriveError::Node(ChainError::Rejected(text)))
        }
        Err(e) => Some(e),
    };
    if let Some(e) = refused {
        state.tex.wake();
        return Err(drive(e));
    }
    tex::set_state(key, id, TexState::Step1Broadcast, None)
        .await
        .map_err(drive)?;
    emit_broadcast(tx, 1, step1_hex.clone()).await?;
    emit(
        tx,
        send_event::Event::TexQueued(v1::TexQueued {
            step1_txid: step1_hex.clone(),
            step2_txid: step2_hex.clone(),
        }),
    )
    .await?;

    // Step 2: offered at once; a node that does not chain mempool
    // transactions refuses it now and takes it from the queue once step 1
    // is mined.
    if let Ok(Offered::Accepted) = offer(built.step2_raw, 2).await {
        tex::set_state(key, id, TexState::Step2Broadcast, None)
            .await
            .map_err(drive)?;
        emit_broadcast(tx, 2, step2_hex.clone()).await?;
    } else {
        tracing::warn!(
            key_id,
            "the node did not take zip 320 step 2 yet; the queue retries once step 1 is mined"
        );
    }
    state.tex.wake();
    state.sync.wake();

    if wait_for_mined {
        let mut step1_done = false;
        loop {
            let s1 = chain.transaction_status(id).await;
            if let Ok(gyges_chain::TxStatus::Mined(h)) = s1
                && !step1_done
            {
                step1_done = true;
                emit_mined(tx, 1, step1_hex.clone(), u32::from(h)).await?;
            }
            let row = wallet_rpc(key, move |w| Ok(core_tex::get(w, id)?)).await?;
            let Some(row) = row else {
                return Err(Status::internal("the tex queue row disappeared"));
            };
            match row.state {
                TexState::Step2Mined => {
                    let h = match chain.transaction_status(row.step2_txid).await {
                        Ok(gyges_chain::TxStatus::Mined(h)) => u32::from(h),
                        _ => 0,
                    };
                    let txid = gyges_chain::display_hash(&row.step2_txid);
                    return emit_mined(tx, 2, txid, h).await;
                }
                TexState::Expired
                | TexState::Failed
                | TexState::Step2Failed
                | TexState::Aborted => {
                    let mut e = GygesError::new(
                        if row.state == TexState::Failed {
                            ErrorReason::NodeRejected
                        } else {
                            ErrorReason::Internal
                        },
                        format!(
                            "the ZIP 320 transfer is `{}`: {}",
                            row.state.as_str(),
                            row.last_error.clone().unwrap_or_default()
                        ),
                    )
                    .with_key(&key_id);
                    if row.state == TexState::Failed {
                        e.node_error = row.last_error.unwrap_or_default();
                    }
                    return Err(e.into_status());
                }
                _ => {}
            }
            state.tex.wake();
            idle_or_closed(tx).await?;
        }
    }
    Ok(())
}

/// Finishes a session as failed when the waiting task goes away (client
/// disconnect, error) before the key arrived.
struct SessionGuard {
    hub: Arc<DaemonState>,
    session_id: String,
}

impl SessionGuard {
    fn disarm(self) {
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

/// `ListSigningSessions` (the ZIP 320 rows are added by the service, from
/// `crate::tex`).
pub(crate) fn list_signing_sessions(
    state: &DaemonState,
    req: &ListSigningSessionsRequest,
) -> Result<ListSigningSessionsResponse, Status> {
    Ok(ListSigningSessionsResponse {
        sessions: state.sessions.list(&req.key_id, req.include_finished),
        tex_transfers: Vec::new(),
    })
}

/// `AbortSigningSession`: the waiting stream ends with `CANCELLED`.
pub(crate) fn abort_signing_session(
    state: &DaemonState,
    req: AbortSigningSessionRequest,
) -> Result<SigningSession, Status> {
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

/// `GetBalance` (API.md): per pool at `min_confirmations`.
pub(crate) async fn get_balance(
    state: Arc<DaemonState>,
    req: GetBalanceRequest,
) -> Result<GetBalanceResponse, Status> {
    let key = state.wallet_key(
        &req.key_id,
        "a signer-only profile has no wallet and no balance",
    )?;
    let min_confirmations = state.min_confirmations(req.min_confirmations);
    let b = wallet_rpc(&key, move |w| core_tx::balance(w, min_confirmations)).await?;
    Ok(GetBalanceResponse {
        pools: b
            .pools
            .iter()
            .map(|p| v1::PoolBalance {
                pool: proto_pool(p.pool) as i32,
                spendable: i64::try_from(p.spendable).unwrap_or(i64::MAX),
                pending: i64::try_from(p.pending).unwrap_or(i64::MAX),
                pending_spend: 0,
            })
            .collect(),
        total_spendable: i64::try_from(b.total_spendable).unwrap_or(i64::MAX),
        total_pending: i64::try_from(b.total_pending).unwrap_or(i64::MAX),
        min_confirmations: b.min_confirmations,
        as_of_height: b.as_of_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_parse_per_proto() {
        assert_eq!(
            parse_amount(Some(v1::Amount {
                value: Some(v1::amount::Value::Zatoshis(5))
            }))
            .unwrap(),
            AmountSpec::Zatoshis(Zatoshis::const_from_u64(5))
        );
        assert_eq!(
            parse_amount(Some(v1::Amount {
                value: Some(v1::amount::Value::Max(true))
            }))
            .unwrap(),
            AmountSpec::Max
        );
        for bad in [
            None,
            Some(v1::Amount { value: None }),
            Some(v1::Amount {
                value: Some(v1::amount::Value::Zatoshis(0)),
            }),
            Some(v1::Amount {
                value: Some(v1::amount::Value::Zatoshis(-1)),
            }),
            Some(v1::Amount {
                value: Some(v1::amount::Value::Max(false)),
            }),
        ] {
            let err = parse_amount(bad).unwrap_err();
            assert_eq!(
                GygesError::from_status(&err).unwrap().reason(),
                ErrorReason::InvalidArgument
            );
        }
    }

    #[test]
    fn tx_errors_map_to_the_documented_reasons() {
        assert_eq!(
            tx_error(
                TxError::InsufficientFunds {
                    available: 1,
                    required: 2
                },
                "k"
            )
            .reason(),
            ErrorReason::InsufficientFunds
        );
        assert_eq!(
            tx_error(TxError::NotSynced("x".into()), "k").reason(),
            ErrorReason::NotSynced
        );
        assert_eq!(
            tx_error(TxError::UnsupportedPool("x".into()), "k").reason(),
            ErrorReason::UnsupportedPool
        );
        let e = broadcast_error(ChainError::Rejected("tx-expired".into()), "k");
        assert_eq!(e.reason(), ErrorReason::NodeRejected);
        assert_eq!(e.node_error, "tx-expired");
        assert_eq!(
            broadcast_error(ChainError::Unreachable("down".into()), "k").reason(),
            ErrorReason::NodeUnreachable
        );
    }

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
