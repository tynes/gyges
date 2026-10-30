//! The spending RPCs `SendTransaction`, `ShieldFunds` and `GetBalance`
//! (docs/interface.md API §4.1).
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
//! without ever being written (docs/security.md §6 item 1). The spending
//! key is obtained from, in order, the
//! connection-scoped token the request carries, a daemon-scoped unlock, or
//! a **signing session** (`crate::sessions`): the stream pauses on
//! `SignatureRequired` and the client answers with
//! `UnlockKey { session_id, passphrase }`, which verifies the passphrase
//! (per-key back-off included), derives the spending key and hands it to
//! the waiting task through a channel. The key is used for the signing
//! step and dropped.

use std::sync::Arc;
use std::time::Duration;

use gyges_chain::ChainError;
use gyges_core::tx::{self as core_tx, AmountSpec, Expected, ProposalSummary, TxError};
use gyges_core::vault::manager::{Auth, Token};
use gyges_core::{KeyEntry, SigningMode};
use gyges_proto::v1::{
    self, ErrorReason, GetBalanceRequest, GetBalanceResponse, GygesError, SendEvent,
    SendTransactionRequest, SessionStatus, ShieldFundsRequest, SignatureKind, SignatureRequired,
    send_event,
};
use pczt::Pczt;
use prost::Message as _;
use tokio::sync::mpsc;
use tonic::Status;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::value::Zatoshis;

use crate::broadcast::{self, Route, broadcast_route, connected_chain};
use crate::conn::ConnInfo;
use crate::errors::{ForKey, broadcast_error, tx_error, vault_error};
use crate::keys::{AUDIT_TARGET, proto_pool};
use crate::service::{DaemonState, invalid, unix_now};
use crate::sessions::SessionGuard;
use crate::tex::{self, DriveError, Offered};
use crate::{blocking, wallet_rpc};

/// The server-streaming response type for `SendTransaction` / `ShieldFunds`.
pub(crate) type SendStream = tonic::codegen::BoxStream<SendEvent>;

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
    /// is there (docs/architecture.md Components §3.3).
    Tex(Box<core_tx::SendProposal>),
}

/// What the proposing step produces: the summary for `Proposed`, and, unless
/// dry-run, what the rest of the pipeline needs.
type Proposed = (ProposalSummary, Option<Built>);

/// `SendTransaction` (docs/interface.md API §4.1).
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
    let to = core_tx::parse_recipient(&params, &req.to).for_key(&key_id)?;
    let memo = core_tx::memo_for(&to, &req.memo).for_key(&key_id)?;
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
        // docs/security.md §6 item 7: how the device shows ZIP 320's
        // transparent step 2 needs verification on hardware, and upstream
        // builds a PCZT from a single-step proposal only.
        return Err(GygesError::new(
            ErrorReason::HardwareSigner,
            "a tex1 recipient cannot be paid from a Keystone yet: its two-step transfer needs \
             verification on the device (docs/security.md §6 item 7); nothing was sent",
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
        let expiry = keystone.then(|| crate::roles::long_expiry(proposal.min_target_height()));
        let summary = core_tx::summarize(&params, &proposal, min_confirmations, expiry);
        if dry_run {
            return Ok((summary, None));
        }
        if core_tx::is_two_step(&proposal) {
            return Ok((summary, Some(Built::Tex(Box::new(proposal)))));
        }
        let (expected, pczt) =
            core_tx::build_single_step(wallet, &params, account, &proposal, expiry)?;
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

/// `ShieldFunds` (docs/interface.md API §4.1): the same stream for a transparent → Orchard
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
        let expiry = keystone.then(|| crate::roles::long_expiry(proposal.min_target_height()));
        let summary = core_tx::summarize(&params, &proposal, min_confirmations, expiry);
        if dry_run {
            return Ok((summary, None));
        }
        let (expected, pczt) =
            core_tx::build_single_step(wallet, &params, account, &proposal, expiry)?;
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

/// The pipeline proper (docs/interface.md API §4.1 event order for `n = 1`).
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
    // (docs/security.md §6 item 1); `SignatureRequired` then precedes
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
        Ok::<_, TxError>((core_tx::prove(pczt, &provers)?, early_key))
    })
    .await
    .for_key(&key_id)?;
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
        let signer =
            core_tx::SignerId::of(key.profile(), &state.registry.params()).for_key(&key_id)?;
        let pczt = wallet_rpc(key, move |w| core_tx::sign(Some(&*w), pczt, &usk, &signer)).await?;
        // `usk` was moved into the signing task and dropped there.

        // 6. Verify against the approved proposal (Q-K7).
        let pczt = broadcast::verified(state, key, pczt, expected)
            .await?
            .for_key(&key_id)?;

        // 7. Extract, record in the wallet, and broadcast.
        let provers = state.provers.clone();
        let (txid, raw) =
            wallet_rpc(key, move |w| core_tx::extract_and_store(w, pczt, &provers)).await?;
        emit(tx, send_event::Event::Signed(v1::StepSigned { step: 1 })).await?;
        broadcast::broadcast(state, key, prepared.chain()?, route, raw, txid, None).await?;
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
            let usk = usk.for_key(&key_id)?;
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
/// (docs/interface.md API §4.1), and ends the stream with `NOT_SYNCED` otherwise (without
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
        let guard = SessionGuard::new(state, &session_id);
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

/// The ZIP 320 branch of the pipeline (docs/architecture.md Components §3.3, docs/interface.md API §4.1
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
    // a row the queue finishes (docs/testing.md §3 row 12).
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
        DriveError::Wallet(e) => tx_error(e, &key_id).into_status(),
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

/// `GetBalance` (docs/interface.md API): per pool at `min_confirmations`.
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
}
