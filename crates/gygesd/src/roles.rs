//! The PCZT role RPCs behind `gyges pczt …` (ARCHITECTURE.md §3.5, API.md
//! §4.2, §7.1, CLI_SPEC.md §2.6): `CreatePczt`, `InspectPczt`, `ProvePczt`,
//! `SignPczt`, `CombinePczt` and `BroadcastPczt`.
//!
//! The six are the single-step send pipeline of [`crate::tx`] cut at the
//! role boundaries, with a file in between instead of a stream. What holds
//! them together across processes and machines is the ZIP 374 global
//! `proprietary` map: `CreatePczt` writes `gyges.key_id`, `gyges.network`
//! and `gyges.session_id`, and every later RPC reads the key from there
//! (`--key` is only an assertion, `KEY_MISMATCH` when it differs). The
//! session id names a row in the key's `ext_gyges_signing_sessions` table
//! holding the approved proposal, so that `BroadcastPczt` runs the Verifier
//! (Q-K7) against what the user saw at `create`, not against what the file
//! says: a file tampered with on the way is refused with `INVALID_ARGUMENT`.
//!
//! `InspectPczt`, `ProvePczt`, `SignPczt` and `CombinePczt` need no node
//! and are on the air-gapped allow-list (API.md §8); `SignPczt` accepts a
//! `signer-only` profile, which signs transparent inputs from the BIP 44
//! derivations in the file (`gyges_core::tx::sign`).

use std::sync::Arc;

use gyges_core::db::sessions::{self, Protocol, SessionRow, SessionState};
use gyges_core::pczt_io::{self, Inspection, Role, Tags};
use gyges_core::tx::{self as core_tx, Expected, TxError};
use gyges_proto::v1::{
    self, BroadcastPcztRequest, BroadcastPcztResponse, CombinePcztRequest, CombinePcztResponse,
    CreatePcztRequest, CreatePcztResponse, ErrorReason, GygesError, InspectPcztRequest,
    InspectPcztResponse, PcztRole, ProvePcztRequest, ProvePcztResponse, SignPcztEvent,
    SignPcztRequest, sign_pczt_event,
};
use pczt::Pczt;
use pczt::roles::combiner::Combiner;
use prost::Message as _;
use tokio::sync::mpsc;
use tonic::Status;
use zcash_protocol::consensus::BlockHeight;

use crate::broadcast::{self, broadcast_route, connected_chain};
use crate::conn::ConnInfo;
use crate::errors::tx_error;
use crate::keys::{AUDIT_TARGET, proto_pool};
use crate::service::{DaemonState, invalid, proto_network, unix_now};
use crate::sessions::set_session_state;
use crate::tx::{self, Purpose, blocking, obtain_key, proto_proposal, wallet_rpc};
use crate::with_wallet;

/// The server-streaming response type for `SignPczt`.
pub(crate) type SignStream = tonic::codegen::BoxStream<SignPcztEvent>;

/// How far past the proposal's target height a `pczt create` transaction
/// may still be mined. A file travels on removable media and waits for a
/// person (ARCHITECTURE.md §3.5), so the default `target + 40` of `tx send`
/// (fifty minutes on mainnet) would expire most of them; this is about a
/// day of 75-second blocks, the window `vault.signing_session_ttl` gives a
/// passphrase session.
pub const PCZT_EXPIRY_BLOCKS: u32 = 1152;

/// Parse the bytes, read the tags, and apply the two checks every PCZT RPC
/// makes: the file is for this daemon's network, and the caller's `--key`
/// (if any) is the key the file names.
fn parse_and_check(
    state: &DaemonState,
    bytes: &[u8],
    asserted_key: &str,
) -> Result<(Pczt, Tags), Status> {
    let pczt = pczt_io::parse(bytes).map_err(|e| tx_error(e, "").into_status())?;
    let tags = pczt_io::tags_of(&pczt).map_err(|e| tx_error(e, "").into_status())?;
    if tags.network != state.network {
        return Err(GygesError::new(
            ErrorReason::NetworkMismatch,
            format!(
                "the PCZT is for {} but this daemon serves {}",
                tags.network.name(),
                state.network.name()
            ),
        )
        .with_key(&tags.key_id)
        .into_status());
    }
    if !asserted_key.is_empty() && asserted_key != tags.key_id {
        return Err(GygesError::new(
            ErrorReason::KeyMismatch,
            format!(
                "the PCZT belongs to key '{}', not '{asserted_key}'",
                tags.key_id
            ),
        )
        .with_key(&tags.key_id)
        .into_status());
    }
    Ok((pczt, tags))
}

fn proto_role(r: Role) -> PcztRole {
    match r {
        Role::Creator => PcztRole::Creator,
        Role::Constructor => PcztRole::Constructor,
        Role::IoFinalizer => PcztRole::IoFinalizer,
        Role::Updater => PcztRole::Updater,
        Role::Prover => PcztRole::Prover,
        Role::Signer => PcztRole::Signer,
        Role::SpendFinalizer => PcztRole::SpendFinalizer,
    }
}

fn proto_inspection(tags: &Tags, insp: &Inspection) -> InspectPcztResponse {
    InspectPcztResponse {
        key_id: tags.key_id.clone(),
        network: proto_network(tags.network) as i32,
        session_id: tags.session_id.clone(),
        summary: Some(proto_proposal(&insp.summary)),
        completed_roles: insp.roles.iter().map(|r| proto_role(*r) as i32).collect(),
        pools: insp
            .pools
            .iter()
            .map(|p| v1::PcztPoolState {
                pool: proto_pool(p.pool) as i32,
                spends: p.spends,
                outputs: p.outputs,
                proofs_present: p.proofs_present,
                signatures_present: p.signatures_present,
                signatures_required: p.signatures_required,
            })
            .collect(),
    }
}

/// `CreatePczt`: propose, build the PCZT (Creator → Updater), tag it, and
/// store the approved proposal under the session id. One PCZT, because a
/// ZIP 320 recipient is refused here (API.md §9: upstream builds PCZTs from
/// single-step proposals only).
pub(crate) async fn create_pczt(
    state: Arc<DaemonState>,
    conn: Option<ConnInfo>,
    req: CreatePcztRequest,
) -> Result<CreatePcztResponse, Status> {
    let prepared = tx::prepare(
        &state,
        conn,
        &req.key_id,
        &[],
        req.min_confirmations,
        Purpose::CreatePczt,
    )?;
    let key_id = prepared.key.key_id().to_string();
    let err = |e: TxError| tx_error(e, &key_id).into_status();
    let params = state.registry.params();
    let to = core_tx::parse_recipient(&params, &req.to).map_err(err)?;
    let memo = core_tx::memo_for(&to, &req.memo).map_err(err)?;
    let amount = tx::parse_amount(req.amount)?;
    // Sapling notes stay out of a file: proving one needs the proof
    // generation key, which never leaves the `tx send` stream that derives
    // it (THREAT_MODEL.md §6 item 1).
    let profile_pools = &prepared.key.profile().spend_pools;
    let sapling_left_out = profile_pools.contains(&gyges_core::Pool::Sapling);
    let spend_pools: Vec<_> = profile_pools
        .iter()
        .copied()
        .filter(|p| *p != gyges_core::Pool::Sapling)
        .collect();
    let min_confirmations = prepared.min_confirmations;
    let network = state.network;
    let ttl = i64::try_from(state.config.vault.signing_session_ttl.as_secs()).unwrap_or(i64::MAX);
    let kid = key_id.clone();
    let (proto, bytes, session_id) = with_wallet(&prepared.key, move |wallet| {
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
        if core_tx::is_two_step(&proposal) {
            return Err(TxError::InvalidArgument(
                "a ZIP 320 (tex1) recipient takes two transactions and upstream builds a PCZT from a single-step proposal only; use `gyges tx send` for it"
                    .into(),
            ));
        }
        let mut summary = core_tx::summarize(&params, &proposal, min_confirmations);
        let target = BlockHeight::from(proposal.min_target_height());
        let expiry = target + PCZT_EXPIRY_BLOCKS;
        summary.expiry_height = u32::from(expiry);
        let expected = Expected::from_proposal(&params, &proposal, Some(expiry))?;
        let pczt = core_tx::build_pczt(wallet, &params, account, &proposal, Some(expiry))?;
        let session_id = pczt_io::new_session_id();
        let pczt = pczt_io::tag(
            pczt,
            &Tags {
                key_id: kid,
                network,
                session_id: session_id.clone(),
            },
        );
        let bytes = pczt_io::serialize(pczt)?;
        let proto = proto_proposal(&summary);
        let now = unix_now();
        sessions::insert(
            wallet,
            &SessionRow {
                session_id: session_id.clone(),
                protocol: Protocol::File,
                state: SessionState::AwaitingSignature,
                created_at: now,
                expires_at: now.saturating_add(ttl),
                proposal: proto.encode_to_vec(),
                expected: expected.to_json(),
                txid: None,
                last_error: None,
                keystone: None,
            },
        )?;
        Ok((proto, bytes, session_id))
    })
    .await
    .map_err(|e| match e {
        TxError::InsufficientFunds { .. } if sapling_left_out => {
            let mut g = tx_error(e, &key_id);
            g.detail.push_str(
                " (Sapling notes are not spent from a PCZT file; spend them with `gyges tx send`)",
            );
            g.into_status()
        }
        e => err(e),
    })?;
    tracing::info!(target: AUDIT_TARGET, key_id, event = "session_created");
    tracing::info!(key_id, "pczt created");
    Ok(CreatePcztResponse {
        pczts: vec![bytes],
        proposal: Some(proto),
        session_id,
    })
}

/// `InspectPczt`: the tags, the proposal the file implies, the roles that
/// have run and the per-pool proof and signature state. Needs nothing but
/// the bytes.
pub(crate) fn inspect_pczt(
    state: &DaemonState,
    req: InspectPcztRequest,
) -> Result<InspectPcztResponse, Status> {
    let (pczt, tags) = parse_and_check(state, &req.pczt, &req.key_id)?;
    let insp = pczt_io::inspect(&state.registry.params(), &pczt)
        .map_err(|e| tx_error(e, &tags.key_id).into_status())?;
    Ok(proto_inspection(&tags, &insp))
}

/// `ProvePczt`: the Prover role (Orchard, Ironwood and Sapling outputs;
/// no key needed, Q-K3).
pub(crate) async fn prove_pczt(
    state: Arc<DaemonState>,
    req: ProvePcztRequest,
) -> Result<ProvePcztResponse, Status> {
    let (pczt, tags) = parse_and_check(&state, &req.pczt, &req.key_id)?;
    let key_id = tags.key_id.clone();
    let provers = state.provers.clone();
    let t0 = std::time::Instant::now();
    let bytes = blocking(move || {
        let pczt = core_tx::prove(pczt, &provers)?;
        pczt_io::serialize(pczt)
    })
    .await
    .map_err(|e| tx_error(e, &key_id).into_status())?;
    tracing::info!(key_id, ms = t0.elapsed().as_millis(), "pczt proven");
    Ok(ProvePcztResponse { pczt: bytes })
}

/// `SignPczt` (API.md §4.2): the Signer role with the key from the
/// request's token, a daemon-scoped unlock, or a passphrase session the
/// client satisfies with `UnlockKey { session_id }`, exactly as `tx send`.
pub(crate) fn sign_pczt(
    state: Arc<DaemonState>,
    conn: Option<ConnInfo>,
    req: SignPcztRequest,
) -> Result<SignStream, Status> {
    let (pczt, tags) = parse_and_check(&state, &req.pczt, &req.key_id)?;
    let prepared = tx::prepare(
        &state,
        conn,
        &tags.key_id,
        &req.session_token,
        0,
        Purpose::SignPczt,
    )?;
    let key_id = prepared.key.key_id().to_string();
    // Refused before any passphrase is asked for (THREAT_MODEL.md §6
    // item 1).
    let pczt = core_tx::refuse_unkeyed_sapling_spends(pczt)
        .map_err(|e| tx_error(e, &key_id).into_status())?;
    let insp = pczt_io::inspect(&state.registry.params(), &pczt)
        .map_err(|e| tx_error(e, &key_id).into_status())?;
    let summary = proto_proposal(&insp.summary);
    let signer = core_tx::SignerId::of(prepared.key.profile(), &state.registry.params())
        .map_err(|e| tx_error(e, &key_id).into_status())?;
    let (tx, rx) = mpsc::channel::<Result<SignPcztEvent, Status>>(4);
    tokio::spawn(async move {
        let err = |e: TxError| tx_error(e, &key_id).into_status();
        let outcome: Result<(), Status> = async {
            let usk = obtain_key(&state, &prepared, &summary, &tx, 1, |r| SignPcztEvent {
                event: Some(sign_pczt_event::Event::SignatureRequired(r)),
            })
            .await?;
            let key = prepared.key.clone();
            let bytes = blocking(move || {
                let wallet = key.wallet();
                let signed = core_tx::sign(wallet.as_deref(), pczt, &usk, &signer)?;
                pczt_io::serialize(signed)
            })
            .await
            .map_err(err)?;
            tracing::info!(key_id, "pczt signed");
            let event = Some(sign_pczt_event::Event::Signed(bytes));
            tx::send(&tx, SignPcztEvent { event }).await
        }
        .await;
        if let Err(status) = outcome {
            tracing::debug!(key_id, error = %status.message(), "sign stream ended with an error");
            let _ = tx.send(Err(status)).await;
        }
    });
    Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
}

/// `CombinePczt`: the Combiner role over two or more files for the same
/// key (API.md §7.1 refuses mixed key ids before upstream sees them).
pub(crate) fn combine_pczt(
    state: &DaemonState,
    req: CombinePcztRequest,
) -> Result<CombinePcztResponse, Status> {
    if req.pczts.len() < 2 {
        return Err(invalid("combine needs at least two PCZTs"));
    }
    let mut parsed = Vec::with_capacity(req.pczts.len());
    let mut first: Option<Tags> = None;
    for bytes in &req.pczts {
        let (pczt, tags) = parse_and_check(state, bytes, &req.key_id)?;
        if let Some(f) = &first
            && f.key_id != tags.key_id
        {
            return Err(GygesError::new(
                ErrorReason::KeyMismatch,
                format!(
                    "the PCZTs belong to different keys ('{}' and '{}')",
                    f.key_id, tags.key_id
                ),
            )
            .with_key(&f.key_id)
            .into_status());
        }
        first.get_or_insert(tags);
        parsed.push(pczt);
    }
    let key_id = first.map(|t| t.key_id).unwrap_or_default();
    let combined = Combiner::new(parsed).combine().map_err(|e| {
        GygesError::new(
            ErrorReason::InvalidArgument,
            format!("the PCZTs do not describe the same transaction ({e:?})"),
        )
        .with_key(&key_id)
        .into_status()
    })?;
    let bytes = pczt_io::serialize(combined).map_err(|e| tx_error(e, &key_id).into_status())?;
    Ok(CombinePcztResponse { pczt: bytes })
}

/// `BroadcastPczt`: Verifier against the stored proposal, Spend Finalizer,
/// Transaction Extractor, the wallet's own record, `sendrawtransaction`.
pub(crate) async fn broadcast_pczt(
    state: Arc<DaemonState>,
    req: BroadcastPcztRequest,
) -> Result<BroadcastPcztResponse, Status> {
    let (pczt, tags) = parse_and_check(&state, &req.pczt, &req.key_id)?;
    let key = state.wallet_key(
        &tags.key_id,
        "a signer-only profile has no wallet; broadcast from the daemon that created the PCZT",
    )?;
    let key_id = key.key_id().to_string();
    let typed = |reason, detail: String| GygesError::new(reason, detail).with_key(&key_id);
    let err = |e: TxError| tx_error(e, &key_id).into_status();
    let chain = connected_chain(&state, &key_id)?;
    let route = broadcast_route(&state, req.via_tor, &key_id)?;

    // What the file is missing is named before the Verifier judges it.
    let insp = pczt_io::inspect(&state.registry.params(), &pczt).map_err(err)?;
    if !insp.is_proven() {
        return Err(typed(
            ErrorReason::InvalidArgument,
            "the PCZT is not proven; run `gyges pczt prove` first".into(),
        )
        .into_status());
    }
    if !insp.is_signed() {
        return Err(typed(
            ErrorReason::InvalidArgument,
            "the PCZT is not fully signed; run `gyges pczt sign` first".into(),
        )
        .into_status());
    }

    // The approved proposal, from the key's own table.
    let session_id = tags.session_id.clone();
    let sid = session_id.clone();
    let row = wallet_rpc(&key, move |w| Ok(sessions::get(w, &sid)?)).await?;
    let Some(row) = row else {
        return Err(typed(
            ErrorReason::SessionNotFound,
            "this daemon holds no proposal for the PCZT's session; it was created by another daemon, or the wallet was restored since"
                .into(),
        )
        .with_session(&session_id)
        .into_status());
    };
    if row.state == SessionState::Broadcast {
        return Err(typed(
            ErrorReason::InvalidArgument,
            format!(
                "this PCZT was already broadcast as {}",
                row.txid
                    .map(|t| gyges_chain::display_hash(&t))
                    .unwrap_or_default()
            ),
        )
        .with_session(&session_id)
        .into_status());
    }
    let expected = Expected::from_json(&row.expected).map_err(err)?;

    // Verifier (Q-K7), then extract and record.
    let owner_params = state.registry.params();
    let owner = wallet_rpc(&key, move |w| core_tx::Owner::of_wallet(&owner_params, w)).await?;
    let pczt = core_tx::verify(pczt, &expected, &owner).map_err(err)?;
    let provers = state.provers.clone();
    let (txid, raw) =
        wallet_rpc(&key, move |w| core_tx::extract_and_store(w, pczt, &provers)).await?;
    broadcast::broadcast_signed(&key, &chain, &route, &session_id, raw).await?;
    set_session_state(
        &key,
        &session_id,
        SessionState::Broadcast,
        Some(*txid.as_ref()),
        None,
    )
    .await
    .map_err(err)?;
    tracing::info!(target: AUDIT_TARGET, key_id, event = "broadcast", via = route.name());
    tracing::info!(key_id, via = route.name(), "transaction broadcast");
    state.sync.wake();
    Ok(BroadcastPcztResponse {
        txid: txid.to_string(),
    })
}
