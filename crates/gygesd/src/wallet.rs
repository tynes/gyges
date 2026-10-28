//! The read side of a key's wallet (API.md §7: `address`, `notes`,
//! `tx list`, `tx status`): `GetCurrentAddress`, `NewAddress`,
//! `InspectAddress`, `ListNotes`, `ListTransactions` and
//! `GetTransactionStatus`. The wallet work is in `gyges_core::{addresses,
//! history}`; this module resolves keys, applies the profile's pool rules,
//! joins the ZIP 320 queue rows and asks the node.

use std::sync::Arc;

use gyges_chain::{ChainError, TxStatus, display_hash, parse_display_hash};
use gyges_core::addresses::{self, AddressKind, Inspected};
use gyges_core::history::{self, NoteRow, TxRow};
use gyges_core::tex::{self as core_tex, TexRow};
use gyges_core::{KeyEntry, Network, Pool, SigningMode};
use gyges_proto::v1::{
    self, AddressInfo, ErrorReason, GetCurrentAddressRequest, GetTransactionStatusRequest,
    GetTransactionStatusResponse, GygesError, InspectAddressRequest, InspectAddressResponse,
    ListNotesRequest, ListNotesResponse, ListTransactionsRequest, ListTransactionsResponse,
    NewAddressRequest, SpentFilter, StatusSource, TransactionOutput, TransactionStatus,
    TransactionSummary,
};
use tonic::Status;
use zcash_protocol::consensus::{NetworkType, Parameters as _};

use crate::keys::proto_pool;
use crate::service::{DaemonState, invalid, proto_network};
use crate::tex;
use crate::tx::wallet_rpc;

/// `ListTransactions.limit = 0` (API.md).
pub const DEFAULT_TX_LIMIT: usize = 50;
/// The most one page returns.
pub const MAX_TX_LIMIT: usize = 1000;

/// Resolve `key_id` to a profile with a wallet.
fn wallet_key(state: &DaemonState, key_id: &str) -> Result<Arc<KeyEntry>, Status> {
    state.wallet_key(
        key_id,
        "a signer-only profile has no wallet: no addresses, notes or history",
    )
}

fn core_pool(p: i32) -> Result<Pool, Status> {
    match v1::Pool::try_from(p) {
        Ok(v1::Pool::Transparent) => Ok(Pool::Transparent),
        Ok(v1::Pool::Sapling) => Ok(Pool::Sapling),
        Ok(v1::Pool::Orchard) => Ok(Pool::Orchard),
        Ok(v1::Pool::Ironwood) => Ok(Pool::Ironwood),
        _ => Err(invalid("unknown pool")),
    }
}

fn network_of(net: NetworkType) -> Network {
    match net {
        NetworkType::Main => Network::Mainnet,
        NetworkType::Test => Network::Testnet,
        NetworkType::Regtest => Network::Regtest,
    }
}

fn proto_receivers(rs: &[addresses::Receiver]) -> Vec<v1::Receiver> {
    rs.iter()
        .map(|r| v1::Receiver {
            pool: proto_pool(r.pool) as i32,
            encoded: r.encoded.clone(),
        })
        .collect()
}

fn proto_address(a: addresses::AddressInfo) -> AddressInfo {
    AddressInfo {
        receivers: proto_receivers(&a.receivers),
        address: a.address,
        diversifier_index: a.diversifier_index,
        label: a.label.unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// `GetCurrentAddress`: the address most recently handed out, or the
/// default shielded address on a fresh key (stored, so it stays current).
pub async fn get_current_address(
    state: Arc<DaemonState>,
    req: GetCurrentAddressRequest,
) -> Result<AddressInfo, Status> {
    let key = wallet_key(&state, &req.key_id)?;
    wallet_rpc(&key, addresses::current)
        .await
        .map(proto_address)
}

/// The receivers `address new` uses without `--receivers` (CLI_SPEC.md
/// §2.4): shielded only, except that a Keystone account has no Sapling key
/// for the wallet to use and pairs Orchard with transparent.
pub fn default_receivers(mode: SigningMode) -> Vec<Pool> {
    match mode {
        SigningMode::KeystoneQr => vec![Pool::Orchard, Pool::Transparent],
        _ => addresses::DEFAULT_RECEIVERS.to_vec(),
    }
}

/// `NewAddress`: a fresh diversified address with exactly the requested
/// receivers (Ironwood names the Orchard receiver), each of which the
/// profile must be able to receive to.
pub async fn new_address(
    state: Arc<DaemonState>,
    req: NewAddressRequest,
) -> Result<AddressInfo, Status> {
    let key = wallet_key(&state, &req.key_id)?;
    let profile = key.profile();
    let mut pools = Vec::new();
    for p in &req.receivers {
        let pool = core_pool(*p)?;
        if !pools.contains(&pool) {
            pools.push(pool);
        }
    }
    if pools.is_empty() {
        pools = default_receivers(profile.signing_mode);
    }
    for p in &pools {
        if !profile.receive_pools.contains(p) {
            return Err(GygesError::new(
                ErrorReason::UnsupportedPool,
                format!(
                    "this profile does not receive to the {} pool",
                    format!("{p:?}").to_lowercase()
                ),
            )
            .with_key(key.key_id())
            .into_status());
        }
    }
    let label = (!req.label.is_empty()).then(|| req.label.clone());
    let info = wallet_rpc(&key, move |w| {
        addresses::new_address(w, &pools, label.as_deref())
    })
    .await?;
    Ok(proto_address(info))
}

fn proto_kind(k: AddressKind) -> v1::AddressKind {
    match k {
        AddressKind::Unified => v1::AddressKind::Unified,
        AddressKind::Sapling => v1::AddressKind::Sapling,
        AddressKind::TransparentP2pkh => v1::AddressKind::TransparentP2pkh,
        AddressKind::TransparentP2sh => v1::AddressKind::TransparentP2sh,
        AddressKind::Tex => v1::AddressKind::Tex,
    }
}

/// `InspectAddress`: a pure parse, no key. A malformed address, or one for
/// another network than the daemon's, is `valid = false` with `error` set
/// (the RPC itself succeeds); `network` is reported whenever the encoding
/// names one.
pub fn inspect_address(state: &DaemonState, req: InspectAddressRequest) -> InspectAddressResponse {
    let daemon_net = state.network.consensus_params().network_type();
    match addresses::inspect(&req.address) {
        Err(error) => InspectAddressResponse {
            valid: false,
            error,
            ..Default::default()
        },
        Ok(i) => {
            let on_network = i.on_network(daemon_net);
            // A testnet-encoded transparent address on a regtest daemon is a
            // regtest address (they share prefixes).
            let shown = if on_network { daemon_net } else { i.network };
            let Inspected {
                kind, receivers, ..
            } = &i;
            InspectAddressResponse {
                valid: on_network,
                network: proto_network(network_of(shown)) as i32,
                kind: proto_kind(*kind) as i32,
                receivers: proto_receivers(receivers),
                transparent_source_only: i.transparent_source_only(),
                error: if on_network {
                    String::new()
                } else {
                    format!(
                        "the address is for {}; this daemon is on {}",
                        network_of(i.network).name(),
                        state.network.name()
                    )
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

fn proto_note(n: &NoteRow) -> v1::Note {
    v1::Note {
        pool: proto_pool(n.pool) as i32,
        txid: display_hash(&n.txid),
        output_index: n.output_index,
        value: i64::try_from(n.value).unwrap_or(i64::MAX),
        height: n.height.unwrap_or(0),
        memo_preview: n.memo_preview.clone(),
        spent: n.spent(),
        spent_txid: n.spent_txid.map(|t| display_hash(&t)).unwrap_or_default(),
        witness_ready: n.witness_ready,
        ephemeral: n.ephemeral,
    }
}

/// `ListNotes`: received notes and UTXOs, by pool (UNSPECIFIED = all) and
/// spent state (UNSPECIFIED = unspent), oldest first.
pub async fn list_notes(
    state: Arc<DaemonState>,
    req: ListNotesRequest,
) -> Result<ListNotesResponse, Status> {
    let key = wallet_key(&state, &req.key_id)?;
    let pool = match v1::Pool::try_from(req.pool) {
        Ok(v1::Pool::Unspecified) => None,
        _ => Some(core_pool(req.pool)?),
    };
    let spent = match SpentFilter::try_from(req.spent) {
        Ok(SpentFilter::Unspecified | SpentFilter::Unspent) => Some(false),
        Ok(SpentFilter::Spent) => Some(true),
        Ok(SpentFilter::All) => None,
        Err(_) => return Err(invalid("unknown spent filter")),
    };
    let notes = wallet_rpc(&key, history::notes).await?;
    Ok(ListNotesResponse {
        notes: notes
            .iter()
            .filter(|n| pool.is_none_or(|p| n.pool == p))
            .filter(|n| spent.is_none_or(|s| n.spent() == s))
            .map(proto_note)
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// The ZIP 320 row a transaction belongs to, as either step.
fn tex_row_of<'a>(rows: &'a [TexRow], txid: &[u8; 32]) -> Option<&'a TexRow> {
    rows.iter()
        .find(|r| &r.step1_txid == txid || &r.step2_txid == txid)
}

/// The wallet's view of a transaction's state. A ZIP 320 transfer is
/// `TEX_PENDING` until its row finishes, a mined step included: the
/// transfer is one payment.
pub fn status_of(row: &TxRow, tex: Option<&TexRow>) -> TransactionStatus {
    use gyges_core::TexState as T;
    match tex.map(|t| t.state) {
        Some(T::Failed | T::Aborted) if row.mined_height.is_none() => TransactionStatus::Failed,
        Some(T::Expired) if row.mined_height.is_none() => TransactionStatus::Expired,
        Some(s) if !s.is_terminal() => TransactionStatus::TexPending,
        _ if row.mined_height.is_some() => TransactionStatus::Mined,
        _ if row.expired_unmined => TransactionStatus::Expired,
        _ => TransactionStatus::Pending,
    }
}

fn proto_summary(key_id: &str, row: &TxRow, tex_rows: &[TexRow]) -> TransactionSummary {
    let tex = tex_row_of(tex_rows, &row.txid);
    TransactionSummary {
        txid: display_hash(&row.txid),
        status: status_of(row, tex) as i32,
        height: row.mined_height.unwrap_or(0),
        timestamp: row.timestamp,
        net_value: row.net_value,
        fee: row.fee.map_or(0, |f| i64::try_from(f).unwrap_or(i64::MAX)),
        expiry_height: row.expiry_height.unwrap_or(0),
        outputs: row
            .outputs
            .iter()
            .map(|o| TransactionOutput {
                pool: proto_pool(o.pool) as i32,
                address: o.address.clone().unwrap_or_default(),
                value: i64::try_from(o.value).unwrap_or(i64::MAX),
                is_change: o.is_change,
                is_ephemeral: o.is_ephemeral
                    || tex.is_some_and(|t| o.address.as_deref() == Some(&t.ephemeral_addr)),
                memo: o.memo.clone(),
            })
            .collect(),
        tex: tex.map(|t| tex::to_proto(key_id, t)),
        // Sessions hold no transaction until they are signed, so nothing
        // in the wallet is ever awaiting a signature.
        session_id: String::new(),
    }
}

fn parse_txid(s: &str, field: &str) -> Result<[u8; 32], Status> {
    parse_display_hash(s).map_err(|_| invalid(format!("{field} must be a 64-hex txid")))
}

/// `ListTransactions`: newest first, `limit` (0 = 50) per page, paged by
/// `before_txid`; each ZIP 320 step carries its queue row.
pub async fn list_transactions(
    state: Arc<DaemonState>,
    req: ListTransactionsRequest,
) -> Result<ListTransactionsResponse, Status> {
    let key = wallet_key(&state, &req.key_id)?;
    let limit = match req.limit {
        0 => DEFAULT_TX_LIMIT,
        n => usize::try_from(n).unwrap_or(MAX_TX_LIMIT).min(MAX_TX_LIMIT),
    };
    let before = if req.before_txid.is_empty() {
        None
    } else {
        Some(parse_txid(&req.before_txid, "before_txid")?)
    };
    let (rows, tex_rows) = wallet_rpc(&key, move |w| {
        let rows = history::transactions(w, limit, before)?;
        let tex_rows = core_tex::list(w, true)?;
        Ok((rows, tex_rows))
    })
    .await?;
    Ok(ListTransactionsResponse {
        transactions: rows
            .iter()
            .map(|r| proto_summary(key.key_id(), r, &tex_rows))
            .collect(),
    })
}

/// `GetTransactionStatus` (CLI_SPEC.md §2.5): asked of the node, so that a
/// fully transparent transaction the wallet cannot see mined is reported
/// too. The wallet and the ZIP 320 queue settle what the node no longer
/// holds: expired, failed, or (when the node has dropped a mined
/// transaction from its index) the height the wallet scanned it at, with
/// `source` left unspecified.
pub async fn get_transaction_status(
    state: Arc<DaemonState>,
    req: GetTransactionStatusRequest,
) -> Result<GetTransactionStatusResponse, Status> {
    if req.via_pir {
        return Err(invalid(
            "status over zakura-pir-status is not implemented yet (ROADMAP.md M6)",
        ));
    }
    let txid = parse_txid(&req.txid, "txid")?;
    let key = wallet_key(&state, &req.key_id)?;
    let chain = state.chain.clone().ok_or_else(|| {
        GygesError::new(ErrorReason::Airgapped, "air-gapped: no node interface").into_status()
    })?;
    let key_id = key.key_id().to_string();
    let (row, tex_row) = wallet_rpc(&key, move |w| {
        let row = history::transaction(w, txid)?;
        let tex_rows = core_tex::list(w, true)?;
        Ok((row, tex_row_of(&tex_rows, &txid).cloned()))
    })
    .await?;

    let node = chain.transaction_status(txid).await.map_err(|e| {
        tracing::debug!(key_id, error = %e, "transaction status from the node failed");
        let detail = match e {
            ChainError::Unreachable(_) => "the node is unreachable",
            _ => "the node could not report the transaction's status",
        };
        GygesError::new(ErrorReason::NodeUnreachable, detail)
            .with_key(&key_id)
            .into_status()
    })?;
    // A fresh tip: the scheduler's last poll can be older than the block
    // the node just reported the transaction in.
    let tip = match chain.node_bounds().await {
        Ok(b) => u32::from(b.tip_height),
        Err(_) => chain.status().bounds.map_or(0, |b| u32::from(b.tip_height)),
    };
    let confirmations = |h: u32| tip.max(h) - h + 1;
    let pending = if tex_row.as_ref().is_some_and(|t| !t.state.is_terminal()) {
        TransactionStatus::TexPending
    } else {
        TransactionStatus::Pending
    };
    let resp = |status: TransactionStatus, height: u32, source: StatusSource| {
        GetTransactionStatusResponse {
            status: status as i32,
            height,
            confirmations: if height == 0 {
                0
            } else {
                confirmations(height)
            },
            source: source as i32,
        }
    };
    Ok(match (node, row) {
        (TxStatus::Mined(h), _) => resp(TransactionStatus::Mined, u32::from(h), StatusSource::Node),
        (TxStatus::InMempool, _) => resp(pending, 0, StatusSource::Node),
        (TxStatus::Unknown, Some(row)) => match row.mined_height {
            Some(h) => resp(TransactionStatus::Mined, h, StatusSource::Unspecified),
            None => resp(status_of(&row, tex_row.as_ref()), 0, StatusSource::Node),
        },
        (TxStatus::Unknown, None) => {
            if let Some(t) = &tex_row {
                let status = match t.state {
                    gyges_core::TexState::Expired => TransactionStatus::Expired,
                    s if s.is_terminal() => TransactionStatus::Failed,
                    _ => TransactionStatus::TexPending,
                };
                resp(status, 0, StatusSource::Node)
            } else {
                return Err(GygesError::new(
                    ErrorReason::InvalidArgument,
                    "neither the node nor this key knows that transaction",
                )
                .with_key(key_id)
                .into_status());
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_core::TexState;

    fn row(mined: Option<u32>, expired: bool) -> TxRow {
        TxRow {
            txid: [1; 32],
            mined_height: mined,
            expiry_height: None,
            expired_unmined: expired,
            timestamp: 0,
            net_value: 0,
            fee: None,
            outputs: Vec::new(),
            tx_index: None,
        }
    }

    fn tex(state: TexState) -> TexRow {
        TexRow {
            step1_txid: [1; 32],
            step2_txid: [2; 32],
            proposal: Vec::new(),
            step1_raw: Vec::new(),
            step2_raw: Vec::new(),
            ephemeral_addr: String::new(),
            recipient: String::new(),
            amount: 0,
            expiry_height: 0,
            state,
            created_at: 0,
            last_attempt_at: None,
            attempts: 0,
            last_error: None,
        }
    }

    #[test]
    fn statuses_follow_the_wallet_and_the_queue() {
        use TransactionStatus as S;
        assert_eq!(status_of(&row(Some(5), false), None), S::Mined);
        assert_eq!(status_of(&row(None, false), None), S::Pending);
        assert_eq!(status_of(&row(None, true), None), S::Expired);
        let t = tex(TexState::Step1Mined);
        assert_eq!(status_of(&row(Some(5), false), Some(&t)), S::TexPending);
        let t = tex(TexState::Step2Mined);
        assert_eq!(status_of(&row(Some(5), false), Some(&t)), S::Mined);
        let t = tex(TexState::Failed);
        assert_eq!(status_of(&row(None, false), Some(&t)), S::Failed);
        let t = tex(TexState::Expired);
        assert_eq!(status_of(&row(None, true), Some(&t)), S::Expired);
        let t = tex(TexState::Step2Failed);
        assert_eq!(status_of(&row(None, false), Some(&t)), S::TexPending);
    }

    #[test]
    fn keystone_profiles_default_to_orchard_and_transparent() {
        assert_eq!(
            default_receivers(SigningMode::LocalSeed),
            vec![Pool::Orchard, Pool::Sapling]
        );
        assert_eq!(
            default_receivers(SigningMode::KeystoneQr),
            vec![Pool::Orchard, Pool::Transparent]
        );
    }
}
