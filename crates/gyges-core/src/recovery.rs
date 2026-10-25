//! Transparent history below the node's window (SYNC.md §5.3, ROADMAP.md M2).
//!
//! Compact blocks from the fallback endpoint carry no transparent outputs,
//! so a key backfilled below `retained_from` learns its transparent funds
//! there from the endpoint's `GetAddressUtxos`, which it cannot fully check.
//! What it can check, it does before anything reaches the wallet:
//!
//! - the endpoint's raw transaction (`GetTransaction`) hashes to the txid
//!   it reported, and the reported output is in it with that script and
//!   value ([`check_utxo`]);
//! - the reported height has a block the node knows (`getblockhash`), and
//!   the endpoint's block at that height hashes to the node's;
//! - where the node still holds the block, the transaction is in it; below
//!   the window, a transaction with shielded parts must be listed in the
//!   endpoint's compact block. A transparent-only transaction below the
//!   window cannot be placed: compact blocks list only transactions with
//!   shielded parts and carry no Merkle proof, so it is accepted as
//!   best-effort ([`Placement::Unplaced`]).
//!
//! An omitted UTXO cannot be detected at all, which is why every restore
//! below the window warns that transparent history there is best-effort
//! (THREAT_MODEL.md §6 item 9). The daemon side (fetching, the node checks)
//! is `gygesd::backfill`.

use std::collections::HashSet;

use gyges_chain::AddressUtxo;
use gyges_chain::compact::TransparentOutput;
use serde::{Deserialize, Serialize};
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BranchId, NetworkType};

use crate::network::ConsensusParams;
use crate::registry::Wallet;
use crate::sync::SyncError;

/// How far a recovered output could be placed in the node's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// In a block the node itself served.
    Node,
    /// Listed in the endpoint's compact block, whose hash is the node's.
    EndpointBlock,
    /// In a block whose hash is the node's, but the transaction cannot be
    /// shown to be in it (transparent-only, below the window).
    Unplaced,
}

/// What a recovery pass did, kept in `keys/<id>/transparent_recovery.json`
/// so `daemon status` can repeat the warning.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The heights the endpoint was asked about.
    pub from: u32,
    pub to: u32,
    /// Transparent history below this height came from the endpoint and is
    /// best-effort (the node's `retained_from` at the time).
    pub best_effort_below: u32,
    pub credited: u32,
    /// Of `credited`, how many could not be placed in a block.
    pub unplaced: u32,
    /// Reported outputs refused by a check.
    pub discarded: u32,
}

/// The key's transparent receivers (external, change, ephemeral) across its
/// accounts, encoded for `GetAddressUtxos`.
pub fn receivers(
    wallet: &Wallet,
    network: NetworkType,
) -> Result<Vec<(TransparentAddress, String)>, SyncError> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for account in wallet
        .get_account_ids()
        .map_err(|e| SyncError::Wallet(e.to_string()))?
    {
        for addr in wallet
            .get_transparent_receivers(account, true, true)
            .map_err(|e| SyncError::Wallet(e.to_string()))?
            .into_keys()
        {
            if seen.insert(addr) {
                out.push((
                    addr,
                    gyges_chain::compact::encode_transparent_address(network, &addr),
                ));
            }
        }
    }
    Ok(out)
}

/// The output `utxo` names, checked against `raw`, the endpoint's bytes for
/// its transaction, reported at `raw_height`. Returns the output to credit
/// and whether the transaction has shielded parts (so that it must appear
/// in the endpoint's compact block). The error is the reason to discard it,
/// free of addresses and amounts (it is logged).
pub fn check_utxo(
    params: &ConsensusParams,
    utxo: &AddressUtxo,
    raw: &[u8],
    raw_height: u64,
) -> Result<(TransparentOutput, bool), String> {
    if raw_height != u64::from(u32::from(utxo.height)) {
        return Err(format!(
            "the transaction is reported at height {raw_height}, the output at {}",
            u32::from(utxo.height)
        ));
    }
    let branch = BranchId::for_height(params, utxo.height);
    let tx = Transaction::read(raw, branch)
        .map_err(|e| format!("the endpoint's transaction does not parse: {e}"))?;
    if *tx.txid().as_ref() != utxo.txid {
        return Err("the endpoint's transaction does not hash to the reported txid".into());
    }
    let out = tx
        .transparent_bundle()
        .and_then(|b| b.vout.get(utxo.index as usize))
        .ok_or("the transaction has no output at the reported index")?;
    let script = out.script_pubkey().0.0.clone();
    if out.value().into_u64() != utxo.value_zat || script != utxo.script_pubkey {
        return Err("the reported value or script differs from the transaction's output".into());
    }
    let shielded = tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
        || tx.ironwood_bundle().is_some();
    Ok((
        TransparentOutput {
            height: utxo.height,
            block_hash: [0; 32],
            txid: utxo.txid,
            index: utxo.index,
            value_zat: utxo.value_zat,
            address: gyges_chain::compact::address_of_script(&script),
            script_pubkey: script,
        },
        shielded,
    ))
}

/// Whether `block` (compact, transparent fields present when it came from
/// the node) holds `output`: the txid listed and, where the block carries
/// `vout`, the output itself.
pub fn block_holds(
    block: &zcash_client_backend::proto::compact_formats::CompactBlock,
    output: &TransparentOutput,
) -> bool {
    block.vtx.iter().any(|tx| {
        tx.txid == output.txid
            && (tx.vout.is_empty()
                || tx.vout.get(output.index as usize).is_some_and(|o| {
                    o.value == output.value_zat && o.script_pub_key == output.script_pubkey
                }))
    })
}
