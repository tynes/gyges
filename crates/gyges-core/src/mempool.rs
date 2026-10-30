//! Trial decryption of mempool transactions (docs/architecture.md Sync §7).
//!
//! The daemon lists the node's mempool each poll tick, fetches every
//! transaction it has not seen once, and hands it to [`scan_tx`] for each
//! key. A transaction that pays or spends one of the key's notes is stored
//! unmined, which `balance` shows under *pending* until a block includes it
//! (upstream's summary counts unmined received value as pending and the
//! notes it spends as spent). Expiry needs no handling here: upstream drops
//! an unmined transaction from the balance once the tip passes its expiry
//! height.

use zcash_client_backend::TransferType;
use zcash_client_backend::data_api::{WalletRead as _, WalletWrite as _};
use zcash_client_backend::decrypt_transaction;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::network::ConsensusParams;
use crate::registry::Wallet;
use crate::sync::{SyncError, wallet_err};

/// Parse a mempool transaction for the block after `tip`, where it would be
/// mined.
pub fn parse(
    params: &ConsensusParams,
    raw: &[u8],
    tip: BlockHeight,
) -> Result<Transaction, String> {
    Transaction::read(raw, BranchId::for_height(params, tip + 1))
        .map_err(|e| format!("mempool transaction does not parse: {e}"))
}

/// Trial-decrypt `tx` with the wallet's viewing keys and store what it
/// finds, unmined. Returns the number of notes it pays to the wallet
/// (received or change; outputs the wallet sent elsewhere are not counted).
/// A wallet without a chain tip yet is skipped (`Ok(0)`): upstream needs
/// one to store an unmined transaction.
///
/// This is upstream's `decrypt_and_store_transaction` with the count added,
/// so it must stay in step with it. gyges never opens one-time keys; if it
/// ever does, this must become the `_with_one_time_ivks` variant, which
/// upstream requires while one is open.
pub fn scan_tx(
    params: &ConsensusParams,
    wallet: &mut Wallet,
    tx: &Transaction,
) -> Result<usize, SyncError> {
    let Some(chain_tip) = wallet.chain_height().map_err(wallet_err)? else {
        return Ok(0);
    };
    let ufvks = wallet.get_unified_full_viewing_keys().map_err(wallet_err)?;
    let mined_height = wallet.get_tx_height(tx.txid()).map_err(wallet_err)?;
    let decrypted = decrypt_transaction(params, mined_height, Some(chain_tip), tx, &ufvks);
    let notes = received(decrypted.sapling_outputs())
        + received(decrypted.orchard_outputs())
        + received(decrypted.ironwood_outputs());
    wallet.store_decrypted_tx(decrypted).map_err(wallet_err)?;
    Ok(notes)
}

/// How many of `outputs` were received rather than sent.
fn received<N, A>(outputs: &[zcash_client_backend::DecryptedOutput<N, A>]) -> usize {
    outputs
        .iter()
        .filter(|o| o.transfer_type() != TransferType::Outgoing)
        .count()
}
