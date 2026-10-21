//! Synthetic `CompactBlock`s from raw blocks (SYNC.md §2.1).
//!
//! Zakura has no CompactBlock API, so Case A parses `getblock(h, 0)` with
//! `zcash_primitives` and keeps, per transaction: the txid, Sapling spends'
//! nullifiers, Sapling outputs' `(cmu, ephemeral_key, enc_ciphertext[..52])`,
//! Orchard and Ironwood actions' `(nullifier, cmx, ephemeral_key,
//! enc_ciphertext[..52])`, and, because the raw block is at hand, every
//! transparent input and output. The result is the lightwalletd protobuf
//! (`zcash_client_backend::proto::compact_formats`), so `scan_cached_blocks`
//! sees no difference from a lightwalletd-served block. The scanner ignores
//! `vin`/`vout`; the sync scheduler reads them from the cache to credit
//! transparent receivers (DATA_MODEL.md §5.4).

use std::io::{self, Cursor};

use transparent::address::TransparentAddress;
use zcash_address::ZcashAddress;
use zcash_client_backend::proto::compact_formats::{
    ChainMetadata, CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactSaplingSpend,
    CompactTx, CompactTxIn, TxOut,
};
use zcash_primitives::block::Block;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, NetworkType, Parameters};

/// Length of the compact note ciphertext prefix the scanner trial-decrypts.
pub const COMPACT_CIPHERTEXT_LEN: usize = 52;

/// Note commitment tree sizes as of the end of a block
/// (`getblock(h, 1).trees`), carried as `ChainMetadata`. The scanner needs
/// them to place newly found notes in the tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TreeSizes {
    pub sapling: u32,
    pub orchard: u32,
    pub ironwood: u32,
}

/// Why a raw block could not be turned into a compact block.
#[derive(Debug, thiserror::Error)]
pub enum CompactError {
    #[error("block at height {height} does not parse: {source}")]
    Parse {
        height: BlockHeight,
        #[source]
        source: io::Error,
    },
    /// The coinbase claims a different height than the one we asked for.
    #[error("asked the node for block {requested} but its coinbase claims height {claimed}")]
    HeightMismatch {
        requested: BlockHeight,
        claimed: BlockHeight,
    },
}

/// Parse a raw block and build its compact form. `sizes` is `None` when the
/// node did not report tree sizes; the scanner then needs a prior block with
/// known sizes, which every block after the birthday has.
pub fn from_raw<P: Parameters>(
    params: &P,
    height: BlockHeight,
    raw: &[u8],
    sizes: Option<TreeSizes>,
) -> Result<CompactBlock, CompactError> {
    let block =
        Block::read(raw, params).map_err(|source| CompactError::Parse { height, source })?;
    if block.claimed_height() != height {
        return Err(CompactError::HeightMismatch {
            requested: height,
            claimed: block.claimed_height(),
        });
    }
    Ok(from_block(&block, sizes))
}

/// The compact form of an already parsed block.
pub fn from_block(block: &Block, sizes: Option<TreeSizes>) -> CompactBlock {
    let header = block.header();
    CompactBlock {
        height: u64::from(u32::from(block.claimed_height())),
        hash: header.hash().0.to_vec(),
        prev_hash: header.prev_block.0.to_vec(),
        time: header.time,
        // "the header field should always be unset" (compact_formats.proto).
        header: Vec::new(),
        vtx: block
            .vtx()
            .iter()
            .enumerate()
            .map(|(i, tx)| compact_tx(i as u64, tx))
            .collect(),
        chain_metadata: sizes.map(|s| ChainMetadata {
            sapling_commitment_tree_size: s.sapling,
            orchard_commitment_tree_size: s.orchard,
            ironwood_commitment_tree_size: s.ironwood,
        }),
    }
}

/// One transaction's compact form. `index` is its position in the block;
/// the coinbase's null input is omitted as the proto requires.
pub fn compact_tx(index: u64, tx: &Transaction) -> CompactTx {
    let mut ctx = CompactTx {
        index,
        txid: tx.txid().as_ref().to_vec(),
        // Not computable without the inputs' previous outputs; lightwalletd
        // leaves it unset in the same situation.
        fee: 0,
        ..Default::default()
    };
    if let Some(bundle) = tx.transparent_bundle() {
        if !bundle.is_coinbase() {
            ctx.vin = bundle
                .vin
                .iter()
                .map(|txin| CompactTxIn {
                    prevout_txid: txin.prevout().hash().to_vec(),
                    prevout_index: txin.prevout().n(),
                })
                .collect();
        }
        ctx.vout = bundle
            .vout
            .iter()
            .map(|out| TxOut {
                value: out.value().into_u64(),
                script_pub_key: out.script_pubkey().0.0.clone(),
            })
            .collect();
    }
    if let Some(bundle) = tx.sapling_bundle() {
        ctx.spends = bundle
            .shielded_spends()
            .iter()
            .map(|s| CompactSaplingSpend {
                nf: s.nullifier().0.to_vec(),
            })
            .collect();
        ctx.outputs = bundle
            .shielded_outputs()
            .iter()
            .map(|o| CompactSaplingOutput {
                cmu: o.cmu().to_bytes().to_vec(),
                ephemeral_key: o.ephemeral_key().0.to_vec(),
                ciphertext: o.enc_ciphertext()[..COMPACT_CIPHERTEXT_LEN].to_vec(),
            })
            .collect();
    }
    if let Some(bundle) = tx.orchard_bundle() {
        ctx.actions = bundle.actions().iter().map(compact_action).collect();
    }
    if let Some(bundle) = tx.ironwood_bundle() {
        ctx.ironwood_actions = bundle.actions().iter().map(compact_action).collect();
    }
    ctx
}

fn compact_action<A>(a: &orchard::Action<A>) -> CompactOrchardAction {
    let note = a.encrypted_note();
    CompactOrchardAction {
        nullifier: a.nullifier().to_bytes().to_vec(),
        cmx: a.cmx().to_bytes().to_vec(),
        ephemeral_key: note.epk_bytes.to_vec(),
        ciphertext: note.enc_ciphertext[..COMPACT_CIPHERTEXT_LEN].to_vec(),
    }
}

/// A transparent output seen in a compact block, decoded for address matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentOutput {
    pub height: BlockHeight,
    /// Internal byte order.
    pub block_hash: [u8; 32],
    /// Internal byte order.
    pub txid: [u8; 32],
    pub index: u32,
    pub value_zat: u64,
    pub script_pubkey: Vec<u8>,
    /// `None` for a non-standard script (not P2PKH or P2SH).
    pub address: Option<TransparentAddress>,
}

impl TransparentOutput {
    /// The address as handed out (`t1…`, `t3…`, `tm…`), if standard.
    pub fn address_string(&self, network: NetworkType) -> Option<String> {
        self.address
            .map(|a| encode_transparent_address(network, &a))
    }
}

/// Every transparent output in `block`, in block order.
pub fn transparent_outputs(block: &CompactBlock) -> Vec<TransparentOutput> {
    let height = BlockHeight::from_u32(u32::try_from(block.height).unwrap_or(u32::MAX));
    let block_hash = to_array(&block.hash);
    let mut out = Vec::new();
    for tx in &block.vtx {
        let txid = to_array(&tx.txid);
        for (index, vout) in tx.vout.iter().enumerate() {
            out.push(TransparentOutput {
                height,
                block_hash,
                txid,
                index: index as u32,
                value_zat: vout.value,
                script_pubkey: vout.script_pub_key.clone(),
                address: address_of_script(&vout.script_pub_key),
            });
        }
    }
    out
}

/// Decode a `scriptPubKey` into a P2PKH or P2SH address, through the
/// upstream `TxOut` parser so that the standard-script rules stay upstream's.
pub fn address_of_script(script_pub_key: &[u8]) -> Option<TransparentAddress> {
    parse_txout(0, script_pub_key).and_then(|o| o.recipient_address())
}

/// The upstream `TxOut` for a decoded output, for
/// `WalletTransparentOutput::from_parts`. `None` if the value is out of range.
pub fn txout_of(output: &TransparentOutput) -> Option<transparent::bundle::TxOut> {
    parse_txout(output.value_zat, &output.script_pubkey)
}

/// Build a `TxOut` by serialising its parts, so that no `zcash_script`
/// dependency is needed here.
fn parse_txout(value_zat: u64, script_pub_key: &[u8]) -> Option<transparent::bundle::TxOut> {
    let value = i64::try_from(value_zat).ok()?;
    let mut encoded = Vec::with_capacity(8 + 9 + script_pub_key.len());
    encoded.extend_from_slice(&value.to_le_bytes());
    write_compact_size(&mut encoded, script_pub_key.len());
    encoded.extend_from_slice(script_pub_key);
    let mut cursor = Cursor::new(encoded);
    transparent::bundle::TxOut::read(&mut cursor).ok()
}

/// Encode a transparent address for `network`.
pub fn encode_transparent_address(network: NetworkType, addr: &TransparentAddress) -> String {
    use zcash_address::ToAddress as _;
    match addr {
        TransparentAddress::PublicKeyHash(data) => {
            ZcashAddress::from_transparent_p2pkh(network, *data)
        }
        TransparentAddress::ScriptHash(data) => ZcashAddress::from_transparent_p2sh(network, *data),
    }
    .encode()
}

fn write_compact_size(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

fn to_array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if bytes.len() == 32 {
        out.copy_from_slice(bytes);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{BlockSpec, regtest_params};

    #[test]
    fn synthetic_block_round_trips_into_a_compact_block() {
        let params = regtest_params();
        let pay_to = TransparentAddress::PublicKeyHash([7u8; 20]);
        let spec = BlockSpec::new(BlockHeight::from_u32(5), [1u8; 32], 1_700_000_000)
            .with_payment(pay_to, 12_345);
        let built = spec.build(&params);
        let sizes = TreeSizes {
            sapling: 3,
            orchard: 4,
            ironwood: 0,
        };
        let cb = from_raw(&params, BlockHeight::from_u32(5), &built.raw, Some(sizes)).unwrap();

        assert_eq!(cb.height, 5);
        assert_eq!(cb.hash, built.hash.to_vec());
        assert_eq!(cb.prev_hash, [1u8; 32].to_vec());
        assert_eq!(cb.time, 1_700_000_000);
        assert!(cb.header.is_empty());
        assert_eq!(cb.vtx.len(), 2, "coinbase + payment");
        assert_eq!(cb.chain_metadata.unwrap().orchard_commitment_tree_size, 4);

        let coinbase = &cb.vtx[0];
        assert_eq!(coinbase.index, 0);
        assert_eq!(coinbase.txid, built.txids[0].to_vec());
        assert!(coinbase.vin.is_empty(), "null coinbase input omitted");
        assert_eq!(coinbase.vout.len(), 1);

        let payment = &cb.vtx[1];
        assert_eq!(payment.index, 1);
        assert_eq!(payment.txid, built.txids[1].to_vec());
        assert_eq!(payment.vin.len(), 1);
        assert_eq!(payment.vin[0].prevout_index, 0);
        assert_eq!(payment.vout[0].value, 12_345);
        assert!(payment.spends.is_empty() && payment.actions.is_empty());

        let outs = transparent_outputs(&cb);
        assert_eq!(outs.len(), 2);
        let paid = &outs[1];
        assert_eq!(paid.address, Some(pay_to));
        assert_eq!(paid.value_zat, 12_345);
        assert_eq!(paid.index, 0);
        assert_eq!(paid.txid, built.txids[1]);
        assert_eq!(paid.block_hash, built.hash);
        let s = paid.address_string(NetworkType::Regtest).unwrap();
        assert!(s.starts_with("tm"), "{s}");
        assert!(
            encode_transparent_address(NetworkType::Main, &pay_to).starts_with("t1"),
            "mainnet P2PKH"
        );
    }

    #[test]
    fn height_mismatch_and_garbage_are_errors() {
        let params = regtest_params();
        let built = BlockSpec::new(BlockHeight::from_u32(9), [0u8; 32], 1).build(&params);
        let err = from_raw(&params, BlockHeight::from_u32(10), &built.raw, None).unwrap_err();
        assert!(matches!(err, CompactError::HeightMismatch { .. }), "{err}");
        let err = from_raw(&params, BlockHeight::from_u32(9), b"nonsense", None).unwrap_err();
        assert!(matches!(err, CompactError::Parse { .. }), "{err}");
    }

    #[test]
    fn non_standard_scripts_have_no_address() {
        assert_eq!(address_of_script(&[0x6a, 0x01, 0x00]), None); // OP_RETURN
        assert_eq!(address_of_script(&[]), None);
        let p2sh = TransparentAddress::ScriptHash([9u8; 20]);
        let script = transparent::address::Script::from(p2sh.script());
        assert_eq!(address_of_script(&script.0.0), Some(p2sh));
    }
}
