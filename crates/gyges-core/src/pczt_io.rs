//! What a `.pczt` file carries beyond the transaction (ARCHITECTURE.md §3.5,
//! API.md §7.1, CLI_SPEC.md §2.6): the ZIP 374 global `proprietary` tags
//! `gyges.key_id`, `gyges.network` and `gyges.session_id`, the bytes on the
//! wire, and the two views `pczt inspect` renders: the proposal as the file
//! itself implies it (inputs, outputs, fee, expiry), and which roles have
//! run over it.
//!
//! Nothing here needs a wallet or the node: the air-gapped side runs it on
//! a `signer-only` profile with only the file in hand.

use pczt::Pczt;
use pczt::roles::updater::Updater;
use pczt::roles::verifier::Verifier;
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_protocol::consensus::Parameters as _;

use crate::Pool;
use crate::network::{ConsensusParams, Network};
use crate::tx::{InputSummary, OutputSummary, ProposalSummary, StepSummary, TxError};

/// The global `proprietary` keys `pczt create` writes.
pub const TAG_KEY_ID: &str = "gyges.key_id";
pub const TAG_NETWORK: &str = "gyges.network";
pub const TAG_SESSION_ID: &str = "gyges.session_id";

/// The three tags, as read from or written to a PCZT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tags {
    pub key_id: String,
    pub network: Network,
    /// 32 hex characters; names the stored proposal `BroadcastPczt`
    /// verifies against.
    pub session_id: String,
}

/// A fresh session id: 16 random bytes, hex.
pub fn new_session_id() -> String {
    use rand::Rng as _;
    let mut id = [0u8; 16];
    rand::rand_core::UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut id);
    hex::encode(id)
}

/// The Updater role, writing the three tags.
pub fn tag(pczt: Pczt, tags: &Tags) -> Pczt {
    Updater::new(pczt)
        .update_global_with(|mut g| {
            g.set_proprietary(TAG_KEY_ID.into(), tags.key_id.as_bytes().to_vec());
            g.set_proprietary(TAG_NETWORK.into(), tags.network.name().as_bytes().to_vec());
            g.set_proprietary(TAG_SESSION_ID.into(), tags.session_id.as_bytes().to_vec());
        })
        .finish()
}

/// The tags of a PCZT; `INVALID_ARGUMENT` when any is missing or malformed
/// (the file did not come from `gyges pczt create`).
pub fn tags_of(pczt: &Pczt) -> Result<Tags, TxError> {
    let map = pczt.global().proprietary();
    let text = |key: &str| -> Result<String, TxError> {
        let bytes = map.get(key).ok_or_else(|| {
            TxError::InvalidArgument(format!(
                "the PCZT carries no `{key}` in its proprietary map; it was not written by `gyges pczt create`"
            ))
        })?;
        String::from_utf8(bytes.clone())
            .map_err(|_| TxError::InvalidArgument(format!("the PCZT's `{key}` is not UTF-8")))
    };
    let key_id = text(TAG_KEY_ID)?;
    let network_name = text(TAG_NETWORK)?;
    let network = Network::ALL
        .into_iter()
        .find(|n| n.name() == network_name)
        .ok_or_else(|| {
            TxError::InvalidArgument(format!(
                "the PCZT names an unknown network `{network_name}`"
            ))
        })?;
    let session_id = text(TAG_SESSION_ID)?;
    if session_id.len() != 32 || !session_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TxError::InvalidArgument(
            "the PCZT's `gyges.session_id` is not 32 hex characters".into(),
        ));
    }
    Ok(Tags {
        key_id,
        network,
        session_id,
    })
}

/// Bytes → PCZT (`INVALID_ARGUMENT` on anything that is not one).
pub fn parse(bytes: &[u8]) -> Result<Pczt, TxError> {
    if bytes.is_empty() {
        return Err(TxError::InvalidArgument("the PCZT is empty".into()));
    }
    Pczt::parse(bytes).map_err(|e| TxError::InvalidArgument(format!("not a PCZT: {e:?}")))
}

/// PCZT → bytes, in the `pczt` crate's own encoding (postcard behind a
/// magic header; v1 when representable, v2 otherwise).
pub fn serialize(pczt: Pczt) -> Result<Vec<u8>, TxError> {
    pczt.serialize()
        .map_err(|e| TxError::Internal(format!("serialising the PCZT: {e:?}")))
}

/// The ZIP 374 roles whose output can be seen in a PCZT, in pipeline order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Creator,
    Constructor,
    IoFinalizer,
    Updater,
    Prover,
    Signer,
    SpendFinalizer,
}

/// One pool's inputs, outputs, proofs and signatures (`PcztPoolState` on
/// the wire). Only pools with data are listed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolState {
    pub pool: Pool,
    /// Non-dummy spends (transparent inputs; shielded spends with value).
    pub spends: u32,
    pub outputs: u32,
    pub proofs_present: bool,
    pub signatures_present: u32,
    /// Every transparent input and every shielded action needs one.
    pub signatures_required: u32,
}

/// Everything `pczt inspect` shows besides the tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub summary: ProposalSummary,
    pub roles: Vec<Role>,
    pub pools: Vec<PoolState>,
}

impl Inspection {
    /// Every pool with data has its proofs.
    pub fn is_proven(&self) -> bool {
        self.pools.iter().all(|p| p.proofs_present)
    }

    /// Every required signature is there.
    pub fn is_signed(&self) -> bool {
        self.pools
            .iter()
            .all(|p| p.signatures_present >= p.signatures_required)
    }
}

/// One shielded output as the parsed bundle shows it.
struct ShieldedOut {
    value: u64,
    user_address: Option<String>,
    has_memo: bool,
}

/// The proposal the file implies, and the roles' progress. The anchor
/// height and `min_confirmations` are not in a PCZT (only the anchor root
/// is) and are reported as 0.
pub fn inspect(params: &ConsensusParams, pczt: &Pczt) -> Result<Inspection, TxError> {
    let global = pczt.global();
    let has_orchard = !pczt.orchard().actions().is_empty();
    let has_ironwood = !pczt.ironwood().actions().is_empty();
    let has_sapling = !pczt.sapling().spends().is_empty() || !pczt.sapling().outputs().is_empty();
    let has_transparent =
        !pczt.transparent().inputs().is_empty() || !pczt.transparent().outputs().is_empty();

    // Memo flags come from the unparsed Orchard outputs: a v2 file may carry
    // the memo plaintext instead of the ciphertext, which is the only way to
    // tell without a key.
    let memo_flags = |bundle: &pczt::orchard::Bundle| -> Vec<bool> {
        bundle
            .actions()
            .iter()
            .map(|a| match a.output().enc_ciphertext() {
                pczt::orchard::EncCiphertext::MemoPlaintext(m) => !m.as_stripped_bytes().is_empty(),
                pczt::orchard::EncCiphertext::Encrypted(_) => false,
            })
            .collect()
    };
    let orchard_memos = memo_flags(pczt.orchard());
    let ironwood_memos = memo_flags(pczt.ironwood());

    // The parsed bundles through the Verifier role, which is the one place
    // the upstream types (with every getter) are reachable from outside.
    let mut t_sigs = 0u32;
    let mut t_finalized = 0u32;
    let mut t_outputs: Vec<(Option<String>, bool)> = Vec::new();
    let mut orchard_in = (0u32, 0u64);
    let mut ironwood_in = (0u32, 0u64);
    let mut orchard_outs: Vec<ShieldedOut> = Vec::new();
    let mut ironwood_outs: Vec<ShieldedOut> = Vec::new();
    let mut orchard_sigs = 0u32;
    let mut ironwood_sigs = 0u32;
    let actions = |bundle: &orchard::pczt::Bundle,
                   memos: &[bool],
                   inputs: &mut (u32, u64),
                   outs: &mut Vec<ShieldedOut>,
                   sigs: &mut u32| {
        for (i, action) in bundle.actions().iter().enumerate() {
            let spent = action.spend().value().map_or(0, |v| v.inner());
            if spent > 0 {
                inputs.0 += 1;
                inputs.1 += spent;
            }
            if action.spend().spend_auth_sig().is_some() {
                *sigs += 1;
            }
            outs.push(ShieldedOut {
                value: action.output().value().map_or(0, |v| v.inner()),
                user_address: action.output().user_address().clone(),
                has_memo: memos.get(i).copied().unwrap_or(false),
            });
        }
    };
    let verifier = Verifier::new(pczt.clone());
    let verifier = if has_transparent {
        verifier
            .with_transparent::<String, _>(|bundle| {
                for input in bundle.inputs() {
                    if input.script_sig().is_some() {
                        t_finalized += 1;
                        t_sigs += 1;
                    } else if !input.partial_signatures().is_empty() {
                        t_sigs += 1;
                    }
                }
                for output in bundle.outputs() {
                    t_outputs.push((
                        output.user_address().clone(),
                        !output.bip32_derivation().is_empty(),
                    ));
                }
                Ok(())
            })
            .map_err(|e| TxError::InvalidArgument(format!("transparent bundle: {e:?}")))?
    } else {
        verifier
    };
    let verifier = if has_orchard {
        verifier
            .with_orchard::<String, _>(|bundle| {
                actions(
                    bundle,
                    &orchard_memos,
                    &mut orchard_in,
                    &mut orchard_outs,
                    &mut orchard_sigs,
                );
                Ok(())
            })
            .map_err(|e| TxError::InvalidArgument(format!("orchard bundle: {e:?}")))?
    } else {
        verifier
    };
    let verifier = if has_ironwood {
        verifier
            .with_ironwood::<String, _>(|bundle| {
                actions(
                    bundle,
                    &ironwood_memos,
                    &mut ironwood_in,
                    &mut ironwood_outs,
                    &mut ironwood_sigs,
                );
                Ok(())
            })
            .map_err(|e| TxError::InvalidArgument(format!("ironwood bundle: {e:?}")))?
    } else {
        verifier
    };
    let mut sapling_proofs = 0u32;
    let mut sapling_sigs = 0u32;
    if has_sapling {
        verifier
            .with_sapling::<String, _>(|bundle| {
                for s in bundle.spends() {
                    sapling_proofs += u32::from(s.zkproof().is_some());
                    sapling_sigs += u32::from(s.spend_auth_sig().is_some());
                }
                for o in bundle.outputs() {
                    sapling_proofs += u32::from(o.zkproof().is_some());
                }
                Ok(())
            })
            .map_err(|e| TxError::InvalidArgument(format!("sapling bundle: {e:?}")))?;
    }

    // Inputs and outputs as `tx send --dry-run` lists them.
    let mut inputs = Vec::new();
    let t_in: u64 = pczt.transparent().inputs().iter().map(|i| *i.value()).sum();
    if !pczt.transparent().inputs().is_empty() {
        inputs.push(InputSummary {
            pool: Pool::Transparent,
            count: pczt.transparent().inputs().len() as u32,
            value: t_in,
        });
    }
    let sapling_spends = pczt.sapling().spends().len() as u32;
    if sapling_spends > 0 {
        // Sapling spends are never proposed in this milestone (Q-K3); their
        // value is not readable from the file without the key.
        inputs.push(InputSummary {
            pool: Pool::Sapling,
            count: sapling_spends,
            value: 0,
        });
    }
    for (pool, (count, value)) in [(Pool::Orchard, orchard_in), (Pool::Ironwood, ironwood_in)] {
        if count > 0 {
            inputs.push(InputSummary { pool, count, value });
        }
    }
    let mut outputs = Vec::new();
    let mut t_out = 0u64;
    for (i, out) in pczt.transparent().outputs().iter().enumerate() {
        t_out += *out.value();
        let (user_address, owned) = t_outputs.get(i).cloned().unwrap_or((None, false));
        let address = user_address.unwrap_or_else(|| {
            gyges_chain::compact::address_of_script(out.script_pubkey()).map_or_else(
                || "unrecognised script".to_string(),
                |a| gyges_chain::compact::encode_transparent_address(params.network_type(), &a),
            )
        });
        let is_change = owned && t_outputs[i].0.is_none();
        outputs.push(OutputSummary {
            address: if is_change { "change".into() } else { address },
            pool: Pool::Transparent,
            value: *out.value(),
            is_change,
            is_ephemeral: false,
            has_memo: false,
        });
    }
    let mut sapling_out = 0u64;
    for out in pczt.sapling().outputs() {
        let value = out.value().unwrap_or(0);
        sapling_out += value;
        let address = out
            .recipient()
            .and_then(|r| sapling::PaymentAddress::from_bytes(&r))
            .and_then(|a| UnifiedAddress::from_receivers(None, Some(a), None))
            .map(|ua| Address::Unified(ua).encode(params));
        outputs.push(OutputSummary {
            address: address.clone().unwrap_or_else(|| "change".into()),
            pool: Pool::Sapling,
            value,
            is_change: address.is_none(),
            is_ephemeral: false,
            has_memo: false,
        });
    }
    let mut shielded_out = 0u64;
    for (pool, outs) in [
        (Pool::Orchard, orchard_outs),
        (Pool::Ironwood, ironwood_outs),
    ] {
        for o in outs {
            shielded_out += o.value;
            // A recipient the wallet did not name (`user_address`) is
            // change or a dummy: the proposal shows both as change, and the
            // raw receiver would only invite comparing it by eye.
            let address = o.user_address;
            let is_change = address.is_none();
            outputs.push(OutputSummary {
                address: address.unwrap_or_else(|| "change".into()),
                pool,
                value: o.value,
                is_change,
                is_ephemeral: false,
                has_memo: o.has_memo,
            });
        }
    }
    let total_in = t_in + orchard_in.1 + ironwood_in.1;
    let total_out = t_out + sapling_out + shielded_out;
    let fee = total_in.saturating_sub(total_out);
    let transparent_only = !(has_orchard || has_ironwood || has_sapling);
    let step = StepSummary {
        inputs,
        outputs: outputs.clone(),
        fee,
        transparent_only,
    };
    let total_debit = outputs
        .iter()
        .filter(|o| !o.is_change)
        .map(|o| o.value)
        .sum::<u64>()
        + fee;
    let summary = ProposalSummary {
        steps: vec![step],
        total_debit,
        total_fee: fee,
        anchor_height: 0,
        expiry_height: *global.expiry_height(),
        min_confirmations: 0,
        upstream: Vec::new(),
    };

    // Per pool.
    let mut pools = Vec::new();
    if has_transparent {
        let n = pczt.transparent().inputs().len() as u32;
        pools.push(PoolState {
            pool: Pool::Transparent,
            spends: n,
            outputs: pczt.transparent().outputs().len() as u32,
            proofs_present: true,
            signatures_present: t_sigs,
            signatures_required: n,
        });
    }
    if has_sapling {
        pools.push(PoolState {
            pool: Pool::Sapling,
            spends: sapling_spends,
            outputs: pczt.sapling().outputs().len() as u32,
            proofs_present: sapling_proofs
                == sapling_spends + pczt.sapling().outputs().len() as u32,
            signatures_present: sapling_sigs,
            signatures_required: sapling_spends,
        });
    }
    if has_orchard {
        pools.push(PoolState {
            pool: Pool::Orchard,
            spends: orchard_in.0,
            outputs: pczt.orchard().actions().len() as u32,
            proofs_present: pczt.orchard().zkproof().is_some(),
            signatures_present: orchard_sigs,
            signatures_required: pczt.orchard().actions().len() as u32,
        });
    }
    if has_ironwood {
        pools.push(PoolState {
            pool: Pool::Ironwood,
            spends: ironwood_in.0,
            outputs: pczt.ironwood().actions().len() as u32,
            proofs_present: pczt.ironwood().zkproof().is_some(),
            signatures_present: ironwood_sigs,
            signatures_required: pczt.ironwood().actions().len() as u32,
        });
    }

    // Roles, by their footprints.
    let mut roles = vec![Role::Creator];
    let any_data = has_transparent || has_sapling || has_orchard || has_ironwood;
    if any_data {
        roles.push(Role::Constructor);
    }
    let shielded = has_sapling || has_orchard || has_ironwood;
    if (shielded && !global.shielded_modifiable())
        || (!shielded && !global.inputs_modifiable() && !global.outputs_modifiable())
    {
        roles.push(Role::IoFinalizer);
    }
    if global.proprietary().contains_key(TAG_KEY_ID) {
        roles.push(Role::Updater);
    }
    let proven = any_data && pools.iter().all(|p| p.proofs_present);
    if proven {
        roles.push(Role::Prover);
    }
    let signed = any_data
        && pools
            .iter()
            .all(|p| p.signatures_present >= p.signatures_required);
    if signed {
        roles.push(Role::Signer);
    }
    if has_transparent && t_finalized == pczt.transparent().inputs().len() as u32 {
        roles.push(Role::SpendFinalizer);
    }
    Ok(Inspection {
        summary,
        roles,
        pools,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_32_hex_and_unique() {
        let a = new_session_id();
        let b = new_session_id();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn garbage_is_not_a_pczt() {
        assert!(matches!(parse(b""), Err(TxError::InvalidArgument(_))));
        assert!(matches!(
            parse(b"not a pczt at all"),
            Err(TxError::InvalidArgument(_))
        ));
    }
}
