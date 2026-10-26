//! The `TxEngine` (ARCHITECTURE.md §2.1, §3.2; API.md §4.1, §6.4;
//! OVERVIEW.md Q-K3, Q-K7): one send, from a recipient and an amount to a
//! raw transaction the node can take.
//!
//! The steps are the ZIP 374 roles, each a function here so that the
//! daemon can emit a stream event between them and pause for the signature:
//!
//! 1. [`propose_send`] / [`propose_shield`] — `propose_transfer` /
//!    `propose_shielding` with the greedy input selector, ZIP 317 fees and
//!    single-output change; the profile's `spend_pools` decide which notes
//!    and UTXOs may fund it;
//! 2. [`summarize`] — the proposal as the user sees it (`Proposed`,
//!    `--dry-run`), including the upstream proto for `--json`;
//! 3. [`build_pczt`] — Creator, Constructor, IO Finalizer and Updater, all
//!    inside `create_pczt_from_proposal`;
//! 4. [`prove`] — the Prover role, which needs no secret for Orchard and
//!    transparent (Q-K3) and so runs while the vault is locked;
//! 5. [`sign`] — the Signer role with the `UnifiedSpendingKey` derived from
//!    the decrypted entropy; the key lives for this call only;
//! 6. [`verify`] — the Verifier role against what was proposed: a PCZT
//!    whose outputs, values or fee drifted from the approved proposal is
//!    never broadcast (Q-K7);
//! 7. [`extract_and_store`] — Spend Finalizer and Transaction Extractor,
//!    then the wallet records the transaction as its own (unmined) so that
//!    `balance` shows the pending spend and the scanner recognises it when
//!    it is mined.
//!
//! Everything runs synchronously against one key's wallet under its lock;
//! the daemon decides the threads. Nothing here touches the node: the
//! daemon broadcasts the bytes [`extract_and_store`] returns.

use std::convert::Infallible;
use std::fmt;
use std::sync::OnceLock;

use orchard::circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey};
use pczt::Pczt;
use pczt::roles::prover::Prover;
use pczt::roles::signer::Signer;
use pczt::roles::verifier::Verifier;
use prost::Message as _;
use secrecy::ExposeSecret as _;
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zcash_client_backend::data_api::error::Error as WalletApiError;
use zcash_client_backend::data_api::wallet::input_selection::{
    CoinbasePolicy, GreedyInputSelector, SpendPolicy, TransparentSpendPolicy,
};
use zcash_client_backend::data_api::wallet::{
    ConfirmationsPolicy, SpendingKeys, create_pczt_from_proposal, create_proposed_transactions,
    extract_and_store_transaction_from_pczt, propose_shielding, propose_transfer,
};
use zcash_client_backend::data_api::{CoinbaseFilter, InputSource as _, WalletRead as _};
use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
use zcash_client_backend::fees::{DustOutputPolicy, StandardFeeRule};
use zcash_client_backend::proposal::{Proposal, Step, StepOutputIndex};
use zcash_client_backend::wallet::{
    Note, OvkPolicy, TransparentAddressSource, WalletTransparentOutput,
};
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId};
use zcash_keys::address::Address;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::builder::{
    BundlePadding, NU7_DEFAULT_TX_EXPIRY_DELTA, PRE_NU7_DEFAULT_TX_EXPIRY_DELTA,
};
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters as _};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedPool, TxId};

use crate::Pool;
use crate::network::ConsensusParams;
use crate::registry::Wallet;
use crate::vault::{Entropy, seed_from_entropy};

/// The longest memo `tx send --memo` accepts (CLI_SPEC.md §1.5).
pub const MAX_MEMO_BYTES: usize = 512;

/// Why a send could not be built, in the terms the daemon maps to
/// `GygesError` reasons (API.md §3).
#[derive(Debug, thiserror::Error)]
pub enum TxError {
    /// `INSUFFICIENT_FUNDS`: both values in zatoshis.
    #[error("insufficient funds: {available} zatoshis available, {required} required")]
    InsufficientFunds { available: u64, required: u64 },
    /// `NOT_SYNCED`: the wallet has no chain tip or anchor to build on.
    #[error("the wallet has not scanned far enough to build a transaction: {0}")]
    NotSynced(String),
    /// `INVALID_ARGUMENT`: a bad address, amount or memo.
    #[error("{0}")]
    InvalidArgument(String),
    /// `UNSUPPORTED_POOL`.
    #[error("{0}")]
    UnsupportedPool(String),
    /// `INVALID_ARGUMENT`: the Verifier found the PCZT differs from the
    /// approved proposal (Q-K7); nothing is broadcast.
    #[error("{0}")]
    Verifier(String),
    /// `INTERNAL`: the wallet or the PCZT pipeline failed.
    #[error("{0}")]
    Internal(String),
}

pub(crate) fn internal(context: &str, e: impl fmt::Display) -> TxError {
    TxError::Internal(format!("{context}: {e}"))
}

/// What `tx send --amount` resolved to (CLI_SPEC.md §1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountSpec {
    Zatoshis(Zatoshis),
    /// Every spendable zatoshi of the permitted pools minus the fee.
    Max,
}

/// A proposal with the wallet's note references (the only fee rule Gyges
/// uses is ZIP 317).
pub type SendProposal = Proposal<StandardFeeRule, ReceivedNoteId>;
/// A shielding proposal: transparent inputs only, so no note references.
pub type ShieldProposal = Proposal<StandardFeeRule, Infallible>;

/// Parse a recipient for the network. A ZIP 320 (`tex1`) recipient parses
/// like any other; `propose_send` then yields the two-step proposal of
/// ARCHITECTURE.md §3.3.
pub fn parse_recipient(params: &ConsensusParams, s: &str) -> Result<Address, TxError> {
    let s = s.trim();
    Address::decode(params, s).ok_or_else(|| {
        TxError::InvalidArgument(
            "the recipient is not a valid address for this network".to_string(),
        )
    })
}

/// CLI_SPEC.md §1.5: a memo goes only to a recipient with a shielded
/// receiver and is at most 512 bytes; it is never silently dropped.
pub fn memo_for(recipient: &Address, memo: &[u8]) -> Result<Option<MemoBytes>, TxError> {
    if memo.is_empty() {
        return Ok(None);
    }
    if memo.len() > MAX_MEMO_BYTES {
        return Err(TxError::InvalidArgument(format!(
            "the memo is {} bytes; at most {MAX_MEMO_BYTES} are allowed",
            memo.len()
        )));
    }
    let shielded = match recipient {
        Address::Sapling(_) => true,
        Address::Unified(ua) => ua.orchard().is_some() || ua.sapling().is_some(),
        Address::Transparent(_) | Address::Tex(_) => false,
    };
    if !shielded {
        return Err(TxError::InvalidArgument(
            "a memo needs a shielded recipient; this address has no shielded receiver".to_string(),
        ));
    }
    MemoBytes::from_bytes(memo)
        .map(Some)
        .map_err(|e| TxError::InvalidArgument(format!("invalid memo: {e}")))
}

/// `policy.min_confirmations` as the upstream policy (symmetric for trusted
/// and untrusted notes; zero-conf shielding is not allowed).
pub fn confirmations_policy(min_confirmations: u32) -> ConfirmationsPolicy {
    ConfirmationsPolicy::new_symmetrical(
        std::num::NonZeroU32::new(min_confirmations.max(1)).expect("non-zero"),
        false,
    )
}

/// The first (and only) account of a key's wallet.
pub fn account_of(wallet: &Wallet) -> Result<AccountUuid, TxError> {
    wallet
        .get_account_ids()
        .map_err(|e| internal("listing accounts", e))?
        .first()
        .copied()
        .ok_or_else(|| TxError::Internal("the wallet has no account".into()))
}

/// Which pools a key may fund a send from, as the upstream policy. Sapling
/// is receive-only in the MVP (ROADMAP.md "Pools are data"), so a profile
/// without it in `spend_pools` never spends Sapling notes.
fn spend_policy(spend_pools: &[Pool]) -> SpendPolicy {
    let shielded = spend_pools.iter().filter_map(|p| match p {
        Pool::Sapling => Some(ShieldedPool::Sapling),
        Pool::Orchard => Some(ShieldedPool::Orchard),
        Pool::Ironwood => Some(ShieldedPool::Ironwood),
        Pool::Transparent => None,
    });
    let mut policy = SpendPolicy::shielded_pools(shielded);
    if spend_pools.contains(&Pool::Transparent) {
        policy = policy.with_transparent(
            TransparentSpendPolicy::any_account_addr().with_coinbase(CoinbasePolicy::NonCoinbase),
        );
    }
    policy
}

fn change_strategy() -> SingleOutputChangeStrategy<Wallet> {
    SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    )
}

/// Map an upstream wallet error to ours: `not_synced` is the detail for a
/// missing anchor, `what` names the step for anything else. The upstream
/// type is generic over six error parameters, so only its shape is matched.
fn wallet_api_error<D, C, S, F, Ch, N>(
    e: WalletApiError<D, C, S, F, Ch, N>,
    not_synced: &str,
    what: &str,
) -> TxError
where
    WalletApiError<D, C, S, F, Ch, N>: fmt::Display,
{
    match e {
        WalletApiError::InsufficientFunds {
            available,
            required,
        } => TxError::InsufficientFunds {
            available: available.into_u64(),
            required: required.into_u64(),
        },
        WalletApiError::ScanRequired => TxError::NotSynced(not_synced.into()),
        other => TxError::Internal(format!("{what} failed: {other}")),
    }
}

/// The `NotSynced` detail when a proposal finds nothing to anchor on.
const NO_SCANNED_BLOCKS: &str = "no scanned blocks to anchor the transaction on";

/// A ZIP 321 request for one payment of `amount` to `recipient`.
fn single_payment(
    recipient: zcash_address::ZcashAddress,
    amount: Zatoshis,
    memo: Option<MemoBytes>,
) -> Result<TransactionRequest, TxError> {
    let payment = Payment::new(recipient, Some(amount), memo, None, None, vec![])
        .map_err(|e| TxError::InvalidArgument(format!("invalid payment: {e}")))?;
    TransactionRequest::new(vec![payment])
        .map_err(|e| TxError::InvalidArgument(format!("invalid payment request: {e}")))
}

/// `propose_transfer` for one payment. With [`AmountSpec::Max`] the amount
/// is found by asking for everything spendable and lowering it by exactly
/// what the first attempt says is missing (the ZIP 317 fee), at most a few
/// times.
#[allow(clippy::too_many_arguments)]
pub fn propose_send(
    wallet: &mut Wallet,
    params: &ConsensusParams,
    account: AccountUuid,
    spend_pools: &[Pool],
    to: &Address,
    amount: AmountSpec,
    memo: Option<MemoBytes>,
    min_confirmations: u32,
) -> Result<SendProposal, TxError> {
    let policy = spend_policy(spend_pools);
    let confirmations = confirmations_policy(min_confirmations);
    let recipient = to.to_zcash_address(params);
    let selector = GreedyInputSelector::<Wallet>::new();
    let strategy = change_strategy();
    let attempt = |wallet: &mut Wallet, amount: Zatoshis| -> Result<SendProposal, TxError> {
        let request = single_payment(recipient.clone(), amount, memo.clone())?;
        propose_transfer::<_, _, _, _, Infallible>(
            wallet,
            params,
            account,
            &selector,
            &strategy,
            request,
            confirmations,
            &policy,
            None,
            None,
        )
        .map_err(|e| wallet_api_error(e, NO_SCANNED_BLOCKS, "proposal"))
    };
    match amount {
        AmountSpec::Zatoshis(z) => {
            if z == Zatoshis::ZERO {
                return Err(TxError::InvalidArgument(
                    "the amount must be positive".into(),
                ));
            }
            attempt(wallet, z)
        }
        AmountSpec::Max => {
            let total = spendable_total(wallet, spend_pools, min_confirmations)?.into_u64();
            let mut amount = Zatoshis::from_u64(total).map_err(|e| internal("amount", e))?;
            for _ in 0..8 {
                if amount == Zatoshis::ZERO {
                    return Err(TxError::InsufficientFunds {
                        available: 0,
                        required: 1,
                    });
                }
                match attempt(wallet, amount) {
                    Ok(p) => return Ok(p),
                    Err(TxError::InsufficientFunds {
                        available,
                        required,
                    }) if required > available => {
                        // `required` is the amount plus the fee. Upstream
                        // reports what it could select as `available`, but
                        // reports 0 when the selection would have been
                        // transparent inputs only, so fall back to the
                        // wallet's own spendable total there; otherwise a
                        // transparent-only wallet could never send `max`.
                        let fee = required.saturating_sub(amount.into_u64());
                        let have = if available > 0 { available } else { total };
                        amount = Zatoshis::from_u64(have.saturating_sub(fee))
                            .map_err(|e| internal("amount", e))?;
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(TxError::Internal(
                "could not settle on an amount for `max` after several attempts".into(),
            ))
        }
    }
}

/// Spendable value across the permitted pools at `min_confirmations`.
fn spendable_total(
    wallet: &Wallet,
    spend_pools: &[Pool],
    min_confirmations: u32,
) -> Result<Zatoshis, TxError> {
    let b = balance(wallet, min_confirmations)?;
    let mut total = 0u64;
    for p in &b.pools {
        if spend_pools.contains(&p.pool) {
            total += p.spendable;
        }
    }
    Zatoshis::from_u64(total).map_err(|e| internal("balance", e))
}

/// `propose_shielding`: every non-coinbase UTXO of the account's transparent
/// receivers into Orchard, when at least `threshold` zatoshis are there.
pub fn propose_shield(
    wallet: &mut Wallet,
    params: &ConsensusParams,
    account: AccountUuid,
    threshold: u64,
    min_confirmations: u32,
) -> Result<ShieldProposal, TxError> {
    let receivers: Vec<_> = wallet
        .get_transparent_receivers(account, true, true)
        .map_err(|e| internal("listing transparent receivers", e))?
        .into_keys()
        .collect();
    if receivers.is_empty() {
        return Err(TxError::InsufficientFunds {
            available: 0,
            required: threshold.max(1),
        });
    }
    let selector = GreedyInputSelector::<Wallet>::new();
    let strategy = change_strategy();
    propose_shielding::<_, _, _, _, Infallible>(
        wallet,
        params,
        &selector,
        &strategy,
        Zatoshis::from_u64(threshold).map_err(|e| internal("threshold", e))?,
        &receivers,
        account,
        confirmations_policy(min_confirmations),
        CoinbaseFilter::NonCoinbaseOnly,
        None,
    )
    .map_err(|e| wallet_api_error(e, NO_SCANNED_BLOCKS, "proposal"))
}

/// One proposed input group (`ProposedInput` on the wire).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSummary {
    pub pool: Pool,
    pub count: u32,
    pub value: u64,
}

/// One proposed output (`ProposedOutput` on the wire).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSummary {
    /// The recipient as encoded, `change` or `ephemeral`.
    pub address: String,
    pub pool: Pool,
    pub value: u64,
    pub is_change: bool,
    pub is_ephemeral: bool,
    pub has_memo: bool,
}

/// One step (`ProposalStep` on the wire).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepSummary {
    pub inputs: Vec<InputSummary>,
    pub outputs: Vec<OutputSummary>,
    pub fee: u64,
    pub transparent_only: bool,
}

/// The proposal as shown to the user and verified against before
/// broadcast (`Proposal` on the wire).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalSummary {
    pub steps: Vec<StepSummary>,
    /// Every non-change output plus every fee.
    pub total_debit: u64,
    pub total_fee: u64,
    pub anchor_height: u32,
    /// The height the transaction will carry as `nExpiryHeight`.
    pub expiry_height: u32,
    pub min_confirmations: u32,
    /// `zcash_client_backend::proto::proposal::Proposal`, serialised.
    pub upstream: Vec<u8>,
}

fn pool_of(p: PoolType) -> Pool {
    match p {
        PoolType::Transparent => Pool::Transparent,
        PoolType::Shielded(ShieldedPool::Sapling) => Pool::Sapling,
        PoolType::Shielded(ShieldedPool::Orchard) => Pool::Orchard,
        PoolType::Shielded(ShieldedPool::Ironwood) => Pool::Ironwood,
    }
}

/// The default expiry `create_pczt_from_proposal` applies when none is
/// given: `target + 40` blocks (or the NU7-scaled delta once NU7 is active).
pub fn default_expiry(params: &ConsensusParams, target: BlockHeight) -> BlockHeight {
    let delta = if params.is_nu_active(NetworkUpgrade::Nu7, target) {
        NU7_DEFAULT_TX_EXPIRY_DELTA
    } else {
        PRE_NU7_DEFAULT_TX_EXPIRY_DELTA
    };
    target + delta
}

fn summarize_step<N>(proposal: &Proposal<StandardFeeRule, N>, step: &Step<N>) -> StepSummary {
    let mut inputs: Vec<InputSummary> = Vec::new();
    let mut add_input = |pool: Pool, value: u64| match inputs.iter_mut().find(|i| i.pool == pool) {
        Some(i) => {
            i.count += 1;
            i.value += value;
        }
        None => inputs.push(InputSummary {
            pool,
            count: 1,
            value,
        }),
    };
    for utxo in step.transparent_inputs() {
        add_input(Pool::Transparent, utxo.value().into_u64());
    }
    // ZIP 320 step 2 spends an output of step 1 (the ephemeral one): shown
    // as the transparent input it will be.
    for prior in step.prior_step_inputs() {
        let Some(prior_step) = proposal.steps().get(prior.step_index()) else {
            continue;
        };
        let value = match prior.output_index() {
            StepOutputIndex::Change(i) => prior_step
                .balance()
                .proposed_change()
                .get(i)
                .map_or(0, |c| c.value().into_u64()),
            StepOutputIndex::Payment(i) => prior_step
                .transaction_request()
                .payments()
                .get(&i)
                .and_then(|p| p.amount())
                .map_or(0, Zatoshis::into_u64),
        };
        add_input(Pool::Transparent, value);
    }
    if let Some(shielded) = step.shielded_inputs() {
        for note in shielded.notes() {
            let pool = match note.note() {
                Note::Sapling(_) => Pool::Sapling,
                Note::Orchard { pool, .. } => match pool {
                    orchard::ValuePool::Orchard => Pool::Orchard,
                    orchard::ValuePool::Ironwood => Pool::Ironwood,
                },
            };
            add_input(pool, note.note().value().into_u64());
        }
    }
    let mut outputs = Vec::new();
    for (idx, payment) in step.transaction_request().payments() {
        let pool = step
            .payment_pools()
            .get(idx)
            .copied()
            .map_or(Pool::Transparent, pool_of);
        outputs.push(OutputSummary {
            address: payment.recipient_address().encode(),
            pool,
            value: payment.amount().map_or(0, Zatoshis::into_u64),
            is_change: false,
            is_ephemeral: false,
            has_memo: payment.memo().is_some(),
        });
    }
    for change in step.balance().proposed_change() {
        outputs.push(OutputSummary {
            address: if change.is_ephemeral() {
                "ephemeral".into()
            } else {
                "change".into()
            },
            pool: pool_of(change.output_pool()),
            value: change.value().into_u64(),
            is_change: !change.is_ephemeral(),
            is_ephemeral: change.is_ephemeral(),
            has_memo: change.memo().is_some(),
        });
    }
    let shielded_pools = [
        ShieldedPool::Sapling,
        ShieldedPool::Orchard,
        ShieldedPool::Ironwood,
    ];
    let transparent_only = !shielded_pools
        .iter()
        .any(|p| step.involves(PoolType::Shielded(*p)));
    StepSummary {
        inputs,
        outputs,
        fee: step.balance().fee_required().into_u64(),
        transparent_only,
    }
}

/// Step 2 of the pipeline: what the user approves.
pub fn summarize<N>(
    params: &ConsensusParams,
    proposal: &Proposal<StandardFeeRule, N>,
    min_confirmations: u32,
) -> ProposalSummary {
    let steps: Vec<StepSummary> = proposal
        .steps()
        .iter()
        .map(|s| summarize_step(proposal, s))
        .collect();
    let total_fee = steps.iter().map(|s| s.fee).sum::<u64>();
    let total_debit = steps
        .iter()
        .flat_map(|s| s.outputs.iter())
        .filter(|o| !o.is_change && !o.is_ephemeral)
        .map(|o| o.value)
        .sum::<u64>()
        + total_fee;
    let target = BlockHeight::from(proposal.min_target_height());
    let upstream =
        zcash_client_backend::proto::proposal::Proposal::from_standard_proposal(proposal)
            .encode_to_vec();
    ProposalSummary {
        steps,
        total_debit,
        total_fee,
        anchor_height: proposal
            .steps()
            .first()
            .anchor_height()
            .map_or(0, u32::from),
        expiry_height: u32::from(default_expiry(params, target)),
        min_confirmations,
        upstream,
    }
}

/// Step 3: Creator, Constructor, IO Finalizer and Updater (anchors and
/// witnesses from the wallet). Only single-step proposals can become one
/// PCZT, which is every proposal except ZIP 320's. `expiry` overrides the
/// default `target + 40` (`pczt create` gives a file time to travel).
pub fn build_pczt<N: fmt::Display>(
    wallet: &mut Wallet,
    params: &ConsensusParams,
    account: AccountUuid,
    proposal: &Proposal<StandardFeeRule, N>,
    expiry: Option<BlockHeight>,
) -> Result<Pczt, TxError> {
    create_pczt_from_proposal::<_, _, Infallible, _, Infallible, N>(
        wallet,
        params,
        account,
        OvkPolicy::Sender,
        proposal,
        expiry,
        BundlePadding {
            bundle_required: false,
            pad_to_minimum: None,
        },
    )
    .map_err(|e| wallet_api_error(e, "no anchor available", "building the PCZT"))
}

/// The proving and verifying keys, built on first use (seconds for Orchard;
/// the bundled Sapling parameters are tens of megabytes) and kept for the
/// daemon's lifetime.
#[derive(Default)]
pub struct Provers {
    orchard: OnceLock<(ProvingKey, VerifyingKey)>,
    sapling: OnceLock<LocalTxProver>,
}

impl fmt::Debug for Provers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provers")
            .field("orchard_built", &self.orchard.get().is_some())
            .field("sapling_built", &self.sapling.get().is_some())
            .finish()
    }
}

impl Provers {
    pub fn new() -> Self {
        Self::default()
    }

    /// The Orchard keys for the circuit that can currently be proven.
    pub fn orchard(&self) -> &(ProvingKey, VerifyingKey) {
        self.orchard.get_or_init(|| {
            let version = OrchardCircuitVersion::PostNu6_3;
            let t0 = std::time::Instant::now();
            let pk = ProvingKey::build(version).expect("the current circuit supports proving");
            let vk = VerifyingKey::build(version);
            tracing::info!(ms = t0.elapsed().as_millis(), "orchard proving key built");
            (pk, vk)
        })
    }

    /// The bundled Sapling prover.
    pub fn sapling(&self) -> &LocalTxProver {
        self.sapling.get_or_init(|| {
            let t0 = std::time::Instant::now();
            let p = LocalTxProver::bundled();
            tracing::info!(ms = t0.elapsed().as_millis(), "sapling parameters loaded");
            p
        })
    }

    /// Build the Orchard keys now (the daemon does this at start so the
    /// first send does not pay for it).
    pub fn warm_orchard(&self) {
        let _ = self.orchard();
    }
}

/// What [`prove`] had to prove, for the `Proving` progress events.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProvingWork {
    pub orchard_actions: u32,
    pub ironwood_actions: u32,
    pub sapling_spends: u32,
    pub sapling_outputs: u32,
}

/// What a PCZT needs proven, before doing it.
pub fn proving_work(pczt: &Pczt) -> ProvingWork {
    ProvingWork {
        orchard_actions: pczt.orchard().actions().len() as u32,
        ironwood_actions: pczt.ironwood().actions().len() as u32,
        sapling_spends: pczt.sapling().spends().len() as u32,
        sapling_outputs: pczt.sapling().outputs().len() as u32,
    }
}

/// Step 4: the Prover role. Orchard and Ironwood bundles share the Orchard
/// circuit and proving key. Refuses PCZTs whose consensus branch needs a
/// circuit this build cannot prove, and Sapling *spends* (their proof
/// generation key would have to come from the unlocked seed first, Q-K3;
/// Sapling is receive-only in the MVP so none are ever proposed).
pub fn prove(pczt: Pczt, provers: &Provers) -> Result<Pczt, TxError> {
    let branch = BranchId::try_from(*pczt.global().consensus_branch_id())
        .map_err(|e| TxError::Internal(format!("unknown consensus branch in the PCZT: {e}")))?;
    if !pczt.sapling().spends().is_empty() {
        return Err(TxError::UnsupportedPool(
            "Sapling spends are not supported in this milestone (ROADMAP.md M6)".into(),
        ));
    }
    let mut prover = Prover::new(pczt);
    if prover.requires_orchard_proof() || prover.requires_ironwood_proof() {
        let version = bundle_version_for_branch(branch, orchard::ValuePool::Orchard)
            .ok_or_else(|| {
                TxError::Internal(format!("branch {branch:?} has no Orchard bundle version"))
            })?
            .circuit_version();
        if version != OrchardCircuitVersion::PostNu6_3 {
            return Err(TxError::Internal(format!(
                "the PCZT needs Orchard circuit {version:?}, which this build cannot prove"
            )));
        }
        let (pk, _) = provers.orchard();
        if prover.requires_orchard_proof() {
            prover = prover
                .create_orchard_proof(pk)
                .map_err(|e| TxError::Internal(format!("orchard proving failed: {e:?}")))?;
        }
        if prover.requires_ironwood_proof() {
            prover = prover
                .create_ironwood_proof(pk)
                .map_err(|e| TxError::Internal(format!("ironwood proving failed: {e:?}")))?;
        }
    }
    if prover.requires_sapling_proofs() {
        let sapling = provers.sapling();
        prover = prover
            .create_sapling_proofs(sapling, sapling)
            .map_err(|e| TxError::Internal(format!("sapling proving failed: {e:?}")))?;
    }
    Ok(prover.finish())
}

/// Derive the account's spending key from decrypted entropy.
pub fn spending_key(
    params: &ConsensusParams,
    entropy: &Entropy,
    account_index: u32,
) -> Result<UnifiedSpendingKey, TxError> {
    let account = zip32::AccountId::try_from(account_index)
        .map_err(|_| TxError::Internal("account index out of range".into()))?;
    let seed = seed_from_entropy(entropy);
    UnifiedSpendingKey::from_seed(params, seed.expose_secret(), account)
        .map_err(|e| TxError::Internal(format!("key derivation failed: {e:?}")))
}

/// Who signs: the seed fingerprint and account a transparent input's BIP 44
/// derivation must name for this key to sign it.
#[derive(Clone, Copy, Debug)]
pub struct SignerId {
    pub params: ConsensusParams,
    pub seed_fingerprint: zip32::fingerprint::SeedFingerprint,
    pub account: zip32::AccountId,
    /// SLIP-44 coin type of the network (133 mainnet, 1 testnet and regtest).
    pub coin_type: u32,
}

impl SignerId {
    /// From a profile that derives from a seed (`local-seed`,
    /// `signer-only`).
    pub fn of(profile: &crate::KeyProfile, params: &ConsensusParams) -> Result<Self, TxError> {
        use zcash_protocol::consensus::NetworkConstants as _;
        let hex_fp = profile
            .seed_fingerprint
            .as_deref()
            .ok_or_else(|| TxError::Internal("this profile has no seed fingerprint".into()))?;
        let bytes: [u8; 32] = hex::decode(hex_fp)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                TxError::Internal("the profile's seed fingerprint is malformed".into())
            })?;
        let account = zip32::AccountId::try_from(profile.account_index)
            .map_err(|_| TxError::Internal("account index out of range".into()))?;
        Ok(Self {
            params: *params,
            seed_fingerprint: zip32::fingerprint::SeedFingerprint::from_bytes(bytes),
            account,
            coin_type: params.network_type().coin_type(),
        })
    }
}

/// The non-hardened tail of a BIP 44 path: scope and address index.
type Bip44Path = (TransparentKeyScope, NonHardenedChildIndex);

/// The `(scope, address_index)` each transparent input's BIP 44 derivation
/// names for `signer`, in input order; `None` where the input carries no
/// derivation for this seed and account. Read through the Verifier role,
/// the only place the `pczt` crate exposes the field.
fn transparent_derivations(
    pczt: Pczt,
    signer: &SignerId,
) -> Result<(Pczt, Vec<Option<Bip44Path>>), TxError> {
    let coin = bip32::ChildNumber(signer.coin_type | bip32::ChildNumber::HARDENED_FLAG);
    let mut found = Vec::new();
    let verifier = Verifier::new(pczt)
        .with_transparent::<Infallible, _>(|bundle| {
            for input in bundle.inputs() {
                found.push(input.bip32_derivation().values().find_map(|d| {
                    d.extract_bip_44_fields(&signer.seed_fingerprint, coin)
                        .filter(|(account, _, _)| *account == signer.account)
                        .map(|(_, scope, index)| (scope, index))
                }));
            }
            Ok(())
        })
        .map_err(|e| TxError::InvalidArgument(format!("transparent bundle: {e:?}")))?;
    Ok((verifier.finish(), found))
}

/// Step 5: the Signer role. Orchard and Ironwood spends are signed with the
/// account's spend authorizing key (every action is tried; the ones that
/// are not ours or are dummies answer `WrongSpendAuthorizingKey` and are
/// skipped, as upstream does). Transparent inputs are
/// signed with the key their BIP 44 derivation names (upstream writes it on
/// every input of an HD account, which is how Gyges imports accounts), so
/// no wallet is needed and a `signer-only` profile signs them too; an input
/// without one falls back to the wallet's address index when `wallet` is
/// given. The Signer role checks each derived key against the input's
/// script, so a lying derivation is refused rather than signed.
pub fn sign(
    wallet: Option<&Wallet>,
    pczt: Pczt,
    usk: &UnifiedSpendingKey,
    signer: &SignerId,
) -> Result<Pczt, TxError> {
    use pczt::roles::signer::Error as SignErr;

    // Which key signs which transparent input, decided before the Signer
    // takes the PCZT.
    let mut transparent_keys = Vec::new();
    let pczt = if pczt.transparent().inputs().is_empty() {
        pczt
    } else {
        let scripts: Vec<_> = pczt
            .transparent()
            .inputs()
            .iter()
            .map(|i| i.script_pubkey().clone())
            .collect();
        let (pczt, derivations) = transparent_derivations(pczt, signer)?;
        let mut receivers = None;
        for (i, (script, derivation)) in scripts.iter().zip(derivations).enumerate() {
            let (scope, index) = match (derivation, wallet) {
                (Some(path), _) => path,
                (None, Some(wallet)) => {
                    if receivers.is_none() {
                        let account = account_of(wallet)?;
                        receivers = Some(
                            wallet
                                .get_transparent_receivers(account, true, true)
                                .map_err(|e| internal("listing transparent receivers", e))?,
                        );
                    }
                    wallet_path(receivers.as_ref().expect("set above"), script, i)?
                }
                (None, None) => {
                    return Err(TxError::InvalidArgument(format!(
                        "transparent input {i} carries no BIP 44 derivation for this key's seed and account; it cannot be signed here"
                    )));
                }
            };
            let sk = usk
                .transparent()
                .derive_secret_key(scope, index)
                .map_err(|e| TxError::Internal(format!("transparent key derivation: {e}")))?;
            transparent_keys.push((i, sk));
        }
        pczt
    };

    // The outputs are checked, and change that is not ours refused, before
    // anything is signed.
    let pczt = check_change(pczt, &Owner::of_usk(&signer.params, usk, wallet)?)?;

    let mut signer = Signer::new(pczt)
        .map_err(|e| TxError::Internal(format!("the PCZT cannot be signed: {e:?}")))?;
    let ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    for index in 0.. {
        match signer.sign_orchard(index, &ask) {
            Err(SignErr::InvalidIndex) => break,
            Ok(())
            | Err(SignErr::OrchardSign(orchard::pczt::SignerError::WrongSpendAuthorizingKey)) => {}
            Err(e) => return Err(TxError::Internal(format!("orchard signing failed: {e:?}"))),
        }
    }
    for index in 0.. {
        match signer.sign_ironwood(index, &ask) {
            Err(SignErr::InvalidIndex) => break,
            Ok(())
            | Err(SignErr::IronwoodSign(orchard::pczt::SignerError::WrongSpendAuthorizingKey)) => {}
            Err(e) => return Err(TxError::Internal(format!("ironwood signing failed: {e:?}"))),
        }
    }
    for (index, sk) in &transparent_keys {
        signer
            .sign_transparent(*index, sk)
            .map_err(|e| TxError::Internal(format!("transparent signing failed: {e:?}")))?;
    }
    Ok(signer.finish())
}

/// The derivation of the wallet address `script` pays, for an input without
/// a BIP 44 derivation of its own.
fn wallet_path(
    receivers: &std::collections::HashMap<
        transparent::address::TransparentAddress,
        zcash_client_backend::wallet::TransparentAddressMetadata,
    >,
    script: &[u8],
    i: usize,
) -> Result<Bip44Path, TxError> {
    let addr = gyges_chain::compact::address_of_script(script).ok_or_else(|| {
        TxError::Internal(format!("transparent input {i} has an unrecognised script"))
    })?;
    let meta = receivers.get(&addr).ok_or_else(|| {
        TxError::Internal(format!(
            "transparent input {i} pays an address this wallet does not own"
        ))
    })?;
    #[allow(unreachable_patterns)] // other sources exist behind upstream features
    match meta.source() {
        TransparentAddressSource::Derived {
            scope,
            address_index,
        } => Ok((*scope, *address_index)),
        _ => Err(TxError::Internal(format!(
            "transparent input {i} is at an address without a derivation path"
        ))),
    }
}

/// How far past index 0 a transparent change script is searched for in each
/// scope when no wallet is at hand (`pczt sign` on a `signer-only`
/// profile). Gyges' proposals send change to a shielded pool, so this only
/// bounds a case that does not arise from its own pipeline.
pub const TRANSPARENT_CHANGE_SEARCH: u32 = 1000;

/// What a key owns, for the change checks at sign and broadcast time
/// (THREAT_MODEL.md §6 item 8): the account's viewing keys and, when the
/// profile has a wallet, its transparent receivers (change included).
pub struct Owner {
    params: ConsensusParams,
    ufvk: zcash_keys::keys::UnifiedFullViewingKey,
    wallet_transparent: Option<std::collections::HashSet<transparent::address::TransparentAddress>>,
}

impl fmt::Debug for Owner {
    // The viewing key is not printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Owner").finish_non_exhaustive()
    }
}

impl Owner {
    /// From the spending key (the signer always has it) and the wallet,
    /// when the profile has one.
    pub fn of_usk(
        params: &ConsensusParams,
        usk: &UnifiedSpendingKey,
        wallet: Option<&Wallet>,
    ) -> Result<Self, TxError> {
        Ok(Self {
            params: *params,
            ufvk: usk.to_unified_full_viewing_key(),
            wallet_transparent: wallet.map(wallet_transparent).transpose()?,
        })
    }

    /// From the wallet alone (the broadcasting side, where the key is
    /// locked).
    pub fn of_wallet(params: &ConsensusParams, wallet: &Wallet) -> Result<Self, TxError> {
        use zcash_client_backend::data_api::Account as _;
        let id = account_of(wallet)?;
        let account = wallet
            .get_account(id)
            .map_err(|e| internal("reading the account", e))?
            .ok_or_else(|| TxError::Internal("the wallet has no account".into()))?;
        let ufvk = account
            .ufvk()
            .cloned()
            .ok_or_else(|| TxError::Internal("the account has no viewing key".into()))?;
        Ok(Self {
            params: *params,
            ufvk,
            wallet_transparent: Some(wallet_transparent(wallet)?),
        })
    }

    /// An Orchard-protocol address (Orchard or Ironwood bundle) of this
    /// account, in either scope.
    pub fn owns_orchard(&self, raw: &[u8; 43]) -> bool {
        let Some(fvk) = self.ufvk.orchard() else {
            return false;
        };
        Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(raw))
            .is_some_and(|a| fvk.scope_for_address(&a).is_some())
    }

    pub fn owns_sapling(&self, raw: &[u8; 43]) -> bool {
        let Some(dfvk) = self.ufvk.sapling() else {
            return false;
        };
        sapling::PaymentAddress::from_bytes(raw)
            .is_some_and(|a| dfvk.decrypt_diversifier(&a).is_some())
    }

    /// A transparent script paying this account: one of the wallet's
    /// receivers, or (without a wallet) a P2PKH address at an external or
    /// internal index below [`TRANSPARENT_CHANGE_SEARCH`].
    pub fn owns_script(&self, script: &[u8]) -> bool {
        let Some(addr) = gyges_chain::compact::address_of_script(script) else {
            return false;
        };
        if let Some(known) = &self.wallet_transparent {
            return known.contains(&addr);
        }
        let Some(tfvk) = self.ufvk.transparent() else {
            return false;
        };
        [TransparentKeyScope::EXTERNAL, TransparentKeyScope::INTERNAL]
            .into_iter()
            .any(|scope| {
                (0..TRANSPARENT_CHANGE_SEARCH).any(|i| {
                    NonHardenedChildIndex::from_index(i)
                        .and_then(|i| tfvk.derive_address_pubkey(scope, i).ok())
                        .is_some_and(|pk| {
                            transparent::address::TransparentAddress::from_pubkey(&pk) == addr
                        })
                })
            })
    }
}

fn wallet_transparent(
    wallet: &Wallet,
) -> Result<std::collections::HashSet<transparent::address::TransparentAddress>, TxError> {
    let account = account_of(wallet)?;
    Ok(wallet
        .get_transparent_receivers(account, true, true)
        .map_err(|e| internal("listing transparent receivers", e))?
        .into_keys()
        .collect())
}

/// Check what a PCZT says about its outputs before anything relies on it,
/// and refuse change this key does not own (THREAT_MODEL.md §6 item 8; the
/// upstream Signer role checks neither).
///
/// 1. Every Orchard, Ironwood and Sapling output's `recipient`, `value` and
///    `rseed` must produce its note commitment, and every action's and
///    Sapling output's value commitment must match its values. Nothing else
///    ties those fields to what the transaction pays: proving needs no
///    secret, so a file can commit to an attacker's note while naming the
///    signer's own address. A missing field fails closed.
/// 2. An output with a `user_address` (upstream sets one on every payment
///    to an external address; `inspect` shows it as the recipient) must pay
///    that address's receiver for its pool, so stolen change cannot be
///    relabelled as a payment.
/// 3. Every other non-zero output is change and must belong to `owner`.
pub fn check_change(pczt: Pczt, owner: &Owner) -> Result<Pczt, TxError> {
    let mut problem: Option<String> = None;
    let mut flag = |what: String| {
        problem.get_or_insert(what);
    };
    let label = |s: &str| Address::decode(&owner.params, s);
    let scripts: Vec<Vec<u8>> = pczt
        .transparent()
        .outputs()
        .iter()
        .map(|o| o.script_pubkey().clone())
        .collect();
    let verifier = Verifier::new(pczt)
        .with_transparent::<Infallible, _>(|bundle| {
            for (i, o) in bundle.outputs().iter().enumerate() {
                let script = scripts.get(i).map(Vec::as_slice).unwrap_or_default();
                match o.user_address() {
                    Some(s) => {
                        let pays = label(s)
                            .and_then(|a| a.to_transparent_address())
                            .map(|t| transparent::address::Script::from(t.script()).0.0.clone());
                        if pays.as_deref() != Some(script) {
                            flag(format!("transparent output {i}: its recipient address label does not match the script it pays"));
                        }
                    }
                    None if *o.value() > Zatoshis::ZERO && !owner.owns_script(script) => {
                        flag(format!("transparent output {i} is change (no recipient address) that does not belong to this key"));
                    }
                    None => {}
                }
            }
            Ok(())
        })
        .map_err(|e| TxError::InvalidArgument(format!("transparent bundle: {e:?}")))?;
    let mut actions = |pool: &str, bundle: &orchard::pczt::Bundle| {
        for (i, a) in bundle.actions().iter().enumerate() {
            let out = a.output();
            if let Err(e) = out.verify_note_commitment(a.spend()) {
                flag(format!(
                    "{pool} action {i}: the output does not match its note commitment ({e:?})"
                ));
                continue;
            }
            if let Err(e) = a.verify_cv_net() {
                flag(format!(
                    "{pool} action {i}: the values do not match the value commitment ({e:?})"
                ));
                continue;
            }
            let (Some(recipient), Some(value)) = (out.recipient(), out.value()) else {
                continue; // unreachable: the note commitment needs both
            };
            let raw = recipient.to_raw_address_bytes();
            match out.user_address() {
                Some(s) => {
                    let pays = label(s).and_then(|a| match a {
                        Address::Unified(ua) => ua.orchard().map(|o| o.to_raw_address_bytes()),
                        _ => None,
                    });
                    if pays != Some(raw) {
                        flag(format!(
                            "{pool} action {i}: its recipient address label does not match the note it pays"
                        ));
                    }
                }
                None if value.inner() > 0 && !owner.owns_orchard(&raw) => {
                    flag(format!(
                        "{pool} action {i} is change (no recipient address) that does not belong to this key"
                    ));
                }
                None => {}
            }
        }
    };
    let verifier = verifier
        .with_orchard::<Infallible, _>(|b| {
            actions("Orchard", b);
            Ok(())
        })
        .map_err(|e| TxError::InvalidArgument(format!("orchard bundle: {e:?}")))?
        .with_ironwood::<Infallible, _>(|b| {
            actions("Ironwood", b);
            Ok(())
        })
        .map_err(|e| TxError::InvalidArgument(format!("ironwood bundle: {e:?}")))?
        .with_sapling::<Infallible, _>(|bundle| {
            for (i, o) in bundle.outputs().iter().enumerate() {
                if let Err(e) = o.verify_note_commitment() {
                    flag(format!("Sapling output {i}: it does not match its note commitment ({e:?})"));
                    continue;
                }
                if let Err(e) = o.verify_cv() {
                    flag(format!("Sapling output {i}: its value does not match the value commitment ({e:?})"));
                    continue;
                }
                let (Some(recipient), Some(value)) = (o.recipient(), o.value()) else {
                    continue; // unreachable: the note commitment needs both
                };
                let raw = recipient.to_bytes();
                match o.user_address() {
                    Some(s) => {
                        let pays = label(s)
                            .and_then(|a| a.to_sapling_address())
                            .map(|a| a.to_bytes());
                        if pays != Some(raw) {
                            flag(format!("Sapling output {i}: its recipient address label does not match the note it pays"));
                        }
                    }
                    None if value.inner() > 0 && !owner.owns_sapling(&raw) => {
                        flag(format!("Sapling output {i} is change (no recipient address) that does not belong to this key"));
                    }
                    None => {}
                }
            }
            Ok(())
        })
        .map_err(|e| TxError::InvalidArgument(format!("sapling bundle: {e:?}")))?;
    match problem {
        Some(what) => Err(TxError::Verifier(format!(
            "verifier: {what}; refusing to sign or broadcast"
        ))),
        None => Ok(verifier.finish()),
    }
}

/// What the Verifier checks a signed PCZT against: the approved proposal,
/// reduced to the outputs a transaction must carry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Expected {
    /// `(scriptPubKey, value)` of every transparent payment and change.
    pub transparent_outputs: Vec<(Vec<u8>, u64)>,
    /// `(raw Orchard address, value)` of every Orchard-protocol payment,
    /// whether the proposal routes it through the Orchard or the Ironwood
    /// bundle (both pay the unified address's Orchard receiver).
    pub orchard_payments: Vec<([u8; 43], u64)>,
    /// Value of Orchard-protocol change, as a total (the change address is
    /// the wallet's internal one, which the PCZT carries but the proposal
    /// does not; [`verify`] checks each change output's owner instead).
    pub orchard_change: u64,
    /// `(raw Sapling address, value)` of every Sapling payment.
    pub sapling_payments: Vec<([u8; 43], u64)>,
    pub sapling_change: u64,
    pub fee: u64,
    /// `nExpiryHeight` must be in `[min_target, expiry]`.
    pub min_target_height: u32,
    pub expiry_height: u32,
}

/// `Expected` on disk (`ext_gyges_signing_sessions.expected`): the same
/// fields with the fixed-size arrays as byte vectors, since serde has no
/// 43-byte arrays.
#[derive(serde::Serialize, serde::Deserialize)]
struct ExpectedWire {
    transparent_outputs: Vec<(Vec<u8>, u64)>,
    orchard_payments: Vec<(Vec<u8>, u64)>,
    orchard_change: u64,
    sapling_payments: Vec<(Vec<u8>, u64)>,
    sapling_change: u64,
    fee: u64,
    min_target_height: u32,
    expiry_height: u32,
}

impl Expected {
    /// From a single-step proposal; `expiry` is what [`build_pczt`] was
    /// given (`None` for the default).
    pub fn from_proposal<N>(
        params: &ConsensusParams,
        proposal: &Proposal<StandardFeeRule, N>,
        expiry: Option<BlockHeight>,
    ) -> Result<Self, TxError> {
        let step = proposal.steps().first();
        let target = BlockHeight::from(proposal.min_target_height());
        let mut exp = Expected {
            fee: step.balance().fee_required().into_u64(),
            min_target_height: u32::from(target),
            expiry_height: u32::from(expiry.unwrap_or_else(|| default_expiry(params, target))),
            ..Default::default()
        };
        for (idx, payment) in step.transaction_request().payments() {
            let value = payment.amount().map_or(0, Zatoshis::into_u64);
            let encoded = payment.recipient_address().encode();
            let addr = Address::decode(params, &encoded)
                .ok_or_else(|| TxError::Internal("a proposed recipient does not decode".into()))?;
            let pool = step
                .payment_pools()
                .get(idx)
                .copied()
                .ok_or_else(|| TxError::Internal("a proposed payment has no pool".into()))?;
            match pool {
                PoolType::Transparent => {
                    let t = addr.to_transparent_address().ok_or_else(|| {
                        TxError::Internal("transparent payment to a shielded address".into())
                    })?;
                    exp.transparent_outputs.push((
                        transparent::address::Script::from(t.script()).0.0.clone(),
                        value,
                    ));
                }
                PoolType::Shielded(ShieldedPool::Orchard | ShieldedPool::Ironwood) => {
                    let Address::Unified(ua) = &addr else {
                        return Err(TxError::Internal(
                            "orchard payment to a non-unified address".into(),
                        ));
                    };
                    let o = ua.orchard().ok_or_else(|| {
                        TxError::Internal("orchard payment to an address without one".into())
                    })?;
                    exp.orchard_payments.push((o.to_raw_address_bytes(), value));
                }
                PoolType::Shielded(ShieldedPool::Sapling) => {
                    let s = addr.to_sapling_address().ok_or_else(|| {
                        TxError::Internal("sapling payment to an address without one".into())
                    })?;
                    exp.sapling_payments.push((s.to_bytes(), value));
                }
            }
        }
        for change in step.balance().proposed_change() {
            let value = change.value().into_u64();
            match change.output_pool() {
                PoolType::Transparent => {
                    // Transparent change goes to a wallet address the
                    // proposal does not name; checked by value below.
                    exp.transparent_outputs.push((Vec::new(), value));
                }
                PoolType::Shielded(ShieldedPool::Orchard | ShieldedPool::Ironwood) => {
                    exp.orchard_change += value;
                }
                PoolType::Shielded(ShieldedPool::Sapling) => exp.sapling_change += value,
            }
        }
        Ok(exp)
    }

    /// For the signing sessions table.
    pub fn to_json(&self) -> Vec<u8> {
        let wire = ExpectedWire {
            transparent_outputs: self.transparent_outputs.clone(),
            orchard_payments: self
                .orchard_payments
                .iter()
                .map(|(a, v)| (a.to_vec(), *v))
                .collect(),
            orchard_change: self.orchard_change,
            sapling_payments: self
                .sapling_payments
                .iter()
                .map(|(a, v)| (a.to_vec(), *v))
                .collect(),
            sapling_change: self.sapling_change,
            fee: self.fee,
            min_target_height: self.min_target_height,
            expiry_height: self.expiry_height,
        };
        serde_json::to_vec(&wire).expect("plain data serialises")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, TxError> {
        let wire: ExpectedWire = serde_json::from_slice(bytes)
            .map_err(|e| TxError::Internal(format!("stored proposal is unreadable: {e}")))?;
        let arr = |v: Vec<u8>| -> Result<[u8; 43], TxError> {
            <[u8; 43]>::try_from(v)
                .map_err(|_| TxError::Internal("stored proposal has a malformed address".into()))
        };
        Ok(Expected {
            transparent_outputs: wire.transparent_outputs,
            orchard_payments: wire
                .orchard_payments
                .into_iter()
                .map(|(a, v)| Ok((arr(a)?, v)))
                .collect::<Result<_, TxError>>()?,
            orchard_change: wire.orchard_change,
            sapling_payments: wire
                .sapling_payments
                .into_iter()
                .map(|(a, v)| Ok((arr(a)?, v)))
                .collect::<Result<_, TxError>>()?,
            sapling_change: wire.sapling_change,
            fee: wire.fee,
            min_target_height: wire.min_target_height,
            expiry_height: wire.expiry_height,
        })
    }
}

/// Step 6: the Verifier role (Q-K7). Every transparent output, every
/// Orchard-protocol (Orchard or Ironwood bundle) and Sapling payment
/// (recipient and value), the change totals, the fee (inputs minus
/// outputs) and the expiry must match `expected`, and every change output
/// must belong to `owner` (THREAT_MODEL.md §6 item 8); otherwise the PCZT
/// is refused and nothing is broadcast.
pub fn verify(pczt: Pczt, expected: &Expected, owner: &Owner) -> Result<Pczt, TxError> {
    // The output fields are authenticated (note and value commitments,
    // address labels) before the matching below relies on them.
    let pczt = check_change(pczt, owner)?;
    let mismatch = |what: &str| {
        TxError::Verifier(format!(
            "verifier: {what} differs from the approved proposal"
        ))
    };

    let expiry = *pczt.global().expiry_height();
    if expiry < expected.min_target_height || expiry > expected.expiry_height {
        return Err(mismatch("the expiry height"));
    }

    // Transparent: exact multiset of (script, value), with change matched
    // by value against a remaining output whose script is this key's.
    let mut want: Vec<(Vec<u8>, u64)> = expected.transparent_outputs.clone();
    let mut have: Vec<(Vec<u8>, u64)> = pczt
        .transparent()
        .outputs()
        .iter()
        .map(|o| (o.script_pubkey().clone(), *o.value()))
        .collect();
    for (script, value) in want.iter().filter(|(s, _)| !s.is_empty()) {
        match have.iter().position(|(s, v)| s == script && v == value) {
            Some(i) => {
                have.remove(i);
            }
            None => return Err(mismatch("a transparent output")),
        }
    }
    want.retain(|(s, _)| s.is_empty());
    for (_, value) in &want {
        match have
            .iter()
            .position(|(s, v)| v == value && owner.owns_script(s))
        {
            Some(i) => {
                have.remove(i);
            }
            None => return Err(mismatch("transparent change")),
        }
    }
    if !have.is_empty() {
        return Err(mismatch("an extra transparent output"));
    }
    let transparent_in: u64 = pczt.transparent().inputs().iter().map(|i| *i.value()).sum();
    let transparent_out: u64 = pczt
        .transparent()
        .outputs()
        .iter()
        .map(|o| *o.value())
        .sum();

    // Sapling: payments by recipient and value; change by total.
    let mut sapling_payments = expected.sapling_payments.clone();
    let mut sapling_change = 0u64;
    let mut sapling_out = 0u64;
    for out in pczt.sapling().outputs() {
        let value = out.value().unwrap_or(0);
        sapling_out += value;
        if value == 0 {
            continue;
        }
        match out.recipient().and_then(|r| {
            sapling_payments
                .iter()
                .position(|(a, v)| *a == r && *v == value)
        }) {
            Some(i) => {
                sapling_payments.remove(i);
            }
            None if out.recipient().is_some_and(|r| owner.owns_sapling(&r)) => {
                sapling_change += value
            }
            None => return Err(mismatch("a Sapling change output (not this key's)")),
        }
    }
    if !sapling_payments.is_empty() || sapling_change != expected.sapling_change {
        return Err(mismatch("a Sapling output"));
    }
    // Sapling spends are refused before proving (Q-K3), so none can be
    // here; if one is, the PCZT did not come from this pipeline.
    if !pczt.sapling().spends().is_empty() {
        return Err(mismatch("a Sapling spend (none was proposed)"));
    }
    let sapling_in: u64 = 0;

    // Orchard and Ironwood, through the parsed bundles the Verifier role
    // exposes; both carry Orchard-protocol actions.
    let mut orchard_payments = expected.orchard_payments.clone();
    let mut orchard_change = 0u64;
    let mut foreign_change = false;
    let mut orchard_in = 0u64;
    let mut orchard_out = 0u64;
    let mut check_actions = |bundle: &orchard::pczt::Bundle| {
        for action in bundle.actions() {
            orchard_in += action.spend().value().map_or(0, |v| v.inner());
            let value = action.output().value().map_or(0, |v| v.inner());
            orchard_out += value;
            if value == 0 {
                continue;
            }
            let recipient = action
                .output()
                .recipient()
                .map(|r| r.to_raw_address_bytes());
            match recipient.and_then(|r| {
                orchard_payments
                    .iter()
                    .position(|(a, v)| *a == r && *v == value)
            }) {
                Some(i) => {
                    orchard_payments.remove(i);
                }
                None if recipient.is_some_and(|r| owner.owns_orchard(&r)) => {
                    orchard_change += value
                }
                None => foreign_change = true,
            }
        }
    };
    let verifier = Verifier::new(pczt)
        .with_orchard::<String, _>(|bundle| {
            check_actions(bundle);
            Ok(())
        })
        .map_err(|e| TxError::Internal(format!("verifier: orchard bundle: {e:?}")))?
        .with_ironwood::<String, _>(|bundle| {
            check_actions(bundle);
            Ok(())
        })
        .map_err(|e| TxError::Internal(format!("verifier: ironwood bundle: {e:?}")))?;
    if foreign_change {
        return Err(mismatch("an Orchard change output (not this key's)"));
    }
    if !orchard_payments.is_empty() || orchard_change != expected.orchard_change {
        return Err(mismatch("an Orchard output"));
    }

    let fee = (transparent_in + sapling_in + orchard_in)
        .checked_sub(transparent_out + sapling_out + orchard_out)
        .ok_or_else(|| mismatch("the balance (outputs exceed inputs)"))?;
    if fee != expected.fee {
        return Err(mismatch("the fee"));
    }
    Ok(verifier.finish())
}

/// Step 7: Spend Finalizer, Transaction Extractor (proofs verified with the
/// keys in `provers`), and the wallet's own record of the transaction.
/// Returns the txid and the bytes for `sendrawtransaction`.
pub fn extract_and_store(
    wallet: &mut Wallet,
    pczt: Pczt,
    provers: &Provers,
) -> Result<(TxId, Vec<u8>), TxError> {
    let needs_sapling = !pczt.sapling().spends().is_empty() || !pczt.sapling().outputs().is_empty();
    let sapling_vks = needs_sapling.then(|| provers.sapling().verifying_keys());
    let (_, orchard_vk) = provers.orchard();
    let txid = extract_and_store_transaction_from_pczt::<_, Infallible>(
        wallet,
        pczt,
        sapling_vks.as_ref().map(|(s, o)| (s, o)),
        Some(orchard_vk),
    )
    .map_err(|e| TxError::Internal(format!("extracting the transaction failed: {e}")))?;
    let (_, raw) = stored_transaction(wallet, txid)?;
    Ok((txid, raw))
}

// ---------------------------------------------------------------------------
// ZIP 320 (ARCHITECTURE.md §3.3)
// ---------------------------------------------------------------------------

/// Whether a proposal is the two-step shape a `tex1` recipient produces.
pub fn is_two_step<N>(proposal: &Proposal<StandardFeeRule, N>) -> bool {
    proposal.steps().len() == 2
}

/// Both transactions of a ZIP 320 transfer, signed, as the queue stores
/// them (`gyges_core::tex::TexRow` minus the bookkeeping).
#[derive(Clone, Debug)]
pub struct TexBuilt {
    pub step1_txid: TxId,
    pub step1_raw: Vec<u8>,
    pub step2_txid: TxId,
    pub step2_raw: Vec<u8>,
    /// The ephemeral `t1…` step 1 pays, as the wallet encodes it.
    pub ephemeral_addr: String,
    /// The `tex1…` recipient, as the wallet encodes it.
    pub recipient: String,
    /// Step 2's single output, in zatoshis.
    pub amount: u64,
    pub expiry_height: u32,
}

/// The raw bytes and the parsed form of a transaction the wallet stored.
fn stored_transaction(
    wallet: &Wallet,
    txid: TxId,
) -> Result<(zcash_primitives::transaction::Transaction, Vec<u8>), TxError> {
    let tx = wallet
        .get_transaction(txid)
        .map_err(|e| internal("reading the stored transaction", e))?
        .ok_or_else(|| TxError::Internal("a created transaction was not stored".into()))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| internal("serialising the transaction", e))?;
    Ok((tx, raw))
}

/// Build, prove, sign and store both steps of a two-step proposal with
/// `create_proposed_transactions` (the upstream PCZT path takes
/// single-step proposals only, so for ZIP 320 the roles run inside the
/// builder with the key present: `SignatureRequired` precedes `Proving`
/// for these sends, API.md §9). Both steps share `expiry_height`.
pub fn create_tex_transactions(
    wallet: &mut Wallet,
    params: &ConsensusParams,
    account: AccountUuid,
    proposal: &SendProposal,
    usk: UnifiedSpendingKey,
    provers: &Provers,
) -> Result<TexBuilt, TxError> {
    if !is_two_step(proposal) {
        return Err(TxError::Internal(format!(
            "expected a two-step proposal, got {} step(s)",
            proposal.steps().len()
        )));
    }
    let target = BlockHeight::from(proposal.min_target_height());
    let expiry = default_expiry(params, target);
    let txids = run_create_proposed(wallet, params, usk, provers, proposal, expiry)?;
    let (step1_txid, step2_txid) = match txids.as_slice() {
        [a, b] => (*a, *b),
        other => {
            return Err(TxError::Internal(format!(
                "the builder returned {} transaction(s) for two steps",
                other.len()
            )));
        }
    };
    let (step1, step1_raw) = stored_transaction(wallet, step1_txid)?;
    let (_, step2_raw) = stored_transaction(wallet, step2_txid)?;

    // The ephemeral address is chosen at build time; it is the step-1
    // output whose address the wallet knows under the ephemeral key scope.
    let mut ephemeral = None;
    for out in step1
        .transparent_bundle()
        .into_iter()
        .flat_map(|b| b.vout.iter())
    {
        let Some(addr) = out.recipient_address() else {
            continue;
        };
        let meta = wallet
            .get_transparent_address_metadata(account, &addr)
            .map_err(|e| internal("reading address metadata", e))?;
        if meta.and_then(|m| m.scope()) == Some(transparent::keys::TransparentKeyScope::EPHEMERAL) {
            ephemeral = Some(addr);
            break;
        }
    }
    let ephemeral = ephemeral.ok_or_else(|| {
        TxError::Internal("step 1 has no output at a known ephemeral address".into())
    })?;
    let step2 = &proposal.steps()[1];
    let (recipient, amount) = step2
        .transaction_request()
        .payments()
        .values()
        .next()
        .map(|p| {
            (
                p.recipient_address().encode(),
                p.amount().map_or(0, Zatoshis::into_u64),
            )
        })
        .ok_or_else(|| TxError::Internal("step 2 has no payment".into()))?;
    Ok(TexBuilt {
        step1_txid,
        step1_raw,
        step2_txid,
        step2_raw,
        ephemeral_addr: gyges_chain::compact::encode_transparent_address(
            params.network_type(),
            &ephemeral,
        ),
        recipient,
        amount,
        expiry_height: u32::from(expiry),
    })
}

fn run_create_proposed<N: fmt::Display>(
    wallet: &mut Wallet,
    params: &ConsensusParams,
    usk: UnifiedSpendingKey,
    provers: &Provers,
    proposal: &Proposal<StandardFeeRule, N>,
    expiry: BlockHeight,
) -> Result<Vec<TxId>, TxError> {
    let keys = SpendingKeys::from_unified_spending_key(usk);
    // The Sapling prover is only consulted for Sapling spends or outputs,
    // of which a ZIP 320 transfer from an Orchard/Ironwood wallet has none;
    // the builder still wants one, and the bundled parameters load once per
    // daemon.
    let sapling = provers.sapling();
    let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, N>(
        wallet,
        params,
        sapling,
        sapling,
        &keys,
        OvkPolicy::Sender,
        proposal,
        Some(expiry),
    )
    .map_err(|e| wallet_api_error(e, "no anchor available", "building the transactions"))?;
    Ok(txids.into_iter().collect())
}

/// `tx resume` after step 1 was mined and step 2 expired (ARCHITECTURE.md
/// §3.3, TESTING.md §3 row 11): a fresh single transparent transaction
/// spending the ephemeral output of `step1_txid` to the recipient for
/// `amount`, paying whatever the ephemeral output holds above it as the
/// fee (step 2's ZIP 317 fee was fixed at proposal time). Returns the new
/// txid, its bytes and its expiry.
///
/// The wallet treats an ephemeral output as spent until it is told
/// otherwise (ZIP 320 wallets must not reuse one): `verified_unspent_at`
/// is the chain height through which the caller confirmed with the node
/// that nothing spent it, which must be past the old step 2's expiry.
#[allow(clippy::too_many_arguments)]
pub fn build_tex_step2(
    wallet: &mut Wallet,
    params: &ConsensusParams,
    usk: UnifiedSpendingKey,
    provers: &Provers,
    step1_txid: [u8; 32],
    ephemeral_addr: &str,
    recipient: &str,
    amount: u64,
    min_confirmations: u32,
    verified_unspent_at: BlockHeight,
) -> Result<(TxId, Vec<u8>, u32), TxError> {
    use std::collections::BTreeMap;
    use transparent::bundle::OutPoint;
    use zcash_client_backend::data_api::WalletWrite as _;
    use zcash_client_backend::fees::TransactionBalance;

    let ephemeral = Address::decode(params, ephemeral_addr)
        .and_then(|a| a.to_transparent_address())
        .ok_or_else(|| TxError::Internal("the stored ephemeral address does not decode".into()))?;
    let recipient_addr = parse_recipient(params, recipient)?;
    if !matches!(recipient_addr, Address::Tex(_)) {
        return Err(TxError::Internal(
            "the stored recipient is not a ZIP 320 address".into(),
        ));
    }
    let (step1, _) = stored_transaction(wallet, TxId::from_bytes(step1_txid))?;
    let index = step1
        .transparent_bundle()
        .into_iter()
        .flat_map(|b| b.vout.iter().enumerate())
        .find(|(_, o)| o.recipient_address() == Some(ephemeral))
        .map(|(i, _)| i as u32)
        .ok_or_else(|| TxError::Internal("step 1 has no output at the ephemeral address".into()))?;
    let outpoint = OutPoint::new(step1_txid, index);
    let policy = confirmations_policy(min_confirmations);
    let (target, anchor) = wallet
        .get_target_and_anchor_heights(
            std::num::NonZeroU32::new(min_confirmations.max(1)).expect("non-zero"),
        )
        .map_err(|e| internal("target height", e))?
        .ok_or_else(|| TxError::NotSynced("no scanned blocks to build on".into()))?;
    // Spendable at the target height: step 1 mined, and the expired step 2
    // no longer counts as a pending spend of it (which the wallet accepts
    // only once the output was seen unspent past that expiry).
    wallet
        .notify_output_verified_unspent(outpoint.clone(), verified_unspent_at)
        .map_err(|e| internal("recording the unspent ephemeral output", e))?;
    let utxo = wallet
        .get_unspent_transparent_output(&outpoint, target)
        .map_err(|e| internal("reading the ephemeral output", e))?
        .ok_or_else(|| {
            TxError::Internal(
                "the ephemeral output is not spendable yet (step 1 unmined, or step 2 not expired)"
                    .into(),
            )
        })?;
    let value = utxo.txout().value();
    let amount = Zatoshis::from_u64(amount).map_err(|e| internal("amount", e))?;
    let fee = (value - amount).ok_or_else(|| TxError::InsufficientFunds {
        available: value.into_u64(),
        required: amount.into_u64(),
    })?;
    let input = WalletTransparentOutput::<()>::from_parts(
        outpoint,
        utxo.txout().clone(),
        utxo.mined_height(),
        None,
        None,
        None,
    )
    .ok_or_else(|| TxError::Internal("the ephemeral output has no recognised script".into()))?;

    let request = single_payment(recipient_addr.to_zcash_address(params), amount, None)?;
    let balance = TransactionBalance::new(Vec::new(), fee)
        .map_err(|e| TxError::Internal(format!("balance: {e:?}")))?;
    let ironwood_active = params.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from(target));
    let proposal: Proposal<StandardFeeRule, Infallible> = Proposal::single_step(
        request,
        BTreeMap::from([(0usize, PoolType::Transparent)]),
        vec![input],
        None,
        anchor,
        balance,
        StandardFeeRule::Zip317,
        target,
        policy,
        false,
        ironwood_active,
    )
    .map_err(|e| TxError::Internal(format!("step 2 proposal: {e:?}")))?;
    let expiry = default_expiry(params, BlockHeight::from(target));
    let txids = run_create_proposed(wallet, params, usk, provers, &proposal, expiry)?;
    let txid = *txids
        .first()
        .ok_or_else(|| TxError::Internal("no transaction built".into()))?;
    let (_, raw) = stored_transaction(wallet, txid)?;
    Ok((txid, raw, u32::from(expiry)))
}

/// One pool's balance (`PoolBalance` on the wire).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolBalance {
    pub pool: Pool,
    pub spendable: u64,
    /// Received but not yet spendable (below `min_confirmations`, unmined
    /// or awaiting a witness).
    pub pending: u64,
}

/// `GetBalance` (API.md): per pool, at `min_confirmations`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BalanceSummary {
    pub pools: Vec<PoolBalance>,
    pub total_spendable: u64,
    pub total_pending: u64,
    pub min_confirmations: u32,
    /// The wallet's chain tip, 0 before the first scan.
    pub as_of_height: u32,
}

/// `get_wallet_summary` reduced to what `balance` prints.
pub fn balance(wallet: &Wallet, min_confirmations: u32) -> Result<BalanceSummary, TxError> {
    let min_confirmations = min_confirmations.max(1);
    let Some(summary) = wallet
        .get_wallet_summary(confirmations_policy(min_confirmations))
        .map_err(|e| internal("wallet summary", e))?
    else {
        return Ok(BalanceSummary {
            min_confirmations,
            ..Default::default()
        });
    };
    // Indexed below in this order.
    let mut pools: Vec<PoolBalance> = [
        Pool::Orchard,
        Pool::Ironwood,
        Pool::Sapling,
        Pool::Transparent,
    ]
    .into_iter()
    .map(|pool| PoolBalance {
        pool,
        ..Default::default()
    })
    .collect();
    for account in summary.account_balances().values() {
        let add = |p: &mut PoolBalance, b: &zcash_client_backend::data_api::Balance| {
            p.spendable += b.spendable_value().into_u64();
            p.pending += b.value_pending_spendability().into_u64()
                + b.change_pending_confirmation().into_u64();
        };
        add(&mut pools[0], account.orchard_balance());
        add(&mut pools[1], account.ironwood_balance());
        add(&mut pools[2], account.sapling_balance());
        add(&mut pools[3], &account.unshielded_balance());
    }
    Ok(BalanceSummary {
        total_spendable: pools.iter().map(|p| p.spendable).sum(),
        total_pending: pools.iter().map(|p| p.pending).sum(),
        pools,
        min_confirmations,
        as_of_height: u32::from(summary.chain_tip_height()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;

    fn params() -> ConsensusParams {
        Network::Regtest.consensus_params()
    }

    #[test]
    fn recipients_parse_per_network_including_tex() {
        let p = params();
        // A regtest transparent address and a mainnet one.
        let t = Address::Transparent(transparent::address::TransparentAddress::PublicKeyHash(
            [7; 20],
        ))
        .encode(&p);
        assert!(matches!(
            parse_recipient(&p, &t),
            Ok(Address::Transparent(_))
        ));
        let mainnet = "t1cVDkFrBSqLFDuNq2VpQTMzSj5A6aNfqQe";
        assert!(matches!(
            parse_recipient(&p, mainnet),
            Err(TxError::InvalidArgument(_))
        ));
        let tex = Address::Tex([9; 20]).encode(&p);
        assert!(matches!(parse_recipient(&p, &tex), Ok(Address::Tex(_))));
        assert!(memo_for(&Address::Tex([9; 20]), b"hi").is_err());
        assert!(matches!(
            parse_recipient(&p, "nonsense"),
            Err(TxError::InvalidArgument(_))
        ));
    }

    #[test]
    fn memos_need_a_shielded_recipient_and_fit() {
        let t = Address::Transparent(transparent::address::TransparentAddress::PublicKeyHash(
            [7; 20],
        ));
        assert!(memo_for(&t, b"").unwrap().is_none());
        let err = memo_for(&t, b"hi").unwrap_err();
        assert!(err.to_string().contains("shielded recipient"), "{err}");
        let err = memo_for(&t, &[0u8; MAX_MEMO_BYTES + 1]).unwrap_err();
        assert!(err.to_string().contains("at most"), "{err}");
    }

    #[test]
    fn default_expiry_is_forty_blocks_before_nu7() {
        let p = params();
        assert_eq!(
            default_expiry(&p, BlockHeight::from_u32(100)),
            BlockHeight::from_u32(140)
        );
    }

    #[test]
    fn confirmations_policy_never_goes_below_one() {
        let _ = confirmations_policy(0);
        let _ = confirmations_policy(10);
    }
}
