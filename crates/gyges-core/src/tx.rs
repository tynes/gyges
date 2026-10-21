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
use zcash_client_backend::data_api::error::Error as WalletApiError;
use zcash_client_backend::data_api::wallet::input_selection::{
    CoinbasePolicy, GreedyInputSelector, SpendPolicy, TransparentSpendPolicy,
};
use zcash_client_backend::data_api::wallet::{
    ConfirmationsPolicy, create_pczt_from_proposal, extract_and_store_transaction_from_pczt,
    propose_shielding, propose_transfer,
};
use zcash_client_backend::data_api::{CoinbaseFilter, WalletRead as _};
use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
use zcash_client_backend::fees::{DustOutputPolicy, StandardFeeRule};
use zcash_client_backend::proposal::{Proposal, Step};
use zcash_client_backend::wallet::{Note, OvkPolicy, TransparentAddressSource};
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
    /// `INTERNAL`: the wallet or the PCZT pipeline failed.
    #[error("{0}")]
    Internal(String),
}

fn internal(context: &str, e: impl fmt::Display) -> TxError {
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

/// Parse a recipient for the network. TEX addresses parse but are refused
/// until the ZIP 320 queue exists (ROADMAP.md M3).
pub fn parse_recipient(params: &ConsensusParams, s: &str) -> Result<Address, TxError> {
    let s = s.trim();
    let addr = Address::decode(params, s).ok_or_else(|| {
        TxError::InvalidArgument(
            "the recipient is not a valid address for this network".to_string(),
        )
    })?;
    if matches!(addr, Address::Tex(_)) {
        return Err(TxError::UnsupportedPool(
            "ZIP 320 (tex1) recipients arrive with the TexQueue (ROADMAP.md M3)".to_string(),
        ));
    }
    Ok(addr)
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

/// Map an upstream proposal error to ours. The upstream type is generic over
/// six error parameters, so only its shape is matched.
fn propose_error<D, C, S, F, Ch, N>(e: WalletApiError<D, C, S, F, Ch, N>) -> TxError
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
        WalletApiError::ScanRequired => {
            TxError::NotSynced("no scanned blocks to anchor the transaction on".into())
        }
        other => TxError::Internal(format!("proposal failed: {other}")),
    }
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
        let payment = Payment::new(
            recipient.clone(),
            Some(amount),
            memo.clone(),
            None,
            None,
            vec![],
        )
        .map_err(|e| TxError::InvalidArgument(format!("invalid payment: {e}")))?;
        let request = TransactionRequest::new(vec![payment])
            .map_err(|e| TxError::InvalidArgument(format!("invalid payment request: {e}")))?;
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
        .map_err(propose_error)
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
            let mut amount = spendable_total(wallet, spend_pools, min_confirmations)?;
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
                        let short = required - available;
                        amount = Zatoshis::from_u64(amount.into_u64().saturating_sub(short))
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
    .map_err(propose_error)
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

fn summarize_step<N>(params: &ConsensusParams, step: &Step<N>) -> StepSummary {
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
    let _ = params;
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
        .map(|s| summarize_step(params, s))
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
/// PCZT, which is every proposal until ZIP 320.
pub fn build_pczt<N: fmt::Display>(
    wallet: &mut Wallet,
    params: &ConsensusParams,
    account: AccountUuid,
    proposal: &Proposal<StandardFeeRule, N>,
) -> Result<Pczt, TxError> {
    create_pczt_from_proposal::<_, _, Infallible, _, Infallible, N>(
        wallet,
        params,
        account,
        OvkPolicy::Sender,
        proposal,
        None,
        BundlePadding {
            bundle_required: false,
            pad_to_minimum: None,
        },
    )
    .map_err(|e| match e {
        WalletApiError::InsufficientFunds {
            available,
            required,
        } => TxError::InsufficientFunds {
            available: available.into_u64(),
            required: required.into_u64(),
        },
        WalletApiError::ScanRequired => TxError::NotSynced("no anchor available".into()),
        other => TxError::Internal(format!("building the PCZT failed: {other}")),
    })
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

/// Step 5: the Signer role. Orchard and Ironwood spends are signed with the
/// account's spend authorizing key (every action is tried; the ones that
/// are not ours or are dummies answer `WrongSpendAuthorizingKey` and are
/// skipped, as upstream does). Transparent inputs are matched to the
/// wallet's receivers by `scriptPubKey` and signed with the key at that
/// receiver's BIP 44 path.
pub fn sign(wallet: &Wallet, pczt: Pczt, usk: &UnifiedSpendingKey) -> Result<Pczt, TxError> {
    use pczt::roles::signer::Error as SignErr;

    // Which key signs which transparent input, decided before the Signer
    // takes the PCZT.
    let mut transparent_keys = Vec::new();
    if !pczt.transparent().inputs().is_empty() {
        let account = account_of(wallet)?;
        let receivers = wallet
            .get_transparent_receivers(account, true, true)
            .map_err(|e| internal("listing transparent receivers", e))?;
        for (i, input) in pczt.transparent().inputs().iter().enumerate() {
            let addr = gyges_chain::compact::address_of_script(input.script_pubkey()).ok_or_else(
                || TxError::Internal(format!("transparent input {i} has an unrecognised script")),
            )?;
            let meta = receivers.get(&addr).ok_or_else(|| {
                TxError::Internal(format!(
                    "transparent input {i} pays an address this wallet does not own"
                ))
            })?;
            #[allow(unreachable_patterns)] // other sources exist behind upstream features
            let (scope, index) = match meta.source() {
                TransparentAddressSource::Derived {
                    scope,
                    address_index,
                } => (*scope, *address_index),
                _ => {
                    return Err(TxError::Internal(format!(
                        "transparent input {i} is at an address without a derivation path"
                    )));
                }
            };
            let sk = usk
                .transparent()
                .derive_secret_key(scope, index)
                .map_err(|e| TxError::Internal(format!("transparent key derivation: {e}")))?;
            transparent_keys.push((i, sk));
        }
    }

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
    /// does not).
    pub orchard_change: u64,
    /// `(raw Sapling address, value)` of every Sapling payment.
    pub sapling_payments: Vec<([u8; 43], u64)>,
    pub sapling_change: u64,
    pub fee: u64,
    /// `nExpiryHeight` must be in `[min_target, expiry]`.
    pub min_target_height: u32,
    pub expiry_height: u32,
}

impl Expected {
    /// From a single-step proposal.
    pub fn from_proposal<N>(
        params: &ConsensusParams,
        proposal: &Proposal<StandardFeeRule, N>,
    ) -> Result<Self, TxError> {
        let step = proposal.steps().first();
        let mut exp = Expected {
            fee: step.balance().fee_required().into_u64(),
            min_target_height: u32::from(BlockHeight::from(proposal.min_target_height())),
            expiry_height: u32::from(default_expiry(
                params,
                BlockHeight::from(proposal.min_target_height()),
            )),
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
}

/// Step 6: the Verifier role (Q-K7). Every transparent output, every
/// Orchard-protocol (Orchard or Ironwood bundle) and Sapling payment
/// (recipient and value), the change totals, the fee (inputs minus
/// outputs) and the expiry must match `expected`; otherwise the PCZT is
/// refused and nothing is broadcast.
pub fn verify(pczt: Pczt, expected: &Expected) -> Result<Pczt, TxError> {
    let mismatch = |what: &str| {
        TxError::Internal(format!(
            "verifier: {what} differs from the approved proposal"
        ))
    };

    let expiry = *pczt.global().expiry_height();
    if expiry < expected.min_target_height || expiry > expected.expiry_height {
        return Err(mismatch("the expiry height"));
    }

    // Transparent: exact multiset of (script, value), with change matched
    // by value against any remaining output.
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
        match have.iter().position(|(_, v)| v == value) {
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
            None => sapling_change += value,
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
                None => orchard_change += value,
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
    let tx = wallet
        .get_transaction(txid)
        .map_err(|e| internal("reading the stored transaction", e))?
        .ok_or_else(|| TxError::Internal("the extracted transaction was not stored".into()))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| internal("serialising the transaction", e))?;
    Ok((txid, raw))
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
    let mut pools = vec![
        PoolBalance {
            pool: Pool::Orchard,
            ..Default::default()
        },
        PoolBalance {
            pool: Pool::Ironwood,
            ..Default::default()
        },
        PoolBalance {
            pool: Pool::Sapling,
            ..Default::default()
        },
        PoolBalance {
            pool: Pool::Transparent,
            ..Default::default()
        },
    ];
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
    fn recipients_parse_per_network_and_tex_is_refused() {
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
        assert!(matches!(
            parse_recipient(&p, &tex),
            Err(TxError::UnsupportedPool(_))
        ));
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
