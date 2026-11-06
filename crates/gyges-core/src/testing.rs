//! Deterministic synthetic chains and an in-memory node for the benchmarks
//! (docs/testing.md §9) and tests of the code above `ChainBackend`.
//!
//! [`SyntheticChain::generate`] builds compact blocks of Ironwood actions and
//! transparent outputs from a [`ChainSpec`] and a seed: the same spec gives
//! the same bytes ([`SyntheticChain::digest`]) on every run. Payments to the
//! [`Recipient`]s are real notes (a valid commitment and encryption), so a
//! wallet holding the matching key finds them by trial decryption and can
//! later spend them; the rest of each block pays strangers, so trial
//! decryption fails on most actions, as it does on a real chain. The
//! Ironwood frontier is carried through every block, so [`SyntheticChain::state`]
//! gives the correct prior [`ChainState`] for a scan from any height.
//!
//! [`MemChain`] serves a chain through [`ChainBackend`], with an optional
//! fixed delay per request to stand in for the node round trip, and no
//! HTTP, JSON or raw-block parsing.

use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use age::secrecy::SecretString;
use gyges_chain::{BoxFuture, ChainBackend, ChainError, NodeBounds, NodeStatus, Source, TxStatus};
use incrementalmerkletree::frontier::Frontier;
use orchard::builder::{BundleType, UnauthorizedBundle};
use orchard::bundle::BundleVersion;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::tree::{Anchor, MerkleHashOrchard};
use orchard::value::NoteValue;
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use transparent::address::TransparentAddress;
use transparent::keys::IncomingViewingKey as _;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::proto::compact_formats::{
    ChainMetadata, CompactBlock, CompactOrchardAction, CompactTx, TxOut,
};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_primitives::block::BlockHash;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;

use crate::birthday::ResolvedBirthday;
use crate::network::Network;
use crate::registry::{KeyEntry, KeyRegistry, NewLocalSeedKey};
use crate::vault::{self, Entropy};
use crate::{Config, Home};

/// Value of every shielded payment to a recipient, in zatoshis.
pub const NOTE_VALUE: u64 = 100_000;
/// Value of every transparent payment to a recipient, in zatoshis.
pub const TRANSPARENT_VALUE: u64 = 50_000;
/// Distinct stranger bundles generated per chain; background transactions
/// cycle through them. Trial decryption costs the same on a repeated
/// action, and generating every one fresh would dominate fixture setup.
const NOISE_POOL: usize = 64;

/// The shape of a synthetic chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSpec {
    /// Blocks `1..=blocks` (block 0 is an empty genesis).
    pub blocks: u32,
    /// Two-action transactions paying strangers in every block.
    pub noise_txs: usize,
    /// Transparent outputs paying strangers in every block (one transaction).
    pub noise_transparent: usize,
    /// Every `wallet_every`-th block holds one two-action transaction paying
    /// each recipient twice. 0: never.
    pub wallet_every: u32,
    /// Every `transparent_every`-th block holds one transparent output to
    /// each recipient's first external address. 0: never.
    pub transparent_every: u32,
    pub seed: u64,
}

impl ChainSpec {
    /// The current `scan-range` bench's chain: 10 blocks of 50 two-action
    /// transactions (1,000 actions), the first paying the wallet.
    pub const fn dense() -> Self {
        Self {
            blocks: 10,
            noise_txs: 49,
            noise_transparent: 0,
            wallet_every: 1,
            transparent_every: 0,
            seed: 1,
        }
    }

    /// A quiet chain: two shielded and one transparent stranger transaction
    /// a block, a payment every 50 blocks and a transparent output every 100.
    pub const fn sparse(blocks: u32) -> Self {
        Self {
            blocks,
            noise_txs: 2,
            noise_transparent: 2,
            wallet_every: 50,
            transparent_every: 100,
            seed: 2,
        }
    }

    /// Several `cache.scan_batch`es of [`ChainSpec::sparse`] traffic.
    pub const fn long() -> Self {
        Self::sparse(5_000)
    }

    /// A busy chain: ten shielded and one transparent stranger transaction
    /// (eight outputs) a block, a payment every 10 blocks and a transparent
    /// output every 50.
    pub const fn busy(blocks: u32) -> Self {
        Self {
            blocks,
            noise_txs: 10,
            noise_transparent: 8,
            wallet_every: 10,
            transparent_every: 50,
            seed: 3,
        }
    }

    pub const fn with_seed(self, seed: u64) -> Self {
        Self { seed, ..self }
    }
}

/// Who a synthetic chain pays.
#[derive(Clone, Copy, Debug)]
pub struct Recipient {
    pub ironwood: orchard::Address,
    pub transparent: TransparentAddress,
}

impl Recipient {
    /// The account's default Ironwood receiver and first external
    /// transparent address.
    pub fn of_ufvk(ufvk: &UnifiedFullViewingKey) -> Self {
        let ironwood = ufvk
            .orchard()
            .expect("the key has an Orchard component")
            .address_at(0u32, Scope::External);
        let (transparent, _) = ufvk
            .transparent()
            .expect("the key has a transparent component")
            .derive_external_ivk()
            .expect("an external IVK")
            .default_address();
        Self {
            ironwood,
            transparent,
        }
    }
}

/// A synthetic wallet key: its entropy (hence mnemonic), spending key and
/// the [`Recipient`] it receives on.
pub struct TestKey {
    pub entropy: Entropy,
    pub usk: UnifiedSpendingKey,
    pub recipient: Recipient,
}

impl fmt::Debug for TestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestKey")
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

impl TestKey {
    /// Key `i`: entropy `[i + 1; 32]`, ZIP 32 account 0, as `key restore`
    /// would derive it from the mnemonic.
    pub fn new(network: Network, i: u8) -> Self {
        let entropy = Entropy::new([i.wrapping_add(1); 32]);
        let seed = vault::seed_from_entropy(&entropy);
        let usk = UnifiedSpendingKey::from_seed(
            &network.consensus_params(),
            secrecy::ExposeSecret::expose_secret(&seed),
            zip32::AccountId::ZERO,
        )
        .expect("a spending key");
        let recipient = Recipient::of_ufvk(&usk.to_unified_full_viewing_key());
        Self {
            entropy,
            usk,
            recipient,
        }
    }

    /// The 24 words `RestoreKey` takes.
    pub fn mnemonic(&self) -> String {
        vault::mnemonic_phrase(&self.entropy).to_string()
    }
}

/// A generated chain and the tree state after every block.
#[derive(Clone)]
pub struct SyntheticChain {
    pub spec: ChainSpec,
    /// Blocks `1..=spec.blocks`, ascending.
    pub blocks: Vec<CompactBlock>,
    /// `states[h]`: the chain state at the end of block `h`, `0..=spec.blocks`.
    states: Vec<ChainState>,
    /// Ironwood notes paid to each recipient.
    pub notes_per_recipient: u32,
    /// Transparent outputs paid to each recipient.
    pub transparent_per_recipient: u32,
    /// Ironwood actions across the chain.
    pub actions: u64,
}

impl fmt::Debug for SyntheticChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntheticChain")
            .field("spec", &self.spec)
            .field("actions", &self.actions)
            .field("notes_per_recipient", &self.notes_per_recipient)
            .finish_non_exhaustive()
    }
}

/// The hash of block `height` of the chain generated from `seed`.
pub fn block_hash(seed: u64, height: u32) -> [u8; 32] {
    let mut hash = [0xb1; 32];
    hash[..4].copy_from_slice(&height.to_le_bytes());
    hash[4..12].copy_from_slice(&seed.to_le_bytes());
    hash
}

fn bundle_version() -> BundleVersion {
    BundleVersion::ironwood_v3()
}

/// A two-action Ironwood bundle paying `to`, unproven. Outputs only, so the
/// builder pads each action with a dummy spend.
pub fn two_action_bundle(to: &[orchard::Address; 2], seed: u64) -> UnauthorizedBundle<i64> {
    let version = bundle_version();
    let mut builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        Anchor::empty_tree(),
    )
    .expect("an Ironwood V3 builder");
    for recipient in to {
        builder
            .add_output(None, *recipient, NoteValue::from_raw(NOTE_VALUE), [0; 512])
            .expect("outputs are enabled");
    }
    let (bundle, _) = builder
        .build::<i64>(StdRng::seed_from_u64(seed))
        .expect("the bundle builds")
        .expect("two outputs make a bundle");
    bundle
}

/// A fixed address nobody in a benchmark holds.
pub fn stranger(i: u64) -> orchard::Address {
    let mut sk = [0x5a; 32];
    sk[..8].copy_from_slice(&i.to_le_bytes());
    let sk: SpendingKey = Option::from(SpendingKey::from_bytes(sk)).expect("a valid spending key");
    FullViewingKey::from(&sk).address_at(0u32, Scope::External)
}

/// The P2PKH (or P2SH) `scriptPubKey` paying `addr`.
pub fn script_pubkey(addr: &TransparentAddress) -> Vec<u8> {
    match addr {
        TransparentAddress::PublicKeyHash(h) => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(h);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        }
        TransparentAddress::ScriptHash(h) => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(h);
            s.push(0x87);
            s
        }
    }
}

fn txid(seed: u64, height: u32, index: usize) -> Vec<u8> {
    let mut txid = [0x7c; 32];
    txid[..4].copy_from_slice(&height.to_le_bytes());
    txid[4..8].copy_from_slice(&(index as u32).to_le_bytes());
    txid[8..16].copy_from_slice(&seed.to_le_bytes());
    txid.to_vec()
}

fn compact_actions(bundle: &UnauthorizedBundle<i64>) -> Vec<CompactOrchardAction> {
    bundle
        .actions()
        .iter()
        .map(CompactOrchardAction::from)
        .collect()
}

fn state_at(
    seed: u64,
    height: u32,
    ironwood: &Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
) -> ChainState {
    ChainState::new(
        BlockHeight::from_u32(height),
        BlockHash(block_hash(seed, height)),
        Frontier::empty(),
        Frontier::empty(),
        ironwood.clone(),
    )
}

impl SyntheticChain {
    /// Build the chain `spec` describes, paying every recipient.
    /// Deterministic in `spec` and `recipients`.
    pub fn generate(spec: ChainSpec, recipients: &[Recipient]) -> Self {
        let seed = spec.seed;
        let noise: Vec<Vec<CompactOrchardAction>> = (0..NOISE_POOL as u64)
            .map(|i| {
                let to = [stranger(2 * i + 100), stranger(2 * i + 101)];
                compact_actions(&two_action_bundle(&to, seed ^ (0x6e6f_6973_6500_0000 | i)))
            })
            .collect();
        let mut ironwood = Frontier::empty();
        let mut states = vec![state_at(seed, 0, &ironwood)];
        let mut blocks = Vec::with_capacity(spec.blocks as usize);
        let mut tree_size = 0u32;
        let mut noise_next = 0usize;
        let mut actions = 0u64;
        let mut notes = 0u32;
        let mut transparent = 0u32;
        let every = |n: u32, h: u32| n != 0 && h.is_multiple_of(n);
        for height in 1..=spec.blocks {
            let mut vtx = Vec::new();
            let push = |vtx: &mut Vec<CompactTx>,
                        ironwood_actions: Vec<CompactOrchardAction>,
                        vout: Vec<TxOut>| {
                let index = vtx.len();
                vtx.push(CompactTx {
                    index: index as u64,
                    txid: txid(seed, height, index),
                    ironwood_actions,
                    vout,
                    ..Default::default()
                });
            };
            if every(spec.wallet_every, height) {
                for (r, recipient) in recipients.iter().enumerate() {
                    let bundle_seed = seed ^ (u64::from(height) << 32 | r as u64);
                    let bundle =
                        two_action_bundle(&[recipient.ironwood, recipient.ironwood], bundle_seed);
                    push(&mut vtx, compact_actions(&bundle), Vec::new());
                }
                notes += 2;
            }
            if every(spec.transparent_every, height) {
                for recipient in recipients {
                    let out = TxOut {
                        value: TRANSPARENT_VALUE,
                        script_pub_key: script_pubkey(&recipient.transparent),
                    };
                    push(&mut vtx, Vec::new(), vec![out]);
                }
                transparent += 1;
            }
            for _ in 0..spec.noise_txs {
                push(&mut vtx, noise[noise_next % NOISE_POOL].clone(), Vec::new());
                noise_next += 1;
            }
            if spec.noise_transparent > 0 {
                let vout = (0..spec.noise_transparent)
                    .map(|i| {
                        let mut h = [0x3c; 20];
                        h[..4].copy_from_slice(&height.to_le_bytes());
                        h[4..8].copy_from_slice(&(i as u32).to_le_bytes());
                        TxOut {
                            value: TRANSPARENT_VALUE,
                            script_pub_key: script_pubkey(&TransparentAddress::PublicKeyHash(h)),
                        }
                    })
                    .collect();
                push(&mut vtx, Vec::new(), vout);
            }
            for tx in &vtx {
                for a in &tx.ironwood_actions {
                    let cmx: [u8; 32] = a.cmx.as_slice().try_into().expect("32-byte cmx");
                    let cmx =
                        Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))
                            .expect("a valid cmx");
                    ironwood.append(MerkleHashOrchard::from_cmx(&cmx));
                    tree_size += 1;
                    actions += 1;
                }
            }
            states.push(state_at(seed, height, &ironwood));
            blocks.push(CompactBlock {
                height: u64::from(height),
                hash: block_hash(seed, height).to_vec(),
                prev_hash: block_hash(seed, height - 1).to_vec(),
                time: 1_700_000_000 + height * 75,
                vtx,
                chain_metadata: Some(ChainMetadata {
                    ironwood_commitment_tree_size: tree_size,
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        Self {
            spec,
            blocks,
            states,
            notes_per_recipient: notes,
            transparent_per_recipient: transparent,
            actions,
        }
    }

    pub fn tip(&self) -> BlockHeight {
        BlockHeight::from_u32(self.spec.blocks)
    }

    /// The chain state at the end of block `height`: the prior state of a
    /// scan from `height + 1`.
    pub fn state(&self, height: BlockHeight) -> &ChainState {
        &self.states[u32::from(height) as usize]
    }

    pub fn hash(&self, height: BlockHeight) -> [u8; 32] {
        block_hash(self.spec.seed, u32::from(height))
    }

    /// Blocks `range`, which must lie within `1..=tip`.
    pub fn range(&self, range: Range<BlockHeight>) -> &[CompactBlock] {
        let start = u32::from(range.start) as usize - 1;
        let end = u32::from(range.end) as usize - 1;
        &self.blocks[start..end]
    }

    /// FNV-1a over the encoded blocks and the final tree root: equal
    /// digests mean equal fixtures.
    pub fn digest(&self) -> u64 {
        use prost::Message as _;
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |bytes: &[u8]| {
            for b in bytes {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
        };
        for block in &self.blocks {
            eat(&block.encode_to_vec());
        }
        let last = self.states.last().expect("genesis at least");
        let root = last.final_ironwood_tree().root();
        eat(&root.to_bytes());
        h
    }

    /// The birthday of an account that starts scanning at `height`.
    pub fn birthday(&self, height: u32) -> ResolvedBirthday {
        let prior = BlockHeight::from_u32(height.saturating_sub(1));
        ResolvedBirthday {
            height,
            birthday: zcash_client_backend::data_api::AccountBirthday::from_parts(
                self.state(prior).clone(),
                None,
            ),
        }
    }
}

/// A key registry in `dir` (mode 0700 expected) with scrypt work factor 10.
pub fn registry(dir: &Path, network: Network) -> KeyRegistry {
    let mut config = Config::default();
    config.vault.scrypt_work_factor = 10;
    KeyRegistry::open(Home::new(dir), network, &config).expect("the registry opens")
}

/// `key restore` of `key` as `key_id` through the production path (seed
/// file, migrations, account import), born at `birthday`.
pub fn restore(
    registry: &KeyRegistry,
    key_id: &str,
    key: &TestKey,
    birthday: &ResolvedBirthday,
) -> Arc<KeyEntry> {
    registry
        .create_local_seed(NewLocalSeedKey {
            key_id,
            entropy: &key.entropy,
            passphrase: SecretString::from("pw"),
            birthday,
            account_index: 0,
            label: None,
        })
        .expect("the key restores")
}

/// A node serving a [`SyntheticChain`] from memory.
pub struct MemChain {
    chain: Arc<SyntheticChain>,
    /// The tip the node reports; at most the chain's. Lets a bench grow the
    /// chain under a running daemon.
    tip: AtomicU32,
    /// Added to every request; a batch of blocks pays it once per
    /// `concurrency` blocks, as the node backend's ordered fetches do.
    latency: Duration,
    concurrency: u32,
}

impl fmt::Debug for MemChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemChain")
            .field("tip", &self.tip.load(Ordering::Relaxed))
            .field("latency", &self.latency)
            .finish_non_exhaustive()
    }
}

impl MemChain {
    pub fn new(chain: Arc<SyntheticChain>) -> Self {
        let tip = chain.spec.blocks;
        Self {
            chain,
            tip: AtomicU32::new(tip),
            latency: Duration::ZERO,
            concurrency: 8,
        }
    }

    /// Delay every request by `latency`.
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    pub fn chain(&self) -> &SyntheticChain {
        &self.chain
    }

    /// Report `tip` (clamped to the chain's) from now on.
    pub fn set_tip(&self, tip: u32) {
        self.tip
            .store(tip.min(self.chain.spec.blocks), Ordering::Relaxed);
    }

    fn tip(&self) -> u32 {
        self.tip.load(Ordering::Relaxed)
    }

    fn bounds(&self) -> NodeBounds {
        let tip = BlockHeight::from_u32(self.tip());
        NodeBounds {
            tip_height: tip,
            tip_hash: self.chain.hash(tip),
            retained_from: BlockHeight::from_u32(0),
            estimated_height: Some(tip),
        }
    }

    async fn delay(&self, round_trips: u32) {
        if !self.latency.is_zero() && round_trips > 0 {
            tokio::time::sleep(self.latency * round_trips).await;
        }
    }

    fn check(&self, height: BlockHeight) -> Result<(), ChainError> {
        if u32::from(height) > self.tip() {
            return Err(ChainError::BlockUnavailable { height });
        }
        Ok(())
    }
}

impl ChainBackend for MemChain {
    fn source(&self) -> Source {
        Source::Node
    }

    fn node_bounds(&self) -> BoxFuture<'_, Result<NodeBounds, ChainError>> {
        Box::pin(async move {
            self.delay(1).await;
            Ok(self.bounds())
        })
    }

    fn status(&self) -> NodeStatus {
        NodeStatus {
            connected: true,
            bounds: Some(self.bounds()),
            pruned: false,
            last_error: String::new(),
            last_polled: Some(SystemTime::now()),
            warning: String::new(),
        }
    }

    fn chain_state(&self, height: BlockHeight) -> BoxFuture<'_, Result<ChainState, ChainError>> {
        Box::pin(async move {
            self.delay(1).await;
            self.check(height)?;
            Ok(self.chain.state(height).clone())
        })
    }

    fn block_hash(&self, height: BlockHeight) -> BoxFuture<'_, Result<[u8; 32], ChainError>> {
        Box::pin(async move {
            self.delay(1).await;
            self.check(height)?;
            Ok(self.chain.hash(height))
        })
    }

    fn compact_blocks(
        &self,
        range: Range<BlockHeight>,
    ) -> BoxFuture<'_, Result<Vec<CompactBlock>, ChainError>> {
        Box::pin(async move {
            if range.is_empty() {
                return Ok(Vec::new());
            }
            let len = u32::from(range.end) - u32::from(range.start);
            self.delay(len.div_ceil(self.concurrency)).await;
            if u32::from(range.start) == 0 {
                return Err(ChainError::BlockUnavailable {
                    height: range.start,
                });
            }
            self.check(range.end - 1)?;
            Ok(self.chain.range(range).to_vec())
        })
    }

    fn send_raw_transaction(&self, _raw: Vec<u8>) -> BoxFuture<'_, Result<(), ChainError>> {
        Box::pin(async move {
            self.delay(1).await;
            Ok(())
        })
    }

    fn transaction_status(&self, _txid: [u8; 32]) -> BoxFuture<'_, Result<TxStatus, ChainError>> {
        Box::pin(async move {
            self.delay(1).await;
            Ok(TxStatus::Unknown)
        })
    }

    fn mempool_txids(&self) -> BoxFuture<'_, Result<Vec<[u8; 32]>, ChainError>> {
        Box::pin(async move {
            self.delay(1).await;
            Ok(Vec::new())
        })
    }

    fn fetch_transaction(
        &self,
        _txid: [u8; 32],
    ) -> BoxFuture<'_, Result<Option<Vec<u8>>, ChainError>> {
        Box::pin(async move { Ok(None) })
    }

    fn subtree_roots(
        &self,
        _pool: ShieldedPool,
        _start_index: u32,
        _max_entries: u32,
    ) -> BoxFuture<'_, Result<Vec<gyges_chain::SubtreeRoot>, ChainError>> {
        Box::pin(async move { Ok(Vec::new()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipients() -> Vec<Recipient> {
        vec![TestKey::new(Network::Regtest, 0).recipient]
    }

    #[test]
    fn generation_is_deterministic() {
        let spec = ChainSpec::sparse(200);
        let a = SyntheticChain::generate(spec, &recipients());
        let b = SyntheticChain::generate(spec, &recipients());
        assert_eq!(a.digest(), b.digest());
        let c = SyntheticChain::generate(spec.with_seed(99), &recipients());
        assert_ne!(a.digest(), c.digest());
        assert_eq!(a.notes_per_recipient, 2 * 4);
        assert_eq!(a.transparent_per_recipient, 2);
    }

    /// A restored wallet scans a chain longer than one batch, batch by batch
    /// from the chain's own prior states, and finds exactly its own notes
    /// and transparent outputs.
    #[test]
    fn a_restored_wallet_scans_every_batch() {
        use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};

        let key = TestKey::new(Network::Regtest, 0);
        let chain = SyntheticChain::generate(ChainSpec::sparse(600), &[key.recipient]);
        let cache = gyges_chain::BlockDb::in_memory("regtest").unwrap();
        cache.insert_from(Source::Node, &chain.blocks).unwrap();

        let dir = tempfile::tempdir().unwrap();
        crate::perms::set_mode(dir.path(), 0o700).unwrap();
        let reg = registry(dir.path(), Network::Regtest);
        let entry = restore(&reg, "bench", &key, &chain.birthday(1));
        let params = Network::Regtest.consensus_params();
        let mut wallet = entry.wallet().unwrap();

        let (mut ironwood, mut transparent) = (0, 0);
        let mut start = 1u32;
        while start <= chain.spec.blocks {
            let end = (start + 250).min(chain.spec.blocks + 1);
            let range = ScanRange::from_parts(
                BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
                ScanPriority::Historic,
            );
            let prior = chain.state(BlockHeight::from_u32(start - 1));
            match crate::sync::scan_range(&params, &cache, &mut wallet, &range, prior).unwrap() {
                crate::sync::ScanOutcome::Scanned {
                    transparent_outputs,
                    ironwood_received,
                    ..
                } => {
                    ironwood += ironwood_received;
                    transparent += transparent_outputs;
                }
                crate::sync::ScanOutcome::Reorg { at_height } => panic!("reorg at {at_height}"),
            }
            start = end;
        }
        assert_eq!(ironwood, chain.notes_per_recipient as usize);
        assert_eq!(transparent, chain.transparent_per_recipient as usize);
        let view = crate::sync::WalletView::read(&mut wallet, Some(chain.tip())).unwrap();
        assert_eq!(view.scanned_tip(), chain.tip());
    }

    /// A read-only handle answers while the writer is held (as during a scan
    /// batch), sees what the writer committed, and refuses to write.
    #[test]
    fn readers_do_not_wait_for_the_writer() {
        use zcash_client_backend::data_api::WalletWrite as _;

        let key = TestKey::new(Network::Regtest, 0);
        let chain = SyntheticChain::generate(ChainSpec::sparse(100), &[key.recipient]);
        let cache = gyges_chain::BlockDb::in_memory("regtest").unwrap();
        cache.insert_from(Source::Node, &chain.blocks).unwrap();
        let dir = tempfile::tempdir().unwrap();
        crate::perms::set_mode(dir.path(), 0o700).unwrap();
        let reg = registry(dir.path(), Network::Regtest);
        let entry = restore(&reg, "bench", &key, &chain.birthday(1));
        crate::perms::check_tree(dir.path()).expect("the WAL files are private too");

        let params = Network::Regtest.consensus_params();
        let mut writer = entry.wallet().unwrap();
        let range = zcash_client_backend::data_api::scanning::ScanRange::from_parts(
            BlockHeight::from_u32(1)..chain.tip() + 1,
            zcash_client_backend::data_api::scanning::ScanPriority::Historic,
        );
        crate::sync::scan_range(&params, &cache, &mut writer, &range, chain.state(0.into()))
            .unwrap();
        crate::sync::WalletView::read(&mut writer, Some(chain.tip())).unwrap();

        // The writer's lock is still held here.
        let notes = entry
            .with_reader(crate::history::notes)
            .expect("a wallet")
            .expect("a reader")
            .expect("notes");
        // Notes and UTXOs alike.
        assert_eq!(
            notes.len(),
            (chain.notes_per_recipient + chain.transparent_per_recipient) as usize
        );
        let refused = entry
            .with_reader(|w| w.update_chain_tip(chain.tip() + 1))
            .unwrap()
            .unwrap();
        assert!(refused.is_err(), "a read-only handle must not write");
        drop(writer);
    }

    /// The benchmarks' fixtures, pinned: a change to the generator (or to
    /// an upstream crate it calls) that alters a chain must show up here,
    /// not as a silent change in benchmark numbers. Update the digests
    /// together with docs/testing.md §9.5.
    #[test]
    fn preset_digests_are_pinned() {
        for (spec, digest) in [
            (ChainSpec::dense(), 0x710f_55ac_ed74_7e81u64),
            (ChainSpec::busy(500), 0x020b_6f64_32db_162a),
            (ChainSpec::busy(1_000), 0x196d_0420_2521_68eb),
            (ChainSpec::long(), 0x128d_7f09_c8c4_3691),
        ] {
            let chain = SyntheticChain::generate(spec, &recipients());
            assert_eq!(chain.digest(), digest, "{spec:?}: {:#018x}", chain.digest());
        }
    }

    #[test]
    fn tree_sizes_match_the_frontier() {
        let chain = SyntheticChain::generate(ChainSpec::dense(), &recipients());
        assert_eq!(chain.actions, 1_000);
        for block in &chain.blocks {
            let h = BlockHeight::from_u32(block.height as u32);
            let size = chain
                .state(h)
                .final_ironwood_tree()
                .value()
                .map_or(0, |f| u64::from(f.position()) + 1);
            assert_eq!(
                size,
                u64::from(
                    block
                        .chain_metadata
                        .as_ref()
                        .unwrap()
                        .ironwood_commitment_tree_size
                )
            );
        }
    }
}
