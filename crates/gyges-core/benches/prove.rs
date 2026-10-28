//! Proving and trial-decryption timings for `docs/BENCHMARKS.md`.
//!
//! ```console
//! cargo bench -p gyges-core --bench prove
//! RAYON_NUM_THREADS=1 cargo bench -p gyges-core --bench prove
//! ```
//!
//! Every case goes through Gyges' own entry points where it has one:
//! [`Provers`] for the proving key and `sync::scan_range` for scanning. The
//! bundles are built with orchard's `Builder` directly, since a wallet-built
//! PCZT needs a funded wallet; the circuit and prover are the same ones a
//! `tx send` runs, and a proof's cost depends only on the number of actions.

use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use gyges_chain::{BlockDb, Source};
use gyges_core::Network;
use gyges_core::Provers;
use gyges_core::registry::Wallet;
use gyges_core::sync::{self, ScanOutcome};
use orchard::builder::{BundleType, UnauthorizedBundle};
use orchard::bundle::BundleVersion;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::tree::Anchor;
use orchard::value::NoteValue;
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_client_backend::data_api::{AccountBirthday, AccountPurpose, WalletWrite as _};
use zcash_client_backend::proto::compact_formats::{
    ChainMetadata, CompactBlock, CompactOrchardAction, CompactTx,
};
use zcash_client_sqlite::WalletDb;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::WalletMigrator;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

/// Ironwood actions in the scanned range, as `OVERVIEW.md` Q-D6 asks.
const SCAN_ACTIONS: usize = 1_000;
const BLOCKS: u32 = 10;
/// Two-action transactions per block: 10 × 50 × 2 = 1,000 actions.
const TXS_PER_BLOCK: usize = SCAN_ACTIONS / BLOCKS as usize / 2;

fn bundle_version() -> BundleVersion {
    BundleVersion::ironwood_v3()
}

/// A two-action Ironwood bundle paying `to` twice, unproven. Outputs only, so
/// the builder pads each action with a dummy spend.
fn two_action_bundle(to: &[orchard::Address; 2], seed: u64) -> UnauthorizedBundle<i64> {
    let version = bundle_version();
    let mut builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        Anchor::empty_tree(),
    )
    .expect("an Ironwood V3 builder");
    for (i, recipient) in to.iter().enumerate() {
        builder
            .add_output(
                None,
                *recipient,
                NoteValue::from_raw(10_000 + i as u64),
                [0; 512],
            )
            .expect("outputs are enabled");
    }
    let (bundle, _) = builder
        .build::<i64>(StdRng::seed_from_u64(seed))
        .expect("the bundle builds")
        .expect("two outputs make a bundle");
    assert_eq!(bundle.actions().len(), 2);
    bundle
}

fn stranger(i: u64) -> orchard::Address {
    let mut sk = [0x5a; 32];
    sk[..8].copy_from_slice(&i.to_le_bytes());
    let sk: SpendingKey = Option::from(SpendingKey::from_bytes(sk)).expect("a valid spending key");
    FullViewingKey::from(&sk).address_at(0u32, Scope::External)
}

fn proof_rng(i: u64) -> StdRng {
    StdRng::seed_from_u64(0x9e37_79b9_0000_0000 | i)
}

fn proving(c: &mut Criterion) {
    let to = [stranger(1), stranger(2)];

    let mut group = c.benchmark_group("orchard-proving-key");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(Duration::from_secs(20));
    // What the first `tx send` after a daemon start waits for before it can
    // prove (`Provers::orchard`, shared by Orchard and Ironwood).
    group.bench_function("build", |b| {
        b.iter_with_large_drop(|| {
            let provers = Provers::new();
            let _ = provers.orchard();
            provers
        })
    });
    group.finish();

    let mut group = c.benchmark_group("ironwood-prove-2-actions");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(Duration::from_secs(20));
    // The first proof on a freshly built key, which also fills the key's
    // lazily built commitment tables. Key build is outside the timing.
    group.bench_function("first-after-key-build", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                let provers = Provers::new();
                let (pk, _) = provers.orchard();
                let bundle = two_action_bundle(&to, i);
                let t0 = Instant::now();
                let proven = bundle.create_proof(pk, proof_rng(i)).expect("proves");
                total += t0.elapsed();
                drop(proven);
            }
            total
        })
    });
    // Every later proof in the daemon's lifetime.
    let provers = Provers::new();
    let (pk, _) = provers.orchard();
    two_action_bundle(&to, u64::MAX)
        .create_proof(pk, proof_rng(u64::MAX))
        .expect("the warm-up proof");
    let mut seed = 0;
    group.bench_function("steady", |b| {
        b.iter_batched(
            || {
                seed += 1;
                (two_action_bundle(&to, seed), proof_rng(seed))
            },
            |(bundle, rng)| bundle.create_proof(pk, rng).expect("proves"),
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

fn block_hash(height: u32) -> [u8; 32] {
    let mut hash = [0xb1; 32];
    hash[..4].copy_from_slice(&height.to_le_bytes());
    hash
}

/// Blocks 1..=BLOCKS of two-action Ironwood transactions. The first
/// transaction of each block pays the wallet; the rest pay strangers, so
/// trial decryption fails on 980 of the 1,000 actions, as it mostly does on
/// a real chain.
fn compact_chain(ours: orchard::Address) -> Vec<CompactBlock> {
    let mut tree_size = 0u32;
    let mut stranger_index = 100;
    (1..=BLOCKS)
        .map(|height| {
            let vtx = (0..TXS_PER_BLOCK)
                .map(|index| {
                    let to = if index == 0 {
                        [ours, ours]
                    } else {
                        stranger_index += 2;
                        [stranger(stranger_index), stranger(stranger_index + 1)]
                    };
                    let seed = u64::from(height) << 32 | index as u64;
                    let bundle = two_action_bundle(&to, seed);
                    let mut txid = [0x7c; 32];
                    txid[..8].copy_from_slice(&seed.to_le_bytes());
                    CompactTx {
                        index: index as u64,
                        txid: txid.to_vec(),
                        ironwood_actions: bundle
                            .actions()
                            .iter()
                            .map(CompactOrchardAction::from)
                            .collect(),
                        ..Default::default()
                    }
                })
                .collect::<Vec<_>>();
            tree_size += (TXS_PER_BLOCK * 2) as u32;
            CompactBlock {
                height: u64::from(height),
                hash: block_hash(height).to_vec(),
                prev_hash: block_hash(height - 1).to_vec(),
                time: 1_700_000_000 + height,
                vtx,
                chain_metadata: Some(ChainMetadata {
                    ironwood_commitment_tree_size: tree_size,
                    ..Default::default()
                }),
                ..Default::default()
            }
        })
        .collect()
}

/// A fresh wallet holding `ufvk` as a view-only account born at height 1.
fn wallet(dir: &tempfile::TempDir, ufvk: &UnifiedFullViewingKey, prior: &ChainState) -> Wallet {
    let mut wallet = WalletDb::for_path(
        dir.path().join("wallet.sqlite"),
        Network::Regtest.consensus_params(),
        SystemClock,
        rand::rand_core::UnwrapErr(rand::rngs::SysRng),
    )
    .expect("the wallet opens");
    WalletMigrator::new()
        .init_or_migrate(&mut wallet)
        .expect("the wallet migrates");
    wallet
        .import_account_ufvk(
            "bench",
            ufvk,
            &AccountBirthday::from_parts(prior.clone(), None),
            AccountPurpose::ViewOnly,
            None,
        )
        .expect("the account imports");
    wallet
}

fn scan(
    params: &gyges_core::ConsensusParams,
    cache: &BlockDb,
    wallet: &mut Wallet,
    range: &ScanRange,
    prior: &ChainState,
) {
    match sync::scan_range(params, cache, wallet, range, prior).expect("the range scans") {
        ScanOutcome::Scanned { .. } => {}
        ScanOutcome::Reorg { at_height } => panic!("reorg at {at_height}"),
    }
}

fn scanning(c: &mut Criterion) {
    let params = Network::Regtest.consensus_params();
    let usk = UnifiedSpendingKey::from_seed(&params, &[7; 32], zip32::AccountId::ZERO)
        .expect("a spending key");
    let ufvk = usk.to_unified_full_viewing_key();
    let ours = ufvk
        .orchard()
        .expect("the key has an Orchard component")
        .address_at(0u32, Scope::External);

    let cache = BlockDb::in_memory("regtest").expect("the cache opens");
    cache
        .insert_from(Source::Node, &compact_chain(ours))
        .expect("the blocks insert");
    let prior = ChainState::empty(BlockHeight::from_u32(0), BlockHash(block_hash(0)));
    let range = ScanRange::from_parts(
        BlockHeight::from_u32(1)..BlockHeight::from_u32(BLOCKS + 1),
        ScanPriority::Historic,
    );

    // Check the fixture once, outside the timing: the wallet finds exactly
    // its own notes. Upstream's `ScanSummary` does not count Ironwood notes,
    // so this reads the wallet's table.
    {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut wallet = wallet(&dir, &ufvk, &prior);
        scan(&params, &cache, &mut wallet, &range, &prior);
        let notes: u32 = rusqlite::Connection::open(dir.path().join("wallet.sqlite"))
            .and_then(|c| {
                c.query_row("SELECT COUNT(*) FROM ironwood_received_notes", [], |r| {
                    r.get(0)
                })
            })
            .expect("the wallet's notes");
        assert_eq!(notes, 2 * BLOCKS, "the wallet's Ironwood notes");
    }

    let mut group = c.benchmark_group("scan-range");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Elements(SCAN_ACTIONS as u64));
    // The daemon's scan of one batch: trial decryption of every action with
    // the account's external and internal keys (upstream spreads it over
    // the Rayon pool), the Ironwood tree, and the wallet writes. A fresh
    // wallet per iteration, created outside the timing.
    group.bench_function("1000-ironwood-actions", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let dir = tempfile::tempdir().expect("a temporary directory");
                let mut wallet = wallet(&dir, &ufvk, &prior);
                let t0 = Instant::now();
                scan(&params, &cache, &mut wallet, &range, &prior);
                total += t0.elapsed();
            }
            total
        })
    });
    group.finish();
}

criterion_group!(benches, proving, scanning);
criterion_main!(benches);
