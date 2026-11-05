//! Proving and trial-decryption timings for `docs/testing.md` §9.
//!
//! ```console
//! cargo bench -p gyges-core --bench prove
//! RAYON_NUM_THREADS=1 cargo bench -p gyges-core --bench prove
//! ```
//!
//! Every case goes through Gyges' own entry points where it has one:
//! [`Provers`] for the proving key and `sync::scan_range` for scanning. The
//! bundles are built with orchard's `Builder` directly, so the proof alone
//! is timed (`benches/tx.rs` proves a wallet-built PCZT); the circuit and
//! prover are the same ones a `tx send` runs, and a proof's cost depends
//! only on the number of actions. The scanned chain is `ChainSpec::dense`
//! from `gyges_core::testing`.

use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use gyges_chain::{BlockDb, Source};
use gyges_core::Network;
use gyges_core::Provers;
use gyges_core::registry::Wallet;
use gyges_core::sync::{self, ScanOutcome};
use gyges_core::testing::{self, ChainSpec, SyntheticChain, TestKey, stranger, two_action_bundle};
use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_protocol::consensus::BlockHeight;

/// Ironwood actions in the scanned range, as `docs/decisions.md` Q-D6 asks
/// ([`ChainSpec::dense`]: 10 blocks of 50 two-action transactions).
const SCAN_ACTIONS: usize = 1_000;
const BLOCKS: u32 = 10;

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
    // prove (`Provers::orchard`, shared by Orchard and Ironwood): the key,
    // its prepared commitment tables, and the verifying key.
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
    // The first proof on a freshly built key. Key build is outside the
    // timing.
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
    // The same on a key without `Provers`' prepared commitment tables, for
    // comparison: the tables pay only on pools of at most eight threads
    // (ten on AArch64 macOS).
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3).expect("a proving key");
    two_action_bundle(&to, u64::MAX)
        .create_proof(&pk, proof_rng(u64::MAX))
        .expect("the warm-up proof");
    let pk = &pk;
    group.bench_function("steady-unprepared", |b| {
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

/// A fresh wallet holding `key`, restored through the registry as `key
/// restore` does, born at height 1.
fn wallet(
    dir: &tempfile::TempDir,
    key: &TestKey,
    chain: &SyntheticChain,
) -> std::sync::Arc<gyges_core::KeyEntry> {
    gyges_core::perms::set_mode(dir.path(), 0o700).expect("a private directory");
    let reg = testing::registry(dir.path(), Network::Regtest);
    testing::restore(&reg, "bench", key, &chain.birthday(1))
}

fn scan(
    params: &gyges_core::ConsensusParams,
    cache: &BlockDb,
    wallet: &mut Wallet,
    range: &ScanRange,
    prior: &ChainState,
) -> usize {
    match sync::scan_range(params, cache, wallet, range, prior).expect("the range scans") {
        ScanOutcome::Scanned {
            ironwood_received, ..
        } => ironwood_received,
        ScanOutcome::Reorg { at_height } => panic!("reorg at {at_height}"),
    }
}

fn scanning(c: &mut Criterion) {
    let params = Network::Regtest.consensus_params();
    let key = TestKey::new(Network::Regtest, 0);
    // Blocks 1..=10 of 50 two-action Ironwood transactions; the first of
    // each block pays the wallet, the rest pay strangers, so trial
    // decryption fails on 980 of the 1,000 actions, as it mostly does on a
    // real chain.
    let chain = SyntheticChain::generate(ChainSpec::dense(), &[key.recipient]);
    assert_eq!(chain.actions, SCAN_ACTIONS as u64);
    let cache = BlockDb::in_memory("regtest").expect("the cache opens");
    cache
        .insert_from(Source::Node, &chain.blocks)
        .expect("the blocks insert");
    let prior = chain.state(BlockHeight::from_u32(0)).clone();
    let range = ScanRange::from_parts(
        BlockHeight::from_u32(1)..BlockHeight::from_u32(BLOCKS + 1),
        ScanPriority::Historic,
    );

    // Check the fixture once, outside the timing: the wallet finds exactly
    // its own notes. Upstream's `ScanSummary` does not count Ironwood notes,
    // so this reads the wallet's table, and checks the count the scan
    // outcome reports for the daemon's log against it.
    {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let entry = wallet(&dir, &key, &chain);
        let reported = scan(
            &params,
            &cache,
            &mut entry.wallet().unwrap(),
            &range,
            &prior,
        );
        let notes: u32 = rusqlite::Connection::open(entry.dir().join("wallet.sqlite"))
            .and_then(|c| {
                c.query_row("SELECT COUNT(*) FROM ironwood_received_notes", [], |r| {
                    r.get(0)
                })
            })
            .expect("the wallet's notes");
        assert_eq!(notes, 2 * BLOCKS, "the wallet's Ironwood notes");
        assert_eq!(
            reported, notes as usize,
            "the scan outcome's Ironwood count"
        );
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
                let entry = wallet(&dir, &key, &chain);
                let mut wallet = entry.wallet().unwrap();
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
