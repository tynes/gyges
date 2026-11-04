//! Sync timings for `docs/testing.md` §9: the per-key steps the daemon's
//! scheduler runs, over deterministic synthetic chains
//! (`gyges_core::testing`), with no node.
//!
//! ```console
//! cargo bench -p gyges-core --bench sync
//! RAYON_NUM_THREADS=1 cargo bench -p gyges-core --bench sync
//! ```
//!
//! Every wallet is restored through the registry as `key restore` does
//! (seed file, migrations, account import) and is fresh for each timed run;
//! setup is outside the timing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use gyges_chain::{BlockDb, Source};
use gyges_core::sync::{self, ScanOutcome, WalletView};
use gyges_core::testing::{self, ChainSpec, SyntheticChain, TestKey};
use gyges_core::{KeyEntry, Network};
use zcash_client_backend::data_api::chain::BlockSource as _;
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_protocol::consensus::BlockHeight;

struct Fixture {
    name: &'static str,
    key: TestKey,
    chain: SyntheticChain,
    cache: BlockDb,
}

fn fixture(name: &'static str, spec: ChainSpec) -> Fixture {
    let key = TestKey::new(Network::Regtest, 0);
    let t0 = Instant::now();
    let chain = SyntheticChain::generate(spec, &[key.recipient]);
    let cache = BlockDb::in_memory("regtest").expect("the cache opens");
    cache
        .insert_from(Source::Node, &chain.blocks)
        .expect("the blocks insert");
    eprintln!(
        "fixture {name}: {} blocks, {} Ironwood actions, {} notes + {} transparent outputs to the wallet, digest {:016x} ({:.1?} to build)",
        spec.blocks,
        chain.actions,
        chain.notes_per_recipient,
        chain.transparent_per_recipient,
        chain.digest(),
        t0.elapsed(),
    );
    Fixture {
        name,
        key,
        chain,
        cache,
    }
}

/// A fresh wallet for `f`'s key, born at height 1. The directory must
/// outlive the entry.
fn wallet(f: &Fixture) -> (tempfile::TempDir, Arc<KeyEntry>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    gyges_core::perms::set_mode(dir.path(), 0o700).expect("a private directory");
    let reg = testing::registry(dir.path(), Network::Regtest);
    let entry = testing::restore(&reg, "bench", &f.key, &f.chain.birthday(1));
    (dir, entry)
}

/// Scan `f`'s whole chain into `entry`'s wallet in batches of `batch`
/// blocks, as the scheduler's ticks do (`WalletView::next_range` cuts the
/// same ranges). Returns the Ironwood notes and transparent outputs found.
fn scan_all(f: &Fixture, entry: &KeyEntry, batch: u32) -> (usize, usize) {
    let params = Network::Regtest.consensus_params();
    let mut wallet = entry.wallet().expect("a wallet");
    let (mut notes, mut transparent) = (0, 0);
    let mut start = 1u32;
    while start <= f.chain.spec.blocks {
        let end = (start + batch).min(f.chain.spec.blocks + 1);
        let range = ScanRange::from_parts(
            BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
            ScanPriority::Historic,
        );
        let prior = f.chain.state(BlockHeight::from_u32(start - 1));
        match sync::scan_range(&params, &f.cache, &mut wallet, &range, prior).expect("scans") {
            ScanOutcome::Scanned {
                ironwood_received,
                transparent_outputs,
                ..
            } => {
                notes += ironwood_received;
                transparent += transparent_outputs;
            }
            ScanOutcome::Reorg { at_height } => panic!("reorg at {at_height}"),
        }
        start = end;
    }
    (notes, transparent)
}

/// Check `f` once, outside the timing: a full scan finds exactly the
/// wallet's notes and outputs and reaches the tip.
fn check(f: &Fixture) {
    let (_dir, entry) = wallet(f);
    let found = scan_all(f, &entry, 1_000);
    assert_eq!(
        found,
        (
            f.chain.notes_per_recipient as usize,
            f.chain.transparent_per_recipient as usize
        ),
        "{}: the wallet's notes and transparent outputs",
        f.name
    );
    let view = WalletView::read(&mut entry.wallet().unwrap(), Some(f.chain.tip())).unwrap();
    assert_eq!(
        view.scanned_tip(),
        f.chain.tip(),
        "{}: scanned to the tip",
        f.name
    );
}

fn group<'a>(
    c: &'a mut Criterion,
    name: &str,
) -> criterion::BenchmarkGroup<'a, criterion::measurement::WallTime> {
    let mut g = c.benchmark_group(name);
    g.sample_size(10);
    g.sampling_mode(SamplingMode::Flat);
    g.measurement_time(Duration::from_secs(15));
    g
}

/// The whole chain through `scan_range`, swept over `cache.scan_batch`
/// (default 1,000): how much of a scan is per-batch overhead (the wallet
/// transaction, the tree checkpoint, `suggest_scan_ranges` upstream) rather
/// than per-action work.
fn scan_batches(c: &mut Criterion) {
    for f in [
        fixture("long", ChainSpec::long()),
        // `long` without transparent outputs: what `index_transparent`
        // adds to each batch.
        fixture(
            "long-shielded",
            ChainSpec {
                noise_transparent: 0,
                transparent_every: 0,
                ..ChainSpec::long()
            },
        ),
        fixture("busy", ChainSpec::busy(1_000)),
    ] {
        check(&f);
        let mut g = group(c, &format!("scan-chain/{}", f.name));
        g.throughput(Throughput::Elements(u64::from(f.chain.spec.blocks)));
        for batch in [100u32, 500, 1_000] {
            g.bench_with_input(BenchmarkId::new("batch", batch), &batch, |b, &batch| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let (_dir, entry) = wallet(&f);
                        let t0 = Instant::now();
                        scan_all(&f, &entry, batch);
                        total += t0.elapsed();
                    }
                    total
                })
            });
        }
        g.finish();
    }
}

/// The steps around each batch: `WalletView::read` (twice a batch in the
/// scheduler), `index_transparent` alone, and a 100-block rewind.
fn steps(c: &mut Criterion) {
    let f = fixture("busy-500", ChainSpec::busy(500));
    check(&f);
    let tip = f.chain.tip();

    let mut g = group(c, "sync-steps");
    let (_dir, scanned) = wallet(&f);
    scan_all(&f, &scanned, 1_000);
    g.bench_function("wallet-view-read", |b| {
        b.iter(|| WalletView::read(&mut scanned.wallet().unwrap(), Some(tip)).unwrap())
    });

    // Matching the cached blocks' transparent outputs against the key's
    // receivers and crediting its own: 500 blocks × 8 stranger outputs.
    let all = BlockHeight::from_u32(1)..tip + 1;
    g.throughput(Throughput::Elements(u64::from(f.chain.spec.blocks)));
    g.bench_function("index-transparent/500-blocks", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let (_dir, entry) = wallet(&f);
                let mut w = entry.wallet().unwrap();
                WalletView::read(&mut w, Some(tip)).unwrap();
                let t0 = Instant::now();
                let n = sync::index_transparent(&f.cache, &mut w, all.clone()).unwrap();
                total += t0.elapsed();
                assert_eq!(n, f.chain.transparent_per_recipient as usize);
            }
            total
        })
    });
    g.throughput(Throughput::Elements(100));
    g.bench_function("rewind/100-blocks", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let (_dir, entry) = wallet(&f);
                scan_all(&f, &entry, 1_000);
                let mut w = entry.wallet().unwrap();
                let t0 = Instant::now();
                sync::rewind(&mut w, tip - 100).unwrap();
                total += t0.elapsed();
            }
            total
        })
    });
    g.finish();
}

/// The shared block cache on disk (WAL), as the daemon has it: storing a
/// fetched batch, and reading and decoding a scan batch.
fn block_cache(c: &mut Criterion) {
    let key = TestKey::new(Network::Regtest, 0);
    let chain = SyntheticChain::generate(ChainSpec::busy(1_000), &[key.recipient]);
    let mut g = group(c, "block-cache");
    g.throughput(Throughput::Elements(1_000));
    g.bench_function("insert/1000-blocks", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let dir = tempfile::tempdir().unwrap();
                let db = BlockDb::open(&dir.path().join("blocks.sqlite"), "regtest").unwrap();
                let t0 = Instant::now();
                for chunk in chain.blocks.chunks(100) {
                    db.insert_from(Source::Node, chunk).unwrap();
                }
                total += t0.elapsed();
            }
            total
        })
    });
    let dir = tempfile::tempdir().unwrap();
    let db = BlockDb::open(&dir.path().join("blocks.sqlite"), "regtest").unwrap();
    db.insert_from(Source::Node, &chain.blocks).unwrap();
    g.bench_function("read/1000-blocks", |b| {
        b.iter(|| {
            let mut n = 0usize;
            db.with_blocks::<_, ()>(Some(BlockHeight::from_u32(1)), Some(1_000), |block| {
                n += block.vtx.len();
                Ok(())
            })
            .unwrap();
            n
        })
    });
    g.finish();
}

criterion_group!(benches, scan_batches, steps, block_cache);
criterion_main!(benches);
