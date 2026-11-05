//! Block ingest timings for `docs/testing.md` §9: what the node route does
//! to every block before the cache stores it (`compact::from_raw`: parse,
//! txids, compact outputs).
//!
//! ```console
//! cargo bench -p gyges-chain --bench ingest
//! ```
//!
//! The raw blocks come from `testing::BlockSpec`, so they are transparent
//! only (a coinbase and one payment transaction with many outputs).
//! Shielded bundles, whose proofs dominate a real block's size, are not
//! covered.

use std::time::Duration;

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use gyges_chain::compact;
use gyges_chain::testing::{BlockSpec, BuiltBlock, regtest_params};
use transparent::address::TransparentAddress;
use zcash_protocol::consensus::BlockHeight;

const BLOCKS: u32 = 100;

/// Blocks 1..=BLOCKS, each paying `outputs` distinct addresses.
fn chain(outputs: usize) -> Vec<BuiltBlock> {
    let params = regtest_params();
    let mut prev = [0u8; 32];
    (1..=BLOCKS)
        .map(|h| {
            let mut spec = BlockSpec::new(BlockHeight::from_u32(h), prev, 1_700_000_000 + h);
            for i in 0..outputs {
                let mut pkh = [0x3c; 20];
                pkh[..4].copy_from_slice(&h.to_le_bytes());
                pkh[4..8].copy_from_slice(&(i as u32).to_le_bytes());
                spec = spec.with_payment(TransparentAddress::PublicKeyHash(pkh), 10_000);
            }
            let block = spec.build(&params);
            prev = block.hash;
            block
        })
        .collect()
}

fn from_raw(c: &mut Criterion) {
    let params = regtest_params();
    let mut g = c.benchmark_group("compact-from-raw");
    g.sample_size(20);
    g.sampling_mode(SamplingMode::Flat);
    g.measurement_time(Duration::from_secs(10));
    g.throughput(Throughput::Elements(u64::from(BLOCKS)));
    for outputs in [0usize, 50, 500] {
        let blocks = chain(outputs);
        let bytes: usize = blocks.iter().map(|b| b.raw.len()).sum();
        eprintln!("{BLOCKS} blocks of {outputs} outputs: {bytes} bytes");
        g.bench_with_input(
            BenchmarkId::new("outputs-per-block", outputs),
            &blocks,
            |b, blocks| {
                b.iter(|| {
                    for block in blocks {
                        compact::from_raw(
                            &params,
                            BlockHeight::from_u32(block.height),
                            &block.raw,
                            None,
                        )
                        .expect("the block parses");
                    }
                })
            },
        );
    }
    g.finish();
}

criterion_group!(benches, from_raw);
criterion_main!(benches);
