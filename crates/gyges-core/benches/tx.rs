//! Transaction-engine timings for `docs/testing.md` §9: each step of a
//! `tx send` from an Ironwood-funded wallet to a transparent address, as
//! `gygesd`'s send pipeline runs them (propose and build under the wallet
//! lock, prove outside it, sign, verify, extract and store).
//!
//! ```console
//! cargo bench -p gyges-core --bench tx
//! ```
//!
//! The wallet is funded by a synthetic chain (`gyges_core::testing`): its
//! notes and the Ironwood tree they sit in are real, so the anchors and
//! witnesses the PCZT carries prove and verify.

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use gyges_chain::{BlockDb, Source};
use gyges_core::sync::{self, WalletView};
use gyges_core::testing::{self, ChainSpec, SyntheticChain, TestKey};
use gyges_core::tx::{self, AmountSpec, Expected, InputOptions, Owner, SignerId};
use gyges_core::{KeyEntry, Network, Pool, Provers, pczt_io};
use pczt::Pczt;
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_keys::address::Address;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

struct Funded {
    _dir: tempfile::TempDir,
    entry: Arc<KeyEntry>,
}

/// A wallet restored at height 1 and scanned to the tip of `chain`.
fn funded(key: &TestKey, chain: &SyntheticChain, cache: &BlockDb) -> Funded {
    let params = Network::Regtest.consensus_params();
    let dir = tempfile::tempdir().unwrap();
    gyges_core::perms::set_mode(dir.path(), 0o700).unwrap();
    let reg = testing::registry(dir.path(), Network::Regtest);
    let entry = testing::restore(&reg, "bench", key, &chain.birthday(1));
    {
        let mut w = entry.wallet().unwrap();
        let range = ScanRange::from_parts(
            BlockHeight::from_u32(1)..chain.tip() + 1,
            ScanPriority::Historic,
        );
        sync::scan_range(
            &params,
            cache,
            &mut w,
            &range,
            chain.state(BlockHeight::from_u32(0)),
        )
        .unwrap();
        WalletView::read(&mut w, Some(chain.tip())).unwrap();
    }
    Funded { _dir: dir, entry }
}

fn to() -> Address {
    Address::Transparent(TransparentAddress::PublicKeyHash([0x11; 20]))
}

fn propose(entry: &KeyEntry) -> tx::SendProposal {
    let params = Network::Regtest.consensus_params();
    let mut w = entry.wallet().unwrap();
    let account = tx::account_of(&w).unwrap();
    tx::propose_send(
        &mut w,
        &params,
        account,
        &[Pool::Ironwood],
        &to(),
        AmountSpec::Zatoshis(Zatoshis::const_from_u64(150_000)),
        None,
        1,
        &InputOptions::default(),
    )
    .expect("a proposal")
}

fn build(entry: &KeyEntry, proposal: &tx::SendProposal) -> (Expected, Pczt) {
    let params = Network::Regtest.consensus_params();
    let mut w = entry.wallet().unwrap();
    let account = tx::account_of(&w).unwrap();
    tx::build_single_step(&mut w, &params, account, proposal, None).expect("a PCZT")
}

fn sign(entry: &KeyEntry, key: &TestKey, pczt: Pczt) -> Pczt {
    let params = Network::Regtest.consensus_params();
    let signer = SignerId::of(entry.profile(), &params).unwrap();
    tx::sign(Some(&*entry.wallet().unwrap()), pczt, &key.usk, &signer).expect("signs")
}

fn engine(c: &mut Criterion) {
    let params = Network::Regtest.consensus_params();
    let key = TestKey::new(Network::Regtest, 0);
    // 20 notes of 0.001 ZEC; a 0.0015 send spends two of them.
    let chain = SyntheticChain::generate(
        ChainSpec {
            wallet_every: 10,
            ..ChainSpec::sparse(100)
        },
        &[key.recipient],
    );
    let cache = BlockDb::in_memory("regtest").unwrap();
    cache.insert_from(Source::Node, &chain.blocks).unwrap();
    let provers = Provers::new();
    let _ = provers.orchard();

    let wallet = funded(&key, &chain, &cache);
    let proposal = propose(&wallet.entry);
    let (expected, built) = build(&wallet.entry, &proposal);
    let proven = tx::prove(built.clone(), &provers).expect("proves");
    let signed = sign(&wallet.entry, &key, proven.clone());
    let owner = Owner::of_wallet(&params, &wallet.entry.wallet().unwrap()).unwrap();
    let bytes = pczt_io::serialize(signed.clone()).unwrap();
    eprintln!(
        "{} inputs, {} Ironwood actions, signed PCZT {} bytes",
        proposal
            .steps()
            .first()
            .shielded_inputs()
            .map_or(0, |i| i.notes().len()),
        tx::proving_work(&built).ironwood_actions,
        bytes.len()
    );

    let mut g = c.benchmark_group("tx-send");
    g.sample_size(10);
    g.sampling_mode(SamplingMode::Flat);
    g.measurement_time(Duration::from_secs(10));
    g.bench_function("propose", |b| b.iter(|| propose(&wallet.entry)));
    g.bench_function("build-pczt", |b| b.iter(|| build(&wallet.entry, &proposal)));
    g.bench_function("prove", |b| {
        b.iter_batched(
            || built.clone(),
            |p| tx::prove(p, &provers).unwrap(),
            BatchSize::PerIteration,
        )
    });
    g.bench_function("sign", |b| {
        b.iter_batched(
            || proven.clone(),
            |p| sign(&wallet.entry, &key, p),
            BatchSize::PerIteration,
        )
    });
    g.bench_function("verify", |b| {
        b.iter_batched(
            || signed.clone(),
            |p| tx::verify(p, &expected, &owner).unwrap(),
            BatchSize::PerIteration,
        )
    });
    g.bench_function("pczt-serialize", |b| {
        b.iter_batched(
            || signed.clone(),
            |p| pczt_io::serialize(p).unwrap(),
            BatchSize::PerIteration,
        )
    });
    g.bench_function("pczt-parse", |b| b.iter(|| pczt_io::parse(&bytes).unwrap()));
    // Proof verification, transaction extraction and the wallet's record of
    // it: once per wallet, so a fresh funded wallet per iteration.
    g.bench_function("extract-and-store", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let w = funded(&key, &chain, &cache);
                let p = propose(&w.entry);
                let (_, built) = build(&w.entry, &p);
                let signed = sign(&w.entry, &key, tx::prove(built, &provers).unwrap());
                let mut wallet = w.entry.wallet().unwrap();
                let t0 = Instant::now();
                tx::extract_and_store(&mut wallet, signed, &provers).unwrap();
                total += t0.elapsed();
            }
            total
        })
    });
    g.finish();
}

criterion_group!(benches, engine);
criterion_main!(benches);
