//! Key and wallet-file timings for `docs/testing.md` §9: the seed vault
//! (age + scrypt), key derivation, address derivation, and opening and
//! creating wallets.
//!
//! ```console
//! cargo bench -p gyges-core --bench keys
//! ```
//!
//! The scrypt cases measure a security parameter (`vault.scrypt_work_factor`,
//! default 20): they say what an unlock costs, and are not something to make
//! faster.

use std::time::{Duration, Instant};

use age::secrecy::SecretString;
use criterion::{BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use gyges_core::testing::{self, ChainSpec, SyntheticChain, TestKey};
use gyges_core::{Network, Pool, addresses, perms, vault};
use zcash_keys::keys::UnifiedSpendingKey;

fn group<'a>(
    c: &'a mut Criterion,
    name: &str,
) -> criterion::BenchmarkGroup<'a, criterion::measurement::WallTime> {
    let mut g = c.benchmark_group(name);
    g.sample_size(10);
    g.sampling_mode(SamplingMode::Flat);
    g.measurement_time(Duration::from_secs(10));
    g
}

fn pw() -> SecretString {
    SecretString::from("correct-horse-battery-staple")
}

fn vault_cases(c: &mut Criterion) {
    let key = TestKey::new(Network::Regtest, 0);
    let mut g = group(c, "vault-scrypt");
    for log_n in [10u8, 15, 20] {
        let armored = vault::seal(&key.entropy, pw(), log_n).unwrap();
        g.bench_with_input(BenchmarkId::new("seal", log_n), &log_n, |b, &n| {
            b.iter(|| vault::seal(&key.entropy, pw(), n).unwrap())
        });
        g.bench_with_input(BenchmarkId::new("open", log_n), &log_n, |b, &n| {
            b.iter(|| vault::open(&armored, pw(), n).unwrap())
        });
    }
    g.finish();
}

fn derivation(c: &mut Criterion) {
    let params = Network::Regtest.consensus_params();
    let key = TestKey::new(Network::Regtest, 0);
    let mut g = group(c, "derive");
    // BIP 39 seed (PBKDF2, 2048 rounds), then the ZIP 32 / BIP 44 tree.
    g.bench_function("seed-from-entropy", |b| {
        b.iter(|| vault::seed_from_entropy(&key.entropy))
    });
    let seed = vault::seed_from_entropy(&key.entropy);
    g.bench_function("usk-from-seed", |b| {
        b.iter(|| {
            UnifiedSpendingKey::from_seed(
                &params,
                secrecy::ExposeSecret::expose_secret(&seed),
                zip32::AccountId::ZERO,
            )
            .unwrap()
        })
    });
    g.finish();
}

fn wallets(c: &mut Criterion) {
    let key = TestKey::new(Network::Regtest, 0);
    let chain = SyntheticChain::generate(ChainSpec::sparse(10), &[key.recipient]);
    let birthday = chain.birthday(1);
    let mut g = group(c, "wallet-file");
    // `key restore` at work factor 10: seed file, a new wallet migrated to
    // the current schema, the account import.
    g.bench_function("create-local-seed", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let dir = tempfile::tempdir().unwrap();
                perms::set_mode(dir.path(), 0o700).unwrap();
                let reg = testing::registry(dir.path(), Network::Regtest);
                let t0 = Instant::now();
                testing::restore(&reg, "bench", &key, &birthday);
                total += t0.elapsed();
            }
            total
        })
    });
    // Daemon start with one key: the permission sweep, the profile, the
    // wallet opened and its migrations checked.
    let dir = tempfile::tempdir().unwrap();
    perms::set_mode(dir.path(), 0o700).unwrap();
    {
        let reg = testing::registry(dir.path(), Network::Regtest);
        testing::restore(&reg, "bench", &key, &birthday);
    }
    g.bench_function("registry-open/1-key", |b| {
        b.iter(|| testing::registry(dir.path(), Network::Regtest))
    });
    let reg = testing::registry(dir.path(), Network::Regtest);
    let entry = reg.resolve("bench").unwrap();
    gyges_core::sync::WalletView::read(&mut entry.wallet().unwrap(), Some(chain.tip())).unwrap();
    g.bench_function("new-address", |b| {
        b.iter(|| {
            addresses::new_address(&mut entry.wallet().unwrap(), &[Pool::Ironwood], None).unwrap()
        })
    });
    g.finish();
}

criterion_group!(benches, vault_cases, derivation, wallets);
criterion_main!(benches);
