# Gyges Benchmarks (`docs/BENCHMARKS.md`)

Timings for the CPU-heavy work in `gygesd`: building the proving key, proving, and scanning. These numbers back the build decisions in `ARCHITECTURE.md` §3.7 and `OVERVIEW.md` Q-D6, and replace the draft's unsourced "14x" and "1.5x" figures.

## What a build turns on

| | x86-64 | aarch64 (Apple Silicon, Linux) |
|---|---|---|
| Multi-threaded proving and scanning (`multicore`) | always (upstream default) | always (upstream default) |
| Assembly field arithmetic (`zakura-pasta-curves`) | opt-in: `--features perf-asm-x86_64` on `gygesd` or `gyges-core`; needs BMI2 and ADX, no runtime fallback | always (`zakura-halo2-proofs` turns it on) |

So the only switch that changes a build is `perf-asm-x86_64`, and it applies to x86-64 only. On one machine the variable to measure is the thread count, set with `RAYON_NUM_THREADS`. Nothing in this table can be switched off on aarch64: `zakura-pasta-curves`' `portable` feature only controls the x86-64 backend.

## Running

```bash
cargo bench -p gyges-core --bench prove
```

```bash
RAYON_NUM_THREADS=1 cargo bench -p gyges-core --bench prove
```

On x86-64, also with the assembly (on a BMI2 and ADX machine only):

```bash
cargo bench -p gyges-core --bench prove --features perf-asm-x86_64
```

Use the pinned toolchain (`rust-toolchain.toml`), mains power, and no other build running.

## Cases (`crates/gyges-core/benches/prove.rs`)

- **`orchard-proving-key/build`**: `Provers::orchard()`, the proving and verifying keys for the post-NU6.3 circuit. Orchard and Ironwood share them. The daemon builds them once, at the first send after it starts.
- **`ironwood-prove-2-actions/first-after-key-build`**: one proof of a two-action Ironwood V3 bundle on a freshly built key. Building the key is not timed.
- **`ironwood-prove-2-actions/steady`**: the same proof on a key that has already proven, i.e. every later send. Two actions is the smallest padded bundle, and the cost grows with the number of actions. The bundle comes from orchard's `Builder` with dummy spends rather than from a funded wallet. The circuit and the prover are the ones `tx send` runs.
- **`scan-range/1000-ironwood-actions`**: `gyges_core::sync::scan_range`, the daemon's scan of one batch, over ten cached compact blocks holding 1,000 Ironwood actions (500 two-action transactions). The wallet is a view-only account, and 20 of the actions are its own. The case covers:
  - trial decryption with the account's external and internal keys, which upstream spreads across the Rayon pool;
  - the Ironwood note commitment tree;
  - the wallet writes.

  Each iteration starts from a fresh wallet, created outside the timing. Before timing starts, a check confirms that the wallet finds exactly its 20 notes.

Not covered: Sapling proving (`zakura-proofs` / `bellman`, which `pasta` assembly does not affect) and loading the bundled Sapling parameters.

## Results

Criterion's median of 10 samples.

| Date | CPU | OS | Build | Threads | Key build | First proof | Proof (steady) | Scan 1,000 actions |
|---|---|---|---|---|---|---|---|---|
| 2026-10-28 | Apple M4 Pro (14 cores) | macOS 26.6.2 | default (aarch64 asm) | 14 (default) | 89 ms | 62 ms | 61 ms | 41.5 ms (24.1k actions/s) |
| 2026-10-28 | Apple M4 Pro (14 cores) | macOS 26.6.2 | default (aarch64 asm) | 1 | 305 ms | 394 ms | 394 ms | 67.8 ms (14.7k actions/s) |

Rust 1.97.1, measured on the change that added the benchmark (`ROADMAP.md` M6, `perf` item).

What the rows show:

- **Proving scales with cores.** A two-action proof is 6.5× faster on 14 threads than on one. The key build is 3.4× faster.
- **The first proof costs no more than later ones.** The key build is the whole cold-start cost of a first send, and it is under a tenth of a second.
- **Scanning gains less from threads (1.6×).** Trial decryption runs in parallel, but the tree update and the SQLite writes are serial. On a real chain, where far fewer actions belong to the wallet, the parallel share is larger.

**Not measured: x86-64.** No x86-64 machine was available, so there is no row yet for the portable backend, or for `perf-asm-x86_64` against it. Add both rows, with the CPU model, before deciding whether a release should ship a separate BMI2/ADX build (`ROADMAP.md` M6, release pipeline item).
