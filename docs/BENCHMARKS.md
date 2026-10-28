# Gyges Benchmarks (`docs/BENCHMARKS.md`)

This file times the CPU-heavy work in `gygesd`: building the proving key, proving, and scanning. These numbers back the build decisions in `ARCHITECTURE.md` §3.7 and `OVERVIEW.md` Q-D6. They replace the draft's unsourced "14x" and "1.5x" figures.

## What a build turns on

| | x86-64 | aarch64 (Apple Silicon, Linux) |
|---|---|---|
| Multi-threaded proving and scanning (`multicore`) | always (upstream default) | always (upstream default) |
| Assembly field arithmetic (`zakura-pasta-curves`) | opt-in: `--features perf-asm-x86_64` on `gygesd` or `gyges-core`. Needs BMI2 and ADX, with no runtime fallback | always (`zakura-halo2-proofs` turns it on) |
| Prepared commitment tables for proving | always (`Provers::orchard`) | always (`Provers::orchard`) |

The only build switch is `perf-asm-x86_64`, and it applies to x86-64 only. On a single machine, the variable to measure is the thread count, set with `RAYON_NUM_THREADS`. Nothing in the aarch64 column can be switched off: `zakura-pasta-curves`' `portable` feature controls only the x86-64 backend.

`Provers::orchard` calls upstream's `ProvingKey::prepare_proving` once, when it builds the key. This keeps about 30 MiB of commitment tables for the life of the daemon. Upstream uses the tables only on Rayon pools of at most eight threads (ten on AArch64 macOS), and wider pools take their usual path. See the `steady-unprepared` case below.

## Running

```bash
cargo bench -p gyges-core --bench prove
```

```bash
RAYON_NUM_THREADS=1 cargo bench -p gyges-core --bench prove
```

On x86-64, also run with the assembly, on a BMI2 and ADX machine only:

```bash
cargo bench -p gyges-core --bench prove --features perf-asm-x86_64
```

Use the pinned toolchain (`rust-toolchain.toml`), run on mains power, and don't run another build at the same time.

## Cases (`crates/gyges-core/benches/prove.rs`)

- **`orchard-proving-key/build`**: `Provers::orchard()`. This builds the proving key for the post-NU6.3 circuit, prepares its commitment tables and builds the verifying key. Orchard and Ironwood share these keys. The daemon builds them once, at the first send after it starts.
- **`ironwood-prove-2-actions/first-after-key-build`**: one proof of a two-action Ironwood V3 bundle on a freshly built key. Building the key is not timed.
- **`ironwood-prove-2-actions/steady`**: the same proof on a key that has already proven, as every later send does. Two actions is the smallest padded bundle, and the cost grows with the number of actions. The bundle comes from orchard's `Builder` with dummy spends, not from a funded wallet. The circuit and prover are the same ones `tx send` runs.
- **`ironwood-prove-2-actions/steady-unprepared`**: the same proof on a key built with `ProvingKey::build` alone, without the prepared tables. It shows what the preparation buys.
- **`scan-range/1000-ironwood-actions`**: `gyges_core::sync::scan_range`, the daemon's scan of one batch.
  - Input: ten cached compact blocks holding 1,000 Ironwood actions (500 two-action transactions). The wallet is a view-only account that owns 20 of the actions.
  - Timed work: trial decryption with the account's external and internal keys, which upstream spreads across the Rayon pool; the Ironwood note commitment tree; and the wallet writes.
  - Setup: each iteration starts from a fresh wallet, created outside the timing. Before timing starts, the bench checks that the wallet finds exactly its 20 notes.

All cases run in a warm process. Criterion warms up first, and earlier iterations have already paid for page faults and static tables. So none of these times is a daemon cold start.

Not covered: Sapling proving (`zakura-proofs` / `bellman`, which the `pasta` assembly does not affect) and loading the bundled Sapling parameters.

## Results

Each figure is Criterion's median of 10 samples.

| Date | CPU | OS | Build | Threads | Key build | First proof | Proof (steady) | Proof, unprepared key | Scan 1,000 actions |
|---|---|---|---|---|---|---|---|---|---|
| 2026-10-28 | Apple M4 Pro (14 cores) | macOS 26.6.2 | default (aarch64 asm) | 14 (default) | 99 ms | 61 ms | 62 ms | 64 ms | 40.7 ms (24.6k actions/s) |
| 2026-10-28 | Apple M4 Pro (14 cores) | macOS 26.6.2 | default (aarch64 asm) | 8 | 93 ms | 48 ms | 50 ms | 60 ms | 40.6 ms (24.6k actions/s) |
| 2026-10-28 | Apple M4 Pro (14 cores) | macOS 26.6.2 | default (aarch64 asm) | 1 | 351 ms | 315 ms | 315 ms | 395 ms | 67.8 ms (14.7k actions/s) |

All runs used Rust 1.97.1 on the change that added the benchmark (`ROADMAP.md` M6, `perf` item).

What the rows show:

- **Proving scales with threads.** On an unprepared key, a two-action proof takes 6.2× less time on 14 threads than on one.
- **The prepared tables pay where upstream uses them.** A proof is 20% faster on one thread and 17% faster on eight. On fourteen there is no difference, as upstream documents. Preparing costs about 16 ms of the key build on 14 threads and about 46 ms on one, measured separately. It also costs about 30 MiB of memory for the life of the daemon.
- **On this 14-core machine, eight threads prove faster than fourteen** (50 against 62 ms), because only the narrower pool uses the tables. Gyges leaves the pool at upstream's default, one thread per core. A smaller pool just for proving was not tried, since it would also slow anything else on the pool.
- **The first proof costs no more than later ones** in a warm process.
- **Scanning gains 1.7× from 14 threads, less than proving.** Eight and fourteen threads give the same result. Why was not measured: candidates are the serial tree and SQLite work, and ten blocks giving the batch runner too few tasks to spread.

**Not measured: x86-64.** No x86-64 machine was available, so there is no row for the portable backend, or for `perf-asm-x86_64` against it. Add both rows, with the CPU model, before deciding whether a release should ship a separate BMI2/ADX build (`ROADMAP.md` M6, release pipeline item).
