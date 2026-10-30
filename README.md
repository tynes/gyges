# Gyges

A pure-Rust Zcash wallet daemon (`gygesd`) and CLI (`gyges`) that talks straight to a pruned [Zakura](https://github.com/zakura-core/zakura) node, backfills older history over Tor, isolates keys per profile, and supports Keystone 3 Pro hardware signing and ZIP 320 `tex1` payments.

**Status: pre-alpha.** Milestones M0–M5 and most of M6 have landed and run against a pinned real `zakurad` in the regtest harness:

- `local-seed`, `signer-only` and Keystone 3 Pro key profiles, each with its own database (`watch-only` UFVK import is not built yet).
- Sync through a shared block cache, with reorg handling.
- Backfill below the node's retention window from a configured lightwalletd / zaino endpoint, validated against the node at the handoff.
- Sends to `u1`, `zs1`, `t1` and ZIP 320 `tex1` recipients, with a durable queue for the two-step `tex1` flow.
- The PCZT pipeline over files and pipes, an air-gapped `signer-only` daemon, Keystone signing over animated terminal QR codes, and `--via-tor` broadcasts.

The Tor transport is built, but its bootstrap is untested, and there is no release pipeline yet. [`docs/decisions.md`](docs/decisions.md) §3 lists what is still open.

## Why

- A pruned full node is enough for *recent* history. Only the gap below the node's retention window needs an external source, and that gap is fetched over Tor and validated against the local node.
- Key material never leaves the daemon. The CLI is a thin gRPC client over a Unix socket; the daemon can run as a separate user, and an air-gapped daemon can prove and sign PCZTs with no chain state at all.
- Each key profile is its own SQLite database, so accounts cannot leak into each other and deleting one is `rm -r`.

## Relationship to Zakura

Gyges consumes [`zakura-core/common`](https://github.com/zakura-core/common) and [`zakura-core/wallet-libraries`](https://github.com/zakura-core/wallet-libraries), the Zakura forks of `librustzcash`, under their upstream library-target names (`zcash_client_backend`, `pczt`, `orchard`, …). The entire stack is pre-release; every `zakura-*` crate is pinned exactly in `Cargo.toml` and bumped deliberately, one pull request per Zakura release.

## Documents

The design documents live in [`docs/`](docs/README.md):

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Components, vault, ZIP 320, Keystone, the air-gapped flow; the per-key sync state machine; every file on disk |
| [`docs/interface.md`](docs/interface.md) + [`proto/gyges.proto`](proto/gyges.proto) | Every `gyges` command, and the gRPC contract between `gyges` and `gygesd` |
| [`docs/security.md`](docs/security.md) | Threat model: assets, adversaries, controls and the tests that prove them |
| [`docs/testing.md`](docs/testing.md) | Test tiers, the regtest harness, Keystone fixtures, CI, benchmarks |
| [`docs/decisions.md`](docs/decisions.md) | Design decisions (`Q-*`), verified upstream facts, open work |
| [`docs/glossary.md`](docs/glossary.md) | Terms used across the documents |

## Building

Requires Rust 1.97.1 (pinned in `rust-toolchain.toml`) and `protoc` 22 or newer (Ubuntu's apt package is too old; use the release from protocolbuffers/protobuf).

```bash
cargo build --locked --workspace
```

```bash
cargo test --locked --workspace
```

The test run includes the end-to-end scenarios in `tests/regtest/`, which build and spawn both binaries against a temporary `GYGES_HOME`. The scenarios against the real node download the `zakurad` release pinned in `tests/regtest/versions.toml` on Linux; elsewhere they skip unless `ZAKURAD_BIN` points at a locally built one (see `docs/testing.md` §8).

To try the daemon by hand on regtest (without a node it reports the node as unreachable and keeps keys initialising; point it at one with `--zakura-rpc` and `--zakura-cookie`):

```bash
cargo run -p gygesd -- --network regtest --foreground
```

```bash
cargo run -p gyges-cli -- -n regtest daemon status
```

## Licence

Dual-licensed under MIT ([`LICENSE-MIT`](LICENSE-MIT)) or Apache 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)), at your option.
