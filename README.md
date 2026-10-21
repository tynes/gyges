# Gyges

A pure-Rust Zcash wallet daemon (`gygesd`) and CLI (`gyges`) that talks straight to a pruned [Zakura](https://github.com/zakura-core/zakura) node, backfills older history over Tor, isolates keys per profile, and supports Keystone 3 Pro hardware signing and ZIP 320 `tex1` payments.

**Status: pre-alpha.** The daemon starts, enforces the 0700/0600 layout and the peer-credential check on its Unix socket, and answers `GetInfo` and `Shutdown`; the CLI connects, runs the API-version and network handshake, and drives `daemon start`, `daemon stop` and `daemon status` (with `--json`). No wallet logic (keys, sync, transactions) exists yet. See [`ROADMAP.md`](ROADMAP.md) for the MVP cut.

## Why

- A pruned full node is enough for *recent* history. Only the gap below the node's retention window needs an external source, and that gap is fetched over Tor and validated against the local node.
- Key material never leaves the daemon. The CLI is a thin gRPC client over a Unix socket; the daemon can run as a separate user, and an air-gapped daemon can prove and sign PCZTs with no chain state at all.
- Each key profile is its own SQLite database, so accounts cannot leak into each other and deleting one is `rm -r`.

## Relationship to Zakura

Gyges consumes [`zakura-core/common`](https://github.com/zakura-core/common) and [`zakura-core/wallet-libraries`](https://github.com/zakura-core/wallet-libraries), the Zakura forks of `librustzcash`, under their upstream library-target names (`zcash_client_backend`, `pczt`, `orchard`, …). The entire stack is pre-release; every `zakura-*` crate is pinned exactly in `Cargo.toml` and bumped deliberately, one pull request per Zakura release.

## Documents

| Document | Contents |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Components, sync pipeline, vault, ZIP 320, Keystone, air-gapped flow, directory layout |
| [`CLI_SPEC.md`](CLI_SPEC.md) | Every `gyges` command, exit codes, non-interactive rules |
| [`API.md`](API.md) + [`proto/gyges.proto`](proto/gyges.proto) | The gRPC contract between `gyges` and `gygesd` |
| [`SYNC.md`](SYNC.md) | Per-key sync state machine, reorgs, pruning race, handoff validation |
| [`DATA_MODEL.md`](DATA_MODEL.md) | `config.toml`, `profile.json`, `seed.age`, Gyges-owned SQLite tables, migrations, backups |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Assets, adversaries, controls, open security questions |
| [`TESTING.md`](TESTING.md) | Test tiers, regtest harness, Keystone fixtures, CI |
| [`ROADMAP.md`](ROADMAP.md) | Milestones and the MVP cut |
| [`GLOSSARY.md`](GLOSSARY.md) | Terms used across the documents |
| [`OVERVIEW.md`](OVERVIEW.md) | The design review that produced the documents above, with its open questions and proposals |

## Building

Requires Rust 1.97.1 (pinned in `rust-toolchain.toml`) and `protoc` 22 or newer (Ubuntu's apt package is too old; use the release from protocolbuffers/protobuf).

```bash
cargo build --locked --workspace
```

```bash
cargo test --locked --workspace
```

The test run includes the end-to-end daemon scenarios in `tests/regtest/`, which build and spawn both binaries against a temporary `GYGES_HOME`.

To try the daemon by hand on regtest (no node is needed yet):

```bash
cargo run -p gygesd -- --network regtest --foreground
```

```bash
cargo run -p gyges-cli -- -n regtest daemon status
```

## Licence

Dual-licensed under MIT ([`LICENSE-MIT`](LICENSE-MIT)) or Apache 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)), at your option.
