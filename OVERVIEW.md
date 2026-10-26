# Gyges Design Review (`OVERVIEW.md`)

A review of the three documents currently in this repository, with feedback, suggested improvements, and the open questions that must be answered before a good implementation can begin.

- **Reviewed:** `ARCHITECTURE.md`, `CLI_SPEC.md`, `Cargo.toml` (the only files in the repo, one commit).
- **Review date:** 2026-10-19.
- **Revision 2 (2026-10-19):** §6 now carries a proposed solution under every open question, §5 and §7 are checkbox lists, and §4.1 records the facts re-verified for this revision (Zakura node source, Keystone SDK and firmware docs, wallet-libraries manifests, upstream docs.rs). A checked question means "there is a proposal to review", not "decided".
- **Revision 3 (2026-10-20):** the open items in §5 and §7 are now done or drafted: the workspace compiles against the published crates (`Cargo.lock` committed, `cargo check`/`clippy`/`test` green locally), `proto/gyges.proto` validates, and `README.md`, `API.md`, `THREAT_MODEL.md`, `SYNC.md`, `DATA_MODEL.md`, `TESTING.md`, `ROADMAP.md`, `GLOSSARY.md`, licences, CI and `deny.toml` exist. `ARCHITECTURE.md` and `CLI_SPEC.md` were corrected per §2. Doing the manifest work changed three dependency facts recorded in revision 2; see §4.2.
- **External facts checked:** every `zakura-*` crate on crates.io (versions, repositories, feature flags), the `zakura-core` GitHub organisation, and the READMEs of `zakura-core/zakura` (the node) and `zakura-core/wallet-libraries`. Everything else below is reasoning from the Zcash protocol, ZIPs, and the upstream `librustzcash` APIs the Zakura crates are forked from.

---

## 1. Executive Summary

The two design documents describe an ambitious and coherent product: a daemon/CLI Zcash wallet that talks straight to a pruned Zakura node, backfills history over Tor, isolates keys per profile, and supports Keystone hardware signing and ZIP-320 `tex1` payments. The *vision* is clear and the feature set hangs together. What is missing is the layer underneath the vision: the contracts, failure modes, and security model that turn a feature list into something that can be built, tested, and trusted with money.

**Current state of the repo**

| Item | Status |
|---|---|
| `crates/` directory referenced by `Cargo.toml` | Does not exist |
| `proto/gyges.proto` referenced by `ARCHITECTURE.md` | Does not exist |
| `cargo build` | Cannot succeed: no members, and every `zakura-*` version pin is unpublished (see §4) |
| README, LICENSE files, CI, tests, threat model, gRPC API spec | Absent |

**Top findings, in priority order**

1. **`Cargo.toml` pins versions of the Zakura crates that do not exist.** The pins are the *upstream librustzcash* version numbers (`0.15`, `0.13`, `0.19`, …). The published Zakura crates are at `0.1.0-rc9.1` / `0.1.0-rc7` / `0.0.1-rc1` (wallet-libraries) and `4.0.0-rc3` (common), and the published wallet-libraries crates pin common at exactly `=4.0.0-rc2`, so that is the only common pin that resolves. Nothing resolved as written; **fixed in revision 3** (§4, §4.2).
2. **The architecture names Rust module paths that probably do not exist.** `zakura_client_backend::…`, `zakura_address::kind::tex`, `zakura_pczt::roles::…`. The wallet-libraries README states that library target names keep their *upstream* spelling (`zcash_client_backend`, `pczt`, …) and are consumed via `package = "zakura-…"` renames. The documents should use the real paths. (§2.1)
3. **"Proving works while Locked / with only a UFVK" is only true for Orchard.** Sapling proving requires the proof generation key (`ak`, `nsk`), and `nsk` is not part of any viewing key. Either the vault must be unlocked to prove Sapling spends, the signer must supply the PGK inside the PCZT, or the wallet must be Orchard-only for spending. This affects the vault design, air-gapped mode, Keystone, and watch-only "proving-only" profiles. (§2.1, Q-K3)
4. **No threat model.** The documents make strong security statements ("daemon-only key material", "air-gapped", "0600 socket") without saying who the adversary is. Several design choices (passphrase over the UDS, 60-second unlock windows that begin before proving, `export-seed` over the socket) only make sense once that is written down. (§5, Q-S1…S6)
5. **The ZIP-320 two-step flow has no persistence or recovery story.** Step 2 spends an unconfirmed Step 1 output and is broadcast "immediately". A crash, reorg, or node restart between the two steps strands funds on an ephemeral transparent address. The `TexQueue` component is named in the workspace layout but never described. (§2.1, Q-T1…T4)
6. **The config example is syntactically invalid TOML.** The URLs are wrapped in Markdown link syntax (`"[http://127.0.0.1:8232](http://127.0.0.1:8232)"`), a copy-paste artefact that will break parsing if anyone copies the example. Same artefact appears in `CLI_SPEC.md`. (§2.1, §2.2)

Overall assessment: **good product spec, not yet an engineering spec.** The fastest path forward is to (a) fix the dependency manifest so the project can compile against the real crates, (b) write the gRPC contract and a threat model, and (c) cut an explicit MVP that defers Keystone and ZIP-320 until the core sync/send loop works on regtest.

---

## 2. Document-by-Document Feedback

### 2.1 `ARCHITECTURE.md`

**What works well**

- The six "Core Capabilities" are a crisp statement of what makes Gyges different from Zashi, zingo, or `zcashd`'s built-in wallet. Keep this section; it is the best paragraph in the repo.
- The hybrid sync pipeline (§3.1) correctly identifies the key insight: a pruned node is enough for *recent* history, and only the gap below the retention height needs an external source. Routing that gap over Tor is the right privacy default.
- Per-key SQLite isolation is a sensible choice that avoids cross-account linkage bugs and makes deletion trivial.
- The inline unlock flow (§3.2) is a genuinely nice UX idea and is described concretely enough to implement.

**Accuracy problems**

| Location | Statement | Issue |
|---|---|---|
| §1.2, §3.1 | `zakurad` has a "retention window" exposed via `getblockchaininfo` | Pruning with configurable retention is confirmed in the Zakura node README, so the premise holds. But *which RPC field* carries the retention height is unstated. Bitcoin Core uses `pruneheight`; Zebra has no such field. **Verified (§4.1):** Zakura returns `pruned` and `pruneheight` in `getblockchaininfo`; see Q-D1. |
| §3.1 Case A | `zakura_client_backend::scanning::scan_blocks` | Module path uses the package name, not the library target name. Per the wallet-libraries README the target is still `zcash_client_backend`. Same for `zakura_address`, `zakura_pczt`, `zakura_primitives`, `zakura_client_backend::data_api::…`. |
| §3.1 Case B | "`GetSubtreeRoots` (ZIP-315)" | `GetSubtreeRoots` is a lightwalletd gRPC method. ZIP 315 is "Best Practices for Wallet Handling of Multiple Pools". Check the ZIP reference; it is probably meant to cite the ShardTree/DAG-sync design, not a ZIP. |
| §3.1 Case B | Trial decryption "1.5x vectorized … `zakura-pasta-curves`" | Trial decryption is dominated by Jubjub/Pallas scalar multiplication and ChaCha20-Poly1305, so the speed-up is plausible, but `Cargo.toml` does not enable the `x86_64-asm` / `aarch64-asm` features that exist on `zakura-pasta-curves` and `zakura-orchard`. The claim is unsupported by the manifest as written. |
| §3.2.1 | "Background scanning **and PCZT creation/proving** work 24/7 while `Locked`" | True for Orchard. False for Sapling spends: the Sapling `Prover` needs the proof generation key, which is derived from the spending key. Decide (Q-K3). |
| §3.2.2 | "`age` (scrypt/Argon2id passphrase protection)" | `age` passphrase recipients use scrypt only. There is no Argon2id in age. Either drop Argon2id or do not use age's passphrase mode. |
| §3.2.3 | `UnlockKey(… ttl_secs=60)` | `CLI_SPEC.md` gives `key unlock` a default of `5m`. Pick one source of truth (a config key) and have both paths read it. Also see Q-S3 on *when* the TTL clock should start. |
| §3.3 | Both PCZTs "proven and signed during the same user session" | Correct for ZIP-320, but Step 1 must produce *exactly* `amount + step2_fee` with no change on the ephemeral address, and the ephemeral address must be derived from the ZIP 32 ephemeral chain and never reused. Say so explicitly, and cite them correctly: ZIP 320 mandates only the two-transaction structure and seed-recoverable, unlinkable ephemeral addresses; the exact output value, derivation path and gap limit are librustzcash implementation behaviour (§4.1, Q-T1). |
| §3.3 | "monitors mempool/block inclusion of Step 1's UTXO, and immediately broadcasts Step 2" | No persistence, retry, or failure semantics. See Top Finding 5. |
| §3.4 | `Redactor` strips bloat, then Keystone output goes straight to `TxExtractor` | The redacted PCZT returned by Keystone does not contain the proofs. The daemon must keep the proven, unredacted PCZT and run the **Combiner** role to merge signatures back in before extraction. Add that step. |
| §3.4 | "14x faster Halo2 proving" | Marketing number without a source or a baseline. Either cite the Zakura benchmark or remove it from an architecture document. |
| §4 | `config.toml` example | Invalid TOML (Markdown link artefacts in strings). `socket_path = "~/…"` also requires explicit tilde expansion; say whether the daemon does it. |
| §2 | `gyges-core/ … TexQueue`, `KeyRegistry`, `VaultManager` | Named but never described. Each needs at least a one-paragraph responsibility statement and its persistent state. |

**Structural gaps**

- **No gRPC contract.** The document references `UnlockKey`, `SendTransaction` (server-streaming, with a `KeystoneSignRequired` event), and `CompleteKeystoneSign`, but there is no list of services, messages, streaming semantics, or error codes. This is the single most important missing artefact: it is the boundary between the two binaries and the thing the CLI spec is implicitly written against.
- **Error model is string-matching.** `failed_precondition("VAULT_LOCKED:main")` requires the client to parse a human string. Use `google.rpc.ErrorInfo` (or a typed `GygesError` detail message) with a `reason` enum and a `key_id` field.
- **Reorg handling is never mentioned.** Both backends must handle `PrevHashMismatch` from the scanner by truncating the `WalletDb` to a safe height and rescanning. Note also the race where the node prunes blocks *behind* a slow Case A scanner, forcing a fallback to Tor mid-scan.
- **Note commitment tree continuity across the backend handoff.** The ShardTree frontier at `retention_height - 1` must be identical whether it was produced by the Tor stream or by `z_gettreestate`. Document how the handoff is validated.
- **Block cache.** Case A constructs synthetic `CompactBlock`s in memory. With N key profiles the node is asked for every block N times. Decide whether to introduce a shared `CompactBlock` cache (the upstream `FsBlockDb` pattern) or accept the duplication.
- **The daemon's own lifecycle.** Who starts `gygesd`? Is there a launchd/systemd unit? Does the CLI auto-start it when the socket is absent? What happens to in-flight scans on `daemon stop`?
- **Logging location.** `gyges daemon logs` exists in the CLI but no log file appears in the `~/.gyges/` layout.
- **`profile.json` schema** is referenced but not defined.
- **Existing building blocks are ignored.** `zakura-client-backend` ships a `sync` feature (upstream `zcash_client_backend::sync::run`) and the wallet-libraries repo ships `zakura-wallet-lib`, described as "the backend selector". The architecture hand-rolls a `SyncScheduler` without explaining why those were rejected. Evaluate them first; reuse would remove a large amount of risk.

### 2.2 `CLI_SPEC.md`

**What works well**

- The command tree is well-factored (`daemon`, `key`, `sync`, `address`, `balance`, `notes`, `tx`, `pczt`) and reads like a real `clap` derive hierarchy.
- Global `--json` and `--quiet` flags, environment-variable fallbacks, and the `sync wait` primitive show real care for scripting use.
- The `pczt` Unix-pipe composition example is an excellent illustration of why the PCZT roles are exposed individually.

**Problems and suggestions**

- **`--network` is a global CLI flag but network is a daemon property.** What happens when `gyges -n testnet balance` talks to a mainnet daemon? Either remove the flag (the daemon decides), or make it a *check* that errors on mismatch, or support one daemon per network with per-network socket paths.
- **Does the CLI read `config.toml`?** `--key` defaults to `config.default_key`, implying yes, while everything else implies the CLI is a thin gRPC client. State it. Suggested answer: the CLI never reads config; `default_key` is resolved by the daemon when `key_id` is empty.
- **`--json` output is unspecified.** For a tool that advertises machine-readable output, every command needs a documented schema (or a statement that the JSON is the protobuf `SendTransactionEvent` etc. serialised 1:1, which is the cheap way to get a stable schema).
- **Unlock timeout inconsistency** with `ARCHITECTURE.md` (60s vs 5m). See above.
- **`address new --tex`** makes little sense for a privacy wallet. `tex1` addresses exist so *exchanges* can force senders to pay from transparent funds. A shielded wallet advertising a `tex1` receive address forces every sender to deshield. If there is a real use case, document it; otherwise drop the flag and keep `tex1` on the *send* side only.
- **`tx shield` is labelled "ZIP-316 auto-shielding".** ZIP 316 is Unified Addresses. There is no ZIP for auto-shielding; just describe the behaviour.
- **`key restore` requires `--birthday`.** Most users restoring a seed do not know it. Specify the fallback (e.g. Sapling activation height, 419200 on mainnet, with a warning that a full Tor backfill will follow).
- **`key import-keystone --birthday`** says "override birthday height if not embedded in UR payload" while `ARCHITECTURE.md` §3.4 says the birthday is *extracted* from the UR. **Verified (§4.1):** `zcash-accounts` carries a seed fingerprint, `{ufvk, index, name}` entries and an optional firmware version, and no birthday. `ARCHITECTURE.md` §3.4 is wrong; see Q-K4 for the proposed default.
- **`pczt qr-import <UR_FRAME_1> …`** assumes the user will paste fountain-code frames by hand. A signed PCZT from Keystone is dozens of frames; typing them is not feasible. The input mechanism (webcam, file, phone bridge) is a real design question (Q-K2).
- **`tx send --amount`** grammar ("1.25", "125000000z", "max") should be defined once with its parsing rules and reused by `pczt create` and `tx shield --threshold`.
- **`--memo` says 512 bytes** but should say how text is encoded (UTF-8), how hex is detected, and what happens if the recipient has no shielded receiver (error vs. silently drop).
- **`balance --min-conf`** has no default and "Spendable" is undefined. State the anchor depth / minimum confirmations policy (upstream wallets commonly use 10) and whether it is a daemon setting.
- **`sync run --from`** implies a rewind. Rewinding requires truncating notes, nullifiers, and the ShardTree; say that this is destructive to the scan state and what happens to unconfirmed transactions.
- **`daemon stop`** promises to zero unlocked keys and flush WAL. Also specify behaviour for an in-progress ZIP-320 Step 2 and in-progress proving.
- **`tx status --pir`** relies on `zakura-pir-status`, which is at `0.0.1-rc1` on crates.io. Document which PIR servers are queried, who runs them, and what the privacy guarantee actually is. This should probably be marked experimental.
- **Markdown link artefact** in `daemon start --zakura-rpc` example (`[http://127.0.0.1:8232](http://127.0.0.1:8232)`).
- **Exit codes** are unspecified. Scripts need them (e.g. 0 ok, 2 usage, 3 daemon unreachable, 4 vault locked and non-interactive, 5 insufficient funds).
- **Non-interactive behaviour** is unspecified. What does `tx send` do when stdin is not a TTY and the vault is locked? It must fail fast with a clear error, not hang on `rpassword`.

### 2.3 `Cargo.toml`

- **All twelve Zakura version pins are unpublished.** See §4 for the table. The manifest must be rewritten against `0.1.0-rc9.1` / `0.1.0-rc7` (wallet-libraries) and `=4.0.0-rc2` (common; the wallet-libraries releases pin it exactly, see §4.2), plus `tonic 0.14`, `prost 0.14`, `ur-registry 1.0` (with `default-features = false, features = ["std"]`), `ur 0.5`. **Done in revision 3.**
- **Crates should be renamed to upstream target names.** Per the wallet-libraries README convention: `zcash_client_backend = { package = "zakura-client-backend", version = "0.1.0-rc9", … }`. Without this, every `use` statement in the (future) code and in `ARCHITECTURE.md` is wrong.
- **Performance features not enabled.** `zakura-pasta-curves` and `zakura-orchard` expose `x86_64-asm` / `aarch64-asm` / `multicore`; `zakura-proofs` exposes `multicore`. None are turned on, yet both documents cite the speed-ups. Enable them behind a workspace feature with a `portable` fallback.
- **Feature flags that do exist** (`lightwalletd-tonic`, `tor`, `pczt`, `orchard`, `transparent-inputs` on client-backend; the full PCZT role set on `zakura-pczt`; `bundled-prover` on `zakura-proofs`) all check out against the published crates. Good.
- **Consider the `sync` feature** on `zakura-client-backend` (a ready-made sync loop) before writing `SyncScheduler`.
- **`arti-client 0.25`** is far behind the current `0.47`. The Tor crates move fast and break APIs; pin to whatever version `zakura-client-backend`'s `tor` feature itself depends on, or use that feature and drop the direct dependency.
- **Workspace hygiene missing:** no `[workspace.lints]`, no `[profile.release]` (LTO/codegen-units matter for proving), no `rust-toolchain.toml`, no `deny.toml`/`cargo-audit` configuration for a wallet that handles keys.
- **`reqwest`, `hyper-util`, `tower`** are present without a stated purpose. Presumably JSON-RPC client and the UDS connector for tonic; a one-line comment each would help.
- **No `dev-dependencies`** section and no mention of a regtest harness (`zakurad` in regtest mode) for integration tests.
- **Licence files** (`LICENSE-MIT`, `LICENSE-APACHE`) are declared but absent.

---

## 3. Cross-Document Inconsistencies

| Topic | `ARCHITECTURE.md` | `CLI_SPEC.md` | Resolution needed |
|---|---|---|---|
| Inline unlock TTL | 60 s | `key unlock` default 5 m | One config key, documented once |
| Keystone birthday | Extracted from `ur:zcash-accounts` | `--birthday` "if not embedded" | **Verified:** the registry type carries no birthday (Q-K4). Make `--birthday` required or prompted, default NU5 activation |
| Sync route condition | `scanned_tip` vs `retention_height` | `key restore` describes `birthday` vs `H_retain` | Same thing at restore time; say so |
| Proving while locked | Possible for all pools | Watch-only profile is "proving-only" | Only Orchard; see Q-K3 |
| Module paths | `zakura_*::…` | n/a | Use upstream target names (convention verified, §4.1) |
| Node binary name | `zakurad` | `zakurad` | Confirmed: binary is `zakurad`, repo is `zakura-core/zakura` |
| Keystone result ingestion | "pastes/scans back" | `qr-import <FRAME>…` | QR-only on the device (verified); webcam or pasted frames on the host, batch protocol for small returns (Q-K2) |

---

## 4. Dependency Reality Check (verified 2026-10-19)

| Crate (`Cargo.toml` pin) | Published max version | Repository | Pin for Gyges today |
|---|---|---|---|
| `zakura-client-backend` (0.15) | 0.1.0-rc9.1 (2026-10-20) | zakura-core/wallet-libraries | `=0.1.0-rc9.1` |
| `zakura-client-sqlite` (0.13) | 0.1.0-rc9.1 (2026-10-20) | zakura-core/wallet-libraries | `=0.1.0-rc9.1` |
| `zakura-pczt` (0.2) | 0.1.0-rc7 (2026-10-20) | zakura-core/wallet-libraries | `=0.1.0-rc7` |
| `zakura-pir-status` (0.1) | 0.0.1-rc1 | zakura-core/wallet-libraries | `=0.0.1-rc1` (experimental) |
| `zakura-keys` (0.5) | 4.0.0-rc3 (2026-10-20) | zakura-core/common | `=4.0.0-rc2` (see §4.2) |
| `zakura-address` (0.6) | 4.0.0-rc3 | zakura-core/common | `=4.0.0-rc2` (see §4.2) |
| `zakura-primitives` (0.19) | 4.0.0-rc3 | zakura-core/common | `=4.0.0-rc2` (see §4.2) |
| `zakura-proofs` (0.19) | 4.0.0-rc3 | zakura-core/common | `=4.0.0-rc2` (see §4.2) |
| `zakura-orchard` (0.10) | 4.0.0-rc3 | zakura-core/common | `=4.0.0-rc2` (see §4.2) |
| `zakura-sapling-crypto` (0.4) | 4.0.0-rc3 | zakura-core/common | `=4.0.0-rc2` (see §4.2) |
| `zakura-transparent` (0.2) | 4.0.0-rc3 | zakura-core/common | `=4.0.0-rc2` (see §4.2) |
| `zakura-pasta-curves` (0.5) | 4.0.0-rc3 | zakura-core/common | `=4.0.0-rc2` (see §4.2) |

The table reflects crates.io on 2026-10-20; the revision 2 figures (`rc9`, `rc6`, common at `3.0.0`) were current on 2026-10-19. `Cargo.toml` now carries these pins and `Cargo.lock` is committed.

Other relevant facts from the upstream READMEs:

- The node (`zakura-core/zakura`) is a Zebra fork with **native block pruning and configurable retention**, published pruned snapshots, and a **zcashd-compatibility mode** that, on closer reading, runs a real `zcashd` as a sidecar rather than offering a second RPC dialect (§4.1, Q-D2). The premise of Core Capability 1 is sound.
- The node README shows a `~/.cache/zakura` directory, consistent with the `cookie_path` in the config example.
- The wallet-libraries README describes a `zakura-wallet-lib` crate ("the backend selector"), NU7 exposure through the wallet APIs, and additional features (one-time IVKs, receiver directory, swap-status normalisation). Whether Gyges wants any of these is an open question (Q-D4).
- The entire stack is pre-release (`-rc`). The documents should acknowledge that APIs will shift and that Gyges will track a moving target until Zakura 1.0.


### 4.1 Facts re-verified for revision 2

Checked on 2026-10-19 against the Zakura node source (`zakura-core/zakura`, `crates/zakura-rpc`, `crates/zakura-state`, `crates/zakurad`), the wallet-libraries manifests and README, crates.io metadata, the Keystone SDK registry and firmware protocol docs, and upstream docs.rs. Each item names the question it feeds.

**Dependencies**

- *(Superseded on 2026-10-20, see §4.2.)* The wallet-libraries crates published on 2026-10-19 (`0.1.0-rc9`, `0.1.0-rc6`) depended on the common crates at `^3.0.0`, which made `=3.0.0` the only resolvable pin that day. The `rc9.1` / `rc7` releases of 2026-10-20 pin common at `=4.0.0-rc2` instead. (Q-D3)
- `zakura-client-backend` rc9 depends on `tonic ^0.14`, `prost ^0.14`, `arti-client ^0.35`, `tor-rtcompat ^0.35`, `rusqlite ^0.37` (through sqlite), `shardtree ^0.7`; `Cargo.toml` pins `tonic 0.12`, `prost 0.13`, `arti-client 0.25`, which will produce duplicate major versions. `ur-registry` is at `1.0.9` and `ur` at `0.5.2` (manifest said `0.2` and `0.4`); `age` is at `0.12`. (Q-D3, Q-K6)
- Feature names in `Cargo.toml` (`lightwalletd-tonic`, `tor`, `pczt`, `orchard`, `transparent-inputs`, the `zakura-pczt` role set, `bundled-prover`) all exist. Also available and relevant: `sync`, `sync-decryptor`, `spend-index`, `zcashd-compat`, `lightwalletd-tonic-tls-webpki-roots`; `multicore`, `x86_64-asm`, `aarch64-asm`, `portable` on the curve crates. (Q-D4, Q-D6)
- The lib-target rename convention is confirmed: `[package] name = "zakura-client-backend"`, `[lib] name = "zcash_client_backend"`; the README's consumer snippet is `zcash_client_backend = { version = "0.1.0-rc9", package = "zakura-client-backend" }`. `zakura-wallet-lib` is a 33-line facade for building against either stack and is not needed by a Zakura-only consumer. (Q-D4)
- Upstream `sync::run` takes a lightwalletd `CompactTxStreamerClient` and cannot be pointed at node RPC; `scan_cached_blocks`, `BlockSource` and `BlockCache` are source-agnostic. (Q-D4)

**Zakura node**

- `getblockchaininfo` has `pruned: bool` and `pruneheight` (present only when pruned): "the lowest height whose block body this node still stores". Only transaction bodies are pruned; headers, txids and consensus state remain, and `getblockhash` works at every height. Config key `state.storage_mode.pruned.tx_retention`; default and minimum 10,000 blocks on mainnet and testnet. (Q-D1, Q-Y1, Q-Y2)
- There is no second RPC dialect. Zakura's native JSON-RPC is zcashd-style; "zcashd-compat mode" runs a real `zcashd` sidecar. All methods Gyges needs are in the `Unauthenticated` access class; cookie auth (`enable_cookie_auth`, default true, cookie at `~/.cache/zakura/.cookie`) is HTTP Basic. (Q-D2)
- An optional indexer gRPC (`[rpc] indexer_listen_addr`, `indexer` build feature) streams raw blocks (`get_block_range`), `chain_tip_change` and `mempool_change`. It is not a lightwalletd `CompactTxStreamer`; Zakura has no CompactBlock API today. (Q-D2, Q-Y6)
- A pruned node returns `HistoricalTreeUnavailable` from `z_gettreestate` for pruned heights, and stops maintaining transparent address indexes. (Q-Y5)
- The mempool accepts transactions that spend unconfirmed transparent outputs of other mempool transactions, with `MissingOutput` / `TooManyAncestors` / `TooManyPackageTransactions` rejections and parent-with-descendant eviction; inherited from Zebra 2.1.0, whose changelog cites TEX support as the reason. (Q-T3)
- `z_gettreestate` and `z_getsubtreesbyindex` expose an **Ironwood** pool in addition to Sapling and Orchard. (Q-D7)

**Keystone**

- Registry tags: `zcash-accounts` 49201, `zcash-full-viewing-key` 49202 (reserved, unimplemented), `zcash-unified-full-viewing-key` 49203, `zcash-pczt` 49204, `zcash-sign-batch` 49205, `zcash-sign-result` 49206, `zcash-batch-sig-result` 49207. `zcash-accounts` = `{seed_fingerprint, accounts: [{ufvk, index, name?}], device_version?}`; **no UR type carries a birthday height**, and Zodl (formerly Zashi) asks the user for it. (Q-K4, Q-K6)
- Firmware signs Orchard and Ironwood spends and checks transparent inputs; it does not sign Sapling spends (Sapling outputs tolerated). The batch flow rejects transparent inputs and Sapling entirely. Shielded signing needs the Cypherpunk firmware edition. (Q-K1, Q-K3)
- Transport is QR in both directions; no USB or file path is documented for Zcash. The batch result returns only `(pool, action_index, signature)` tuples, so the return payload is tiny. (Q-K2)

**Upstream wallet API and ZIP 320**

- `propose_standard_transfer_to_address` returns a multi-step `Proposal` for a TEX recipient; `create_proposed_transactions` builds, stores and returns every step's txid, takes one `expiry_height` for all steps, and only transparent outputs of a step may be spent by a later step. Ephemeral receivers are tracked by `get_ephemeral_transparent_receivers`. (Q-T1, Q-T2)
- ZIP 320 mandates the two-transaction structure, that wallets MUST recognise and spend returned funds, and that ephemeral addresses SHOULD be ZIP 32-derivable and unlinkable. It does **not** specify the derivation path, a gap limit, the Step 1 output value rule, or waiting for confirmation; those are librustzcash implementation choices and §2.1 should cite them as such. (Q-T1)
- `zcash_address::ZcashAddress` is an opaque struct with `from_tex` / `try_from_tex`, not an enum with a `Tex` variant; there is no `kind::tex` module. (§2.1)

### 4.2 Facts learned while making the workspace compile (revision 3, 2026-10-20)

Each of these was discovered by `cargo generate-lockfile` / `cargo check` against crates.io and is reflected in `Cargo.toml` with a comment.

- **Common crates must be pinned `=4.0.0-rc2`.** `zakura-client-backend` / `zakura-client-sqlite` `0.1.0-rc9.1` and `zakura-pczt` `0.1.0-rc7` (all published 2026-10-20) depend on every common crate at exactly `=4.0.0-rc2`. Neither `=3.0.0` (revision 2's advice) nor the newer `4.0.0-rc3` resolves alongside them. A few transitive common crates (`zakura-bellman`, `zakura-equihash`, `zakura-pairing`) resolve to `4.0.0-rc3` because the common crates use caret requirements among themselves; that is harmless. (Q-D3)
- **MSRV is 1.97.** Every published Zakura crate declares `rust-version = "1.97"`; the original `1.85` could not build them. `rust-toolchain.toml` pins `1.97.1`.
- **Shared crates must match the Zakura majors**: `rand 0.10`, `secrecy 0.8` (`zcash_keys` takes `SecretVec<u8>` from 0.8), `rusqlite 0.37`, `shardtree 0.7`, `bip0039 0.12` (which has no `zeroize` feature; the old manifest enabled one that does not exist), `tonic`/`prost` 0.14 with the new `tonic-prost` / `tonic-prost-build` split, `arti-client 0.35` (pulled in by the backend's `tor` feature; Gyges has no direct Arti dependency).
- **`ur-registry 1.0.9` needs `default-features = false, features = ["std"]`.** Its default `core` feature depends on `thiserror-core`, which requires a nightly `#![feature]` and fails on stable. It also pulls `prost 0.11` and `minicbor 0.19`, so those majors are duplicated in the graph; `deny.toml` warns rather than denies on duplicates for now. (Q-K6)
- **`BlockCache` is gated behind the `sync` feature** of `zcash_client_backend`, contrary to Q-D4's "source-agnostic" reading. `BlockSource` and `scan_cached_blocks` are not gated. Gyges enables `sync` (cost: `async-trait`, `futures-util`) and implements `BlockCache` for the shared cache as proposed. (Q-D4, Q-Y3)
- **The other module paths cited in §2.1 compile** under the renames: `zcash_client_backend::data_api::wallet::{propose_transfer, propose_standard_transfer_to_address, create_proposed_transactions, create_pczt_from_proposal, extract_and_store_transaction_from_pczt}`, `zcash_client_backend::tor`, `zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient`, `pczt::roles::{combiner, io_finalizer, prover, redactor, signer, spend_finalizer, tx_extractor, updater, verifier}`, `zcash_address::ZcashAddress`, `zcash_client_sqlite::WalletDb`, `zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey}`, `zcash_proofs::prover::LocalTxProver`. They are kept as `use` statements in `gyges-chain` and `gyges-core` so a future Zakura bump that moves one fails `cargo check`.

### 4.3 Facts learned while implementing the RPC backend (2026-10-21)

Read from `zakura-core/zakura` `crates/zakura-rpc/src/methods.rs`, `methods/trees.rs`, `server/cookie.rs` and `server/http_request_compatibility.rs` on `main`; mirrored by the fake node in `gyges_chain::testing`. Exercised against a running `zakurad` v1.6.0 (built from source on macOS; the release assets are Linux-only) by the regtest harness on 2026-10-21, which found:

- `getblockchaininfo.chain` is `"test"` on **regtest** as well as testnet (zcashd says `"regtest"`). `ZakuraRpcBackend` accepts either for a regtest daemon and tells the two apart by `getblockchaininfo.upgrades`: every upgrade the node lists (keyed by branch id, pending ones included) must activate at the height the daemon's parameters say, an upgrade the daemon expects at or below the tip must be listed, and an upgrade active on the node that the daemon does not know is refused. The fake node reports the same shapes.
- A regtest node activates **only Canopy** by default (`activation_heights: {0: Genesis, 1: Canopy}`); NU5 through NU6.3 must be configured under `[network.testnet_parameters.activation_heights]` (`NU5`, `NU6`, `"NU6.1"`, `"NU6.2"`, `"NU6.3"`) for the chain Gyges assumes (every upgrade at height 1). The NU6.1 activation block must pay a lockbox disbursement (ZIP 271): the node refuses an empty `lockbox_disbursements` list, accepts a zero-value entry to a P2SH address, and `generate` then mines it.
- `state.storage_mode.pruned.tx_retention` has a floor of **1001** on regtest (`MAX_BLOCK_REORG_HEIGHT + 1`), not the 200 the plan assumed; mainnet and testnet keep 10,000. Blocks stay non-finalized until 1,000 deep, held in memory and written to `state/non_finalized_state/<net>/<hash>` by a backup task at most every five seconds and never at shutdown: a stop within that window loses them. Starting again over a restored backup sometimes dies with `genesis apply handoff failed: illegal sync lifecycle transition` (the legacy genesis bootstrap finds the sync lifecycle already past `LegacyBootstrap`; about one CI run in three, never on a fresh state); the disk state is intact and a second start succeeds, which is what the harness does. `pruned` is `true` with `pruneheight: 0` until anything is pruned.
- `generate` needs `mining.miner_address`; blocks arrive in milliseconds and the RPC port opens about a second after start, but `generate` before the genesis commit answers "Zakura's state is empty". `invalidateblock` does **not** return the invalidated blocks' transactions to the mempool; they must be rebroadcast, in dependency order because shielded spends anchor on tree roots the reorg removed.
- Coinbases to a transparent address need the usual 100 blocks of maturity before the node accepts a spend; the wallet library does not track maturity, so mining to a wallet's `t1` and shielding immediately is refused by the node. The harness mines to the wallet first and to Zakura's default regtest miner address afterwards.
- `getblock(h, 1)` carries `valuePools[].valueDeltaZat`, the block's effect per pool, which is how the harness learns what a coinbase paid; `trees`, `z_gettreestate` (Sapling, Orchard and Ironwood) and the cookie behaviour matched what the fake node mimics, and a 3-block reorg went through the scheduler as designed.

- `getblock` takes `hash_or_height` as a **string** (`"1234"` or a hash); verbosity 0 returns the raw block as hex, verbosity 1 an object whose `tx` is an array of txids and whose `trees` is `{"sapling":{"size":N},"orchard":{"size":N}}` with a pool **omitted while its tree is empty** (so `trees` can be `{}`; `ironwood` appears once NU6.3 is active). Those sizes are what `CompactBlock.chain_metadata` needs, so Case A costs two `getblock` calls per height until the indexer gRPC is used. (Q-D2, Q-Y3)
- A body the node no longer stores answers `-8 Block not found` from `getblock(h, 0)`; the RPC layer has no pruning-specific error text, and `HistoricalTreeUnavailable` (§4.1) does not appear in it. `z_gettreestate` for such a height answers `-8 "the requested block is not in the main chain"`. Gyges maps `-8` to `BlockUnavailable` / `TreeStateUnavailable` and re-polls the bounds to tell "pruned" from "above the tip". (Q-D1, Q-Y2)
- `z_gettreestate` nests the frontier at `<pool>.commitments.finalState` (hex of the legacy `CommitmentTree` serialisation, the same bytes lightwalletd's `TreeState` carries, so `zcash_client_backend::proto::service::TreeState::to_chain_state` parses it); an inactive pool serialises as `{"commitments":{}}`, and so does an active pool for which the state returned no tree. Gyges reads a missing frontier as an empty tree and logs a warning when the pool is active at that height. **Needs verification** against a node that this never happens for an active pool. (Q-Y5)
- `getblockhash` above the tip is an `InvalidParams` error ("Provided index is greater than the current tip"), not `-8`.
- `getblockchaininfo` carries no `tx_retention`, and no RPC Gyges calls reports the node's version, so `NodeStatus.tx_retention` and `node_version` stay 0 / empty for now.
- The cookie file is `__cookie__:` + base64 of 32 random bytes, written `0600` at every node start; the server ignores the username and compares only the part after the colon, and answers a wrong cookie with an **empty** response rather than a JSON error. Gyges re-reads the file on every request and treats an empty reply as an authentication failure. (Q-D2)
- `zcash_protocol::consensus::Parameters` requires `Clone` (so `Self: Sized`) and cannot be used as `dyn Parameters`; type-erasure needs a wrapper. `zcash_primitives::block::Block::from_parts` is behind the `test-dependencies` feature, so test blocks are serialised by hand (header, CompactSize count, transactions).

Learned while building the scheduler against the wallet crates (2026-10-21):

- A `WalletDb` handle must select a **transparent ledger mode** (`with_transparent_ledger_mode(TransparentLedgerMode::Public)`); Zakura's transparent APIs, `put_received_transparent_utxo` included, fail closed with "Transparent ledger mode is not configured" otherwise. It is per handle, not persisted. Gyges picks `Public` because Case A discovery reads the local node's raw blocks. The `PrivateRequired` mode and the transparent PIR machinery are not used. (Q-D4)
- Zakura's compact-block scanner records a `tx_locator_map` row for **every** transaction of a scanned block, and `scanning/compact.rs` still carries `TODO: Scan transparent data in CompactTx if present`: the `vin`/`vout` fields are not consumed upstream, so Gyges' own transparent indexing from the cache is needed and not redundant. (Q-D4, Q-Y3)
- A v5 txid does not commit to the scriptSig (ZIP 244), so two coinbases that differ only in their height push collide; consensus avoids this by making a v5 coinbase's `nExpiryHeight` equal its block height. The fake node now does the same; before it did, the duplicate locator surfaced as the UNIQUE failure above during `put_blocks`.
- `truncate_to_height` returns the height actually truncated to, which can be lower than requested (checkpoint granularity); the scheduler reports that height, not the one it asked for.

Learned while building the transaction engine against the wallet and PCZT crates (2026-10-21):

- **Ironwood is not optional after NU6.3.** `GreedyInputSelector::propose_transaction` represents every payment to an Orchard receiver as an *Ironwood-pool* output once `ironwood_active_at(params, target_height)` holds, and `select_change_pool` sends change to Ironwood because the ZIP 318 turnstile forbids value entering Orchard after activation (`fees/common.rs`). NU6.3 activates at regtest height 1 (every upgrade does), mainnet 3,428,143 and testnet 4,134,000. So on a Zakura chain Orchard notes are spent, never received, and the "Ironwood off" policy of Q-D7 is withdrawn: profiles list Ironwood in `spend_pools` and `receive_pools`, `balance` has an Ironwood row, and the engine proves (`create_ironwood_proof`, same Orchard proving key), signs (`sign_ironwood`, same spend authorizing key) and verifies (`with_ironwood`) the Ironwood bundle. Transactions are v6 with separate Orchard and Ironwood bundles; the fake node keeps a third commitment tree for `z_gettreestate.ironwood`. (Q-D7)
- `propose_transfer` takes a `SpendPolicy` whose `with_transparent(TransparentSpendPolicy::any_account_addr())` lets the greedy selector fund a payment from the account's transparent UTXOs, so `tx send` from transparent funds needs no separate shielding step; `propose_shielding` remains for `tx shield`. `ConfirmationsPolicy::new_symmetrical(n, allow_zero_conf_shielding)` is the constructor (there is no `_unchecked` form). (Q-D4)
- `create_pczt_from_proposal` runs Creator, Constructor, IO Finalizer (which signs padding dummy spends itself) and Updater, and writes `zcash_client_backend:proposal_info` / `output_info` into the proprietary maps; `extract_and_store_transaction_from_pczt` runs Spend Finalizer and Transaction Extractor and stores the transaction as the wallet's own (unmined). Both are generic over error types that appear only in `Err`, so callers pass `Infallible` for them. The Signer finds no "mine" flag on actions: upstream signs every index and ignores `WrongSpendAuthorizingKey`, and Gyges does the same. Transparent inputs are matched to the wallet's receivers by `scriptPubKey` and signed with `AccountPrivKey::derive_secret_key(scope, index)` from `TransparentAddressSource::Derived`. (Q-K3)
- `zcash_primitives::transaction::builder::cached_orchard_proving_key` is behind the `circuits` and `std` features, which the wallet stack does not enable for Gyges, so `gyges_core::tx::Provers` builds and caches `ProvingKey::build(OrchardCircuitVersion::PostNu6_3)` itself (seconds; first send pays for it) and `LocalTxProver::bundled()` lazily. (Q-D6)
- `TransactionDataRequest` in rc9.1 has only `TransactionsInvolvingAddress` and, with `spend-index`, `GetSpendingTx(OutPoint)`; there is no `GetStatus` / `Enhancement`. Status lookups moved to a separate trait instead, `data_api::status::TransactionStatusRead::transaction_status_work()`.
  - `store_transactions_to_be_sent` queues a lookup for every sent transaction that scanning cannot detect: one with no shielded spend of ours and no `InternalShielded` output, which is a fully transparent send without change. A zero-value shielded change output counts as detectable.
  - A rewind queues the lookups again (`queue_status_for_unobservable_transactions`).
  - The work fails with `StatusModeNotConfigured` unless the handle selects a status mode (`with_status_mode`, per handle, not persisted) and a transparent ledger mode.
  - `set_transaction_status` answers it. `Mined(h)` records the height. `NotInMainChain` and `TxidNotRecognized` set `confirmed_unmined_at_height` and keep the lookup queued until the transaction is conclusively past its expiry.
  - Corrected 2026-10-26 (M1 leftovers). This item first said such a transaction had no path to "mined" status.
  - A transaction with change, or any shielded one, is recognised when the scanner finds the change output or nullifier. (Q-D4)
- `sendrawtransaction` returns the txid as display hex and refuses with a JSON-RPC error whose text Gyges passes through as `GygesError.node_error`; a refused transaction is already stored in the wallet as unmined and its inputs stay unspendable until `nExpiryHeight` (`target + 40` before NU7). (Q-T1)

Learned while building the ZIP 320 queue (2026-10-21, ROADMAP.md M3), against `zakurad` v1.6.0 and the rc9.1 wallet crates:

- **Mempool chaining confirmed (Q-T3), with a race.** `zakurad` accepts a step 2 that spends the unmined ephemeral output of a step 1 already in its mempool, and mines both in the same block. But `sendrawtransaction` for step 1 returns while the node may still be verifying it (its log shows the Orchard verifying key being built inside that request), and a step 2 that arrives in that window is refused as spending an unknown output; the queue re-offers it a second later and it is taken. So `tx send` prints one txid or two depending on timing, and the tests accept either. The node does **not** persist its mempool across a restart: `getrawmempool` is empty afterwards, so the queue's rebroadcast-what-is-missing pass is what carries a transfer over a node restart (Q-T2).
- `getrawtransaction(txid, 1)` answers an object with `height` (`-1` for a mempool transaction) and `confirmations`; an unknown txid is error `-5 "No such mempool or main chain transaction"`. That is `ChainBackend::transaction_status` (`Unknown | InMempool | Mined(h)`), the only node call the queue needs.
- `create_pczt_from_proposal` refuses multi-step proposals (`Error::ProposalNotSupported`) and the per-step `build_proposed_transaction` is private, so the PCZT role pipeline cannot carry ZIP 320. The queue uses `create_proposed_transactions` with `SpendingKeys::from_unified_spending_key` and one `expiry_height` for both steps (passed explicitly as `target + 40`). It wants Sapling spend and output provers even when no Sapling is involved; Gyges hands it the bundled `LocalTxProver`, loaded once. `Builder::build` caches the Orchard proving key itself under the `std` feature, so a ZIP 320 send does not rebuild it. (Q-T1)
- `propose_transfer` with a TEX payment already yields the two-step proposal; `propose_standard_transfer_to_address` is a thin wrapper and adds nothing. Step 2's input is a `prior_step_inputs` reference (`StepOutputIndex::Change(i)` into step 1's `proposed_change`), not a `transparent_inputs` entry, so a summary has to resolve it to show step 2's input value. Step 1 is an ordinary spend under the profile's `spend_pools`: with transparent allowed, the greedy selector may fund the ephemeral output from a transparent UTXO (with shielded change) rather than from notes, which the real-node test observed when a TEX payment to the wallet's own pubkey hash left a spendable `t1` output behind. ZIP 320 permits it (only the ephemeral address must be fresh and unlinkable); a user who wants step 1 to deshield should keep transparent funds shielded (`tx shield`).
- **Application tables use upstream's extension API.** `WalletMigrator::with_external_migrations` runs a `schemerz_rusqlite::RusqliteMigration` with the wallet's own, and `WalletDb::transactionally_with_extension` yields an `ExtensionTransaction` whose SQLite authorizer allows `INSERT`/`UPDATE`/`DELETE` only on `ext_*` tables and denies DDL, `PRAGMA` and transaction control; it offers `execute` and `query_row` only, so multi-row reads go through `group_concat`. Hence `ext_gyges_tex_queue` (DATA_MODEL.md §5.1). No `AUTOINCREMENT` (it writes `sqlite_sequence`).
- `get_known_ephemeral_addresses` and `get_transparent_output` live on the test-only `WalletTest` trait in rc9.1. Production code identifies the ephemeral output of step 1 through `WalletRead::get_transparent_address_metadata(account, &addr)` (which includes reserved ephemeral addresses; `scope() == TransparentKeyScope::EPHEMERAL`) and fetches it with `InputSource::get_unspent_transparent_output(&outpoint, target)`.
- **An ephemeral output stays unspendable until the wallet is told it is free.** `excluding_wallet_internal_ephemeral_outputs` hides an ephemeral output whose creating transaction has wallet inputs unless `max_observed_unspent_height > tx.expiry_height`, and only `WalletWrite::notify_output_verified_unspent(outpoint, h)` (the `GetSpendingTx` data-request answer, `spend-index` feature) sets that. Before `tx resume` builds a new step 2 the daemon checks with the node that the old step 2 is unknown and the tip is past its expiry, then records that height; `build_tex_step2` then makes a `Proposal::single_step` with the ephemeral `WalletTransparentOutput<()>` as its one input and the recipient as its one payment, and `create_proposed_transactions` signs it with the ephemeral key it derives from the address metadata. (Q-T2)
- **The `pczt` crate (rc7) reads but never writes.** Its own bundle types have getters for most fields but none for a transparent input's `partial_signatures`, `script_sig` or `bip32_derivation`, and no setters anywhere; the parsed upstream bundles (every getter) are reachable only inside the Verifier role's `with_transparent` / `with_orchard` / `with_ironwood` / `with_sapling` closures, which is how `pczt inspect` counts signatures and finds change (`zip32_derivation` set, no `user_address`). The one public way to write the global proprietary map is the Updater role's `update_global_with`. `Pczt::serialize` picks the v1 encoding when the content fits and v2 otherwise; only v2 can carry an Orchard output's memo as `EncCiphertext::MemoPlaintext`, so a file made by upstream (ciphertext) does not say whether a memo is attached. Dummy spends are signed by the IO Finalizer, so a transparent-funded PCZT's shielded actions count as signed before the Signer runs. The Combiner merges field by field and refuses any disagreement (`DataMismatch`), proprietary maps included: proven ⊕ signed of one file merges, two sessions do not. `create_pczt_from_proposal` takes the expiry height; `pczt create` passes `target + 1152` so a file has a day to travel. (ROADMAP.md M4, first item)
- `set_transaction_status(txid, Mined(h))` on a transaction the wallet stored (`store_transactions_to_be_sent`) records its mined height, which is how a fully transparent step 2 is ever marked mined given the scanner does not see it (above). The call needs the wallet's chain tip to be known. Since the M1 leftovers item, the scheduler also answers upstream's status work for every key (`gygesd::sync::Scheduler::check_status`), so the queue's own `mark_mined` is no longer the only path for step 2.
- **Upstream's insufficient-funds error reports `available = 0` for a selection that would use transparent inputs only.** Found 2026-10-26. A `max` send from a wallet whose spendable value is all transparent fell to zero in `propose_send`'s fee loop; the loop now subtracts the fee (`required - amount`) from the wallet's own spendable total when `available` is 0.

### 4.4 Facts learned while implementing the lightwalletd backend (2026-10-21)

Read from `zakura-client-backend` 0.1.0-rc9.1 (`src/tor.rs`, `src/tor/grpc.rs`, `src/tor/http.rs`, `src/sync.rs`, `src/proto/service.rs`), `tonic` 0.14.6 (`transport/channel/service/tls.rs`, `transport/channel/endpoint.rs`) and the Zakura node's `crates/zakura-rpc/src/methods.rs` / `methods/trees.rs` on `main`; mirrored by the fake lightwalletd and the fake node in `gyges_chain::testing`.

- **gRPC-over-Tor is gated behind `lightwalletd-tonic-tls-webpki-roots`**, not `tor`. The `tor` feature builds `tor::Client` (arti with `onion-service-client`), `isolated_client`, `set_dormant` and the HTTP-over-Tor helpers; `Client::connect_to_lightwalletd` / `connect_lightwalletd_channel` only exist with `lightwalletd-tonic-tls-webpki-roots` (which turns on `tonic/tls-webpki-roots`). `Cargo.toml` now enables it. (Q-D5)
- **TLS on the Tor path** (THREAT_MODEL.md §3 row 10, verified): `connect_lightwalletd_channel` classifies the endpoint by scheme (`https` → TLS, `http` → plaintext, anything else refused), and for `https` sets `ClientTlsConfig::new().with_webpki_roots()` on the tonic `Endpoint`. tonic builds a rustls `ClientConfig` with safe default protocol versions, a `RootCertStore` of `webpki_roots::TLS_SERVER_ROOTS` only, no client auth, and verifies the certificate against `ServerName::try_from(uri.host())`, so hostname verification and SNI come from the configured URL; there is no option to accept invalid certificates short of a custom verifier, which Gyges never installs. The Tor stream is opened by arti to `(host, port)` with `connect_to_onion_services` enabled only when Gyges says the host is an onion service, so `.onion` endpoints (which have no TLS and need none) are the only plaintext case, and `Config::validate` already refuses `http://` clearnet endpoints outside regtest. The direct transport (`use_tor = false`) applies the same `with_webpki_roots()` rule for `https://`.
- **rustls crypto provider:** tonic's connector uses the process default provider if one is installed, else the one its own `tls-ring` / `tls-aws-lc` feature names, else rustls's compile-time default, which panics when two providers are compiled in. The lock currently has only `ring` (via `reqwest` and arti); `gyges-chain` enables `tonic/tls-ring` so the choice stays explicit if a future dependency adds `aws-lc-rs`.
- **Timeouts:** `tor::Timeouts` bounds connect (30 s), request headers (60 s) and HTTP response bodies, and uses HTTP/2 keep-alive pings (30 s / 20 s) to detect a gRPC peer that stalls mid-stream, because no request deadline fits a long `GetBlockRange`. Gyges adds its own per-message idle timeout on streams (`LwdTimeouts::stream_idle`, 60 s), which is what the hung-stream test exercises without a Tor network. `Client::create` requires the directory to exist and runs arti's `fs-mistrust` permission checks (no group/world write) unless `ARTI_FS_DISABLE_PERMISSION_CHECKS` is set; Gyges creates `tor_cache/` `0700` first. The client re-bootstraps itself on the next request when its directory information expires (`ensure_bootstrapped`).
- **`GetBlockRange` and `GetSubtreeRoots`:** upstream `sync::run` sends `BlockRange { start, end }` with `end` *inclusive* and `pool_types: []` (the legacy, shielded-only answer: no `vin` / `vout`), collects the whole stream and inserts it into the `BlockCache`; `GetSubtreeRootsArg { start_index, shielded_protocol, max_entries }` (0 = all) streams `SubtreeRoot { root_hash, completing_block_hash, completing_block_height }` and upstream reads `root_hash` with `HashSer::read` directly, so it is the raw node bytes with no reversal. `ShieldedProtocol` has `Ironwood = 2` and `sync::run` seeds all three pools. `TreeState.hash` is display (reversed) hex, as `to_chain_state` expects; the fake serves the same. (Q-Y5)
- **`z_getsubtreesbyindex` on the node:** `(pool: String, start_index: u16, limit: Option<u16>)`, pool matched exactly against `"sapling"`, `"orchard"`, `"ironwood"` (any other name is a `Misc` error "invalid pool name, must be one of: …"), answering `{"pool", "start_index", "subtrees": [{"root": <hex>, "end_height": N}]}` with the root as `to_bytes()` hex (Sapling) or the node's `encode_hex` (Orchard, Ironwood), no byte reversal, and **no completing block hash** (lightwalletd's `completing_block_hash` has no counterpart). The list is empty for an index the node has not built yet (it rebuilds the index from the tip during initial sync). The handler has no pruning check; whether the state answers for pruned ranges on a pruned node is still the open item of THREAT_MODEL.md §6, for the regtest run of the handoff item. `gyges_chain::SubtreeRoot` therefore carries `end_hash: Option<_>`.
- `GetTransaction` answers `RawTransaction.height` as 0 for a mempool transaction, `0xffffffffffffffff` for one mined only on a fork, else the main-chain height (the proto comment documents the sentinel mapping from `getrawtransaction`'s `-1`); an unknown txid is NOT_FOUND (zaino answers `Internal` instead, §4.5). That is `ChainBackend::transaction_status` on the lightwalletd route.
- `GetLightdInfo.chain_name` is `"main"` or `"test"` from lightwalletd. zaino 0.10.2 answered `"test"` on regtest (§4.5). The backend accepts `"test"` or `"regtest"` for a regtest daemon, like `ZakuraRpcBackend` does for the node. `tonic` reports a dead connection as `Code::Unknown` with the transport error as `source()`; Gyges maps that, `Unavailable`, `DeadlineExceeded`, `Cancelled` and `Aborted` to `ChainError::Unreachable` and drops the connection.
- `tonic-prost-build`'s `extern_path` maps every proto message onto an existing Rust type, including the request and response types of generated services, so `gyges-chain`'s `build.rs` can generate only the *server* side of `CompactTxStreamer` for the fake over `zcash_client_backend::proto::{compact_formats, service}` types (`generate_default_stubs` makes the unimplemented methods answer UNIMPLEMENTED, server-streaming methods take `BoxStream`). The upstream crate ships no `.proto` files, only the generated modules, so the proto subset in `crates/gyges-chain/proto/` was written from them. (Q-O2)


### 4.5 Facts about an archival endpoint for the regtest harness (2026-10-25)

Gathered for ROADMAP.md M2's sixth item. The bullets below are research from source and release pages. The smoke test at the end of this section ran them against a real node: an archive `zakurad` v1.6.0 with `zainod` 0.10.2 in front of it.

- **zakura-core publishes no indexer.** The organisation has `common`, `zakura`, `wallet-libraries` and forks of rocksdb, iroh, iroh-quinn and librustzcash. There is no zaino or lightwalletd fork. Zakura's docs send wallet features to Zaino (`docs/contributing.md`, `docs/zcashd-compat.md`). Zakura's own tests use `electriccoinco/lightwalletd` (`docker/docker-compose.lwd.yml`, `crates/zakurad/tests/common/lightwalletd/`). `zakurad` serves the Zebra indexer gRPC (zakura PR #612), and its `getblockchaininfo` reports `pruned` / `pruneheight` (PR #470).
- **Upstream zaino against `zakurad` v1.6.0: plausible, untested.**
  - zaino 0.10.1/0.10.2 links zebra-chain 12 (zebra v6.3.0).
  - NU6.3 (Ironwood) has the same branch id in both (`0x37a5165b`), and zaino already handles the Ironwood pool.
  - NU7 differs (zebra's placeholder `0xfffffffe` against Zakura's `0x77190ad9`, plus Zakura's 25 s spacing). The harness activates only through NU6.3, so this does not matter yet.
  - Only zaino's `backend = "rpc"` (JSON-RPC) can work: the `direct` backend reads the node's database, whose format has diverged (Zakura format 29).
- **No release binaries.** zaino's GitHub releases carry only `CHANGELOG.md`, and so do lightwalletd's. Pinnable instead:
  - the crates.io `zainod` 0.10.2 `.crate` (sha256 `501b24362ae267a9c64a2236c7089208a3db63e7b09f38f93c5658c6c8edf76e`), built with `cargo install --locked`;
  - the `zingodevops/zaino:0.10.1` image (linux/amd64 only, digest `sha256:f2fda4a8ef06d5b41d914de6575b980d27c5392170578001c5127bbb5eb6c6d9`).
- **Regtest config.** `network = "Regtest"` adopts the node's activation heights. Keys:
  - `backend = "rpc"`;
  - `[validator_settings] validator_jsonrpc_listen_address`, `validator_cookie_path`;
  - `[grpc_settings] listen_address`;
  - `[storage.database] path`.

  It serves plaintext gRPC on loopback; TLS is enforced only for non-private binds.
- **zaino cannot sit in front of the wallet's pruned node.** Compact blocks and tree states are served from its own LMDB store once indexed. But mined transactions (`GetTransaction`) and subtree roots are fetched from the node every time, which fails below a pruned node's window. So the harness needs a **second, archive-mode `zakurad`** peered with the wallet's pruned one, with zaino in front of the archive node. (Not exercised by the smoke test, which used an archive node only.)

#### Smoke test: `zainod` 0.10.2 in front of an archive `zakurad` v1.6.0 (2026-10-25, macOS arm64)

**Result: the pairing works.** Every `ArtiTorLwdBackend` call answered, and every answer matched the node's. There are three deviations from the lightwalletd contract that `gyges_chain::lwd` assumes. lightwalletd was therefore not needed.

**Setup.** No harness change; a throwaway example (not committed) drove the backend.
- **Node:** `zakurad` 1.6.0+gebda15e23ed0, built from the tag. The config is the one `tests/regtest/harness/node.rs` writes (every upgrade through NU6.3 at height 1, cookie auth, `checkpoint_sync = false`), minus the `storage_mode` line: `Archive` is the default. `getblockchaininfo` then reports `pruned: false`.
- **zaino:** `cargo +1.97.1 install zainod --version 0.10.2 --locked` built in 2 min 10 s.
- **Config used** (paths shortened):

  ```toml
  backend = "rpc"
  network = "Regtest"

  [validator_settings]
  validator_jsonrpc_listen_address = "127.0.0.1:39232"   # the node's [rpc] listen_addr
  validator_cookie_path = "<node dir>/cookie/.cookie"

  [grpc_settings]
  listen_address = "127.0.0.1:39237"                     # plaintext gRPC on loopback

  [storage.database]
  path = "<zaino dir>/db"
  ```

  Run as `zainod start --config <file>`.
- **Chain:** 101 coinbases to the abandon-mnemonic key, then a node restart (miner set to the burn address) and 100 more blocks. Then, through `gygesd`:
  - `tx shield` of 101 UTXOs into Ironwood (24,065 bytes);
  - a 1 ZEC Ironwood payment to a second key, sent `--via-tor`;
  - a 2 ZEC payment to that key's `tm…` receiver.

  Tip 210.

**What worked:**
- **Startup and adoption.** zaino adopted the node's activation heights ("Adopted activation heights from the validator": Overwinter through NU6.3 at 1). It indexed the 101-block chain and was serving 0.7 s after start. A restart over its existing database took 1.2 s. A new block reached `GetLatestBlock` within about 1 s (five runs: 0.28 s, then 1.0 s each), which fits a polling chain-head service with a ~1 s interval.
- **`GetLightdInfo`** (1–3 ms):
  - `vendor "ZingoLabs ZainoD"`, `version "0.10.2"`, `chain_name "test"` (not `"regtest"`);
  - `consensus_branch_id "37a5165b"`, `upgrade_name "NU6.3"`, `sapling_activation_height 1`;
  - `zcashd_build "v1.6.0+gebda15e23ed0"`, `zcashd_subversion "/Zakura:1.6.0/"`, `lightwallet_protocol_version "v0.5.0"`.

  `node_bounds` passes the chain check, and its tip height and hash equal the node's.
- **`block_range(1..211)`**: 210 blocks in under 1 ms; heights, `hash` and `prev_hash` equal `getblockhash`. With `pool_types: []`, zaino answers like lightwalletd: no transparent-only transactions (the coinbases) and no `vin` / `vout`. After dropping those from the node route's blocks (`ZakuraRpcBackend::compact_blocks`), all 210 blocks are equal field for field, including `chain_metadata` and the two `ironwood_actions` (proto tag 9) of each shielded transaction. zaino's `compact_formats.proto` has the same tags as `zakura-client-backend`'s.
- **`chain_state`** at heights 1, 105, 201–204 and 210: 6 ms each, and equal to `z_gettreestate` through `ZakuraRpcBackend`. That includes a non-empty Ironwood frontier: position 5 after three 2-action transactions.
- **`raw_transaction` / `transaction_status`**: bytes equal to `getrawtransaction` for a coinbase, the shield, the Ironwood payment and the transparent payment (heights 1, 202, 203, 204). The shield showed height 0 / `InMempool` while unmined.
- **`address_utxos`**: agrees with the node's `getaddressutxos`.
  - With 101 coinbases: the same count, and the entries spot-checked are equal (txid, index, value, height).
  - After the shield: 0 at the key's address, and the single output at the recipient's is identical.
- **`send_transaction`**: `tx send --via-tor` on regtest with `use_tor = false` reached the node's mempool through zaino. The audit log records `via="fallback"`.
- **`subtree_roots`** for Sapling, Orchard and Ironwood: empty on both sides. No subtree completes in a few blocks, so root correctness is still untested.

**Deviations** (1 and 2 are handled in `gyges_chain::lwd`, see below):
1. **Unknown txid.** `GetTransaction` answers gRPC `Internal`, `RPC error: LegacyRpcError { code: -5, message: "No such mempool or main chain transaction" }`, not `NOT_FOUND`.
   - Before the fix, `transaction_status` returned `ChainError::Rpc` where it should return `TxStatus::Unknown`.
   - `raw_transaction` returned an error where it should return `None`. So `gygesd::backfill::place_utxo` retried an output whose transaction the endpoint lacks (`SyncError::Fallback`) instead of discarding it.
   - **Handled:** `raw_transaction` reads an `Internal` answer that `zaino_tx_not_found` recognises as `None`. That needs both the code -5 and the text. `transaction_status` then gives `TxStatus::Unknown`.
2. **Rejected broadcast.** A `SendTransaction` the node refuses comes back as gRPC `Internal`, not as a `SendResponse` with `error_code`. The error text is `InternalServerError: error receiving data from backing node: critical error in backing block source: validator unreachable: <the node's text>`. The run below shows a second shape.
   - Before the fix, `send_transaction` mapped it to `ChainError::Rpc`, so a refused `--via-tor` broadcast reached the user as `INTERNAL` instead of `NODE_REJECTED`.
   - zaino stays `Ready` afterwards.
   - **Handled:** `send_transaction` passes an `Internal` answer through `zaino_rejection`, which returns the node's text as `ChainError::Rejected` only when the answer is the node refusing the transaction. A node zaino cannot reach or authenticate to stays `ChainError::Rpc`.
3. **Stale cookie after a node restart.** `zakurad` rotates its cookie on restart and drops a connection that presents the old one: an empty reply, not a 401. So a client that re-reads the cookie only on a 401 never recovers. zaino builds its credentials from the cookie file at start (`zaino-rpc` `auth_from_parts`). zaino logged `validator unavailable: … error sending request` and backed off, with status `RecoverableError`. Still failing at its eighth retry (attempt 8, about a minute in), it was restarted by hand. Meanwhile it kept serving its indexed blocks over gRPC. So the harness must restart zaino after every `Node::restart`.

The `chain_name` `"test"` is already accepted.

**Error answers, recorded (2026-10-26).** The same pairing on a 5-block chain, driven by a throwaway example over `Transport::Direct` (not committed). Every answer below is gRPC `Internal`, with no details and no extra metadata.
- **(a) `GetTransaction`, unknown txid** (4 ms): `RPC error: LegacyRpcError { code: -5, message: "No such mempool or main chain transaction" }`.
- **(b) `SendTransaction`, node refuses.** The shape depends on the node's JSON-RPC code, which zaino does not pass on.
  - **Already mined:** a coinbase re-sent. The node answers `{"code":-1,"message":"any transaction with the same effects will be rejected from the mempool until a chain reset: transaction was committed to the best chain"}`. zaino retries -1 as "work queue full" (`zaino-source` `is_retryable`, which also retries -28 "warming up"), then answers after 2.5 s: `InternalServerError: error receiving data from backing node: critical error in backing block source: validator unreachable: any transaction with the same effects will be rejected from the mempool until a chain reset: transaction was committed to the best chain`.
  - **Malformed:** the bytes `deadbeef`. The node answers `{"code":-22,"message":"parse error: bad tx header"}`. zaino classes -22 and -25 to -27 as a rejection (`zaino-source-zebra-rpc` `submission_rejection`) and answers in 2 ms: `InternalServerError: error receiving data from backing node: critical error in backing block source: validator rejected the query: malformed transaction: parse error: bad tx header`.
- **(c) `SendTransaction`, node stopped** (2 ms): `InternalServerError: error receiving data from backing node: critical error in backing block source: validator unreachable: http error: error sending request for url (http://127.0.0.1:41232/)`. `GetTransaction` gives the same text, and so does `GetLightdInfo`, so a backend connecting afresh fails at its chain check with `ChainError::Rpc`.
- **(d) `SendTransaction` after a node restart, zaino holding the stale cookie** (2 ms): the same text as (c). The node already answered `getblockcount` under its new cookie. zaino's log showed `ChainHead failed to advance; retrying, error: validator unavailable: http error: error sending request …` before and after the restart.

So the text after `validator unreachable:` is the node's own message when the node answered with a JSON-RPC error. zaino prints that message alone (`zaino-rpc` `From<RpcError> for NonDomainError`). For any other failure it prints one of `zaino-rpc`'s `RpcError` texts (`http error: `, `json error: `, `http status `, `work queue full after `, `null result without error`, `response body exceeded `), or a bare `FailureMode` name. `zaino_rejection` relies on exactly this. A real -1 "busy" or -28 "warming up" from the node would also read as a rejection, which matches what `ZakuraRpcBackend` does on the direct route. `FakeLightwalletd::set_zaino_errors` makes the fake answer (a) and (b) in these shapes.

**Not covered:**
- zaino in front of a pruned node;
- the Tor transport;
- `pool_types` other than `[]`;
- Sapling outputs. A Sapling payment from `tx send` failed in Gyges itself: "PCZTs require that ZIP 212 is enforced for outputs". `sapling-crypto` builds PCZT Sapling outputs only once ZIP 212 is `On`, which is Canopy + `ZIP212_GRACE_PERIOD` (32,256 blocks). With Canopy at 1, that is height 32,257, so a Sapling scenario on the real regtest node must mine past it first.
- Orchard actions (the wallet sends Ironwood).

#### Harness facts: a pruned node, an archive node and zaino (2026-10-26, v1.6.0, macOS arm64)

Measured while building `tests/regtest/harness/zaino.rs` (ROADMAP.md M2, sixth item, step 2).

- **Pruning starts about 2,000 blocks deep, not 1,001.** A pruned node counts `tx_retention` from its *finalized* tip, and a block is finalized 1,000 deep. So `pruneheight` is `tip - 1000 - (tx_retention - 1)` once that is positive, and 0 before. With `tx_retention = 1001`:
  - at tips 1,100, 1,200 and 1,500, `pruneheight` was 0;
  - at tip 2,100 it was 100, and `getblock("50", 0)` answered `-8 "Block not found"`.

  So a regtest scenario must mine past tip 2,001 before the node prunes block 1. `getblockchaininfo.header_chain.finalized.height` shows the finalized tip (100 at tip 1,100). The harness constant is `gyges_regtest::FINALITY_DEPTH`.
- **Only the newest 1,000 blocks are in the non-finalized backup.** Finalized blocks leave `state/non_finalized_state/<net>/`, so a wait for "every block in the backup" never ends on a chain longer than 1,000. `Node::wait_for_backup` now waits for the non-finalized blocks only.
- **Two regtest nodes peer, but slowly.** With `p2p_stack = "legacy"` and the second node's `initial_testnet_peers = ["127.0.0.1:<first node's listen_addr>"]`, the second node connected at once (`getpeerinfo`). It first reported the 20 blocks mined on the first node 27 s later.
- **`submitblock` copies blocks quickly and in order.** `getblock(h, 0)` on one node and `submitblock` on the other: the answer is `null` for an accepted block. 1,100 blocks took 34 s from a shell loop and well under that from the harness. Mining 2,100 blocks, copying them and waiting for zaino takes about 20 s in all. The harness copies after every 100 mined blocks, far inside the 2,000-block pruning depth.
- **zaino follows an archive node fed by `submitblock`** and serves blocks below the pruned node's `pruneheight`, with hashes equal to the pruned node's `getblockhash`. After an archive-node restart, restarting zaino is enough: it serves new blocks again.

The harness therefore runs the three as `gyges_regtest::Fallback`:
- the pruned node, which mines and takes broadcasts;
- the archive node, which receives blocks by `submitblock` and has no peers;
- zaino in front of the archive node, restarted with it.

One consequence: a transaction broadcast through zaino (`--via-tor`) reaches only the archive node's mempool, and nothing mines there.

---

## 5. Missing Documents

A wallet that holds spending keys needs more than an architecture sketch and a command list. Recommended additions, in order of leverage:

- [x] **`README.md`** — what Gyges is, who it is for, status (pre-alpha, nothing implemented), how it relates to Zakura, and a pointer to the other docs. *Written (revision 3).*
- [x] **`THREAT_MODEL.md`** — adversaries (malware running as the same user, a compromised archival lightwalletd, a malicious Zakura node, a stolen laptop at rest, a stolen laptop while unlocked), what each can learn or steal, and which design choice mitigates each. This will immediately surface the UDS-authentication question (Q-S1). *Written as a first draft from Q-S1…S7 and Q-K7 (revision 3). Reviewed 2026-10-21 and promoted from draft: §5 re-verified against the M1 code, §6 turned into decisions plus four items that still need verification, each assigned to a milestone.*
- [x] **`proto/gyges.proto` + `API.md`** — the full gRPC service, including streaming events, error details, and versioning policy between `gyges` and `gygesd`. *Written (revision 3): 39 RPCs in one `gyges.v1.Gyges` service, typed `GygesError`, `UnlockScope { CONNECTION, DAEMON }`; validates with `protoc` and compiles through `tonic-prost-build` in `gyges-proto`. Deviations from the proposals are listed at the end of `API.md`.*
- [x] **`DATA_MODEL.md`** — `profile.json` schema, `config.toml` schema with defaults, what lives in `wallet.sqlite` beyond the upstream schema (labels, ZIP-320 queue, pending Keystone sessions), and the migration policy. *Written (revision 3) with `CREATE TABLE` statements for `gyges_tex_queue`, `gyges_signing_sessions`, `gyges_address_labels`, `gyges_transparent_received_outputs`, `gyges_meta` and the block cache; the `config.toml` example is parsed by CI.*
- [x] **`SYNC.md`** — the state machine for each key: initial state from `z_gettreestate`, backend selection, reorg handling, pruning-race handling, handoff validation, and what "synced" means. *Written (revision 3) from Q-Y1…Y6, Q-D1 and Q-D4; three items marked needs verification (finality depth, `z_getsubtreesbyindex` on pruned ranges, coverage of a Tor-sourced birthday treestate).*
- [x] **`TESTING.md`** — regtest harness, how Keystone is tested without hardware (recorded UR fixtures), how Tor fallback is tested (a local lightwalletd), and property tests for the PCZT pipeline. *Written (revision 3): tiers, harness design, an 18-scenario table, Keystone fixtures, redaction test, CI gates.*
- [x] **`ROADMAP.md` / MVP cut** — see §7. *Written (revision 3): milestones M0–M6, M1 is the MVP.*
- [x] **`GLOSSARY.md`** — UFVK, USK, PCZT, ShardTree, retention height, ephemeral address, `tex1`, BC-UR. The current documents assume the reader knows all of them. *Written (revision 3), 55 entries.*

---

## 6. Open Questions and Proposed Solutions

Grouped by area. Each question is a checkbox; it is checked when a concrete proposal is written under it. A checked box means "there is a proposal to review", not "decided": every proposal below is open for feedback, and the ones marked **needs verification** rest on a fact that should be confirmed against the Zakura or Keystone source before code is written.

### Dependencies and node (D)

- [x] **Q-D1.** Which RPC and field exposes the retention height on Zakura? Native API, zcashd-compat API, or both? *Blocks §3.1 entirely.*

  **Proposed solution.** Verified against `crates/zakura-rpc/src/methods.rs`: `getblockchaininfo` returns `pruned: bool` and, only when `pruned` is true, `pruneheight`, "the lowest height whose block body this node still stores". Zakura prunes only raw transaction data; headers, txids and consensus state are kept below `pruneheight`, and the genesis block is never pruned. There is no dedicated pruning RPC. Retention is configured as `state.storage_mode.pruned.tx_retention` (default and minimum 10,000 blocks on mainnet and testnet, enforced at node startup). Design: `ChainBackend::node_bounds() -> NodeBounds { tip_height, tip_hash, retained_from }` where `retained_from = pruneheight` if `pruned`, else `0`; keep a defensive fallback that treats a "block not available" error from `getblock` as a signal to re-poll bounds rather than binary-searching, since the field is authoritative. `gyges daemon status` shows both values and the node's `tx_retention`.
- [x] **Q-D2.** Will Gyges target Zakura's native RPC or its zcashd-compat mode?

  **Proposed solution.** Target Zakura's native JSON-RPC and nothing else. Verification showed the premise of the question was wrong: Zakura has no second RPC dialect. Its native JSON-RPC is the Zebra-derived zcashd-style API, and "zcashd-compat mode" (`zakurad start --zcashd-compat`) means running a real `zcashd` binary as a P2P sidecar for wallet and ZMQ users, which Gyges does not need. Every method the pipeline uses (`getblockchaininfo`, `getblockhash`, `getbestblockhash`, `getblock(h, 0)`, `getrawtransaction`, `z_gettreestate`, `z_getsubtreesbyindex`, `getrawmempool`, `sendrawtransaction`) exists on the native API and is classified `Unauthenticated`, so Gyges works both with cookie auth (`enable_cookie_auth = true`, HTTP Basic from `~/.cache/zakura/.cookie`, the default) and against an unauthenticated listener. Two additions worth designing for: (1) Zakura's optional **indexer gRPC** (`[rpc] indexer_listen_addr`, `indexer` build feature) streams `get_block_range` raw blocks, `chain_tip_change` and `mempool_change` events; `ZakuraRpcBackend` should use it when present and fall back to polling JSON-RPC otherwise; (2) `z_getsubtreesbyindex` and `z_gettreestate` already expose an `ironwood` pool alongside Sapling and Orchard (see Q-D7). Remove the "native vs compat" branch from `ARCHITECTURE.md` and the `ChainBackend` trait.
- [x] **Q-D3.** How are Zakura crate upgrades tracked while everything is `-rc`?

  **Proposed solution.** Exact pins (`=0.1.0-rc9`, `=3.0.0`) for every `zakura-*` crate in `[workspace.dependencies]`, with `Cargo.lock` committed and CI running `cargo build --locked`. Bumps are deliberate, one PR per Zakura release, and must pass the regtest suite (Q-O2). Use `[patch.crates-io]` pointing at a git revision only on feature branches, never on `main`. A short `docs/ZAKURA_VERSIONS.md` records which Zakura release each Gyges tag was built against. Note from the crates.io check (§4.2): the wallet-libraries `rc9.1` / `rc7` crates pin the common crates at `=4.0.0-rc2`, so Gyges pins exactly that and moves only when wallet-libraries publishes a release that does. **Implemented:** `Cargo.toml` carries the pins with the policy as a comment and `Cargo.lock` is committed.

- [x] **Q-D4.** Should Gyges build on `zakura-wallet-lib` and the `sync` feature rather than its own `SyncScheduler` and `TxEngine`?

  **Proposed solution.** Not `zakura-wallet-lib`: it is a 33-line `no_std` facade that re-exports either the upstream or the Zakura crates behind a feature flag, and its own README says "an end consumer that builds for exactly one stack does not need this crate at all". Depend on `zakura-client-backend`, `zakura-client-sqlite` and `zakura-pczt` directly with `package =` renames. The `sync` feature is only partly reusable: `sync::run` is bound to a lightwalletd `CompactTxStreamerClient` (its `client` parameter must implement the tonic `GrpcService`), so it cannot be fed from node RPC, but everything underneath it is source-agnostic: `BlockSource`, `BlockCache` (gated behind the `sync` feature, which is therefore enabled; §4.2), `scan_cached_blocks`, `suggest_scan_ranges`, `update_chain_tip`, `put_sapling_subtree_roots` and the continuity-error truncation loop documented in the `data_api::chain` module. Proposal: (a) implement `BlockCache` once (Q-Y3) and a `CompactBlockSource` trait with `latest_block()`, `subtree_roots()`, `block_range()`, with one implementation over node RPC (building `CompactBlock`s from `getblock(h, 0)`) and one over Tor lightwalletd; (b) port the ~300-line loop body of `sync::run` onto that trait rather than designing a scheduler from scratch; (c) enable the `spend-index` feature, which exists precisely "for consumers that have access to a spent-outpoint index (e.g. a full node's spend index)", so transparent spent-ness checks go to the node. If Zakura later inherits Zebra 6.4's experimental `CompactTxStreamer` server (`rpc.lightwalletd_listen_addr`), `sync::run` can be used unchanged for Case A and the custom loop shrinks to the Tor route. `TxEngine` stays thin: `propose_transfer` / `propose_standard_transfer_to_address` / `create_proposed_transactions` already do input selection, ZIP 317 fees and multi-step ZIP 320 proposals; Gyges adds PCZT role orchestration and the `TexQueue` broadcaster.
- [x] **Q-D5.** Which archival lightwalletd/zaino endpoints are acceptable defaults, and is shipping a hard-coded third-party URL acceptable for a privacy-focused wallet?

  **Proposed solution.** No hard-coded endpoint in the binary. `fallback_lightwalletd.grpc_url` is required when `enabled = true`, and the generated `config.toml` template lists a few well-known public endpoints as commented-out examples with their operator named (the ECC and community endpoints that Zashi uses) so the user makes an explicit choice. The first restore that needs backfill prompts once: "N blocks below the node's retention height must be fetched over Tor from `<url>`; continue? [y/N]" (`--yes` for scripts). Prefer `.onion` endpoints when the operator offers one (the `tor` feature enables `onion-service-client`), since they remove the exit-node hop. Document what the endpoint learns even over Tor: the requested block range (an approximate birthday) and, for transparent recovery, any addresses queried via `GetAddressUtxos`. Power users should run their own `zaino` and point the fallback at it.

- [x] **Q-D6.** Are the "14x" and "1.5x" numbers reproducible with the `*-asm` features, and what is the fallback on CPUs without BMI2/ADX?

  **Proposed solution.** Add a workspace feature `perf` that enables `zakura-pasta-curves/{x86_64-asm | aarch64-asm, multicore}`, `zakura-orchard/{x86_64-asm | aarch64-asm, multicore}` and `zakura-proofs/multicore` via `[target.'cfg(target_arch = "x86_64")'.dependencies]` blocks, on by default in release builds. Add `gyges-core/benches/prove.rs` (Criterion) that proves a 2-action Orchard bundle and trial-decrypts 1,000 compact outputs, and record results per CPU in `docs/BENCHMARKS.md`; replace "14x" and "1.5x" in `ARCHITECTURE.md` with a link to that table. The fallback question depends on whether the assembly paths do runtime feature detection (`is_x86_feature_detected!`) or assume BMI2/ADX unconditionally; until that is checked in the `zakura-pasta-curves` source, publish release binaries with the `portable` feature and let `perf` be a documented opt-in build flag. If runtime detection is confirmed, flip the default.

- [x] **Q-D7 (new, found during verification).** The Zakura node, wallet libraries and Keystone firmware all expose an **Ironwood** shielded pool (`z_getsubtreesbyindex` accepts `"ironwood"`, upstream `Step` has `ironwood_action_count`, Keystone signs Ironwood spends). Neither design document mentions it. What is the policy?

  **Proposed solution.** Treat pool support as data, not as code paths: `spend_pools` and `receive_pools` in `profile.json` (Q-K1), a `pools` list in `address new --receivers`, and per-pool rows in `balance`, so adding Ironwood is configuration plus the upstream crate's support rather than a redesign. For the MVP keep Orchard+transparent, make Sapling receive-only, and leave Ironwood off until the upstream wallet APIs for it are out of `-pre`; add a glossary entry and a one-paragraph note in `ARCHITECTURE.md` so readers are not surprised by the field in RPC responses. **Revised (§4.3, 2026-10-21):** "off" turned out not to be a choice. After NU6.3 the wallet libraries build every shielded output in the Ironwood pool and the ZIP 318 turnstile keeps value out of Orchard, so the MVP spends Orchard, Ironwood and transparent and receives Ironwood, Sapling and transparent (Orchard notes are spent, never created).

### Synchronisation (Y)

- [x] **Q-Y1.** How is a reorg detected and handled on each backend? How deep a reorg is tolerated?

  **Proposed solution.** Detection: (1) every poll compares the node's `getbestblockhash` chain against the stored hash at `scanned_tip` (the `blocks` table keeps block hashes); (2) the scanner's `ScanError::PrevHashMismatch` on a batch whose first block does not link to the stored tip. Handling: walk back with `getblockhash(h)` versus stored hashes to find the fork point `f`, call `WalletWrite::truncate_to_height(f)` (notes, nullifiers, ShardTree checkpoints are all rewound by the upstream implementation), and resume scanning from `f + 1`. Tolerance: the node itself cannot reorg deeper than its finality depth (100 blocks on the Zebra lineage), so Gyges searches at most 100 blocks for a fork point; if none is found the chain is inconsistent with the wallet's view and the key enters `SyncState::Stalled(ChainInconsistent)`, surfaced in `sync status` and fixable with `sync run --from <h>`. If the fork point lies below `retained_from`, the rewind goes through the Tor backfill path (Q-Y2). Unmined transactions survive truncation in the `transactions` table and are re-evaluated against their `expiry_height`.

- [x] **Q-Y2.** What happens when the node prunes past a slow Case A scanner's position?

  **Proposed solution.** State the invariant explicitly: Case A requires `scanned_tip + 1 >= retained_from`. It is checked before each batch and whenever a `getblock` returns the pruned error. On violation the scheduler switches that key to Case B for `[scanned_tip + 1, retained_from)` if a fallback endpoint is configured and the daemon is not air-gapped, logs a warning, and continues; otherwise the key enters `SyncState::Stalled(PrunedPastScanTip)`, `sync wait` exits non-zero, and `daemon status` explains the fix. Prevention: at startup `gygesd` compares the node's retention window with the longest gap it would have to close and warns if the window is under a configurable minimum (`min_retention_blocks`, default 10,000 ≈ 9 days at 75 s blocks). The daemon keeps all keys at the tip while running, so the race only matters after downtime.

- [x] **Q-Y3.** Is there a shared `CompactBlock` cache across key profiles, and what is the disk budget?

  **Proposed solution.** Yes, one cache per network at `~/.gyges/<network>/cache/blocks.sqlite` (schema: `height INTEGER PRIMARY KEY, hash BLOB, prev_hash BLOB, source TEXT, data BLOB`) implementing the upstream `BlockCache` trait, so `scan_cached_blocks` works unchanged. A single `BlockFetcher` task fills `[min(scanned_tip) + 1, tip]` and every key's scanner reads from the cache; the node is asked for each block once regardless of how many profiles exist. Eviction: a block is deletable once every registered key has scanned it, with `cache.retain_blocks = 1000` kept behind the slowest key for cheap rewinds and `cache.max_mb = 2048` as a hard cap (compact blocks are a few KB each on average, so the cap is generous). Tor-fetched ranges are cached too, so a second restore with a similar birthday does not hit the network again, with a documented privacy trade-off: the cached range reveals approximate birthdays, so cache files are 0600 and `cache.keep_historical = false` drops Tor-fetched ranges once consumed.

- [x] **Q-Y4.** What does `sync wait` wait for exactly?

  **Proposed solution.** Define "synced" in terms the upstream API already exposes: a key is **scanned** when `scanned_tip >= chain_tip`, and **spendable** when additionally `WalletRead::suggest_scan_ranges()` returns no range with priority above `Ignored`, i.e. all `ChainTip`, `FoundNote` and `Historic` gaps that affect witnesses are closed. `sync wait` defaults to `--until spendable`; `--until scanned` is the cheaper check for scripts that only need the tip. `--confirmations N` is redefined to require `--txid <TXID>` and waits until that transaction has `N` confirmations, which is what scripts actually want after a send. Both `sync status` and the `GetSyncStatus` RPC expose the two booleans so the CLI never computes them itself.

- [x] **Q-Y5.** How is the handoff frontier at `retention_height` validated against the node to catch a lying or buggy lightwalletd?

  **Proposed solution.** Validate *inside* the node's retention window, not at its edge. Verification showed a pruned Zakura node returns `HistoricalTreeUnavailable` from `z_gettreestate` for heights whose bodies are pruned, so the Tor stream must overlap the node by a few blocks: stream `[birthday, retained_from + k]` with `k = 10`, then at `V = retained_from + k` run three checks against the trusted local node: (1) **tree roots**: `z_gettreestate(V)` final-state Sapling and Orchard frontiers must have the same root and leaf count as the ShardTree checkpoints built from the stream; any omitted, injected or reordered commitment changes the root, so this alone defeats an endpoint that hides or forges outputs; (2) **hash chain**: the stream must link by `prev_hash`, and `getblockhash(h)` (which works for every height on a pruned node, since headers are kept) must match the stream's hash at `V` and at `retained_from`; (3) **subtree roots**: every completed subtree root from `GetSubtreeRoots` must equal `z_getsubtreesbyindex` for the same index, expected to work for pruned ranges because the commitment tree is consensus state, but to be confirmed on a pruned node. On failure the daemon truncates the key back to its birthday, marks the endpoint `untrusted` in `daemon status`, and refuses further backfill from it until the config changes. Transparent history is the residual gap in two directions: a pruned node's address indexes are explicitly unreliable (`getaddressutxos` and friends stop being maintained in pruned mode), and compact blocks carry no transparent outputs. Above `retained_from` Gyges sees full raw blocks in Case A and can index its own transparent outputs directly while building compact blocks; below it, `GetAddressUtxos` over Tor is the only source and cannot be root-checked, so each returned UTXO's transaction is fetched and its inclusion verified against a block hash the node confirms.
- [x] **Q-Y6.** Will `sync mempool` run continuously in the daemon or only on demand?

  **Proposed solution.** Continuously but cheaply. If the node's indexer gRPC is enabled, subscribe to its `mempool_change` stream (Added / Invalidated / Mined events with txid) and fetch only added transactions with `getrawtransaction`; otherwise, on every `poll_interval_secs` tick call `getrawmempool`, diff against seen txids, and fetch only the new ones. Trial-decrypt new transactions for every key. Load on a local node is negligible, and the request pattern is identical whether or not the wallet has activity, so it leaks nothing the block requests do not already. `mempool.scan = true` in config turns it off for users who do not want unconfirmed balances; `gyges sync mempool` forces an immediate pass. Decrypted unconfirmed notes are stored unmined and shown under "Pending Confirmation" in `balance`; `tex_queue` (Q-T1) consumes the same events.
### Keys, vault and security (S)

- [x] **Q-S1.** Who may connect to `gygesd.sock`?

  **Proposed solution.** Three layers. (1) **Peer credentials, always**: the daemon reads `SO_PEERCRED` / `LOCAL_PEERCRED` on every accepted connection and rejects any uid other than its own (or, in the hardened deployment below, any uid not in an allow-list). (2) **Connection-scoped unlock**: `UnlockKey` does not make the key globally unlocked; it creates a *signing session* bound to the calling connection and returns a random 32-byte `session_token`. Only RPCs that present the token (`SendTransaction`, `SignPczt`, `ExportSeed`) can use the decrypted key, and the session is destroyed when the connection closes or the TTL expires, whichever is first. Malware with socket access therefore cannot ride on another process's unlock window; it must obtain the passphrase or steal the token from the CLI process, which is the same bar as reading the passphrase from the terminal. (3) **Hardened deployment, documented**: run `gygesd` as a dedicated user, socket mode 0660 with a `gyges` group, so a compromise of the interactive user cannot even read `seed.age` or `wallet.sqlite`. Same-user malware that replaces the `gyges` binary or keylogs the passphrase is explicitly out of scope and said so in `THREAT_MODEL.md`.

  **Decision (2026-10-21).** Accepted. Landed as `gygesd::policy::PeerPolicy` (uid check in the accept loop and again in a tower layer), `daemon.allowed_uids`, connection-scoped unlocks with 32-byte tokens in `gyges_core::vault::manager::VaultManager`, and `daemon.socket_group` for the 0660 socket. One amendment: the CLI's inline `tx send` uses passphrase signing sessions (`UnlockKey { session_id }`) rather than connection tokens, so tokens are an API-level mechanism for other clients; the hardened deployment is documented, its tooling is M6 (`THREAT_MODEL.md` §6 items 4 and 5).

- [x] **Q-S2.** Is the passphrase sent over the UDS acceptable, or should key derivation happen in the CLI?

  **Proposed solution.** Send the passphrase over the socket. A Unix socket is kernel-local and not observable by other same-user processes without `ptrace`, which is the same assumption `ssh-agent` and `gpg-agent` make. Deriving in the CLI would require the CLI to read `seed.age`, putting key material in two processes and breaking the "daemon-only key material" property, which is worse. Mitigations: the request field is a `SecretString` zeroized after use, marked `[debug_redact = true]` in the proto so it never appears in logs, and the daemon rate-limits failed unlock attempts (exponential back-off per key) so the socket cannot be used as a passphrase oracle.

  **Decision (2026-10-21).** Accepted as proposed: `[debug_redact = true]`, `SecretString` moved out of the request first thing, per-key back-off of 1 s doubling to `vault.unlock_backoff_max`, proven to survive a reconnect (`rpc.rs::wrong_passphrases_are_rate_limited_per_key`).

- [x] **Q-S3.** When does the unlock TTL start?

  **Proposed solution.** Prompt as late as possible and hold the key as briefly as possible. `SendTransaction` is a server stream whose order is: propose → report the proposal (`Proposed` event) → prove (works while locked for Orchard and transparent) → emit `SignatureRequired { key_id, kind: Passphrase | Keystone, session_id }` → the client unlocks or supplies the Keystone result → sign → broadcast. The USK is held only across the signing step and dropped immediately after, independent of any TTL. For the explicit `gyges key unlock --timeout` path (batch scripts) the TTL is a plain idle timer starting at unlock. One config key, `vault.unlock_ttl = "5m"`, is the single source of truth and the "60 s" in `ARCHITECTURE.md` is removed. Exception: a Sapling spend needs the proof generation key *before* proving (Q-K3), so for proposals with Sapling inputs the `SignatureRequired` event is emitted before the proving step instead; and if a session expires mid-flow the daemon emits `SignatureRequired` again rather than failing, so a slow proof never costs the user a retry from scratch.

  **Decision (2026-10-21).** Accepted. `vault.unlock_ttl` is the single source of truth and the "60 s" is gone from `ARCHITECTURE.md`. The signing step derives the `UnifiedSpendingKey` from the entropy and moves it into the signing task, so it is out of scope before verification and broadcast (`gygesd::tx`); the re-prompt on session expiry is implemented (`obtain_key` loops with a fresh `SignatureRequired` while the proposal can still be mined). The Sapling exception waits for M6. One fact found in review: the upstream key type does not zeroize on drop (`THREAT_MODEL.md` §6 item 10).

- [x] **Q-S4.** Should `key export-seed` exist at all?

  **Proposed solution.** Keep it, because users need a backup path after `key init` (which must also display the mnemonic once and require the user to type three random words back before continuing). Constraints: TTY required (exit 4 otherwise); the passphrase is supplied in the same `ExportSeed` request and never reused from an existing session; the user must type the literal phrase `reveal seed` to confirm; output goes to the terminal only, never to `--json`, never to a file; the call is written to the audit log (Q-O1) with key id and time only; and `vault.allow_seed_export = false` in config disables the RPC entirely for hardened deployments.

  **Decision (2026-10-21).** Accepted in full: TTY required on all three streams, passphrase in the request and never from a session, the literal `reveal seed`, no `--json`, an audit event, and `vault.allow_seed_export = false` to disable the RPC; `key init` shows the mnemonic once and asks for three random words back.

- [x] **Q-S5.** What is the at-rest encryption design given `age` is scrypt-only?

  **Proposed solution.** Keep `age` as the container, because a standard format that `rage` can decrypt independently is a real recovery benefit, and accept scrypt: age's passphrase recipient uses scrypt with a tunable work factor; pin it to a value that takes ~1 s on a modern laptop and record it in `profile.json` (`seed_format = "age-scrypt-v1"`) so it can be raised in a migration. Encrypt the 32-byte BIP-39 *entropy* (the mnemonic is recoverable from it), not the 64-byte derived seed, so the exported backup is the same words the user wrote down. If Argon2id becomes a hard requirement, the compatible construction is: derive a 32-byte secret from the passphrase with Argon2id, use it as an age X25519 identity, and encrypt `seed.age` to that identity's recipient; the file is still a valid age file, only the identity derivation is Gyges-specific. Not recommended for v1 since it loses `rage`-compatible recovery.

  **Decision (2026-10-21).** Accepted: age with one scrypt recipient at `vault.scrypt_work_factor`, recorded as `seed_format = "age-scrypt-v1"`, over the 32-byte entropy. The Argon2id construction is not pursued; `rage -d` recovers the words because `rage` is the CLI of the same `age` crate.

- [x] **Q-S6.** Are `wallet.sqlite` contents considered sensitive at rest?

  **Proposed solution.** Yes: the database reveals the full financial history, memos and address set without the seed. For v1, state the assumption in `THREAT_MODEL.md`: at-rest confidentiality of `wallet.sqlite` relies on OS full-disk encryption plus 0700/0600 permissions, and the daemon must be able to scan while the vault is locked, which rules out encrypting the database under the vault passphrase. Provide `gyges key delete --wipe` (best-effort overwrite then unlink). As a later option, support SQLCipher via rusqlite's `bundled-sqlcipher` with a per-key random database key stored in the OS keychain (macOS Keychain, Linux secret-service); that keeps background scanning working and protects the file when copied off the machine, at the cost of a platform-specific dependency.

  **Decision (2026-10-21).** Accepted: v1 relies on full-disk encryption plus 0700/0600, stated in `THREAT_MODEL.md` §3 row 4; `key delete --wipe` and optional SQLCipher (database key in the OS keychain only, never under the vault passphrase) are M6.

- [x] **Q-S7.** What is the policy for file permissions and backups?

  **Proposed solution.** `~/.gyges` and every subdirectory 0700, every file 0600, socket 0600 (0660 in the hardened deployment); the daemon refuses to start if it finds wider permissions, as `sshd` does, with a one-line fix in the error. Backups: the minimal backup is the mnemonic plus birthday height, since `wallet.sqlite` is derived state and ZIP 320 ephemeral addresses are recovered by gap-limit scanning. For convenience add `gyges key backup --id X -o X.tar` which runs a SQLite `wal_checkpoint(TRUNCATE)`, then archives `profile.json`, `seed.age` and optionally `wallet.sqlite`; and `gyges key import-backup`. Copying `keys/<id>/` by hand is supported only while the daemon is stopped (WAL files), and the docs say so.

  **Decision (2026-10-21).** Accepted: the 0700/0600 sweep runs at every start with the one-line `chmod` in the error, the daemon's umask is 077, and the registry re-checks each key directory on load and after creation. `key backup` / `key import-backup` and the documented by-hand copy rule are M6.

### PCZT and hardware signing (K)

- [x] **Q-K1.** Which pools does Keystone 3 Pro actually sign for?

  **Proposed solution.** Verified from the firmware source README and protocol docs: Keystone signs **Orchard** and **Ironwood** spends and checks **transparent** inputs in the single-PCZT flow; it does **not** sign Sapling spends ("proof generation requires signer participation, but Keystone lacks the necessary computational capacity"), though Sapling outputs are tolerated. The batch-signing flow is stricter and rejects transparent inputs and any Sapling component. Shielded support needs the Cypherpunk firmware edition; the Multi-Coin edition is transparent-only. The exported UFVK carries only transparent and Orchard components, so a Keystone profile can never receive Sapling funds through its own addresses. Design: `profile.json` carries `spend_pools = ["orchard", "ironwood", "transparent"]` for Keystone profiles and input selection is restricted to it; addresses default to `--receivers orchard,transparent`; `key import-keystone` records `device_version` from the UR payload and refuses firmware older than the minimum Zodl requires. ZIP 320 Step 2 is a transparent-only transaction, which the single-PCZT flow should accept, but no Keystone document mentions TEX, so this is marked **needs verification on hardware** before `tx send --to tex1…` is enabled for Keystone profiles.
- [x] **Q-K2.** How does the host ingest the signed PCZT from the Keystone?

  **Proposed solution.** QR only, confirmed: Keystone's Zcash flow has no USB or file transport, and Zodl (formerly Zashi) scans the device with the phone camera. Two decisions follow. (1) **Use the batch-signing protocol for pure shielded sends.** `zcash-sign-batch` (tag 49205) sends the PCZTs and `zcash-batch-sig-result` (49207) returns only `(pool, action_index, 64-byte signature)` tuples, so the return payload for a typical send is a single QR frame that can be scanned once or even typed. The host applies the signatures to its own proven copy (upstream provides `redact_pczt_for_batch_signer` and `extract_orchard_spend_auth_signatures`), so no multi-frame return and no Combiner. The single-PCZT flow (`zcash-pczt`, 49204, full PCZT back with signatures inserted) is kept only for transactions with transparent inputs, which batch mode rejects: shielding and ZIP 320 Step 2. (2) **Two input paths on the host**: `gyges pczt qr-scan` uses the laptop camera (`gyges-qr` gains a decoder built on a capture crate plus a pure-Rust QR decoder, feeding the `ur` fountain decoder until complete) and is used automatically by `tx send` when a camera is present; `gyges pczt qr-import --from-file frames.txt` or stdin accepts one `ur:…` frame per line as exported by any phone QR app, for headless machines. Positional `qr-import <FRAME>…` stays for single-frame payloads, which with batch mode is the common case. The signing session (Q-K4) records which protocol and path was used.
- [x] **Q-K3.** Sapling proving needs the proof generation key. Which option?

  **Proposed solution.** Option (b) for seed profiles, option (a) for everything else, implemented through mechanism (c). Concretely: the MVP spends from Orchard and transparent only (matching §7). When Sapling spending is enabled for `LocalEncryptedSeed` profiles, a proposal containing Sapling inputs requires an unlock *before* proving; the daemon then runs the PCZT **Updater** role to insert each Sapling spend's `proof_generation_key` into the PCZT (ZIP 374 defines this field), proves, signs, and drops the key. `KeystoneQr` and `WatchOnly` profiles have `spend_pools` without `sapling` (Q-K1), so the question never arises for them. Air-gapped signing boxes hold the seed, so they can prove Sapling after unlocking; the online watch-only side only creates the PCZT. Rename "proving-only" in `CLI_SPEC.md` to "Orchard proving-only" and state the rule in one place in `ARCHITECTURE.md` §3.2. **Revised (§4.3, 2026-10-25):** the MVP spends Orchard, Ironwood and transparent, not Orchard and transparent only (see the revision under Q-D7). Ironwood is spent and received since M1: in `scenarios/node.rs::restore_mine_shield_send_and_reorg_against_the_real_node` `tx shield` lands in Ironwood, the payment to the second key is spent from it, and that key's note is listed as `POOL_IRONWOOD`; `rpc.rs::tx_engine_shields_spends_orchard_and_pays_transparent_through_the_fake_node` checks the Ironwood balance at each step. The Sapling reasoning above is unchanged.

- [x] **Q-K4.** Where does the Combiner step run after Keystone returns the signed PCZT, and how is it correlated?

  **Proposed solution.** In the daemon, against a persisted session. New table `signing_sessions (session_id TEXT PK, key_id, protocol, created_at, expires_at, status, proven_pczt BLOB, sent_payload_hash BLOB, request_id BLOB, proposal BLOB)`. `SendTransaction` stores the proven PCZT and emits `SignatureRequired { session_id }`; the CLI's `CompleteKeystoneSign { session_id, payload }` looks up the row and dispatches on `protocol`: for **batch** results, the echoed `request_id` in `zcash-batch-sig-result` must match the row, and each `(pool, action_index, signature)` is applied to the stored proven PCZT; for **single-PCZT** results, the daemon runs **Combiner** (proven ⊕ signed; the upstream Combiner rejects structurally different PCZTs, which is the correlation check). Both paths then run **Verifier** to confirm the effects still match the stored proposal (Q-K7), then **Spend Finalizer** and **Tx Extractor**, then broadcast. Sessions survive daemon restarts, expire after `vault.signing_session_ttl = "24h"`, show in `tx list` as `awaiting-signature`, and can be listed and aborted with `gyges tx sessions` / `gyges tx abort <session_id>`. The same mechanism serves the non-interactive case in Q-C4. `ARCHITECTURE.md` §3.4 should also drop "extracts the birthday height" from the import step: verified, `zcash-accounts` carries `seed_fingerprint`, a list of `{ufvk, index, name}` and an optional `device_version`, and no birthday; Zodl asks the user for it. `key import-keystone` should require `--birthday` or prompt, defaulting to the NU5 activation height (1,687,104 on mainnet) because an Orchard-only key cannot have received shielded funds earlier.
- [x] **Q-K5.** In `--airgapped` mode the daemon has no chain state. Does `pczt prove` receive anchors and witnesses inside the PCZT, and how are files moved?

  **Proposed solution.** Yes: a PCZT produced by the online side after the Constructor and Updater roles contains, per spend, the note, `rseed`, Merkle `witness` and `anchor`, which is everything the Prover and Signer need; the air-gapped box needs no database at all. Introduce a fourth profile mode, `SignerOnly`, which has `seed.age` and `profile.json` but no `wallet.sqlite`, and is the only mode `--airgapped` requires. Transport: the primary path is a binary `.pczt` file (the `pczt` crate's postcard serialization) moved by USB stick or SD card: `gyges pczt create … -o tx.pczt` online → `gyges pczt prove tx.pczt | gyges pczt sign -o tx.signed.pczt` offline → `gyges pczt broadcast tx.signed.pczt` online. QR in both directions (`qr-export` / `qr-scan`) is supported for small transactions but a proven Orchard action is several kilobytes, so it is documented as slow. The online side runs Verifier before broadcast exactly as in Q-K4, so a tampered file is caught.

- [x] **Q-K6.** Are the CBOR tags (49201, 49204) confirmed against the `ur-registry` version Gyges will pin? Is there a UFVK type to accept too?

  **Proposed solution.** Confirmed from `keystone-sdk-rust` `registry_types.rs`: `zcash-accounts` 49201, `zcash-full-viewing-key` 49202 (a constant only, no implementation; treat as reserved), `zcash-unified-full-viewing-key` 49203, `zcash-pczt` 49204, `zcash-sign-batch` 49205, `zcash-sign-result` 49206 (SDK-only, not documented for firmware), `zcash-batch-sig-result` 49207. Pin `ur-registry` at the current `1.0.x` (the `0.2` in `Cargo.toml` is stale) and `ur` at `0.5`, take the constants from the crate, and add a unit test in `gyges-qr` asserting the seven values so a registry change fails CI. `key import-keystone` accepts `ur:zcash-accounts` (the device's export), a bare `ur:zcash-unified-full-viewing-key`, and a plain `uview1…` string.
- [x] **Q-K7.** Is the host trusted or is the device the root of trust?

  **Proposed solution.** The device is the root of trust for *what gets signed*; the host is the root of trust for *what gets broadcast*, and each checks the other. Against a compromised host the only defense is the Keystone display, so the Redactor must remove proofs and witnesses but never amounts, recipients or memos the device shows; `ARCHITECTURE.md` §3.4 should say which fields are redacted. Against a compromised or buggy device, the daemon runs the PCZT **Verifier** after Combining (Q-K4) and refuses to broadcast if any output, amount, fee or anchor differs from the stored proposal, and `tx send` prints the same summary the device shows so the user can compare. Document both directions in `THREAT_MODEL.md`.

  **Decision (2026-10-21).** Accepted. The Verifier exists as `gyges_core::tx::verify` (outputs, change totals, fee and expiry against the approved proposal) and already runs after the local signing step; Combiner, the Redactor's documented field list and the device-summary comparison come with M5, the `.pczt` path with M4. Found in review: the upstream Signer role does not check change ownership, so `pczt sign` must (`THREAT_MODEL.md` §6 item 8, `ROADMAP.md` M4).

### ZIP-320 / `tex1` (T)

- [x] **Q-T1.** What is persisted between Step 1 and Step 2, and how is a stranded ephemeral UTXO recovered?

  **Proposed solution.** Lean on upstream first. A `tex1` recipient makes `propose_standard_transfer_to_address` return a two-step `Proposal` ("depending upon the recipient address, more than one transaction may be constructed"); `create_proposed_transactions` builds both transactions, with Step 2 consuming Step 1's transparent output through `prior_step_inputs` (only transparent outputs of a step may be spent by a later step), stores both and returns both txids. The wallet tracks ephemeral receivers (`get_ephemeral_transparent_receivers`, with an exposure depth and used-flag) so the ephemeral address is known *before* anything is broadcast. ZIP 320 itself only mandates that wallets MUST recognise and be able to spend funds returned to an ephemeral address and SHOULD derive them from the ZIP 32 seed; the derivation path and gap limit are librustzcash implementation details, not ZIP text, and should be cited as such in `ARCHITECTURE.md`. What Gyges adds is the broadcaster, which is what `TexQueue` should be defined as: a durable table `tex_queue (step1_txid PK, step2_txid, step1_raw BLOB, step2_raw BLOB, state, created_at, last_attempt_at, attempts, last_error)` with states `built → step1_broadcast → step2_broadcast → step1_mined → step2_mined (done) | expired | failed`. On startup and on every poll (or `mempool_change` event) the queue re-checks each non-terminal row against the node and rebroadcasts whichever transaction is missing; raw bytes are persisted so no re-signing is needed. `tx list` shows `tex pending (step 2 of 2)`, `tx resume <txid>` forces a retry, `tx abort <txid>` is allowed only while state is `built`. Recovery from a seed alone works through the ephemeral-receiver gap scan, so a stranded UTXO reappears as transparent balance that `tx shield` or a fresh `tx send` can spend; ZIP 320 explicitly accepts that the "this was a TEX payment" label may be lost on seed recovery.
- [x] **Q-T2.** What happens if Step 1 is reorged out or evicted before Step 2 confirms? If Step 2 fails for fee reasons?

  **Proposed solution.** Reorg or eviction of Step 1 invalidates Step 2 automatically (its only input disappears; Zakura's mempool also evicts descendants together with their parent), and the queue simply rebroadcasts both when they drop out of the node's view. If Step 1 reaches its expiry unmined, both expire and funds never left the shielded pool; the queue marks the row `expired`. The one asymmetric case is Step 1 mined but Step 2 expired or rejected: funds sit at the ephemeral address, the queue marks the row `step2_failed`, and `tx resume` builds and signs a *new* Step 2 (one transparent input, one output, same recipient) through a fresh signing session. Note that `create_proposed_transactions` takes a single `expiry_height` that applies to every step, so the two transactions share an expiry; with mempool chaining accepted (Q-T3) they are normally mined in the same block, and the shared expiry is fine. Fees cannot fail in the market sense: ZIP 317 is deterministic, Step 2 is one input and one output so its fee is the 10,000-zatoshi minimum and is fixed into Step 1's output value at proposal time; a node rejecting Step 2 on fee grounds would indicate a bug and is treated as `failed` with the node's error text preserved.
- [x] **Q-T3.** Does the Zakura node accept a Step 2 that spends an unconfirmed Step 1 output?

  **Proposed solution.** Yes, verified in `crates/zakurad/src/components/mempool.rs`: the mempool resolves transparent inputs against outputs created by other mempool transactions (`AwaitOutput`, `spent_mempool_outpoints`, dependency tracking), with typed rejections `MissingOutput`, `TooManyAncestors` and `TooManyPackageTransactions`; the behaviour was inherited from Zebra 2.1.0, whose changelog cites TEX transactions as the motivation. Shielded spends still need anchors in the chain, which is why Step 2 must be transparent-only. Design: the queue broadcasts Step 2 immediately after Step 1 and expects success; a `MissingOutput` rejection (for example after a node restart that lost Step 1) is a soft failure that leaves the row in `step1_broadcast` and retries after Step 1 reappears or is mined. Covered by a regtest test that restarts the node between the two broadcasts.
- [x] **Q-T4.** Will `tx send --dry-run` show both hops and both fees?

  **Proposed solution.** Yes. `--dry-run` returns the full `Proposal` and the CLI renders one block per step: inputs (pool, count, total), outputs (recipient or "ephemeral t1…", value), ZIP 317 fee, and a final line "Total debit: amount + fee₁ + fee₂". With `--json` the output is the upstream proposal protobuf (`zcash_client_backend::proto::proposal`) serialized as proto3 JSON, which gives a stable schema for free. The same summary is printed before the signature prompt in a real send so the user confirms the total cost before unlocking.

- [x] **Q-T5.** Is receiving at a `tex1` address a real requirement?

  **Proposed solution.** No. Remove `address new --tex`. `tex1` is a sender-side constraint invented for exchanges; a privacy wallet advertising one forces every counterparty to deshield. Keep `tex1` on the send side only, keep `address inspect` able to parse it, and note in `CLI_SPEC.md` why it was dropped so it is not re-added by accident.

### CLI and UX (C)

- [x] **Q-C1.** Does the CLI read `config.toml`?

  **Proposed solution.** No. The CLI reads only flags and environment variables. `--key` defaults to empty, and the daemon substitutes `default_key` whenever `key_id` is empty in a request; `--socket` defaults to a deterministic path derived from `GYGES_HOME` (default `~/.gyges`) and `--network` (Q-C2) and needs no config. This keeps the CLI a pure gRPC client that can run on a different machine from the daemon via socket forwarding.

- [x] **Q-C2.** How is a `--network` mismatch between CLI and daemon handled? Can multiple daemons run side by side?

  **Proposed solution.** One daemon per network, each with its own home: `~/.gyges/<network>/{config.toml, gygesd.sock, gygesd.pid, keys/, cache/, logs/}`. `--network` on the CLI selects that home and therefore the socket; `--socket` overrides it explicitly. The daemon's `GetInfo` RPC returns its network, and the CLI compares it with `--network` whenever both are given, failing with exit code 6 on mismatch. This makes mainnet and testnet daemons coexist naturally and makes `-n` meaningful instead of advisory. `ARCHITECTURE.md` §4 should adopt the per-network layout.

- [x] **Q-C3.** What are the JSON schemas and exit codes for every command?

  **Proposed solution.** `--json` emits the gRPC response message serialized 1:1 as proto3 JSON (via `prost-reflect` or `serde` derives on the generated types), with a top-level `"schema_version"` field; `API.md` and `gyges.proto` are therefore the schema, and streaming commands emit one JSON object per line. Exit codes: `0` success, `1` unspecified failure, `2` usage error (clap), `3` daemon unreachable, `4` authorization required and non-interactive (vault locked, Keystone signature needed, seed export refused), `5` insufficient funds, `6` invalid argument or mismatch (bad address, wrong network), `7` not ready (chain not synced, node unreachable), `8` cancelled by user, `9` hardware signer error, `10` node rejected transaction. Each code maps from the `reason` enum in the typed `GygesError` detail proposed in §2.1, so the mapping lives in one function.

- [x] **Q-C4.** What happens in non-interactive contexts when a passphrase or Keystone scan is required?

  **Proposed solution.** Never block on a prompt when stdin is not a TTY or `--non-interactive` / `GYGES_NON_INTERACTIVE=1` is set. For passphrases, support `--passphrase-fd <N>` and `GYGES_PASSPHRASE_FILE` (the `gpg` conventions) and otherwise exit 4 with "key 'main' is locked; run `gyges key unlock` or pass --passphrase-fd". For Keystone, exit 4 after printing the `session_id` and the UR frames (or writing them with `--qr-out <file>`), so the signature can be completed later with `gyges pczt qr-import --session <id>`; the session persists per Q-K4. `--json` output in these cases carries the `reason` and `session_id` fields so wrappers can drive the flow.

- [x] **Q-C5.** Does the CLI auto-start the daemon if the socket is missing?

  **Proposed solution.** Not by default: implicit background processes are hard to discover and stop, and would start with whatever network and config the first command happened to use. The CLI exits 3 with "gygesd is not running; start it with `gyges daemon start` or install a service with `gyges daemon install`". Add `gyges daemon install` / `uninstall`, which write a `launchd` user agent on macOS or a `systemd --user` unit on Linux. `GYGES_AUTOSTART=1` enables auto-start for development.

- [x] **Q-C6.** Which `--key` is used by `pczt` subcommands reading from stdin, and is the key id embedded in the PCZT?

  **Proposed solution.** Embed it. ZIP 374 PCZTs carry a global `proprietary` map; `pczt create` writes `gyges.key_id`, `gyges.network` and `gyges.session_id` there, and `prove`, `sign`, `combine` and `broadcast` read the key id from the stream, using `--key` only as an assertion that fails with exit 6 on mismatch. `combine` refuses inputs whose key ids differ. The Redactor strips the proprietary map before the PCZT goes to a Keystone so no local identifiers leave the host.

### Operations and testing (O)

- [x] **Q-O1.** Where do logs go, how are they rotated, and are they free of sensitive data?

  **Proposed solution.** `~/.gyges/<network>/logs/gygesd.log` written by `tracing-appender` with daily rotation and seven files retained; a separate `audit.log` records security-relevant events (unlock, lock, export, session creation, broadcast) with key id and timestamp only. `gyges daemon logs` streams through a `StreamLogs` RPC rather than tailing the file, so the CLI stays socket-only. Redaction is enforced by type: addresses, amounts, memos, txids and keys are wrapped in `Sensitive<T>` whose `Debug`/`Display` print a placeholder, and a workspace clippy configuration denies `Debug` derives on the key types. Level policy: `info` logs heights and counts only; `debug` may include txids; nothing ever logs memos, passphrases or key material. A regtest test runs a full send and greps the resulting logs for every address, memo and amount used. **Implemented** (`gyges_core::log`, `gygesd::logs`): as proposed, with two refinements. `audit.log` is JSON lines and bypasses the configured level so a `warn` daemon still audits; it is never rotated. The clippy denial of `Debug` on key types is not possible for upstream types that derive it, so redaction rests on `Sensitive<T>` at every call site plus the three-level test in `TESTING.md` §5; upstream error texts are logged at `debug` only.

- [x] **Q-O2.** What is the regtest story?

  **Proposed solution.** A `tests/regtest/` harness that downloads a pinned Zakura release (or builds it in a cached CI layer), starts `zakurad` in regtest with a small retention window (e.g. 200 blocks) so Case B is exercised, mines with the regtest generate RPC, and starts a local `zaino`/`lightwalletd` against the same node for the backfill path. In CI the fallback runs with `use_tor = false` (direct gRPC) because bootstrapping Tor is slow and non-deterministic; a nightly job runs the same tests through a local Tor test network. Keystone is tested with recorded UR fixtures (accounts export, redacted PCZT in, signed PCZT out) captured once from real hardware and replayed. Core scenarios: init → mine → send to `u1`/`t1` → reorg of 3 blocks → prune-race recovery → ZIP 320 with and without mempool chaining → air-gapped PCZT round trip → crash-restart with a pending `tex_queue` row.

- [x] **Q-O3.** How is backward compatibility between `gyges` and `gygesd` handled?

  **Proposed solution.** `GetInfo` returns `daemon_version` and `api_version` (`major.minor`). The CLI requires an equal major and warns on a newer daemon minor; the daemon accepts clients of its major and the previous major for one release cycle. Proto rules: never remove or renumber fields, every enum has an `_UNSPECIFIED = 0` value, new events in streams are ignorable by older clients. Ship `gyges` and `gygesd` as one release artifact so mismatches are rare in practice, and have the `daemon install` unit restart the daemon after upgrades.

- [x] **Q-O4.** What are the supported platforms?

  **Proposed solution.** Tier 1: Linux x86_64 and aarch64, macOS aarch64 (all with UDS). Tier 2 (built, lightly tested): macOS x86_64. Windows is out of scope for v1 and the docs say so; if added later it needs named pipes with an explicit ACL in place of the 0600 socket, and the hardened deployment story changes, so it deserves its own design note.

- [x] **Q-O5.** Release process and supply-chain checks?

  **Proposed solution.** CI on every PR: `cargo build --locked`, `clippy -D warnings`, `cargo test`, `cargo deny check` (advisories, licenses, bans, sources), plus the regtest job. Nightly: `cargo audit`. Releases: a tag triggers a GitHub Actions matrix that builds each Tier 1 target with a pinned `rust-toolchain.toml`, produces tarballs and `SHA256SUMS`, signs them with a project `minisign` key, and attaches SLSA build provenance via GitHub's artifact attestation. No auto-updater. `cargo vet` is deferred until the Zakura stack stabilizes, since the audit set would churn with every `-rc`.

---

## 7. Recommended Next Steps

- [x] **Fix `Cargo.toml` against the published crates** (versions in §4, `=4.0.0-rc2` common pins, `package =` renames, `tonic 0.14`, `ur-registry 1.0`, asm/multicore features behind `perf`) and create empty crates so `cargo check` passes. Commit `Cargo.lock`. *Done (revision 3): six crates, `cargo check --workspace --all-targets` passes, upstream paths compile-checked, `perf` / `perf-asm-x86_64` / `perf-asm-aarch64` features on `gyges-core`, `rust-toolchain.toml` at 1.97.1, `Cargo.lock` committed. Findings in §4.2.*
- [x] **Write `proto/gyges.proto`** and a short `API.md`. Everything in `CLI_SPEC.md` should map to exactly one RPC, with the typed error detail, `GetInfo`, `StreamLogs`, and the signing-session RPCs from Q-K4. *Done (revision 3); the command-to-RPC table is `API.md` §7.*
- [x] **Write `THREAT_MODEL.md`** from the Q-S1…S7 and Q-K7 proposals once they have been reviewed. *Draft written (revision 3) ahead of the review so the review has something concrete to mark up. Q-S1…S7 and Q-K7 decided 2026-10-21 (recorded under each question); promoted from draft.*
- [x] **Correct the factual issues in `ARCHITECTURE.md`** listed in §2.1 (module paths, age/scrypt, Sapling PGK, Combiner step, ZIP numbers, invalid TOML, retention RPC) and add Reorg, Block cache, Daemon lifecycle and per-network layout subsections from the §6 proposals. *Done (revision 3), together with the `CLI_SPEC.md` items in §2.2: `--tex` removed, exit codes, non-interactive rules, amount and memo grammar, `sync wait --until`, `tx sessions/abort/resume`, `key backup/delete`, `daemon install`, `pczt qr-scan` and `qr-import --from-file`.*
- [x] **Cut an MVP:** local-seed profiles, Orchard+transparent, Case A sync against a local Zakura node, `tx send` to `u1`/`t1`, regtest integration test. Defer Tor backfill, Keystone, ZIP-320 and PIR to later milestones, each with its own design note. *(Revised 2026-10-25: the MVP's shielded pool is Ironwood, not Orchard; it spends Orchard, Ironwood and transparent and receives Ironwood, Sapling and transparent, see Q-D7.)* *Done: `ROADMAP.md` M1 is the MVP; M2 Tor, M3 ZIP 320, M4 PCZT/air-gapped, M5 Keystone, M6 hardening.*
- [x] **Add `README.md`, licence files, CI (`cargo check`, `clippy`, `cargo-deny`)** so the repo is honest about its state and safe to contribute to. *Done (revision 3): `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `.github/workflows/ci.yml` (fmt, build `--locked`, clippy `-D warnings`, test, cargo-deny, `protoc` validation, TOML validation of `DATA_MODEL.md`), `deny.toml`, `rustfmt.toml`.*

### What remains open after revision 3

- ~~Review the §6 proposals and record decisions~~ The S questions and Q-K7 were reviewed and decided on 2026-10-21 (recorded under each question) and `THREAT_MODEL.md` is promoted. The other §6 proposals are decided as each milestone lands them, with deviations recorded in the "Landed as" notes of `ROADMAP.md`; `API.md` is the contract the code implements.
- The items still needing verification are tabled with their milestones in `THREAT_MODEL.md` §6 (TEX Step 2 and the display fields on Keystone, `z_getsubtreesbyindex` on pruned ranges, TLS in the `tor` feature, runtime CPU detection in the asm paths); `SYNC.md` keeps the node's finality depth.
- Start `ROADMAP.md` M1.
