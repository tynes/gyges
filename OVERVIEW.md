# Gyges Design Review (`OVERVIEW.md`)

A review of the three documents currently in this repository, with feedback, suggested improvements, and the open questions that must be answered before a good implementation can begin.

- **Reviewed:** `ARCHITECTURE.md`, `CLI_SPEC.md`, `Cargo.toml` (the only files in the repo, one commit).
- **Review date:** 2026-10-19.
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

1. **`Cargo.toml` pins versions of the Zakura crates that do not exist.** The pins are the *upstream librustzcash* version numbers (`0.15`, `0.13`, `0.19`, …). The published Zakura crates are at `0.1.0-rc9` / `0.1.0-rc6` / `0.0.1-rc1` (wallet-libraries) and `4.0.0-rc2` (common). Nothing resolves. (§4)
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
| §1.2, §3.1 | `zakurad` has a "retention window" exposed via `getblockchaininfo` | Pruning with configurable retention is confirmed in the Zakura node README, so the premise holds. But *which RPC field* carries the retention height is unstated. Bitcoin Core uses `pruneheight`; Zebra has no such field; Zakura's choice must be verified. |
| §3.1 Case A | `zakura_client_backend::scanning::scan_blocks` | Module path uses the package name, not the library target name. Per the wallet-libraries README the target is still `zcash_client_backend`. Same for `zakura_address`, `zakura_pczt`, `zakura_primitives`, `zakura_client_backend::data_api::…`. |
| §3.1 Case B | "`GetSubtreeRoots` (ZIP-315)" | `GetSubtreeRoots` is a lightwalletd gRPC method. ZIP 315 is "Best Practices for Wallet Handling of Multiple Pools". Check the ZIP reference; it is probably meant to cite the ShardTree/DAG-sync design, not a ZIP. |
| §3.1 Case B | Trial decryption "1.5x vectorized … `zakura-pasta-curves`" | Trial decryption is dominated by Jubjub/Pallas scalar multiplication and ChaCha20-Poly1305, so the speed-up is plausible, but `Cargo.toml` does not enable the `x86_64-asm` / `aarch64-asm` features that exist on `zakura-pasta-curves` and `zakura-orchard`. The claim is unsupported by the manifest as written. |
| §3.2.1 | "Background scanning **and PCZT creation/proving** work 24/7 while `Locked`" | True for Orchard. False for Sapling spends: the Sapling `Prover` needs the proof generation key, which is derived from the spending key. Decide (Q-K3). |
| §3.2.2 | "`age` (scrypt/Argon2id passphrase protection)" | `age` passphrase recipients use scrypt only. There is no Argon2id in age. Either drop Argon2id or do not use age's passphrase mode. |
| §3.2.3 | `UnlockKey(… ttl_secs=60)` | `CLI_SPEC.md` gives `key unlock` a default of `5m`. Pick one source of truth (a config key) and have both paths read it. Also see Q-S3 on *when* the TTL clock should start. |
| §3.3 | Both PCZTs "proven and signed during the same user session" | Correct for ZIP-320, but Step 1 must produce *exactly* `amount + step2_fee` with no change on the ephemeral address, and the ephemeral address must be derived from the ZIP 32 ephemeral chain and never reused. Say so explicitly; these are consensus-irrelevant but protocol-mandated. |
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
- **`key import-keystone --birthday`** says "override birthday height if not embedded in UR payload" while `ARCHITECTURE.md` §3.4 says the birthday is *extracted* from the UR. Check the `zcash-accounts` registry type; to my knowledge it carries UFVKs, account indices, and names, not a birthday. One of the two documents is wrong.
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

- **All twelve Zakura version pins are unpublished.** See §4 for the table. The manifest must be rewritten against `0.1.0-rc*` (wallet-libraries) and `4.0.0-rc2` (common).
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
| Keystone birthday | Extracted from `ur:zcash-accounts` | `--birthday` "if not embedded" | Verify registry type; align |
| Sync route condition | `scanned_tip` vs `retention_height` | `key restore` describes `birthday` vs `H_retain` | Same thing at restore time; say so |
| Proving while locked | Possible for all pools | Watch-only profile is "proving-only" | Only Orchard; see Q-K3 |
| Module paths | `zakura_*::…` | n/a | Use upstream target names |
| Node binary name | `zakurad` | `zakurad` | Confirmed: binary is `zakurad`, repo is `zakura-core/zakura` |
| Keystone result ingestion | "pastes/scans back" | `qr-import <FRAME>…` | Define a real input path |

---

## 4. Dependency Reality Check (verified 2026-10-19)

| Crate (`Cargo.toml` pin) | Published max version | Repository |
|---|---|---|
| `zakura-client-backend` (0.15) | 0.1.0-rc9 | zakura-core/wallet-libraries |
| `zakura-client-sqlite` (0.13) | 0.1.0-rc9 | zakura-core/wallet-libraries |
| `zakura-pczt` (0.2) | 0.1.0-rc6 | zakura-core/wallet-libraries |
| `zakura-pir-status` (0.1) | 0.0.1-rc1 | zakura-core/wallet-libraries |
| `zakura-keys` (0.5) | 4.0.0-rc2 | zakura-core/common |
| `zakura-address` (0.6) | 4.0.0-rc2 | zakura-core/common |
| `zakura-primitives` (0.19) | 4.0.0-rc2 | zakura-core/common |
| `zakura-proofs` (0.19) | 4.0.0-rc2 | zakura-core/common |
| `zakura-orchard` (0.10) | 4.0.0-rc2 | zakura-core/common |
| `zakura-sapling-crypto` (0.4) | 4.0.0-rc2 | zakura-core/common |
| `zakura-transparent` (0.2) | 4.0.0-rc2 | zakura-core/common |
| `zakura-pasta-curves` (0.5) | 4.0.0-rc2 | zakura-core/common |

Other relevant facts from the upstream READMEs:

- The node (`zakura-core/zakura`) is a Zebra fork with **native block pruning and configurable retention**, published pruned snapshots, and a **zcashd-compatibility RPC mode**. The premise of Core Capability 1 is sound.
- The node README shows a `~/.cache/zakura` directory, consistent with the `cookie_path` in the config example.
- The wallet-libraries README describes a `zakura-wallet-lib` crate ("the backend selector"), NU7 exposure through the wallet APIs, and additional features (one-time IVKs, receiver directory, swap-status normalisation). Whether Gyges wants any of these is an open question (Q-D4).
- The entire stack is pre-release (`-rc`). The documents should acknowledge that APIs will shift and that Gyges will track a moving target until Zakura 1.0.

---

## 5. Missing Documents

A wallet that holds spending keys needs more than an architecture sketch and a command list. Recommended additions, in order of leverage:

1. **`README.md`** — what Gyges is, who it is for, status (pre-alpha, nothing implemented), how it relates to Zakura, and a pointer to the other docs.
2. **`THREAT_MODEL.md`** — adversaries (malware running as the same user, a compromised archival lightwalletd, a malicious Zakura node, a stolen laptop at rest, a stolen laptop while unlocked), what each can learn or steal, and which design choice mitigates each. This will immediately surface the UDS-authentication question (Q-S1).
3. **`proto/gyges.proto` + `API.md`** — the full gRPC service, including streaming events, error details, and versioning policy between `gyges` and `gygesd`.
4. **`DATA_MODEL.md`** — `profile.json` schema, `config.toml` schema with defaults, what lives in `wallet.sqlite` beyond the upstream schema (labels, ZIP-320 queue, pending Keystone sessions), and the migration policy.
5. **`SYNC.md`** — the state machine for each key: initial state from `z_gettreestate`, backend selection, reorg handling, pruning-race handling, handoff validation, and what "synced" means.
6. **`TESTING.md`** — regtest harness, how Keystone is tested without hardware (recorded UR fixtures), how Tor fallback is tested (a local lightwalletd), and property tests for the PCZT pipeline.
7. **`ROADMAP.md` / MVP cut** — see §7.
8. **`GLOSSARY.md`** — UFVK, USK, PCZT, ShardTree, retention height, ephemeral address, `tex1`, BC-UR. The current documents assume the reader knows all of them.

---

## 6. Open Questions

Grouped by area. Each should be answered in a design doc (or explicitly deferred) before the corresponding code is written. Where I have a recommended default I give it.

### Dependencies and node (D)

- **Q-D1.** Which RPC and field exposes the retention height on Zakura? Native API, zcashd-compat API, or both? *Blocks §3.1 entirely.*
- **Q-D2.** Will Gyges target Zakura's native RPC or its zcashd-compat mode? `z_gettreestate`, `z_getsubtreesbyindex`, `getblock(h, 0)`, `getrawmempool`, `sendrawtransaction` are zcashd names. If native mode differs, the `ChainBackend` trait needs a second implementation.
- **Q-D3.** How are Zakura crate upgrades tracked while everything is `-rc`? Pin to exact versions and bump deliberately, or follow git `main`? *Recommend exact pins plus a `Cargo.lock` committed for the binaries.*
- **Q-D4.** Should Gyges build on `zakura-wallet-lib` and the `sync` feature rather than its own `SyncScheduler` and `TxEngine`? What do they not provide that Gyges needs?
- **Q-D5.** Which archival lightwalletd/zaino endpoints are acceptable defaults, and is shipping a hard-coded third-party URL (`mainnet.lightwalletd.com`) acceptable for a privacy-focused wallet?
- **Q-D6.** Are the "14x" and "1.5x" numbers reproducible on the target hardware with the `*-asm` features, and will Gyges enable those features by default? What is the fallback on CPUs without BMI2/ADX?

### Synchronisation (Y)

- **Q-Y1.** How is a reorg detected and handled on each backend? How deep a reorg is tolerated before manual intervention?
- **Q-Y2.** What happens when the node prunes past a slow Case A scanner's position? Fall back to Tor transparently, or error?
- **Q-Y3.** Is there a shared `CompactBlock` cache across key profiles, or does each profile fetch independently? What is the disk budget?
- **Q-Y4.** What does `sync wait` wait for exactly: `scanned_tip == chain_tip`, or also "all ShardTree witnesses complete" so that notes are actually spendable?
- **Q-Y5.** How is the handoff frontier at `retention_height` validated against `z_gettreestate` to catch a lying or buggy lightwalletd?
- **Q-Y6.** Will `sync mempool` run continuously in the daemon or only on demand? Continuous polling has privacy and load implications on the node.

### Keys, vault and security (S)

- **Q-S1.** Who may connect to `gygesd.sock`? A 0600 socket admits every process running as the user, including malware, which can then call `UnlockKey`-dependent RPCs during the TTL window or `ExportSeed` with the passphrase. Is per-request passphrase, peer-credential checking, or a capability token in scope?
- **Q-S2.** Is the passphrase sent over the UDS acceptable, or should key derivation happen in the CLI and only a session key cross the socket?
- **Q-S3.** When does the unlock TTL start? If it starts before proving, a large Orchard transaction may outlive 60 seconds and fail at signing. *Recommend: prove first, then prompt and sign; hold the USK only for the signing step.*
- **Q-S4.** Should `key export-seed` exist at all in a daemon-only-key-material design? If yes, require a fresh passphrase prompt and a confirmation, and never offer it over a non-TTY.
- **Q-S5.** What is the at-rest encryption design given `age` is scrypt-only? Acceptable, or do you want Argon2id via a different construction?
- **Q-S6.** Are `wallet.sqlite` contents (note values, memos, addresses, transaction graph) considered sensitive at rest? They reveal the full financial history even without the seed. Encrypt the database, rely on disk encryption, or document the assumption.
- **Q-S7.** What is the policy for `profile.json` and `wallet.sqlite` file permissions, and for backups? Can a user safely copy `~/.gyges/keys/main/` to another machine?

### PCZT and hardware signing (K)

- **Q-K1.** Which pools does Keystone 3 Pro actually sign for? To my knowledge the Zcash firmware supports Orchard and transparent, not Sapling spends. If so, Keystone profiles must be restricted to Orchard+transparent note selection.
- **Q-K2.** How does the host ingest the signed PCZT from the Keystone? Terminal cannot scan QR codes. Options: webcam decode in the CLI, a phone "bridge" app, file transfer, or the Keystone's USB mode. This is a hard requirement for the feature to work at all.
- **Q-K3.** Sapling proving needs the proof generation key. Decide between: (a) Orchard-only spends when locked / on Keystone / in watch-only, (b) unlock required for any Sapling spend, (c) signer supplies PGK into the PCZT. Each changes the vault and air-gap story.
- **Q-K4.** Where does the Combiner step run after Keystone returns the redacted-and-signed PCZT, and how does the daemon correlate it to the stored proven PCZT (session id, PCZT hash)?
- **Q-K5.** In `--airgapped` mode the daemon has no chain state. Does `pczt prove` on the air-gapped box receive anchors and witnesses entirely inside the PCZT, and how are PCZT files moved between machines (QR both ways, USB)?
- **Q-K6.** Are the CBOR tags (49201 `zcash-accounts`, 49204 `zcash-pczt`) confirmed against the published `ur-registry` version Gyges will pin? Is there a `zcash-unified-full-viewing-key` type that should be accepted for import too?
- **Q-K7.** Will Gyges verify what the Keystone shows the user (amounts, recipients) matches the PCZT it built, i.e. is the host trusted or is the device the root of trust?

### ZIP-320 / `tex1` (T)

- **Q-T1.** What is persisted between Step 1 broadcast and Step 2 broadcast, and how does the daemon recover a stranded ephemeral UTXO after a crash or restart? Should `tx list` show a "pending step 2" state and should there be a `tx resume`?
- **Q-T2.** What happens if Step 1 is reorged out or evicted from the mempool before Step 2 confirms? If Step 2 fails for fee reasons?
- **Q-T3.** Does the Zakura node accept a Step 2 that spends an unconfirmed Step 1 output (mempool chaining) in both native and compat mode?
- **Q-T4.** Will `tx send --dry-run` show both hops and both fees so the user sees total cost before signing?
- **Q-T5.** Is receiving at a `tex1` address (`address new --tex`) a real requirement? If not, remove it.

### CLI and UX (C)

- **Q-C1.** Does the CLI read `config.toml`? (Recommend: no.)
- **Q-C2.** How is a `--network` mismatch between CLI and daemon handled? Can multiple daemons (mainnet + testnet) run side by side?
- **Q-C3.** What are the JSON schemas and exit codes for every command?
- **Q-C4.** What happens in non-interactive contexts (no TTY) when a passphrase or Keystone scan is required?
- **Q-C5.** Does the CLI auto-start the daemon if the socket is missing?
- **Q-C6.** Which `--key` is used by `pczt` subcommands reading from stdin, and is the key id embedded in the PCZT stream so a pipe cannot mix keys?

### Operations and testing (O)

- **Q-O1.** Where do logs go, how are they rotated, and are they guaranteed free of addresses, memos and amounts?
- **Q-O2.** What is the regtest story: a scripted `zakurad --regtest` plus local lightwalletd so the hybrid sync path can be exercised in CI?
- **Q-O3.** How is backward compatibility between a newer `gyges` and an older `gygesd` (or vice versa) handled? Proto versioning, a `GetVersion` RPC, minimum supported version?
- **Q-O4.** What are the supported platforms (Linux, macOS, Windows without UDS)? Windows would need named pipes and changes to the "0600 socket" security assumption.
- **Q-O5.** Release process: reproducible builds, signed binaries, supply-chain checks (`cargo-deny`, `cargo-vet`) for a key-handling binary?

---

## 7. Recommended Next Steps

1. **Fix `Cargo.toml` against the published crates** (versions in §4, `package =` renames, enable asm/multicore features) and create empty crates so `cargo check` passes. Commit `Cargo.lock`.
2. **Write `proto/gyges.proto`** and a short `API.md`. Everything in `CLI_SPEC.md` should map to exactly one RPC.
3. **Write `THREAT_MODEL.md`** and answer Q-S1…S7. Several CLI details (TTL, export-seed, passphrase transport) fall out of it.
4. **Correct the factual issues in `ARCHITECTURE.md`** listed in §2.1 (module paths, age/scrypt, Sapling PGK, Combiner step, ZIP numbers, invalid TOML, retention RPC) and add Reorg, Block cache, and Daemon lifecycle subsections.
5. **Cut an MVP:** local-seed profiles, Orchard+transparent, Case A sync against a local Zakura node, `tx send` to `u1`/`t1`, regtest integration test. Defer Tor backfill, Keystone, ZIP-320 and PIR to later milestones, each with its own design note answering the questions above.
6. **Add `README.md`, licence files, CI (`cargo check`, `clippy`, `cargo-deny`)** so the repo is honest about its state and safe to contribute to.
