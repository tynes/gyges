# Gyges Threat Model (`THREAT_MODEL.md`)

> **Status: first draft.** This document is derived from the proposals in `OVERVIEW.md` §6 (Q-S1…S7, Q-K7, Q-D5, Q-Y5, Q-O1). Every control it names is a *proposal*, not implemented behaviour. It must be reviewed, and each "needs verification" item resolved, before the MVP ships. Where it disagrees with `ARCHITECTURE.md`, this document is the more recent statement of intent and `ARCHITECTURE.md` should be corrected.

---

## 1. Scope and Assets

Gyges is a two-process wallet: a daemon (`gygesd`) that holds all key material and chain state, and a CLI (`gyges`) that is a pure gRPC client over a Unix Domain Socket (UDS). The daemon talks to a Zakura node over JSON-RPC, optionally to an archival `lightwalletd`/`zaino` over Tor for historical backfill, and optionally to a Keystone 3 Pro over QR codes.

### 1.1 Assets, ranked by impact

| # | Asset | Where it lives | Impact if disclosed | Impact if tampered |
|---|---|---|---|---|
| A1 | **BIP-39 entropy** (32 bytes; the mnemonic is derived from it) | `keys/<id>/seed.age`, encrypted at rest (Q-S5); decrypted transiently in `gygesd` RAM for `key init`, `key export-seed` and unlock | Total loss of all funds of that profile, now and forever, on every chain the seed is used on | Irrelevant: a tampered seed simply fails to derive the known UFVK |
| A2 | **Unified Spending Key (USK)** | `gygesd` RAM only, inside `secrecy::SecretBox`, for the duration of a signing session (Q-S3) | Total loss of funds of that profile | n/a |
| A3 | **Vault passphrase** | User's head; terminal input; one gRPC request field (`[debug_redact]`); never on disk | Equivalent to A1 while `seed.age` is also obtained | n/a |
| A4 | **Signing session token** (random 32 bytes, connection-scoped, Q-S1) | `gygesd` RAM; the CLI process for the life of one command | Lets the holder sign with the unlocked key until the session ends; same connection only, so near-useless to a third process | n/a |
| A5 | **Unified Full Viewing Key (UFVK)** | `wallet.sqlite` `accounts` table; `profile.json` fingerprint; Keystone UR payloads | Complete, permanent visibility into all incoming and outgoing shielded activity of the profile; no spending ability | A substituted UFVK makes the wallet scan for someone else's notes; the profile would appear empty |
| A6 | **`wallet.sqlite` contents** (notes, nullifiers, memos, addresses, labels, `tex_queue`, `signing_sessions` with proven PCZTs) | `keys/<id>/wallet.sqlite`, plaintext at rest (Q-S6) | Full financial history, counterparties where memos reveal them, address set, pending payments | Could cause the wallet to build transactions against a false view of the chain; the Verifier role and node-confirmed anchors limit what this achieves (see §3, row 6) |
| A7 | **Proven, unsigned PCZTs** in `signing_sessions` | `wallet.sqlite` | Reveal the full transaction (recipients, amounts, memos) before broadcast | A modified PCZT is caught by the Verifier before broadcast (Q-K4, Q-K7) |
| A8 | **Block cache** (`cache/blocks.sqlite`, Q-Y3) | `~/.gyges/<network>/cache/` | The *range* of cached Tor-fetched blocks reveals the approximate birthday of restored keys | A corrupted cache yields `PrevHashMismatch` and a rescan; it cannot forge notes because tree roots are checked against the node (Q-Y5) |
| A9 | **Network metadata**: birthday height, requested block ranges, transparent addresses queried, broadcast timing and origin IP | Observable by the Zakura node, the archival endpoint, and the network path | Links the user to wallet activity; weakens shielded privacy | n/a |
| A10 | **Logs** (`logs/gygesd.log`, `logs/audit.log`, Q-O1) | `~/.gyges/<network>/logs/` | Should contain heights, counts, key ids and timestamps only; any leak of A5–A9 into logs is a bug | n/a |

### 1.2 Security goals

1. **Confidentiality of A1–A3** against every adversary in §3 except those explicitly out of scope (§4).
2. **No unauthorised spend**: funds move only after an action the legitimate user took (passphrase entry or Keystone confirmation) *in the same CLI invocation* that initiated the spend, or in a deliberate `key unlock --timeout` window.
3. **Integrity of what is broadcast**: a transaction leaves the daemon only if its effects match the proposal the user saw.
4. **Integrity of the wallet's view of the chain**: no external data source can make the wallet believe in notes, nullifiers or tree states the local node does not confirm.
5. **Privacy**: no third party learns more than the Zcash protocol already exposes, and the user is told exactly what the archival endpoint and the node do learn.

---

## 2. Trust Boundaries

```text
 user's terminal                                     filesystem  ~/.gyges/<network>/  (0700)
 ┌───────────────┐                                   ┌──────────────────────────────────────┐
 │   gyges CLI   │  passphrase / token /              │ seed.age  (0600, age-scrypt)         │
 │  (no keys,    │  UR frames in; events out          │ wallet.sqlite  (0600, plaintext)     │
 │   no config)  │                                    │ cache/blocks.sqlite  (0600)          │
 └──────┬────────┘                                    │ logs/*.log  (0600, redacted)         │
        │ UDS  gygesd.sock (0600 / 0660)              └──────────────────▲───────────────────┘
        │ SO_PEERCRED checked per connection  [B1]                       │ [B4] same uid, or
        ▼                                                                │      dedicated gygesd user
 ┌─────────────────────────────────────────────────────────────────────┐ │
 │  gygesd                                                             │─┘
 │  USK in SecretBox only during signing; sessions bound to connection │
 │  Prover · Updater · Combiner · Verifier · Spend Finalizer · Extract │
 └────┬───────────────────────────┬───────────────────────┬────────────┘
      │ [B2] JSON-RPC, cookie     │ [B3] gRPC over Tor    │ [B5] QR codes only
      │ (loopback or LAN)         │ (arti-client)         │ (redacted PCZT out,
      ▼                           ▼                       │  signatures/PCZT in)
 ┌──────────────┐          ┌───────────────────┐         ▼
 │ zakurad      │          │ archival          │   ┌───────────────┐
 │ (pruned,     │          │ lightwalletd /    │   │ Keystone 3 Pro│
 │  TRUSTED for │          │ zaino             │   │ (own root of  │
 │  consensus   │          │ (UNTRUSTED;       │   │  trust for    │
 │  state)      │          │  root-checked)    │   │  what it signs│
 └──────────────┘          └───────────────────┘   └───────────────┘

 Air-gapped variant (Q-K5): a second gygesd in SignerOnly mode with seed.age and no
 wallet.sqlite; .pczt files cross boundary [B6] by removable media, in both directions.
```

| Boundary | Crosses it | Control |
|---|---|---|
| **B1** CLI ↔ daemon | Passphrase (one field, zeroized, `debug_redact`), session token, UR frames, proposal summaries, events | Kernel-local UDS; `SO_PEERCRED` / `LOCAL_PEERCRED` uid check on every accept; connection-scoped sessions; per-key unlock rate limiting (Q-S1, Q-S2) |
| **B2** daemon ↔ Zakura node | Block requests, tree-state requests, raw transactions to broadcast, mempool polls | Cookie auth (HTTP Basic). The node is **trusted for consensus state** (tree roots, block hashes, anchors). It is not trusted with keys and it sees the wallet's full request pattern (Q-D2) |
| **B3** daemon ↔ archival endpoint | Block range `[birthday, retained_from + k]`, `GetSubtreeRoots`, optionally `GetAddressUtxos` | Tor circuit (prefer `.onion`); every result validated against the node's tree roots and hash chain before use; no hard-coded endpoint; endpoint marked `untrusted` on any mismatch (Q-D5, Q-Y5) |
| **B4** daemon ↔ filesystem | All at-rest assets | 0700 dirs, 0600 files, startup refusal on wider permissions; `seed.age` encrypted; `wallet.sqlite` relies on full-disk encryption (Q-S5, Q-S6, Q-S7) |
| **B5** daemon ↔ Keystone (via CLI terminal and camera) | Redacted PCZT or batch request out; signatures or signed PCZT in | Redactor strips proofs, witnesses and the proprietary map but never amounts, recipients or memos; Verifier compares the result to the stored proposal before broadcast (Q-K4, Q-K7, Q-C6) |
| **B6** online daemon ↔ air-gapped daemon | `.pczt` files on removable media | Online side runs Verifier on the returned file exactly as for Keystone (Q-K5) |

---

## 3. Adversaries

Each row: what the adversary can *learn*, what they can *steal or cause*, which proposed control mitigates it, and what remains.

| # | Adversary | Can learn | Can steal / cause | Mitigating controls | Residual risk |
|---|---|---|---|---|---|
| 1 | **Same-user malware with socket access only** (can open `gygesd.sock`, read the user's files, but cannot `ptrace` or replace binaries) | Everything in `wallet.sqlite` (A5–A7): full history, memos, addresses, pending PCZTs. The encrypted `seed.age` bytes. Via RPC: balances, addresses, sync state. | Cannot spend: `UnlockKey` creates a session bound to *its own* connection, so it cannot ride on the user's open window (Q-S1). It can call `UnlockKey` itself and guess passphrases (rate-limited, Q-S2). It can call `SendTransaction` and get as far as `SignatureRequired`, i.e. it can build and prove transactions but not sign them. It can abort or create signing sessions and pollute `tex_queue` state. It can exfiltrate `seed.age` for an offline passphrase attack. | Connection-scoped unlock and session tokens (Q-S1); passphrase rate limiting with exponential back-off (Q-S2); scrypt work factor ~1 s (Q-S5); no `--json` path for seed export and `vault.allow_seed_export = false` (Q-S4); audit log of every unlock, session and broadcast (Q-O1) | **Total loss of privacy for the profile.** Offline brute force of a weak passphrase. Denial of service (session spam, abort of in-flight ZIP 320 steps while `built`). The hardened deployment (dedicated `gygesd` user, 0660 socket with a `gyges` group) removes file access and leaves only the RPC surface. |
| 2 | **Same-user malware that can `ptrace` the daemon or replace `gyges`/`gygesd`** | Everything, including the USK while a session is open and the passphrase as it is typed | Everything | None by design; the hardened deployment (different uid) converts this into adversary 3 | **Out of scope** (§4). Documented honestly rather than mitigated. |
| 3 | **Another local user** on the same machine | Nothing from `~/.gyges` (0700). Process list shows that `gygesd` runs and for which network. | Nothing. Cannot connect to the socket (`SO_PEERCRED` uid check, 0600 mode). | Peer-credential check, directory and socket permissions, startup refusal on wider permissions (Q-S1, Q-S7) | A root user is adversary 2. Shared `/tmp` or world-readable backup tarballs created by the user (`key backup`) are the user's responsibility; the docs must say so. |
| 4 | **Stolen laptop, powered off** (attacker has the disk) | With full-disk encryption: nothing. Without it: everything in row 1 plus `seed.age` for offline attack. | Without FDE: offline brute force of the passphrase; with a weak passphrase, total loss. | `seed.age` with scrypt ~1 s (Q-S5); 32-byte entropy, not the derived seed, so there is no second secret to protect; `profile.json` records the scrypt parameters so they can be raised by migration | **`wallet.sqlite` is plaintext.** v1 explicitly relies on OS full-disk encryption for A6 (Q-S6). SQLCipher with an OS-keychain key is the proposed later mitigation. The passphrase strength is the only barrier to A1. |
| 5 | **Stolen laptop while unlocked** (screen unlocked, user session live) | Everything in row 1 via the CLI or the files | If a `key unlock --timeout` window is open on a still-connected CLI session: can spend until the TTL expires, by using that CLI's shell. The inline-unlock path holds the USK only across the signing step (Q-S3), so an interrupted `tx send` leaves nothing unlocked. | Short default TTL (`vault.unlock_ttl = "5m"`), idle timer, `key lock --all`, USK dropped immediately after signing in the inline flow (Q-S3); sessions die with the connection (Q-S1) | A user who runs `key unlock --timeout 8h` for a batch job has chosen to accept this. The docs should warn and the audit log records it. Adversary can also exfiltrate `seed.age` (becomes row 4). |
| 6 | **Malicious or buggy Zakura node** | The wallet's complete request pattern: every block fetched (hence the scan position of each key), every `getrawtransaction`, every broadcast and its timing, transparent address queries where used. Not the UFVK, not note contents. | Can feed false tree states and block data. Consequences: (a) wallet builds a transaction against a false anchor, which the *real* network rejects, i.e. denial of service; (b) withholds blocks so the wallet never sees incoming notes or a spend of its own notes (stale balance); (c) lies about `pruneheight` to force a Tor backfill and learn the birthday from the endpoint it does not control, or to prevent one; (d) drops or delays broadcasts; (e) reports a transaction as mined when it is not. | None against a trusted node by design: the node is the root of trust for consensus state (§2, B2). `sync status` exposes chain tip and hashes so a user can cross-check against another node. ZIP 317 and deterministic proposals mean the node cannot inflate fees. Broadcast over Tor (`--via-tor`) decouples broadcast origin from the node. | **The node is trusted.** A user who does not run their own node has moved this adversary into the trusted base. The documents must state that Gyges is designed for a *local* Zakura node, and that a remote node operator sees everything in the "can learn" column. Detecting an eclipsed or lying node is out of scope for v1. |
| 7 | **Compromised archival lightwalletd / zaino** (Case B backfill over Tor) | The requested block range, hence the approximate birthday of the restored key; the fact that *someone* is restoring; any transparent addresses queried via `GetAddressUtxos` for transparent recovery. Not the origin IP (Tor), not the UFVK. | Attempts: omit blocks (hide incoming notes), inject or reorder commitments (corrupt witnesses so the wallet cannot spend, or desynchronise it from the real tree), serve a fork, hang the stream (DoS), return fake transparent UTXOs. | Stream overlaps the node's window by `k = 10` blocks and is validated at `V = retained_from + k`: (1) Sapling and Orchard tree roots and leaf counts from `z_gettreestate(V)` must match the ShardTree built from the stream; (2) `prev_hash` chain must link and `getblockhash` must match at `V` and `retained_from`; (3) `GetSubtreeRoots` must equal `z_getsubtreesbyindex`. On failure: truncate the key to its birthday, mark the endpoint `untrusted`, refuse further backfill until the config changes (Q-Y5). No hard-coded endpoint; explicit user consent before the first backfill; `.onion` preferred (Q-D5). | An omitted or forged *shielded* output changes the tree root and is caught. **Transparent history below `retained_from` cannot be root-checked**; each returned UTXO's transaction is fetched and its inclusion verified against a node-confirmed block hash, which prevents fabricated UTXOs but not *omitted* ones. Timing and range leakage is inherent and documented. DoS is accepted. **Needs verification:** that `z_getsubtreesbyindex` works for pruned ranges on a pruned node (Q-Y5 expects so; the commitment tree is consensus state). |
| 8 | **Compromised or buggy Keystone device** | Everything in the redacted PCZT it is shown: recipients, amounts, memos, the wallet's Orchard actions. It already holds the seed, so key secrecy is not the concern. | Returns signatures for a *different* transaction than displayed (e.g. altered recipient or amount), or a malformed result. | Daemon never trusts the returned payload: Combiner rejects structurally different PCZTs; the **Verifier** role re-checks every output, amount, fee and anchor against the *stored* proposal before Spend Finalizer and Tx Extractor run (Q-K4, Q-K7). The host keeps the proven, unredacted PCZT and applies only the signatures. | A device can refuse to sign (DoS). A device that signs correctly but exfiltrates the seed through side channels is a hardware-wallet problem outside this document. The device sees memos; users who do not want that should not use memos with Keystone. |
| 9 | **Compromised host when signing with Keystone** (the host is adversary 1 or 2, the device is honest) | Everything the host holds (rows 1–2). | Presents the device with a PCZT whose recipient or amount differs from what the user intended. The device display is the only defence. | The Redactor strips proofs, witnesses and the `gyges.*` proprietary map but **must never strip amounts, recipients or memos** that the device displays; `ARCHITECTURE.md` §3.4 must list the redacted fields exactly. `tx send` prints the same summary the device shows so the user can compare (Q-K7). The device refuses transactions it cannot fully display. | The user must actually read the device screen. A host can still DoS, leak metadata, and substitute the destination for a *shielding* transaction the user does not inspect carefully. **Needs verification:** which PCZT fields the current Keystone firmware displays, so the summary matches the device exactly. |
| 10 | **Network observer on the Tor path** (exit node, Tor directory authorities, ISP, archival endpoint's upstream) | That a Tor client bootstrapped from the user's IP (ISP); that *some* Tor user fetched Zcash blocks from the endpoint (exit node, unless `.onion`). With TLS to the endpoint, not the content. Broadcast over Tor: the raw transaction (public anyway), not its origin. | Traffic correlation between the user's Tor bootstrap and the endpoint's incoming connection, in principle. Blocking Tor (DoS). | Tor via `arti-client`; `.onion` endpoints preferred so no exit node exists; TLS (`rustls`, webpki roots) to clearnet endpoints; `broadcast_via_tor` option for the final transaction (Q-D5) | Tor's own threat model applies: a global passive adversary can correlate. Users on networks that block Tor fall back to `use_tor = false` and become visible to the endpoint directly, which the config must make loud rather than silent. **Needs verification:** that the `tor` feature of `zakura-client-backend` pins the TLS verification Gyges expects. |
| 11 | **Malicious `.pczt` file in the air-gapped flow** (removable media tampered between the online and offline machine, in either direction) | Online → offline: the attacker sees the unsigned transaction (recipients, amounts, memos, note witnesses, i.e. A7). Offline → online: the signed transaction. | Online → offline: substitute recipients or amounts so the offline signer signs an attacker's transaction. Offline → online: substitute a different signed transaction for broadcast; or inject proofs that do not verify. | Offline side: `pczt inspect` and `pczt sign` display the full effects and require confirmation; the signer holds the seed, so it can derive its own addresses and flag an unknown change output (**needs verification** that the upstream Signer role or Gyges's wrapper checks change ownership). Online side: Verifier against the stored proposal before broadcast, so a substituted signed transaction is refused (Q-K5, Q-K4). `combine` refuses PCZTs whose embedded `gyges.key_id` differ (Q-C6). | The offline user must read the `pczt sign` summary as carefully as a Keystone screen; there is no device-enforced display. A substituted file that matches the stored proposal exactly is by definition the intended transaction. The attacker learns A7 in transit; encrypting `.pczt` files at rest on the media is a possible later addition. |

---

## 4. Out of Scope

These are stated so that nobody mistakes silence for a guarantee.

- **Keyloggers or screen capture on the host.** The passphrase is typed into a terminal; anything that can read it before `rpassword` does defeats the vault.
- **A replaced or trojaned `gyges` or `gygesd` binary**, or a modified Rust toolchain. Release signing and provenance (Q-O5) address distribution, not a host that is already compromised.
- **Kernel, hypervisor or firmware compromise**, including anything that can read `gygesd` memory or `ptrace` it as the same uid without the user noticing. `secrecy`/`zeroize` limit the *window*, not the *possibility*.
- **Physical attacks on the Keystone device**, fault injection, supply-chain substitution of the device, or Keystone firmware vulnerabilities. The device is treated as a black box that either behaves or is detected by the Verifier.
- **Memory-disclosure side channels** (Spectre-class, cold boot, swap). The daemon should request `mlock` for `SecretBox` pages where the platform allows it, but this is a hardening step, not a boundary.
- **Windows.** Named pipes, ACLs and the absence of `SO_PEERCRED` make §2 and §3 rows 1–3 different; a separate design note is required before support is claimed (Q-O4).
- **Remote daemons.** The design assumes the UDS and the daemon are on the user's own machine. Forwarding the socket over SSH is possible but extends boundary B1 across the network and is not analysed here.
- **The Zcash protocol's own privacy limits**: transaction graph analysis of transparent components, amount and timing correlation of deshielding steps (ZIP 320 Step 1 → Step 2 is visibly linked on-chain by design), and anything a `tex1` recipient learns from the ephemeral address.
- **Consensus bugs in Zakura** or in the upstream `librustzcash` crates. The entire stack is pre-release (§4 of `OVERVIEW.md`).

---

## 5. Security Controls Checklist

Each control, the component responsible for it, the question that proposed it, and the test that should prove it. Unchecked boxes are not implemented; nothing is implemented yet.

| ✓ | Control | Implemented in | Proposed by | Proof |
|---|---|---|---|---|
| ☐ | Reject UDS connections whose peer uid is not the daemon's (or not in the allow-list) using `SO_PEERCRED` / `LOCAL_PEERCRED` | `gygesd` accept loop | Q-S1 | Integration test connecting as another uid (CI runs as two users, or a mocked peer-cred layer) |
| ☐ | Socket mode 0600 by default, 0660 with a group in the hardened deployment | `gygesd` startup | Q-S1, Q-S7 | Stat the socket after start |
| ☐ | `UnlockKey` creates a session bound to the calling connection and returns a random 32-byte token; only `SendTransaction`, `SignPczt`, `ExportSeed` with a valid token use the key; session dies with the connection or at TTL | `gyges-core::VaultManager`, `gygesd` interceptor | Q-S1, Q-S3 | Test: unlock on connection A, attempt sign on connection B, expect `PERMISSION_DENIED` |
| ☐ | USK held only across the signing step of `SendTransaction` and dropped after; `SecretBox` with `Zeroize` on drop | `gyges-core::VaultManager` | Q-S3 | Unit test that the `SecretBox` is dropped before the broadcast event is emitted |
| ☐ | Passphrase field marked `[debug_redact = true]`, wrapped in `SecretString`, zeroized after derivation | `proto/gyges.proto`, `gygesd` | Q-S2 | Log-grep test (Q-O1) |
| ☐ | Per-key exponential back-off on failed `UnlockKey` | `gyges-core::VaultManager` | Q-S2 | Test: N failures, measure delay |
| ☐ | `seed.age` encrypts 32-byte entropy with age scrypt at a work factor of ~1 s; parameters recorded as `seed_format` in `profile.json` | `gyges-core::VaultManager` | Q-S5 | `rage -d` can decrypt the file with the passphrase |
| ☐ | `~/.gyges` tree 0700/0600; daemon refuses to start on wider permissions with a one-line fix | `gygesd` startup | Q-S7 | Test with a 0644 `seed.age` |
| ☐ | `key export-seed`: TTY required, passphrase supplied in-request and never from a session, `reveal seed` confirmation, terminal output only, audit-logged, disabled by `vault.allow_seed_export = false` | `gyges-cli`, `gygesd` | Q-S4 | Test each refusal path |
| ☐ | `key init` displays the mnemonic once and requires three random words typed back | `gyges-cli` | Q-S4 | UX test |
| ☐ | Case B stream validated at `V = retained_from + k` against the node's tree roots, hash chain and subtree roots; endpoint marked `untrusted` on mismatch and the key truncated to birthday | `gyges-chain::ArtiTorLwdBackend`, `gyges-core::SyncScheduler` | Q-Y5 | Regtest with a lightwalletd that omits one block, one output, and serves a fork |
| ☐ | Transparent UTXOs from `GetAddressUtxos` are accepted only after fetching the transaction and verifying inclusion against a node-confirmed block hash | `gyges-chain::ArtiTorLwdBackend` | Q-Y5 | Regtest with a fabricated UTXO |
| ☐ | No hard-coded archival endpoint; explicit consent before the first backfill; `.onion` preferred | `gygesd` config loading, `gyges-cli` | Q-D5 | Config test: `enabled = true` without `grpc_url` fails to start |
| ☐ | Verifier runs after Combiner (Keystone) and after loading a signed `.pczt` (air-gapped), and the daemon refuses to broadcast on any difference from the stored proposal | `gyges-core::TxEngine` | Q-K4, Q-K7, Q-K5 | Test: mutate one output in the signed PCZT, expect refusal |
| ☐ | Redactor removes proofs, witnesses and the `gyges.*` proprietary map, and nothing the device displays; the redacted field list is documented in `ARCHITECTURE.md` §3.4 | `gyges-core::TxEngine` | Q-K7, Q-C6 | Fixture test on a recorded PCZT |
| ☐ | `tx send` prints the same transaction summary the device shows | `gyges-cli` | Q-K7 | Fixture comparison with recorded device screens (**needs verification** of the firmware display format) |
| ☐ | `Sensitive<T>` wrapper for addresses, amounts, memos, txids and keys; `Debug` derives denied on key types by clippy config; `info` logs heights and counts only | all crates | Q-O1 | Regtest send, then grep logs for every address, memo and amount used |
| ☐ | `audit.log` records unlock, lock, export, session create/complete/abort and broadcast with key id and timestamp only | `gygesd` | Q-O1 | Same grep test |
| ☐ | Signing sessions persisted with the proven PCZT, expire at `vault.signing_session_ttl`, listable and abortable | `gyges-core::TxEngine`, `wallet.sqlite` | Q-K4 | Crash-restart test |
| ☐ | `tex_queue` persists raw bytes of both ZIP 320 steps so no re-signing is needed on retry; `tx abort` only while `built` | `gyges-core::TexQueue` | Q-T1, Q-T2 | Crash-restart test between broadcasts |
| ☐ | `cache/blocks.sqlite` 0600; `cache.keep_historical = false` drops Tor-fetched ranges once consumed | `gyges-chain` block cache | Q-Y3 | Test that the range is gone after scan |
| ☐ | Non-interactive invocations never block on a prompt; `--passphrase-fd` and `GYGES_PASSPHRASE_FILE` are the only non-TTY passphrase paths | `gyges-cli` | Q-C4 | Test with stdin closed |
| ☐ | `cargo deny`, `cargo audit`, `--locked` builds, signed release artifacts with provenance | CI | Q-O5 | CI configuration |

---

## 6. Open Security Questions

Unresolved items that this draft could not close. Each should become a decision or a verified fact before the control that depends on it is implemented.

1. **Sapling proof generation key handling (Q-K3).** The proposal inserts `proof_generation_key` into the PCZT via the Updater role after an unlock and before proving. This puts a key that can create proofs (though not signatures) into a data structure that is persisted in `signing_sessions`. Decide whether Sapling-input proposals may be persisted at all, or must be proven and signed in one session with nothing written to disk. The MVP avoids the question by not spending Sapling.
2. **Runtime CPU feature detection for the `*-asm` features (Q-D6).** If `zakura-pasta-curves` assumes BMI2/ADX unconditionally, a `perf` build on an older CPU is a crash, not a security problem; but a *silent fallback to a different implementation* could in principle alter timing behaviour. **Needs verification** in the crate source before `perf` is default.
3. **`wallet.sqlite` at rest (Q-S6).** v1 relies on full-disk encryption. Decide whether SQLCipher with an OS-keychain key is a v1.x requirement, and whether the per-key database key should itself be wrapped by the vault passphrase (which would break background scanning) or only by the keychain.
4. **Hardened deployment ergonomics (Q-S1).** Running `gygesd` as a dedicated user means the interactive user cannot read `seed.age`, which is the point, but also means `key backup` and `key init` must be done through the daemon. Decide whether the hardened mode is documented-only or gets first-class tooling (`gyges daemon install --hardened`).
5. **Session token transport.** The token is returned to the CLI over the same connection and never needs to leave the process. Confirm that no CLI code path ever prints it (including `--json` and verbose logging) and that `UnlockKey` for the explicit `key unlock --timeout` path does *not* return a connection-bound token but a daemon-global idle-timer unlock, since that CLI process exits immediately. The two unlock modes have different threat profiles and the API must make the difference impossible to confuse.
6. **Rate limiting across connections.** Exponential back-off per key is proposed; confirm it is keyed on the key id and not the connection, or adversary 1 bypasses it by reconnecting.
7. **Keystone display coverage (Q-K7).** **Needs verification** on hardware: which PCZT fields the Cypherpunk firmware displays, whether it shows memos, and whether it shows the ZIP 320 Step 2 transparent-only transaction in a way that identifies the `tex1` recipient. Until confirmed, `tx send --to tex1…` stays disabled for Keystone profiles (Q-K1).
8. **Air-gapped change-output verification (§3 row 11).** **Needs verification** whether the upstream `pczt` Signer role verifies that change outputs belong to the signer's own keys, or whether Gyges must add that check in `pczt sign`.
9. **Transparent recovery below `retained_from` (Q-Y5).** Omitted UTXOs cannot be detected. Decide whether to warn on every restore that transparent history before the retention height is best-effort, or to require a second independent endpoint for transparent queries.
10. **`mlock` and core dumps.** Decide whether `gygesd` sets `RLIMIT_CORE = 0` and attempts `mlock` on `SecretBox` allocations, and what to do on platforms where it is refused.
11. **Log retention and the audit log as an asset.** Seven daily log files retained (Q-O1) means seven days of key ids and timestamps of every unlock and broadcast. Confirm that this is acceptable under adversary 1, or shorten the audit retention.
12. **Remote-node mode.** If `zakura_rpc.url` is not loopback, adversary 6's "can learn" column applies to a third party. Decide whether to warn at startup, require an explicit `allow_remote_node = true`, or route node RPC over Tor as well.
