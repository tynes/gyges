# Gyges Glossary (`GLOSSARY.md`)

Terms used across `ARCHITECTURE.md`, `CLI_SPEC.md`, `THREAT_MODEL.md` and `OVERVIEW.md`, in alphabetical order. Where a term is defined by a ZIP or an upstream crate, the reference is given; where it is a Gyges-specific name, that is said.

---

**Anchor.** The root of a shielded note commitment tree (Sapling or Orchard) at a particular block height, referenced by a shielded spend to prove that the spent note is in the tree. A transaction's anchors must be in the chain the node accepts, which is why the ZIP 320 Step 2 transaction, which spends an unconfirmed output, must be transparent-only. See Zcash Protocol Specification §4.9 and §4.17.

**Archival endpoint.** Gyges term for the `lightwalletd` or `zaino` server, reached over Tor, that supplies compact blocks below the local node's retention height (Case B). Configured as `fallback_lightwalletd.grpc_url`; never hard-coded (Q-D5).

**BC-UR.** Blockchain Commons Uniform Resources: a scheme for encoding CBOR-tagged binary payloads as `ur:<type>/<data>` strings and splitting them into animated QR frames using a fountain code. Keystone uses it for all Zcash traffic. Defined in BCR-2020-005 (UR) and BCR-2020-006 (registry).

**Birthday height.** The block height at or before which a key was created, below which the wallet has no notes and does not scan. For a restored seed it must be supplied by the user; `key restore` defaults to Sapling activation (419,200 mainnet) with a warning, and `key import-keystone` defaults to NU5 activation (1,687,104 mainnet) because an Orchard-only key cannot have received funds earlier (Q-K4). No Keystone UR type carries a birthday.

**BIP-39 entropy vs seed.** BIP-39 maps 32 bytes of *entropy* to a 24-word mnemonic, and the mnemonic (with an optional passphrase) to a 64-byte *seed* by PBKDF2. Gyges encrypts the 32-byte entropy in `seed.age`, so the exported backup is exactly the words the user wrote down (Q-S5). ZIP 32 derives all Zcash keys from the 64-byte seed.

**Block cache.** The shared SQLite store `~/.gyges/<network>/cache/blocks.sqlite` of `CompactBlock`s implementing the upstream `BlockCache` trait, filled once per block by a single fetcher and read by every key profile's scanner (Q-Y3). Gyges-specific.

**Case A / Case B.** Gyges names for the two sync routes in `ARCHITECTURE.md` §3.1. **Case A**: the key's `scanned_tip + 1 >= retained_from`, so blocks are fetched from the local Zakura node (`getblock(h, 0)`) and turned into compact blocks locally. **Case B**: the key needs blocks below `retained_from`, so compact blocks are streamed from the archival endpoint over Tor and validated against the node (Q-Y5) before the scanner hands off to Case A.

**Combiner.** PCZT role (ZIP 374) that merges several PCZTs for the same transaction into one, e.g. a proven copy and a signed copy. Gyges runs it in the daemon when a Keystone returns a full signed PCZT in the single-PCZT flow (Q-K4). The upstream Combiner rejects structurally different inputs, which doubles as the correlation check.

**CompactBlock.** The lightwalletd wire format (`compact_formats.proto`) containing, per transaction, only the data needed for trial decryption: note commitments, ephemeral keys, the first 52 bytes of each ciphertext, and nullifiers. Carries no transparent outputs. Gyges builds them from raw blocks in Case A and receives them from the archival endpoint in Case B.

**Constructor.** PCZT role (ZIP 374) that adds spends and outputs to a PCZT. In Gyges it is performed inside `create_pczt_from_proposal` in the daemon.

**Cookie authentication.** Zakura's default RPC authentication: the node writes a random secret to `~/.cache/zakura/.cookie` and the client sends it as HTTP Basic credentials. Config key `enable_cookie_auth` (Q-D2).

**Ephemeral transparent address.** A single-use transparent (`t1`) address derived from the ZIP 32 seed on a dedicated derivation chain, used as the intermediate hop of a ZIP 320 payment. Must never be reused and must receive exactly `amount + step2_fee` (Q-T1). Recoverable from the seed by gap-limit scanning; the derivation path and gap limit are `librustzcash` implementation choices, not ZIP 320 text.

**Fountain code.** An erasure code (Luby transform) that lets a multi-part UR be reconstructed from *any* sufficient subset of frames, so an animated QR loop can be scanned starting at any frame and tolerating missed ones. Used by BC-UR for payloads larger than one QR code.

**Full-disk encryption (FDE).** FileVault, LUKS or equivalent. Gyges v1 relies on it for the confidentiality of `wallet.sqlite` at rest (Q-S6, `THREAT_MODEL.md` §3 row 4).

**Hardened deployment.** The documented configuration in which `gygesd` runs as a dedicated OS user with a 0660 socket and a `gyges` group, so the interactive user's processes cannot read `seed.age` or `wallet.sqlite` (Q-S1).

**Ironwood.** A third shielded pool, using the Orchard protocol with its own note commitment tree, exposed by the Zakura node (`z_gettreestate`, `z_getsubtreesbyindex` accept `"ironwood"`), the Zakura wallet libraries (`ironwood_action_count` on a proposal `Step`, a separate v6 transaction bundle) and Keystone firmware (signs Ironwood spends). After NU6.3 every shielded output the wallet libraries build is Ironwood and the ZIP 318 turnstile keeps value out of Orchard, so Gyges spends Orchard and Ironwood and receives Ironwood (Q-D7, `OVERVIEW.md` §4.3).

**Keystone 3 Pro.** An air-gapped hardware wallet that communicates only by QR code. With the Cypherpunk firmware edition it signs Zcash Orchard and Ironwood spends and checks transparent inputs; it does not sign Sapling spends (Q-K1). Pairs by exporting `ur:zcash-accounts`.

**lightwalletd / zaino.** Servers that index a Zcash chain and serve `CompactBlock`s, subtree roots and transparent address data to light clients over the `CompactTxStreamer` gRPC service. `lightwalletd` is the original Go implementation; `zaino` is the Rust successor. Gyges uses one only as the archival endpoint for Case B.

**NU5 / NU6.3.** Zcash network upgrades. NU5 (mainnet block 1,687,104, ZIP 252) activated Orchard and Unified Addresses. NU6.3 introduces the Ironwood pool and the ZIP 318 turnstile (mainnet 3,428,143, regtest height 1; `ARCHITECTURE.md` §1); its activation heights are set by the node. NU7 is a later upgrade; the regtest harness activates only through NU6.3 (`OVERVIEW.md` §4.5).

**Orchard.** The shielded pool introduced by NU5, using the Pallas curve and Halo 2 proofs with no trusted setup. Its proving key can be derived from the full viewing key, so Orchard spends can be *proven* while the vault is locked; only the spend authorising signature needs the spending key (Q-K3). See ZIP 224.

**Passphrase.** The user secret that decrypts `seed.age`. Never stored; sent once per unlock over the UDS as a redacted, zeroized field (Q-S2).

**PCZT.** Partially Created Zcash Transaction (ZIP 374): a serialised, incrementally completed transaction that lets separate parties and devices perform the Constructor, Updater, Prover, Signer, Combiner, Spend Finalizer, Verifier, Redactor and Tx Extractor roles. The `pczt` crate (imported from `zakura-pczt`) implements it; the on-disk form is its postcard serialisation (`.pczt` files).

**PIR.** Private Information Retrieval. `zakura-pir-status` lets `gyges tx status --pir` ask a server whether a transaction is mined without revealing which transaction. Pre-release (`0.0.1-rc1`); treated as experimental.

**Proof generation key (PGK).** The Sapling key pair `(ak, nsk)` required to create a Sapling spend proof. `nsk` is not part of any viewing key, so Sapling spends cannot be proven from a UFVK alone; the vault must be unlocked first and the PGK inserted into the PCZT by the Updater (Q-K3). Orchard has no equivalent restriction.

**profile.json.** Per-key metadata file: key id, signing mode (`LocalEncryptedSeed`, `KeystoneQr`, `WatchOnly`, `SignerOnly`), birthday height, `spend_pools`, `receive_pools`, `seed_format`, Keystone `device_version`. Schema to be defined in `DATA_MODEL.md`. Gyges-specific.

**Proprietary map.** The free-form `proprietary` key-value area in a PCZT's global section (ZIP 374). Gyges writes `gyges.key_id`, `gyges.network` and `gyges.session_id` there so `pczt` subcommands know which profile a stream belongs to; the Redactor strips it before anything leaves the host (Q-C6).

**Prover.** PCZT role (ZIP 374) that creates the zero-knowledge proofs for each shielded spend and output. Gyges runs it in the daemon (or on the air-gapped box) with the `pczt` crate's `prover` feature and `zcash_proofs`' bundled Sapling parameters.

**pruneheight / retention height / `retained_from`.** Three names for one number. `pruneheight` is the `getblockchaininfo` field on a pruned Zakura node: "the lowest height whose block body this node still stores" (Q-D1). `ARCHITECTURE.md` calls it the retention height, $H_{\text{retain}}$. `retained_from` is the field name in Gyges' `NodeBounds` struct (`pruneheight` when `pruned`, else `0`). Configured on the node as `state.storage_mode.pruned.tx_retention`, default and minimum 10,000 blocks. Headers, txids and consensus state are kept below it; only transaction bodies are pruned.

**Redactor.** PCZT role (ZIP 374) that removes data a given party does not need, so a smaller PCZT can cross a QR boundary. Gyges' Redactor removes proofs, Merkle witnesses and the proprietary map, and never the amounts, recipients or memos a Keystone displays (Q-K7).

**Reorg.** A chain reorganisation: the node switches to a different best chain and blocks the wallet has scanned are no longer canonical. Detected by hash mismatch or the scanner's `PrevHashMismatch`; handled by `truncate_to_height` to the fork point and rescanning (Q-Y1). Bounded by the node's 100-block finality depth.

**Sapling.** The shielded pool introduced in 2018 (Sapling activation, mainnet 419,200, ZIP 205), using the Jubjub curve and Groth16 proofs with the Sapling parameters. Gyges MVP receives Sapling but does not spend it, because of the proof generation key requirement (Q-K3).

**scanned_tip.** The highest block height a key profile has trial-decrypted, stored per profile in `wallet.sqlite`. Drives the Case A / Case B decision.

**ShardTree.** The `shardtree` crate's sparse Merkle tree that stores note commitment tree fragments ("shards") and the witnesses the wallet needs for its own notes, without storing every leaf. Populated from subtree roots plus scanned blocks. Each key profile has its own in `wallet.sqlite`.

**Signing mode.** The per-profile backend that authorises spends: `LocalEncryptedSeed` (passphrase-unlocked seed in the daemon), `KeystoneQr` (hardware device over QR), `WatchOnly` (UFVK only; can propose and prove Orchard, cannot sign), `SignerOnly` (seed but no chain state; the air-gapped box, Q-K5).

**Signing session.** Gyges term for a persisted row in `signing_sessions` that holds a proven PCZT awaiting a signature (passphrase or Keystone), identified by `session_id`, bound to a connection for the passphrase case, expiring at `vault.signing_session_ttl` (Q-K4, Q-S1). Also the unit the audit log records.

**SO_PEERCRED / LOCAL_PEERCRED.** Socket options (Linux and macOS respectively) that return the uid, gid and pid of the process on the other end of a Unix Domain Socket. `gygesd` reads them on every accepted connection and rejects foreign uids (Q-S1).

**Spend Finalizer.** PCZT role (ZIP 374) that assembles the transparent input scripts once signatures are present. Runs in the daemon after Combiner and Verifier.

**Subtree roots.** The roots of completed fixed-size subtrees (2^16 leaves) of a note commitment tree, served by lightwalletd's `GetSubtreeRoots` and the node's `z_getsubtreesbyindex`. Loading them lets a ShardTree skip over history it does not need to witness. Gyges cross-checks the two sources (Q-Y5).

**tex1 / ZIP 320.** A Transparent-Source-Only Address (`tex1…` mainnet, `textest1…` testnet) defined by ZIP 320. Funds sent to it must come from a transparent input, so a shielded wallet pays it in two transactions: Step 1 deshields to an ephemeral transparent address, Step 2 spends that output to the `tex1` recipient. Gyges supports `tex1` on the send side only (Q-T5).

**TexQueue.** Gyges component that persists both ZIP 320 transactions as raw bytes in the `tex_queue` table and rebroadcasts whichever is missing from the node until both are mined or expired (Q-T1, Q-T2). Named in `ARCHITECTURE.md` §2, defined in `OVERVIEW.md` Q-T1.

**Trial decryption.** Attempting to decrypt every shielded output in a block with the wallet's incoming viewing keys to find the ones addressed to it. The dominant cost of scanning; dominated by scalar multiplication and ChaCha20-Poly1305, hence the `*-asm` features on the curve crates (Q-D6).

**Tx Extractor.** PCZT role (ZIP 374) that produces the final serialised transaction from a complete PCZT. The last step before `sendrawtransaction`.

**UFVK.** Unified Full Viewing Key (`uview1…`, ZIP 316): the viewing keys for every receiver type of an account bundled together. Lets the wallet detect incoming and outgoing shielded activity and, for Orchard, create proofs, but not sign. Stored in `wallet.sqlite`; the only key material a `WatchOnly` or `KeystoneQr` profile has.

**Unified Address (UA).** `u1…` (ZIP 316): an address bundling an Orchard receiver, a Sapling receiver and/or a transparent receiver so the sender can pick the most private pool both sides support. `gyges address new --receivers` chooses which receivers to include.

**Unlock TTL.** `vault.unlock_ttl` (default `5m`): the idle timer after `gyges key unlock --timeout`. The inline unlock inside `tx send` does not use it; the USK is dropped as soon as signing completes (Q-S3).

**Updater.** PCZT role (ZIP 374) that adds information other roles need, such as Merkle witnesses, anchors, or the Sapling proof generation key (Q-K3).

**USK.** Unified Spending Key: the per-account spending keys for every pool, derived from the seed by ZIP 32. Exists only in `gygesd` RAM inside a `SecretBox` during a signing session (Q-S3).

**Verifier.** PCZT role (ZIP 374) that checks a PCZT's effects (outputs, amounts, fees, anchors) against what the caller expects. Gyges runs it against the stored proposal after every signature arrives from outside the daemon (Keystone, air-gapped file) and refuses to broadcast on any difference (Q-K4, Q-K7).

**wallet.sqlite.** The per-profile `zcash_client_sqlite` `WalletDb`: accounts, UFVK, notes, nullifiers, transactions, ShardTree, plus Gyges' own tables (`tex_queue`, `signing_sessions`, labels). Plaintext at rest (Q-S6).

**WatchOnly.** See *Signing mode*. Created by `key import-ufvk`. Can scan and, for Orchard, prove; `CLI_SPEC.md`'s "proving-only" should read "Orchard proving-only" (Q-K3).

**Zakura.** The organisation (`zakura-core` on GitHub) and the stack: a Zebra-derived node with pruning, and forks of the `librustzcash` wallet crates published as `zakura-*` on crates.io but exposing their *upstream* library target names (`zcash_client_backend`, `pczt`, `orchard`, …). Pre-release (`-rc`) throughout.

**zakurad.** The Zakura node binary, started with `zakurad start`. Speaks zcashd-style JSON-RPC and optionally an indexer gRPC. Gyges' only required network peer.

**zcashd-compat mode.** `zakurad start --zcashd-compat`: runs a real `zcashd` binary as a P2P sidecar for users of the legacy `zcashd` wallet and ZMQ. It is **not** a second RPC dialect, and Gyges does not use it (Q-D2).

**ZIP 32.** Shielded hierarchical deterministic wallets: derives all Sapling, Orchard and transparent account keys from one seed by a path such as `m/32'/133'/account'`. Also defines the ephemeral transparent address chain used by ZIP 320.

**ZIP 317.** Proportional transfer fee mechanism: the fee is deterministic in the number of logical actions (inputs and outputs), with a 10,000-zatoshi floor. `--dry-run` shows the fee per step; a one-input one-output ZIP 320 Step 2 always pays the floor (Q-T2).

**ZIP 374.** The PCZT specification. See *PCZT*.
