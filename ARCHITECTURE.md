# Gyges Architecture Specification (`gygesd` & `gyges`)

## 1. Overview
**Gyges** is a pure-Rust Zcash wallet daemon (`gygesd`) and CLI wrapper (`gyges`) built on the **Zakura Common** and **Zakura Wallet Libraries** stack.

### Core Capabilities
1. **Direct-to-`zakurad` Operation:** Syncs recent blocks, tree states (`z_gettreestate`), subtrees (`z_getsubtreesbyindex`), and broadcasts raw transactions (`sendrawtransaction`) directly against a local or remote pruned `zakurad` JSON-RPC endpoint without requiring `lightwalletd` middleware.
2. **Embedded Tor Historical Backfill:** When restoring a key whose `birthday_height` precedes the local pruned `zakurad`'s retention window ($H_{\text{retain}}$), `gygesd` automatically routes historical `CompactBlock` queries (`birthday_height .. H_retain`) through an embedded `arti-client` Tor circuit to a configured archival `lightwalletd`/`zaino` gRPC endpoint, then cuts over to local `zakurad` for `H_retain .. tip`.
3. **Independent Multi-Key Profiles:** Each managed key (`KeyId`) operates over an isolated SQLite database (`~/.gyges/keys/<key_id>/wallet.sqlite`) with its own `ShardTree` Merkle witnesses, `birthday_height`, `scanned_tip`, and signing backend (`LocalEncryptedSeed`, `KeystoneQr`, or `WatchOnly`).
4. **Daemon-Only Key Material & Air-Gapped Mode:** All key material and SQLite state live strictly inside `gygesd`. Running `gygesd --airgapped` disables all network/Tor interfaces while keeping the local Unix Domain Socket (`gygesd.sock`), SQLite state, and PCZT `Prover`/`Signer` roles active.
5. **Full Address & ZIP-320 (`tex1`) Support:** Supports sending and receiving across Unified (`u1`), Sapling (`zs1`), Transparent (`t1`), and ZIP-320 Transparent-Source-Only Exchange (`tex1` / `textest1`) addresses via automatic two-step deshielding orchestration.
6. **Keystone 3 Pro Hardware Wallet Support:** Pairs via `ur:zcash-accounts` (CBOR tag `49201`) and signs redacted PCZTs via animated terminal UTF-8 QR codes (`ur:zcash-pczt`, CBOR tag `49204`).

---

## 2. Workspace Layout

```text
gyges/
├── Cargo.toml
├── proto/
│   └── gyges.proto              # Tonic UDS gRPC contract between gyges and gygesd
└── crates/
    ├── gyges-proto/             # Generated protobuf types and gRPC client/server stubs
    ├── gyges-qr/                # UTF-8 half-block QR renderer & BC-UR (49201/49204) codec
    ├── gyges-chain/             # ChainBackend trait: ZakuraRpcBackend + ArtiTorLwdBackend
    ├── gyges-core/              # KeyRegistry, VaultManager, SyncScheduler, TxEngine, TexQueue
    ├── gygesd/                  # Daemon binary (hosts UDS tonic server + background loops)
    └── gyges-cli/               # CLI binary (`gyges` command router, prompts, QR TUI)
```

---

## 3. Component Data-Flow & State Machines

### 3.1 Hybrid Synchronization Pipeline (`SyncScheduler`)
Each `KeyProfile` tracks its own `scanned_tip` independently in its SQLite database:

1. **Poll Node Bounds:** `ZakuraRpcBackend` calls `getblockchaininfo` on `zakurad` to retrieve `(chain_tip, retention_height)`.
2. **Determine Sync Route for `KeyProfile`:**
   - **Case A (`key.scanned_tip >= retention_height`):**
     - `ZakuraRpcBackend` fetches raw blocks via `getblock(height, 0)`, strips non-essential proofs/scripts in memory using `zakura-primitives`, constructs synthetic `CompactBlock` batches, and passes them to `zakura_client_backend::scanning::scan_blocks`.
   - **Case B (`key.scanned_tip < retention_height` — Historical Restore):**
     - `ArtiTorLwdBackend` bootstraps an in-memory Tor circuit (`arti-client`) to the configured fallback `lightwalletd` endpoint.
     - Calls `GetSubtreeRoots` (ZIP-315) to pre-populate the Sapling and Orchard `ShardTree` roots.
     - Streams `GetBlockRange(key.scanned_tip .. retention_height)` over Tor and executes batch trial decryption (`zakura-pasta-curves` 1.5x vectorized arithmetic).
     - At `height == retention_height`, closes the Tor stream and hands off `retention_height .. chain_tip` to `ZakuraRpcBackend`.

### 3.2 Vault Lifecycle & Inline CLI Unlock
1. **Default State (`Locked`):** On startup, `gygesd` loads only the `UnifiedFullViewingKey` (UFVK) from each key's SQLite `accounts` table. Background scanning and PCZT creation/proving work 24/7 while `Locked`.
2. **Encrypted Seed on Disk:** For `SigningMode::LocalEncryptedSeed`, the raw 64-byte seed is encrypted with `age` (scrypt/Argon2id passphrase protection) at `~/.gyges/keys/<key_id>/seed.age`.
3. **Inline Unlock Flow:**
   - User runs `gyges tx send --key main --to u1... --amount 1.0`.
   - If `main` is `Locked`, `gygesd` returns `tonic::Status::failed_precondition("VAULT_LOCKED:main")`.
   - `gyges-cli` intercepts `VAULT_LOCKED`, prompts `Enter passphrase to unlock key 'main': ` via `rpassword`, invokes `UnlockKey(key_id="main", passphrase, ttl_secs=60)`, and immediately re-invokes `SendTransaction`.
   - Inside `gygesd`, the derived `UnifiedSpendingKey` (USK) is wrapped in `secrecy::SecretBox<UnifiedSpendingKey>` (`Zeroize` on drop) and evicted automatically by a Tokio timer when `expires_at` is reached.

### 3.3 ZIP-320 (`tex1`) Two-Step Transaction Orchestration
When the recipient address parses as `zakura_address::kind::tex` (`tex1...` on Mainnet, `textest1...` on Testnet):
1. **Proposal Generation:** `TxEngine` calls `zakura_client_backend::data_api::wallet::propose_standard_transfer_to_address`.
2. **Two-Step Plan Construction:**
   - **Step 1 (Deshielding Hop):** Spends from the wallet's Orchard/Sapling notes to an internal ephemeral transparent P2PKH address (`t1...`) for `amount + step2_zip317_fee`.
   - **Step 2 (Transparent Hop):** Spends the newly created ephemeral UTXO in a pure `Transparent -> Transparent` transaction to the decoded 20-byte pubkey hash of the `tex1` address.
3. **Execution:**
   - Both Step 1 and Step 2 PCZTs are proven and signed during the same user session (so the user only unlocks their vault or scans a Keystone QR once).
   - `gygesd` broadcasts Step 1 via `sendrawtransaction`, monitors mempool/block inclusion of Step 1's UTXO, and immediately broadcasts Step 2.

### 3.4 Keystone 3 Pro Hardware Signing (`KeystoneQr`)
1. **Import (`gyges key import-keystone`):** Parses a `ur:zcash-accounts/...` string (CBOR tag `49201`), extracts the master fingerprint, UFVK, and birthday height, and initializes `~/.gyges/keys/<key_id>/wallet.sqlite`.
2. **Signing (`gyges tx send` or `gyges pczt sign`):**
   - `gygesd` builds the PCZT, runs `zakura_pczt::roles::prover::Prover` on the host CPU (14x faster Halo2 proving via `zakura-pasta-curves`), and strips witness bloat via `zakura_pczt::roles::redactor::Redactor`.
   - `gygesd` streams the raw PCZT bytes in a `SendTransactionEvent::KeystoneSignRequired` gRPC message to `gyges-cli`.
   - `gyges-cli` encodes the PCZT as a multi-part fountain `ur:zcash-pczt` (CBOR tag `49204`) and renders an 8 FPS UTF-8 half-block QR loop in the terminal.
   - User signs on Keystone and pastes/scans the resulting `ur:zcash-pczt` string back into `gyges-cli`, which submits it to `gygesd` via `CompleteKeystoneSign` for final extraction (`TxExtractor`) and broadcast.

---

## 4. Directory & Configuration Layout (`~/.gyges/`)

```text
~/.gyges/
├── config.toml                  # Daemon & network configuration
├── gygesd.sock                  # Unix Domain Socket (0600 permissions)
├── gygesd.pid                   # Active daemon PID
├── tor_cache/                   # Arti Tor directory & consensus cache
└── keys/
    ├── main/
    │   ├── profile.json         # KeyProfile metadata (id, birthday, signing_mode)
    │   ├── wallet.sqlite        # zakura-client-sqlite WalletDb (UFVK, notes, ShardTree)
    │   └── seed.age             # Age-encrypted entropy (absent for KeystoneQr / WatchOnly)
    └── keystone-vault/
        ├── profile.json
        └── wallet.sqlite
```

### Example `~/.gyges/config.toml`
```toml
network = "mainnet"
socket_path = "~/.gyges/gygesd.sock"
default_key = "main"
airgapped = false

[zakura_rpc]
url = "[http://127.0.0.1:8232](http://127.0.0.1:8232)"
cookie_path = "~/.cache/zakura/.cookie"
poll_interval_secs = 15

[fallback_lightwalletd]
enabled = true
grpc_url = "[https://mainnet.lightwalletd.com:9067](https://mainnet.lightwalletd.com:9067)"
use_tor = true
broadcast_via_tor = false
```
