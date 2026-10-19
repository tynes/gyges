# Gyges CLI Specification (`gyges`)

## 1. Global Options
Every `gyges` invocation accepts the following global flags:

```text
gyges [GLOBAL_OPTIONS] <SUBCOMMAND>

Global Options:
  -s, --socket <PATH>      Path to gygesd Unix Domain Socket [env: GYGES_SOCKET] [default: ~/.gyges/gygesd.sock]
  -k, --key <KEY_ID>       Target key profile ID [env: GYGES_KEY] [default: config.default_key]
  -n, --network <NET>      Network: mainnet | testnet | regtest [env: GYGES_NETWORK]
  -j, --json               Emit machine-readable JSON output to stdout
  -q, --quiet              Suppress progress bars, spinners, and interactive banners
```

---

## 2. Command Reference

### 2.1 Daemon Management (`gyges daemon`)

#### `gyges daemon start`
Starts the `gygesd` background server and initializes the Unix Domain Socket.
```text
Flags:
  -f, --foreground                 Run in foreground (do not daemonize)
      --airgapped                  Disable all network/RPC/Tor interfaces (offline proving & signing only)
      --zakura-rpc <URL>           Override zakurad JSON-RPC endpoint (e.g., [http://127.0.0.1:8232](http://127.0.0.1:8232))
      --zakura-cookie <PATH>       Path to zakurad RPC auth cookie
      --fallback-lwd <GRPC_URL>    Public archival lightwalletd/zaino gRPC URL for historical restores
      --no-tor                     Disable embedded Arti Tor circuit for lightwalletd fallback
```

#### `gyges daemon stop`
Gracefully stops `gygesd`, flushes all SQLite WAL files, and zeroes all unlocked spending keys in RAM.

#### `gyges daemon status`
Displays daemon health, `zakurad` connection status, `zakurad` pruning retention height ($H_{\text{retain}}$), Tor bootstrap status, and per-key sync/lock summary.

#### `gyges daemon logs [--follow] [--lines <N>]`
Streams structured daemon logs.

---

### 2.2 Multi-Key & Vault Management (`gyges key`)

#### `gyges key list`
Lists all registered independent key profiles, their `SigningMode` (`local-seed`, `keystone-qr`, `watch-only`), `LOCKED`/`UNLOCKED` status, `birthday_height`, and `scanned_tip`.

#### `gyges key init --id <KEY_ID>`
Generates a new 24-word BIP-39 seed, sets `birthday_height` to `zakurad`'s current tip, initializes `~/.gyges/keys/<KEY_ID>/wallet.sqlite`, and encrypts `seed.age` with a passphrase.
```text
Flags:
      --id <KEY_ID>         Unique identifier for this key profile (e.g., "main", "hot")
      --set-default         Set this key as the default profile
```

#### `gyges key restore --id <KEY_ID> --birthday <HEIGHT>`
Restores an existing 24-word mnemonic. If `<HEIGHT>` is below `zakurad`'s retention height ($H_{\text{retain}}$), `gygesd` automatically backfills `<HEIGHT> .. H_retain` over Tor via `fallback_lightwalletd` before switching to local `zakurad`.
```text
Flags:
      --id <KEY_ID>         Unique identifier for this key profile
      --birthday <HEIGHT>   Block height when the wallet was created
      --stdin               Read 24-word mnemonic from stdin
```

#### `gyges key import-keystone --id <KEY_ID> [--birthday <HEIGHT>]`
Registers a Keystone 3 Pro hardware wallet profile from a `ur:zcash-accounts/...` QR payload (CBOR tag `49201`).
```text
Flags:
      --id <KEY_ID>         Unique identifier for this Keystone profile
      --ur <UR_STRING>      Pass the `ur:zcash-accounts/...` string directly (or prompt interactively)
      --birthday <HEIGHT>   Override birthday height if not embedded in UR payload
```

#### `gyges key import-ufvk --id <KEY_ID> --ufvk <UFVK> --birthday <HEIGHT>`
Creates a watch-only / proving-only key profile from a Unified Full Viewing Key (`uview1...`).

#### `gyges key unlock [--id <KEY_ID>] [--timeout <DURATION>]`
Prompts for the passphrase and unlocks the key's `UnifiedSpendingKey` inside `gygesd` RAM for `<DURATION>` (default: `5m`, e.g., `60s`, `15m`).

#### `gyges key lock [--id <KEY_ID> | --all]`
Immediately zeroes the decrypted spending key(s) in `gygesd` RAM.

#### `gyges key export-ufvk [--id <KEY_ID>]` / `gyges key export-seed [--id <KEY_ID>]`
Exports the UFVK or decrypted 24-word mnemonic (requires passphrase prompt).

---

### 2.3 Synchronization (`gyges sync`)

#### `gyges sync status [--key <KEY_ID> | --all]`
Displays live sync progress, blocks/sec, active backend (`zakurad-rpc` vs `tor-lwd-fallback`), and `ShardTree` witness health for the specified key(s).

#### `gyges sync wait [--key <KEY_ID>] [--confirmations <N>]`
Blocks until `scanned_tip` reaches `zakurad`'s current chain tip (ideal for shell scripts prior to `gyges balance` or `gyges tx send`).

#### `gyges sync run [--key <KEY_ID>] [--from <HEIGHT>] [--to <HEIGHT>] [--force-tor-lwd]`
Triggers an immediate foreground scan or rescan for the target key.

#### `gyges sync mempool [--key <KEY_ID>]`
Polls `zakurad` `getrawmempool` and trial-decrypts unconfirmed incoming outputs.

---

### 2.4 Addresses, Terminal QR Codes & Balances (`gyges address`, `gyges balance`, `gyges notes`)

#### `gyges address current [--qr]`
Prints the current Unified Address for `--key`. If `--qr` is passed, renders a compact UTF-8 half-block QR code directly in the terminal.

#### `gyges address new [--receivers <LIST>] [--label <TEXT>] [--qr]`
Derives a fresh diversified Unified Address (`u1...`) from the key's UFVK.
```text
Flags:
      --receivers <LIST>    Comma-separated receivers: orchard,sapling,transparent [default: orchard,sapling]
      --tex                 Encode the transparent receiver as a ZIP-320 `tex1...` address
      --label <TEXT>        Optional metadata label stored in WalletDb
      --qr                  Render UTF-8 QR code in terminal
```

#### `gyges address qr [<ADDRESS>]`
Renders a static terminal QR code for the active key's current address, or for any arbitrary `<ADDRESS>` passed on the command line.

#### `gyges address inspect <ADDRESS>`
Parses any Zcash address (`u1`, `utest1`, `zs1`, `t1`, `t3`, `tex1`, `textest1`), validates its checksum/network, and lists all embedded receivers and ZIP-320 flags.

#### `gyges balance [--min-conf <N>]`
Displays **Spendable**, **Pending Confirmation**, and **Transparent UTXO** balances broken down across **Orchard**, **Sapling**, and **Transparent** pools.

#### `gyges notes [--pool <orchard|sapling|transparent>] [--unspent | --spent]`
Lists decrypted notes and UTXOs, block heights, values, memo previews, and `ShardTree` witness readiness.

---

### 2.5 High-Level Transactions (`gyges tx`)

#### `gyges tx send --to <ADDR> --amount <ZEC_OR_MAX>`
Constructs, proves (via `zakura-pasta-curves` 14x Halo2 acceleration), signs, and broadcasts a transaction.
- **Inline Unlock:** If `--key` uses `local-seed` and is currently `Locked`, `gyges` prompts for the passphrase inline, unlocks for 60s, and continues.
- **Keystone Hardware Flow:** If `--key` uses `keystone-qr`, `gyges` displays the animated BC-UR (`ur:zcash-pczt`) QR code in the terminal and prompts for the signed UR string from the Keystone device before broadcasting.
- **Binance / ZIP-320 (`tex1...`) Flow:** Automatically detects `tex1` recipients and executes the 2-step `Shielded -> Ephemeral t1 -> tex1` transfer plan.
```text
Flags:
      --to <ADDR>           Destination address (u1, zs1, t1, t3, or tex1)
      --amount <VAL>        Amount in ZEC (e.g., "1.25"), zatoshis ("125000000z"), or "max"
      --memo <TEXT_OR_HEX>  512-byte encrypted memo (Orchard/Sapling receivers only)
      --via-tor             Broadcast final transaction over an isolated Arti Tor circuit
      --dry-run             Compute ZIP-317 fee, note selection, and ZIP-320 hops without signing/broadcasting
```

#### `gyges tx shield [--threshold <ZEC>]`
Sweeps transparent UTXOs into the key's Orchard pool (ZIP-316 auto-shielding).

#### `gyges tx list [--limit <N>]`
Prints transaction history with timestamps, pool flows, ZIP-317 fees, and decrypted UTF-8 memos.

#### `gyges tx status <TXID> [--pir]`
Queries confirmation status via `zakurad` or privately via `zakura-pir-status` if `--pir` is set.

---

### 2.6 Modular & Air-Gapped PCZT Pipeline (`gyges pczt`)
Exposes the ZIP-374 `zakura-pczt` roles for Unix-pipe composition and air-gapped signing (`gygesd --airgapped`).

```bash
# Example Unix Pipe Workflow:
gyges pczt create --to u1q... --amount 2.5 \
  | gyges pczt prove \
  | gyges pczt sign \
  | gyges pczt broadcast
```

- `gyges pczt create --to <ADDR> --amount <ZEC> [--memo <TEXT>] [-o <FILE>]`
- `gyges pczt inspect [<FILE>]`
- `gyges pczt prove [<FILE>] [-o <OUT_FILE>]`
- `gyges pczt sign [<FILE>] [-o <OUT_FILE>] [--qr-out]`
- `gyges pczt qr-export [<FILE>] [--fps <N>]` (Animates `ur:zcash-pczt` tag `49204` QR frames in terminal)
- `gyges pczt qr-import <UR_FRAME_1> [<UR_FRAME_N>...] [-o <OUT_FILE>]`
- `gyges pczt combine <FILE_A> <FILE_B> [-o <OUT_FILE>]`
- `gyges pczt broadcast [<FILE>] [--via-tor]`
