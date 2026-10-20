# Gyges CLI Specification (`gyges`)

> Revision 2 (2026-10-20). Incorporates the corrections from `OVERVIEW.md` §2.2 and the proposals in §6. Every command maps to exactly one RPC in `proto/gyges.proto`; the mapping table is in `API.md`.

## 1. Global behaviour

### 1.1 Global options
```text
gyges [GLOBAL_OPTIONS] <SUBCOMMAND>

Global Options:
  -s, --socket <PATH>      gygesd Unix Domain Socket [env: GYGES_SOCKET] [default: $GYGES_HOME/<network>/gygesd.sock]
  -k, --key <KEY_ID>       Target key profile [env: GYGES_KEY] [default: the daemon's config `default_key`]
  -n, --network <NET>      mainnet | testnet | regtest [env: GYGES_NETWORK] [default: mainnet]
  -j, --json               Emit machine-readable JSON to stdout (one object per line for streams)
  -q, --quiet              Suppress progress bars, spinners and banners
      --non-interactive    Never prompt [env: GYGES_NON_INTERACTIVE]
      --passphrase-fd <N>  Read the vault passphrase from file descriptor N [env: GYGES_PASSPHRASE_FILE for a path]
```

- **The CLI never reads `config.toml`.** It is a pure gRPC client driven by flags and environment variables. An empty `--key` is sent as an empty `key_id` and the daemon substitutes its `default_key`.
- **`--network` selects the daemon.** There is one daemon per network under `$GYGES_HOME/<network>/` (default `~/.gyges`), so `-n testnet` resolves to the testnet socket. When both `--socket` and `--network` are given, the CLI compares `--network` with the daemon's `GetInfo.network` and exits 6 on mismatch.
- **`--json`** emits the gRPC response message serialized 1:1 as proto3 JSON plus a top-level `"schema_version"`; `API.md` and `gyges.proto` are the schema.

### 1.2 Non-interactive behaviour
The CLI never blocks on a prompt when stdin is not a TTY or `--non-interactive` is set.
- Passphrase needed: use `--passphrase-fd` / `GYGES_PASSPHRASE_FILE`, otherwise exit 4 with `key 'main' is locked; run 'gyges key unlock' or pass --passphrase-fd`.
- Keystone signature needed: the CLI prints the `session_id` and the UR frames (or writes them with `--qr-out <FILE>`) and exits 4; complete later with `gyges pczt qr-import --session <ID>`.
- With `--json`, these cases carry `reason` and `session_id` so wrappers can drive the flow.

### 1.3 Exit codes
| Code | Meaning |
|---|---|
| 0 | success |
| 1 | unspecified failure |
| 2 | usage error (clap) |
| 3 | daemon unreachable (`gygesd is not running; start it with 'gyges daemon start' or install a service with 'gyges daemon install'`) |
| 4 | authorization required and non-interactive (vault locked, Keystone signature needed, seed export refused) |
| 5 | insufficient funds |
| 6 | invalid argument or mismatch (bad address, wrong network, key id mismatch) |
| 7 | not ready (chain not synced, node unreachable) |
| 8 | cancelled by user |
| 9 | hardware signer error |
| 10 | node rejected transaction |

Each code maps from the `reason` field of the typed `GygesError` detail (`API.md` §4); the mapping lives in one function in `gyges-cli`.

### 1.4 Amount grammar
Used by `tx send --amount`, `pczt create --amount` and `tx shield --threshold`:
- decimal ZEC with up to 8 fractional digits: `1.25`, `0.00000001`;
- zatoshis with a `z` suffix: `125000000z`;
- `max`: all spendable funds of the selected pools minus the ZIP 317 fee (not valid for `--threshold`).
Thousands separators are rejected; leading `+` is rejected; the result must be in `[1, 21_000_000 ZEC]`.

### 1.5 Memo rules
`--memo <TEXT_OR_HEX>`: a value of the form `0x…` (even length, up to 1024 hex digits) is raw memo bytes; anything else is UTF-8 text, at most 512 bytes after encoding. A memo to a recipient without a shielded receiver (`t1`, `t3`, `tex1`) is an error (exit 6), never silently dropped.

---

## 2. Command Reference

### 2.1 Daemon management (`gyges daemon`)

#### `gyges daemon start`
Starts `gygesd` for `--network` and creates its Unix socket.
```text
Flags:
  -f, --foreground                 Run in foreground (do not daemonize)
      --airgapped                  Disable all network/RPC/Tor interfaces (signer-only profiles, PCZT proving and signing only)
      --zakura-rpc <URL>           Override the zakurad JSON-RPC endpoint (e.g. http://127.0.0.1:8232)
      --zakura-cookie <PATH>       Path to the zakurad RPC auth cookie
      --fallback-lwd <GRPC_URL>    Archival lightwalletd/zaino gRPC URL for historical restores (no default)
      --no-tor                     Reach the fallback endpoint directly instead of over Tor
```
The CLI does not start the daemon implicitly (exit 3 when the socket is absent) unless `GYGES_AUTOSTART=1` is set for development.

#### `gyges daemon install` / `gyges daemon uninstall`
Writes or removes a `launchd` user agent (macOS) or `systemd --user` unit (Linux) that runs `gygesd --foreground` for `--network` and restarts it after upgrades.

#### `gyges daemon stop`
Finishes the current scan batch, checkpoints SQLite WAL, aborts in-progress proving, leaves pending ZIP 320 and signing-session rows to resume on next start, and zeroizes all unlocked keys before exit.

#### `gyges daemon status`
Daemon version and API version, network, airgapped flag, `zakurad` connection state, node bounds (`tip_height`, `retained_from`, the node's `tx_retention`), Tor bootstrap state, fallback endpoint trust state, and a per-key line with signing mode, lock state, `scanned_tip` and sync state.

#### `gyges daemon logs [--follow] [--lines <N>]`
Streams structured daemon logs through the `StreamLogs` RPC (the CLI never tails the file).

---

### 2.2 Keys and vault (`gyges key`)

#### `gyges key list`
Lists key profiles with `SigningMode` (`local-seed`, `keystone-qr`, `watch-only`, `signer-only`), `LOCKED`/`UNLOCKED`, `birthday_height`, `scanned_tip` and sync state.

#### `gyges key init --id <KEY_ID> [--set-default]`
Generates 24-word BIP 39 entropy, sets `birthday_height` to the node's current tip, initialises `wallet.sqlite`, encrypts `seed.age` with a passphrase (prompted twice), displays the mnemonic once and requires three randomly chosen words to be typed back before continuing. TTY required (exit 4 otherwise).

#### `gyges key restore --id <KEY_ID> [--birthday <HEIGHT>] [--stdin]`
Restores a 24-word mnemonic. `--birthday` is strongly recommended; when omitted the CLI warns and uses the Sapling activation height (419,200 on mainnet), which implies a full backfill over Tor. If the birthday is below the node's `retained_from`, the daemon backfills over the configured fallback endpoint first; the first such restore asks `N blocks below the node's retention height must be fetched over Tor from <url>; continue? [y/N]` (`--yes` for scripts).

#### `gyges key import-keystone --id <KEY_ID> --birthday <HEIGHT> [--ur <UR_STRING>]`
Registers a Keystone 3 Pro profile from `ur:zcash-accounts` (tag 49201), `ur:zcash-unified-full-viewing-key` (49203) or a bare `uview1…` string. The accounts payload carries **no birthday**, so `--birthday` is required or prompted; the prompt defaults to the NU5 activation height (1,687,104 on mainnet). Records `device_version` and refuses firmware below the minimum.

#### `gyges key import-ufvk --id <KEY_ID> --ufvk <UFVK> --birthday <HEIGHT>`
Creates a watch-only profile (Orchard proving-only: Sapling spends need the proof generation key, which a UFVK does not contain).

#### `gyges key unlock [--id <KEY_ID>] [--timeout <DURATION>]`
Prompts for the passphrase and creates a **daemon-scoped** signing session with an idle TTL (`--timeout`, default `vault.unlock_ttl` = `5m`; e.g. `60s`, `15m`). This is the weaker of the two unlock modes (the inline `tx send` flow uses a connection-scoped session) and exists for batch scripts.

#### `gyges key lock [--id <KEY_ID> | --all]`
Destroys the signing sessions and zeroizes the decrypted key(s) immediately.

#### `gyges key export-ufvk [--id <KEY_ID>]`
Prints the `uview1…` UFVK.

#### `gyges key export-seed [--id <KEY_ID>]`
Prints the 24-word mnemonic. TTY required; prompts for the passphrase (never reuses a session); requires typing `reveal seed`; output never goes to `--json` or a file; written to the audit log; disabled when `vault.allow_seed_export = false`.

#### `gyges key backup --id <KEY_ID> -o <FILE.tar>` / `gyges key import-backup <FILE.tar>`
Checkpoints WAL and archives `profile.json`, `seed.age` and optionally `wallet.sqlite` (`--with-db`). Copying `keys/<id>/` by hand is supported only while the daemon is stopped.

#### `gyges key delete --id <KEY_ID> [--wipe]`
Removes a profile; `--wipe` overwrites files best-effort before unlinking. Requires typing the key id to confirm.

---

### 2.3 Synchronisation (`gyges sync`)

#### `gyges sync status [--key <KEY_ID> | --all]`
Live progress, blocks/sec, active route (`zakura-rpc` or `tor-lwd-fallback`), sync state (`initializing`, `backfilling`, `scanning`, `synced`, `stalled(<reason>)`), the `scanned` and `spendable` booleans, and ShardTree witness health.

#### `gyges sync wait [--key <KEY_ID>] [--until scanned|spendable] [--txid <TXID> --confirmations <N>] [--timeout <DURATION>]`
Blocks until the key is *spendable* (default: `scanned_tip` at the node tip and no open scan ranges above priority `Ignored`) or merely *scanned* (`--until scanned`). With `--txid`, waits until that transaction has `N` confirmations instead. Exits 7 if the key is `stalled`.

#### `gyges sync run [--key <KEY_ID>] [--from <HEIGHT>] [--to <HEIGHT>] [--force-tor-lwd]`
Triggers an immediate foreground scan. `--from` **rewinds**: it truncates notes, nullifiers and ShardTree checkpoints above `HEIGHT - 1` before rescanning; unmined transactions are kept and re-evaluated against their expiry. Requires confirmation unless `--yes`.

#### `gyges sync mempool [--key <KEY_ID>]`
Forces an immediate mempool pass. Mempool scanning otherwise runs continuously in the daemon (`mempool.scan = true`), fed by the node's `mempool_change` stream or `getrawmempool` diffs.

---

### 2.4 Addresses, QR codes and balances (`gyges address`, `gyges balance`, `gyges notes`)

#### `gyges address current [--qr]`
Prints the current Unified Address for `--key`; `--qr` renders it as a UTF-8 half-block QR code.

#### `gyges address new [--receivers <LIST>] [--label <TEXT>] [--qr]`
Derives a fresh diversified Unified Address.
```text
Flags:
      --receivers <LIST>    Comma-separated: orchard,sapling,transparent [default: orchard,sapling; keystone-qr profiles: orchard,transparent]
      --label <TEXT>        Metadata label stored in gyges_address_labels
      --qr                  Render a QR code in the terminal
```
There is deliberately no `--tex` flag: `tex1` addresses exist so exchanges can force senders to pay from transparent funds, and a privacy wallet advertising one would force every counterparty to deshield. `tex1` is supported on the send side only.

#### `gyges address qr [<ADDRESS>]`
Static QR for the current address or any address given.

#### `gyges address inspect <ADDRESS>`
Parses any Zcash address (`u1`, `utest1`, `zs1`, `t1`, `t3`, `tex1`, `textest1`), validates checksum and network, lists embedded receivers and whether the address is a ZIP 320 TEX address.

#### `gyges balance [--min-conf <N>]`
**Spendable**, **Pending confirmation** and **Transparent UTXO** balances per pool (Orchard, Sapling, Transparent; Ironwood when enabled). *Spendable* means confirmed to the daemon's anchor depth (`--min-conf`, default 10, the upstream default), with witnesses available.

#### `gyges notes [--pool <orchard|sapling|transparent>] [--unspent | --spent]`
Decrypted notes and UTXOs with heights, values, memo previews and witness readiness.

---

### 2.5 Transactions (`gyges tx`)

#### `gyges tx send --to <ADDR> --amount <AMOUNT>`
Proposes, proves, signs and broadcasts. The proposal summary (inputs per pool, outputs, ZIP 317 fee per step, total debit) is printed before any signature prompt.
- **Inline unlock (`local-seed`):** on `SignatureRequired`, prompts for the passphrase, creates a connection-scoped session and continues; the key is dropped after signing.
- **Keystone (`keystone-qr`):** renders the animated UR QR (batch protocol for shielded-only sends, single-PCZT when transparent inputs are present) and reads the result from the camera (`qr-scan`), a file, stdin or pasted frames.
- **ZIP 320 (`tex1`):** runs the two-step plan through the durable `TexQueue`; prints `tex pending (step 2 of 2)` until Step 2 is mined.
```text
Flags:
      --to <ADDR>           u1, zs1, t1, t3, tex1 (or testnet equivalents)
      --amount <AMOUNT>     See §1.4
      --memo <TEXT_OR_HEX>  See §1.5; shielded recipients only
      --via-tor             Broadcast over an isolated Tor circuit
      --dry-run             Print the full proposal (every step, every fee) and exit without signing
      --yes                 Skip the confirmation prompt
```

#### `gyges tx shield [--threshold <AMOUNT>]`
Sweeps transparent UTXOs above the threshold into the key's Orchard pool (auto-shielding; no ZIP governs this behaviour).

#### `gyges tx list [--limit <N>]`
History with timestamps, pool flows, ZIP 317 fees, decrypted memos, and pending states (`awaiting-signature`, `tex pending`).

#### `gyges tx status <TXID> [--pir]`
Confirmation status from the node, or via `zakura-pir-status` with `--pir`. **Experimental:** the PIR servers queried, their operators and the privacy guarantee must be documented before this leaves experimental status.

#### `gyges tx sessions` / `gyges tx abort <SESSION_ID | TXID>` / `gyges tx resume <TXID>`
Lists pending signing sessions and ZIP 320 rows; `abort` cancels a signing session, or a TEX row while it is still `built`; `resume` forces a retry of a TEX row, building a new Step 2 if Step 1 was mined and Step 2 expired.

---

### 2.6 PCZT pipeline (`gyges pczt`)
Exposes the ZIP 374 roles for Unix-pipe composition and air-gapped signing. Every PCZT written by `pczt create` carries `gyges.key_id`, `gyges.network` and `gyges.session_id` in its global `proprietary` map; downstream commands read the key id from the stream and use `--key` only as an assertion (exit 6 on mismatch). `combine` refuses inputs with different key ids. The Redactor strips the proprietary map before a PCZT goes to a Keystone.

```bash
gyges pczt create --to u1q... --amount 2.5 \
  | gyges pczt prove \
  | gyges pczt sign \
  | gyges pczt broadcast
```

- `gyges pczt create --to <ADDR> --amount <AMOUNT> [--memo <TEXT_OR_HEX>] [-o <FILE>]`
- `gyges pczt inspect [<FILE>]`
- `gyges pczt prove [<FILE>] [-o <OUT_FILE>]` (Orchard and transparent while locked; Sapling inputs require an unlock first)
- `gyges pczt sign [<FILE>] [-o <OUT_FILE>] [--qr-out <FILE>]`
- `gyges pczt qr-export [<FILE>] [--fps <N>]` (animates `ur:zcash-pczt` / `ur:zcash-sign-batch` frames)
- `gyges pczt qr-scan [--session <ID>] [-o <OUT_FILE>]` (laptop camera, feeds the fountain decoder until complete)
- `gyges pczt qr-import [--session <ID>] [--from-file <FRAMES.txt>] [<UR_FRAME>...] [-o <OUT_FILE>]` (one `ur:` frame per line from a file or stdin; positional frames for single-frame payloads such as batch signature results)
- `gyges pczt combine <FILE_A> <FILE_B> [-o <OUT_FILE>]`
- `gyges pczt broadcast [<FILE>] [--via-tor]` (runs Verifier against the stored proposal first)

Binary `.pczt` files use the `pczt` crate's postcard serialization; `-` means stdin/stdout.
