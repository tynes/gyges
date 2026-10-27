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
The CLI locates `gygesd` through `GYGES_DAEMON_BIN`, then next to its own executable, then on `PATH`. Without `--foreground` the daemon detaches itself after validating its configuration, so configuration and permission errors are reported by `daemon start` (exit 1). Running `daemon start` against an already running daemon is a no-op (exit 0). The CLI does not start the daemon implicitly (exit 3 when the socket is absent) unless `GYGES_AUTOSTART=1` is set for development.

#### `gyges daemon install` / `gyges daemon uninstall`
Writes or removes a `launchd` user agent (macOS) or `systemd --user` unit (Linux) that runs `gygesd --foreground` for `--network` and restarts it after upgrades.

#### `gyges daemon stop`
Finishes the current scan batch, checkpoints SQLite WAL, aborts in-progress proving, leaves pending ZIP 320 and signing-session rows to resume on next start, and zeroizes all unlocked keys before exit.

#### `gyges daemon status`
Daemon version and API version, network, airgapped flag, `zakurad` connection state, node bounds (`tip_height`, `retained_from`, the node's `tx_retention`), Tor bootstrap state, fallback endpoint trust state, and a per-key line with signing mode, lock state, `scanned_tip` and sync state.

#### `gyges daemon logs [--follow] [--lines <N>] [--audit]`
Streams structured daemon logs through the `StreamLogs` RPC (the CLI never tails the file). Replays the last `N` entries (default 100, at most the 1,000 the daemon keeps), then with `--follow` keeps printing until Ctrl-C. `--audit` streams the audit log instead (`API.md` §4.5). `--json` prints one `LogEntry` per line.

---

### 2.2 Keys and vault (`gyges key`)

#### `gyges key list`
Lists key profiles with `SigningMode` (`local-seed`, `keystone-qr`, `watch-only`, `signer-only`), `locked`/`UNLOCKED`, `birthday_height`, `scanned_tip` and sync state (sync state arrives with `SyncScheduler`; `signer-only` profiles show `-` for birthday and scanned tip).

#### `gyges key init --id <KEY_ID> [--set-default]`
Generates 24-word BIP 39 entropy, sets `birthday_height` to the node's current tip, initialises `wallet.sqlite`, encrypts `seed.age` with a passphrase (prompted twice), displays the mnemonic once and requires three randomly chosen words to be typed back before continuing. TTY required (exit 4 otherwise).

- **Scripted form.** With `--json` *and* a passphrase source (`--passphrase-fd` or `GYGES_PASSPHRASE_FILE`) no terminal is needed: the `InitKeyResponse` (mnemonic included) is printed as JSON and nothing is typed back. This is the form the regtest suite uses. `--json` without a passphrase source is still refused (exit 4, `CONFIRMATION_REQUIRED`).
- **Air-gapped daemon.** Against `gygesd --airgapped` the command creates a `signer-only` profile (seed and profile, no wallet, no birthday), the only mode an air-gapped box needs.
- `--set-default` applies until the daemon restarts; the daemon never rewrites `config.toml`, so the CLI prints the `default_key = "<id>"` line to add. The same holds for `key restore --set-default`.

#### `gyges key restore --id <KEY_ID> [--birthday <HEIGHT>] [--stdin] [--yes] [--set-default]`
Restores a 24-word mnemonic, read from a hidden prompt or, with `--stdin`, from standard input. `--birthday` is strongly recommended; when omitted the CLI warns and uses the Sapling activation height (419,200 on mainnet), which implies a full backfill over Tor. If the birthday is below the node's `retained_from`, the daemon backfills over the configured fallback endpoint first; the first such restore asks `N blocks below the node's retention height must be fetched over Tor from <url>; continue? [y/N]` (`--yes` for scripts). Before the question the CLI prints what the endpoint learns (the block range, about the birthday, and the key's transparent addresses), and, for a clearnet host with `use_tor = true`, that a Tor exit relay sits in between and an `.onion` address avoids it (OVERVIEW.md Q-D5). Such a restore prints `warning: transparent history below height <retained_from> comes from the fallback endpoint and is best-effort…` on stderr, and `daemon status` repeats it under the key once the backfill is validated (THREAT_MODEL.md §6 item 9). Without a configured endpoint, or with one marked untrusted by a failed handoff, such a restore is refused with exit 7 (`FALLBACK_UNAVAILABLE`) after the consent step; any birthday above Sapling activation needs the node's tree state and exits 7 (`NODE_UNREACHABLE`) when no node is connected.

#### `gyges key import-keystone --id <KEY_ID> [--birthday <HEIGHT>] [--ur <UR_STRING>]… [--account <N>] [--allow-unknown-firmware] [--yes] [--set-default]`
Registers a Keystone 3 Pro profile from the device's `ur:zcash-accounts` export (tag 49201, Connect Software Wallet on the device). The frames come from `--ur` (repeat it for a multi-part export; one value may also hold several frames separated by whitespace) or, without `--ur`, from standard input, one per line. Only this type carries the seed fingerprint the device needs in every PCZT to recognise its own key, so a `ur:zcash-unified-full-viewing-key` (49203) or a bare `uview1…` is refused with exit 6 and a pointer to `key import-ufvk` (watch-only).

The export carries **no birthday**: without `--birthday` the CLI asks whether to scan from the NU5 activation height (1,687,104 on mainnet; the device's UFVK has no Sapling component, so nothing earlier can belong to it), and without a terminal it exits 4 asking for `--birthday`. A birthday below the node's window goes through the same consent, notes and best-effort warning as `key restore` (`--yes` for scripts). `--account N` picks a ZIP 32 account when the export lists several (default 0); an export of one account is imported whatever its index.

Firmware: the export's `device_version` is the raw `MAJOR.MINOR.BUILD` of the firmware, whose About screen shows the major less 10 (`13.2.0` in the QR is `v3.2.0` on the device). Below Cypherpunk v3.0.2 (`13.0.2`), the minimum for signing after NU6.3, the import is refused with exit 9, naming both forms. Firmware older than the pairing QR's version field reports none: that is exit 4 unless `--allow-unknown-firmware`, which imports the key with `device_version = "unknown"` and a warning.

Exit codes: 6 for the wrong payload, an incomplete one or an account the export does not list; 9 when the export decodes but its content is refused (old firmware, a seed fingerprint that is not 32 bytes, a UFVK for another network or without an Orchard component); 4 for the unknown version and the birthday or backfill confirmations. The CLI checks the payload type and firmware itself before any question, and the daemon checks everything again. On success it prints the account, seed fingerprint, firmware (both forms) and birthday on stderr; `--json` prints `ImportKeystoneResponse`.

**Landed (ROADMAP.md M5, second item).** The key syncs, survives a daemon restart, shows balances, hands out unified addresses with Orchard and transparent receivers (never Sapling; an Orchard receiver also takes Ironwood payments) and builds PCZTs with `pczt create`; `tx send`, `tx shield`, `pczt sign` and `key unlock` refuse it until the QR signing protocols (third item).

#### `gyges key import-ufvk --id <KEY_ID> --ufvk <UFVK> --birthday <HEIGHT>`
Creates a watch-only profile (Orchard proving-only: Sapling spends need the proof generation key, which a UFVK does not contain).

#### `gyges key unlock [--id <KEY_ID>] [--timeout <DURATION>]`
Prompts for the passphrase (or takes it from `--passphrase-fd` / `GYGES_PASSPHRASE_FILE`) and creates a **daemon-scoped** unlock with an idle TTL (`--timeout`, default `vault.unlock_ttl` = `5m`; e.g. `60s`, `15m`). This is the weaker of the two unlock modes (the inline `tx send` flow uses a connection-scoped session) and exists for batch scripts; the confirmation line says so and names the expiry. `--id` falls back to `--key`, then to the daemon's `default_key`. A wrong passphrase exits 4 (`INVALID_PASSPHRASE`); further attempts on the same key are refused with `RATE_LIMITED` for 1 s, doubling per failure up to `vault.unlock_backoff_max`, whichever connection they come from.

#### `gyges key lock [--id <KEY_ID> | --all]`
Destroys the unlocks of one key (every scope) or of every key and zeroizes the decrypted material immediately. `daemon stop` does the same for every key.

#### `gyges key export-ufvk [--id <KEY_ID>]`
Prints the `uview1…` UFVK. A `signer-only` profile keeps no viewing key on disk, so it needs a live daemon-scoped unlock first (exit 4, `VAULT_LOCKED`, otherwise).

#### `gyges key export-seed [--id <KEY_ID>]`
Prints the 24-word mnemonic. TTY required on stdin, stdout and stderr (exit 4 otherwise); requires typing `reveal seed` first; then prompts for the passphrase on the terminal (never `--passphrase-fd`, never an existing unlock); output never goes to `--json` (exit 6) or a file; written to the audit log; disabled when `vault.allow_seed_export = false` (exit 4, `SEED_EXPORT_DISABLED`). A failed passphrase here counts against the same per-key back-off as `key unlock`.

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
Forces an immediate mempool pass for every key, even with `mempool.scan = false`. It covers every transaction in the node's mempool, up to 500. Mempool scanning otherwise runs continuously in the daemon (`mempool.scan = true`), fed by `getrawmempool` diffs (the node's `mempool_change` stream once an indexer exists). Prints `scanned N transactions, found M notes`, where the notes are those paying `--key` (every key without it). Notes found show as pending in `balance` until mined. `--json` prints `ScanMempoolResponse`.

---

### 2.4 Addresses, QR codes and balances (`gyges address`, `gyges balance`, `gyges notes`)

#### `gyges address current [--qr]`
Prints the current Unified Address for `--key`; `--qr` renders it as a UTF-8 half-block QR code.

#### `gyges address new [--receivers <LIST>] [--label <TEXT>] [--qr]`
Derives a fresh diversified Unified Address.
```text
Flags:
      --receivers <LIST>    Comma-separated: orchard,sapling,transparent [default: orchard,sapling; keystone-qr profiles: orchard,transparent]
      --label <TEXT>        Metadata label stored in ext_gyges_address_labels
      --qr                  Render a QR code in the terminal
```
There is deliberately no `--tex` flag: `tex1` addresses exist so exchanges can force senders to pay from transparent funds, and a privacy wallet advertising one would force every counterparty to deshield. `tex1` is supported on the send side only.

#### `gyges address qr [<ADDRESS>]`
Static QR for the current address or any address given.

#### `gyges address inspect <ADDRESS>`
Parses any Zcash address (`u1`, `utest1`, `zs1`, `t1`, `t3`, `tex1`, `textest1`), validates checksum and network, lists embedded receivers and whether the address is a ZIP 320 TEX address.

#### `gyges balance [--min-conf <N>]`
**Spendable** and **Pending** balances per pool (Orchard, Ironwood, Sapling, Transparent) with totals and the height they are as of. *Spendable* means confirmed to the daemon's anchor depth (`--min-conf`, default `policy.min_confirmations` = 10, the upstream default), with witnesses available; *pending* is received but below that depth, unmined, or change awaiting confirmation.

#### `gyges notes [--pool <orchard|ironwood|sapling|transparent>] [--unspent | --spent | --all]`
Decrypted notes and UTXOs with heights, values, memo previews and witness readiness.

**Landed (ROADMAP.md M1 follow-up):** `address current`, `address new`, `address inspect` and `notes`. `current` and `new` print the address alone on stdout (so `$(gyges address current)` works) and its receivers, diversifier index and label on stderr (quiet with `-q`). On a fresh key `current` is the account's default address, which carries every receiver the key has (Orchard, Sapling and transparent); `address new` without `--receivers` gives a shielded-only one, and from then on `current` is the newest address handed out. `new` needs the first sync to have recorded the chain tip (exit 7 before that); `--receivers transparent` alone is exit 6 (a unified address needs a shielded receiver). `inspect` exits 6 when the address is malformed or for another network than the daemon's (with `--json`, the error object). `notes` lists oldest first; the memo preview of an incoming payment waits for transaction enhancement, while the wallet's own sends always show theirs (API.md §7.2). **Landed (ROADMAP.md M5, first item):** `--qr` on `current` and `new` adds a UTF-8 half-block QR code of the address on stderr (hidden by `-q`), so stdout is still the address alone. `address qr` prints the code on stdout with the address on the line under it; with `--json` it prints `{"address", "qr"}`. A given address is checked with `InspectAddress` first and refused with exit 6 if it is malformed or for another network, so a mistyped address is never rendered. The code is drawn for a light-on-dark terminal (blocks are the light modules), and the address is encoded as typed, in byte mode.

---

### 2.5 Transactions (`gyges tx`)

#### `gyges tx send --to <ADDR> --amount <AMOUNT>`
Proposes, proves, signs and broadcasts. The proposal summary (inputs per pool, outputs, ZIP 317 fee per step, total debit) is printed before any signature prompt; without `--yes` it comes from a dry run and is confirmed before the real send starts (no terminal: exit 4, `CONFIRMATION_REQUIRED`). The txid goes to stdout; progress goes to stderr.
- **Inline unlock (`local-seed`):** on `SignatureRequired`, prompts for the passphrase, creates a connection-scoped session and continues; the key is dropped after signing.
- **Keystone (`keystone-qr`):** renders the animated UR QR (batch protocol for shielded-only sends, single-PCZT when transparent inputs are present) and reads the result from the camera (`qr-scan`), a file, stdin or pasted frames.
- **ZIP 320 (`tex1`):** runs the two-step plan through the durable `TexQueue`; the passphrase prompt comes before proving (both steps are built together, API.md §9), each step's txid goes to stdout as the node takes it, and `tex pending (step 2 of 2): <step1> then <step2>` goes to stderr. A node that will not take Step 2 while Step 1 is unmined leaves one txid on stdout; the queue finishes the transfer and `tx sessions` shows its state.
```text
Flags:
      --to <ADDR>           u1, zs1, t1, t3, tex1 (or testnet equivalents)
      --amount <AMOUNT>     See §1.4
      --memo <TEXT_OR_HEX>  See §1.5; shielded recipients only
      --via-tor             Broadcast through the fallback endpoint over Tor (exit 7 when none is configured; never the node)
      --dry-run             Print the full proposal (every step, every fee) and exit without signing
      --yes                 Skip the confirmation prompt
      --wait                Keep the stream open until the transaction is mined
```

#### `gyges tx shield [--threshold <AMOUNT>] [--dry-run] [--yes] [--wait]`
Sweeps transparent UTXOs of at least the threshold (in total; default: any) into the key's shielded pool (Ironwood after NU6.3; auto-shielding, no ZIP governs this behaviour). Same confirmation, signing and output as `tx send`.

#### `gyges tx list [--limit <N>] [--before <TXID>]`
History with timestamps, pool flows, ZIP 317 fees, decrypted memos, and pending states (`awaiting-signature`, `tex pending`). `--before` pages: pass the last txid of the previous page.

#### `gyges tx status <TXID> [--pir]`
Confirmation status from the node, or via `zakura-pir-status` with `--pir`. **Experimental:** the PIR servers queried, their operators and the privacy guarantee must be documented before this leaves experimental status.

**Landed (ROADMAP.md M1 follow-up):** `tx list` prints newest first, one line per transaction (time, status, height, net value with fees, fee, txid), then its non-change outputs with pool, value, recipient and memo, and its ZIP 320 row; statuses are `pending`, `mined`, `expired`, `failed` and `tex-pending` (`awaiting-signature` never shows: a session holds no transaction until it is signed). `tx status` prints `mined at height H (N confirmations)` or the state; an unknown txid is exit 6, an unreachable node exit 7. `--json` prints `ListTransactionsResponse` / `GetTransactionStatusResponse` (API.md §7.2). Not yet: `--pir` exits 1 before contacting the daemon (ROADMAP.md M6).

#### `gyges tx sessions [--all] [--include-finished]` / `gyges tx abort <SESSION_ID | TXID>` / `gyges tx resume <TXID>`
Lists pending signing sessions (and, with `--include-finished`, completed, expired, aborted and failed ones the daemon still remembers) and ZIP 320 rows (a second table: step-1 txid, key, state, expiry, attempts, amount and the node's last refusal); `abort` cancels a signing session, or a TEX row while it is still `built`; `resume` forces a retry of a TEX row, building a new Step 2 if Step 1 was mined and Step 2 expired. `resume` prompts for the passphrase like `tx send` when the key is locked, waits for the daemon to store the new Step 2 (up to two minutes) and prints its txid on stdout; on a row the queue is still working on it only triggers an immediate re-check.

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
- `gyges pczt qr-export --session <ID> [--fps <N>] [-o <FILE>]` (animates the pending Keystone session's `ur:zcash-pczt` / `ur:zcash-sign-batch` request; `<FILE>` instead of `--session` is not supported yet)
- `gyges pczt qr-scan --session <ID> [--camera <N>] [--timeout <DURATION>]` (laptop camera, feeds the fountain decoder until complete; needs a build with the `camera` feature; without `--session`, for a PCZT file, not supported yet)
- `gyges pczt qr-import --session <ID> [--from-file <FRAMES.txt>] [<UR_FRAME>...]` (one `ur:` frame per line from a file or stdin; positional frames for single-frame payloads such as batch signature results; without `--session`, for a PCZT file, not supported yet)
- `gyges pczt combine <FILE_A> <FILE_B> [-o <OUT_FILE>]`
- `gyges pczt broadcast [<FILE>] [--via-tor]` (runs Verifier against the stored proposal first)

Binary `.pczt` files use the `pczt` crate's postcard serialization; `-` means stdin/stdout.

**Landed (ROADMAP.md M4, first item):** `create`, `inspect`, `prove`, `sign`, `combine` and `broadcast`. Input is the positional file, or stdin when it is absent or `-`; output goes to `-o FILE` (created 0600) or stdout, and a command refuses to write a PCZT to a terminal (exit 6: pass `-o` or pipe). `create` prints the proposal and the session id on stderr (quiet with `-q`); `inspect` prints the key, network and session, the steps as `tx send --dry-run` lays them out (the anchor height and confirmations are not in a file, so the footer is the expiry height only), the roles whose footprints are present, and per pool the spends, outputs, proofs and `signed/required` signatures; `broadcast` prints the txid on stdout. With `--json` every command prints its RPC response on stdout (the PCZT bytes as base64 inside it, per API.md §5) and writes a file only when `-o` is given. `sign` prompts for the passphrase like `tx send` (or reads `--passphrase-fd` / `GYGES_PASSPHRASE_FILE`; no terminal and no source is exit 4). A `tex1` recipient is refused by `create` with exit 6 and a pointer to `tx send` (upstream builds a PCZT from a single-step proposal only). A file from `create` may be mined up to 1152 blocks past its target height (about a day), not the 40 of `tx send`. `broadcast --via-tor` follows the `tx send --via-tor` rule (API.md §4.1). Not yet: `sign --qr-out` (M5).

**Landed (ROADMAP.md M5, third item):** `tx send` and `tx shield` from a `keystone-qr` key.
- **On a terminal:** they print the proposal and loop the request as a QR code on stderr until Enter. The request uses the batch protocol, or the single-PCZT one when the transaction has transparent inputs, as for shielding. They then read the device's answer as pasted `ur:` frames, one or more per line, as a phone's QR reader gives them. A refused answer can be scanned again, up to three times.
- **Without a terminal, or with `--json`:** the request's frames go to stdout, one per line (with `--json` only the `SignatureRequired` event carries the payload), and the command exits 4 naming the session.
- **With `--qr-out FILE`:** the frames are written to the file, with the same exit 4.
- **Completing later:** `pczt qr-export --session ID` shows the frames again, animated on a terminal, else printed or written with `-o`. `pczt qr-import --session ID` completes the session from positional frames, `--from-file` or stdin, and prints the txid. A partial or foreign set of frames is exit 6 before the daemon is asked; a refused answer is exit 9 and the session stays open.
- **Not yet:** the PCZT file flow, meaning `qr-export FILE` (a file must be redacted for the device first) and `qr-import` without `--session`.

**Landed (ROADMAP.md M5, fourth item):** the camera, in builds with the `camera` feature (off by default; `cargo build --features gyges-cli/camera`).
- **`pczt qr-scan --session ID`** reads the device's answer with the camera (the first unless `--camera N`) for up to `--timeout` (default 2 minutes), completes the session, and prints the txid.
  - Progress goes to stderr; Ctrl-C stops the scan.
  - No camera, denied access (macOS asks once, for the terminal application) or a camera that offers only MJPEG is exit 1 with the reason, as is a build without the feature.
- **`tx send` / `tx shield` on a terminal** scan the answer by themselves after Enter, for up to a minute, then fall back to pasted frames; Ctrl-C during the scan also switches to pasting. After a refused answer they wait for Enter (redo it on the device) before scanning again. `GYGES_NO_CAMERA=1` skips the camera.
- **Ctrl-C** at the QR animation or the paste prompt (with or without a camera) leaves the session open and exits 4, for `qr-import` or `qr-scan --session` later.
