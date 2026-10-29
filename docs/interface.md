# Gyges Interface

The two contracts a user or a script touches. The document has two parts:

- [CLI](#cli): every `gyges` command, its options, exit codes and the amount and memo grammar.
- [API](#api): the gRPC contract between `gyges` and `gygesd`: transport, authentication, versioning, the error model, streaming, signing sessions, and the command-to-RPC mapping. The machine-readable source is [`proto/gyges.proto`](../proto/gyges.proto).

Section numbers restart in each part. A bare § refers to the part it appears in; a reference into another part names it (for example "API §6.2").

## CLI

Every command maps to exactly one RPC in [`proto/gyges.proto`](../proto/gyges.proto); the mapping table is API §7.

### 1. Global behaviour

#### 1.1 Global options
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
- **`--json`** emits the gRPC response message serialized 1:1 as proto3 JSON plus a top-level `"schema_version"`; the API part and `gyges.proto` are the schema.

#### 1.2 Non-interactive behaviour
The CLI never blocks on a prompt when stdin is not a TTY or `--non-interactive` is set.
- Passphrase needed: use `--passphrase-fd` / `GYGES_PASSPHRASE_FILE`, otherwise exit 4 with `key 'main' is locked; run 'gyges key unlock' or pass --passphrase-fd`.
- Keystone signature needed: the CLI prints the `session_id` and the UR frames (or writes them with `--qr-out <FILE>`) and exits 4; complete later with `gyges pczt qr-import --session <ID>`.
- With `--json`, these cases carry `reason` and `session_id` so wrappers can drive the flow.

#### 1.3 Exit codes
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

Each code maps from the `reason` field of the typed `GygesError` detail (API §4); the mapping lives in one function in `gyges-cli`.

#### 1.4 Amount grammar
Used by `tx send --amount`, `pczt create --amount` and `tx shield --threshold`:
- decimal ZEC with up to 8 fractional digits: `1.25`, `0.00000001`;
- zatoshis with a `z` suffix: `125000000z`;
- `max`: all spendable funds of the selected pools minus the ZIP 317 fee (not valid for `--threshold`).
Thousands separators are rejected; leading `+` is rejected; the result must be in `[1, 21_000_000 ZEC]`.

#### 1.5 Memo rules
`--memo <TEXT_OR_HEX>`: a value of the form `0x…` (even length, up to 1024 hex digits) is raw memo bytes; anything else is UTF-8 text, at most 512 bytes after encoding. A memo to a recipient without a shielded receiver (`t1`, `t3`, `tex1`) is an error (exit 6), never silently dropped.

---

### 2. Command Reference

#### 2.1 Daemon management (`gyges daemon`)

##### `gyges daemon start`
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

`gygesd` itself also takes `--socket <PATH>`, `--socket-group <GROUP>` and `--allow-uid <UID>` (repeatable), which override `daemon.socket_path`, `daemon.socket_group` and `daemon.allowed_uids` for that process. The hardened unit passes them; `daemon start` does not forward them.

##### `gyges daemon install` / `gyges daemon uninstall`
Writes or removes a per-user service that runs `gygesd --foreground` for `--network`: a `launchd` agent `~/Library/LaunchAgents/org.gyges.gygesd.<network>.plist` (macOS) or a `systemd --user` unit `$XDG_CONFIG_HOME/systemd/user/gygesd-<network>.service` (Linux). One service per network.

- **`install`** writes the unit with the absolute path of `gygesd` (found as for `daemon start`; a bare name is resolved on `PATH` now, since a service manager has none) and `GYGES_HOME` when it is set, loads it (`launchctl bootstrap gui/<uid>`, or `systemctl --user enable --now`), and waits up to 60 s for the daemon to answer. It refuses (exit 1) while a daemon started by hand is answering on the socket, since the unit's daemon would fail on the pid lock.
- **Restarts.** The service restarts the daemon after a failure (`KeepAlive.SuccessfulExit = false`, `Restart=on-failure`), but not after `daemon stop`, which exits 0 and leaves it stopped until the next login. A `systemd` unit gives up after five failed starts in five minutes. Nothing restarts a running daemon when its binary is replaced: **run `daemon install` again after upgrading**, which stops the service, rewrites the unit and starts it.
- **`uninstall`** stops the daemon, removes the unit and exits 0 when there is nothing to remove.
- **Linux.** A user unit stops when the user's last session ends unless lingering is on (`loginctl enable-linger $USER`); `install` says so.
- **`--json`** prints `{manager, unit_path, network, running}`.
- **`install --hardened [--user NAME]`** (Linux with systemd, as root) sets up the hardened deployment (`security.md` §6 item 4):
  - creates the `gyges` system group and user (no login shell) if missing, and adds the admitted user (`--user`, default `$SUDO_USER`, never root) to the group; they must log in again for that to apply;
  - writes `/etc/systemd/system/gygesd-<network>.service`, running `gygesd --network <network> --foreground --socket /run/gyges/<network>/gygesd.sock --socket-group gyges --allow-uid <uid>` as `gyges`, with `GYGES_HOME=/var/lib/gyges` (systemd `StateDirectory`, 0700), the socket directory from `RuntimeDirectory` (0750) and sandboxing (`ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`, `LimitCORE=0`, and others);
  - enables and starts it, and waits for the socket to accept (root is not an admitted peer, so there is no handshake).
  - `gygesd` must not live under `/home` or `/root`, which `ProtectHome=yes` hides; `install` refuses such a path. The node's cookie must be readable by `gyges` and named in `/var/lib/gyges/<network>/config.toml` (`zakura_rpc.cookie_path`).
  - The admitted user reaches the daemon with `GYGES_SOCKET=/run/gyges/<network>/gygesd.sock`.
  - macOS is refused.
- **`uninstall --hardened`** (as root) stops the unit and removes it. The `gyges` account and `/var/lib/gyges`, keys included, stay.

##### `gyges daemon stop`
Finishes the current scan batch, checkpoints SQLite WAL, aborts in-progress proving, leaves pending ZIP 320 and signing-session rows to resume on next start, and zeroizes all unlocked keys before exit.

##### `gyges daemon status`
Daemon version and API version, network, airgapped flag, `zakurad` connection state, node bounds (`tip_height`, `retained_from`, the node's `tx_retention`), Tor bootstrap state, fallback endpoint trust state, and a per-key line with signing mode, lock state, `scanned_tip` and sync state.

##### `gyges daemon logs [--follow] [--lines <N>] [--audit]`
Streams structured daemon logs through the `StreamLogs` RPC (the CLI never tails the file). Replays the last `N` entries (default 100, at most the 1,000 the daemon keeps), then with `--follow` keeps printing until Ctrl-C. `--audit` streams the audit log instead (API §4.5). `--json` prints one `LogEntry` per line.

---

#### 2.2 Keys and vault (`gyges key`)

##### `gyges key list`
Lists key profiles with `SigningMode` (`local-seed`, `keystone-qr`, `watch-only`, `signer-only`), `locked`/`UNLOCKED`, `birthday_height`, `scanned_tip` and sync state (sync state arrives with `SyncScheduler`; `signer-only` profiles show `-` for birthday and scanned tip).

##### `gyges key init --id <KEY_ID> [--set-default]`
Generates 24-word BIP 39 entropy, sets `birthday_height` to the node's current tip, initialises `wallet.sqlite`, encrypts `seed.age` with a passphrase (prompted twice), displays the mnemonic once and requires three randomly chosen words to be typed back before continuing. TTY required (exit 4 otherwise).

- **Scripted form.** With `--json` *and* a passphrase source (`--passphrase-fd` or `GYGES_PASSPHRASE_FILE`) no terminal is needed: the `InitKeyResponse` (mnemonic included) is printed as JSON and nothing is typed back. This is the form the regtest suite uses. `--json` without a passphrase source is still refused (exit 4, `CONFIRMATION_REQUIRED`).
- **Air-gapped daemon.** Against `gygesd --airgapped` the command creates a `signer-only` profile (seed and profile, no wallet, no birthday), the only mode an air-gapped box needs.
- `--set-default` applies until the daemon restarts; the daemon never rewrites `config.toml`, so the CLI prints the `default_key = "<id>"` line to add. The same holds for `key restore --set-default`.

##### `gyges key restore --id <KEY_ID> [--birthday <HEIGHT>] [--stdin] [--yes] [--set-default]`
Restores a 24-word mnemonic, read from a hidden prompt or, with `--stdin`, from standard input. `--birthday` is strongly recommended; when omitted the CLI warns and uses the Sapling activation height (419,200 on mainnet), which implies a full backfill over Tor. If the birthday is below the node's `retained_from`, the daemon backfills over the configured fallback endpoint first; the first such restore asks `N blocks below the node's retention height must be fetched over Tor from <url>; continue? [y/N]` (`--yes` for scripts). Before the question the CLI prints what the endpoint learns (the block range, about the birthday, and the key's transparent addresses), and, for a clearnet host with `use_tor = true`, that a Tor exit relay sits in between and an `.onion` address avoids it (decisions.md Q-D5). Such a restore prints `warning: transparent history below height <retained_from> comes from the fallback endpoint and is best-effort…` on stderr, and `daemon status` repeats it under the key once the backfill is validated (security.md §6 item 9). Without a configured endpoint, or with one marked untrusted by a failed handoff, such a restore is refused with exit 7 (`FALLBACK_UNAVAILABLE`) after the consent step; any birthday above Sapling activation needs the node's tree state and exits 7 (`NODE_UNREACHABLE`) when no node is connected.

##### `gyges key import-keystone --id <KEY_ID> [--birthday <HEIGHT>] [--ur <UR_STRING>]… [--account <N>] [--allow-unknown-firmware] [--yes] [--set-default]`
Registers a Keystone 3 Pro profile from the device's `ur:zcash-accounts` export (tag 49201, Connect Software Wallet on the device). The frames come from `--ur` (repeat it for a multi-part export; one value may also hold several frames separated by whitespace) or, without `--ur`, from standard input, one per line. Only this type carries the seed fingerprint the device needs in every PCZT to recognise its own key, so a `ur:zcash-unified-full-viewing-key` (49203) or a bare `uview1…` is refused with exit 6 and a pointer to `key import-ufvk` (watch-only).

The export carries **no birthday**: without `--birthday` the CLI asks whether to scan from the NU5 activation height (1,687,104 on mainnet; the device's UFVK has no Sapling component, so nothing earlier can belong to it), and without a terminal it exits 4 asking for `--birthday`. A birthday below the node's window goes through the same consent, notes and best-effort warning as `key restore` (`--yes` for scripts). `--account N` picks a ZIP 32 account when the export lists several (default 0); an export of one account is imported whatever its index.

Firmware: the export's `device_version` is the raw `MAJOR.MINOR.BUILD` of the firmware, whose About screen shows the major less 10 (`13.2.0` in the QR is `v3.2.0` on the device). Below Cypherpunk v3.0.2 (`13.0.2`), the minimum for signing after NU6.3, the import is refused with exit 9, naming both forms. Firmware older than the pairing QR's version field reports none: that is exit 4 unless `--allow-unknown-firmware`, which imports the key with `device_version = "unknown"` and a warning.

Exit codes: 6 for the wrong payload, an incomplete one or an account the export does not list; 9 when the export decodes but its content is refused (old firmware, a seed fingerprint that is not 32 bytes, a UFVK for another network or without an Orchard component); 4 for the unknown version and the birthday or backfill confirmations. The CLI checks the payload type and firmware itself before any question, and the daemon checks everything again. On success it prints the account, seed fingerprint, firmware (both forms) and birthday on stderr; `--json` prints `ImportKeystoneResponse`.

**Landed.** The key syncs, survives a daemon restart, shows balances, hands out unified addresses with Orchard and transparent receivers (never Sapling; an Orchard receiver also takes Ironwood payments) and builds PCZTs with `pczt create`; `tx send`, `tx shield`, `pczt sign` and `key unlock` refuse it until the QR signing protocols (third item).

##### `gyges key import-ufvk --id <KEY_ID> --ufvk <UFVK> --birthday <HEIGHT>`
Creates a watch-only profile (Orchard proving-only: Sapling spends need the proof generation key, which a UFVK does not contain).

##### `gyges key unlock [--id <KEY_ID>] [--timeout <DURATION>]`
Prompts for the passphrase (or takes it from `--passphrase-fd` / `GYGES_PASSPHRASE_FILE`) and creates a **daemon-scoped** unlock with an idle TTL (`--timeout`, default `vault.unlock_ttl` = `5m`; e.g. `60s`, `15m`). This is the weaker of the two unlock modes (the inline `tx send` flow uses a connection-scoped session) and exists for batch scripts; the confirmation line says so and names the expiry. `--id` falls back to `--key`, then to the daemon's `default_key`. A wrong passphrase exits 4 (`INVALID_PASSPHRASE`); further attempts on the same key are refused with `RATE_LIMITED` for 1 s, doubling per failure up to `vault.unlock_backoff_max`, whichever connection they come from.

##### `gyges key lock [--id <KEY_ID> | --all]`
Destroys the unlocks of one key (every scope) or of every key and zeroizes the decrypted material immediately. `daemon stop` does the same for every key.

##### `gyges key export-ufvk [--id <KEY_ID>]`
Prints the `uview1…` UFVK. A `signer-only` profile keeps no viewing key on disk, so it needs a live daemon-scoped unlock first (exit 4, `VAULT_LOCKED`, otherwise).

##### `gyges key export-seed [--id <KEY_ID>]`
Prints the 24-word mnemonic. TTY required on stdin, stdout and stderr (exit 4 otherwise); requires typing `reveal seed` first; then prompts for the passphrase on the terminal (never `--passphrase-fd`, never an existing unlock); output never goes to `--json` (exit 6) or a file; written to the audit log; disabled when `vault.allow_seed_export = false` (exit 4, `SEED_EXPORT_DISABLED`). A failed passphrase here counts against the same per-key back-off as `key unlock`.

##### `gyges key backup --id <KEY_ID> -o <FILE.tar>` / `gyges key import-backup <FILE.tar>`
Checkpoints WAL and archives `profile.json`, `seed.age` and optionally `wallet.sqlite` (`--with-db`). Copying `keys/<id>/` by hand is supported only while the daemon is stopped.

##### `gyges key delete --id <KEY_ID> [--wipe]`
Removes a profile; `--wipe` overwrites files best-effort before unlinking. Requires typing the key id to confirm.

---

#### 2.3 Synchronisation (`gyges sync`)

##### `gyges sync status [--key <KEY_ID> | --all]`
Live progress, blocks/sec, active route (`zakura-rpc` or `tor-lwd-fallback`), sync state (`initializing`, `backfilling`, `scanning`, `synced`, `stalled(<reason>)`), the `scanned` and `spendable` booleans, and ShardTree witness health.

##### `gyges sync wait [--key <KEY_ID>] [--until scanned|spendable] [--txid <TXID> --confirmations <N>] [--timeout <DURATION>]`
Blocks until the key is *spendable* (default: `scanned_tip` at the node tip and no open scan ranges above priority `Ignored`) or merely *scanned* (`--until scanned`). With `--txid`, waits until that transaction has `N` confirmations instead. Exits 7 if the key is `stalled`.

##### `gyges sync run [--key <KEY_ID>] [--from <HEIGHT>] [--to <HEIGHT>] [--force-tor-lwd]`
Triggers an immediate foreground scan. `--from` **rewinds**: it truncates notes, nullifiers and ShardTree checkpoints above `HEIGHT - 1` before rescanning; unmined transactions are kept and re-evaluated against their expiry. Requires confirmation unless `--yes`. `--to` and `--force-tor-lwd` are not implemented yet (exit 1).

##### `gyges sync mempool [--key <KEY_ID>]`
Forces an immediate mempool pass for every key, even with `mempool.scan = false`. It covers every transaction in the node's mempool, up to 500. Mempool scanning otherwise runs continuously in the daemon (`mempool.scan = true`), fed by `getrawmempool` diffs (the node's `mempool_change` stream once an indexer exists). Prints `scanned N transactions, found M notes`, where the notes are those paying `--key` (every key without it). Notes found show as pending in `balance` until mined. `--json` prints `ScanMempoolResponse`.

---

#### 2.4 Addresses, QR codes and balances (`gyges address`, `gyges balance`, `gyges notes`)

##### `gyges address current [--qr]`
Prints the current Unified Address for `--key`; `--qr` renders it as a UTF-8 half-block QR code.

##### `gyges address new [--receivers <LIST>] [--label <TEXT>] [--qr]`
Derives a fresh diversified Unified Address.
```text
Flags:
      --receivers <LIST>    Comma-separated: orchard,sapling,transparent [default: orchard,sapling; keystone-qr profiles: orchard,transparent]
      --label <TEXT>        Metadata label stored in ext_gyges_address_labels
      --qr                  Render a QR code in the terminal
```
There is deliberately no `--tex` flag: `tex1` addresses exist so exchanges can force senders to pay from transparent funds, and a privacy wallet advertising one would force every counterparty to deshield. `tex1` is supported on the send side only.

##### `gyges address qr [<ADDRESS>]`
Static QR for the current address or any address given.

##### `gyges address inspect <ADDRESS>`
Parses any Zcash address (`u1`, `utest1`, `zs1`, `t1`, `t3`, `tex1`, `textest1`), validates checksum and network, lists embedded receivers and whether the address is a ZIP 320 TEX address.

##### `gyges balance [--min-conf <N>]`
**Spendable** and **Pending** balances per pool (Orchard, Ironwood, Sapling, Transparent) with totals and the height they are as of. *Spendable* means confirmed to the daemon's anchor depth (`--min-conf`, default `policy.min_confirmations` = 10, the upstream default), with witnesses available; *pending* is received but below that depth, unmined, or change awaiting confirmation.

##### `gyges notes [--pool <orchard|ironwood|sapling|transparent>] [--unspent | --spent | --all]`
Decrypted notes and UTXOs with heights, values, memo previews and witness readiness.

**Landed:** `address current`, `address new`, `address inspect` and `notes`. `current` and `new` print the address alone on stdout (so `$(gyges address current)` works) and its receivers, diversifier index and label on stderr (quiet with `-q`). On a fresh key `current` is the account's default address, which carries every receiver the key has (Orchard, Sapling and transparent); `address new` without `--receivers` gives a shielded-only one, and from then on `current` is the newest address handed out. `new` needs the first sync to have recorded the chain tip (exit 7 before that); `--receivers transparent` alone is exit 6 (a unified address needs a shielded receiver). `inspect` exits 6 when the address is malformed or for another network than the daemon's (with `--json`, the error object). `notes` lists oldest first; the memo preview of an incoming payment waits for transaction enhancement, while the wallet's own sends always show theirs (API §7.2). **Landed:** `--qr` on `current` and `new` adds a UTF-8 half-block QR code of the address on stderr (hidden by `-q`), so stdout is still the address alone. `address qr` prints the code on stdout with the address on the line under it; with `--json` it prints `{"address", "qr"}`. A given address is checked with `InspectAddress` first and refused with exit 6 if it is malformed or for another network, so a mistyped address is never rendered. The code is drawn for a light-on-dark terminal (blocks are the light modules), and the address is encoded as typed, in byte mode.

---

#### 2.5 Transactions (`gyges tx`)

##### `gyges tx send --to <ADDR> --amount <AMOUNT>`
Proposes, proves, signs and broadcasts. The proposal summary (inputs per pool, outputs, ZIP 317 fee per step, total debit) is printed before any signature prompt; without `--yes` it comes from a dry run and is confirmed before the real send starts (no terminal: exit 4, `CONFIRMATION_REQUIRED`). The txid goes to stdout; progress goes to stderr.
- **Inline unlock (`local-seed`):** on `SignatureRequired`, prompts for the passphrase, creates a connection-scoped session and continues; the key is dropped after signing. A send that spends Sapling notes asks before `proving …` rather than after, because the Sapling proofs need the key.
- **Keystone (`keystone-qr`):** renders the animated UR QR (batch protocol for shielded-only sends, single-PCZT when transparent inputs are present) and reads the result from the camera (`qr-scan`), a file, stdin or pasted frames.
- **ZIP 320 (`tex1`):** runs the two-step plan through the durable `TexQueue`; the passphrase prompt comes before proving (both steps are built together, API §9), each step's txid goes to stdout as the node takes it, and `tex pending (step 2 of 2): <step1> then <step2>` goes to stderr. A node that will not take Step 2 while Step 1 is unmined leaves one txid on stdout; the queue finishes the transfer and `tx sessions` shows its state.
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

##### `gyges tx shield [--threshold <AMOUNT>] [--dry-run] [--yes] [--wait]`
Sweeps transparent UTXOs of at least the threshold (in total; default: any) into the key's shielded pool (Ironwood after NU6.3; auto-shielding, no ZIP governs this behaviour). Same confirmation, signing and output as `tx send`.

##### `gyges tx list [--limit <N>] [--before <TXID>]`
History with timestamps, pool flows, ZIP 317 fees, decrypted memos, and pending states (`awaiting-signature`, `tex pending`). `--before` pages: pass the last txid of the previous page.

##### `gyges tx status <TXID> [--pir]`
Confirmation status from the node, or via `zakura-pir-status` with `--pir`. **Experimental:** the PIR servers queried, their operators and the privacy guarantee must be documented before this leaves experimental status.

**Landed:** `tx list` prints newest first, one line per transaction (time, status, height, net value with fees, fee, txid), then its non-change outputs with pool, value, recipient and memo, and its ZIP 320 row; statuses are `pending`, `mined`, `expired`, `failed` and `tex-pending` (`awaiting-signature` never shows: a session holds no transaction until it is signed). `tx status` prints `mined at height H (N confirmations)` or the state; an unknown txid is exit 6, an unreachable node exit 7. `--json` prints `ListTransactionsResponse` / `GetTransactionStatusResponse` (API §7.2). Not yet: `--pir` exits 1 before contacting the daemon.

##### `gyges tx sessions [--all] [--include-finished]` / `gyges tx abort <SESSION_ID | TXID>` / `gyges tx resume <TXID>`
Lists pending signing sessions (and, with `--include-finished`, completed, expired, aborted and failed ones the daemon still remembers) and ZIP 320 rows (a second table: step-1 txid, key, state, expiry, attempts, amount and the node's last refusal); `abort` cancels a signing session, or a TEX row while it is still `built`; `resume` forces a retry of a TEX row, building a new Step 2 if Step 1 was mined and Step 2 expired. `resume` prompts for the passphrase like `tx send` when the key is locked, waits for the daemon to store the new Step 2 (up to two minutes) and prints its txid on stdout; on a row the queue is still working on it only triggers an immediate re-check.

---

#### 2.6 PCZT pipeline (`gyges pczt`)
Exposes the ZIP 374 roles for Unix-pipe composition and air-gapped signing. Every PCZT written by `pczt create` carries `gyges.key_id`, `gyges.network` and `gyges.session_id` in its global `proprietary` map; downstream commands read the key id from the stream and use `--key` only as an assertion (exit 6 on mismatch). `combine` refuses inputs with different key ids. The Redactor strips the proprietary map before a PCZT goes to a Keystone.

```bash
gyges pczt create --to u1q... --amount 2.5 \
  | gyges pczt prove \
  | gyges pczt sign \
  | gyges pczt broadcast
```

- `gyges pczt create --to <ADDR> --amount <AMOUNT> [--memo <TEXT_OR_HEX>] [-o <FILE>]`
- `gyges pczt inspect [<FILE>]`
- `gyges pczt prove [<FILE>] [-o <OUT_FILE>]` (no key needed: a file never spends Sapling. `pczt create` leaves Sapling notes out, saying so when they are all that is left, and `prove` / `sign` refuse a Sapling spend with exit 6, `UNSUPPORTED_POOL`; `tx send` spends Sapling notes)
- `gyges pczt sign [<FILE>] [-o <OUT_FILE>] [--qr-out <FILE>]`
- `gyges pczt qr-export --session <ID> [--fps <N>] [-o <FILE>]` (animates the pending Keystone session's `ur:zcash-pczt` / `ur:zcash-sign-batch` request; `<FILE>` instead of `--session` is not supported yet)
- `gyges pczt qr-scan --session <ID> [--camera <N>] [--timeout <DURATION>]` (laptop camera, feeds the fountain decoder until complete; needs a build with the `camera` feature; without `--session`, for a PCZT file, not supported yet)
- `gyges pczt qr-import --session <ID> [--from-file <FRAMES.txt>] [<UR_FRAME>...]` (one `ur:` frame per line from a file or stdin; positional frames for single-frame payloads such as batch signature results; without `--session`, for a PCZT file, not supported yet)
- `gyges pczt combine <FILE_A> <FILE_B> [-o <OUT_FILE>]`
- `gyges pczt broadcast [<FILE>] [--via-tor]` (runs Verifier against the stored proposal first)

Binary `.pczt` files use the `pczt` crate's postcard serialization; `-` means stdin/stdout.

**Landed:** `create`, `inspect`, `prove`, `sign`, `combine` and `broadcast`. Input is the positional file, or stdin when it is absent or `-`; output goes to `-o FILE` (created 0600) or stdout, and a command refuses to write a PCZT to a terminal (exit 6: pass `-o` or pipe). `create` prints the proposal and the session id on stderr (quiet with `-q`); `inspect` prints the key, network and session, the steps as `tx send --dry-run` lays them out (the anchor height and confirmations are not in a file, so the footer is the expiry height only), the roles whose footprints are present, and per pool the spends, outputs, proofs and `signed/required` signatures; `broadcast` prints the txid on stdout. With `--json` every command prints its RPC response on stdout (the PCZT bytes as base64 inside it, per API §5) and writes a file only when `-o` is given. `sign` prompts for the passphrase like `tx send` (or reads `--passphrase-fd` / `GYGES_PASSPHRASE_FILE`; no terminal and no source is exit 4). A `tex1` recipient is refused by `create` with exit 6 and a pointer to `tx send` (upstream builds a PCZT from a single-step proposal only). A file from `create` may be mined up to 1152 blocks past its target height (about a day), not the 40 of `tx send`. `broadcast --via-tor` follows the `tx send --via-tor` rule (API §4.1). Not yet: `sign --qr-out` (M5).

**Landed:** `tx send` and `tx shield` from a `keystone-qr` key.
- **On a terminal:** they print the proposal and loop the request as a QR code on stderr until Enter. The request uses the batch protocol, or the single-PCZT one when the transaction has transparent inputs, as for shielding. They then read the device's answer as pasted `ur:` frames, one or more per line, as a phone's QR reader gives them. A refused answer can be scanned again, up to three times.
- **Without a terminal, or with `--json`:** the request's frames go to stdout, one per line (with `--json` only the `SignatureRequired` event carries the payload), and the command exits 4 naming the session.
- **With `--qr-out FILE`:** the frames are written to the file, with the same exit 4.
- **Completing later:** `pczt qr-export --session ID` shows the frames again, animated on a terminal, else printed or written with `-o`. `pczt qr-import --session ID` completes the session from positional frames, `--from-file` or stdin, and prints the txid. A partial or foreign set of frames is exit 6 before the daemon is asked; a refused answer is exit 9 and the session stays open.
- **Not yet:** the PCZT file flow, meaning `qr-export FILE` (a file must be redacted for the device first) and `qr-import` without `--session`.

**Landed:** the camera, in builds with the `camera` feature (off by default; `cargo build --features gyges-cli/camera`).
- **`pczt qr-scan --session ID`** reads the device's answer with the camera (the first unless `--camera N`) for up to `--timeout` (default 2 minutes), completes the session, and prints the txid.
  - Progress goes to stderr; Ctrl-C stops the scan.
  - No camera, denied access (macOS asks once, for the terminal application) or a camera that offers only MJPEG is exit 1 with the reason, as is a build without the feature.
- **`tx send` / `tx shield` on a terminal** scan the answer by themselves after Enter, for up to a minute, then fall back to pasted frames; Ctrl-C during the scan also switches to pasting. After a refused answer they wait for Enter (redo it on the device) before scanning again. `GYGES_NO_CAMERA=1` skips the camera.
- **Ctrl-C** at the QR animation or the paste prompt (with or without a camera) leaves the session open and exits 4, for `qr-import` or `qr-scan --session` later.

## API

The contract between the CLI and the daemon. The machine-readable source is
[`proto/gyges.proto`](../proto/gyges.proto); this part explains the parts a
proto file cannot: transport, authentication, versioning, the error model,
streaming semantics and the signing-session lifecycle. Where this document and
the proto disagree, the proto wins and this part has a bug.

Design inputs (`decisions.md` §1): Q-S1…S3 (sessions), Q-Y4
(sync definitions), Q-K2/K4 (Keystone), Q-T1 (ZIP 320 queue), Q-C1…C6 (CLI
behaviour), Q-O1 (logs), Q-O3 (versioning).

---

### 1. Transport and authentication

#### 1.1 Socket

- One daemon per network. The socket is `~/.gyges/<network>/gygesd.sock`
  (`GYGES_HOME` overrides `~/.gyges`). The CLI derives the path from
  `--network` / `GYGES_NETWORK` (default `mainnet`) and never reads
  `config.toml`; `--socket` / `GYGES_SOCKET` overrides the derived path.
- Protocol: gRPC (HTTP/2, no TLS) over the Unix domain socket. The daemon is a
  `tonic` server on a `tokio::net::UnixListener`; the CLI is a `tonic` client
  with a `tower::service_fn` connector that opens a `UnixStream`.
- Socket mode is `0600` (owner only). In the hardened deployment (`gygesd`
  running as its own user, `gyges daemon install --hardened`) it is `0660`
  with a `gyges` group, at `/run/gyges/<network>/gygesd.sock`
  (`daemon.socket_path`), since a group member cannot reach a socket inside
  the 0700 network directory. Admitted users set `GYGES_SOCKET` to it.
- Windows is out of scope for v1 (Q-O4); there is no named-pipe transport.

#### 1.2 Peer credentials

On every accepted connection the daemon reads the peer's uid
(`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS). A uid that is neither
the daemon's own nor in `daemon.allowed_uids` is rejected before any RPC is
read; a client that somehow gets a request through receives
`PERMISSION_DENIED`. Same-uid processes are trusted to *connect*; they are
not trusted to *spend* (see §6).

#### 1.3 Handshake

Every CLI invocation calls `GetInfo` first. It checks:

1. `api_version.major` equals the CLI's own (§2), else exit 6
   (`API_VERSION_MISMATCH`, reported client-side).
2. `network` equals `--network` when the user gave one explicitly, else exit 6
   (`NETWORK_MISMATCH`). Without an explicit `--network` the CLI adopts the
   daemon's network.
3. `airgapped`: the CLI uses this to print a clearer message when a networked
   command fails with `AIRGAPPED`.

If the socket is absent or refuses the connection the CLI exits 3 with
"gygesd is not running; start it with `gyges daemon start`". It never
auto-starts the daemon unless `GYGES_AUTOSTART=1` (Q-C5).

#### 1.4 `key_id` resolution

Every request with a `key_id` field accepts an empty string, which the daemon
replaces with `config.default_key`. If no default is configured the daemon
returns `KEY_NOT_FOUND` with `detail = "no default key; pass --key"`. The CLI
passes `--key` / `GYGES_KEY` through verbatim and does no resolution of its
own (Q-C1).

---

### 2. Versioning

`GetInfoResponse.api_version` is `{major, minor}`.

| Change | Allowed within a minor? | Rule |
|---|---|---|
| Add a field to a message | yes | New fields are optional and default-valued |
| Add an RPC | yes | Older clients never call it |
| Add an enum value | yes | Clients treat unknown values as `_UNSPECIFIED` and keep going |
| Add a `oneof` event to a stream | yes | Clients skip events they do not recognise |
| Remove or renumber a field, RPC or enum value | **no** | Requires a major bump |
| Change the meaning of an existing field | **no** | Requires a major bump |

Compatibility policy (Q-O3):

- The CLI requires an equal `major` and warns once on stderr when the daemon's
  `minor` is newer than its own ("some features may be unavailable").
- The daemon accepts clients of its own `major` and of the previous `major`
  for one release cycle, after which the old major is dropped.
- `gyges` and `gygesd` ship as one release artifact; running
  `daemon install` again after an upgrade restarts the service's daemon on
  the new binary, so mismatches are rare.
- JSON output (§5) carries `schema_version` = `"<major>.<minor>"`.

The first released API version is `1.0`. Until then the number is `0.x` and
nothing in this document is stable.

---

### 3. Error model

Every failed RPC returns a gRPC status whose `details` carry exactly one
`gyges.v1.GygesError` (`grpc-status-details-bin`, type URL
`type.googleapis.com/gyges.v1.GygesError`). The gRPC status code is chosen to
be sensible for generic clients (`FAILED_PRECONDITION` for a locked vault,
`INVALID_ARGUMENT` for a bad address, `UNAVAILABLE` for an unreachable node,
and so on), but **the CLI dispatches on `GygesError.reason`, never on the
status code or message text**. The `"VAULT_LOCKED:main"` string convention
from the original `architecture.md` Components is withdrawn.

`GygesError.detail` is a human-readable sentence that is safe to print and to
log: it never contains addresses, amounts, memos, txids or key material.
`node_error` carries the node's verbatim rejection text for `NODE_REJECTED`
only.

#### 3.1 Exit-code mapping

The mapping lives in one function in `gyges-cli` and is the only place exit
codes are chosen.

| Exit | Meaning | `ErrorReason` values |
|---|---|---|
| 0 | success | — |
| 1 | unspecified failure | `INTERNAL`, `UNSPECIFIED`, any transport error other than connection refused |
| 2 | usage error | clap parse errors (client-side only) |
| 3 | daemon unreachable | socket missing, connection refused (client-side only) |
| 4 | authorization required and non-interactive, or refused | `VAULT_LOCKED`, `SIGNATURE_REQUIRED`, `SEED_EXPORT_DISABLED`, `CONFIRMATION_REQUIRED`, `INVALID_PASSPHRASE`, `RATE_LIMITED`, `PERMISSION_DENIED` |
| 5 | insufficient funds | `INSUFFICIENT_FUNDS` |
| 6 | invalid argument or mismatch | `INVALID_ARGUMENT`, `NETWORK_MISMATCH`, `KEY_MISMATCH`, `KEY_NOT_FOUND`, `KEY_EXISTS`, `SESSION_NOT_FOUND`, `UNSUPPORTED_POOL`, `API_VERSION_MISMATCH` |
| 7 | not ready | `NOT_SYNCED`, `NODE_UNREACHABLE`, `AIRGAPPED`, `FALLBACK_UNAVAILABLE` |
| 8 | cancelled by user | `CANCELLED`, SIGINT during a prompt or stream |
| 9 | hardware signer error | `HARDWARE_SIGNER` |
| 10 | node rejected transaction | `NODE_REJECTED` |

In an interactive terminal the CLI handles `VAULT_LOCKED`, `SIGNATURE_REQUIRED`
and `CONFIRMATION_REQUIRED` itself (prompt, scan, confirm) and only exits 4
when it cannot (§4.3). With `--json`, the error object is printed on stdout
as `{"schema_version": …, "error": <GygesError as JSON>}` and the same exit
code is used.

---

### 4. Streaming RPCs

#### 4.1 `SendTransaction` and `ShieldFunds`

Server-streaming. Event order for a transfer whose proposal has `n` steps
(`n = 1` for ordinary sends, `n = 2` for ZIP 320):

```
Proposed                         always first; for dry_run also last
for each step s in 1..=n:
    Proving { step: s, … }*      zero or more progress events
    SignatureRequired { step: s }   only if the key cannot sign yet (§6)
    Signed { step: s }
Broadcast { step: 1, txid }
TexQueued { step1_txid, step2_txid }     n == 2 only
Broadcast { step: 2, txid }              n == 2 only; may follow TexQueued immediately
Mined { step, txid, height }*            only if wait_for_mined
```

Rules:

- **Prove before unlock.** Orchard and transparent proving need no secret, so
  the proposal is proven while the vault is locked and `SignatureRequired` is
  emitted as late as possible (Q-S3). The exception is a step with Sapling
  spends, which only a `LOCAL_SEED` profile sends: its `SignatureRequired`
  precedes its `Proving` events because the proof generation key must be
  inserted first (Q-K3, security.md §6 item 1). As landed, the key from the token, daemon unlock or session is
  derived once, the Updater role inserts each spend's key, and the same key
  proves, signs and is dropped. A PCZT file never carries a Sapling spend:
  `CreatePczt` leaves Sapling notes out (`INSUFFICIENT_FUNDS` says so when
  they are all that is left), and `ProvePczt` and `SignPczt` refuse one with
  `UNSUPPORTED_POOL`, `SignPczt` before any `SignatureRequired`. A ZIP 320 send (`n = 2`) is the other exception
  (§9): one `SignatureRequired { step: 1 }` comes right after `Proposed`,
  then the `Proving` events of step 1, then `Signed { 1 }`, `Signed { 2 }`.
- **One signature prompt per send.** Both ZIP 320 steps are signed in the
  same session: for `PASSPHRASE` kinds the daemon keeps the USK across both
  steps and drops it after the second `Signed`; for Keystone kinds the batch
  protocol covers both steps in one QR exchange when the device accepts the
  transparent step 2, and otherwise two `SignatureRequired` events are
  emitted (see Q-K1, "needs verification on hardware").
- **The stream pauses on `SignatureRequired`.** It resumes when the client
  satisfies the session (§6.2) on the *same connection* or, for Keystone
  kinds, from any connection with `CompleteKeystoneSign`. If the session
  expires while paused the daemon emits a fresh `SignatureRequired` with a new
  `session_id` and `expires_at` rather than failing the stream, provided the
  proposal's anchor is still valid; otherwise the stream fails with
  `NOT_SYNCED` and the client must start over.
- **Client disconnect** after `SignatureRequired` leaves the session alive
  (§6.3). Disconnect after `Broadcast` has no effect on the daemon; the
  `tex_queue` finishes a ZIP 320 transfer without any client.
- **`dry_run`** emits `Proposed` and ends. No session is created and nothing
  is stored.
- **`session_token`** supplied up front (from `gyges key unlock`) suppresses
  `SignatureRequired` for `PASSPHRASE` kinds. It is never valid for Keystone
  profiles.
- **`via_tor`** (or `[fallback_lightwalletd] broadcast_via_tor = true`, which
  also covers `ShieldFunds` and `BroadcastPczt`) sends the transaction to the
  fallback endpoint's `SendTransaction` over its Tor client instead of the
  node's `sendrawtransaction`. It never falls back to the node: without an
  enabled endpoint, or with `use_tor = false` outside regtest, the RPC fails
  with `FALLBACK_UNAVAILABLE` before anything is proposed, and an endpoint
  that cannot be reached at broadcast time fails the stream with
  `FALLBACK_UNAVAILABLE` (the transaction is already in the wallet as
  unmined). The endpoint passes the node's rejection through as
  `NODE_REJECTED`. A `tex1` recipient with `via_tor` is refused with
  `INVALID_ARGUMENT`: the `tex_queue` broadcasts and rebroadcasts both steps
  through the node. The `broadcast` audit event carries `via = "node"` or
  `"fallback"`.

`ShieldFunds` emits the same events for a one-step transparent-to-shielded
proposal (the output pool is Ironwood after NU6.3, see `decisions.md` §2.3).
A `KEYSTONE_QR` profile always gets `KEYSTONE_SINGLE_PCZT` for it, because
the batch protocol rejects transparent inputs.

Status: implemented for `LOCAL_SEED` profiles
with `n = 1`; `Proving` is emitted once per shielded pool with work before
the proofs and once after. A `WATCH_ONLY` profile answers
`INVALID_ARGUMENT`. A `KEYSTONE_QR` profile pauses on a Keystone
`SignatureRequired` (§6): the batch kind when the
transaction has no transparent inputs, the single-PCZT kind otherwise. Its
transaction gets the expiry of a PCZT file (`target + 1152` blocks, about a
day), since it waits for a person and a device; a `tex1` recipient is
refused with `HARDWARE_SIGNER` until the device's handling of ZIP 320 is
verified (security.md §6 item 7); and while one of its Keystone sessions
awaits the device, another spend from the key is refused with
`SIGNATURE_REQUIRED` naming that session (a second proposal could pick the
same notes). Passphrase sessions live in daemon memory only (§6.1) and show in
`ListSigningSessions` with their status; a session that is aborted ends its
stream with `CANCELLED`. A transaction the node refuses (`NODE_REJECTED`)
has already been recorded in the wallet as unmined and its inputs stay
unspendable until its expiry height. `wait_for_mined` ends once the wallet
has the transaction's mined height. The scanner finds most transactions (a
change output or a nullifier of ours). The daemon learns about a fully
transparent transaction without change from the node: upstream queues it for
a status lookup, and the scheduler asks `getrawtransaction` and records the
answer (`decisions.md` §2.3). The lookup goes to the node only, never to the
fallback endpoint, and is skipped while a key backfills.

The CLI approves before it signs: without `--yes`, `gyges tx send` runs the
request as `dry_run` first, prints the proposal, asks, and only then opens
the real stream (the daemon never waits on a prompt, and a daemon-scoped
unlock would otherwise sign at once). The fee can differ between the two
only if the chain moved in between.

#### 4.2 `SignPczt`

Server-streaming with the same pause semantics as §4.1 but only two event
types: zero or one `SignatureRequired`, then `signed` (the final PCZT bytes).
For Keystone profiles the returned PCZT has already been through Combiner and
Verifier in the daemon (§6.4); the client never sees a half-signed PCZT.

*Landed:* the key is the PCZT's `gyges.key_id`
(`key_id` in the request is an assertion, §7.1); `local-seed` and
`signer-only` profiles sign, the others are refused as in §4.1. The
`SignatureRequired.summary` is what `InspectPczt` derives from the file.
The stream needs no node: a passphrase session that expires is replaced by
a fresh one without the "can still be mined" check of §4.1, since an
air-gapped daemon cannot know the tip; the file's expiry height is the
client's to watch.

*Change ownership:* once the key is unlocked
and before anything is signed, every shielded output must match its note
and value commitments (a missing `recipient`, `value` or `rseed` fails), every
`user_address` must name the receiver its output pays, and every output without a `user_address`
(upstream sets one on each payment to an external address, and
`InspectPczt` lists those as payments) and with a non-zero value must belong
to the key: an Orchard or Ironwood recipient in either scope of the
account's Orchard viewing key, a Sapling recipient the Sapling viewing key
decrypts, a transparent script among the wallet's receivers or, on a
`signer-only` profile, at an external or internal index below 1,000.
Otherwise the stream fails with `INVALID_ARGUMENT` (exit 6). `BroadcastPczt`
and `SendTransaction` apply the same rule in the Verifier: change is
matched to the approved proposal by value and owner, not by value or total
alone.

#### 4.3 Non-interactive clients

When stdin is not a TTY, or `--non-interactive` / `GYGES_NON_INTERACTIVE=1`
is set (Q-C4):

- `PASSPHRASE`: the CLI reads the passphrase from `--passphrase-fd N` or
  `GYGES_PASSPHRASE_FILE` if present and calls `UnlockKey { session_id }`.
  Otherwise it prints the `session_id`, aborts the session with
  `AbortSigningSession` (nothing to resume: a passphrase can be retried from
  scratch) and exits 4.
- `KEYSTONE_*`: the CLI prints the `session_id` and the UR frames (or writes
  them with `--qr-out FILE`), leaves the session alive, and exits 4. The
  signature is supplied later with `gyges pczt qr-import --session ID`, which
  calls `CompleteKeystoneSign`; its response carries the broadcast txids for
  `SEND` sessions or the signed PCZT for `SIGN_PCZT` sessions.
- With `--json` the exit-4 error object includes `reason` and `session_id`
  so a wrapper can drive the flow.

#### 4.4 `WaitSync` and `RunSync`

Server-streaming `SyncProgress`, one element per scanned batch (at most one
per second when idle), ending with `done = true` or a `GygesError`.
`WaitSync` ends when `scanned`/`spendable` holds (per `until`, default
`SPENDABLE`, defined in Q-Y4) or when `txid` has `confirmations`
confirmations. A key in `SYNC_STATE_STALLED` fails the stream immediately
with `NOT_SYNCED` and `detail` naming the stall reason, so scripts do not hang.

`RunSync` with `from_height <= scanned_tip` is a rewind: it truncates notes,
nullifiers and ShardTree checkpoints to `from_height - 1` and requires
`confirm_rewind = true` (the CLI prompts, or `--yes`). Unmined transactions
survive and are re-evaluated against their expiry.

`ScanMempool` (unary) runs one full mempool pass at the scheduler's next tick
(architecture.md Sync §7). The pass covers every key and every transaction in the
node's mempool, up to 500, whether or not `mempool.scan` is on. `transactions_scanned`
counts the transactions fetched and parsed. `notes_found` counts the notes
they pay to `key_id`, or to every key when `key_id` is empty; received notes
and change are counted, outputs the wallet sent elsewhere are not. What is
found shows as `pending` in `GetBalance` until mined. An unknown `key_id`
is `KEY_NOT_FOUND`. A daemon without a node, or a pass that cannot reach
it, answers `NODE_UNREACHABLE`.

#### 4.5 `StreamLogs`

Replays the last `lines` entries (at most 1,000: the daemon keeps that many
of each log in memory), then (with `follow`) delivers new entries until the
client disconnects; a follower that joins during a replay sees every entry
exactly once. Entries come from the in-process `tracing` subscriber, not
from tailing the file, so the CLI stays socket-only (Q-O1). `min_level`
drops entries less severe than the given level; `UNSPECIFIED` delivers
whatever the daemon's own filter (`daemon.log_level`, or `RUST_LOG`) let
through, which for the audit log is everything. `audit = true` streams the
audit log instead: the events `unlock` (field `scope`), `lock`,
`export_seed`, `session_created`, `session_completed`, `session_aborted`,
`sign` (field `via`: `unlock` or `session`), `broadcast` and `rewind` (field
`from`), each with `key_id`, under the target `gyges::audit`. Log entries
are redacted at source (`gyges_core::Sensitive`); `fields` never contain
addresses, amounts, memos, passphrases or key material at any level, and
upstream error texts are logged at `debug` only.

#### 4.6 `InitKey` / `RestoreKey`

`InitKey` takes the birthday from the node's tip (`NODE_UNREACHABLE` when no
node is connected) and creates a `LOCAL_SEED` profile; on an air-gapped
daemon it creates a `SIGNER_ONLY` profile instead (no wallet, `birthday_height
= 0`, empty `ufvk`), which is why it is on the §8 allow-list. `RestoreKey`
with `birthday_height = 0` uses the network's Sapling activation height; any
birthday at or below Sapling activation needs no node's tree state (and no
node at all when none answers), any other needs the node's tree state at
`birthday - 1`. A birthday whose blocks the connected node has pruned (the
tree state at `birthday - 1` below `node.retained_from`, or for one at
Sapling activation the birthday block itself) returns `CONFIRMATION_REQUIRED` until `allow_backfill` is set, then
`FALLBACK_UNAVAILABLE` when no `[fallback_lightwalletd]` endpoint is
configured or it is marked untrusted. Otherwise the tree state at
`birthday - 1` comes from the endpoint (its block hash checked against the
node's `getblockhash`), `backfill_blocks` is how many blocks the scheduler
will fetch from it (up to the handoff height, architecture.md Sync §5.1), and the key
syncs through `Backfilling` (`SYNC_STATE_VALIDATING_HANDOFF` with `backend`
`SYNC_BACKEND_TOR_LWD_FALLBACK` or `_DIRECT_LWD_FALLBACK`) before Case A.
Such a restore carries one entry in `warnings`: transparent history below
`retained_from` comes from the endpoint and is best-effort (architecture.md Sync §5.3).
After the handoff validates, `GetInfo.keys[].transparent_best_effort_below`
is that height for the key (0 for a key never backfilled).
`set_default` on either changes `GetInfo.default_key` for this daemon run
only: the daemon never rewrites `config.toml`. Passphrases and mnemonics are
moved into zeroizing wrappers on arrival; a mnemonic error never echoes a
word back. Both calls run the scrypt and SQLite work on a blocking thread.

`UnlockKey` without `session_id` behaves as §6.3 describes (`CONNECTION` by
default, `DAEMON` on request); with a `session_id` it is the single-use
form of §6.2: the passphrase is verified (same per-key back-off), the
spending key is derived and handed to the paused `SendTransaction` /
`ShieldFunds` stream, and no token or unlock results. A `ttl_secs` of 0
means `vault.unlock_ttl`. `KeySummary.locked` is false only for a daemon-scoped
unlock, with `unlock_expires_at` set. `ExportUfvk` on a `SIGNER_ONLY` profile
derives the key from a live daemon-scoped unlock and answers `VAULT_LOCKED`
without one. `ExportSeed` checks `vault.allow_seed_export`, then the literal
confirmation, then the passphrase (through the same per-key back-off as
`UnlockKey`), and never creates an unlock.

#### 4.7 `BackupKey` / `ImportBackup`

Chunked tar archives. `BackupKey` runs `wal_checkpoint(TRUNCATE)` before
reading `wallet.sqlite` and holds the key's write lock for the duration.
`ImportBackup` refuses an existing `key_id` with `KEY_EXISTS` and validates
`profile.json` before writing anything.

---

### 5. JSON output

`--json` prints the response message as **proto3 JSON, 1:1** (`serde`
implementations generated by `pbjson-build` in `gyges-proto`), with one
addition: a top-level `"schema_version": "<major>.<minor>"`. Enum values
are their proto names (`"POOL_ORCHARD"`), `int64` values are JSON strings,
`bytes` are base64, and unset or zero-valued fields are omitted (so an
`api_version.major` of `0` and a `reason` of `ERROR_REASON_UNSPECIFIED` are
absent rather than present). Field names are the proto field names
(`api_version`), not the lowerCamelCase form the canonical printer would
choose, so output reads like `gyges.proto` and like `schema_version`. Streaming RPCs emit one JSON object per
line, each a serialized stream element with `schema_version` added.

Consequences:

- `gyges.proto` is the JSON schema. There is no second schema document.
- The dry-run output of `tx send --json` is the `Proposal` message;
  `upstream_proposal` is the base64 of the upstream
  `zcash_client_backend::proto::proposal::Proposal` for consumers that want
  note-level detail.
- `address qr` (which checks the address with `InspectAddress`) prints
  `{"schema_version", "address", "qr"}`; `pczt qr-export --session` (which
  reads the session with `ListSigningSessions`) prints
  `{"schema_version", "session_id", "frames"}`. Both are as built in M5;
  the first draft had them print `{"ok": true}` with the frames on stderr.

---

### 6. Signing sessions

A signing session is the daemon-side record of "this transaction is waiting
for a signature". It exists so that the key is held as briefly as possible,
so that malware with socket access cannot ride on another process's unlock,
and so that a Keystone round trip can be completed from a later process.

#### 6.1 Record

*As built:* one `ext_gyges_signing_sessions` row per session, with the
Keystone kinds' device-side columns filled (architecture.md Data model §5.2). The first
draft below is kept for the fields' meaning; `key_id` is implied by the key's
own wallet, `proven_pczt`, `request_id` and the payload are the row's
nullable Keystone columns, and there is no `failed` status (§6.4).

Persisted in `wallet.sqlite` (table `signing_sessions`, Q-K4):

```
session_id        TEXT PRIMARY KEY   -- 16 random bytes, hex
key_id            TEXT
purpose           TEXT   -- send | sign_pczt
kind              TEXT   -- passphrase | keystone_single_pczt | keystone_batch
status            TEXT   -- awaiting_signature | completed | expired | aborted | failed
created_at        INTEGER
expires_at        INTEGER
step              INTEGER
proven_pczt       BLOB   -- the daemon's unredacted, proven copy
sent_payload_hash BLOB   -- BLAKE2b-256 of the CBOR sent to the device
request_id        BLOB   -- batch protocol request id, if any
proposal          BLOB   -- the Proposal the user approved
last_error        TEXT
```

`PASSPHRASE` sessions are not persisted across restarts (the stream that
created them is gone); Keystone sessions are, and expire after
`vault.signing_session_ttl` (default 24 h). Sessions show in `gyges tx list`
as `AWAITING_SIGNATURE` with their `session_id`, in `gyges tx sessions`, and
can be aborted with `gyges tx abort SESSION_ID`.

*As built:* `ListSigningSessions` returns the
persisted Keystone sessions with their `payload` (the CBOR shown to the
device), so `gyges pczt qr-export --session ID` can show the frames again
from another process. A session past `expires_at` is marked expired when it
is next listed or completed. A stream waiting on a Keystone session that
expires ends with `SESSION_NOT_FOUND`; there is no fresh session, since a new
one would need a new scan of the device. A client that disconnects leaves
the session open.

#### 6.2 Satisfying a session

| `kind` | Client action | Daemon action |
|---|---|---|
| `PASSPHRASE` | `UnlockKey { key_id, passphrase, session_id }` | Derives the USK, signs the pending step(s), zeroizes the USK, resumes the stream. No token is returned. |
| `KEYSTONE_BATCH` | `CompleteKeystoneSign { session_id, payload = zcash-batch-sig-result }` | Checks the echoed `request_id`, applies each `(pool, action_index, signature)` to `proven_pczt`, runs Verifier, Spend Finalizer, Tx Extractor, then broadcasts (SEND) or returns the PCZT (SIGN_PCZT). |
| `KEYSTONE_SINGLE_PCZT` | `CompleteKeystoneSign { session_id, payload = zcash-pczt }` | Runs Combiner (`proven_pczt` ⊕ returned PCZT; structural mismatch fails with `HARDWARE_SIGNER`), then Verifier, Spend Finalizer, Tx Extractor, then broadcasts or returns. |

A session can be satisfied once. A second attempt returns
`SESSION_NOT_FOUND`.

*As built:* `CompleteKeystoneSign` finds the session in whichever key holds
it, needs no stream (it works after a restart), and runs these steps in order:
- refuses a session at or past its transaction's expiry height with
  `NOT_SYNCED`, and marks it expired, before anything is recorded;
- applies the answer: for batch, the request id must match and the answer must
  carry exactly one PCZT entry, and each signature is applied with
  `Signer::apply_orchard_spend_auth_signature`, which verifies it against the
  action's randomized key; for single-PCZT, the Combiner;
- checks that every required signature is present;
- runs the Verifier;
- claims the row (`awaiting-signature` → `signed`, conditionally);
- extracts, records and broadcasts.

Two completions of one session cannot run together: the second gets
`SESSION_NOT_FOUND`. The stream that created the session, if still open,
then emits `Signed` and `Broadcast`. If the node refuses the broadcast, the
transaction is already in the wallet as unmined (as for any send, §4.1) and
its inputs stay unspendable until its expiry height. For a Keystone send that
height is about a day away (`target + 1152`), and no rebroadcast of a
completed session exists yet, so the funds wait that long. The `SIGN_PCZT` purpose is not built:
`pczt sign` refuses a Keystone key.

#### 6.3 Connection scoping and tokens

- `UnlockKey` *without* `session_id` takes an `UnlockScope`:
  - **`CONNECTION`** (default): creates a reusable **unlock session** bound to
    the calling connection and returns a 32-byte `session_token`. The token
    is accepted only on the connection that obtained it and only until
    `expires_at` (an idle timer, reset on each use) or until the connection
    closes, whichever is first. The inline `tx send` flow and any long-lived
    client (a wrapper process holding one connection) use this scope. Malware
    with socket access cannot use the unlock without the token.
  - **`DAEMON`**: holds the decrypted key in `gygesd` RAM with the same idle
    TTL and returns no token; until it expires or `LockKey` is called, *any*
    same-uid client that passes the peer-credential check can spend from the
    key. This is what `gyges key unlock --timeout` uses, because the CLI
    process exits and cannot keep a connection open. It is the weaker mode
    and exists only for batch scripts; `security.md` treats a DAEMON
    unlock window as equivalent to a same-uid attacker holding the key for
    its duration. `daemon status` and `key list` show `UNLOCKED (daemon
    scope, expires in …)` so the window is visible.
- `UnlockKey` *with* `session_id` is single-use, ignores `scope` and returns
  no token.
- `SendTransaction` and the other spending RPCs accept, in order: a valid
  `session_token` on this connection, else a live DAEMON-scoped unlock for the
  key, else they pause on `SignatureRequired`.
- Keystone sessions carry no secret and are therefore not connection-scoped:
  the device's signature is the authorization.
- `ExportSeed` never accepts a token; it always takes a fresh passphrase and
  the literal confirmation `reveal seed` (Q-S4).
- Failed `UnlockKey` attempts are rate-limited with exponential back-off
  keyed **per key id, not per connection**, so opening new connections does
  not reset the back-off; the error is `RATE_LIMITED` with the wait in
  `detail` (Q-S2).

#### 6.4 What the daemon verifies before broadcast

For every completed session, regardless of kind, the daemon runs the PCZT
**Verifier** against the stored `proposal` and refuses to broadcast if any
output address, value, fee, memo or anchor differs (Q-K7). On failure the
session is marked `failed` with `last_error`, the response is
`HARDWARE_SIGNER` (Keystone kinds) or `INTERNAL` (passphrase kinds), and
nothing is broadcast or stored as a pending transaction.

*As built, deliberately different:* a refused Keystone answer (wrong
request id, a signature that does not verify, a missing signature, a PCZT
the Combiner or the Verifier refuses) leaves the session
`awaiting-signature` with `last_error`, so the user can scan the device
again; nothing is broadcast or recorded. A failed session would force a new
proposal and a new scan for what is usually a misread QR code.

#### 6.5 ZIP 320 and sessions

A `tex1` send creates one session covering both steps. After both are signed
the daemon inserts a `tex_queue` row (Q-T1) and the stream emits `TexQueued`
before the step-2 `Broadcast`. If step 2 later fails permanently
(`TEX_STATE_STEP2_FAILED`), `gyges tx resume TXID` calls `ResumeTexTransfer`,
which builds a new step-2 transaction and opens a *new* session for it; that
RPC therefore needs a `session_token` or is followed by the same
`SignatureRequired` handling as a send (it is unary, so for Keystone profiles
it returns `SIGNATURE_REQUIRED` with the `session_id` and the client proceeds
via `gyges tx sessions` / `pczt qr-import --session`).

---

### 7. CLI command to RPC mapping

Every command maps to exactly one RPC, or to none when it is purely local.

| Command | RPC | Notes |
|---|---|---|
| `daemon start` | — | Spawns `gygesd`; no socket exists yet |
| `daemon stop` | `Shutdown` | `graceful = true` by default; `--force` sets false |
| `daemon status` | `GetInfo` | Prints node bounds, Tor state, fallback trust, per-key summary |
| `daemon logs` | `StreamLogs` | `--follow`, `--lines`, `--audit` |
| `daemon install` / `uninstall` | — | Writes and loads, or stops and removes, a launchd / systemd user unit (Q-C5); `install` then waits for `GetInfo` |
| `key list` | `ListKeys` | |
| `key init` | `InitKey` | CLI shows the mnemonic once and requires three words typed back |
| `key restore` | `RestoreKey` | CLI prompts for backfill consent using `GetInfo.fallback` and `node.retained_from` |
| `key import-keystone` | `ImportKeystone` | `--birthday` required or prompted; default NU5 activation |
| `key import-ufvk` | `ImportUfvk` | |
| `key unlock` | `UnlockKey` | `scope = DAEMON`; the CLI exits and the key stays unlocked in the daemon until the idle TTL |
| `key lock` | `LockKey` | |
| `key export-ufvk` | `ExportUfvk` | |
| `key export-seed` | `ExportSeed` | TTY only; never with `--json` |
| `key delete` | `DeleteKey` | `--wipe` |
| `key backup` | `BackupKey` | |
| `key import-backup` | `ImportBackup` | |
| `sync status` | `GetSyncStatus` | |
| `sync wait` | `WaitSync` | `--until scanned\|spendable`, `--txid T --confirmations N` |
| `sync run` | `RunSync` | `--from` below `scanned_tip` prompts (or `--yes`) |
| `sync mempool` | `ScanMempool` | |
| `address current` | `GetCurrentAddress` | `--qr` renders locally |
| `address new` | `NewAddress` | `--tex` removed (Q-T5) |
| `address qr [ADDR]` | `GetCurrentAddress` or — | With an explicit address, purely local |
| `address inspect` | `InspectAddress` | |
| `balance` | `GetBalance` | |
| `notes` | `ListNotes` | |
| `tx send` | `SendTransaction` | Inline unlock via `UnlockKey { session_id }`; Keystone via `CompleteKeystoneSign` |
| `tx shield` | `ShieldFunds` | |
| `tx list` | `ListTransactions` | |
| `tx status` | `GetTransactionStatus` | `--pir` sets `via_pir` |
| `tx sessions` | `ListSigningSessions` | The response also carries the ZIP 320 rows (`tex_transfers`) |
| `tx abort SESSION_ID` | `AbortSigningSession` | 32-hex argument |
| `tx abort TXID` | `AbortTexTransfer` | 64-hex argument; allowed only in `BUILT` |
| `tx resume TXID` | `ResumeTexTransfer` | On `SIGNATURE_REQUIRED` the CLI satisfies the session, then polls `ListSigningSessions` for the rebuilt step 2 |
| `pczt create` | `CreatePczt` | One `.pczt`; a `tex1` recipient is refused (§9) |
| `pczt inspect` | `InspectPczt` | |
| `pczt prove` | `ProvePczt` | |
| `pczt sign` | `SignPczt` | |
| `pczt combine` | `CombinePczt` | |
| `pczt broadcast` | `BroadcastPczt` | |
| `pczt qr-export` | — | Encodes a PCZT file as `ur:zcash-pczt` frames locally |
| `pczt qr-scan` | `CompleteKeystoneSign` | Camera input; `--session` selects the session |
| `pczt qr-import` | `CompleteKeystoneSign` | Frames from args, `--from-file`, or stdin; `--session` |

The CLI distinguishes `tx abort SESSION_ID` from `tx abort TXID` by argument
length; both are kept under one verb because that is what the review
proposed, and the proto keeps them as two RPCs because they act on different
tables.

#### 7.1 PCZT key-id rule

`CreatePczt` writes `gyges.key_id`, `gyges.network` and `gyges.session_id`
into the PCZT's global proprietary map. `InspectPczt`, `ProvePczt`,
`SignPczt`, `CombinePczt` and `BroadcastPczt` read `key_id` from the PCZT; a
`--key` flag on those commands is only an assertion and fails with
`KEY_MISMATCH` (exit 6) if it differs. `CombinePczt` refuses inputs whose key
ids differ. The Redactor strips the proprietary map before a PCZT leaves the
host for a Keystone (Q-C6).

*Landed:* the five reading requests carry the
assertion as a `key_id` field (empty asserts nothing), checked after the
tags are read and before anything else, so the error names the file's key.
A file without the three tags, or with a malformed one, is
`INVALID_ARGUMENT`; one tagged for another network is `NETWORK_MISMATCH`.
`CreatePczt` returns the `session_id` it wrote and stores the approved
proposal under it in the key's `ext_gyges_signing_sessions` row
(architecture.md Data model §5.2); `BroadcastPczt` refuses with `SESSION_NOT_FOUND` when
this daemon holds no such row (the file was created elsewhere, or the
wallet was restored since), with `INVALID_ARGUMENT` when the file is not
proven, not fully signed, already broadcast, or when the Verifier finds it
differs from the stored proposal (nothing is broadcast). `CombinePczt`
needs two or more files and maps the Combiner's `DataMismatch` to
`INVALID_ARGUMENT`. A `tex1` recipient is refused by `CreatePczt` with
`INVALID_ARGUMENT` naming `tx send` (§9).

#### 7.2 Addresses, notes and history

*Landed* in `gygesd::wallet` over
`gyges_core::{addresses, history}`; the proto is unchanged.

- **`GetCurrentAddress`** returns the address most recently handed out, by
  any receiver set (upstream's `get_last_generated_address_matching`). On a
  fresh key that is the account's default address, which upstream exposes
  with every receiver the key has (Orchard, Sapling, transparent) when it
  creates the account; it needs no sync.
- **`NewAddress`** (`get_next_available_address`) requires the listed
  receivers and omits the others; empty means `orchard,sapling` (Keystone
  profiles: `orchard,transparent`). `POOL_IRONWOOD` names the Orchard
  receiver, which also takes Ironwood notes after NU6.3. A list without a
  shielded receiver, or with `POOL_UNSPECIFIED`, is `INVALID_ARGUMENT`; a
  pool outside the profile's `receive_pools` is `UNSUPPORTED_POOL`; before
  the first scan has recorded the chain tip it is `NOT_SYNCED`; a used-up
  transparent gap limit is `INVALID_ARGUMENT`. `label` (1–128 bytes, no
  control characters) is stored in `ext_gyges_address_labels`
  (architecture.md Data model §5.3) and returned by both RPCs.
- **Receivers** are listed one per receiver in the address, in its
  preference order; the Orchard receiver is `POOL_ORCHARD` with an empty
  `encoded`. `AddressInfo.receivers` and `InspectAddressResponse.receivers`
  are built by the same parse, so they agree for the same string.
- **`InspectAddress`** never fails on its input: a malformed address is
  `valid = false` with `error`, and so is a well-formed address for another
  network (`network` then names the address's own). Regtest transparent
  addresses share testnet's prefixes, so on a regtest daemon a
  testnet-encoded `t`-address is valid and reported as `NETWORK_REGTEST`.
  The CLI exits 6 when `valid` is false.
- **`ListNotes`** lists received notes and UTXOs oldest first (unmined
  last), from upstream's `v_received_outputs`. A note is `spent` when a
  transaction spending it is mined, or unmined and not expired; a note
  received in an unmined transaction that has expired is not listed.
  `witness_ready` means mined at or below the fully scanned height with a
  commitment tree position (shielded), or mined (transparent). `ephemeral`
  marks ZIP 320 ephemeral outputs. `memo_preview` is filled when the wallet
  holds the memo: always for its own sends, for incoming payments once
  transaction enhancement exists (compact blocks carry no memos).
- **`ListTransactions`** is newest first: unmined transactions, then mined
  ones by height and position in the block. `before_txid` pages after that
  transaction (unknown or malformed: `INVALID_ARGUMENT`); `limit` 0 is 50,
  capped at 1,000. Accounting (`net_value`, `fee`) is upstream's
  `transaction_history_summaries`; `outputs` come from `v_tx_outputs`,
  change included and flagged, with `memo` as the text of a text memo and
  the raw bytes otherwise. Both steps of a ZIP 320 transfer carry its
  `TexQueueEntry` and are `TEX_PENDING` until the row is `step2_mined` or
  terminal (`expired` → `EXPIRED`, `failed` / `aborted` → `FAILED` for an
  unmined step). `AWAITING_SIGNATURE` is never reported: a signing session
  holds no transaction until it is signed.
- **`GetTransactionStatus`** asks the node (`getrawtransaction`), so a fully
  transparent transaction the wallet cannot see mined is reported too;
  `confirmations` counts from the node's current tip. When the node does not
  know the transaction, the wallet and the ZIP 320 queue answer: `EXPIRED`,
  `FAILED`, `PENDING`, or `MINED` at the height the wallet scanned with
  `source = STATUS_SOURCE_UNSPECIFIED` (the node has dropped it from its
  index). Unknown to all three is `INVALID_ARGUMENT`; an unreachable node is
  `NODE_UNREACHABLE`; `via_pir` is `INVALID_ARGUMENT` until PIR status lands (`decisions.md` §3.1).
- All six are outside the air-gapped allow-list (§8), `InspectAddress`
  included, and refuse a `signer-only` profile (no wallet) with
  `INVALID_ARGUMENT`.

---

### 8. Air-gapped mode

With `gygesd --airgapped` the daemon serves only: `GetInfo`, `Shutdown`, `ListKeys`,
`InitKey`, `UnlockKey`, `LockKey`, `ExportSeed`, `ExportUfvk`, `DeleteKey`,
`BackupKey`, `ImportBackup`, `InspectPczt`, `ProvePczt`, `SignPczt`,
`CombinePczt`, `ListSigningSessions`, `AbortSigningSession`,
`CompleteKeystoneSign` (for `SIGN_PCZT` sessions) and `StreamLogs`. Every
other RPC returns `AIRGAPPED` before its handler runs (the allow-list is a
tower layer in `gygesd::policy`, with `Shutdown` included so the daemon can be
stopped over the socket). Profiles on the air-gapped box are
`SIGNER_ONLY` (seed, no database); a PCZT arriving from the online side
carries every anchor and witness the Prover and Signer need (Q-K5).

---

### 9. Deviations from the review

- **`tx abort`** is one CLI verb but two RPCs (`AbortSigningSession`,
  `AbortTexTransfer`), chosen by argument shape. The review used the same
  verb for both without saying how they are told apart.
- **`SendTransaction` is server-streaming, not bidirectional.** The review's
  flow (stream pauses, client unlocks or scans) is implemented with the
  side-channel RPCs `UnlockKey { session_id }` and `CompleteKeystoneSign`
  rather than client messages on the same stream, so that a Keystone session
  can be finished from a different process (Q-C4).
- **`UnlockKey` has an explicit `scope`.** Q-S1's connection-scoped tokens
  die with the process that obtained them, which would make `gyges key unlock
  --timeout 15m` useless from a shell. The proto therefore adds
  `UnlockScope { CONNECTION, DAEMON }`: the inline flow keeps the strong
  connection-bound mode, and `key unlock` uses the weaker daemon-wide mode
  the original `architecture.md` Components described, now documented as weaker (§6.3).
- **`RestoreKey.allow_backfill`** replaces the review's "prompt once" with a
  request flag; the prompt is in the CLI, informed by `GetInfo.fallback`, so
  the daemon never blocks on a user.
- **`ResumeTexTransfer` is unary** and may return `SIGNATURE_REQUIRED` with a
  `session_id` instead of streaming, because the resumed step is a single
  transparent transaction and the session machinery already covers it. As
  landed: the rebuild runs in the background once the session is satisfied,
  a second call while it is pending returns the row unchanged rather than
  opening another session, a call on any other live row is a nudge (the
  queue re-checks the node now), and a failed rebuild shows as a `FAILED`
  session with the reason in `last_error`.
- **ZIP 320 sends sign before they prove.** Upstream's `create_pczt_from_proposal`
  takes single-step proposals only, so the two steps are built with
  `create_proposed_transactions`, which proves and signs inside the builder
  with the key present. The stream therefore emits `SignatureRequired` for
  step 1 right after `Proposed`, before any `Proving` event, and the PCZT
  Verifier (§6.4) does not run for these sends: the builder is the daemon's
  own, and the node-facing checks are the proposal the user approved.
  Keystone profiles cannot send to `tex1` until M5 revisits this.
- **`ListSigningSessionsResponse.tex_transfers`** carries the ZIP 320 rows,
  so that `gyges tx sessions` lists both without a `ListTransactions`
  implementation; `TexQueueEntry` gained `expiry_height` and `key_id`.
- **`Shutdown.graceful`** adds the in-flight handling the review asked for
  under `daemon stop` (§2.2) with a bounded grace period.
