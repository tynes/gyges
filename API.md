# Gyges gRPC API (`gyges` ⇄ `gygesd`)

The contract between the CLI and the daemon. The machine-readable source is
[`proto/gyges.proto`](proto/gyges.proto); this document explains the parts a
proto file cannot: transport, authentication, versioning, the error model,
streaming semantics and the signing-session lifecycle. Where this document and
the proto disagree, the proto wins and this document has a bug.

Design inputs: `OVERVIEW.md` §2.1 (error model), Q-S1…S3 (sessions), Q-Y4
(sync definitions), Q-K2/K4 (Keystone), Q-T1 (ZIP 320 queue), Q-C1…C6 (CLI
behaviour), Q-O1 (logs), Q-O3 (versioning).

---

## 1. Transport and authentication

### 1.1 Socket

- One daemon per network. The socket is `~/.gyges/<network>/gygesd.sock`
  (`GYGES_HOME` overrides `~/.gyges`). The CLI derives the path from
  `--network` / `GYGES_NETWORK` (default `mainnet`) and never reads
  `config.toml`; `--socket` / `GYGES_SOCKET` overrides the derived path.
- Protocol: gRPC (HTTP/2, no TLS) over the Unix domain socket. The daemon is a
  `tonic` server on a `tokio::net::UnixListener`; the CLI is a `tonic` client
  with a `tower::service_fn` connector that opens a `UnixStream`.
- Socket mode is `0600` (owner only). In the hardened deployment (`gygesd`
  running as its own user) it is `0660` with a `gyges` group.
- Windows is out of scope for v1 (Q-O4); there is no named-pipe transport.

### 1.2 Peer credentials

On every accepted connection the daemon reads the peer's uid
(`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS). A uid that is neither
the daemon's own nor in `daemon.allowed_uids` is rejected before any RPC is
read; a client that somehow gets a request through receives
`PERMISSION_DENIED`. Same-uid processes are trusted to *connect*; they are
not trusted to *spend* (see §6).

### 1.3 Handshake

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

### 1.4 `key_id` resolution

Every request with a `key_id` field accepts an empty string, which the daemon
replaces with `config.default_key`. If no default is configured the daemon
returns `KEY_NOT_FOUND` with `detail = "no default key; pass --key"`. The CLI
passes `--key` / `GYGES_KEY` through verbatim and does no resolution of its
own (Q-C1).

---

## 2. Versioning

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
- `gyges` and `gygesd` ship as one release artifact; the `daemon install`
  service unit restarts the daemon after an upgrade, so mismatches are rare.
- JSON output (§5) carries `schema_version` = `"<major>.<minor>"`.

The first released API version is `1.0`. Until then the number is `0.x` and
nothing in this document is stable.

---

## 3. Error model

Every failed RPC returns a gRPC status whose `details` carry exactly one
`gyges.v1.GygesError` (`grpc-status-details-bin`, type URL
`type.googleapis.com/gyges.v1.GygesError`). The gRPC status code is chosen to
be sensible for generic clients (`FAILED_PRECONDITION` for a locked vault,
`INVALID_ARGUMENT` for a bad address, `UNAVAILABLE` for an unreachable node,
and so on), but **the CLI dispatches on `GygesError.reason`, never on the
status code or message text**. The `"VAULT_LOCKED:main"` string convention
from the original `ARCHITECTURE.md` is withdrawn.

`GygesError.detail` is a human-readable sentence that is safe to print and to
log: it never contains addresses, amounts, memos, txids or key material.
`node_error` carries the node's verbatim rejection text for `NODE_REJECTED`
only.

### 3.1 Exit-code mapping

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

## 4. Streaming RPCs

### 4.1 `SendTransaction` and `ShieldFunds`

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
  spends from a `LOCAL_SEED` or `SIGNER_ONLY` profile: its `SignatureRequired`
  precedes its `Proving` events because the proof generation key must be
  inserted first (Q-K3). A ZIP 320 send (`n = 2`) is the other exception
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
proposal (the output pool is Ironwood after NU6.3, see `OVERVIEW.md` §4.3).
A `KEYSTONE_QR` profile always gets `KEYSTONE_SINGLE_PCZT` for it, because
the batch protocol rejects transparent inputs.

Status (ROADMAP.md M1, `TxEngine`): implemented for `LOCAL_SEED` profiles
with `n = 1`; `Proving` is emitted once per shielded pool with work before
the proofs and once after. A `WATCH_ONLY` profile answers
`INVALID_ARGUMENT`, a `KEYSTONE_QR` one `HARDWARE_SIGNER`, until their items
land. Passphrase sessions live in daemon memory only (§6.1) and show in
`ListSigningSessions` with their status; a session that is aborted ends its
stream with `CANCELLED`. A transaction the node refuses (`NODE_REJECTED`)
has already been recorded in the wallet as unmined and its inputs stay
unspendable until its expiry height. `wait_for_mined` ends once the wallet
has the transaction's mined height. The scanner finds most transactions (a
change output or a nullifier of ours). The daemon learns about a fully
transparent transaction without change from the node: upstream queues it for
a status lookup, and the scheduler asks `getrawtransaction` and records the
answer (`OVERVIEW.md` §4.3). The lookup goes to the node only, never to the
fallback endpoint, and is skipped while a key backfills.

The CLI approves before it signs: without `--yes`, `gyges tx send` runs the
request as `dry_run` first, prints the proposal, asks, and only then opens
the real stream (the daemon never waits on a prompt, and a daemon-scoped
unlock would otherwise sign at once). The fee can differ between the two
only if the chain moved in between.

### 4.2 `SignPczt`

Server-streaming with the same pause semantics as §4.1 but only two event
types: zero or one `SignatureRequired`, then `signed` (the final PCZT bytes).
For Keystone profiles the returned PCZT has already been through Combiner and
Verifier in the daemon (§6.4); the client never sees a half-signed PCZT.

*Landed (ROADMAP.md M4, first item):* the key is the PCZT's `gyges.key_id`
(`key_id` in the request is an assertion, §7.1); `local-seed` and
`signer-only` profiles sign, the others are refused as in §4.1. The
`SignatureRequired.summary` is what `InspectPczt` derives from the file.
The stream needs no node: a passphrase session that expires is replaced by
a fresh one without the "can still be mined" check of §4.1, since an
air-gapped daemon cannot know the tip; the file's expiry height is the
client's to watch.

*Change ownership (ROADMAP.md M4, third item):* once the key is unlocked
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

### 4.3 Non-interactive clients

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

### 4.4 `WaitSync` and `RunSync`

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
(SYNC.md §7). The pass covers every transaction in the node's mempool and
every key, whether or not `mempool.scan` is on. `transactions_scanned`
counts the transactions fetched and parsed. `notes_found` counts the notes
they pay to `key_id`, or to every key when `key_id` is empty; received notes
and change are counted, outputs the wallet sent elsewhere are not. What is
found shows as `pending` in `GetBalance` until mined. An unknown `key_id`
is `KEY_NOT_FOUND`. A daemon without a node, or a pass that cannot reach
it, answers `NODE_UNREACHABLE`.

### 4.5 `StreamLogs`

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

### 4.6 `InitKey` / `RestoreKey`

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
will fetch from it (up to the handoff height, SYNC.md §5.1), and the key
syncs through `Backfilling` (`SYNC_STATE_VALIDATING_HANDOFF` with `backend`
`SYNC_BACKEND_TOR_LWD_FALLBACK` or `_DIRECT_LWD_FALLBACK`) before Case A.
Such a restore carries one entry in `warnings`: transparent history below
`retained_from` comes from the endpoint and is best-effort (SYNC.md §5.3).
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

### 4.7 `BackupKey` / `ImportBackup`

Chunked tar archives. `BackupKey` runs `wal_checkpoint(TRUNCATE)` before
reading `wallet.sqlite` and holds the key's write lock for the duration.
`ImportBackup` refuses an existing `key_id` with `KEY_EXISTS` and validates
`profile.json` before writing anything.

---

## 5. JSON output

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
- Commands with no RPC (`address qr ADDRESS`, `pczt qr-export`) print
  `{"schema_version": …, "ok": true}` and the rendered frames on stderr.

---

## 6. Signing sessions

A signing session is the daemon-side record of "this transaction is waiting
for a signature". It exists so that the key is held as briefly as possible,
so that malware with socket access cannot ride on another process's unlock,
and so that a Keystone round trip can be completed from a later process.

### 6.1 Record

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

### 6.2 Satisfying a session

| `kind` | Client action | Daemon action |
|---|---|---|
| `PASSPHRASE` | `UnlockKey { key_id, passphrase, session_id }` | Derives the USK, signs the pending step(s), zeroizes the USK, resumes the stream. No token is returned. |
| `KEYSTONE_BATCH` | `CompleteKeystoneSign { session_id, payload = zcash-batch-sig-result }` | Checks the echoed `request_id`, applies each `(pool, action_index, signature)` to `proven_pczt`, runs Verifier, Spend Finalizer, Tx Extractor, then broadcasts (SEND) or returns the PCZT (SIGN_PCZT). |
| `KEYSTONE_SINGLE_PCZT` | `CompleteKeystoneSign { session_id, payload = zcash-pczt }` | Runs Combiner (`proven_pczt` ⊕ returned PCZT; structural mismatch fails with `HARDWARE_SIGNER`), then Verifier, Spend Finalizer, Tx Extractor, then broadcasts or returns. |

A session can be satisfied once. A second attempt returns
`SESSION_NOT_FOUND`.

### 6.3 Connection scoping and tokens

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
    and exists only for batch scripts; `THREAT_MODEL.md` treats a DAEMON
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

### 6.4 What the daemon verifies before broadcast

For every completed session, regardless of kind, the daemon runs the PCZT
**Verifier** against the stored `proposal` and refuses to broadcast if any
output address, value, fee, memo or anchor differs (Q-K7). On failure the
session is marked `failed` with `last_error`, the response is
`HARDWARE_SIGNER` (Keystone kinds) or `INTERNAL` (passphrase kinds), and
nothing is broadcast or stored as a pending transaction.

### 6.5 ZIP 320 and sessions

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

## 7. CLI command to RPC mapping

Every command maps to exactly one RPC, or to none when it is purely local.

| Command | RPC | Notes |
|---|---|---|
| `daemon start` | — | Spawns `gygesd`; no socket exists yet |
| `daemon stop` | `Shutdown` | `graceful = true` by default; `--force` sets false |
| `daemon status` | `GetInfo` | Prints node bounds, Tor state, fallback trust, per-key summary |
| `daemon logs` | `StreamLogs` | `--follow`, `--lines`, `--audit` |
| `daemon install` / `uninstall` | — | Writes a launchd / systemd user unit (Q-C5) |
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

### 7.1 PCZT key-id rule

`CreatePczt` writes `gyges.key_id`, `gyges.network` and `gyges.session_id`
into the PCZT's global proprietary map. `InspectPczt`, `ProvePczt`,
`SignPczt`, `CombinePczt` and `BroadcastPczt` read `key_id` from the PCZT; a
`--key` flag on those commands is only an assertion and fails with
`KEY_MISMATCH` (exit 6) if it differs. `CombinePczt` refuses inputs whose key
ids differ. The Redactor strips the proprietary map before a PCZT leaves the
host for a Keystone (Q-C6).

*Landed (ROADMAP.md M4, first item):* the five reading requests carry the
assertion as a `key_id` field (empty asserts nothing), checked after the
tags are read and before anything else, so the error names the file's key.
A file without the three tags, or with a malformed one, is
`INVALID_ARGUMENT`; one tagged for another network is `NETWORK_MISMATCH`.
`CreatePczt` returns the `session_id` it wrote and stores the approved
proposal under it in the key's `ext_gyges_signing_sessions` row
(DATA_MODEL.md §5.2); `BroadcastPczt` refuses with `SESSION_NOT_FOUND` when
this daemon holds no such row (the file was created elsewhere, or the
wallet was restored since), with `INVALID_ARGUMENT` when the file is not
proven, not fully signed, already broadcast, or when the Verifier finds it
differs from the stored proposal (nothing is broadcast). `CombinePczt`
needs two or more files and maps the Combiner's `DataMismatch` to
`INVALID_ARGUMENT`. A `tex1` recipient is refused by `CreatePczt` with
`INVALID_ARGUMENT` naming `tx send` (§9).

### 7.2 Addresses, notes and history

*Landed (ROADMAP.md M1 follow-up)* in `gygesd::wallet` over
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
  (DATA_MODEL.md §5.3) and returned by both RPCs.
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
  `NODE_UNREACHABLE`; `via_pir` is `INVALID_ARGUMENT` until ROADMAP.md M6.
- All six are outside the air-gapped allow-list (§8), `InspectAddress`
  included, and refuse a `signer-only` profile (no wallet) with
  `INVALID_ARGUMENT`.

---

## 8. Air-gapped mode

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

## 9. Deviations from the review

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
  the original `ARCHITECTURE.md` described, now documented as weaker (§6.3).
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
