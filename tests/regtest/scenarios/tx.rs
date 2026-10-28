//! `gyges balance`, `gyges tx send` and `gyges tx shield` through the
//! binaries against the in-process fake `zakurad` (TESTING.md §3 rows 1–3
//! and 14 in miniature; the real-node versions are in `scenarios/node.rs`).
//!
//! Covers: the zero balance of a fresh key, the funded transparent balance,
//! `--dry-run --json` (the `Proposal` message with `schema_version`), the
//! exit-4 refusal of a locked key with no terminal and no passphrase source
//! (JSON carries `reason` and `session_id`), the exit-5 insufficient funds,
//! the exit-6 memo-to-transparent refusal, a non-interactive shield with
//! `GYGES_PASSPHRASE_FILE`, and the Ironwood balance after mining.

use std::time::Duration;

use gyges_regtest::{
    Fixture, PASSPHRASE, SPEND_CONFIG, TEX_CONFIG, burn_t_address, burn_tex_address,
    fund_transparent, parse_tex_txids, poll_until, pool_spendable, spendable, sweep_logs,
    synced_key, wait_balance, wait_for_txid, wait_spendable, wait_tex_state,
};

#[test]
fn balance_send_and_shield_through_the_binaries() {
    let (n, fx, pw) = synced_key(10, SPEND_CONFIG);

    // Fresh key: zero everywhere, in both renderings.
    let run = fx.gyges(&["-k", "main", "balance", "--json"]).ok();
    let b = run.json();
    assert_eq!(b["schema_version"], "0.1");
    assert!(b.get("total_spendable").is_none(), "zero is omitted: {b}");
    assert_eq!(b["min_confirmations"], 1);
    fx.gyges(&["-k", "main", "balance"])
        .run()
        .stdout_has("orchard")
        .stdout_has("0.00000000");

    // Insufficient funds is exit 5, before any passphrase is asked.
    let t_addr = burn_t_address();
    let send = |extra: &[&str]| {
        fx.gyges(&[
            "-k", "main", "tx", "send", "--to", &t_addr, "--amount", "0.5",
        ])
        .args(extra)
    };
    send(&["--yes"]).code(5).stderr_has("insufficient funds");

    // Fund 1 ZEC transparent and confirm it.
    fund_transparent(&n, &fx, 100_000_000);
    let run = fx.gyges(&["-k", "main", "balance", "--json"]).run();
    assert_eq!(run.json()["total_spendable"], "100000000", "{run:?}");

    // A memo to a transparent recipient is exit 6, never dropped.
    send(&["--memo", "hi", "--yes"]).code(6).stderr_has("memo");

    // `--dry-run --json` prints the proposal only.
    let run = send(&["--dry-run", "--json"]).ok();
    let lines = run.json_lines();
    assert_eq!(lines.len(), 1, "{}", run.stdout);
    let proposed = &lines[0]["proposed"];
    assert_eq!(
        proposed["steps"][0]["inputs"][0]["pool"],
        "POOL_TRANSPARENT"
    );
    assert_eq!(proposed["steps"][0]["outputs"][0]["address"], t_addr);
    assert_eq!(proposed["steps"][0]["outputs"][0]["value"], "50000000");
    assert!(
        proposed["total_fee"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    assert_eq!(lines[0]["schema_version"], "0.1");

    // The confirmation prompt needs a terminal or --yes (exit 4).
    send(&[]).code(4).stderr_has("--yes");

    // Locked key, no terminal, no passphrase source: exit 4 with the fix,
    // the session aborted, JSON carrying reason and session_id.
    let run = send(&["--yes", "--json"]).code(4);
    let last: serde_json::Value = serde_json::from_str(run.stdout.lines().last().unwrap()).unwrap();
    assert_eq!(last["error"]["reason"], "ERROR_REASON_VAULT_LOCKED");
    assert_eq!(last["error"]["session_id"].as_str().unwrap().len(), 32);
    assert!(
        last["error"]["detail"]
            .as_str()
            .unwrap()
            .contains("run 'gyges key unlock' or pass --passphrase-fd"),
        "{last}"
    );
    fx.gyges(&["-k", "main", "tx", "sessions", "--include-finished"])
        .ok()
        .stdout_has("aborted");

    // Shield everything with the passphrase from a file; the txid is on
    // stdout and the node has it.
    let run = fx
        .gyges(&["-k", "main", "tx", "shield", "--yes"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok();
    let txid = run.stdout.trim().to_string();
    assert_eq!(txid.len(), 64, "{run:?}");
    run.stderr_has("broadcast");
    assert_eq!(
        n.node.mempool(),
        vec![gyges_chain::parse_display_hash(&txid).unwrap()]
    );

    // Mined: the input, less a fee, is Ironwood, and `sync wait --txid`
    // sees the confirmations.
    n.node.mine(2);
    wait_for_txid(&fx, "main", &txid, 2);
    let b = wait_balance(&fx, "main", |b| {
        pool_spendable(b, "POOL_IRONWOOD").is_some()
    });
    let ironwood = spendable(&b, "POOL_IRONWOOD");
    assert!(ironwood > 99_000_000 && ironwood < 100_000_000, "{b}");
    for pool in ["POOL_ORCHARD", "POOL_TRANSPARENT"] {
        assert!(
            b["pools"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["pool"] != pool || p.get("spendable").is_none()),
            "{pool}: {b}"
        );
    }
    fx.gyges(&["-k", "main", "balance"])
        .run()
        .stdout_has("ironwood");

    // TESTING.md §5, system level: neither log shows the address, the txid,
    // an amount (as zatoshis or decimal) or the passphrase.
    let log_dir = fx.network_dir().join("logs");
    let secrets = [
        t_addr.as_str(),
        txid.as_str(),
        "100000000",
        "50000000",
        "0.50000000",
        PASSPHRASE,
    ];
    sweep_logs(&log_dir, &secrets);
    let mut main_log = String::new();
    for entry in std::fs::read_dir(&log_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "audit.log" {
            assert!(
                name.starts_with("gygesd.") && name.ends_with(".log"),
                "{name}"
            );
            main_log.push_str(&std::fs::read_to_string(entry.path()).unwrap());
        }
    }
    assert!(main_log.contains("transaction broadcast"), "{main_log}");

    // `audit.log`: one JSON object per line, key id and event only, and the
    // events of this scenario in order.
    let audit_log = std::fs::read_to_string(log_dir.join("audit.log")).expect("audit.log written");
    let lines: Vec<serde_json::Value> = audit_log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect();
    let allowed = [
        "timestamp",
        "level",
        "event",
        "key_id",
        "scope",
        "via",
        "from",
    ];
    for line in &lines {
        for (k, v) in line.as_object().unwrap() {
            assert!(
                allowed.contains(&k.as_str()),
                "unexpected key {k} in {line}"
            );
            assert!(v.is_string(), "{line}");
        }
        assert_eq!(line["key_id"], "main", "{line}");
        assert_eq!(line["level"], "INFO", "{line}");
    }
    let events: Vec<&str> = lines.iter().map(|l| l["event"].as_str().unwrap()).collect();
    // The locked `tx send --yes --json` above created and aborted a session;
    // the shield's session was completed by the passphrase, then signed
    // through it and broadcast.
    let aborted = events.iter().position(|e| *e == "session_aborted").unwrap();
    let broadcast = events.iter().position(|e| *e == "broadcast").unwrap();
    assert!(aborted < broadcast, "{events:?}");
    assert_eq!(
        &events[broadcast - 3..=broadcast],
        ["session_created", "session_completed", "sign", "broadcast"],
        "{events:?}"
    );
    assert_eq!(lines[broadcast - 1]["via"], "session", "{events:?}");

    // `gyges daemon logs` serves both logs through `StreamLogs` (API.md
    // §4.5), as JSON `LogEntry` messages or rendered lines.
    let run = fx
        .gyges(&["daemon", "logs", "--audit", "--lines", "200", "--json"])
        .ok();
    let streamed = run.json_lines();
    assert_eq!(streamed.len(), lines.len(), "{}", run.stdout);
    let last = streamed.last().unwrap();
    assert_eq!(last["target"], "gyges::audit");
    assert_eq!(last["level"], "LOG_LEVEL_INFO");
    assert_eq!(last["fields"]["event"], "broadcast");
    assert_eq!(last["fields"]["key_id"], "main");
    assert!(
        last["timestamp_unix_ms"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap()
            > 0
    );
    for secret in secrets {
        assert!(!run.stdout.contains(secret), "{secret:?} streamed");
    }
    let run = fx.gyges(&["daemon", "logs", "--lines", "500"]).ok();
    run.stdout_has("transaction broadcast");
    run.stdout_has("gygesd listening");
    for secret in secrets {
        assert!(!run.stdout.contains(secret), "{secret:?} streamed");
    }
}

/// A ZIP 320 send through the binaries (CLI_SPEC.md §2.5 `tex1`), against a
/// node that will not chain mempool transactions, then a daemon crash
/// (SIGKILL) with the row pending (TESTING.md §3 row 12): the restarted
/// daemon finishes the transfer from the stored bytes, without a passphrase,
/// and step 2 keeps its txid. Also `--dry-run` with both steps, `tx
/// sessions`, and the `tx abort` / `tx resume` refusals.
#[test]
fn zip320_send_survives_a_daemon_crash() {
    let (n, mut fx, pw) = synced_key(10, TEX_CONFIG);
    fund_transparent(&n, &fx, 200_000_000);
    fx.gyges(&["-k", "main", "tx", "shield", "--yes"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok();
    n.node.mine(2);
    wait_spendable(&fx);

    let tex_addr = burn_tex_address();
    let send = |extra: &[&str]| {
        fx.gyges(&[
            "-k", "main", "tx", "send", "--to", &tex_addr, "--amount", "0.5",
        ])
        .args(extra)
    };

    // The dry run shows both steps and both fees.
    let run = send(&["--dry-run"]).ok();
    run.stderr_has("Step 1 of 2").stderr_has("Step 2 of 2");
    run.stderr_has("ephemeral");
    run.stderr_has(&tex_addr);
    let run = send(&["--dry-run", "--json"]).ok();
    let proposed = &run.json()["proposed"];
    assert_eq!(proposed["steps"].as_array().unwrap().len(), 2, "{proposed}");
    assert_eq!(proposed["steps"][1]["transparent_only"], true, "{proposed}");

    // The node refuses step 2 until step 1 is mined: the send ends with
    // `tex pending` and one txid on stdout.
    n.node
        .set_reject_transparent_only(Some("bad-txns-inputs-missingorspent".into()));
    let run = send(&["--yes"]).env("GYGES_PASSPHRASE_FILE", &pw).ok();
    let (s1, s2) = parse_tex_txids(&run);
    assert_eq!(
        run.stdout.lines().count(),
        1,
        "only step 1 reached the node: {run:?}"
    );
    assert_eq!(
        n.node.mempool(),
        vec![gyges_chain::parse_display_hash(&s1).unwrap()]
    );
    let row = wait_tex_state(&fx, &s1, "TEX_STATE_STEP1_BROADCAST");
    assert_eq!(row["step2_txid"], s2, "{row}");
    assert!(
        row["last_error"]
            .as_str()
            .unwrap()
            .contains("missingorspent"),
        "{row}"
    );
    fx.gyges(&["-k", "main", "tx", "sessions"])
        .ok()
        .stdout_has(&s1)
        .stdout_has("step1_broadcast");
    // Too late to abort (exit 6), and the argument shapes are checked.
    fx.gyges(&["-k", "main", "tx", "abort", &s1])
        .code(6)
        .stderr_has("built");
    fx.gyges(&["-k", "main", "tx", "resume", "nonsense"])
        .code(6);

    // Crash with the row pending; mine step 1 while the daemon is down.
    fx.kill_daemon();
    n.node.mine(1);
    n.node.set_reject_transparent_only(None);
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();
    // The restarted queue rebroadcasts step 2 from its stored bytes: same
    // txid, no passphrase asked.
    let want = gyges_chain::parse_display_hash(&s2).unwrap();
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(200),
        "step 2 never rebroadcast",
        || {
            let mempool = n.node.mempool();
            if mempool.contains(&want) {
                return Ok(());
            }
            Err(format!("mempool {mempool:?}"))
        },
    );
    n.node.mine(1);
    let row = wait_tex_state(&fx, &s1, "TEX_STATE_STEP2_MINED");
    assert_eq!(row["step2_txid"], s2, "{row}");
    assert_eq!(row["amount"], "50000000", "{row}");
    assert_eq!(row["recipient"], tex_addr, "{row}");
    fx.gyges(&["-k", "main", "tx", "resume", &s1])
        .code(6)
        .stderr_has("nothing to resume");
    wait_spendable(&fx);
    let b = fx.gyges(&["-k", "main", "balance", "--json"]).run().json();
    let ironwood = pool_spendable(&b, "POOL_IRONWOOD").expect("ironwood spendable");
    assert!(
        ironwood < 150_000_000 && ironwood > 149_900_000,
        "amount and both fees left: {b}"
    );

    // Nothing identifying in the logs, across both daemon runs.
    sweep_logs(
        &fx.network_dir().join("logs"),
        &[&tex_addr, &s1, &s2, "50000000", PASSPHRASE],
    );
}

/// Wait until `tx status TXID --json` reports `status`.
fn wait_tx_status(fx: &Fixture, txid: &str, status: &str) -> serde_json::Value {
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(200),
        &format!("never {status}"),
        || {
            let v = fx
                .gyges(&["-k", "main", "tx", "status", txid, "--json"])
                .ok()
                .json();
            if v["status"] == status {
                return Ok(v);
            }
            Err(v.to_string())
        },
    )
}

/// `gyges address current/new/qr/inspect`, `gyges notes`, `gyges tx list`
/// and `gyges tx status` through the binaries against the fake node, in
/// both renderings: the M1 commands a user needs to receive, look at what
/// arrived and follow a transaction, plus the QR codes, the
/// not-implemented `--pir` exit and the exit-6 inspection of a bad address.
#[test]
fn addresses_notes_and_history_through_the_binaries() {
    let (n, fx, pw) = synced_key(10, SPEND_CONFIG);

    // The address alone on stdout, details on stderr; JSON is AddressInfo.
    let run = fx.gyges(&["-k", "main", "address", "current"]).ok();
    let current = run.stdout.trim().to_string();
    assert!(current.starts_with("uregtest1"), "{run:?}");
    assert_eq!(run.stdout.lines().count(), 1, "{run:?}");
    run.stderr_has("receivers:").stderr_has("transparent");
    let run = fx
        .gyges(&["-k", "main", "address", "current", "--json"])
        .run();
    let v = run.json();
    assert_eq!(v["address"], current.as_str());
    assert_eq!(v["schema_version"], "0.1");
    assert_eq!(v["receivers"][0]["pool"], "POOL_ORCHARD", "{v}");

    // `--qr`: the address alone on stdout still, the code on stderr.
    let run = fx.gyges(&["-k", "main", "address", "current", "--qr"]).ok();
    assert_eq!(run.stdout.trim(), current, "{run:?}");
    assert!(is_qr(&run.stderr), "{run:?}");
    let run = fx
        .gyges(&["-q", "-k", "main", "address", "current", "--qr"])
        .ok();
    assert!(run.stderr.is_empty(), "-q hides the code: {run:?}");
    // `address qr`: the code on stdout, the address under it.
    let run = fx.gyges(&["-k", "main", "address", "qr"]).ok();
    assert!(is_qr(&run.stdout), "{run:?}");
    assert_eq!(run.stdout.lines().last(), Some(current.as_str()), "{run:?}");
    let run = fx.gyges(&["address", "qr", &current, "--json"]).run();
    let v = run.json();
    assert_eq!(v["address"], current.as_str());
    assert!(is_qr(v["qr"].as_str().unwrap()), "{v}");
    // A mistyped address is refused, never rendered.
    let run = fx.gyges(&["address", "qr", "u1x"]).run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(!run.stdout.contains('█'), "{run:?}");

    let run = fx
        .gyges(&[
            "-k",
            "main",
            "address",
            "new",
            "--receivers",
            "orchard",
            "--label",
            "shop",
            "--json",
        ])
        .ok();
    let fresh = run.json();
    let fresh_addr = fresh["address"].as_str().unwrap().to_string();
    assert_ne!(fresh_addr, current);
    assert_eq!(fresh["label"], "shop");
    assert_eq!(fresh["receivers"].as_array().unwrap().len(), 1, "{fresh}");
    let run = fx.gyges(&["-k", "main", "address", "current"]).run();
    assert_eq!(run.stdout.trim(), fresh_addr);
    run.stderr_has("shop");
    fx.gyges(&["-k", "main", "address", "new", "--receivers", "transparent"])
        .code(6);

    fx.gyges(&["address", "inspect", &current])
        .ok()
        .stdout_has("valid:      yes")
        .stdout_has("unified");
    let run = fx.gyges(&["address", "inspect", &current, "--json"]).run();
    let v = run.json();
    assert_eq!(v["valid"], true);
    assert_eq!(v["network"], "NETWORK_REGTEST");
    assert_eq!(v["kind"], "ADDRESS_KIND_UNIFIED");
    fx.gyges(&["address", "inspect", "nonsense"]).code(6);
    let run = fx
        .gyges(&["address", "inspect", "nonsense", "--json"])
        .code(6);
    assert_eq!(
        run.json()["error"]["reason"],
        "ERROR_REASON_INVALID_ARGUMENT"
    );

    // Empty history.
    let run = fx.gyges(&["-k", "main", "notes"]).ok();
    assert_eq!(run.stdout, "no notes\n");
    let run = fx.gyges(&["-k", "main", "tx", "list"]).run();
    assert_eq!(run.stdout, "no transactions\n");

    // Fund, then shield.
    fund_transparent(&n, &fx, 100_000_000);
    let run = fx.gyges(&["-k", "main", "notes", "--json"]).run();
    let v = run.json();
    let notes = v["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 1, "{v}");
    assert_eq!(notes[0]["pool"], "POOL_TRANSPARENT");
    assert_eq!(notes[0]["value"], "100000000");
    let funding_txid = notes[0]["txid"].as_str().unwrap().to_string();

    let run = fx
        .gyges(&["-k", "main", "tx", "shield", "--yes"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok();
    let shield = run.stdout.trim().to_string();
    let v = wait_tx_status(&fx, &shield, "TRANSACTION_STATUS_PENDING");
    assert_eq!(v["source"], "STATUS_SOURCE_NODE");
    // `sync mempool` forces a pass over the node's mempool, which holds the
    // shield alone; its Ironwood output is main's note, pending until mined.
    let run = fx.gyges(&["-k", "main", "sync", "mempool"]).ok();
    assert_eq!(run.stdout, "scanned 1 transaction, found 1 note\n");
    let run = fx.gyges(&["-k", "main", "sync", "mempool", "--json"]).run();
    let v = run.json();
    assert_eq!(
        (&v["transactions_scanned"], &v["notes_found"]),
        (&serde_json::json!(1), &serde_json::json!(1)),
        "{v}"
    );
    let v = fx.gyges(&["-k", "main", "balance", "--json"]).run().json();
    // Zero amounts are left out of the JSON.
    assert!(v["total_spendable"].is_null(), "{v}");
    assert!(v["total_pending"].is_string(), "{v}");
    fx.gyges(&["-k", "main", "balance"])
        .run()
        .stdout_has("PENDING");
    n.node.mine(2);
    let v = wait_tx_status(&fx, &shield, "TRANSACTION_STATUS_MINED");
    assert_eq!(v["confirmations"], 2, "{v}");
    fx.gyges(&["-k", "main", "tx", "status", &shield])
        .run()
        .stdout_has("mined at height")
        .stdout_has("2 confirmations");
    fx.gyges(&["-k", "main", "tx", "status", &shield, "--pir"])
        .code(1)
        .stderr_has("not implemented");
    fx.gyges(&["-k", "main", "tx", "status", &"00".repeat(32)])
        .code(6);

    // The scan catches up with the shield: spent UTXO, Ironwood note.
    wait_spendable(&fx);
    let v = poll_until(
        Duration::from_secs(30),
        Duration::from_millis(200),
        "the UTXO never showed as spent",
        || {
            let v = fx
                .gyges(&["-k", "main", "notes", "--spent", "--json"])
                .run()
                .json();
            if v["notes"].as_array().is_some_and(|a| !a.is_empty()) {
                return Ok(v);
            }
            Err(v.to_string())
        },
    );
    assert_eq!(v["notes"][0]["spent_txid"], shield.as_str(), "{v}");
    fx.gyges(&["-k", "main", "notes", "--pool", "ironwood"])
        .ok()
        .stdout_has("ironwood")
        .stdout_has("unspent,witness-ready");

    let run = fx.gyges(&["-k", "main", "tx", "list"]).ok();
    run.stdout_has(&shield).stdout_has(&funding_txid);
    run.stdout_has("mined");
    let run = fx
        .gyges(&["-k", "main", "tx", "list", "--limit", "1", "--json"])
        .run();
    let v = run.json();
    let txs = v["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 1, "{v}");
    assert_eq!(txs[0]["txid"], shield.as_str());
    assert_eq!(txs[0]["status"], "TRANSACTION_STATUS_MINED");
    let run = fx
        .gyges(&["-k", "main", "tx", "list", "--before", &shield, "--json"])
        .run();
    assert_eq!(run.json()["transactions"][0]["txid"], funding_txid.as_str());

    // None of this reaches the logs (TESTING.md §5).
    sweep_logs(
        &fx.network_dir().join("logs"),
        &[&current, &fresh_addr, &shield, "shop"],
    );
}

/// At least a version 1 code (21 modules, two per line, plus the quiet
/// zone) of half-block lines.
fn is_qr(s: &str) -> bool {
    let rows: Vec<&str> = s
        .lines()
        .filter(|l| !l.is_empty() && l.chars().all(|c| " █▀▄".contains(c)))
        .collect();
    rows.len() >= 15
        && rows
            .iter()
            .all(|r| r.chars().count() == rows[0].chars().count())
}
