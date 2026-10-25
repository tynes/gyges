//! `gyges balance`, `gyges tx send` and `gyges tx shield` through the
//! binaries against the in-process fake `zakurad` (TESTING.md §3 rows 1–3
//! and 14 in miniature; the real-node versions wait for the harness item).
//!
//! Covers: the zero balance of a fresh key, the funded transparent balance,
//! `--dry-run --json` (the `Proposal` message with `schema_version`), the
//! exit-4 refusal of a locked key with no terminal and no passphrase source
//! (JSON carries `reason` and `session_id`), the exit-5 insufficient funds,
//! the exit-6 memo-to-transparent refusal, a non-interactive shield with
//! `GYGES_PASSPHRASE_FILE`, and the Orchard balance after mining.

use std::os::unix::fs::PermissionsExt as _;
use std::time::{Duration, Instant};

use gyges_chain::testing::{FakeNode, regtest_params};
use gyges_regtest::Fixture;
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::WalletRead as _;

struct Node {
    _rt: tokio::runtime::Runtime,
    node: FakeNode,
}

fn fake_node(blocks: u32) -> Node {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(FakeNode::start(regtest_params()));
    node.mine(blocks);
    Node { _rt: rt, node }
}

/// The key's first external transparent receiver, read from its wallet
/// (the daemon holds no lock on the file; the read is one SQLite query).
fn first_transparent_receiver(fx: &Fixture, key_id: &str) -> TransparentAddress {
    let params = gyges_core::Network::Regtest.consensus_params();
    let path = fx.key_dir(key_id).join("wallet.sqlite");
    let db = zcash_client_sqlite::WalletDb::for_path(
        &path,
        params,
        zcash_client_sqlite::util::SystemClock,
        rand::rand_core::UnwrapErr(rand::rngs::SysRng),
    )
    .unwrap()
    .with_transparent_ledger_mode(
        zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode::Public,
    );
    let account = db.get_account_ids().unwrap()[0];
    *db.get_transparent_receivers(account, false, false)
        .unwrap()
        .keys()
        .next()
        .expect("a transparent receiver")
}

fn wait_spendable(fx: &Fixture) {
    let run = fx
        .gyges(&["-k", "main", "sync", "wait", "--timeout", "60s"])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
}

#[test]
fn balance_send_and_shield_through_the_binaries() {
    let n = fake_node(10);
    let mut fx = Fixture::new("regtest");
    fx.write_config(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n[policy]\nmin_confirmations = 1\n",
    );
    fx.start_daemon(&["--zakura-rpc", n.node.url()]).unwrap();
    const PASSPHRASE: &str = "correct-horse-battery-staple-7731";
    let pw = fx.passphrase_file(PASSPHRASE);

    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    wait_spendable(&fx);

    // Fresh key: zero everywhere, in both renderings.
    let run = fx.gyges(&["-k", "main", "balance", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let b = run.json();
    assert_eq!(b["schema_version"], "0.1");
    assert!(b.get("total_spendable").is_none(), "zero is omitted: {b}");
    assert_eq!(b["min_confirmations"], 1);
    let run = fx.gyges(&["-k", "main", "balance"]).run();
    assert!(
        run.stdout.contains("orchard") && run.stdout.contains("0.00000000"),
        "{}",
        run.stdout
    );

    // Insufficient funds is exit 5, before any passphrase is asked.
    let t_addr = gyges_chain::compact::encode_transparent_address(
        zcash_protocol::consensus::NetworkType::Regtest,
        &TransparentAddress::PublicKeyHash([0x42; 20]),
    );
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &t_addr, "--amount", "0.5", "--yes",
        ])
        .run();
    assert_eq!(run.code(), 5, "{run:?}");
    assert!(run.stderr.contains("insufficient funds"), "{}", run.stderr);

    // Fund 1 ZEC transparent and confirm it.
    let receiver = first_transparent_receiver(&fx, "main");
    n.node.mine_with_payments(&[(receiver, 100_000_000)]);
    n.node.mine(1);
    wait_spendable(&fx);
    let run = fx.gyges(&["-k", "main", "balance", "--json"]).run();
    assert_eq!(run.json()["total_spendable"], "100000000", "{run:?}");

    // A memo to a transparent recipient is exit 6, never dropped.
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &t_addr, "--amount", "0.5", "--memo", "hi", "--yes",
        ])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(run.stderr.contains("memo"), "{}", run.stderr);

    // `--dry-run --json` prints the proposal only.
    let run = fx
        .gyges(&[
            "-k",
            "main",
            "tx",
            "send",
            "--to",
            &t_addr,
            "--amount",
            "0.5",
            "--dry-run",
            "--json",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let lines: Vec<serde_json::Value> = run
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
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
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &t_addr, "--amount", "0.5",
        ])
        .run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert!(run.stderr.contains("--yes"), "{}", run.stderr);

    // Locked key, no terminal, no passphrase source: exit 4 with the fix,
    // the session aborted, JSON carrying reason and session_id.
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &t_addr, "--amount", "0.5", "--yes", "--json",
        ])
        .run();
    assert_eq!(run.code(), 4, "{run:?}");
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
    let run = fx
        .gyges(&["-k", "main", "tx", "sessions", "--include-finished"])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stdout.contains("aborted"), "{}", run.stdout);

    // Shield everything with the passphrase from a file; the txid is on
    // stdout and the node has it.
    let run = fx
        .gyges(&["-k", "main", "tx", "shield", "--yes"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let txid = run.stdout.trim().to_string();
    assert_eq!(txid.len(), 64, "{run:?}");
    assert!(run.stderr.contains("broadcast"), "{}", run.stderr);
    assert_eq!(
        n.node.mempool(),
        vec![gyges_chain::parse_display_hash(&txid).unwrap()]
    );

    // Mined: the Orchard balance is the input minus the fee the proposal
    // showed, and `sync wait --txid` sees the confirmations.
    n.node.mine(2);
    let run = fx
        .gyges(&[
            "-k",
            "main",
            "sync",
            "wait",
            "--txid",
            &txid,
            "--confirmations",
            "2",
            "--timeout",
            "60s",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let run = fx.gyges(&["-k", "main", "balance", "--json"]).run();
        let b = run.json();
        let orchard = b["pools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["pool"] == "POOL_IRONWOOD")
            .cloned()
            .unwrap_or_default();
        if orchard["spendable"].as_str().is_some() {
            let spendable: u64 = orchard["spendable"].as_str().unwrap().parse().unwrap();
            assert!(spendable > 99_000_000 && spendable < 100_000_000, "{b}");
            assert!(
                b["pools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|p| p["pool"] != "POOL_ORCHARD" || p.get("spendable").is_none())
            );
            assert!(
                b["pools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|p| p["pool"] != "POOL_TRANSPARENT" || p.get("spendable").is_none())
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "orchard balance never appeared: {b}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let run = fx.gyges(&["-k", "main", "balance"]).run();
    assert!(run.stdout.contains("ironwood"), "{}", run.stdout);

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
    let mut main_log = String::new();
    let mut audit_log = None;
    for entry in std::fs::read_dir(&log_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(entry.path()).unwrap();
        assert_eq!(
            std::fs::metadata(entry.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "{name}"
        );
        for secret in secrets {
            assert!(!text.contains(secret), "{secret:?} in {name}");
        }
        if name == "audit.log" {
            audit_log = Some(text);
        } else {
            assert!(
                name.starts_with("gygesd.") && name.ends_with(".log"),
                "{name}"
            );
            main_log.push_str(&text);
        }
    }
    assert!(main_log.contains("transaction broadcast"), "{main_log}");

    // `audit.log`: one JSON object per line, key id and event only, and the
    // events of this scenario in order.
    let audit_log = audit_log.expect("audit.log written");
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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let streamed: Vec<serde_json::Value> = run
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
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
    let run = fx.gyges(&["daemon", "logs", "--lines", "500"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains("transaction broadcast"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("gygesd listening"), "{}", run.stdout);
    for secret in secrets {
        assert!(!run.stdout.contains(secret), "{secret:?} streamed");
    }
}

/// Poll `tx sessions --include-finished --json` until the ZIP 320 row for
/// `step1` is in `state` (a `TEX_STATE_*` name).
fn wait_tex_state(fx: &Fixture, step1: &str, state: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = serde_json::Value::Null;
    loop {
        let run = fx
            .gyges(&[
                "-k",
                "main",
                "tx",
                "sessions",
                "--include-finished",
                "--json",
            ])
            .run();
        assert_eq!(run.code(), 0, "{run:?}");
        let v = run.json();
        if let Some(row) = v["tex_transfers"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["step1_txid"] == step1))
        {
            if row["state"] == state {
                return row.clone();
            }
            last = row.clone();
        }
        assert!(
            Instant::now() < deadline,
            "row never reached {state}; last {last}"
        );
        std::thread::sleep(Duration::from_millis(200));
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
    let n = fake_node(10);
    let mut fx = Fixture::new("regtest");
    fx.write_config(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n\
         [policy]\nmin_confirmations = 1\n[tex]\nrebroadcast_interval = \"1s\"\n",
    );
    let node_url = n.node.url().to_string();
    fx.start_daemon(&["--zakura-rpc", &node_url]).unwrap();
    const PASSPHRASE: &str = "correct-horse-battery-staple-7731";
    let pw = fx.passphrase_file(PASSPHRASE);
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    wait_spendable(&fx);
    let receiver = first_transparent_receiver(&fx, "main");
    n.node.mine_with_payments(&[(receiver, 200_000_000)]);
    n.node.mine(1);
    wait_spendable(&fx);
    let run = fx
        .gyges(&["-k", "main", "tx", "shield", "--yes"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    n.node.mine(2);
    wait_spendable(&fx);

    let params = gyges_core::Network::Regtest.consensus_params();
    let tex_addr = zcash_keys::address::Address::Tex([0x42; 20]).encode(&params);

    // The dry run shows both steps and both fees.
    let run = fx
        .gyges(&[
            "-k",
            "main",
            "tx",
            "send",
            "--to",
            &tex_addr,
            "--amount",
            "0.5",
            "--dry-run",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stderr.contains("Step 1 of 2") && run.stderr.contains("Step 2 of 2"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("ephemeral"), "{}", run.stderr);
    assert!(run.stderr.contains(&tex_addr), "{}", run.stderr);
    let run = fx
        .gyges(&[
            "-k",
            "main",
            "tx",
            "send",
            "--to",
            &tex_addr,
            "--amount",
            "0.5",
            "--dry-run",
            "--json",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let proposed = &run.json()["proposed"];
    assert_eq!(proposed["steps"].as_array().unwrap().len(), 2, "{proposed}");
    assert_eq!(proposed["steps"][1]["transparent_only"], true, "{proposed}");

    // The node refuses step 2 until step 1 is mined: the send ends with
    // `tex pending` and one txid on stdout.
    n.node
        .set_reject_transparent_only(Some("bad-txns-inputs-missingorspent".into()));
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &tex_addr, "--amount", "0.5", "--yes",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let txids: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(txids.len(), 1, "only step 1 reached the node: {run:?}");
    let s1 = txids[0].to_string();
    assert_eq!(s1.len(), 64);
    let pending = run
        .stderr
        .lines()
        .find(|l| l.starts_with("tex pending (step 2 of 2)"))
        .unwrap_or_else(|| panic!("no tex pending line: {}", run.stderr));
    let s2 = pending.rsplit(' ').next().unwrap().to_string();
    assert_eq!(s2.len(), 64, "{pending}");
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
    let run = fx.gyges(&["-k", "main", "tx", "sessions"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains(&s1) && run.stdout.contains("step1_broadcast"),
        "{}",
        run.stdout
    );
    // Too late to abort (exit 6), and the argument shapes are checked.
    let run = fx.gyges(&["-k", "main", "tx", "abort", &s1]).run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(run.stderr.contains("built"), "{}", run.stderr);
    let run = fx.gyges(&["-k", "main", "tx", "resume", "nonsense"]).run();
    assert_eq!(run.code(), 6, "{run:?}");

    // Crash with the row pending; mine step 1 while the daemon is down.
    fx.kill_daemon();
    n.node.mine(1);
    n.node.set_reject_transparent_only(None);
    fx.start_daemon(&["--zakura-rpc", &node_url]).unwrap();
    // The restarted queue rebroadcasts step 2 from its stored bytes: same
    // txid, no passphrase asked.
    let want = gyges_chain::parse_display_hash(&s2).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !n.node.mempool().contains(&want) {
        assert!(Instant::now() < deadline, "step 2 never rebroadcast");
        std::thread::sleep(Duration::from_millis(200));
    }
    n.node.mine(1);
    let row = wait_tex_state(&fx, &s1, "TEX_STATE_STEP2_MINED");
    assert_eq!(row["step2_txid"], s2, "{row}");
    assert_eq!(row["amount"], "50000000", "{row}");
    assert_eq!(row["recipient"], tex_addr, "{row}");
    let run = fx.gyges(&["-k", "main", "tx", "resume", &s1]).run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(run.stderr.contains("nothing to resume"), "{}", run.stderr);
    wait_spendable(&fx);
    let run = fx.gyges(&["-k", "main", "balance", "--json"]).run();
    let b = run.json();
    let ironwood: u64 = b["pools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["pool"] == "POOL_IRONWOOD")
        .and_then(|p| p["spendable"].as_str())
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        ironwood < 150_000_000 && ironwood > 149_900_000,
        "amount and both fees left: {b}"
    );

    // Nothing identifying in the logs, across both daemon runs.
    let log_dir = fx.network_dir().join("logs");
    for entry in std::fs::read_dir(&log_dir).unwrap().flatten() {
        let text = std::fs::read_to_string(entry.path()).unwrap();
        for secret in [
            tex_addr.as_str(),
            s1.as_str(),
            s2.as_str(),
            "50000000",
            PASSPHRASE,
        ] {
            assert!(
                !text.contains(secret),
                "{secret:?} in {}",
                entry.file_name().to_string_lossy()
            );
        }
    }
}

/// Wait until `tx status TXID --json` reports `status`.
fn wait_tx_status(fx: &Fixture, txid: &str, status: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let run = fx
            .gyges(&["-k", "main", "tx", "status", txid, "--json"])
            .run();
        assert_eq!(run.code(), 0, "{run:?}");
        let v = run.json();
        if v["status"] == status {
            return v;
        }
        assert!(Instant::now() < deadline, "never {status}: {v}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `gyges address current/new/qr/inspect`, `gyges notes`, `gyges tx list`
/// and `gyges tx status` through the binaries against the fake node, in
/// both renderings: the M1 commands a user needs to receive, look at what
/// arrived and follow a transaction, plus the not-implemented `--qr` /
/// `--pir` exits and the exit-6 inspection of a bad address.
#[test]
fn addresses_notes_and_history_through_the_binaries() {
    let n = fake_node(10);
    let mut fx = Fixture::new("regtest");
    fx.write_config(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n[policy]\nmin_confirmations = 1\n",
    );
    fx.start_daemon(&["--zakura-rpc", n.node.url()]).unwrap();
    const PASSPHRASE: &str = "correct-horse-battery-staple-7731";
    let pw = fx.passphrase_file(PASSPHRASE);
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    wait_spendable(&fx);

    // The address alone on stdout, details on stderr; JSON is AddressInfo.
    let run = fx.gyges(&["-k", "main", "address", "current"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let current = run.stdout.trim().to_string();
    assert!(current.starts_with("uregtest1"), "{run:?}");
    assert_eq!(run.stdout.lines().count(), 1, "{run:?}");
    assert!(
        run.stderr.contains("receivers:") && run.stderr.contains("transparent"),
        "{}",
        run.stderr
    );
    let run = fx
        .gyges(&["-k", "main", "address", "current", "--json"])
        .run();
    let v = run.json();
    assert_eq!(v["address"], current.as_str());
    assert_eq!(v["schema_version"], "0.1");
    assert_eq!(v["receivers"][0]["pool"], "POOL_ORCHARD", "{v}");

    for args in [
        &["-k", "main", "address", "current", "--qr"][..],
        &["-k", "main", "address", "new", "--qr"],
        &["-k", "main", "address", "qr"],
        &["address", "qr", "u1x"],
    ] {
        let run = fx.gyges(args).run();
        assert_eq!(run.code(), 1, "{args:?}: {run:?}");
        assert!(run.stderr.contains("not implemented"), "{}", run.stderr);
    }

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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let fresh = run.json();
    let fresh_addr = fresh["address"].as_str().unwrap().to_string();
    assert_ne!(fresh_addr, current);
    assert_eq!(fresh["label"], "shop");
    assert_eq!(fresh["receivers"].as_array().unwrap().len(), 1, "{fresh}");
    let run = fx.gyges(&["-k", "main", "address", "current"]).run();
    assert_eq!(run.stdout.trim(), fresh_addr);
    assert!(run.stderr.contains("shop"), "{}", run.stderr);
    let run = fx
        .gyges(&["-k", "main", "address", "new", "--receivers", "transparent"])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");

    let run = fx.gyges(&["address", "inspect", &current]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains("valid:      yes") && run.stdout.contains("unified"),
        "{}",
        run.stdout
    );
    let run = fx.gyges(&["address", "inspect", &current, "--json"]).run();
    let v = run.json();
    assert_eq!(v["valid"], true);
    assert_eq!(v["network"], "NETWORK_REGTEST");
    assert_eq!(v["kind"], "ADDRESS_KIND_UNIFIED");
    let run = fx.gyges(&["address", "inspect", "nonsense"]).run();
    assert_eq!(run.code(), 6, "{run:?}");
    let run = fx
        .gyges(&["address", "inspect", "nonsense", "--json"])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert_eq!(
        run.json()["error"]["reason"],
        "ERROR_REASON_INVALID_ARGUMENT"
    );

    // Empty history.
    let run = fx.gyges(&["-k", "main", "notes"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.stdout, "no notes\n");
    let run = fx.gyges(&["-k", "main", "tx", "list"]).run();
    assert_eq!(run.stdout, "no transactions\n");

    // Fund, then shield.
    let receiver = first_transparent_receiver(&fx, "main");
    n.node.mine_with_payments(&[(receiver, 100_000_000)]);
    n.node.mine(1);
    wait_spendable(&fx);
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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let shield = run.stdout.trim().to_string();
    let v = wait_tx_status(&fx, &shield, "TRANSACTION_STATUS_PENDING");
    assert_eq!(v["source"], "STATUS_SOURCE_NODE");
    n.node.mine(2);
    let v = wait_tx_status(&fx, &shield, "TRANSACTION_STATUS_MINED");
    assert_eq!(v["confirmations"], 2, "{v}");
    let run = fx.gyges(&["-k", "main", "tx", "status", &shield]).run();
    assert!(
        run.stdout.contains("mined at height") && run.stdout.contains("2 confirmations"),
        "{}",
        run.stdout
    );
    let run = fx
        .gyges(&["-k", "main", "tx", "status", &shield, "--pir"])
        .run();
    assert_eq!(run.code(), 1, "{run:?}");
    assert!(run.stderr.contains("not implemented"), "{}", run.stderr);
    let run = fx
        .gyges(&["-k", "main", "tx", "status", &"00".repeat(32)])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");

    // The scan catches up with the shield: spent UTXO, Ironwood note.
    wait_spendable(&fx);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let run = fx
            .gyges(&["-k", "main", "notes", "--spent", "--json"])
            .run();
        let v = run.json();
        if v["notes"].as_array().is_some_and(|a| !a.is_empty()) {
            assert_eq!(v["notes"][0]["spent_txid"], shield.as_str(), "{v}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the UTXO never showed as spent: {v}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let run = fx
        .gyges(&["-k", "main", "notes", "--pool", "ironwood"])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains("ironwood") && run.stdout.contains("unspent,witness-ready"),
        "{}",
        run.stdout
    );

    let run = fx.gyges(&["-k", "main", "tx", "list"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains(&shield) && run.stdout.contains(&funding_txid),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("mined"), "{}", run.stdout);
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
    let log_dir = fx.network_dir().join("logs");
    for entry in std::fs::read_dir(&log_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(entry.path()).unwrap();
        for secret in [
            current.as_str(),
            fresh_addr.as_str(),
            shield.as_str(),
            "shop",
        ] {
            assert!(!text.contains(secret), "{secret:?} in {name}");
        }
    }
}
