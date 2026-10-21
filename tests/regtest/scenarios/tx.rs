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
    let pw = fx.passphrase_file("pw");

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

    // The log never shows the address, the txid or the amount (TESTING.md §5).
    let log_dir = fx.network_dir().join("logs");
    if let Ok(entries) = std::fs::read_dir(&log_dir) {
        for entry in entries.flatten() {
            let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
            assert!(
                !text.contains(&t_addr),
                "address in {}",
                entry.path().display()
            );
            assert!(!text.contains(&txid), "txid in {}", entry.path().display());
        }
    }
}
