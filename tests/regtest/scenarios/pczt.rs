//! `gyges pczt create | prove | sign | broadcast` through the binaries
//! against the in-process fake `zakurad` (TESTING.md §3 row 13 without its
//! air-gapped half, which is the second M4 item): over files, over a pipe,
//! across a daemon restart, and with a tampered file refused by the
//! Verifier (exit 6).

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use gyges_chain::testing::{FakeNode, regtest_params};
use gyges_regtest::{Fixture, tamper_value};
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

/// The Ironwood spendable balance, once it is non-zero.
fn wait_ironwood_spendable(fx: &Fixture) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let run = fx.gyges(&["-k", "main", "balance", "--json"]).run();
        let b = run.json();
        let spendable = b["pools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["pool"] == "POOL_IRONWOOD")
            .and_then(|p| p["spendable"].as_str())
            .and_then(|s| s.parse::<u64>().ok());
        if let Some(s) = spendable {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "ironwood balance never appeared: {b}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn mempool_has(n: &Node, txid: &str) -> bool {
    n.node
        .mempool()
        .contains(&gyges_chain::parse_display_hash(txid).unwrap())
}

#[test]
fn pczt_pipeline_over_files_and_pipes_through_the_binaries() {
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

    // Fund 2 ZEC transparent and confirm it.
    let receiver = first_transparent_receiver(&fx, "main");
    n.node.mine_with_payments(&[(receiver, 200_000_000)]);
    n.node.mine(1);
    wait_spendable(&fx);
    let t_addr = gyges_chain::compact::encode_transparent_address(
        zcash_protocol::consensus::NetworkType::Regtest,
        &TransparentAddress::PublicKeyHash([0x42; 20]),
    );
    let dir = fx.home().join("pczt");
    std::fs::create_dir_all(&dir).unwrap();
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();

    // --- Files: create -o, inspect, prove -o, sign -o, broadcast ---------
    let run = fx
        .gyges(&[
            "-k",
            "main",
            "pczt",
            "create",
            "--to",
            &t_addr,
            "--amount",
            "0.5",
            "-o",
            &path("a.pczt"),
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stdout.is_empty(), "{run:?}");
    assert!(run.stderr.contains("session "), "{}", run.stderr);
    assert!(run.stderr.contains("0.50000000 ZEC"), "{}", run.stderr);
    let a = std::fs::read(dir.join("a.pczt")).unwrap();
    assert!(!a.is_empty());
    assert_eq!(
        std::fs::metadata(dir.join("a.pczt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let run = fx.gyges(&["pczt", "inspect", &path("a.pczt")]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stdout.contains("Key:     main"), "{}", run.stdout);
    assert!(run.stdout.contains("Network: regtest"), "{}", run.stdout);
    assert!(
        run.stdout
            .contains(&format!("{t_addr} (transparent) 0.50000000 ZEC")),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("Roles:   creator, constructor, io-finalizer, updater"),
        "{}",
        run.stdout
    );
    let run = fx
        .gyges(&["pczt", "inspect", "--json", &path("a.pczt")])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let j = run.json();
    assert_eq!(j["key_id"], "main");
    assert_eq!(j["session_id"].as_str().unwrap().len(), 32);
    assert!(
        j["completed_roles"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("PCZT_ROLE_UPDATER".into())),
        "{j}"
    );

    // `--key` is an assertion only: exit 6 when it names another key.
    let run = fx
        .gyges(&["-k", "other", "pczt", "inspect", &path("a.pczt")])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(
        run.stderr.contains("belongs to key 'main'"),
        "{}",
        run.stderr
    );

    // The stored proposal survives a daemon restart (the session row is in
    // the key's wallet.sqlite).
    fx.kill_daemon();
    fx.start_daemon(&["--zakura-rpc", n.node.url()]).unwrap();

    let run = fx
        .gyges(&["pczt", "prove", &path("a.pczt"), "-o", &path("b.pczt")])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stderr.contains("proven"), "{}", run.stderr);
    let run = fx
        .gyges(&["pczt", "sign", &path("b.pczt"), "-o", &path("c.pczt")])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stderr.contains("signed"), "{}", run.stderr);
    let run = fx.gyges(&["pczt", "inspect", &path("c.pczt")]).run();
    assert!(run.stdout.contains("prover, signer"), "{}", run.stdout);

    // Signing without a terminal and without a passphrase source is exit
    // 4 with the fix, like `tx send`.
    let run = fx.gyges(&["pczt", "sign", &path("b.pczt")]).run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert!(run.stderr.contains("--passphrase-fd"), "{}", run.stderr);

    let run = fx.gyges(&["pczt", "broadcast", &path("c.pczt")]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let txid = run.stdout.trim().to_string();
    assert_eq!(txid.len(), 64, "{run:?}");
    assert!(mempool_has(&n, &txid));

    // Twice is refused.
    let run = fx.gyges(&["pczt", "broadcast", &path("c.pczt")]).run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(run.stderr.contains("already broadcast"), "{}", run.stderr);

    // Mined: 1.5 ZEC minus the fee came back as Ironwood change, nothing
    // transparent is left.
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
    let ironwood = wait_ironwood_spendable(&fx);
    assert!(
        ironwood > 149_900_000 && ironwood < 150_000_000,
        "{ironwood}"
    );
    let run = fx.gyges(&["-k", "main", "balance", "--json"]).run();
    let b = run.json();
    assert!(
        b["pools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["pool"] != "POOL_TRANSPARENT" || p.get("spendable").is_none()),
        "{b}"
    );

    // --- Pipe: create | prove | sign | broadcast, Ironwood spend ---------
    wait_spendable(&fx);
    let run = fx
        .gyges(&[
            "-k", "main", "pczt", "create", "--to", &t_addr, "--amount", "0.25",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let created = run.stdout_bytes.clone();
    assert!(!created.is_empty());
    let run = fx.gyges(&["pczt", "prove"]).stdin(created.clone()).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let proven = run.stdout_bytes.clone();
    let run = fx
        .gyges(&["pczt", "sign"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(proven)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let signed = run.stdout_bytes.clone();
    let run = fx.gyges(&["pczt", "broadcast", "-"]).stdin(signed).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let txid2 = run.stdout.trim().to_string();
    assert_eq!(txid2.len(), 64, "{run:?}");
    assert!(mempool_has(&n, &txid2));

    // Mined and rescanned, so the change is spendable again.
    n.node.mine(2);
    let run = fx
        .gyges(&[
            "-k",
            "main",
            "sync",
            "wait",
            "--txid",
            &txid2,
            "--confirmations",
            "2",
            "--timeout",
            "60s",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let deadline = Instant::now() + Duration::from_secs(30);
    while wait_ironwood_spendable(&fx) >= ironwood {
        assert!(
            Instant::now() < deadline,
            "the change never became spendable"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // --- Tampered: one output value changed on the way ------------------
    let run = fx
        .gyges(&[
            "-k", "main", "pczt", "create", "--to", &t_addr, "--amount", "0.1",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let tampered = tamper_value(&run.stdout_bytes, 10_000_000, 10_000_001);
    let run = fx.gyges(&["pczt", "inspect"]).stdin(tampered.clone()).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stdout.contains("0.10000001 ZEC"), "{}", run.stdout);
    let run = fx.gyges(&["pczt", "prove"]).stdin(tampered).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let run = fx
        .gyges(&["pczt", "sign"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(run.stdout_bytes)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let mempool_before = n.node.mempool().len();
    let run = fx
        .gyges(&["pczt", "broadcast"])
        .stdin(run.stdout_bytes)
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(
        run.stderr.contains("differs from the approved proposal"),
        "{}",
        run.stderr
    );
    assert_eq!(n.node.mempool().len(), mempool_before);

    // Not a PCZT at all, and an empty stdin, are exit 6 too.
    let run = fx.gyges(&["pczt", "inspect"]).stdin("hello").run();
    assert_eq!(run.code(), 6, "{run:?}");
    let run = fx.gyges(&["pczt", "prove"]).run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(run.stderr.contains("stdin"), "{}", run.stderr);

    let _ = Path::new(&dir);
}
