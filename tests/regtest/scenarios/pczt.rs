//! `gyges pczt create | prove | sign | broadcast` through the binaries
//! against the in-process fake `zakurad` (docs/testing.md §3 row 13): over
//! files, over a pipe, across a daemon restart, with a tampered file refused
//! by the Verifier (exit 6), and signed on an `--airgapped` daemon.

use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use gyges_regtest::{
    FakeNodeHandle, Fixture, SPEND_CONFIG, burn_t_address, fund_transparent, poll_until, spendable,
    synced_key, tamper_value, wait_balance, wait_for_txid, wait_spendable,
};

/// The Ironwood spendable balance, once it is non-zero and `ok` with it.
fn wait_ironwood_spendable(fx: &Fixture, ok: impl Fn(u64) -> bool) -> u64 {
    let b = wait_balance(fx, "main", |b| {
        let s = spendable(b, "POOL_IRONWOOD");
        s > 0 && ok(s)
    });
    spendable(&b, "POOL_IRONWOOD")
}

fn mempool_has(n: &FakeNodeHandle, txid: &str) -> bool {
    n.node
        .mempool()
        .contains(&gyges_chain::parse_display_hash(txid).unwrap())
}

#[test]
fn pczt_pipeline_over_files_and_pipes_through_the_binaries() {
    let (n, mut fx, pw) = synced_key(10, SPEND_CONFIG);

    // Fund 2 ZEC transparent and confirm it.
    fund_transparent(&n, &fx, 200_000_000);
    let t_addr = burn_t_address();
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
        .ok();
    assert!(run.stdout.is_empty(), "{run:?}");
    run.stderr_has("session ");
    run.stderr_has("0.50000000 ZEC");
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

    let run = fx.gyges(&["pczt", "inspect", &path("a.pczt")]).ok();
    run.stdout_has("Key:     main");
    run.stdout_has("Network: regtest");
    run.stdout_has(&format!("{t_addr} (transparent) 0.50000000 ZEC"));
    run.stdout_has("Roles:   creator, constructor, io-finalizer, updater");
    let run = fx
        .gyges(&["pczt", "inspect", "--json", &path("a.pczt")])
        .ok();
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
    fx.gyges(&["-k", "other", "pczt", "inspect", &path("a.pczt")])
        .code(6)
        .stderr_has("belongs to key 'main'");

    // The stored proposal survives a daemon restart (the session row is in
    // the key's wallet.sqlite).
    fx.kill_daemon();
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();

    fx.gyges(&["pczt", "prove", &path("a.pczt"), "-o", &path("b.pczt")])
        .ok()
        .stderr_has("proven");
    fx.gyges(&["pczt", "sign", &path("b.pczt"), "-o", &path("c.pczt")])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok()
        .stderr_has("signed");
    fx.gyges(&["pczt", "inspect", &path("c.pczt")])
        .run()
        .stdout_has("prover, signer");

    // Signing without a terminal and without a passphrase source is exit
    // 4 with the fix, like `tx send`.
    fx.gyges(&["pczt", "sign", &path("b.pczt")])
        .code(4)
        .stderr_has("--passphrase-fd");

    let run = fx.gyges(&["pczt", "broadcast", &path("c.pczt")]).ok();
    let txid = run.stdout.trim().to_string();
    assert_eq!(txid.len(), 64, "{run:?}");
    assert!(mempool_has(&n, &txid));

    // Twice is refused.
    fx.gyges(&["pczt", "broadcast", &path("c.pczt")])
        .code(6)
        .stderr_has("already broadcast");

    // Mined: 1.5 ZEC minus the fee came back as Ironwood change, nothing
    // transparent is left.
    n.node.mine(2);
    wait_for_txid(&fx, "main", &txid, 2);
    let ironwood = wait_ironwood_spendable(&fx, |_| true);
    assert!(
        ironwood > 149_900_000 && ironwood < 150_000_000,
        "{ironwood}"
    );
    let b = fx.gyges(&["-k", "main", "balance", "--json"]).run().json();
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
        .ok();
    let created = run.stdout_bytes.clone();
    assert!(!created.is_empty());
    let run = fx.gyges(&["pczt", "prove"]).stdin(created.clone()).ok();
    let proven = run.stdout_bytes.clone();
    let run = fx
        .gyges(&["pczt", "sign"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(proven)
        .ok();
    let signed = run.stdout_bytes.clone();
    let run = fx.gyges(&["pczt", "broadcast", "-"]).stdin(signed).ok();
    let txid2 = run.stdout.trim().to_string();
    assert_eq!(txid2.len(), 64, "{run:?}");
    assert!(mempool_has(&n, &txid2));

    // Mined and rescanned, so the change is spendable again.
    n.node.mine(2);
    wait_for_txid(&fx, "main", &txid2, 2);
    wait_ironwood_spendable(&fx, |s| s < ironwood);

    // --- Tampered: one output value changed on the way ------------------
    let run = fx
        .gyges(&[
            "-k", "main", "pczt", "create", "--to", &t_addr, "--amount", "0.1",
        ])
        .ok();
    let tampered = tamper_value(&run.stdout_bytes, 10_000_000, 10_000_001);
    fx.gyges(&["pczt", "inspect"])
        .stdin(tampered.clone())
        .ok()
        .stdout_has("0.10000001 ZEC");
    let run = fx.gyges(&["pczt", "prove"]).stdin(tampered).ok();
    let run = fx
        .gyges(&["pczt", "sign"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(run.stdout_bytes)
        .ok();
    let mempool_before = n.node.mempool().len();
    fx.gyges(&["pczt", "broadcast"])
        .stdin(run.stdout_bytes)
        .code(6)
        .stderr_has("differs from the approved proposal");
    assert_eq!(n.node.mempool().len(), mempool_before);

    // Not a PCZT at all, and an empty stdin, are exit 6 too.
    fx.gyges(&["pczt", "inspect"]).stdin("hello").code(6);
    fx.gyges(&["pczt", "prove"]).code(6).stderr_has("stdin");
}

/// docs/testing.md §3 row 13, air-gapped half: `pczt create` on the online
/// daemon, the file carried to an `--airgapped` daemon whose `signer-only`
/// key holds the same seed and no wallet, `pczt prove` and `sign` there,
/// and `pczt broadcast` back online. The funds are transparent, so the
/// offline signer derives each input's key from the BIP 44 path in the file.
#[test]
fn airgapped_signer_only_daemon_signs_a_transparent_funded_file() {
    let n = FakeNodeHandle::start(10);

    // The offline box makes the seed.
    let mut off = Fixture::new("regtest");
    off.write_config(SPEND_CONFIG);
    off.start_daemon(&["--airgapped"]).unwrap();
    let off_pw = off.passphrase_file("offline-passphrase-1234");
    let run = off
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &off_pw)
        .ok();
    let mnemonic = run.json()["mnemonic"].as_str().unwrap().to_string();
    assert!(!off.key_dir("main").join("wallet.sqlite").exists());

    // The online daemon restores it with a wallet and is funded.
    let mut fx = Fixture::new("regtest");
    fx.write_config(SPEND_CONFIG);
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();
    let pw = fx.passphrase_file("online-passphrase-5678");
    fx.gyges(&[
        "key",
        "restore",
        "--id",
        "main",
        "--stdin",
        "--birthday",
        "5",
        "-q",
        "--json",
    ])
    .env("GYGES_PASSPHRASE_FILE", &pw)
    .stdin(mnemonic)
    .ok();
    wait_spendable(&fx);
    fund_transparent(&n, &fx, 200_000_000);
    let t_addr = burn_t_address();

    let online = fx.home().join("pczt");
    let media = off.home().join("media");
    std::fs::create_dir_all(&online).unwrap();
    std::fs::create_dir_all(&media).unwrap();
    let on_path = |name: &str| online.join(name).to_string_lossy().into_owned();
    let media_path = |name: &str| media.join(name).to_string_lossy().into_owned();

    fx.gyges(&[
        "-k",
        "main",
        "pczt",
        "create",
        "--to",
        &t_addr,
        "--amount",
        "0.5",
        "-q",
        "-o",
        &on_path("a.pczt"),
    ])
    .ok();

    // Carried over, proven and signed offline, carried back.
    std::fs::copy(online.join("a.pczt"), media.join("a.pczt")).unwrap();
    off.gyges(&[
        "pczt",
        "prove",
        &media_path("a.pczt"),
        "-o",
        &media_path("b.pczt"),
    ])
    .ok();
    off.gyges(&[
        "pczt",
        "sign",
        &media_path("b.pczt"),
        "-o",
        &media_path("c.pczt"),
    ])
    .env("GYGES_PASSPHRASE_FILE", &off_pw)
    .ok();
    std::fs::copy(media.join("c.pczt"), online.join("c.pczt")).unwrap();

    let run = fx.gyges(&["pczt", "broadcast", &on_path("c.pczt")]).ok();
    let txid = run.stdout.trim().to_string();
    assert_eq!(txid.len(), 64, "{run:?}");
    poll_until(
        Duration::from_secs(10),
        Duration::from_millis(100),
        &format!("{txid} never reached the node"),
        || {
            if mempool_has(&n, &txid) {
                return Ok(());
            }
            Err(format!("mempool {:?}", n.node.mempool()))
        },
    );
    off.kill_daemon();
    fx.kill_daemon();
}
