//! `gyges pczt create | prove | sign | broadcast` through the binaries
//! against the in-process fake `zakurad` (TESTING.md §3 row 13): over
//! files, over a pipe, across a daemon restart, with a tampered file refused
//! by the Verifier (exit 6), and signed on an `--airgapped` daemon.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use gyges_regtest::{
    FakeNodeHandle, Fixture, SPEND_CONFIG, fund_transparent, poll_until, pool_spendable,
    synced_key, tamper_value, wait_spendable,
};
use transparent::address::TransparentAddress;

/// The Ironwood spendable balance, once it is non-zero.
fn wait_ironwood_spendable(fx: &Fixture) -> u64 {
    poll_until(
        Duration::from_secs(30),
        Duration::from_millis(200),
        "ironwood balance never appeared",
        || {
            let b = fx.gyges(&["-k", "main", "balance", "--json"]).run().json();
            pool_spendable(&b, "POOL_IRONWOOD").ok_or_else(|| b.to_string())
        },
    )
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
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();

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
    poll_until(
        Duration::from_secs(30),
        Duration::from_millis(200),
        "the change never became spendable",
        || {
            let s = wait_ironwood_spendable(&fx);
            if s < ironwood {
                return Ok(());
            }
            Err(format!("ironwood {s}"))
        },
    );

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

/// TESTING.md §3 row 13, air-gapped half: `pczt create` on the online
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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let mnemonic = run.json()["mnemonic"].as_str().unwrap().to_string();
    assert!(!off.key_dir("main").join("wallet.sqlite").exists());

    // The online daemon restores it with a wallet and is funded.
    let mut fx = Fixture::new("regtest");
    fx.write_config(SPEND_CONFIG);
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();
    let pw = fx.passphrase_file("online-passphrase-5678");
    let run = fx
        .gyges(&[
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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    wait_spendable(&fx);
    fund_transparent(&n, &fx, 200_000_000);
    let t_addr = gyges_chain::compact::encode_transparent_address(
        zcash_protocol::consensus::NetworkType::Regtest,
        &TransparentAddress::PublicKeyHash([0x42; 20]),
    );

    let online = fx.home().join("pczt");
    let media = off.home().join("media");
    std::fs::create_dir_all(&online).unwrap();
    std::fs::create_dir_all(&media).unwrap();
    let on_path = |name: &str| online.join(name).to_string_lossy().into_owned();
    let media_path = |name: &str| media.join(name).to_string_lossy().into_owned();

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
            "-q",
            "-o",
            &on_path("a.pczt"),
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");

    // Carried over, proven and signed offline, carried back.
    std::fs::copy(online.join("a.pczt"), media.join("a.pczt")).unwrap();
    let run = off
        .gyges(&[
            "pczt",
            "prove",
            &media_path("a.pczt"),
            "-o",
            &media_path("b.pczt"),
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let run = off
        .gyges(&[
            "pczt",
            "sign",
            &media_path("b.pczt"),
            "-o",
            &media_path("c.pczt"),
        ])
        .env("GYGES_PASSPHRASE_FILE", &off_pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    std::fs::copy(media.join("c.pczt"), online.join("c.pczt")).unwrap();

    let run = fx.gyges(&["pczt", "broadcast", &on_path("c.pczt")]).run();
    assert_eq!(run.code(), 0, "{run:?}");
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
