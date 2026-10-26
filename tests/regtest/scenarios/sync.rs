//! `gyges sync status / wait / run` through the binaries against an
//! in-process fake `zakurad` (TESTING.md §2: the stand-in until a pinned
//! node is wired in). Covers the daemon reaching the tip for a new key, the
//! node bounds in `daemon status`, the exit-7 stall on a prune race and the
//! `--from` rewind confirmation.

use std::time::{Duration, Instant};

use gyges_regtest::{FAST_CONFIG, FakeNodeHandle, Fixture};

#[test]
fn a_new_key_syncs_to_the_tip_and_sync_wait_follows_new_blocks() {
    let n = FakeNodeHandle::start(25);
    let mut fx = Fixture::new("regtest");
    fx.write_config(FAST_CONFIG);
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();

    let run = fx.gyges(&["daemon", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains("node:         connected, tip 25"),
        "{}",
        run.stdout
    );

    // No wallet yet: status says so, wait is a typed error.
    let run = fx.gyges(&["sync", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains("no keys with a wallet"),
        "{}",
        run.stdout
    );
    let run = fx
        .gyges(&["-k", "main", "sync", "wait", "--timeout", "5s"])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");

    let pw = fx.passphrase_file("pw");
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["birthday_height"], 25);

    let run = fx
        .gyges(&[
            "-k",
            "main",
            "sync",
            "wait",
            "--until",
            "spendable",
            "--timeout",
            "30s",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stderr.contains("main: synced"), "{}", run.stderr);

    let run = fx.gyges(&["sync", "status", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let keys = run.json()["keys"].clone();
    assert_eq!(keys[0]["key_id"], "main");
    assert_eq!(keys[0]["scanned_tip"], 25);
    assert_eq!(keys[0]["chain_tip"], 25);
    assert_eq!(keys[0]["scanned"], true);
    assert_eq!(keys[0]["spendable"], true);
    assert_eq!(keys[0]["backend"], "SYNC_BACKEND_ZAKURA_RPC");
    let run = fx.gyges(&["sync", "status"]).run();
    assert!(run.stdout.contains("synced"), "{}", run.stdout);
    assert!(run.stdout.contains("scanned spendable"), "{}", run.stdout);

    // New blocks: `sync wait --json` streams one object per element and the
    // last has done = true at the new tip.
    n.node.mine(7);
    let run = fx
        .gyges(&["-k", "main", "sync", "wait", "--json", "--timeout", "30s"])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let last: serde_json::Value = serde_json::from_str(run.stdout.lines().last().unwrap()).unwrap();
    assert_eq!(last["done"], true);
    assert_eq!(last["status"]["scanned_tip"], 32);
    assert_eq!(last["schema_version"], "0.1");

    // `key list` shows the scanned tip too.
    let run = fx.gyges(&["key", "list", "--json"]).run();
    assert_eq!(run.json()["keys"][0]["scanned_tip"], 32);

    // A rewind asks for confirmation (exit 4 non-interactively), then
    // rescans with --yes.
    let run = fx
        .gyges(&["-k", "main", "sync", "run", "--from", "30"])
        .run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert!(run.stderr.contains("--yes"), "{}", run.stderr);
    let run = fx
        .gyges(&["-k", "main", "sync", "run", "--from", "30", "--yes"])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stderr.contains("synced scanned 32/32"),
        "{}",
        run.stderr
    );

    // Prune race: the node forgets bodies the key still needs.
    n.node.mine(10);
    n.node.set_prune_height(Some(40));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let run = fx
            .gyges(&["-k", "main", "sync", "wait", "--timeout", "3s"])
            .run();
        if run.code() == 7 && run.stderr.contains("pruned-past-scan-tip") {
            assert!(run.stderr.contains("tx_retention"), "{}", run.stderr);
            break;
        }
        assert!(Instant::now() < deadline, "no stall: {run:?}");
    }
    let run = fx.gyges(&["sync", "status"]).run();
    assert!(
        run.stdout.contains("stalled(pruned-past-scan-tip)"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("node pruned past key 'main'"),
        "{}",
        run.stdout
    );
}

#[test]
fn sync_wait_times_out_with_exit_7_when_the_node_is_down() {
    let mut fx = Fixture::new("regtest");
    fx.write_config(FAST_CONFIG);
    // A port nobody listens on.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    fx.start_daemon(&["--zakura-rpc", &url]).unwrap();
    let pw = fx.passphrase_file("pw");
    let run = fx
        .gyges(&["key", "restore", "--id", "r", "--stdin", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin("abandon ".repeat(23) + "art\n")
        .run();
    assert_eq!(run.code(), 0, "{run:?}");

    let run = fx
        .gyges(&["-k", "r", "sync", "wait", "--timeout", "2s"])
        .run();
    assert_eq!(run.code(), 7, "{run:?}");
    assert!(
        run.stderr.contains("still not there after 2s"),
        "{}",
        run.stderr
    );
    let run = fx.gyges(&["sync", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stdout.contains("initializing"), "{}", run.stdout);
}

/// `key restore` below the node's window through the binaries (ROADMAP.md
/// M2, fifth item): without a terminal the consent is exit 4 and asks for
/// `--yes`; with it, the notes on what the endpoint learns, the best-effort
/// warning, the backfill, and `daemon status` repeating the warning. A
/// first start also leaves a commented `config.toml`.
#[test]
fn restore_below_the_window_asks_consent_warns_and_backfills() {
    let n = FakeNodeHandle::start(50);
    n.node.set_prune_height(Some(30));
    let lwd = n
        .runtime()
        .block_on(gyges_chain::testing::FakeLightwalletd::from_node(&n.node));

    // A first start without a config writes the commented template.
    let mut plain = Fixture::new("regtest");
    plain.start_daemon(&["--airgapped"]).unwrap();
    let template = std::fs::read_to_string(plain.network_dir().join("config.toml")).unwrap();
    assert!(template.contains("[fallback_lightwalletd]"), "{template}");
    assert!(
        template.lines().all(|l| l.trim().is_empty()
            || l.trim_start().starts_with('#')
            || l.trim_start().starts_with('[')),
        "every value is commented out: {template}"
    );
    plain.kill_daemon();

    let mut fx = Fixture::new("regtest");
    fx.write_config(&format!(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n\
         [fallback_lightwalletd]\nenabled = true\ngrpc_url = \"{}\"\nuse_tor = false\n",
        lwd.url()
    ));
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();
    let pw = fx.passphrase_file("restore-passphrase-0001");
    let mnemonic = "abandon ".repeat(23) + "art";
    let restore = |extra: &[&str]| {
        let mut args = vec!["key", "restore", "--id", "r", "--stdin", "--birthday", "4"];
        args.extend_from_slice(extra);
        fx.gyges(&args)
            .env("GYGES_PASSPHRASE_FILE", &pw)
            .stdin(mnemonic.clone())
            .run()
    };

    // No terminal, no --yes: exit 4, nothing created.
    let run = restore(&[]);
    assert_eq!(run.code(), 4, "{run:?}");
    assert!(run.stderr.contains("--yes"), "{}", run.stderr);
    assert!(!fx.key_dir("r").exists());

    let run = restore(&["--yes"]);
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stderr
            .contains("note: the endpoint learns the block range"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("use_tor = false"), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("warning: transparent history below height 30"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("blocks will be backfilled"),
        "{}",
        run.stderr
    );

    let run = fx
        .gyges(&["-k", "r", "sync", "wait", "--timeout", "60s"])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let run = fx.gyges(&["daemon", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout
            .contains("transparent history below 30 is best-effort"),
        "{}",
        run.stdout
    );
    fx.kill_daemon();
    drop(lwd);
}
