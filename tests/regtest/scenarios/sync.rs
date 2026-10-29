//! `gyges sync status / wait / run` through the binaries against an
//! in-process fake `zakurad` (docs/testing.md §2; the real-node runs are in
//! `scenarios/node.rs`). Covers the daemon reaching the tip for a new key, the
//! node bounds in `daemon status`, the exit-7 stall on a prune race and the
//! `--from` rewind confirmation.

use std::time::Duration;

use gyges_regtest::{
    FAST_CONFIG, FakeNodeHandle, Fixture, fallback_section, mnemonic, wait_stalled,
};

#[test]
fn a_new_key_syncs_to_the_tip_and_sync_wait_follows_new_blocks() {
    let n = FakeNodeHandle::start(25);
    let mut fx = Fixture::new("regtest");
    fx.write_config(FAST_CONFIG);
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();

    fx.gyges(&["daemon", "status"])
        .ok()
        .stdout_has("node:         connected, tip 25");

    // No wallet yet: status says so, wait is a typed error.
    fx.gyges(&["sync", "status"])
        .ok()
        .stdout_has("no keys with a wallet");
    fx.gyges(&["-k", "main", "sync", "wait", "--timeout", "5s"])
        .code(6);

    let pw = fx.passphrase_file("pw");
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok();
    assert_eq!(run.json()["birthday_height"], 25);

    fx.gyges(&[
        "-k",
        "main",
        "sync",
        "wait",
        "--until",
        "spendable",
        "--timeout",
        "30s",
    ])
    .ok()
    .stderr_has("main: synced");

    let run = fx.gyges(&["sync", "status", "--json"]).ok();
    let keys = run.json()["keys"].clone();
    assert_eq!(keys[0]["key_id"], "main");
    assert_eq!(keys[0]["scanned_tip"], 25);
    assert_eq!(keys[0]["chain_tip"], 25);
    assert_eq!(keys[0]["scanned"], true);
    assert_eq!(keys[0]["spendable"], true);
    assert_eq!(keys[0]["backend"], "SYNC_BACKEND_ZAKURA_RPC");
    let run = fx.gyges(&["sync", "status"]).run();
    run.stdout_has("synced");
    run.stdout_has("scanned spendable");

    // New blocks: `sync wait --json` streams one object per element and the
    // last has done = true at the new tip.
    n.node.mine(7);
    let run = fx
        .gyges(&["-k", "main", "sync", "wait", "--json", "--timeout", "30s"])
        .ok();
    let last = run.json_lines().pop().unwrap();
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
        .code(4);
    run.stderr_has("--yes");
    fx.gyges(&["-k", "main", "sync", "run", "--from", "30", "--yes"])
        .ok()
        .stderr_has("synced scanned 32/32");

    // Prune race: the node forgets bodies the key still needs.
    n.node.mine(10);
    n.node.set_prune_height(Some(40));
    wait_stalled(&fx, "main", Duration::from_secs(30)).stderr_has("tx_retention");
    let run = fx.gyges(&["sync", "status"]).run();
    run.stdout_has("stalled(pruned-past-scan-tip)");
    run.stdout_has("node pruned past key 'main'");
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
    fx.gyges(&["key", "restore", "--id", "r", "--stdin", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(mnemonic() + "\n")
        .ok();

    fx.gyges(&["-k", "r", "sync", "wait", "--timeout", "2s"])
        .code(7)
        .stderr_has("still not there after 2s");
    fx.gyges(&["sync", "status"])
        .ok()
        .stdout_has("initializing");
}

/// `key restore` below the node's window through the binaries:
/// without a terminal the consent is exit 4 and asks for
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
    fx.write_config(&format!("{FAST_CONFIG}{}", fallback_section(lwd.url())));
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();
    let pw = fx.passphrase_file("restore-passphrase-0001");
    let restore = |extra: &[&str]| {
        fx.gyges(&["key", "restore", "--id", "r", "--stdin", "--birthday", "4"])
            .args(extra)
            .env("GYGES_PASSPHRASE_FILE", &pw)
            .stdin(mnemonic())
    };

    // No terminal, no --yes: exit 4, nothing created.
    restore(&[]).code(4).stderr_has("--yes");
    assert!(!fx.key_dir("r").exists());

    let run = restore(&["--yes"]).ok();
    run.stderr_has("note: the endpoint learns the block range");
    run.stderr_has("use_tor = false");
    run.stderr_has("warning: transparent history below height 30");
    run.stderr_has("blocks will be backfilled");

    fx.gyges(&["-k", "r", "sync", "wait", "--timeout", "60s"])
        .ok();
    fx.gyges(&["daemon", "status"])
        .ok()
        .stdout_has("transparent history below 30 is best-effort");
    fx.kill_daemon();
    drop(lwd);
}
