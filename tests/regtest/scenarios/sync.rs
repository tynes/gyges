//! `gyges sync status / wait / run` through the binaries against an
//! in-process fake `zakurad` (TESTING.md §2: the stand-in until a pinned
//! node is wired in). Covers the daemon reaching the tip for a new key, the
//! node bounds in `daemon status`, the exit-7 stall on a prune race and the
//! `--from` rewind confirmation.

use std::time::{Duration, Instant};

use gyges_chain::testing::{FakeNode, regtest_params};
use gyges_regtest::Fixture;

/// The fake node lives on a runtime whose worker threads keep serving while
/// the test thread drives the binaries.
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

fn fast_config(fx: &Fixture) {
    fx.write_config("[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n");
}

#[test]
fn a_new_key_syncs_to_the_tip_and_sync_wait_follows_new_blocks() {
    let n = fake_node(25);
    let mut fx = Fixture::new("regtest");
    fast_config(&fx);
    fx.start_daemon(&["--zakura-rpc", n.node.url()]).unwrap();

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
    fast_config(&fx);
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
