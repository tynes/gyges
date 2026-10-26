//! The backfill scenarios against a real pruned `zakurad`, an archive node
//! and `zaino` (TESTING.md §3 rows 5–7, ROADMAP.md M2 sixth item). Each
//! skips itself without both `ZAKURAD_BIN` and `ZAINOD_BIN` off Linux.

use std::time::{Duration, Instant};

use gyges_regtest::{FINALITY_DEPTH, Fallback, Fixture, MIN_TX_RETENTION, NodeOpts, PASSPHRASE};
use serde_json::json;

mod common;
use common::*;

/// Enough blocks past the current tip for the pruned node to drop the
/// block after it: pruning runs [`FINALITY_DEPTH`] behind the window.
const PAST_THE_WINDOW: u32 = FINALITY_DEPTH + MIN_TX_RETENTION + 99;

/// [`daemon_config`]'s settings, without the fallback endpoint.
const BASE_CONFIG: &str = "[vault]\nscrypt_work_factor = 10\n\
     [zakura_rpc]\npoll_interval_secs = 1\nmin_retention_blocks = 1000\n\
     [policy]\nmin_confirmations = 1\n";

/// `gyges daemon stop`, then wait for the process.
fn stop_daemon(fx: &mut Fixture) {
    let run = fx.gyges(&["daemon", "stop"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    fx.wait_daemon(Duration::from_secs(60)).unwrap();
}

fn daemon_status(fx: &Fixture) -> String {
    let run = fx.gyges(&["daemon", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    run.stdout
}

/// The harness itself: past the pruned node's window, zaino still serves
/// the blocks the node pruned, and it follows the archive node across a
/// restart (which rotates the node's cookie).
#[test]
fn zaino_serves_what_the_pruned_node_dropped() {
    let Some(mut fb) = Fallback::start_or_skip(NodeOpts::default()) else {
        return;
    };
    fb.mine(FINALITY_DEPTH + MIN_TX_RETENTION + 99);
    let tip = fb.node.tip_height();
    assert_eq!(fb.archive.tip_height(), tip);
    assert_eq!(fb.zaino.tip().unwrap(), tip);

    let info = fb.node.rpc("getblockchaininfo", json!([])).unwrap();
    assert_eq!(info["pruned"], true, "{info}");
    let prune_height = fb.node.prune_height();
    assert_eq!(
        prune_height,
        tip - FINALITY_DEPTH - (MIN_TX_RETENTION - 1),
        "{info}"
    );
    let archive = fb.archive.rpc("getblockchaininfo", json!([])).unwrap();
    assert_eq!(archive["pruned"], false, "{archive}");

    // Below the window: the pruned node still answers the hash, zaino the
    // block, and they agree.
    for h in [1, prune_height - 1, tip] {
        assert_eq!(
            fb.zaino.block_hash(h).unwrap(),
            fb.node.block_hash(h),
            "block {h}"
        );
    }
    let mined = fb.node.mined_height(&first_coinbase(&fb));
    assert_eq!(
        mined, None,
        "the pruned node no longer has block 1's coinbase"
    );

    fb.restart_archive().unwrap();
    fb.mine(3);
    assert_eq!(fb.zaino.tip().unwrap(), tip + 3);
}

/// The txid of block 1's coinbase, from the archive node.
fn first_coinbase(fb: &Fallback) -> String {
    let block = fb
        .archive
        .rpc("getblock", json!(["1", 1]))
        .expect("getblock 1");
    block["tx"][0].as_str().unwrap().to_string()
}

/// TESTING.md §3 rows 6, 5 and 7 on one chain.
///
/// A funded key pays a second key; the daemon stops before that payment is
/// mined. Then the chain grows past the pruned node's window, so the
/// payment's block is gone from the node, and neither key's scanned tip is
/// retained.
/// * Row 6: without a fallback endpoint, both keys stall with
///   `pruned-past-scan-tip` and `sync wait` exits 7.
/// * Row 5: with zaino configured (`use_tor = false`), both keys backfill
///   from it, the handoff validates, the endpoint shows `verified`, and the
///   second key holds the payment, which only zaino could have served.
/// * Row 7: a second daemon restores the funded key's mnemonic at birthday
///   1, below the window. It backfills from zaino and ends with the same
///   balance as the original key.
///
/// Subtree roots are compared at the handoff (check 3), but no subtree
/// completes on a chain this size, so both sides are empty.
#[test]
fn prune_race_stalls_without_a_fallback_then_backfills_through_zaino() {
    let wallet_taddr = test_key_transparent_address();
    let Some(mut fb) = Fallback::start_or_skip(NodeOpts {
        miner_address: wallet_taddr.clone(),
        ..NodeOpts::default()
    }) else {
        return;
    };
    // Two coinbases to the wallet, matured by a hundred more to nobody.
    fb.mine(2);
    fb.node.restart(NodeOpts::default()).unwrap();
    fb.mine(100);
    let funded = fb.node.coinbase_value(1) + fb.node.coinbase_value(2);

    let mut fx = Fixture::new("regtest");
    fx.write_config(BASE_CONFIG);
    start_daemon(&mut fx, &fb.node);
    let pw = fx.passphrase_file(PASSPHRASE);
    let run = fx
        .gyges(&["key", "restore", "--id", "main", "--stdin", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(mnemonic())
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    sync_wait(&fx, "main", &["--until", "spendable"]);
    wait_balance(&fx, "main", |b| spendable(b, "POOL_TRANSPARENT") == funded);

    let run = fx
        .gyges(&["-k", "main", "tx", "shield", "--yes"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}\n{}", fb.node.log_tail());
    let shield_txid = run.stdout.trim().to_string();
    fb.mine(1);
    wait_for_txid(&fx, "main", &shield_txid);
    wait_balance(&fx, "main", |b| spendable(b, "POOL_IRONWOOD") > 0);

    let run = fx
        .gyges(&["key", "init", "--id", "bob", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let run = fx.gyges(&["-k", "bob", "address", "current"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let bob_ua = run.stdout.trim().to_string();
    sync_wait(&fx, "bob", &["--until", "spendable"]);
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &bob_ua, "--amount", "1", "--yes",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}\n{}", fb.node.log_tail());
    let pay_txid = run.stdout.trim().to_string();

    // The daemon stops with the payment in the mempool; the chain moves on.
    stop_daemon(&mut fx);
    let stopped_at = fb.node.tip_height();
    fb.mine(PAST_THE_WINDOW);
    assert_eq!(fb.archive.mined_height(&pay_txid), Some(stopped_at + 1));
    let retained_from = fb.node.prune_height();
    assert!(
        retained_from > stopped_at + 1,
        "pruned from {retained_from}"
    );
    assert_eq!(
        fb.node.mined_height(&pay_txid),
        None,
        "the pruned node no longer has the payment"
    );

    // Row 6: no fallback, so both keys stall.
    start_daemon(&mut fx, &fb.node);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let run = fx
            .gyges(&["-k", "main", "sync", "wait", "--timeout", "3s"])
            .run();
        if run.code() == 7 && run.stderr.contains("pruned-past-scan-tip") {
            break;
        }
        assert!(Instant::now() < deadline, "no stall: {run:?}");
    }
    let run = fx.gyges(&["sync", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    for key in ["main", "bob"] {
        assert!(
            run.stdout
                .contains(&format!("node pruned past key '{key}'")),
            "{}",
            run.stdout
        );
    }
    assert!(daemon_status(&fx).contains("fallback:     disabled"));
    stop_daemon(&mut fx);

    // Row 5: the same daemon with zaino as its fallback endpoint.
    fx.write_config(&format!("{BASE_CONFIG}{}", fb.config_section()));
    start_daemon(&mut fx, &fb.node);
    sync_wait_within(&fx, "main", "600s", &["--until", "spendable"]);
    sync_wait_within(&fx, "bob", "600s", &["--until", "spendable"]);
    let bob = wait_balance(&fx, "bob", |b| spendable(b, "POOL_IRONWOOD") == 100_000_000);
    assert_eq!(bob["total_spendable"], "100000000", "{bob}");
    let tip = fb.node.tip_height();
    let run = fx.gyges(&["sync", "status", "--json"]).run();
    for key in run.json()["keys"].as_array().unwrap() {
        assert_eq!(key["scanned_tip"], tip, "{key}");
        assert_eq!(key["detail"], "synced", "{key}");
        assert_eq!(key["backend"], "SYNC_BACKEND_ZAKURA_RPC", "{key}");
    }
    let status = daemon_status(&fx);
    assert!(status.contains("trust: verified"), "{status}");
    let main = wait_balance(&fx, "main", |b| {
        spendable(b, "POOL_IRONWOOD") > 0 && spendable(b, "POOL_TRANSPARENT") == 0
    });

    // Row 7: the funded key's mnemonic restored on a second daemon at
    // birthday 1, far below the window.
    let mut fx2 = Fixture::new("regtest");
    fx2.write_config(&format!("{BASE_CONFIG}{}", fb.config_section()));
    start_daemon(&mut fx2, &fb.node);
    let pw2 = fx2.passphrase_file(PASSPHRASE);
    let run = fx2
        .gyges(&[
            "key",
            "restore",
            "--id",
            "again",
            "--stdin",
            "--birthday",
            "1",
            "--yes",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw2)
        .stdin(mnemonic())
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stderr.contains("blocks will be backfilled"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&format!(
            "warning: transparent history below height {retained_from}"
        )),
        "{}",
        run.stderr
    );
    sync_wait_within(&fx2, "again", "900s", &["--until", "spendable"]);
    let again = wait_balance(&fx2, "again", |b| b["pools"] == main["pools"]);
    assert_eq!(again["total_spendable"], main["total_spendable"], "{again}");
    let status = daemon_status(&fx2);
    assert!(status.contains("trust: verified"), "{status}");

    // Nothing identifying in either daemon's logs (row 18 for rows 5–7).
    for f in [&fx, &fx2] {
        sweep_logs(
            &f.network_dir().join("logs"),
            &[&wallet_taddr, &bob_ua, &shield_txid, &pay_txid, PASSPHRASE],
        );
    }
}
