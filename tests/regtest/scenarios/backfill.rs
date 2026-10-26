//! The backfill scenarios against a real pruned `zakurad`, an archive node
//! and `zaino` (TESTING.md §3 rows 5–7, ROADMAP.md M2 sixth item). Each
//! skips itself without both `ZAKURAD_BIN` and `ZAINOD_BIN` off Linux.

use std::time::Duration;

use gyges_regtest::{
    FINALITY_DEPTH, Fallback, Fixture, MIN_TX_RETENTION, NODE_CONFIG, NodeOpts, PASSPHRASE,
    funded_wallet, mnemonic, send, shield, spendable, start_daemon, sweep_logs, sync_wait,
    sync_wait_within, test_key_miner, test_key_transparent_address, wait_balance, wait_stalled,
};
use serde_json::json;

/// Enough blocks past the current tip for the pruned node to drop the
/// block after it: pruning runs [`FINALITY_DEPTH`] behind the window.
const PAST_THE_WINDOW: u32 = FINALITY_DEPTH + MIN_TX_RETENTION + 99;

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
    let Some(mut fb) = Fallback::start_or_skip(test_key_miner()) else {
        return;
    };
    // Two coinbases to the wallet, matured by a hundred more to nobody.
    fb.mine(2);
    fb.node.restart(NodeOpts::default()).unwrap();
    fb.mine(100);
    let log = fb.node.log_path();
    let (mut fx, pw, _) = funded_wallet(&fb.node);
    let (shield_txid, _) = shield(&fx, &pw, &log, |_| {
        fb.mine(1);
    });

    fx.gyges(&["key", "init", "--id", "bob", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok();
    let run = fx.gyges(&["-k", "bob", "address", "current"]).ok();
    let bob_ua = run.stdout.trim().to_string();
    sync_wait(&fx, "bob", &["--until", "spendable"]);
    let pay_txid = send(&fx, &pw, &log, &bob_ua, "1").stdout.trim().to_string();

    // The daemon stops with the payment in the mempool; the chain moves on.
    fx.stop_daemon();
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
    wait_stalled(&fx, "main", Duration::from_secs(60));
    let run = fx.gyges(&["sync", "status"]).ok();
    for key in ["main", "bob"] {
        run.stdout_has(&format!("node pruned past key '{key}'"));
    }
    fx.gyges(&["daemon", "status"])
        .ok()
        .stdout_has("fallback:     disabled");
    fx.stop_daemon();

    // Row 5: the same daemon with zaino as its fallback endpoint.
    fx.write_config(&format!("{NODE_CONFIG}{}", fb.config_section()));
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
    fx.gyges(&["daemon", "status"])
        .ok()
        .stdout_has("trust: verified");
    let main = wait_balance(&fx, "main", |b| {
        spendable(b, "POOL_IRONWOOD") > 0 && spendable(b, "POOL_TRANSPARENT") == 0
    });

    // Row 7: the funded key's mnemonic restored on a second daemon at
    // birthday 1, far below the window.
    let mut fx2 = Fixture::new("regtest");
    fx2.write_config(&format!("{NODE_CONFIG}{}", fb.config_section()));
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
        .ok();
    run.stderr_has("blocks will be backfilled");
    run.stderr_has(&format!(
        "warning: transparent history below height {retained_from}"
    ));
    sync_wait_within(&fx2, "again", "900s", &["--until", "spendable"]);
    let again = wait_balance(&fx2, "again", |b| b["pools"] == main["pools"]);
    assert_eq!(again["total_spendable"], main["total_spendable"], "{again}");
    fx2.gyges(&["daemon", "status"])
        .ok()
        .stdout_has("trust: verified");

    // Nothing identifying in either daemon's logs (row 18 for rows 5–7).
    for f in [&fx, &fx2] {
        sweep_logs(
            &f.network_dir().join("logs"),
            &[&wallet_taddr, &bob_ua, &shield_txid, &pay_txid, PASSPHRASE],
        );
    }
}
