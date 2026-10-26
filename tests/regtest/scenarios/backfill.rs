//! The backfill scenarios against a real pruned `zakurad`, an archive node
//! and `zaino` (TESTING.md §3 rows 5–7, ROADMAP.md M2 sixth item). Each
//! skips itself without both `ZAKURAD_BIN` and `ZAINOD_BIN` off Linux.

use gyges_regtest::{FINALITY_DEPTH, Fallback, MIN_TX_RETENTION, NodeOpts};
use serde_json::json;

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
