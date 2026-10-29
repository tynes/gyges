//! The core loop against the pinned real `zakurad` (TESTING.md §3 rows 1–4;
//! ROADMAP.md M1 exit criterion): restore a key, mine to it, shield, pay a
//! second key's unified address and a transparent address, then survive a
//! three-block reorg that unmines every one of those transactions.
//!
//! Skips itself (with a message) where no node binary is available; see
//! `tests/regtest/versions.toml`.

use std::time::Duration;

use gyges_chain::{ChainBackend as _, ChainError, ZakuraRpcBackend};
use gyges_regtest::{
    BURN_MINER_ADDRESS, Fixture, NODE_CONFIG, Node, NodeOpts, PASSPHRASE, Run, balance,
    funded_wallet, parse_tex_txids, poll_until, regtest, send, shield, spendable, start_daemon,
    sweep_logs, sync_wait, sync_wait_within, test_key_miner, test_key_transparent,
    test_key_transparent_address, tex_row, wait_balance, wait_for_txid, wait_tex_state,
};
use transparent::address::TransparentAddress;

/// The ZIP 320 (`texregtest1…`) form of the same pubkey hash: a TEX payment
/// to it comes back to the wallet as transparent balance, which is how the
/// recipient side of TESTING.md §3 row 9 is observed without a second node.
fn test_key_tex_address() -> String {
    let TransparentAddress::PublicKeyHash(hash) = test_key_transparent() else {
        panic!("the default address is P2PKH");
    };
    zcash_keys::address::Address::Tex(hash).encode(&regtest())
}

/// Both txids of a `tx send --to tex…` run ([`parse_tex_txids`]). Whether
/// step 2 is also on stdout depends on the node: a step 2 that arrives
/// while the node is still verifying step 1 is refused on that first
/// attempt and left to the queue (the refusal text ends up in the row's
/// `last_error`, printed here for the record).
fn tex_txids(fx: &Fixture, run: &Run) -> (String, String) {
    let (s1, s2) = parse_tex_txids(run);
    let stdout: Vec<&str> = run.stdout.lines().collect();
    assert!(stdout.len() <= 2, "{run:?}");
    if stdout.len() == 2 {
        assert_eq!(stdout[1], s2, "{run:?}");
    } else {
        // The queue re-offers step 2 within a second, so the row may already
        // have moved on; this is for the record only.
        let row = tex_row(fx, &s1);
        eprintln!(
            "step 2 was not taken on the first attempt: state {} error {}",
            row["state"], row["last_error"]
        );
    }
    (s1, s2)
}

/// Wait until the node's mempool holds every txid in `want`.
fn wait_mempool(node: &Node, want: &[&str]) {
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(250),
        &format!("mempool never held {want:?}"),
        || {
            let mp = node.mempool();
            if want.iter().all(|t| mp.iter().any(|m| m == t)) {
                return Ok(());
            }
            Err(format!("{mp:?}\n{}", node.log_tail()))
        },
    );
}

/// Make sure `txid` is in the chain after a reorg: rebroadcast the raw bytes
/// if the node dropped it, then mine. Shielded spends need their anchors
/// re-mined first, so callers pass transactions in dependency order.
fn ensure_mined(node: &Node, txid: &str, raw: &str) -> u32 {
    if node.mined_height(txid).is_none() {
        if !node.mempool().iter().any(|t| t == txid) {
            node.send_raw_transaction(raw)
                .unwrap_or_else(|e| panic!("rebroadcast {txid}: {e}\n{}", node.log_tail()));
        }
        node.mine(1);
    }
    node.mined_height(txid).expect("mined after rebroadcast")
}

/// A node (an archive node if `archive`) with two coinbases to the wallet
/// ([`test_key_miner`]), then a hundred to nobody so that both are mature
/// (COINBASE_MATURITY = 100) before anything spends them. `None` where no
/// node binary is available.
fn node_with_mature_coinbases(archive: bool) -> Option<Node> {
    let opts = |o: NodeOpts| NodeOpts { archive, ..o };
    let mut node = Node::start_or_skip(opts(test_key_miner()))?;
    node.mine(2);
    node.restart(opts(NodeOpts::default())).unwrap();
    node.mine(100);
    Some(node)
}

/// TESTING.md §3 row 15 in spirit, plus the status surface: the daemon sees
/// the node's bounds, `key init` takes its birthday from the live tip, and
/// a daemon for the wrong network is refused by the activation heights.
#[test]
fn daemon_status_and_key_init_against_the_real_node() {
    let Some(node) = Node::start_or_skip(NodeOpts::default()) else {
        return;
    };
    node.mine(3);
    let mut fx = Fixture::new("regtest");
    fx.write_config(NODE_CONFIG);
    start_daemon(&mut fx, &node);

    fx.gyges(&["daemon", "status"])
        .ok()
        .stdout_has("connected, tip 3");
    let run = fx.gyges(&["daemon", "status", "--json"]).run();
    let node_status = &run.json()["node"];
    assert_eq!(node_status["connected"], true, "{node_status}");
    assert_eq!(node_status["tip_height"], 3);
    assert_eq!(node_status["tip_hash"], node.block_hash(3));
    assert_eq!(node_status["pruned"], true, "{node_status}");
    // Zero is omitted from the JSON (API.md §5).
    assert_eq!(node_status["retained_from"].as_u64().unwrap_or(0), 0);

    let pw = fx.passphrase_file(PASSPHRASE);
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok();
    assert_eq!(run.json()["birthday_height"], 3);
    sync_wait(&fx, "main", &["--until", "spendable"]);
    let run = fx.gyges(&["sync", "status", "--json"]).run();
    assert_eq!(run.json()["keys"][0]["scanned_tip"], 3, "{}", run.stdout);
    drop(fx);

    // A wrong or missing cookie: zakurad closes the connection without an
    // answer, which must still read as a credentials problem, not as a
    // node that is down.
    let dir = tempfile::tempdir().unwrap();
    let wrong = dir.path().join(".cookie");
    std::fs::write(&wrong, "__cookie__:wrong").unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (cookie, hint) in [
        (Some(wrong), "presented but rejected"),
        (None, "no cookie configured"),
    ] {
        let be = ZakuraRpcBackend::new(node.url(), cookie, regtest()).unwrap();
        let err = rt.block_on(be.node_bounds()).unwrap_err();
        assert!(
            matches!(&err, ChainError::Unreachable(m) if m.contains("credentials") && m.contains(hint)),
            "{err}"
        );
    }

    // A testnet daemon pointed at this regtest node: same chain name
    // ("test"), different activation heights.
    let mut other = Fixture::new("testnet");
    other.write_config(NODE_CONFIG);
    start_daemon(&mut other, &node);
    other
        .gyges(&["daemon", "status"])
        .ok()
        .stdout_has("activates Overwinter at height 1");
}

/// Rows 1–4: restore → mine → shield → send to `u1` → send to `t1` →
/// 3-block reorg → every transaction re-mined and every balance back.
#[test]
fn restore_mine_shield_send_and_reorg_against_the_real_node() {
    let wallet_taddr = test_key_transparent_address();
    let Some(node) = node_with_mature_coinbases(false) else {
        return;
    };
    assert_eq!(node.tip_height(), 102);
    let log = node.log_path();

    // Row 1: restore at the default birthday, sync, see the coinbases.
    let (fx, pw, funded) = funded_wallet(&node);

    // Row 3, first half: shield everything into Ironwood.
    let (shield_txid, b) = shield(&fx, &pw, &log, |txid| {
        assert_eq!(node.mempool(), vec![txid], "the node accepted it");
        node.mine(1);
    });
    let shielded = spendable(&b, "POOL_IRONWOOD");
    assert!(shielded < funded && shielded > funded - 100_000, "{b}");
    assert_eq!(spendable(&b, "POOL_ORCHARD"), 0, "{b}");

    // Row 2: a second key, born now, paid at its unified address.
    let run = fx
        .gyges(&["key", "init", "--id", "bob", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok();
    assert_eq!(run.json()["birthday_height"], 103);
    // The receive address comes from `gyges address current`, as a user
    // would get it (the M1 exit criterion).
    let run = fx.gyges(&["-k", "bob", "address", "current"]).ok();
    let bob_ua = run.stdout.trim().to_string();
    assert!(bob_ua.starts_with("uregtest1"), "{bob_ua}");
    let run = fx.gyges(&["address", "inspect", &bob_ua, "--json"]).ok();
    assert_eq!(run.json()["kind"], "ADDRESS_KIND_UNIFIED");
    let pay_bob_txid = send(&fx, &pw, &log, &bob_ua, "1").stdout.trim().to_string();
    // SYNC.md §7: while the payment is in the node's mempool, bob sees it
    // as pending (the loop finds it on its own; `sync mempool` forces it).
    fx.gyges(&["-k", "bob", "sync", "mempool"])
        .ok()
        .stdout_has("found 1 note");
    let b = wait_balance(&fx, "bob", |b| {
        b["pools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["pool"] == "POOL_IRONWOOD" && p["pending"] == "100000000")
    });
    assert!(b["total_spendable"].is_null(), "{b}");
    node.mine(1);
    wait_for_txid(&fx, "bob", &pay_bob_txid, 1);
    let b = wait_balance(&fx, "bob", |b| spendable(b, "POOL_IRONWOOD") == 100_000_000);
    assert_eq!(b["total_spendable"], "100000000", "{b}");
    // What arrived and how the payment stands, through the M1 commands.
    let run = fx.gyges(&["-k", "bob", "notes", "--json"]).ok();
    let notes = run.json();
    let notes = notes["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0]["pool"], "POOL_IRONWOOD");
    assert_eq!(notes[0]["value"], "100000000");
    assert_eq!(notes[0]["txid"], pay_bob_txid.as_str());
    let run = fx
        .gyges(&["-k", "main", "tx", "status", &pay_bob_txid, "--json"])
        .ok();
    let st = run.json();
    assert_eq!(st["status"], "TRANSACTION_STATUS_MINED", "{st}");
    assert_eq!(st["source"], "STATUS_SOURCE_NODE", "{st}");
    assert!(st["confirmations"].as_u64().unwrap_or(0) >= 1, "{st}");
    wait_for_txid(&fx, "main", &pay_bob_txid, 1);
    let run = fx.gyges(&["-k", "main", "tx", "list", "--json"]).ok();
    let history = run.json();
    let txids: Vec<&str> = history["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["txid"].as_str().unwrap())
        .collect();
    assert_eq!(txids.first(), Some(&pay_bob_txid.as_str()), "{history}");
    assert!(txids.contains(&shield_txid.as_str()), "{history}");
    let b = wait_balance(&fx, "main", |b| {
        spendable(b, "POOL_IRONWOOD") < shielded - 100_000_000
    });
    let after_bob = spendable(&b, "POOL_IRONWOOD");
    assert!(after_bob > shielded - 100_100_000, "{b}");

    // Row 3, second half: pay a transparent address (the wallet's own).
    let pay_t_txid = send(&fx, &pw, &log, &wallet_taddr, "0.5")
        .stdout
        .trim()
        .to_string();
    node.mine(1);
    let tip = node.tip_height();
    assert_eq!(tip, 105);
    wait_for_txid(&fx, "main", &pay_t_txid, 1);
    let before_reorg = wait_balance(&fx, "main", |b| {
        spendable(b, "POOL_TRANSPARENT") == 50_000_000
    });
    assert!(
        spendable(&before_reorg, "POOL_IRONWOOD") < after_bob - 50_000_000,
        "{before_reorg}"
    );
    let bob_before = balance(&fx, "bob");

    // Row 4: invalidate the block three below the tip (103, 104 and 105 go,
    // and with them all three transactions), mine four, and re-mine the
    // transactions in dependency order.
    let txs = [&shield_txid, &pay_bob_txid, &pay_t_txid];
    let raws: Vec<String> = txs.iter().map(|t| node.raw_transaction(t)).collect();
    let fork = tip - 2;
    let old_hashes: Vec<String> = (fork..=tip).map(|h| node.block_hash(h)).collect();
    node.invalidate_block(&old_hashes[0]);
    assert_eq!(node.tip_height(), fork - 1);
    node.mine(4);
    assert_eq!(node.tip_height(), tip + 1);
    assert_ne!(node.block_hash(fork), old_hashes[0]);
    let mut heights = Vec::new();
    for (txid, raw) in txs.iter().zip(&raws) {
        heights.push(ensure_mined(&node, txid, raw));
    }
    assert!(heights.windows(2).all(|w| w[0] <= w[1]), "{heights:?}");
    assert!(heights[0] > fork - 1, "{heights:?}");
    let new_tip = node.tip_height();

    // The daemon rewound to the fork, rescanned, and the balances are back.
    sync_wait(&fx, "main", &[]);
    sync_wait(&fx, "bob", &[]);
    wait_for_txid(&fx, "main", &pay_t_txid, 1);
    wait_for_txid(&fx, "bob", &pay_bob_txid, 1);
    let run = fx.gyges(&["sync", "status", "--json"]).run();
    for key in run.json()["keys"].as_array().unwrap() {
        assert_eq!(key["chain_tip"], new_tip, "{key}");
        assert_eq!(key["scanned_tip"], new_tip, "{key}");
        assert_eq!(key["scanned"], true, "{key}");
        assert_eq!(key["spendable"], true, "{key}");
        assert_eq!(key["detail"], "synced", "{key}");
    }
    let after = wait_balance(&fx, "main", |b| {
        spendable(b, "POOL_TRANSPARENT") == 50_000_000
            && spendable(b, "POOL_IRONWOOD") == spendable(&before_reorg, "POOL_IRONWOOD")
    });
    assert_eq!(after["pools"], before_reorg["pools"], "{after}");
    let bob_after = wait_balance(&fx, "bob", |b| spendable(b, "POOL_IRONWOOD") == 100_000_000);
    assert_eq!(bob_after["pools"], bob_before["pools"]);

    // The audit log saw the three broadcasts; the main log saw both wallets
    // rewound to the fork (bob was born in a reorged block, so its rewind is
    // a reset to the node's tree state rather than a truncation).
    let run = fx
        .gyges(&["daemon", "logs", "--audit", "--lines", "1000", "--json"])
        .ok();
    let audit = run.json_lines();
    assert_eq!(
        audit
            .iter()
            .filter(|e| e["fields"]["event"] == "broadcast" && e["fields"]["key_id"] == "main")
            .count(),
        3,
        "{}",
        run.stdout
    );
    let run = fx
        .gyges(&["daemon", "logs", "--lines", "1000", "--json"])
        .ok();
    let entries = run.json_lines();
    for key in ["main", "bob"] {
        let rewound = entries
            .iter()
            .find(|e| e["message"] == "reorg: wallet rewound" && e["fields"]["key_id"] == key)
            .unwrap_or_else(|| panic!("no rewind for {key} in {}", run.stdout));
        let to: u32 = rewound["fields"]["truncated_to"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(to, fork - 1, "{rewound}");
    }

    // Nothing identifying in either log (TESTING.md §5 row 18 for rows 1–4).
    sweep_logs(
        &fx.network_dir().join("logs"),
        &[
            &wallet_taddr,
            &bob_ua,
            &shield_txid,
            &pay_bob_txid,
            &pay_t_txid,
            PASSPHRASE,
            &funded.to_string(),
            "100000000",
            "50000000",
            BURN_MINER_ADDRESS,
        ],
    );
}

/// TESTING.md §3 rows 9, 10 and 12 against `zakurad`: a `texregtest1`
/// payment chains both steps in the node's mempool and mines them in one
/// block; the recipient (the wallet's own pubkey hash) sees exactly the
/// amount as transparent balance; a second payment survives a node restart
/// and a daemon crash between broadcast and mining, finished by the queue
/// from the stored bytes with the same txids.
#[test]
fn zip320_against_the_real_node() {
    let wallet_taddr = test_key_transparent_address();
    let Some(mut node) = node_with_mature_coinbases(false) else {
        return;
    };
    let log = node.log_path();
    let (mut fx, pw, funded) = funded_wallet(&node);
    let (shield_txid, b) = shield(&fx, &pw, &log, |_| {
        node.mine(1);
    });
    let shielded = spendable(&b, "POOL_IRONWOOD");

    let tex_addr = test_key_tex_address();
    assert!(tex_addr.starts_with("texregtest1"), "{tex_addr}");

    // Row 9: both steps accepted by the mempool at once (the node chains
    // them), mined together.
    let (s1, s2) = tex_txids(&fx, &send(&fx, &pw, &log, &tex_addr, "1"));
    // The queue gets step 2 in while step 1 is still unmined (the node
    // chains them), whether or not the send's own attempt was accepted.
    wait_mempool(&node, &[&s1, &s2]);
    node.mine(1);
    let mined_at = node.tip_height();
    assert_eq!(node.mined_height(&s1), Some(mined_at));
    assert_eq!(node.mined_height(&s2), Some(mined_at), "same block");
    let row = wait_tex_state(&fx, &s1, "TEX_STATE_STEP2_MINED");
    assert_eq!(row["step2_txid"], s2, "{row}");
    assert_eq!(row["amount"], "100000000", "{row}");
    wait_for_txid(&fx, "main", &s1, 1);
    // The exchange side: exactly the amount, as a plain transparent output.
    let b = wait_balance(&fx, "main", |b| {
        spendable(b, "POOL_TRANSPARENT") == 100_000_000
    });
    let fees = shielded - 100_000_000 - spendable(&b, "POOL_IRONWOOD");
    assert!(fees > 0 && fees < 100_000, "two ZIP 317 fees: {fees} ({b})");

    // Rows 10 and 12: a second payment, then the node restarts and the
    // daemon is killed before anything is mined. The restarted queue puts
    // back whatever the node lost, from the bytes it stored, and the txids
    // do not change.
    let (s1b, s2b) = tex_txids(&fx, &send(&fx, &pw, &log, &tex_addr, "0.5"));
    wait_mempool(&node, &[&s1b, &s2b]);
    fx.kill_daemon();
    node.restart(NodeOpts::default()).unwrap();
    let kept = node.mempool();
    eprintln!("mempool after the node restart: {kept:?}");
    start_daemon(&mut fx, &node);
    wait_mempool(&node, &[&s1b, &s2b]);
    node.mine(1);
    let row = wait_tex_state(&fx, &s1b, "TEX_STATE_STEP2_MINED");
    assert_eq!(row["step2_txid"], s2b, "{row}");
    assert!(
        row["attempts"].as_u64().unwrap() >= 2,
        "rebroadcast after the restart: {row}"
    );
    wait_for_txid(&fx, "main", &s1b, 1);
    // The recipient is this wallet, so only fees left it: the shield (two
    // transparent inputs, 20,000) and two ZIP 320 pairs (15,000 + 10,000
    // each). Where the 0.5 ZEC was funded from is the input selector's
    // choice: the profile spends transparent, and the 1 ZEC the first
    // payment returned is a spendable UTXO, so step 1 of the second payment
    // may draw on it (with Ironwood change) instead of on shielded notes.
    let b = wait_balance(&fx, "main", |b| {
        b["total_spendable"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            == Some(funded - 70_000)
    });
    let transparent = spendable(&b, "POOL_TRANSPARENT");
    assert!(
        transparent == 150_000_000 || transparent == 50_000_000,
        "both TEX payments came back as transparent funds, less what the second re-spent: {b}"
    );
    eprintln!(
        "second step 1 funded from {}",
        if transparent == 50_000_000 {
            "the first payment's transparent output"
        } else {
            "shielded notes"
        }
    );
    let run = fx
        .gyges(&["-k", "main", "tx", "sessions", "--include-finished"])
        .ok();
    assert_eq!(
        run.stdout.matches("step2_mined").count(),
        2,
        "{}",
        run.stdout
    );

    sweep_logs(
        &fx.network_dir().join("logs"),
        &[
            &wallet_taddr,
            &tex_addr,
            &shield_txid,
            &s1,
            &s2,
            &s1b,
            &s2b,
            PASSPHRASE,
            &funded.to_string(),
            "100000000",
            "50000000",
            BURN_MINER_ADDRESS,
        ],
    );
}

/// The first regtest height at which the wallet builds Sapling outputs:
/// ZIP 212 is enforced from Canopy (height 1) plus its 32,256-block grace
/// period, and a Sapling spend always pads its bundle with two outputs.
const ZIP212_ON: u32 = 1 + 32_256;

/// ROADMAP.md M6, first item (THREAT_MODEL.md §6 item 1), on the real node:
/// past ZIP 212, a second key paid at a Sapling-only address spends that
/// note with `tx send` (the key is asked for before proving, the proof
/// generation key inserted, the PCZT proven and signed in the stream), and
/// the node takes the transaction.
#[test]
fn sapling_spend_against_the_real_node() {
    // Fund and shield while the chain is young (regtest's subsidy halves
    // every few hundred blocks, so a coinbase past ZIP 212 pays nothing).
    // An archive node, so that nothing is pruned while the daemon scans
    // the long chain behind the miner.
    let Some(node) = node_with_mature_coinbases(true) else {
        return;
    };
    let log = node.log_path();
    let (fx, pw, _) = funded_wallet(&node);
    let keys = fx.gyges(&["key", "list", "--json"]).ok().json();
    assert!(
        keys["keys"][0]["spend_pools"]
            .as_array()
            .is_some_and(|p| p.iter().any(|x| x == "POOL_SAPLING")),
        "{keys}"
    );
    let (shield_txid, _) = shield(&fx, &pw, &log, |txid| {
        assert_eq!(node.mempool(), vec![txid], "the node accepted it");
        node.mine(1);
    });
    while node.tip_height() < ZIP212_ON {
        node.mine((ZIP212_ON - node.tip_height()).min(2_000));
    }
    sync_wait_within(&fx, "main", "900s", &["--until", "spendable"]);

    // bob, born now, paid at a Sapling-only address.
    fx.gyges(&["key", "init", "--id", "bob", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok();
    let bob_sapling = fx
        .gyges(&["-k", "bob", "address", "new", "--receivers", "sapling"])
        .ok()
        .stdout
        .trim()
        .to_string();
    let pay = send(&fx, &pw, &log, &bob_sapling, "1")
        .stdout
        .trim()
        .to_string();
    assert_eq!(node.mempool(), vec![pay.clone()], "the node accepted it");
    node.mine(1);
    let b = wait_balance(&fx, "bob", |b| spendable(b, "POOL_SAPLING") == 100_000_000);
    assert_eq!(b["total_spendable"], "100000000", "{b}");

    // bob spends it: a Sapling spend the node must accept.
    let run = fx
        .gyges(&[
            "-k",
            "bob",
            "tx",
            "send",
            "--to",
            &gyges_regtest::burn_t_address(),
            "--amount",
            "0.5",
            "--yes",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .ok_with_log(&log);
    let spend = run.stdout.trim().to_string();
    assert_eq!(node.mempool(), vec![spend.clone()], "the node accepted it");
    node.mine(1);
    wait_for_txid(&fx, "bob", &spend, 1);
    let b = wait_balance(&fx, "bob", |b| {
        b["total_spendable"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|t| t > 49_900_000 && t < 50_000_000)
    });
    assert_eq!(spendable(&b, "POOL_TRANSPARENT"), 0, "{b}");

    sweep_logs(
        &fx.network_dir().join("logs"),
        &[&shield_txid, &pay, &spend, &bob_sapling, PASSPHRASE],
    );
}
