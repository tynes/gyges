//! The core loop against the pinned real `zakurad` (TESTING.md §3 rows 1–4;
//! ROADMAP.md M1 exit criterion): restore a key, mine to it, shield, pay a
//! second key's unified address and a transparent address, then survive a
//! three-block reorg that unmines every one of those transactions.
//!
//! Skips itself (with a message) where no node binary is available; see
//! `tests/regtest/versions.toml`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use gyges_regtest::{BURN_MINER_ADDRESS, Fixture, Node, NodeOpts};
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_protocol::consensus::NetworkType;

/// 23×abandon + art: the all-zero-entropy BIP 39 vector.
fn mnemonic() -> String {
    "abandon ".repeat(23) + "art"
}

const PASSPHRASE: &str = "correct-horse-battery-staple-7731";

fn regtest() -> gyges_core::ConsensusParams {
    gyges_core::Network::Regtest.consensus_params()
}

/// Account 0's first external transparent address for [`mnemonic`], the
/// way the wallet derives it (`zcash_client_sqlite` → ZIP 32 account key →
/// external chain, index 0), so the node can mine to it before the key
/// exists in Gyges.
fn test_key_transparent() -> TransparentAddress {
    use transparent::keys::IncomingViewingKey as _;
    let seed = bip0039::Mnemonic::<bip0039::English>::from_phrase(mnemonic())
        .unwrap()
        .to_seed("");
    let usk =
        zcash_keys::keys::UnifiedSpendingKey::from_seed(&regtest(), &seed, zip32::AccountId::ZERO)
            .unwrap();
    let (addr, _) = usk
        .transparent()
        .to_account_pubkey()
        .derive_external_ivk()
        .unwrap()
        .default_address();
    addr
}

fn test_key_transparent_address() -> String {
    gyges_chain::compact::encode_transparent_address(NetworkType::Regtest, &test_key_transparent())
}

/// The ZIP 320 (`texregtest1…`) form of the same pubkey hash: a TEX payment
/// to it comes back to the wallet as transparent balance, which is how the
/// recipient side of TESTING.md §3 row 9 is observed without a second node.
fn test_key_tex_address() -> String {
    let TransparentAddress::PublicKeyHash(hash) = test_key_transparent() else {
        panic!("the default address is P2PKH");
    };
    zcash_keys::address::Address::Tex(hash).encode(&regtest())
}

/// The default unified address of an exported UFVK (`key init --json`).
fn unified_address_of(ufvk: &str) -> String {
    let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&regtest(), ufvk).unwrap();
    let (ua, _) = ufvk
        .default_address(zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys)
        .unwrap();
    ua.encode(&regtest())
}

/// The transparent receivers the key's wallet watches (the gap-limit set).
fn transparent_receivers(fx: &Fixture, key_id: &str) -> Vec<TransparentAddress> {
    let path = fx.key_dir(key_id).join("wallet.sqlite");
    let db = zcash_client_sqlite::WalletDb::for_path(
        &path,
        regtest(),
        zcash_client_sqlite::util::SystemClock,
        rand::rand_core::UnwrapErr(rand::rngs::SysRng),
    )
    .unwrap()
    .with_transparent_ledger_mode(
        zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode::Public,
    );
    let account = db.get_account_ids().unwrap()[0];
    db.get_transparent_receivers(account, false, false)
        .unwrap()
        .keys()
        .copied()
        .collect()
}

fn daemon_config(fx: &Fixture) {
    fx.write_config(
        "[vault]\nscrypt_work_factor = 10\n\
         [zakura_rpc]\npoll_interval_secs = 1\nmin_retention_blocks = 1000\n\
         [policy]\nmin_confirmations = 1\n\
         [tex]\nrebroadcast_interval = \"1s\"\n",
    );
}

/// Poll `tx sessions --include-finished --json` until the ZIP 320 row for
/// `step1` is in `state` (a `TEX_STATE_*` name).
fn wait_tex_state(fx: &Fixture, step1: &str, state: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = serde_json::Value::Null;
    loop {
        let run = fx
            .gyges(&[
                "-k",
                "main",
                "tx",
                "sessions",
                "--include-finished",
                "--json",
            ])
            .run();
        assert_eq!(run.code(), 0, "{run:?}");
        let v = run.json();
        if let Some(row) = v["tex_transfers"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["step1_txid"] == step1))
        {
            if row["state"] == state {
                return row.clone();
            }
            last = row.clone();
        }
        assert!(
            Instant::now() < deadline,
            "row never reached {state}; last {last}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Both txids of a `tx send --to tex…` run: step 1 is the first stdout
/// line, step 2 the last word of the `tex pending` line on stderr. Whether
/// step 2 is also on stdout depends on the node: a step 2 that arrives
/// while the node is still verifying step 1 is refused on that first
/// attempt and left to the queue (the refusal text ends up in the row's
/// `last_error`, printed here for the record).
fn tex_txids(fx: &Fixture, run: &gyges_regtest::Run) -> (String, String) {
    let stdout: Vec<&str> = run.stdout.lines().collect();
    assert!(!stdout.is_empty() && stdout.len() <= 2, "{run:?}");
    let s1 = stdout[0].to_string();
    assert_eq!(s1.len(), 64, "{run:?}");
    let pending = run
        .stderr
        .lines()
        .find(|l| l.starts_with("tex pending (step 2 of 2)"))
        .unwrap_or_else(|| panic!("no tex pending line: {run:?}"));
    let s2 = pending.rsplit(' ').next().unwrap().to_string();
    assert_eq!(s2.len(), 64, "{pending}");
    if stdout.len() == 2 {
        assert_eq!(stdout[1], s2, "{run:?}");
    } else {
        // The queue re-offers step 2 within a second, so the row may already
        // have moved on; this is for the record only.
        let sessions = fx
            .gyges(&[
                "-k",
                "main",
                "tx",
                "sessions",
                "--include-finished",
                "--json",
            ])
            .run()
            .json();
        let row = sessions["tex_transfers"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["step1_txid"] == s1))
            .cloned()
            .unwrap_or_default();
        eprintln!(
            "step 2 was not taken on the first attempt: state {} error {}",
            row["state"], row["last_error"]
        );
    }
    (s1, s2)
}

/// Wait until the node's mempool holds every txid in `want`.
fn wait_mempool(node: &Node, want: &[&str]) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mp = node.mempool();
        if want.iter().all(|t| mp.iter().any(|m| m == t)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "mempool never held {want:?}: {mp:?}\n{}",
            node.log_tail()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn node_args(node: &Node) -> [String; 4] {
    [
        "--zakura-rpc".into(),
        node.url(),
        "--zakura-cookie".into(),
        node.cookie_path().display().to_string(),
    ]
}

fn start_daemon(fx: &mut Fixture, node: &Node) {
    let args = node_args(node);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    fx.start_daemon(&args).unwrap();
}

/// `balance --json` for a key.
fn balance(fx: &Fixture, key: &str) -> serde_json::Value {
    let run = fx.gyges(&["-k", key, "balance", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    run.json()
}

/// Spendable zatoshis of one pool in a `balance --json`, 0 when omitted.
fn spendable(b: &serde_json::Value, pool: &str) -> u64 {
    b["pools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["pool"] == pool)
        .and_then(|p| p["spendable"].as_str())
        .map(|s| s.parse().unwrap())
        .unwrap_or(0)
}

fn sync_wait(fx: &Fixture, key: &str, extra: &[&str]) {
    let mut args = vec!["-k", key, "sync", "wait", "--timeout", "180s"];
    args.extend_from_slice(extra);
    let run = fx.gyges(&args).run();
    assert_eq!(run.code(), 0, "{run:?}");
}

fn wait_for_txid(fx: &Fixture, key: &str, txid: &str) {
    sync_wait(fx, key, &["--txid", txid, "--confirmations", "1"]);
}

/// The balance can lag `sync wait` by a tick; poll it.
fn wait_balance(
    fx: &Fixture,
    key: &str,
    ok: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let b = balance(fx, key);
        if ok(&b) {
            return b;
        }
        assert!(Instant::now() < deadline, "balance never settled: {b}");
        std::thread::sleep(Duration::from_millis(250));
    }
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

/// Every file in `dir` is 0600 and free of `secrets`.
fn sweep_logs(dir: &Path, secrets: &[&str]) {
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        seen += 1;
        let name = entry.file_name().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(entry.path()).unwrap();
        assert_eq!(
            std::fs::metadata(entry.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "{name}"
        );
        for secret in secrets {
            assert!(!text.contains(secret), "{secret:?} in {name}");
        }
    }
    assert!(
        seen >= 2,
        "main log and audit log expected in {}",
        dir.display()
    );
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
    daemon_config(&fx);
    start_daemon(&mut fx, &node);

    let run = fx.gyges(&["daemon", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stdout.contains("connected, tip 3"), "{}", run.stdout);
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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["birthday_height"], 3);
    sync_wait(&fx, "main", &["--until", "spendable"]);
    let run = fx.gyges(&["sync", "status", "--json"]).run();
    assert_eq!(run.json()["keys"][0]["scanned_tip"], 3, "{}", run.stdout);
    drop(fx);

    // A testnet daemon pointed at this regtest node: same chain name
    // ("test"), different activation heights.
    let mut other = Fixture::new("testnet");
    daemon_config(&other);
    start_daemon(&mut other, &node);
    let run = other.gyges(&["daemon", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains("activates Overwinter at height 1"),
        "{}",
        run.stdout
    );
}

/// Rows 1–4: restore → mine → shield → send to `u1` → send to `t1` →
/// 3-block reorg → every transaction re-mined and every balance back.
#[test]
fn restore_mine_shield_send_and_reorg_against_the_real_node() {
    let wallet_taddr = test_key_transparent_address();
    // Two coinbases to the wallet, then a hundred to nobody so that both are
    // mature (COINBASE_MATURITY = 100) before anything spends them.
    let Some(mut node) = Node::start_or_skip(NodeOpts {
        miner_address: wallet_taddr.clone(),
        ..NodeOpts::default()
    }) else {
        return;
    };
    node.mine(2);
    node.restart(NodeOpts::default()).unwrap();
    node.mine(100);
    assert_eq!(node.tip_height(), 102);
    let funded = node.coinbase_value(1) + node.coinbase_value(2);
    assert!(funded > 0, "coinbases pay the transparent pool");

    let mut fx = Fixture::new("regtest");
    daemon_config(&fx);
    start_daemon(&mut fx, &node);
    let pw = fx.passphrase_file(PASSPHRASE);

    // Row 1: restore at the default birthday, sync, see the coinbases.
    let run = fx
        .gyges(&["key", "restore", "--id", "main", "--stdin", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(mnemonic())
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["birthday_height"], 1);
    let watched: Vec<String> = transparent_receivers(&fx, "main")
        .iter()
        .map(|a| gyges_chain::compact::encode_transparent_address(NetworkType::Regtest, a))
        .collect();
    assert!(
        watched.contains(&wallet_taddr),
        "the harness derives one of the wallet's own receivers: {watched:?}"
    );
    sync_wait(&fx, "main", &["--until", "spendable"]);
    let b = wait_balance(&fx, "main", |b| spendable(b, "POOL_TRANSPARENT") == funded);
    assert_eq!(b["total_spendable"], funded.to_string(), "{b}");

    // Row 3, first half: shield everything into Ironwood.
    let run = fx
        .gyges(&["-k", "main", "tx", "shield", "--yes"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}\n{}", node.log_tail());
    let shield_txid = run.stdout.trim().to_string();
    assert_eq!(shield_txid.len(), 64, "{run:?}");
    assert_eq!(
        node.mempool(),
        vec![shield_txid.clone()],
        "the node accepted it"
    );
    node.mine(1);
    wait_for_txid(&fx, "main", &shield_txid);
    let b = wait_balance(&fx, "main", |b| spendable(b, "POOL_IRONWOOD") > 0);
    let shielded = spendable(&b, "POOL_IRONWOOD");
    assert!(shielded < funded && shielded > funded - 100_000, "{b}");
    assert_eq!(spendable(&b, "POOL_TRANSPARENT"), 0, "{b}");
    assert_eq!(spendable(&b, "POOL_ORCHARD"), 0, "{b}");

    // Row 2: a second key, born now, paid at its unified address.
    let run = fx
        .gyges(&["key", "init", "--id", "bob", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["birthday_height"], 103);
    let bob_ua = unified_address_of(run.json()["ufvk"].as_str().unwrap());
    assert!(bob_ua.starts_with("uregtest1"), "{bob_ua}");
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &bob_ua, "--amount", "1", "--yes",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}\n{}", node.log_tail());
    let pay_bob_txid = run.stdout.trim().to_string();
    node.mine(1);
    wait_for_txid(&fx, "bob", &pay_bob_txid);
    let b = wait_balance(&fx, "bob", |b| spendable(b, "POOL_IRONWOOD") == 100_000_000);
    assert_eq!(b["total_spendable"], "100000000", "{b}");
    wait_for_txid(&fx, "main", &pay_bob_txid);
    let b = wait_balance(&fx, "main", |b| {
        spendable(b, "POOL_IRONWOOD") < shielded - 100_000_000
    });
    let after_bob = spendable(&b, "POOL_IRONWOOD");
    assert!(after_bob > shielded - 100_100_000, "{b}");

    // Row 3, second half: pay a transparent address (the wallet's own).
    let run = fx
        .gyges(&[
            "-k",
            "main",
            "tx",
            "send",
            "--to",
            &wallet_taddr,
            "--amount",
            "0.5",
            "--yes",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}\n{}", node.log_tail());
    let pay_t_txid = run.stdout.trim().to_string();
    node.mine(1);
    let tip = node.tip_height();
    assert_eq!(tip, 105);
    wait_for_txid(&fx, "main", &pay_t_txid);
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
    wait_for_txid(&fx, "main", &pay_t_txid);
    wait_for_txid(&fx, "bob", &pay_bob_txid);
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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let audit: Vec<serde_json::Value> = run
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let entries: Vec<serde_json::Value> = run
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
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
    let Some(mut node) = Node::start_or_skip(NodeOpts {
        miner_address: wallet_taddr.clone(),
        ..NodeOpts::default()
    }) else {
        return;
    };
    node.mine(2);
    node.restart(NodeOpts::default()).unwrap();
    node.mine(100);
    let funded = node.coinbase_value(1) + node.coinbase_value(2);

    let mut fx = Fixture::new("regtest");
    daemon_config(&fx);
    start_daemon(&mut fx, &node);
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
    assert_eq!(run.code(), 0, "{run:?}\n{}", node.log_tail());
    let shield_txid = run.stdout.trim().to_string();
    node.mine(1);
    wait_for_txid(&fx, "main", &shield_txid);
    let b = wait_balance(&fx, "main", |b| spendable(b, "POOL_IRONWOOD") > 0);
    let shielded = spendable(&b, "POOL_IRONWOOD");
    assert_eq!(spendable(&b, "POOL_TRANSPARENT"), 0, "{b}");

    let tex_addr = test_key_tex_address();
    assert!(tex_addr.starts_with("texregtest1"), "{tex_addr}");

    // Row 9: both steps accepted by the mempool at once (the node chains
    // them), mined together.
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &tex_addr, "--amount", "1", "--yes",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}\n{}", node.log_tail());
    let (s1, s2) = tex_txids(&fx, &run);
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
    wait_for_txid(&fx, "main", &s1);
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
    let run = fx
        .gyges(&[
            "-k", "main", "tx", "send", "--to", &tex_addr, "--amount", "0.5", "--yes",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}\n{}", node.log_tail());
    let (s1b, s2b) = tex_txids(&fx, &run);
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
    wait_for_txid(&fx, "main", &s1b);
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
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
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
