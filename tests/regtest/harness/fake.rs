//! Shared setup for the scenarios that run against the in-process fake
//! `zakurad` (`gyges_chain::testing::FakeNode`), plus the wallet and
//! `gyges` polling helpers they and the real-node scenarios have in common.

use std::path::PathBuf;
use std::time::Duration;

use gyges_chain::testing::{FakeNode, regtest_params};
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::WalletRead as _;

use crate::{Fixture, poll_until};

/// Fast scrypt and a one-second node poll.
pub const FAST_CONFIG: &str =
    "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n";

/// [`FAST_CONFIG`] with funds spendable after one confirmation.
pub const SPEND_CONFIG: &str = "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n[policy]\nmin_confirmations = 1\n";

/// [`SPEND_CONFIG`] with the ZIP 320 queue retrying every second.
pub const TEX_CONFIG: &str = "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n[policy]\nmin_confirmations = 1\n[tex]\nrebroadcast_interval = \"1s\"\n";

/// The passphrase [`synced_key`] protects key `main` with.
pub const PASSPHRASE: &str = "correct-horse-battery-staple-7731";

/// The fake node on a runtime whose worker threads keep serving while the
/// test thread drives the binaries.
#[derive(Debug)]
pub struct FakeNodeHandle {
    rt: tokio::runtime::Runtime,
    pub node: FakeNode,
}

impl FakeNodeHandle {
    /// A fake node with `blocks` blocks mined.
    pub fn start(blocks: u32) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let node = rt.block_on(FakeNode::start(regtest_params()));
        node.mine(blocks);
        Self { rt, node }
    }

    /// The node's JSON-RPC URL, for `--zakura-rpc`.
    pub fn url(&self) -> &str {
        self.node.url()
    }

    /// The runtime the node serves on, for starting companions on it.
    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.rt
    }
}

/// A fake node with `blocks` mined and a daemon following it under
/// `config`, with key `main` initialised (protected by [`PASSPHRASE`], in
/// the returned passphrase file) and synced.
pub fn synced_key(blocks: u32, config: &str) -> (FakeNodeHandle, Fixture, PathBuf) {
    let n = FakeNodeHandle::start(blocks);
    let mut fx = Fixture::new("regtest");
    fx.write_config(config);
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();
    let pw = fx.passphrase_file(PASSPHRASE);
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    wait_spendable(&fx);
    (n, fx, pw)
}

/// Pay `zats` to one of `main`'s transparent receivers, confirm it and wait
/// until the key has scanned it.
pub fn fund_transparent(n: &FakeNodeHandle, fx: &Fixture, zats: u64) {
    let receiver = transparent_receivers(fx, "main")
        .into_iter()
        .next()
        .expect("a transparent receiver");
    n.node.mine_with_payments(&[(receiver, zats)]);
    n.node.mine(1);
    wait_spendable(fx);
}

/// The transparent receivers the key's wallet watches (the gap-limit set),
/// read from its wallet (the daemon holds no lock on the file; the read is
/// one SQLite query).
pub fn transparent_receivers(fx: &Fixture, key_id: &str) -> Vec<TransparentAddress> {
    let path = fx.key_dir(key_id).join("wallet.sqlite");
    let db = zcash_client_sqlite::WalletDb::for_path(
        &path,
        gyges_core::Network::Regtest.consensus_params(),
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

/// `gyges -k main sync wait --timeout 60s`, which must succeed.
pub fn wait_spendable(fx: &Fixture) {
    let run = fx
        .gyges(&["-k", "main", "sync", "wait", "--timeout", "60s"])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
}

/// Spendable zatoshis of one pool in a `balance --json`, `None` when the
/// pool or its (zero, so omitted) spendable value is absent.
pub fn pool_spendable(balance: &serde_json::Value, pool: &str) -> Option<u64> {
    balance["pools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["pool"] == pool)
        .and_then(|p| p["spendable"].as_str())
        .map(|s| s.parse().unwrap())
}

/// Poll `tx sessions --include-finished --json` for key `main`, every
/// `every` for up to `timeout`, until the ZIP 320 row for `step1` is in
/// `state` (a `TEX_STATE_*` name).
pub fn wait_tex_state(
    fx: &Fixture,
    step1: &str,
    state: &str,
    timeout: Duration,
    every: Duration,
) -> serde_json::Value {
    let mut last = serde_json::Value::Null;
    poll_until(
        timeout,
        every,
        &format!("row never reached {state}"),
        || {
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
                    return Ok(row.clone());
                }
                last = row.clone();
            }
            Err(format!("last {last}"))
        },
    )
}
