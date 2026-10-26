//! Helpers shared by the scenarios against the real `zakurad`
//! (`node.rs`, `backfill.rs`). Each test target uses a subset.

#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use gyges_regtest::{Fixture, Node, poll_until, pool_spendable};
use transparent::address::TransparentAddress;
use zcash_protocol::consensus::NetworkType;

/// 23×abandon + art: the all-zero-entropy BIP 39 vector.
pub fn mnemonic() -> String {
    "abandon ".repeat(23) + "art"
}

pub fn regtest() -> gyges_core::ConsensusParams {
    gyges_core::Network::Regtest.consensus_params()
}

/// Account 0's first external transparent address for [`mnemonic`], the
/// way the wallet derives it (`zcash_client_sqlite` → ZIP 32 account key →
/// external chain, index 0), so the node can mine to it before the key
/// exists in Gyges.
pub fn test_key_transparent() -> TransparentAddress {
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

pub fn test_key_transparent_address() -> String {
    gyges_chain::compact::encode_transparent_address(NetworkType::Regtest, &test_key_transparent())
}

pub fn daemon_config(fx: &Fixture) {
    fx.write_config(
        "[vault]\nscrypt_work_factor = 10\n\
         [zakura_rpc]\npoll_interval_secs = 1\nmin_retention_blocks = 1000\n\
         [policy]\nmin_confirmations = 1\n\
         [tex]\nrebroadcast_interval = \"1s\"\n",
    );
}

pub fn node_args(node: &Node) -> [String; 4] {
    [
        "--zakura-rpc".into(),
        node.url(),
        "--zakura-cookie".into(),
        node.cookie_path().display().to_string(),
    ]
}

pub fn start_daemon(fx: &mut Fixture, node: &Node) {
    let args = node_args(node);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    fx.start_daemon(&args).unwrap();
}

/// `balance --json` for a key.
pub fn balance(fx: &Fixture, key: &str) -> serde_json::Value {
    let run = fx.gyges(&["-k", key, "balance", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    run.json()
}

/// Spendable zatoshis of one pool in a `balance --json`, 0 when omitted.
pub fn spendable(b: &serde_json::Value, pool: &str) -> u64 {
    pool_spendable(b, pool).unwrap_or(0)
}

pub fn sync_wait(fx: &Fixture, key: &str, extra: &[&str]) {
    sync_wait_within(fx, key, "180s", extra);
}

/// `sync wait` with a timeout of the CLI's form (`"600s"`).
pub fn sync_wait_within(fx: &Fixture, key: &str, timeout: &str, extra: &[&str]) {
    let mut args = vec!["-k", key, "sync", "wait", "--timeout", timeout];
    args.extend_from_slice(extra);
    let run = fx.gyges(&args).run();
    assert_eq!(run.code(), 0, "{run:?}");
}

pub fn wait_for_txid(fx: &Fixture, key: &str, txid: &str) {
    sync_wait(fx, key, &["--txid", txid, "--confirmations", "1"]);
}

/// The balance can lag `sync wait` by a tick; poll it.
pub fn wait_balance(
    fx: &Fixture,
    key: &str,
    ok: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(250),
        "balance never settled",
        || {
            let b = balance(fx, key);
            if ok(&b) {
                return Ok(b);
            }
            Err(b.to_string())
        },
    )
}

/// Every file in `dir` is 0600 and free of `secrets`.
pub fn sweep_logs(dir: &Path, secrets: &[&str]) {
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
