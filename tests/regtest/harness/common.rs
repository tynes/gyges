//! Wallet helpers the scenarios share: the daemon configurations, the known
//! test key and a burn address, `gyges` waits and balance checks, the log
//! sweep, and the setup the scenarios against the real `zakurad` repeat.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use transparent::address::TransparentAddress;
use zcash_protocol::consensus::NetworkType;

use crate::{
    Fixture, Node, NodeOpts, PASSPHRASE, Run, poll_until, pool_spendable, transparent_receivers,
};

/// Fast scrypt and a one-second node poll, then the `$extra` lines. With no
/// extra lines the text ends inside `[zakura_rpc]`.
macro_rules! config {
    ($($extra:literal),*) => {
        concat!(
            "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n"
            $(, $extra)*
        )
    };
}

/// Fast scrypt and a one-second node poll.
pub const FAST_CONFIG: &str = config!();

/// [`FAST_CONFIG`] with funds spendable after one confirmation.
pub const SPEND_CONFIG: &str = config!("[policy]\nmin_confirmations = 1\n");

/// [`SPEND_CONFIG`] with the ZIP 320 queue retrying every second.
pub const TEX_CONFIG: &str = config!(
    "[policy]\nmin_confirmations = 1\n",
    "[tex]\nrebroadcast_interval = \"1s\"\n"
);

/// [`TEX_CONFIG`] for a daemon on the real node, which accepts the node's
/// smallest retention window.
pub const NODE_CONFIG: &str = config!(
    "min_retention_blocks = 1000\n",
    "[policy]\nmin_confirmations = 1\n",
    "[tex]\nrebroadcast_interval = \"1s\"\n"
);

/// 23×abandon + art: the all-zero-entropy BIP 39 vector.
pub fn mnemonic() -> String {
    "abandon ".repeat(23) + "art"
}

pub fn regtest() -> gyges_core::ConsensusParams {
    gyges_core::Network::Regtest.consensus_params()
}

/// The pubkey hash behind [`burn_t_address`].
const BURN_PKH: [u8; 20] = [0x42; 20];

/// A regtest P2PKH address nobody holds the key to.
pub fn burn_t_address() -> String {
    gyges_chain::compact::encode_transparent_address(
        NetworkType::Regtest,
        &TransparentAddress::PublicKeyHash(BURN_PKH),
    )
}

/// The ZIP 320 (`texregtest1…`) form of [`burn_t_address`].
pub fn burn_tex_address() -> String {
    zcash_keys::address::Address::Tex(BURN_PKH).encode(&regtest())
}

/// The BIP 39 seed of [`mnemonic`], with no passphrase.
fn test_seed() -> [u8; 64] {
    bip0039::Mnemonic::<bip0039::English>::from_phrase(mnemonic())
        .unwrap()
        .to_seed("")
}

/// Account 0's spending key for [`test_seed`].
fn test_usk(seed: &[u8]) -> zcash_keys::keys::UnifiedSpendingKey {
    zcash_keys::keys::UnifiedSpendingKey::from_seed(&regtest(), seed, zip32::AccountId::ZERO)
        .unwrap()
}

/// Account 0's first external transparent address for [`mnemonic`], the
/// way the wallet derives it (`zcash_client_sqlite` → ZIP 32 account key →
/// external chain, index 0), so the node can mine to it before the key
/// exists in Gyges.
pub fn test_key_transparent() -> TransparentAddress {
    use transparent::keys::IncomingViewingKey as _;
    let (addr, _) = test_usk(&test_seed())
        .transparent()
        .to_account_pubkey()
        .derive_external_ivk()
        .unwrap()
        .default_address();
    addr
}

/// The Keystone pairing export (`ur:zcash-accounts`) of [`mnemonic`]'s
/// account 0, reporting `device_version`, as the frames a camera sees, one
/// per line. The UFVK has the device's shape: the seed's Orchard and
/// transparent items, no Sapling.
pub fn keystone_export(device_version: Option<&str>) -> String {
    use zcash_address::unified::{Container as _, Encoding as _, Fvk, Ufvk};
    let seed = test_seed();
    let usk = test_usk(&seed);
    let payload = gyges_qr::Payload::Accounts(gyges_qr::Accounts {
        seed_fingerprint: zip32::fingerprint::SeedFingerprint::from_seed(&seed)
            .unwrap()
            .to_bytes()
            .to_vec(),
        accounts: vec![gyges_qr::Account {
            ufvk: {
                let full = usk.to_unified_full_viewing_key().encode(&regtest());
                let (net, ufvk) = Ufvk::decode(&full).unwrap();
                let items: Vec<Fvk> = ufvk
                    .items()
                    .into_iter()
                    .filter(|i| !matches!(i, Fvk::Sapling(_)))
                    .collect();
                Ufvk::try_from_items(items).unwrap().encode(&net)
            },
            index: 0,
            name: Some("Keystone".into()),
        }],
        device_version: device_version.map(Into::into),
    });
    let mut frames = payload.frames(gyges_qr::DEFAULT_FRAGMENT_LEN).unwrap();
    let n = if frames.is_single() {
        1
    } else {
        2 * frames.fragment_count()
    };
    (0..n)
        .map(|_| frames.next_frame().unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The Keystone that [`keystone_export`] pairs: [`mnemonic`]'s account 0,
/// as `gyges_core::keystone::emulator` signs with it.
pub fn keystone_device() -> gyges_core::keystone::emulator::Device {
    let seed = test_seed();
    gyges_core::keystone::emulator::Device {
        usk: test_usk(&seed),
        fingerprint: zip32::fingerprint::SeedFingerprint::from_seed(&seed).unwrap(),
        coin_type: 1,
    }
}

pub fn test_key_transparent_address() -> String {
    gyges_chain::compact::encode_transparent_address(NetworkType::Regtest, &test_key_transparent())
}

/// Node options whose coinbases pay [`test_key_transparent_address`].
pub fn test_key_miner() -> NodeOpts {
    NodeOpts {
        miner_address: test_key_transparent_address(),
        ..NodeOpts::default()
    }
}

/// Start `fx`'s daemon on `node`, with its cookie.
pub fn start_daemon(fx: &mut Fixture, node: &Node) {
    let url = node.url();
    let cookie = node.cookie_path().display().to_string();
    fx.start_daemon(&["--zakura-rpc", &url, "--zakura-cookie", &cookie])
        .unwrap();
}

/// `balance --json` for a key.
#[track_caller]
pub fn balance(fx: &Fixture, key: &str) -> serde_json::Value {
    fx.gyges(&["-k", key, "balance", "--json"]).ok().json()
}

/// Spendable zatoshis of one pool in a `balance --json`, 0 when omitted.
pub fn spendable(b: &serde_json::Value, pool: &str) -> u64 {
    pool_spendable(b, pool).unwrap_or(0)
}

#[track_caller]
pub fn sync_wait(fx: &Fixture, key: &str, extra: &[&str]) {
    sync_wait_within(fx, key, "180s", extra);
}

/// `sync wait` with a timeout of the CLI's form (`"600s"`).
#[track_caller]
pub fn sync_wait_within(fx: &Fixture, key: &str, timeout: &str, extra: &[&str]) {
    fx.gyges(&["-k", key, "sync", "wait", "--timeout", timeout])
        .args(extra)
        .ok();
}

/// `sync wait --txid` until `txid` has `confirmations`.
#[track_caller]
pub fn wait_for_txid(fx: &Fixture, key: &str, txid: &str, confirmations: u32) {
    let confirmations = confirmations.to_string();
    sync_wait(
        fx,
        key,
        &["--txid", txid, "--confirmations", &confirmations],
    );
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

/// Repeat `sync wait --timeout 3s` for `key` until it exits 7 with
/// `pruned-past-scan-tip`, for up to `timeout`; that run.
pub fn wait_stalled(fx: &Fixture, key: &str, timeout: Duration) -> Run {
    poll_until(timeout, Duration::ZERO, "no stall", || {
        let run = fx
            .gyges(&["-k", key, "sync", "wait", "--timeout", "3s"])
            .run();
        if run.code() == 7 && run.stderr.contains("pruned-past-scan-tip") {
            return Ok(run);
        }
        Err(format!("{run:?}"))
    })
}

/// Both txids of a `tx send --to tex…` run: step 1 is the first stdout
/// line, step 2 the last word of the `tex pending` line on stderr. Whether
/// step 2 is on stdout as well is the caller's to check.
#[track_caller]
pub fn parse_tex_txids(run: &Run) -> (String, String) {
    let s1 = run
        .stdout
        .lines()
        .next()
        .unwrap_or_else(|| panic!("no step 1 txid: {run:?}"))
        .to_string();
    assert_eq!(s1.len(), 64, "{run:?}");
    let pending = run
        .stderr
        .lines()
        .find(|l| l.starts_with("tex pending (step 2 of 2)"))
        .unwrap_or_else(|| panic!("no tex pending line: {run:?}"));
    let s2 = pending.rsplit(' ').next().unwrap().to_string();
    assert_eq!(s2.len(), 64, "{pending}");
    (s1, s2)
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

/// A daemon on `node` under [`NODE_CONFIG`], with key `main` restored from
/// [`mnemonic`] at the default birthday and synced until the coinbases of
/// blocks 1 and 2 (mined to [`test_key_miner`], mature by now) are
/// spendable. The fixture, its passphrase file and those coinbases' value.
pub fn funded_wallet(node: &Node) -> (Fixture, PathBuf, u64) {
    let funded = node.coinbase_value(1) + node.coinbase_value(2);
    assert!(funded > 0, "coinbases pay the transparent pool");
    let mut fx = Fixture::new("regtest");
    fx.write_config(NODE_CONFIG);
    start_daemon(&mut fx, node);
    let pw = fx.passphrase_file(PASSPHRASE);
    let run = fx
        .gyges(&["key", "restore", "--id", "main", "--stdin", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(mnemonic())
        .ok();
    assert_eq!(run.json()["birthday_height"], 1, "{run:?}");
    let watched: Vec<String> = transparent_receivers(&fx, "main")
        .iter()
        .map(|a| gyges_chain::compact::encode_transparent_address(NetworkType::Regtest, a))
        .collect();
    assert!(
        watched.contains(&test_key_transparent_address()),
        "the harness derives one of the wallet's own receivers: {watched:?}"
    );
    sync_wait(&fx, "main", &["--until", "spendable"]);
    let b = wait_balance(&fx, "main", |b| spendable(b, "POOL_TRANSPARENT") == funded);
    assert_eq!(b["total_spendable"], funded.to_string(), "{b}");
    (fx, pw, funded)
}

/// `tx shield --yes` for key `main`, then `mine` to get the txid it is
/// handed mined, then wait until the shielded funds are spendable with
/// nothing transparent left. A failed shield shows the node's log at `log`.
/// The txid and that balance.
pub fn shield(
    fx: &Fixture,
    pw: &Path,
    log: &Path,
    mine: impl FnOnce(&str),
) -> (String, serde_json::Value) {
    let run = fx
        .gyges(&["-k", "main", "tx", "shield", "--yes"])
        .env("GYGES_PASSPHRASE_FILE", pw)
        .ok_with_log(log);
    let txid = run.stdout.trim().to_string();
    assert_eq!(txid.len(), 64, "{run:?}");
    mine(&txid);
    wait_for_txid(fx, "main", &txid, 1);
    let b = wait_balance(fx, "main", |b| spendable(b, "POOL_IRONWOOD") > 0);
    assert_eq!(spendable(&b, "POOL_TRANSPARENT"), 0, "{b}");
    (txid, b)
}

/// `tx send --to <to> --amount <amount> --yes` from key `main`, which must
/// succeed; a failure shows the node's log at `log`.
#[track_caller]
pub fn send(fx: &Fixture, pw: &Path, log: &Path, to: &str, amount: &str) -> Run {
    fx.gyges(&[
        "-k", "main", "tx", "send", "--to", to, "--amount", amount, "--yes",
    ])
    .env("GYGES_PASSPHRASE_FILE", pw)
    .ok_with_log(log)
}
