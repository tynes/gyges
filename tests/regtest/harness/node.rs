//! The real `zakurad` for the end-to-end scenarios (TESTING.md §2.1).
//!
//! [`zakurad_binary`] finds the node: `ZAKURAD_BIN`, else the release pinned
//! in `versions.toml` downloaded into `target/regtest-bin/` and verified
//! against its sha256 (Linux only: Zakura publishes no other binaries).
//! [`Node`] runs it in regtest from a temporary directory with proof of work
//! disabled, every network upgrade through NU6.3 active at height 1, the
//! smallest retention window the node accepts, cookie authentication and a
//! configurable coinbase recipient, and drives it over JSON-RPC.
//!
//! Facts this module relies on, verified against v1.6.0 on 2026-10-21 and
//! recorded in `OVERVIEW.md` §4.3: `generate` mines instantly once
//! `mining.miner_address` is set; a regtest node activates only Canopy
//! unless `[network.testnet_parameters.activation_heights]` says otherwise;
//! `state.storage_mode.pruned.tx_retention` must be at least 1001 on
//! regtest; the RPC port opens about a second after start.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context as _, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::process::{
    KeptDir, download_verified, env_bin, free_port, kill, log_tail, move_into_place,
    regtest_bin_dir, spawn_logged, untar, wait_or_kill, wait_ready,
};

/// `tests/regtest/versions.toml`.
pub const VERSIONS: &str = include_str!("../versions.toml");

/// The transparent address Zakura itself uses as the default regtest miner
/// address; coinbases paid here belong to nobody in the scenarios.
pub const BURN_MINER_ADDRESS: &str = "tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV";

/// The smallest `tx_retention` a regtest node accepts (`MAX_BLOCK_REORG_HEIGHT + 1`).
pub const MIN_TX_RETENTION: u32 = 1001;

/// How deep a block is when the node finalizes it. A pruned node counts
/// `tx_retention` from its finalized tip, not from the chain tip, so its
/// `pruneheight` is `tip - FINALITY_DEPTH - (tx_retention - 1)` once that
/// is positive, and 0 before: with the smallest window, block 1 is pruned
/// at tip 2,002 (measured on v1.6.0, `OVERVIEW.md` §4.5).
pub const FINALITY_DEPTH: u32 = 1000;

#[derive(Debug, Deserialize)]
pub(crate) struct Versions {
    zakurad: ZakuradVersion,
    pub(crate) zainod: crate::zaino::ZainodVersion,
}

#[derive(Debug, Deserialize)]
struct ZakuradVersion {
    tag: String,
    sha256: BTreeMap<String, String>,
}

pub(crate) fn versions() -> Versions {
    toml::from_str(VERSIONS).expect("versions.toml parses")
}

/// Where `zakurad` is, or `None` when this platform has no pinned binary and
/// `ZAKURAD_BIN` is unset. On Linux a failed download is a panic, not a
/// skip, so CI cannot pass by accident.
pub fn zakurad_binary() -> Option<PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = env_bin("ZAKURAD_BIN") {
            return Some(p);
        }
        if cfg!(target_os = "linux") {
            Some(download_pinned().expect("download the pinned zakurad release"))
        } else {
            None
        }
    })
    .clone()
}

fn download_pinned() -> anyhow::Result<PathBuf> {
    let v = versions().zakurad;
    let platform = format!("linux-{}", std::env::consts::ARCH);
    let expected = v
        .sha256
        .get(&platform)
        .with_context(|| format!("versions.toml has no sha256 for {platform}"))?;
    let dir = regtest_bin_dir().join(format!("zakurad-{}-{platform}", v.tag));
    let bin = dir.join("bin/zakurad");
    if bin.is_file() {
        return Ok(bin);
    }
    if dir.exists() {
        // The directory without its binary: an interrupted earlier run, or a
        // CI cache that kept the tree but trimmed the file. `rename` below
        // cannot replace a non-empty directory, so clear it first.
        eprintln!("removing incomplete {}", dir.display());
        fs::remove_dir_all(&dir).with_context(|| format!("remove incomplete {}", dir.display()))?;
    }
    fs::create_dir_all(regtest_bin_dir())?;
    let archive = format!("zakurad-{}-{platform}.tar.gz", v.tag);
    let url = format!(
        "https://github.com/zakura-core/zakura/releases/download/{}/{archive}",
        v.tag
    );
    let tmp = regtest_bin_dir().join(format!("{archive}.{}.part", std::process::id()));
    download_verified(&url, &tmp, expected)?;
    let staging = regtest_bin_dir().join(format!(
        "{}.{}.extract",
        dir.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    fs::create_dir_all(&staging)?;
    untar(&tmp, &staging)?;
    let _ = fs::remove_file(&tmp);
    if !staging.join("bin/zakurad").is_file() {
        bail!("{archive} has no bin/zakurad");
    }
    move_into_place(&staging, &dir, &bin)?;
    Ok(bin)
}

/// How to run the node.
#[derive(Clone, Debug)]
pub struct NodeOpts {
    /// Where `generate` pays the coinbase.
    pub miner_address: String,
    /// `state.storage_mode.pruned.tx_retention`.
    pub tx_retention: u32,
    /// Keep every block and transaction (no `storage_mode` line, so the
    /// node's default `archive`); `tx_retention` is then ignored. The
    /// archival node behind zaino ([`crate::Fallback`]) runs this way.
    pub archive: bool,
}

impl Default for NodeOpts {
    fn default() -> Self {
        Self {
            miner_address: BURN_MINER_ADDRESS.into(),
            tx_retention: MIN_TX_RETENTION,
            archive: false,
        }
    }
}

/// A running regtest `zakurad`. Killed on drop; the directory is kept when
/// `GYGES_TEST_KEEP` is set.
#[derive(Debug)]
pub struct Node {
    dir: KeptDir,
    child: Option<Child>,
    opts: NodeOpts,
    rpc_port: u16,
    p2p_port: u16,
    zakura_port: u16,
    client: reqwest::blocking::Client,
}

impl Node {
    /// Start a node from an empty state, or `None` with a message on stderr
    /// when no `zakurad` is available on this platform.
    pub fn start_or_skip(opts: NodeOpts) -> Option<Self> {
        if zakurad_binary().is_none() {
            eprintln!(
                "skipping: no zakurad for this platform (Zakura publishes Linux binaries only); \
                 set ZAKURAD_BIN to run the node scenarios"
            );
            return None;
        }
        Some(Self::start(opts).expect("start zakurad"))
    }

    /// Start a node from an empty state.
    pub fn start(opts: NodeOpts) -> anyhow::Result<Self> {
        let dir = KeptDir::new("node")?;
        for sub in ["state", "cookie", "identity"] {
            fs::create_dir_all(dir.path().join(sub))?;
        }
        let mut node = Self {
            dir,
            child: None,
            opts,
            rpc_port: free_port(),
            p2p_port: free_port(),
            zakura_port: free_port(),
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()?,
        };
        node.spawn(0)?;
        Ok(node)
    }

    /// Where the node backs up its non-finalized blocks, one file per hash.
    fn backup_dir(&self) -> PathBuf {
        self.dir.path().join("state/non_finalized_state/regtest")
    }

    /// Block until every non-finalized block of the best chain (the newest
    /// [`FINALITY_DEPTH`]) is in the backup directory. The node writes the
    /// backup at most every five seconds after a change and only while
    /// running; a stop before that loses the blocks. Finalized blocks are
    /// on disk already and leave the backup.
    pub fn wait_for_backup(&self) {
        let tip = self.tip_height();
        let first = (tip + 1).saturating_sub(FINALITY_DEPTH).max(1);
        let hashes: Vec<String> = (first..=tip).map(|h| self.block_hash(h)).collect();
        crate::poll_until(
            Duration::from_secs(30),
            Duration::from_millis(200),
            "non-finalized backup never caught up",
            || {
                let present: std::collections::HashSet<String> = fs::read_dir(self.backup_dir())
                    .map(|rd| {
                        rd.flatten()
                            .map(|e| e.file_name().to_string_lossy().into_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                if hashes.iter().all(|h| present.contains(h)) {
                    return Ok(());
                }
                Err(format!(
                    "{} of {} blocks in {}",
                    hashes.iter().filter(|h| present.contains(*h)).count(),
                    hashes.len(),
                    self.backup_dir().display()
                ))
            },
        );
    }

    fn config_path(&self) -> PathBuf {
        self.dir.path().join("zakura.toml")
    }

    /// The node's log (stdout and stderr).
    pub fn log_path(&self) -> PathBuf {
        self.dir.path().join("zakurad.log")
    }

    pub fn cookie_path(&self) -> PathBuf {
        self.dir.path().join("cookie/.cookie")
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.rpc_addr())
    }

    /// The JSON-RPC listen address, `127.0.0.1:<port>`.
    pub fn rpc_addr(&self) -> String {
        format!("127.0.0.1:{}", self.rpc_port)
    }

    pub fn opts(&self) -> &NodeOpts {
        &self.opts
    }

    fn write_config(&self) -> anyhow::Result<()> {
        let d = self.dir.path().display();
        let storage = if self.opts.archive {
            String::new()
        } else {
            format!(
                "storage_mode = {{ pruned = {{ tx_retention = {} }} }}",
                self.opts.tx_retention
            )
        };
        let config = format!(
            r#"# Written by the gyges regtest harness.
[network]
network = "Regtest"
listen_addr = "127.0.0.1:{p2p}"
cache_dir = false
identity_dir = "{d}/identity"

[network.zakura]
listen_addr = "127.0.0.1:{zakura}"

# Without this a regtest node activates Canopy only; Gyges expects every
# upgrade through NU6.3 at height 1 (gyges_core::network). The NU6.1
# activation block must pay the one-time lockbox disbursement (ZIP 271) and
# the node refuses an empty list, so it pays nothing to the P2SH address
# Zakura's own testnet constants use.
[network.testnet_parameters]
lockbox_disbursements = [{{ address = "t2RnBRiqrN1nW4ecZs1Fj3WWjNdnSs4kiX8", amount = 0 }}]

[network.testnet_parameters.activation_heights]
NU5 = 1
NU6 = 1
"NU6.1" = 1
"NU6.2" = 1
"NU6.3" = 1

[state]
cache_dir = "{d}/state"
{storage}

[rpc]
listen_addr = "127.0.0.1:{rpc}"
cookie_dir = "{d}/cookie"
enable_cookie_auth = true

[mining]
miner_address = "{miner}"

[consensus]
checkpoint_sync = false

[tracing]
use_color = false
"#,
            p2p = self.p2p_port,
            zakura = self.zakura_port,
            rpc = self.rpc_port,
            miner = self.opts.miner_address,
        );
        fs::write(self.config_path(), config)?;
        Ok(())
    }

    /// Start the process and wait until it serves RPC with at least
    /// `min_tip` blocks (the genesis commit and the restore of backed-up
    /// blocks both happen after the RPC port opens).
    fn spawn(&mut self, min_tip: u32) -> anyhow::Result<()> {
        assert!(self.child.is_none(), "node already running");
        self.write_config()?;
        let bin = zakurad_binary().context("no zakurad binary")?;
        let child = spawn_logged(
            Command::new(&bin)
                .arg("-c")
                .arg(self.config_path())
                .arg("start")
                .current_dir(self.dir.path()),
            &self.log_path(),
        )?;
        let log = self.log_path();
        let child = wait_ready(
            "zakurad",
            child,
            Some(&log),
            Duration::from_secs(90),
            Duration::from_millis(100),
            || {
                let tip = self
                    .rpc("getblock", json!(["0", 1]))
                    .and_then(|_| self.rpc("getblockcount", json!([])))
                    .map_err(|e| format!("{e:#}"))?;
                match tip.as_u64() {
                    Some(h) if h >= u64::from(min_tip) => Ok(()),
                    _ => Err(format!("tip {tip}, waiting for {min_tip}")),
                }
            },
        )?;
        self.child = Some(child);
        Ok(())
    }

    /// The last lines of the node's log, for failure messages.
    pub fn log_tail(&self) -> String {
        log_tail(&self.log_path())
    }

    /// One JSON-RPC call; `Err` carries the node's error object or the
    /// transport failure.
    pub fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let cookie = fs::read_to_string(self.cookie_path()).context("read cookie")?;
        let (user, secret) = cookie.trim().split_once(':').context("cookie has no ':'")?;
        let resp: Value = self
            .client
            .post(self.url())
            .basic_auth(user, Some(secret))
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .with_context(|| format!("{method}: send"))?
            .error_for_status()
            .with_context(|| format!("{method}: http"))?
            .json()
            .with_context(|| format!("{method}: not JSON"))?;
        if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
            bail!("{method}: {err}");
        }
        Ok(resp["result"].clone())
    }

    /// One JSON-RPC call that must succeed, its result deserialized.
    #[track_caller]
    pub fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> T {
        self.rpc(method, params)
            .and_then(|v| Ok(serde_json::from_value(v)?))
            .unwrap_or_else(|e| panic!("{method}: {e:#}"))
    }

    /// `generate n`: the hashes of the new blocks.
    pub fn mine(&self, n: u32) -> Vec<String> {
        self.call("generate", json!([n]))
    }

    pub fn tip_height(&self) -> u32 {
        self.call("getblockcount", json!([]))
    }

    pub fn block_hash(&self, height: u32) -> String {
        self.call("getblockhash", json!([height]))
    }

    pub fn invalidate_block(&self, hash: &str) {
        self.call::<Value>("invalidateblock", json!([hash]));
    }

    /// Txids in the mempool.
    pub fn mempool(&self) -> Vec<String> {
        self.call("getrawmempool", json!([]))
    }

    /// Raw transaction hex, from the chain or the mempool.
    pub fn raw_transaction(&self, txid: &str) -> String {
        self.call("getrawtransaction", json!([txid, 0]))
    }

    /// Height the transaction is mined at, if it is.
    pub fn mined_height(&self, txid: &str) -> Option<u32> {
        let v = self.rpc("getrawtransaction", json!([txid, 1])).ok()?;
        v.get("height")
            .and_then(Value::as_i64)
            .filter(|h| *h >= 0)
            .map(|h| u32::try_from(h).unwrap())
    }

    /// `getblockchaininfo.pruneheight`: the lowest height whose block body
    /// the node still stores (0 for an archive node or before any pruning).
    pub fn prune_height(&self) -> u32 {
        let info: Value = self.call("getblockchaininfo", json!([]));
        info["pruneheight"]
            .as_u64()
            .map_or(0, |h| u32::try_from(h).unwrap())
    }

    /// `getblock(h, 0)`: the serialized block as hex.
    pub fn raw_block(&self, height: u32) -> String {
        self.call("getblock", json!([height.to_string(), 0]))
    }

    /// `submitblock`: the node answers `null` for a block it accepted and a
    /// BIP 22 reason string (`"duplicate"`, `"rejected"`, …) otherwise.
    pub fn submit_block(&self, hex: &str) -> anyhow::Result<()> {
        match self.rpc("submitblock", json!([hex]))? {
            Value::Null => Ok(()),
            Value::String(r) if r == "duplicate" => Ok(()),
            other => bail!("submitblock: {other}"),
        }
    }

    pub fn send_raw_transaction(&self, hex: &str) -> anyhow::Result<String> {
        Ok(serde_json::from_value(
            self.rpc("sendrawtransaction", json!([hex]))?,
        )?)
    }

    /// What the coinbase of `height` paid to the transparent pool (zatoshis),
    /// read from `getblock(h, 1).valuePools`.
    pub fn coinbase_value(&self, height: u32) -> u64 {
        let block: Value = self.call("getblock", json!([height.to_string(), 1]));
        block["valuePools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "transparent")
            .and_then(|p| p["valueDeltaZat"].as_u64())
            .expect("transparent valueDeltaZat")
    }

    /// `stop` over RPC, then wait; kill after ten seconds.
    pub fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = self.rpc("stop", json!([]));
        wait_or_kill(&mut child, Duration::from_secs(10));
    }

    /// Stop and start again with new options over the same chain and ports
    /// (the cookie is rotated by the node; Gyges re-reads it). Waits for the
    /// non-finalized backup first, so no block is lost.
    pub fn restart(&mut self, opts: NodeOpts) -> anyhow::Result<()> {
        self.wait_for_backup();
        let tip = self.tip_height();
        self.stop();
        self.opts = opts;
        // zakurad 1.6.0 sometimes dies while starting over a restored
        // non-finalized backup: its legacy genesis bootstrap finds the sync
        // lifecycle already past `LegacyBootstrap` and exits with
        // "genesis apply handoff failed: illegal sync lifecycle transition"
        // (seen on about one CI run in three, never on a fresh state). The
        // state on disk is intact, so starting again is enough.
        let mut attempt = 1;
        loop {
            match self.spawn(tip) {
                Ok(()) => return Ok(()),
                Err(e) if attempt < RESTART_ATTEMPTS && e.to_string().contains(HANDOFF_RACE) => {
                    eprintln!(
                        "zakurad restart attempt {attempt} hit the genesis handoff race; retrying"
                    );
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// How many times [`Node::restart`] starts the node before giving up on the
/// handoff race.
const RESTART_ATTEMPTS: u32 = 4;

/// The text zakurad 1.6.0 exits with when the race in [`Node::restart`] bites.
const HANDOFF_RACE: &str = "genesis apply handoff failed: illegal sync lifecycle transition";

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            kill(&mut child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_file_pins_zainod_and_its_crate_hash() {
        let v = versions().zainod;
        assert!(v.version.split('.').count() == 3, "{}", v.version);
        assert_eq!(v.sha256.len(), 64);
        assert!(v.sha256.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn versions_file_pins_a_tag_and_both_linux_hashes() {
        let v = versions().zakurad;
        assert!(v.tag.starts_with('v'), "{}", v.tag);
        for platform in ["linux-x86_64", "linux-aarch64"] {
            let h = &v.sha256[platform];
            assert_eq!(h.len(), 64, "{platform}");
            assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "{platform}");
        }
    }
}
