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
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use serde::Deserialize;
use serde_json::{Value, json};

/// `tests/regtest/versions.toml`.
pub const VERSIONS: &str = include_str!("../versions.toml");

/// The transparent address Zakura itself uses as the default regtest miner
/// address; coinbases paid here belong to nobody in the scenarios.
pub const BURN_MINER_ADDRESS: &str = "tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV";

/// The smallest `tx_retention` a regtest node accepts (`MAX_BLOCK_REORG_HEIGHT + 1`).
pub const MIN_TX_RETENTION: u32 = 1001;

#[derive(Debug, Deserialize)]
struct Versions {
    zakurad: ZakuradVersion,
}

#[derive(Debug, Deserialize)]
struct ZakuradVersion {
    tag: String,
    sha256: BTreeMap<String, String>,
}

fn versions() -> Versions {
    toml::from_str(VERSIONS).expect("versions.toml parses")
}

/// The release tag the harness pins.
pub fn pinned_tag() -> String {
    versions().zakurad.tag
}

/// Where `zakurad` is, or `None` when this platform has no pinned binary and
/// `ZAKURAD_BIN` is unset. On Linux a failed download is a panic, not a
/// skip, so CI cannot pass by accident.
pub fn zakurad_binary() -> Option<PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = std::env::var_os("ZAKURAD_BIN").filter(|p| !p.is_empty()) {
            let p = PathBuf::from(p);
            assert!(p.is_file(), "ZAKURAD_BIN={} is not a file", p.display());
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

/// `target/regtest-bin/`, beside the profile directory the tests run from.
fn regtest_bin_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // target/<profile>/deps/<test>-<hash> -> target/
    let target = exe
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("target dir");
    target.join("regtest-bin")
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
    fs::create_dir_all(regtest_bin_dir())?;
    let archive = format!("zakurad-{}-{platform}.tar.gz", v.tag);
    let url = format!(
        "https://github.com/zakura-core/zakura/releases/download/{}/{archive}",
        v.tag
    );
    let tmp = regtest_bin_dir().join(format!("{archive}.{}.part", std::process::id()));
    eprintln!("downloading {url}");
    let status = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&tmp)
        .arg(&url)
        .status()
        .context("run curl")?;
    if !status.success() {
        bail!("curl {url} failed: {status}");
    }
    let bytes = fs::read(&tmp)?;
    let digest = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&bytes))
    };
    if digest != *expected {
        let _ = fs::remove_file(&tmp);
        bail!("{archive}: sha256 {digest}, versions.toml expects {expected}");
    }
    let staging = regtest_bin_dir().join(format!(
        "{}.{}.extract",
        dir.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    fs::create_dir_all(&staging)?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&tmp)
        .arg("-C")
        .arg(&staging)
        .status()
        .context("run tar")?;
    if !status.success() {
        bail!("tar failed: {status}");
    }
    let _ = fs::remove_file(&tmp);
    if !staging.join("bin/zakurad").is_file() {
        bail!("{archive} has no bin/zakurad");
    }
    // Another test binary may have raced us to the same directory.
    match fs::rename(&staging, &dir) {
        Ok(()) => {}
        Err(_) if bin.is_file() => {
            let _ = fs::remove_dir_all(&staging);
        }
        Err(e) => return Err(e).context("move the extracted node into place"),
    }
    Ok(bin)
}

/// How to run the node.
#[derive(Clone, Debug)]
pub struct NodeOpts {
    /// Where `generate` pays the coinbase.
    pub miner_address: String,
    /// `state.storage_mode.pruned.tx_retention`.
    pub tx_retention: u32,
}

impl Default for NodeOpts {
    fn default() -> Self {
        Self {
            miner_address: BURN_MINER_ADDRESS.into(),
            tx_retention: MIN_TX_RETENTION,
        }
    }
}

/// A running regtest `zakurad`. Killed on drop; the directory is kept when
/// `GYGES_TEST_KEEP` is set.
#[derive(Debug)]
pub struct Node {
    dir: Option<tempfile::TempDir>,
    dir_path: PathBuf,
    child: Option<Child>,
    opts: NodeOpts,
    rpc_port: u16,
    p2p_port: u16,
    zakura_port: u16,
    client: reqwest::blocking::Client,
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    l.local_addr().unwrap().port()
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
        let dir = tempfile::tempdir()?;
        let dir_path = dir.path().to_path_buf();
        for sub in ["state", "cookie", "identity"] {
            fs::create_dir_all(dir_path.join(sub))?;
        }
        let mut node = Self {
            dir: Some(dir),
            dir_path,
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
        self.dir_path.join("state/non_finalized_state/regtest")
    }

    /// Block until every block of the best chain is in the backup directory.
    /// The node writes the backup at most every five seconds after a change
    /// and only while running; a stop before that loses the blocks (they are
    /// non-finalized until 1,000 deep on regtest).
    pub fn wait_for_backup(&self) {
        let tip = self.tip_height();
        let hashes: Vec<String> = (1..=tip).map(|h| self.block_hash(h)).collect();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let present: std::collections::HashSet<String> = fs::read_dir(self.backup_dir())
                .map(|rd| {
                    rd.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            if hashes.iter().all(|h| present.contains(h)) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "non-finalized backup never caught up: {} of {} blocks in {}",
                hashes.iter().filter(|h| present.contains(*h)).count(),
                hashes.len(),
                self.backup_dir().display()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn config_path(&self) -> PathBuf {
        self.dir_path.join("zakura.toml")
    }

    /// The node's log (stdout and stderr).
    pub fn log_path(&self) -> PathBuf {
        self.dir_path.join("zakurad.log")
    }

    pub fn cookie_path(&self) -> PathBuf {
        self.dir_path.join("cookie/.cookie")
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn opts(&self) -> &NodeOpts {
        &self.opts
    }

    fn write_config(&self) -> anyhow::Result<()> {
        let d = self.dir_path.display();
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
storage_mode = {{ pruned = {{ tx_retention = {retention} }} }}

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
            retention = self.opts.tx_retention,
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
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path())?;
        let bin = zakurad_binary().context("no zakurad binary")?;
        let child = Command::new(&bin)
            .arg("-c")
            .arg(self.config_path())
            .arg("start")
            .current_dir(&self.dir_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()
            .with_context(|| format!("spawn {}", bin.display()))?;
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait()? {
                self.child = None;
                bail!(
                    "zakurad exited during startup: {status}\n{}",
                    self.log_tail()
                );
            }
            if self.cookie_path().is_file()
                && self.rpc("getblock", json!(["0", 1])).is_ok()
                && self
                    .rpc("getblockcount", json!([]))
                    .ok()
                    .and_then(|v| v.as_u64())
                    .is_some_and(|h| h >= u64::from(min_tip))
            {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!("zakurad did not answer RPC in time\n{}", self.log_tail());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The last lines of the node's log, for failure messages.
    pub fn log_tail(&self) -> String {
        let text = fs::read_to_string(self.log_path()).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(30);
        lines[start..].join("\n")
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

    /// `generate n`: the hashes of the new blocks.
    pub fn mine(&self, n: u32) -> Vec<String> {
        let v = self.rpc("generate", json!([n])).expect("generate");
        v.as_array()
            .expect("array of hashes")
            .iter()
            .map(|h| h.as_str().unwrap().to_string())
            .collect()
    }

    pub fn tip_height(&self) -> u32 {
        u32::try_from(
            self.rpc("getblockcount", json!([]))
                .expect("getblockcount")
                .as_u64()
                .unwrap(),
        )
        .unwrap()
    }

    pub fn block_hash(&self, height: u32) -> String {
        self.rpc("getblockhash", json!([height]))
            .expect("getblockhash")
            .as_str()
            .unwrap()
            .to_string()
    }

    pub fn invalidate_block(&self, hash: &str) {
        self.rpc("invalidateblock", json!([hash]))
            .expect("invalidateblock");
    }

    /// Txids in the mempool.
    pub fn mempool(&self) -> Vec<String> {
        self.rpc("getrawmempool", json!([]))
            .expect("getrawmempool")
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect()
    }

    /// Raw transaction hex, from the chain or the mempool.
    pub fn raw_transaction(&self, txid: &str) -> String {
        self.rpc("getrawtransaction", json!([txid, 0]))
            .expect("getrawtransaction")
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Height the transaction is mined at, if it is.
    pub fn mined_height(&self, txid: &str) -> Option<u32> {
        let v = self.rpc("getrawtransaction", json!([txid, 1])).ok()?;
        v.get("height")
            .and_then(Value::as_i64)
            .filter(|h| *h >= 0)
            .map(|h| u32::try_from(h).unwrap())
    }

    pub fn send_raw_transaction(&self, hex: &str) -> anyhow::Result<String> {
        Ok(self
            .rpc("sendrawtransaction", json!([hex]))?
            .as_str()
            .unwrap()
            .to_string())
    }

    /// What the coinbase of `height` paid to the transparent pool (zatoshis),
    /// read from `getblock(h, 1).valuePools`.
    pub fn coinbase_value(&self, height: u32) -> u64 {
        let block = self
            .rpc("getblock", json!([height.to_string(), 1]))
            .expect("getblock");
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
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() > deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => return,
            }
        }
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

    /// Keep the directory for inspection and return its path.
    pub fn keep(&mut self) -> PathBuf {
        if let Some(dir) = self.dir.take() {
            return dir.keep();
        }
        self.dir_path.clone()
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
            let _ = child.kill();
            let _ = child.wait();
        }
        if std::env::var_os("GYGES_TEST_KEEP").is_some() {
            let path = self.keep();
            eprintln!("GYGES_TEST_KEEP: left node at {}", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
