//! The archival endpoint for the backfill scenarios (ROADMAP.md M2, sixth
//! item; `OVERVIEW.md` §4.5).
//!
//! zaino cannot sit in front of the wallet's pruned node: it fetches mined
//! transactions and subtree roots from its node on every request, and those
//! are gone below a pruned node's window. So [`Fallback`] runs three
//! processes:
//! * the wallet's pruned `zakurad`, where blocks are mined and transactions
//!   broadcast;
//! * an archive-mode `zakurad` that receives each block by `submitblock`;
//! * [`Zaino`], `zainod` with `backend = "rpc"` in front of the archive node.
//!
//! The archive node copies blocks by `submitblock` rather than by peering.
//! Two regtest nodes on the legacy p2p stack do sync, but the archive node
//! took about 27 s to notice 20 new blocks (2026-10-26, v1.6.0), and
//! `submitblock` makes the copy finish before `mine` returns. Blocks are
//! copied in chunks smaller than the pruned node's window, so no block is
//! pruned before it is copied.
//!
//! zaino reads the node's cookie once, at start; `zakurad` rotates it at
//! every start. [`Fallback::restart_archive`] therefore restarts zaino too
//! (§4.5, deviation 3).

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use gyges_chain::{ArtiTorLwdBackend, ChainBackend as _, Transport};
use serde::Deserialize;
use zcash_protocol::local_consensus::LocalNetwork;

use crate::node::{download_verified, free_port, regtest_bin_dir, versions};
use crate::{Node, NodeOpts, zakurad_binary};

/// `[zainod]` in `versions.toml`.
#[derive(Debug, Deserialize)]
pub(crate) struct ZainodVersion {
    pub(crate) version: String,
    /// Of the crates.io `.crate` file.
    pub(crate) sha256: String,
}

/// Where `zainod` is: `ZAINOD_BIN`, else the build cached in
/// `target/regtest-bin/`, else a fresh build of the pinned crate on Linux
/// when `GYGES_BUILD_ZAINOD` is set (the CI `regtest` job; the build takes
/// minutes and gigabytes the `check` job has no room for). `None`
/// otherwise. A failed build is a panic, not a skip, so CI cannot pass by
/// accident.
pub fn zainod_binary() -> Option<PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = std::env::var_os("ZAINOD_BIN").filter(|p| !p.is_empty()) {
            let p = PathBuf::from(p);
            assert!(p.is_file(), "ZAINOD_BIN={} is not a file", p.display());
            return Some(p);
        }
        let cached = pinned_dir().join("bin/zainod");
        if cached.is_file() {
            return Some(cached);
        }
        if cfg!(target_os = "linux") && std::env::var_os("GYGES_BUILD_ZAINOD").is_some() {
            Some(build_pinned().expect("build the pinned zainod"))
        } else {
            None
        }
    })
    .clone()
}

fn pinned_dir() -> PathBuf {
    regtest_bin_dir().join(format!("zainod-{}", versions().zainod.version))
}

/// Download the pinned `.crate`, check its sha256, and `cargo install
/// --locked` it into [`pinned_dir`].
///
/// The source and the build's target directory live in a temporary
/// directory outside the repository, removed afterwards. Outside, because
/// cargo refuses a package unpacked under `target/` ("current package
/// believes it's in a workspace when it's not"); removed, because the CI
/// runner has little disk to spare. Only the installed binary lands under
/// `target/regtest-bin/`, staged beside [`pinned_dir`] so the final rename
/// stays on one filesystem.
fn build_pinned() -> anyhow::Result<PathBuf> {
    let v = versions().zainod;
    let dir = pinned_dir();
    let bin = dir.join("bin/zainod");
    let work = tempfile::Builder::new().prefix("zainod-build").tempdir()?;
    let root = regtest_bin_dir().join(format!("zainod-{}.{}.root", v.version, std::process::id()));
    fs::create_dir_all(regtest_bin_dir())?;
    let result = (|| {
        let krate = work.path().join(format!("zainod-{}.crate", v.version));
        let url = format!(
            "https://static.crates.io/crates/zainod/zainod-{}.crate",
            v.version
        );
        download_verified(&url, &krate, &v.sha256)?;
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&krate)
            .arg("-C")
            .arg(work.path())
            .status()
            .context("run tar")?;
        if !status.success() {
            bail!("tar failed: {status}");
        }
        let src = work.path().join(format!("zainod-{}", v.version));
        eprintln!(
            "building zainod {} (cargo install --locked, a few minutes)",
            v.version
        );
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(cargo)
            .args(["install", "--locked", "--path"])
            .arg(&src)
            .arg("--root")
            .arg(&root)
            .env("CARGO_TARGET_DIR", work.path().join("target"))
            .status()
            .context("run cargo install")?;
        if !status.success() {
            bail!("cargo install zainod failed: {status}");
        }
        if dir.exists() {
            let _ = fs::remove_dir_all(&dir);
        }
        // Another test process may have finished first: keep either copy.
        match fs::rename(&root, &dir) {
            Ok(()) => Ok(()),
            Err(_) if bin.is_file() => Ok(()),
            Err(e) => Err(e).context(format!("move zainod into {}", dir.display())),
        }
    })();
    let _ = fs::remove_dir_all(&root);
    drop(work);
    result?;
    Ok(bin)
}

/// A running `zainod` in front of one node. Killed on drop; the directory
/// is kept when `GYGES_TEST_KEEP` is set.
#[derive(Debug)]
pub struct Zaino {
    dir: Option<tempfile::TempDir>,
    dir_path: PathBuf,
    child: Option<Child>,
    grpc_port: u16,
    runtime: tokio::runtime::Runtime,
}

impl Zaino {
    /// Start zaino in front of `node` and wait until it serves `node`'s tip.
    pub fn start(node: &Node) -> anyhow::Result<Self> {
        let dir = tempfile::tempdir()?;
        let dir_path = dir.path().to_path_buf();
        fs::create_dir_all(dir_path.join("db"))?;
        let mut zaino = Self {
            dir: Some(dir),
            dir_path,
            child: None,
            grpc_port: free_port(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
        };
        zaino.spawn(node)?;
        Ok(zaino)
    }

    /// `http://127.0.0.1:<port>`: plaintext gRPC, as `grpc_url` takes it on
    /// regtest with `use_tor = false`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.grpc_port)
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir_path.join("zainod.log")
    }

    fn config_path(&self) -> PathBuf {
        self.dir_path.join("zindexer.toml")
    }

    /// The last lines of zaino's log, for failure messages.
    pub fn log_tail(&self) -> String {
        let text = fs::read_to_string(self.log_path()).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(30)..].join("\n")
    }

    /// The configuration of `OVERVIEW.md` §4.5's smoke test.
    fn write_config(&self, node: &Node) -> anyhow::Result<()> {
        let config = format!(
            r#"# Written by the gyges regtest harness.
backend = "rpc"
network = "Regtest"

[validator_settings]
validator_jsonrpc_listen_address = "{rpc}"
validator_cookie_path = "{cookie}"

[grpc_settings]
listen_address = "127.0.0.1:{grpc}"

[storage.database]
path = "{db}"
"#,
            rpc = node.rpc_addr(),
            cookie = node.cookie_path().display(),
            grpc = self.grpc_port,
            db = self.dir_path.join("db").display(),
        );
        fs::write(self.config_path(), config)?;
        Ok(())
    }

    fn spawn(&mut self, node: &Node) -> anyhow::Result<()> {
        assert!(self.child.is_none(), "zaino already running");
        self.write_config(node)?;
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path())?;
        let bin = zainod_binary().context("no zainod binary")?;
        let child = Command::new(&bin)
            .arg("start")
            .arg("--config")
            .arg(self.config_path())
            .current_dir(&self.dir_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()
            .with_context(|| format!("spawn {}", bin.display()))?;
        self.child = Some(child);
        self.wait_for_tip(node.tip_height(), Duration::from_secs(120))
    }

    /// Block until zaino's `GetLatestBlock` reports at least `height`.
    pub fn wait_for_tip(&mut self, height: u32, timeout: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .and_then(|c| c.try_wait().ok().flatten())
            {
                self.child = None;
                bail!("zainod exited: {status}\n{}", self.log_tail());
            }
            let last = match self.tip() {
                Ok(tip) if tip >= height => return Ok(()),
                Ok(tip) => format!("at {tip}"),
                Err(e) => e.to_string(),
            };
            if Instant::now() > deadline {
                bail!(
                    "zaino did not reach height {height}: {last}\n{}",
                    self.log_tail()
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// The tip zaino serves, through the backend `gygesd` uses for it
    /// (which also checks `GetLightdInfo`'s chain name).
    pub fn tip(&self) -> anyhow::Result<u32> {
        let backend = self.backend()?;
        let bounds = self.runtime.block_on(backend.node_bounds())?;
        Ok(u32::from(bounds.tip_height))
    }

    /// The hash of zaino's compact block at `height`, display hex (as
    /// [`Node::block_hash`] prints it).
    pub fn block_hash(&self, height: u32) -> anyhow::Result<String> {
        let backend = self.backend()?;
        let hash = self
            .runtime
            .block_on(backend.block_hash(gyges_chain::testing::h(height)))?;
        Ok(gyges_chain::display_hash(&hash))
    }

    /// A fresh client each time, so a restarted zaino is never asked over
    /// a dead connection.
    fn backend(&self) -> anyhow::Result<ArtiTorLwdBackend<LocalNetwork>> {
        Ok(ArtiTorLwdBackend::new(
            &self.url(),
            Transport::Direct,
            gyges_chain::testing::regtest_params(),
        )?)
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Stop and start again in front of `node` over the same database and
    /// port, picking up the node's current cookie.
    pub fn restart(&mut self, node: &Node) -> anyhow::Result<()> {
        self.stop();
        self.spawn(node)
    }

    /// Keep the directory for inspection and return its path.
    pub fn keep(&mut self) -> PathBuf {
        if let Some(dir) = self.dir.take() {
            return dir.keep();
        }
        self.dir_path.clone()
    }
}

impl Drop for Zaino {
    fn drop(&mut self) {
        self.stop();
        if std::env::var_os("GYGES_TEST_KEEP").is_some() {
            let path = self.keep();
            eprintln!("GYGES_TEST_KEEP: left zaino at {}", path.display());
        }
    }
}

/// How many blocks [`Fallback::mine`] mines before copying them to the
/// archive node: far fewer than the depth at which the pruned node drops a
/// block ([`crate::FINALITY_DEPTH`] plus its window), so none is pruned
/// before it is copied.
const MIRROR_CHUNK: u32 = 100;

/// The wallet's pruned node, an archive node following it, and zaino in
/// front of the archive node.
#[derive(Debug)]
pub struct Fallback {
    /// The wallet's node: mine and broadcast here.
    pub node: Node,
    pub archive: Node,
    pub zaino: Zaino,
}

impl Fallback {
    /// Start the three processes, or `None` with a message on stderr when
    /// this platform has no `zakurad` or no `zainod`. `opts` is the pruned
    /// node's.
    pub fn start_or_skip(opts: NodeOpts) -> Option<Self> {
        if zakurad_binary().is_none() || zainod_binary().is_none() {
            eprintln!(
                "skipping: no zakurad or zainod; set ZAKURAD_BIN and ZAINOD_BIN (or \
                 GYGES_BUILD_ZAINOD=1 on Linux) to run the backfill scenarios"
            );
            return None;
        }
        Some(Self::start(opts).expect("start the node, the archive node and zaino"))
    }

    pub fn start(opts: NodeOpts) -> anyhow::Result<Self> {
        assert!(!opts.archive, "the wallet's node is the pruned one");
        let node = Node::start(opts)?;
        let archive = Node::start(NodeOpts {
            archive: true,
            ..NodeOpts::default()
        })?;
        let zaino = Zaino::start(&archive)?;
        Ok(Self {
            node,
            archive,
            zaino,
        })
    }

    /// Mine `n` blocks on the wallet's node, copy them to the archive node
    /// as they come, and wait until zaino serves them. The hashes of the
    /// new blocks.
    pub fn mine(&mut self, n: u32) -> Vec<String> {
        let mut hashes = Vec::with_capacity(n as usize);
        let mut left = n;
        while left > 0 {
            let chunk = left.min(MIRROR_CHUNK);
            hashes.extend(self.node.mine(chunk));
            self.mirror().expect("copy blocks to the archive node");
            left -= chunk;
        }
        self.sync_zaino();
        hashes
    }

    /// Copy every block the archive node lacks from the wallet's node. The
    /// archive node's tip must still be on the wallet node's chain (the
    /// harness does not follow reorgs here).
    pub fn mirror(&self) -> anyhow::Result<()> {
        let from = self.archive.tip_height();
        let to = self.node.tip_height();
        if from > 0 && self.archive.block_hash(from) != self.node.block_hash(from) {
            bail!("the archive node's block {from} is not on the wallet node's chain");
        }
        for h in from + 1..=to {
            self.archive
                .submit_block(&self.node.raw_block(h))
                .with_context(|| format!("block {h}"))?;
        }
        let got = self.archive.tip_height();
        if got != to {
            bail!("the archive node is at {got} after copying up to {to}");
        }
        Ok(())
    }

    /// Wait until zaino serves the archive node's tip.
    pub fn sync_zaino(&mut self) {
        let tip = self.archive.tip_height();
        self.zaino
            .wait_for_tip(tip, Duration::from_secs(120))
            .expect("zaino follows the archive node");
    }

    /// Restart the archive node, then zaino, which would otherwise keep the
    /// node's rotated-out cookie.
    pub fn restart_archive(&mut self) -> anyhow::Result<()> {
        let opts = self.archive.opts().clone();
        self.archive.restart(opts)?;
        self.zaino.restart(&self.archive)
    }

    /// The `[fallback_lightwalletd]` section pointing `gygesd` at zaino.
    pub fn config_section(&self) -> String {
        format!(
            "[fallback_lightwalletd]\nenabled = true\ngrpc_url = \"{}\"\nuse_tor = false\n",
            self.zaino.url()
        )
    }

    /// Keep every directory for inspection.
    pub fn keep(&mut self) -> Vec<PathBuf> {
        vec![self.node.keep(), self.archive.keep(), self.zaino.keep()]
    }
}
