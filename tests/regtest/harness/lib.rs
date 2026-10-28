//! Test harness for the end-to-end scenarios (TESTING.md §2).
//!
//! [`Fixture`] runs `gygesd` and `gyges` against a temporary `GYGES_HOME`;
//! [`Node`] runs the pinned `zakurad` in regtest (`versions.toml`) and drives
//! it over JSON-RPC; [`Fallback`] adds an archive node and `zaino` in front of
//! it as the fallback endpoint (ROADMAP.md M2). Gyges
//! binaries are taken from `GYGES_DAEMON_BIN` / `GYGES_CLI_BIN` when set;
//! otherwise they are built (once per test process, a no-op when fresh)
//! into the same target directory as the test executable, so a `cargo test
//! -p gyges-regtest` never runs against stale binaries.

#![forbid(unsafe_code)]

mod common;
mod fake;
mod node;
mod process;
mod zaino;

pub use common::{
    FAST_CONFIG, NODE_CONFIG, SPEND_CONFIG, TEX_CONFIG, balance, burn_t_address, burn_tex_address,
    funded_wallet, keystone_device, keystone_export, mnemonic, parse_tex_txids, regtest, send,
    shield, spendable, start_daemon, sweep_logs, sync_wait, sync_wait_within, test_key_miner,
    test_key_transparent, test_key_transparent_address, wait_balance, wait_for_txid, wait_stalled,
};
pub use fake::{
    FakeNodeHandle, PASSPHRASE, fund_transparent, pool_spendable, synced_key, tex_row,
    transparent_receivers, wait_spendable, wait_tex_state,
};
pub use node::{
    BURN_MINER_ADDRESS, FINALITY_DEPTH, MIN_TX_RETENTION, Node, NodeOpts, zakurad_binary,
};
pub use zaino::{Fallback, Zaino, fallback_section, zainod_binary};

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

use crate::process::{KeptDir, env_bin, kill, log_tail, profile_dir, wait_or_kill, wait_ready};

/// Where a built binary lives, building both binaries on first use.
pub fn binary(name: &str) -> PathBuf {
    let env = match name {
        "gygesd" => "GYGES_DAEMON_BIN",
        "gyges" => "GYGES_CLI_BIN",
        other => panic!("unknown binary {other}"),
    };
    if let Some(p) = env_bin(env) {
        return p;
    }
    let target_dir = build_binaries();
    let candidate = target_dir.join(name);
    assert!(
        candidate.is_file(),
        "{} missing after build",
        candidate.display()
    );
    candidate
}

/// `cargo build -p gygesd -p gyges-cli` into the test executable's profile
/// directory, once per process. Returns that directory.
fn build_binaries() -> &'static Path {
    static TARGET: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    TARGET.get_or_init(|| {
        let target_dir = profile_dir();
        let mut cmd = Command::new(env!("CARGO"));
        cmd.args(["build", "--quiet", "-p", "gygesd", "-p", "gyges-cli"]);
        if target_dir.file_name().is_some_and(|p| p == "release") {
            cmd.arg("--release");
        }
        let status = cmd.status().expect("run cargo");
        assert!(
            status.success(),
            "cargo build of gygesd and gyges-cli failed"
        );
        target_dir
    })
}

/// The captured result of one `gyges` or `gygesd` invocation.
#[derive(Debug)]
pub struct Run {
    pub status: ExitStatus,
    pub stdout: String,
    /// Standard output as bytes, for commands that write a `.pczt`.
    pub stdout_bytes: Vec<u8>,
    pub stderr: String,
}

impl Run {
    pub fn code(&self) -> i32 {
        self.status.code().unwrap_or(-1)
    }

    /// Parse stdout as one JSON object.
    #[track_caller]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.stdout))
    }

    /// Parse each stdout line as a JSON object (a `--json` stream).
    #[track_caller]
    pub fn json_lines(&self) -> Vec<serde_json::Value> {
        self.stdout
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l:?}")))
            .collect()
    }

    /// Assert that stdout contains `needle`.
    #[track_caller]
    pub fn stdout_has(&self, needle: &str) -> &Self {
        assert!(
            self.stdout.contains(needle),
            "{needle:?} not on stdout: {}",
            self.stdout
        );
        self
    }

    /// Assert that stderr contains `needle`.
    #[track_caller]
    pub fn stderr_has(&self, needle: &str) -> &Self {
        assert!(
            self.stderr.contains(needle),
            "{needle:?} not on stderr: {}",
            self.stderr
        );
        self
    }

    fn from(output: Output) -> Self {
        Self {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stdout_bytes: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// A `gyges` command under construction.
#[derive(Debug)]
pub struct Cmd {
    cmd: Command,
    stdin: Option<Vec<u8>>,
}

impl Cmd {
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.cmd.env(key, value);
        self
    }

    /// One more argument (a path, say).
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.cmd.arg(arg);
        self
    }

    /// More arguments, after the ones given so far.
    pub fn args(mut self, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Self {
        self.cmd.args(args);
        self
    }

    /// Feed `text` on standard input (which is otherwise `/dev/null`).
    pub fn stdin(mut self, text: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(text.into());
        self
    }

    pub fn run(mut self) -> Run {
        let Some(input) = self.stdin.take() else {
            let output = self.cmd.output().expect("spawn gyges");
            return Run::from(output);
        };
        self.cmd.stdin(Stdio::piped());
        let mut child = self.cmd.spawn().expect("spawn gyges");
        {
            use std::io::Write as _;
            let mut pipe = child.stdin.take().expect("piped stdin");
            pipe.write_all(&input).expect("write stdin");
        }
        Run::from(child.wait_with_output().expect("collect output"))
    }

    /// Run, asserting exit code `want`.
    #[track_caller]
    pub fn code(self, want: i32) -> Run {
        let run = self.run();
        assert_eq!(run.code(), want, "{run:?}");
        run
    }

    /// Run, asserting success.
    #[track_caller]
    pub fn ok(self) -> Run {
        self.code(0)
    }

    /// [`Cmd::ok`], with the tail of the log at `log` (a node's) in the
    /// failure message.
    #[track_caller]
    pub fn ok_with_log(self, log: &Path) -> Run {
        let run = self.run();
        assert_eq!(run.code(), 0, "{run:?}\n{}", log_tail(log));
        run
    }
}

/// A temporary `GYGES_HOME` with, optionally, a daemon running in it.
#[derive(Debug)]
pub struct Fixture {
    home: KeptDir,
    network: &'static str,
    daemon: Option<Child>,
}

impl Fixture {
    /// A fresh, empty home for `network`; no daemon yet.
    pub fn new(network: &'static str) -> Self {
        let home = KeptDir::new("home").expect("tempdir");
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            home,
            network,
            daemon: None,
        }
    }

    pub fn home(&self) -> &Path {
        self.home.path()
    }

    pub fn network_dir(&self) -> PathBuf {
        self.home().join(self.network)
    }

    pub fn socket(&self) -> PathBuf {
        self.network_dir().join("gygesd.sock")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.network_dir().join("gygesd.pid")
    }

    /// Write `config.toml` for this network (creating the directory 0700).
    pub fn write_config(&self, toml: &str) {
        let dir = self.network_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, toml).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// `gygesd --foreground --network <net> <extra…>` with this home.
    fn daemon_command(&self, extra: &[&str]) -> Command {
        let mut cmd = Command::new(binary("gygesd"));
        cmd.args(["--foreground", "--network", self.network])
            .args(extra)
            .env("GYGES_HOME", self.home())
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }

    /// Start a daemon in the foreground and wait until its socket accepts.
    pub fn start_daemon(&mut self, extra: &[&str]) -> anyhow::Result<()> {
        assert!(self.daemon.is_none(), "daemon already started");
        let child = self.daemon_command(extra).spawn().context("spawn gygesd")?;
        let socket = self.socket();
        let child = wait_ready(
            "gygesd",
            child,
            None,
            Duration::from_secs(20),
            Duration::from_millis(20),
            || {
                UnixStream::connect(&socket)
                    .map(drop)
                    .map_err(|e| format!("{}: {e}", socket.display()))
            },
        )?;
        self.daemon = Some(child);
        Ok(())
    }

    /// Run `gygesd --foreground` to completion (for startup refusals), with
    /// its stderr captured.
    pub fn run_daemon_to_exit(&self, extra: &[&str]) -> Run {
        let mut cmd = self.daemon_command(extra);
        cmd.stderr(Stdio::piped()).stdout(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn gygesd");
        wait_or_kill(&mut child, Duration::from_secs(20));
        Run::from(child.wait_with_output().expect("collect output"))
    }

    /// Pid of the daemon this fixture started.
    pub fn daemon_pid(&self) -> Option<u32> {
        self.daemon.as_ref().map(Child::id)
    }

    /// `gyges --network <net> <args…>` with `GYGES_HOME` set and the
    /// `gygesd` binary resolvable for `daemon start`.
    pub fn gyges(&self, args: &[&str]) -> Cmd {
        self.cli(Some(self.network), args)
    }

    /// Like [`Fixture::gyges`] but without `--network`, so the CLI adopts
    /// whatever the daemon reports.
    pub fn gyges_no_network(&self, args: &[&str]) -> Cmd {
        self.cli(None, args)
    }

    fn cli(&self, network: Option<&str>, args: &[&str]) -> Cmd {
        let mut cmd = Command::new(binary("gyges"));
        if let Some(network) = network {
            cmd.arg("--network").arg(network);
        }
        cmd.args(args)
            .env("GYGES_HOME", self.home())
            .env("GYGES_DAEMON_BIN", binary("gygesd"))
            .env_remove("GYGES_SOCKET")
            .env_remove("GYGES_NETWORK")
            .env_remove("GYGES_KEY")
            .env_remove("GYGES_PASSPHRASE_FILE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Cmd { cmd, stdin: None }
    }

    /// A `0600` file holding `passphrase`, for `GYGES_PASSPHRASE_FILE`.
    pub fn passphrase_file(&self, passphrase: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = self.home().join(format!("pw-{}-{n}", std::process::id()));
        std::fs::write(&path, format!("{passphrase}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// `keys/<id>/` for this network.
    pub fn key_dir(&self, key_id: &str) -> PathBuf {
        self.network_dir().join("keys").join(key_id)
    }

    /// SIGKILL the daemon this fixture started (a crash, TESTING.md §3 row
    /// 12). The pid file's advisory lock dies with the process, so
    /// `start_daemon` works again afterwards.
    pub fn kill_daemon(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            kill(&mut child);
        }
    }

    /// Wait for the daemon this fixture started to exit.
    pub fn wait_daemon(&mut self, timeout: Duration) -> anyhow::Result<ExitStatus> {
        let Some(mut child) = self.daemon.take() else {
            bail!("no daemon started")
        };
        wait_or_kill(&mut child, timeout)
            .with_context(|| format!("gygesd still running after {timeout:?}"))
    }

    /// `gyges daemon stop`, which must succeed, then wait for the process.
    #[track_caller]
    pub fn stop_daemon(&mut self) {
        self.gyges(&["daemon", "stop"]).ok();
        self.wait_daemon(Duration::from_secs(60)).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.kill_daemon();
    }
}

/// Call `f` every `every` until it returns `Ok`, panicking with `what` and
/// the last `Err` once `timeout` has passed.
pub fn poll_until<T>(
    timeout: Duration,
    every: Duration,
    what: &str,
    mut f: impl FnMut() -> Result<T, String>,
) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        match f() {
            Ok(v) => return v,
            Err(last) => assert!(Instant::now() < deadline, "{what}: {last}"),
        }
        std::thread::sleep(every);
    }
}

/// Postcard's unsigned varint (LEB128: seven bits per byte, low bits
/// first, high bit set on every byte but the last).
fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// A PCZT with the one occurrence of the value `old` replaced by `new`
/// (same encoded length): a file tampered with on the way (TESTING.md §3
/// row 13), which still parses and only differs in that one output value.
pub fn tamper_value(bytes: &[u8], old: u64, new: u64) -> Vec<u8> {
    let from = varint(old);
    let to = varint(new);
    assert_eq!(from.len(), to.len(), "pick values of equal varint length");
    let hits: Vec<usize> = (0..=bytes.len() - from.len())
        .filter(|&i| bytes[i..i + from.len()] == from[..])
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected the value once in the file: {hits:?}"
    );
    let mut out = bytes.to_vec();
    out[hits[0]..hits[0] + to.len()].copy_from_slice(&to);
    out
}
