//! Test harness for the end-to-end scenarios (TESTING.md §2).
//!
//! Today the fixture knows how to run `gygesd` and `gyges` against a
//! temporary `GYGES_HOME`; the node (`zakurad`) and archival (`zaino`)
//! processes arrive with ROADMAP.md M1/M2. Binaries are taken from
//! `GYGES_DAEMON_BIN` / `GYGES_CLI_BIN` when set; otherwise they are built
//! (once per test process, a no-op when fresh) into the same target directory
//! as the test executable, so a `cargo test -p gyges-regtest` never runs
//! against stale binaries.

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

/// Where a built binary lives, building both binaries on first use.
pub fn binary(name: &str) -> PathBuf {
    let env = match name {
        "gygesd" => "GYGES_DAEMON_BIN",
        "gyges" => "GYGES_CLI_BIN",
        other => panic!("unknown binary {other}"),
    };
    if let Some(p) = std::env::var_os(env).filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
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
        let exe = std::env::current_exe().expect("current_exe");
        // target/<profile>/deps/<test>-<hash> -> target/<profile>/
        let target_dir = exe
            .parent()
            .and_then(Path::parent)
            .expect("target dir")
            .to_path_buf();
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
    pub stderr: String,
}

impl Run {
    pub fn code(&self) -> i32 {
        self.status.code().unwrap_or(-1)
    }

    /// Parse stdout as one JSON object.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.stdout))
    }

    fn from(output: Output) -> Self {
        Self {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// A `gyges` command under construction.
#[derive(Debug)]
pub struct Cmd {
    cmd: Command,
}

impl Cmd {
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.cmd.env(key, value);
        self
    }

    pub fn run(mut self) -> Run {
        let output = self.cmd.output().expect("spawn gyges");
        Run::from(output)
    }
}

/// A temporary `GYGES_HOME` with, optionally, a daemon running in it.
#[derive(Debug)]
pub struct Fixture {
    home: Option<tempfile::TempDir>,
    home_path: PathBuf,
    network: &'static str,
    daemon: Option<Child>,
}

impl Fixture {
    /// A fresh, empty home for `network`; no daemon yet.
    pub fn new(network: &'static str) -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let home_path = home.path().to_path_buf();
        Self {
            home: Some(home),
            home_path,
            network,
            daemon: None,
        }
    }

    pub fn home(&self) -> &Path {
        &self.home_path
    }

    pub fn network(&self) -> &'static str {
        self.network
    }

    pub fn network_dir(&self) -> PathBuf {
        self.home_path.join(self.network)
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
            .env("GYGES_HOME", &self.home_path)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }

    /// Start a daemon in the foreground and wait until its socket accepts.
    pub fn start_daemon(&mut self, extra: &[&str]) -> anyhow::Result<()> {
        assert!(self.daemon.is_none(), "daemon already started");
        let mut child = self.daemon_command(extra).spawn().context("spawn gygesd")?;
        let socket = self.socket();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("gygesd exited during startup: {status}");
            }
            if UnixStream::connect(&socket).is_ok() {
                self.daemon = Some(child);
                return Ok(());
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                bail!("gygesd did not open {} in time", socket.display());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Run `gygesd --foreground` to completion (for startup refusals), with
    /// its stderr captured.
    pub fn run_daemon_to_exit(&self, extra: &[&str]) -> Run {
        let mut cmd = self.daemon_command(extra);
        cmd.stderr(Stdio::piped()).stdout(Stdio::piped());
        let child = cmd.spawn().expect("spawn gygesd");
        let output = wait_with_timeout(child, Duration::from_secs(20));
        Run::from(output)
    }

    /// Pid of the daemon this fixture started.
    pub fn daemon_pid(&self) -> Option<u32> {
        self.daemon.as_ref().map(Child::id)
    }

    /// `gyges --network <net> <args…>` with `GYGES_HOME` set and the
    /// `gygesd` binary resolvable for `daemon start`.
    pub fn gyges(&self, args: &[&str]) -> Cmd {
        let mut cmd = Command::new(binary("gyges"));
        cmd.arg("--network")
            .arg(self.network)
            .args(args)
            .env("GYGES_HOME", &self.home_path)
            .env("GYGES_DAEMON_BIN", binary("gygesd"))
            .env_remove("GYGES_SOCKET")
            .env_remove("GYGES_NETWORK")
            .env_remove("GYGES_KEY")
            .stdin(Stdio::null());
        Cmd { cmd }
    }

    /// Like [`Fixture::gyges`] but without `--network`, so the CLI adopts
    /// whatever the daemon reports.
    pub fn gyges_no_network(&self, args: &[&str]) -> Cmd {
        let mut cmd = Command::new(binary("gyges"));
        cmd.args(args)
            .env("GYGES_HOME", &self.home_path)
            .env("GYGES_DAEMON_BIN", binary("gygesd"))
            .env_remove("GYGES_SOCKET")
            .env_remove("GYGES_NETWORK")
            .env_remove("GYGES_KEY")
            .stdin(Stdio::null());
        Cmd { cmd }
    }

    /// Wait for the daemon this fixture started to exit.
    pub fn wait_daemon(&mut self, timeout: Duration) -> anyhow::Result<ExitStatus> {
        let Some(mut child) = self.daemon.take() else {
            bail!("no daemon started")
        };
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                bail!("gygesd still running after {timeout:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Keep the directory for inspection and return its path.
    pub fn keep(&mut self) -> PathBuf {
        if let Some(home) = self.home.take() {
            return home.keep();
        }
        self.home_path.clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if std::env::var_os("GYGES_TEST_KEEP").is_some() {
            let path = self.keep();
            eprintln!("GYGES_TEST_KEEP: left {}", path.display());
        }
    }
}

fn wait_with_timeout(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().expect("collect output"),
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                return child.wait_with_output().expect("collect output");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("wait: {e}"),
        }
    }
}
