//! Process plumbing shared by [`crate::Fixture`], [`crate::Node`] and
//! [`crate::Zaino`]: temporary directories kept under `GYGES_TEST_KEEP`,
//! children logging to a file, readiness and shutdown waits, and finding,
//! downloading and unpacking the binaries they run.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

/// A temporary directory, left in place (and named on stderr) when it is
/// dropped with `GYGES_TEST_KEEP` set.
#[derive(Debug)]
pub(crate) struct KeptDir {
    dir: Option<tempfile::TempDir>,
    path: PathBuf,
    what: &'static str,
}

impl KeptDir {
    /// A fresh directory; `what` names it in the `GYGES_TEST_KEEP` line.
    pub(crate) fn new(what: &'static str) -> anyhow::Result<Self> {
        let dir = tempfile::tempdir()?;
        Ok(Self {
            path: dir.path().to_path_buf(),
            dir: Some(dir),
            what,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for KeptDir {
    fn drop(&mut self) {
        if std::env::var_os("GYGES_TEST_KEEP").is_some()
            && let Some(dir) = self.dir.take()
        {
            let path = dir.keep();
            eprintln!("GYGES_TEST_KEEP: left {} at {}", self.what, path.display());
        }
    }
}

/// The last lines of the log at `path`, for failure messages.
pub(crate) fn log_tail(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(30)..].join("\n")
}

/// Spawn `cmd` with stdin closed and stdout and stderr appended to `log`.
pub(crate) fn spawn_logged(cmd: &mut Command, log: &Path) -> anyhow::Result<Child> {
    let file = fs::OpenOptions::new().create(true).append(true).open(log)?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::from(file))
        .spawn()
        .with_context(|| format!("spawn {}", Path::new(cmd.get_program()).display()))
}

/// Call `ready` every `every` until it returns `Ok`, then hand `child`
/// back. When `child` exits first or `timeout` passes, `child` is gone
/// (killed if need be) and the error names `what` and ends with the tail of
/// `log`, all in its top-level message: callers add no context, because
/// [`crate::Node::restart`] matches the node's exit text in it.
pub(crate) fn wait_ready(
    what: &str,
    mut child: Child,
    log: Option<&Path>,
    timeout: Duration,
    every: Duration,
    mut ready: impl FnMut() -> Result<(), String>,
) -> anyhow::Result<Child> {
    let tail = || {
        log.map(|p| format!("\n{}", log_tail(p)))
            .unwrap_or_default()
    };
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("{what} exited: {status}{}", tail());
        }
        let last = match ready() {
            Ok(()) => return Ok(child),
            Err(last) => last,
        };
        if Instant::now() > deadline {
            kill(&mut child);
            bail!("{what} not ready after {timeout:?}: {last}{}", tail());
        }
        std::thread::sleep(every);
    }
}

/// SIGKILL `child` and reap it.
pub(crate) fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Wait up to `timeout` for `child` to exit, then kill it: its status when
/// it exited by itself.
pub(crate) fn wait_or_kill(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                kill(child);
                return None;
            }
        }
    }
}

/// A loopback port nobody listens on (yet).
pub(crate) fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    l.local_addr().unwrap().port()
}

/// The binary `var` names, when it is set and non-empty; it must exist.
pub(crate) fn env_bin(var: &str) -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os(var).filter(|p| !p.is_empty())?);
    assert!(p.is_file(), "{var}={} is not a file", p.display());
    Some(p)
}

/// `target/<profile>/`, which holds the test executable's `deps/`.
pub(crate) fn profile_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // target/<profile>/deps/<test>-<hash> -> target/<profile>/
    exe.parent()
        .and_then(Path::parent)
        .expect("target dir")
        .to_path_buf()
}

/// `target/regtest-bin/`, beside the profile directory the tests run from.
pub(crate) fn regtest_bin_dir() -> PathBuf {
    profile_dir()
        .parent()
        .expect("target dir")
        .join("regtest-bin")
}

/// Download `url` to `dest` and check its sha256 against `expected`; a
/// mismatch removes the file.
pub(crate) fn download_verified(url: &str, dest: &Path, expected: &str) -> anyhow::Result<()> {
    eprintln!("downloading {url}");
    let status = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .context("run curl")?;
    if !status.success() {
        bail!("curl {url} failed: {status}");
    }
    let bytes = fs::read(dest)?;
    let digest = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&bytes))
    };
    if digest != expected {
        let _ = fs::remove_file(dest);
        bail!("{url}: sha256 {digest}, versions.toml expects {expected}");
    }
    Ok(())
}

/// `tar -xzf <archive> -C <into>`.
pub(crate) fn untar(archive: &Path, into: &Path) -> anyhow::Result<()> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .status()
        .context("run tar")?;
    if !status.success() {
        bail!("tar failed: {status}");
    }
    Ok(())
}

/// Rename `staged` to `dir`. Another test process may have raced us to
/// `dir`: when it already holds `bin`, keep that copy. `staged` is gone
/// afterwards either way.
pub(crate) fn move_into_place(staged: &Path, dir: &Path, bin: &Path) -> anyhow::Result<()> {
    let result = match fs::rename(staged, dir) {
        Ok(()) => Ok(()),
        Err(_) if bin.is_file() => Ok(()),
        Err(e) => Err(e).with_context(|| format!("move {} into place", dir.display())),
    };
    let _ = fs::remove_dir_all(staged);
    result
}
