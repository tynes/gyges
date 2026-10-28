//! `gyges daemon install` / `uninstall` (CLI_SPEC.md §2.1, OVERVIEW.md
//! Q-C5): a per-user service that runs `gygesd --foreground` for one
//! network. macOS gets a `launchd` agent in `~/Library/LaunchAgents`, Linux a
//! `systemd --user` unit in `$XDG_CONFIG_HOME/systemd/user`.
//!
//! The service restarts the daemon only when it fails: `daemon stop` exits 0
//! and leaves it stopped until the next login or `daemon install`. Nothing
//! restarts a running daemon when its binary is replaced, so running
//! `daemon install` again is the upgrade step: it stops the service, rewrites
//! the unit and starts it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow, bail};
use gyges_proto::uds;
use gyges_proto::v1::Network;

use crate::client::Ctx;
use crate::daemon::{DAEMON_BIN_ENV, daemon_binary};
use crate::exit::CliError;

/// The service manager a unit is written for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Manager {
    Launchd,
    SystemdUser,
}

impl Manager {
    /// The manager of this platform, if Gyges supports one.
    pub fn native() -> Result<Self, CliError> {
        if cfg!(target_os = "macos") {
            Ok(Self::Launchd)
        } else if cfg!(target_os = "linux") {
            Ok(Self::SystemdUser)
        } else {
            Err(anyhow!("daemon install supports launchd (macOS) and systemd (Linux) only").into())
        }
    }

    /// Where this manager looks for per-user units.
    pub fn unit_dir(self) -> Result<PathBuf, CliError> {
        let home =
            || std::env::home_dir().ok_or_else(|| anyhow!("cannot determine the home directory"));
        Ok(match self {
            Self::Launchd => home()?.join("Library/LaunchAgents"),
            Self::SystemdUser => match std::env::var_os("XDG_CONFIG_HOME") {
                Some(d) if Path::new(&d).is_absolute() => PathBuf::from(d).join("systemd/user"),
                _ => home()?.join(".config/systemd/user"),
            },
        })
    }
}

/// What the unit runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub network: Network,
    /// Absolute path to `gygesd`.
    pub binary: PathBuf,
    /// Absolute `GYGES_HOME`, written into the unit when the installing
    /// shell had one set.
    pub gyges_home: Option<PathBuf>,
}

impl Spec {
    /// `launchd` label, also the plist's file stem.
    pub fn label(&self) -> String {
        format!("org.gyges.gygesd.{}", self.network.name())
    }

    /// `systemd` unit name.
    pub fn unit_name(&self) -> String {
        format!("gygesd-{}.service", self.network.name())
    }

    pub fn file_name(&self, manager: Manager) -> String {
        match manager {
            Manager::Launchd => format!("{}.plist", self.label()),
            Manager::SystemdUser => self.unit_name(),
        }
    }

    fn args(&self) -> [String; 4] {
        [
            self.binary.display().to_string(),
            "--network".into(),
            self.network.name().into(),
            "--foreground".into(),
        ]
    }

    pub fn render(&self, manager: Manager) -> String {
        match manager {
            Manager::Launchd => self.render_launchd(),
            Manager::SystemdUser => self.render_systemd(),
        }
    }

    /// A `launchd` agent. `KeepAlive.SuccessfulExit = false` restarts the
    /// daemon after a failure but not after `daemon stop`. No
    /// `StandardOutPath`: the daemon logs to `$GYGES_HOME/<network>/logs`,
    /// and a file launchd creates inside the home would be 0644, which the
    /// next start refuses.
    fn render_launchd(&self) -> String {
        let mut s = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n<dict>\n",
        );
        s += &format!(
            "  <key>Label</key>\n  <string>{}</string>\n",
            xml(&self.label())
        );
        s += "  <key>ProgramArguments</key>\n  <array>\n";
        for a in self.args() {
            s += &format!("    <string>{}</string>\n", xml(&a));
        }
        s += "  </array>\n";
        if let Some(home) = &self.gyges_home {
            s += &format!(
                "  <key>EnvironmentVariables</key>\n  <dict>\n    \
                 <key>GYGES_HOME</key>\n    <string>{}</string>\n  </dict>\n",
                xml(&home.display().to_string())
            );
        }
        s += "  <key>RunAtLoad</key>\n  <true/>\n\
              \x20 <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n\
              \x20 <key>ThrottleInterval</key>\n  <integer>10</integer>\n\
              \x20 <key>ExitTimeOut</key>\n  <integer>90</integer>\n\
              \x20 <key>ProcessType</key>\n  <string>Background</string>\n\
              </dict>\n</plist>\n";
        s
    }

    /// A `systemd --user` unit. A daemon that keeps failing (bad config)
    /// gives up after five tries instead of looping forever.
    /// `TimeoutStopSec` covers `daemon.shutdown_grace` (30 s by default).
    fn render_systemd(&self) -> String {
        let exec = self
            .args()
            .iter()
            .map(|a| systemd_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let mut s = format!(
            "[Unit]\n\
             Description=Gyges wallet daemon ({})\n\
             StartLimitIntervalSec=300\n\
             StartLimitBurst=5\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exec}\n",
            self.network.name()
        );
        if let Some(home) = &self.gyges_home {
            s += &format!(
                "Environment={}\n",
                systemd_quote(&format!("GYGES_HOME={}", home.display()))
            );
        }
        s += "Restart=on-failure\n\
              RestartSec=10\n\
              TimeoutStopSec=90\n\
              \n\
              [Install]\n\
              WantedBy=default.target\n";
        s
    }
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// One word for `ExecStart=` / `Environment=`: double-quoted, with `\` and
/// `"` escaped, `%` (specifiers) and `$` (variable expansion) doubled.
fn systemd_quote(s: &str) -> String {
    let mut q = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                q.push('\\');
                q.push(c);
            }
            '%' => q.push_str("%%"),
            '$' => q.push_str("$$"),
            _ => q.push(c),
        }
    }
    q.push('"');
    q
}

/// Runs the service manager's commands; tests record them instead.
pub trait Runner {
    /// Run `program args…`; `Ok(Err(stderr))` when it exits non-zero.
    fn run(&mut self, program: &str, args: &[String]) -> anyhow::Result<Result<(), String>>;
}

/// The real commands.
pub struct System;

impl Runner for System {
    fn run(&mut self, program: &str, args: &[String]) -> anyhow::Result<Result<(), String>> {
        let out = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("cannot run {program}"))?;
        Ok(if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        })
    }
}

/// The commands that load, start, stop and unload a unit.
struct Commands {
    manager: Manager,
    /// `gui/<uid>` for launchd.
    domain: String,
}

impl Commands {
    fn new(manager: Manager) -> Self {
        Self {
            manager,
            domain: format!("gui/{}", nix::unistd::getuid()),
        }
    }

    /// Stop and unload the unit; `true` if it was loaded.
    fn stop(&self, r: &mut dyn Runner, spec: &Spec) -> anyhow::Result<bool> {
        Ok(match self.manager {
            Manager::Launchd => r
                .run(
                    "launchctl",
                    &[
                        "bootout".into(),
                        format!("{}/{}", self.domain, spec.label()),
                    ],
                )?
                .is_ok(),
            Manager::SystemdUser => r
                .run(
                    "systemctl",
                    &[
                        "--user".into(),
                        "disable".into(),
                        "--now".into(),
                        spec.unit_name(),
                    ],
                )?
                .is_ok(),
        })
    }

    /// Load the unit from `path` and start it now and at every login.
    fn start(&self, r: &mut dyn Runner, spec: &Spec, path: &Path) -> anyhow::Result<()> {
        let (program, steps): (&str, Vec<Vec<String>>) = match self.manager {
            Manager::Launchd => (
                "launchctl",
                vec![vec![
                    "bootstrap".into(),
                    self.domain.clone(),
                    path.display().to_string(),
                ]],
            ),
            Manager::SystemdUser => (
                "systemctl",
                vec![
                    vec!["--user".into(), "daemon-reload".into()],
                    vec![
                        "--user".into(),
                        "enable".into(),
                        "--now".into(),
                        spec.unit_name(),
                    ],
                ],
            ),
        };
        for args in steps {
            if let Err(stderr) = r.run(program, &args)? {
                bail!("{program} {} failed: {stderr}", args.join(" "));
            }
        }
        Ok(())
    }

    /// Forget a removed unit file (systemd only).
    fn reload(&self, r: &mut dyn Runner) -> anyhow::Result<()> {
        if self.manager == Manager::SystemdUser {
            // Best effort: the file is already gone.
            let _ = r.run("systemctl", &["--user".into(), "daemon-reload".into()])?;
        }
        Ok(())
    }

    /// Where to look when the daemon does not come up.
    fn log_hint(&self, spec: &Spec) -> String {
        match self.manager {
            Manager::Launchd => format!("launchctl print {}/{}", self.domain, spec.label()),
            Manager::SystemdUser => format!("journalctl --user -u {}", spec.unit_name()),
        }
    }
}

/// `--json` output of `daemon install` / `uninstall`.
#[derive(Debug, serde::Serialize)]
pub struct ServiceReport {
    pub manager: Manager,
    pub unit_path: String,
    pub network: String,
    /// `install`: the daemon answered after the unit started. `uninstall`:
    /// a unit was loaded and has been stopped.
    pub running: bool,
}

/// Absolute path of the `gygesd` the unit should run: `GYGES_DAEMON_BIN`,
/// next to this executable, or on `PATH`. A service manager has no
/// interactive `PATH`, so a bare name is resolved here. Symlinks are kept:
/// a package manager's stable link survives upgrades, its versioned target
/// does not.
pub fn absolute_daemon_binary() -> Result<PathBuf, CliError> {
    let bin = daemon_binary();
    let found = if bin.components().count() > 1 {
        Some(std::path::absolute(&bin)?)
    } else {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .filter(|d| d.is_absolute())
                .map(|d| d.join(&bin))
                .find(|p| p.is_file())
        })
    };
    match found {
        Some(p) if p.is_file() => Ok(p),
        _ => Err(anyhow!(
            "cannot find gygesd (looked at {DAEMON_BIN_ENV}, next to gyges, and on PATH); \
             install it or set {DAEMON_BIN_ENV} to its absolute path"
        )
        .into()),
    }
}

/// The spec for `network` from the environment.
pub fn spec_from_env(network: Network) -> Result<Spec, CliError> {
    let gyges_home = match std::env::var_os("GYGES_HOME") {
        Some(d) if !d.is_empty() => Some(std::path::absolute(PathBuf::from(d))?),
        _ => None,
    };
    Ok(Spec {
        network,
        binary: absolute_daemon_binary()?,
        gyges_home,
    })
}

pub async fn install(ctx: &Ctx) -> Result<(), CliError> {
    let manager = Manager::native()?;
    let spec = spec_from_env(ctx.network.unwrap_or(Network::Mainnet))?;
    let report = install_with(ctx, &mut System, manager, &manager.unit_dir()?, &spec, WAIT).await?;
    ctx.report(&report, || {
        eprintln!(
            "installed {} and started gygesd for {}",
            report.unit_path, report.network
        );
        eprintln!("run `gyges daemon install` again after upgrading gyges to restart it");
        if manager == Manager::SystemdUser {
            eprintln!("to keep it running while you are logged out: loginctl enable-linger $USER");
        }
    })
}

pub async fn uninstall(ctx: &Ctx) -> Result<(), CliError> {
    let manager = Manager::native()?;
    let spec = spec_from_env(ctx.network.unwrap_or(Network::Mainnet))
        // Uninstalling must work when gygesd is gone already.
        .or_else(|_| {
            Ok::<_, CliError>(Spec {
                network: ctx.network.unwrap_or(Network::Mainnet),
                binary: PathBuf::new(),
                gyges_home: None,
            })
        })?;
    let report = uninstall_with(&mut System, manager, &manager.unit_dir()?, &spec)?;
    ctx.report(&report, || {
        if report.running {
            eprintln!(
                "stopped gygesd for {} and removed {}",
                report.network, report.unit_path
            );
        } else {
            eprintln!("no gygesd service is installed for {}", report.network);
        }
    })
}

/// How long `install` waits for a stopped service's socket to close, and for
/// the new one to answer.
const WAIT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(100);

pub async fn install_with(
    ctx: &Ctx,
    runner: &mut dyn Runner,
    manager: Manager,
    unit_dir: &Path,
    spec: &Spec,
    wait: Duration,
) -> Result<ServiceReport, CliError> {
    let cmds = Commands::new(manager);
    let path = unit_dir.join(spec.file_name(manager));

    // Reinstalling restarts: stop the old service and wait for its socket.
    if cmds.stop(runner, spec)? {
        let deadline = Instant::now() + wait;
        while uds::probe(&ctx.socket).await.is_ok() && Instant::now() < deadline {
            tokio::time::sleep(POLL).await;
        }
    }
    // A daemon still answering was started by hand; a unit would fail on
    // its pid lock and restart forever.
    if uds::probe(&ctx.socket).await.is_ok() {
        return Err(anyhow!(
            "a gygesd not started by a service is running on {}; stop it with \
             `gyges daemon stop` first",
            ctx.socket.display()
        )
        .into());
    }

    std::fs::create_dir_all(unit_dir)
        .with_context(|| format!("cannot create {}", unit_dir.display()))?;
    std::fs::write(&path, spec.render(manager))
        .with_context(|| format!("cannot write {}", path.display()))?;
    cmds.start(runner, spec, &path)?;

    let deadline = Instant::now() + wait;
    let up = loop {
        match ctx.connect().await {
            Ok(_) => break Ok(()),
            Err(e) if Instant::now() >= deadline => break Err(e.message()),
            Err(_) => tokio::time::sleep(POLL).await,
        }
    };
    if let Err(last) = up {
        return Err(anyhow!(
            "{} is installed but gygesd did not answer on {} within {}s ({last}); see `{}` \
             and the logs under the network directory",
            path.display(),
            ctx.socket.display(),
            wait.as_secs(),
            cmds.log_hint(spec)
        )
        .into());
    }
    Ok(ServiceReport {
        manager,
        unit_path: path.display().to_string(),
        network: spec.network.name().into(),
        running: true,
    })
}

pub fn uninstall_with(
    runner: &mut dyn Runner,
    manager: Manager,
    unit_dir: &Path,
    spec: &Spec,
) -> Result<ServiceReport, CliError> {
    let cmds = Commands::new(manager);
    let path = unit_dir.join(spec.file_name(manager));
    let was_loaded = cmds.stop(runner, spec)?;
    let existed = match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(anyhow!("cannot remove {}: {e}", path.display()).into()),
    };
    if existed {
        cmds.reload(runner)?;
    }
    Ok(ServiceReport {
        manager,
        unit_path: path.display().to_string(),
        network: spec.network.name().into(),
        running: was_loaded || existed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(home: Option<&str>) -> Spec {
        Spec {
            network: Network::Testnet,
            binary: "/opt/gyges bin/gygesd".into(),
            gyges_home: home.map(PathBuf::from),
        }
    }

    #[test]
    fn launchd_agent_runs_the_daemon_in_the_foreground_and_restarts_only_on_failure() {
        let s = spec(Some("/tmp/a&b")).render(Manager::Launchd);
        assert!(
            s.contains("<string>org.gyges.gygesd.testnet</string>"),
            "{s}"
        );
        assert!(
            s.contains(
                "<string>/opt/gyges bin/gygesd</string>\n    <string>--network</string>\n    \
                 <string>testnet</string>\n    <string>--foreground</string>"
            ),
            "{s}"
        );
        assert!(s.contains("<key>GYGES_HOME</key>\n    <string>/tmp/a&amp;b</string>"));
        assert!(s.contains("<key>SuccessfulExit</key>\n    <false/>"));
        assert!(!s.contains("StandardOutPath") && !s.contains("StandardErrorPath"));
        assert!(!spec(None).render(Manager::Launchd).contains("GYGES_HOME"));
    }

    /// `plutil -lint` accepts the plist (macOS only).
    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_agent_passes_plutil() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.plist");
        std::fs::write(&path, spec(Some("/tmp/a&b<c>")).render(Manager::Launchd)).unwrap();
        let out = Command::new("plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn systemd_unit_quotes_its_arguments() {
        let s = spec(Some("/var/lib/g%y$s\"")).render(Manager::SystemdUser);
        assert!(
            s.contains(
                "ExecStart=\"/opt/gyges bin/gygesd\" \"--network\" \"testnet\" \"--foreground\"\n"
            ),
            "{s}"
        );
        assert!(
            s.contains("Environment=\"GYGES_HOME=/var/lib/g%%y$$s\\\"\"\n"),
            "{s}"
        );
        assert!(s.contains("Restart=on-failure\n"));
        assert!(s.contains("WantedBy=default.target\n"));
        assert!(
            !spec(None)
                .render(Manager::SystemdUser)
                .contains("Environment=")
        );
    }

    #[derive(Default)]
    struct Recorder {
        calls: Vec<String>,
        /// Calls whose line starts with one of these fail.
        failing: Vec<&'static str>,
    }

    impl Runner for Recorder {
        fn run(&mut self, program: &str, args: &[String]) -> anyhow::Result<Result<(), String>> {
            let line = format!("{program} {}", args.join(" "));
            let fail = self.failing.iter().any(|f| line.starts_with(f));
            self.calls.push(line);
            Ok(if fail {
                Err("not loaded".into())
            } else {
                Ok(())
            })
        }
    }

    #[test]
    fn uninstall_stops_removes_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = spec(None);
        let path = dir.path().join(s.unit_name());
        std::fs::write(&path, "x").unwrap();

        let mut r = Recorder::default();
        let rep = uninstall_with(&mut r, Manager::SystemdUser, dir.path(), &s).unwrap();
        assert!(rep.running && !path.exists());
        assert_eq!(
            r.calls,
            [
                "systemctl --user disable --now gygesd-testnet.service",
                "systemctl --user daemon-reload"
            ]
        );

        // Nothing installed: the stop fails, nothing is removed, still Ok.
        let mut r = Recorder {
            failing: vec!["launchctl bootout"],
            ..Default::default()
        };
        let rep = uninstall_with(&mut r, Manager::Launchd, dir.path(), &s).unwrap();
        assert!(!rep.running);
        assert_eq!(r.calls.len(), 1);
        assert!(r.calls[0].starts_with("launchctl bootout gui/"));
        assert!(r.calls[0].ends_with("/org.gyges.gygesd.testnet"));
    }

    fn ctx(socket: PathBuf) -> Ctx {
        Ctx {
            socket,
            network: Some(Network::Testnet),
            key: String::new(),
            json: false,
            quiet: true,
            prompter: crate::prompt::Prompter {
                non_interactive: true,
                passphrase_fd: None,
            },
        }
    }

    /// The unit is written and loaded; without a daemon behind the socket
    /// the wait times out and says where to look.
    #[tokio::test]
    async fn install_writes_and_loads_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let s = spec(None);
        let mut r = Recorder {
            failing: vec!["systemctl --user disable"],
            ..Default::default()
        };
        let err = install_with(
            &ctx(dir.path().join("none.sock")),
            &mut r,
            Manager::SystemdUser,
            &dir.path().join("units"),
            &s,
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert_eq!(
            r.calls,
            [
                "systemctl --user disable --now gygesd-testnet.service",
                "systemctl --user daemon-reload",
                "systemctl --user enable --now gygesd-testnet.service"
            ]
        );
        let unit = std::fs::read_to_string(dir.path().join("units").join(s.unit_name())).unwrap();
        assert_eq!(unit, s.render(Manager::SystemdUser));
        assert!(
            err.message()
                .contains("journalctl --user -u gygesd-testnet.service"),
            "{}",
            err.message()
        );
    }

    /// A daemon answering on the socket that the service did not start is
    /// refused before anything is written.
    #[tokio::test]
    async fn install_refuses_a_daemon_started_by_hand() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("d.sock");
        let _listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let mut r = Recorder {
            failing: vec!["launchctl bootout"],
            ..Default::default()
        };
        let units = dir.path().join("units");
        let err = install_with(
            &ctx(sock),
            &mut r,
            Manager::Launchd,
            &units,
            &spec(None),
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert!(
            err.message().contains("gyges daemon stop"),
            "{}",
            err.message()
        );
        assert!(!units.exists());
        assert_eq!(r.calls.len(), 1);
    }
}
