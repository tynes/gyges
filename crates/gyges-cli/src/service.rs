//! `gyges daemon install` / `uninstall` (docs/interface.md CLI §2.1, docs/decisions.md
//! Q-C5): a per-user service that runs `gygesd --foreground` for one
//! network. macOS gets a `launchd` agent in `~/Library/LaunchAgents`, Linux a
//! `systemd --user` unit in `$XDG_CONFIG_HOME/systemd/user`.
//!
//! The service restarts the daemon only when it fails: `daemon stop` exits 0
//! and leaves it stopped until the next login or `daemon install`. Nothing
//! restarts a running daemon when its binary is replaced, so running
//! `daemon install` again is the upgrade step: it stops the service, rewrites
//! the unit and starts it.
//!
//! `--hardened` (Linux only, as root) is the deployment of docs/security.md
//! §6 item 4: a system unit that runs the daemon as the `gyges` user with
//! its home in `/var/lib/gyges` and its socket at
//! `/run/gyges/<network>/gygesd.sock` (0660, group `gyges`). The socket
//! cannot stay in the 0700 network directory, where no group member could
//! reach it. One named user is admitted (`--allow-uid`) and added to the
//! group.

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
    /// A system unit for the hardened deployment.
    SystemdSystem,
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
            Self::SystemdSystem => PathBuf::from("/etc/systemd/system"),
        })
    }

    /// `systemctl` arguments that select this manager's instance.
    fn systemctl(self, args: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        if self == Self::SystemdUser {
            v.push("--user".into());
        }
        v.extend(args.iter().map(|a| a.to_string()));
        v
    }
}

/// The hardened deployment's fixed names.
pub mod hardened {
    /// The daemon's user and group; the socket's group.
    pub const ACCOUNT: &str = "gyges";
    /// The daemon's `GYGES_HOME` (systemd `StateDirectory`).
    pub const HOME: &str = "/var/lib/gyges";

    /// `/run/gyges/<network>/gygesd.sock` (systemd `RuntimeDirectory`).
    pub fn socket(network: &str) -> String {
        format!("/run/gyges/{network}/gygesd.sock")
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
    /// The admitted uid of a hardened unit.
    pub allow_uid: Option<u32>,
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
            Manager::SystemdUser | Manager::SystemdSystem => self.unit_name(),
        }
    }

    /// The socket the unit's daemon listens on.
    pub fn socket(&self, manager: Manager, default: &Path) -> PathBuf {
        match manager {
            Manager::SystemdSystem => hardened::socket(self.network.name()).into(),
            _ => default.to_path_buf(),
        }
    }

    fn args(&self, manager: Manager) -> Vec<String> {
        let mut v = vec![
            self.binary.display().to_string(),
            "--network".into(),
            self.network.name().into(),
            "--foreground".into(),
        ];
        if manager == Manager::SystemdSystem {
            v.extend([
                "--socket".into(),
                hardened::socket(self.network.name()),
                "--socket-group".into(),
                hardened::ACCOUNT.into(),
            ]);
            if let Some(uid) = self.allow_uid {
                v.extend(["--allow-uid".into(), uid.to_string()]);
            }
        }
        v
    }

    pub fn render(&self, manager: Manager) -> String {
        match manager {
            Manager::Launchd => self.render_launchd(),
            Manager::SystemdUser | Manager::SystemdSystem => self.render_systemd(manager),
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
        for a in self.args(Manager::Launchd) {
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

    /// A `systemd` unit. A daemon that keeps failing (bad config) gives up
    /// after five tries instead of looping forever. `TimeoutStopSec` covers
    /// `daemon.shutdown_grace` (30 s by default).
    ///
    /// The hardened unit runs as `gyges`. systemd creates `/var/lib/gyges`
    /// (0700) and `/run/gyges/<network>` (0750, group `gyges`, removed when
    /// the daemon stops), and the sandboxing lines take away what a wallet
    /// daemon does not need. `ProtectHome=yes` hides `/home`, so neither
    /// `gygesd` nor the node's cookie may live there.
    fn render_systemd(&self, manager: Manager) -> String {
        let hard = manager == Manager::SystemdSystem;
        let exec = self
            .args(manager)
            .iter()
            .map(|a| systemd_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let mut s = format!(
            "[Unit]\nDescription=Gyges wallet daemon ({}{})\n",
            self.network.name(),
            if hard { ", hardened" } else { "" }
        );
        if hard {
            s += "After=network-online.target\nWants=network-online.target\n";
        }
        s += &format!(
            "StartLimitIntervalSec=300\n\
             StartLimitBurst=5\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exec}\n"
        );
        if hard {
            let net = self.network.name();
            let a = hardened::ACCOUNT;
            s += &format!(
                "User={a}\n\
                 Group={a}\n\
                 Environment=\"GYGES_HOME={home}\"\n\
                 StateDirectory={a}\n\
                 StateDirectoryMode=0700\n\
                 RuntimeDirectory={a}/{net}\n\
                 RuntimeDirectoryMode=0750\n\
                 UMask=0077\n\
                 LimitCORE=0\n\
                 NoNewPrivileges=yes\n\
                 ProtectSystem=strict\n\
                 ProtectHome=yes\n\
                 PrivateTmp=yes\n\
                 PrivateDevices=yes\n\
                 ProtectKernelTunables=yes\n\
                 ProtectKernelModules=yes\n\
                 ProtectControlGroups=yes\n\
                 RestrictSUIDSGID=yes\n\
                 LockPersonality=yes\n\
                 RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
                home = hardened::HOME
            );
        } else if let Some(home) = &self.gyges_home {
            s += &format!(
                "Environment={}\n",
                systemd_quote(&format!("GYGES_HOME={}", home.display()))
            );
        }
        s += "Restart=on-failure\n\
              RestartSec=10\n\
              TimeoutStopSec=90\n\
              \n\
              [Install]\n";
        s += if hard {
            "WantedBy=multi-user.target\n"
        } else {
            "WantedBy=default.target\n"
        };
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
        let (program, args) = match self.manager {
            Manager::Launchd => (
                "launchctl",
                vec![
                    "bootout".into(),
                    format!("{}/{}", self.domain, spec.label()),
                ],
            ),
            Manager::SystemdUser | Manager::SystemdSystem => (
                "systemctl",
                self.manager
                    .systemctl(&["disable", "--now", &spec.unit_name()]),
            ),
        };
        Ok(r.run(program, &args)?.is_ok())
    }

    /// Load the unit from `path` and start it now and at every login (or
    /// boot, for a system unit).
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
            Manager::SystemdUser | Manager::SystemdSystem => (
                "systemctl",
                vec![
                    self.manager.systemctl(&["daemon-reload"]),
                    self.manager
                        .systemctl(&["enable", "--now", &spec.unit_name()]),
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
        if self.manager != Manager::Launchd {
            // Best effort: the file is already gone.
            let _ = r.run("systemctl", &self.manager.systemctl(&["daemon-reload"]))?;
        }
        Ok(())
    }

    /// Where to look when the daemon does not come up.
    fn log_hint(&self, spec: &Spec) -> String {
        match self.manager {
            Manager::Launchd => format!("launchctl print {}/{}", self.domain, spec.label()),
            Manager::SystemdUser => format!("journalctl --user -u {}", spec.unit_name()),
            Manager::SystemdSystem => format!("journalctl -u {}", spec.unit_name()),
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
        allow_uid: None,
    })
}

/// `gyges daemon install` flags.
#[derive(Debug, Clone, clap::Args)]
pub struct InstallArgs {
    /// Linux, as root: a system unit running gygesd as the `gyges` user,
    /// socket /run/gyges/<network>/gygesd.sock for the `gyges` group.
    #[arg(long)]
    pub hardened: bool,
    /// With --hardened: the user admitted to the socket and added to the
    /// `gyges` group [default: $SUDO_USER].
    #[arg(long, requires = "hardened", value_name = "NAME")]
    pub user: Option<String>,
}

/// The admitted user of a hardened install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub name: String,
    pub uid: u32,
}

/// What exists already; the steps create the rest.
#[derive(Clone, Copy, Debug, Default)]
pub struct Accounts {
    pub group_exists: bool,
    pub user_exists: bool,
    /// The admitted user is in the `gyges` group already.
    pub member: bool,
}

impl Accounts {
    fn lookup(admitted: &str) -> anyhow::Result<Self> {
        use nix::unistd::{Group, User};
        let group = Group::from_name(hardened::ACCOUNT)?;
        Ok(Self {
            member: group
                .as_ref()
                .is_some_and(|g| g.mem.iter().any(|m| m == admitted)),
            group_exists: group.is_some(),
            user_exists: User::from_name(hardened::ACCOUNT)?.is_some(),
        })
    }

    /// `groupadd`, `useradd` and `usermod` for whatever is missing. The
    /// daemon's account is a system account with no login shell, and its
    /// home is created by systemd (`StateDirectory`), not by `useradd`.
    pub fn steps(self, admitted: &str) -> Vec<(&'static str, Vec<String>)> {
        let a = hardened::ACCOUNT;
        let v = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let mut steps = Vec::new();
        if !self.group_exists {
            steps.push(("groupadd", v(&["--system", a])));
        }
        if !self.user_exists {
            steps.push((
                "useradd",
                v(&[
                    "--system",
                    "--gid",
                    a,
                    "--home-dir",
                    hardened::HOME,
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    a,
                ]),
            ));
        }
        if !self.member {
            steps.push(("usermod", v(&["--append", "--groups", a, admitted])));
        }
        steps
    }
}

/// Root, systemd and Linux, or a clear refusal.
fn require_hardened_platform() -> Result<(), CliError> {
    if Manager::native()? != Manager::SystemdUser {
        return Err(anyhow!("--hardened needs Linux with systemd").into());
    }
    if !nix::unistd::geteuid().is_root() {
        return Err(anyhow!("--hardened creates a system account and unit; run it as root").into());
    }
    Ok(())
}

/// `--user`, else `$SUDO_USER`; never root.
fn admitted_user(user: Option<String>) -> Result<Admitted, CliError> {
    let name = user
        .or_else(|| std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty()))
        .ok_or_else(|| {
            anyhow!("--hardened needs the user to admit: pass --user NAME or run through sudo")
        })?;
    let user = nix::unistd::User::from_name(&name)
        .map_err(|e| anyhow!("cannot look up user {name}: {e}"))?
        .ok_or_else(|| anyhow!("no user named {name}"))?;
    if user.uid.is_root() || name == hardened::ACCOUNT {
        return Err(anyhow!("admit the interactive user, not {name}").into());
    }
    Ok(Admitted {
        name,
        uid: user.uid.as_raw(),
    })
}

async fn install_hardened(ctx: &Ctx, user: Option<String>) -> Result<(), CliError> {
    require_hardened_platform()?;
    let admitted = admitted_user(user)?;
    let mut spec = spec_from_env(ctx.network.unwrap_or(Network::Mainnet))?;
    // `ProtectHome=yes` hides these from the service.
    if spec.binary.starts_with("/home") || spec.binary.starts_with("/root") {
        return Err(anyhow!(
            "{} is under a home directory, which the hardened unit cannot see; \
             install gygesd under /usr/local/bin (or set {DAEMON_BIN_ENV})",
            spec.binary.display()
        )
        .into());
    }
    spec.gyges_home = None;
    spec.allow_uid = Some(admitted.uid);

    let accounts = Accounts::lookup(&admitted.name)?;
    let mut system = System;
    for (program, args) in accounts.steps(&admitted.name) {
        if let Err(stderr) = system.run(program, &args)? {
            return Err(anyhow!("{program} {} failed: {stderr}", args.join(" ")).into());
        }
    }
    let manager = Manager::SystemdSystem;
    let report = install_with(ctx, &mut system, manager, &manager.unit_dir()?, &spec, WAIT).await?;
    let socket = hardened::socket(spec.network.name());
    ctx.report(&report, || {
        eprintln!(
            "installed {} and started gygesd for {} as user {}, home {}",
            report.unit_path,
            report.network,
            hardened::ACCOUNT,
            hardened::HOME
        );
        eprintln!(
            "admitted {} (uid {}){}",
            admitted.name,
            admitted.uid,
            if accounts.member {
                String::new()
            } else {
                format!(
                    " and added them to the {} group; they must log in again to use it",
                    hardened::ACCOUNT
                )
            }
        );
        eprintln!(
            "{} reaches the daemon with: export GYGES_SOCKET={socket}",
            admitted.name
        );
        eprintln!(
            "set zakura_rpc.cookie_path in {}/{}/config.toml to a cookie the {} user can read",
            hardened::HOME,
            report.network,
            hardened::ACCOUNT
        );
    })
}

pub async fn install(ctx: &Ctx, args: InstallArgs) -> Result<(), CliError> {
    if args.hardened {
        return install_hardened(ctx, args.user).await;
    }
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

pub async fn uninstall(ctx: &Ctx, hardened: bool) -> Result<(), CliError> {
    let manager = if hardened {
        require_hardened_platform()?;
        Manager::SystemdSystem
    } else {
        Manager::native()?
    };
    let spec = spec_from_env(ctx.network.unwrap_or(Network::Mainnet))
        // Uninstalling must work when gygesd is gone already.
        .or_else(|_| {
            Ok::<_, CliError>(Spec {
                network: ctx.network.unwrap_or(Network::Mainnet),
                binary: PathBuf::new(),
                gyges_home: None,
                allow_uid: None,
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
        if hardened {
            eprintln!(
                "the {} user and group and {} (keys included) are left in place",
                hardened::ACCOUNT,
                hardened::HOME
            );
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
    let socket = spec.socket(manager, &ctx.socket);

    // Reinstalling restarts: stop the old service and wait for its socket.
    if cmds.stop(runner, spec)? {
        let deadline = Instant::now() + wait;
        while uds::probe(&socket).await.is_ok() && Instant::now() < deadline {
            tokio::time::sleep(POLL).await;
        }
    }
    // A daemon still answering was started by hand; a unit would fail on
    // its pid lock and restart forever.
    if uds::probe(&socket).await.is_ok() {
        return Err(anyhow!(
            "a gygesd not started by a service is running on {}; stop it with \
             `gyges daemon stop` first",
            socket.display()
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
        // Root is not an admitted peer of the hardened daemon, so there the
        // socket accepting is the signal; elsewhere the handshake is.
        let r = if manager == Manager::SystemdSystem {
            uds::probe(&socket).await.map_err(|e| e.to_string())
        } else {
            ctx.connect().await.map(drop).map_err(|e| e.message())
        };
        match r {
            Ok(()) => break Ok(()),
            Err(e) if Instant::now() >= deadline => break Err(e),
            Err(_) => tokio::time::sleep(POLL).await,
        }
    };
    if let Err(last) = up {
        return Err(anyhow!(
            "{} is installed but gygesd did not answer on {} within {}s ({last}); see `{}` \
             and the logs under the network directory",
            path.display(),
            socket.display(),
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
            allow_uid: None,
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

    #[test]
    fn hardened_unit_runs_as_gyges_with_its_socket_outside_the_home() {
        let mut s = spec(Some("/ignored"));
        s.gyges_home = None;
        s.allow_uid = Some(1000);
        let u = s.render(Manager::SystemdSystem);
        assert!(
            u.contains(
                "ExecStart=\"/opt/gyges bin/gygesd\" \"--network\" \"testnet\" \"--foreground\" \
                 \"--socket\" \"/run/gyges/testnet/gygesd.sock\" \"--socket-group\" \"gyges\" \
                 \"--allow-uid\" \"1000\"\n"
            ),
            "{u}"
        );
        for line in [
            "User=gyges\n",
            "Group=gyges\n",
            "Environment=\"GYGES_HOME=/var/lib/gyges\"\n",
            "StateDirectoryMode=0700\n",
            "RuntimeDirectory=gyges/testnet\n",
            "RuntimeDirectoryMode=0750\n",
            "ProtectHome=yes\n",
            "LimitCORE=0\n",
            "WantedBy=multi-user.target\n",
        ] {
            assert!(u.contains(line), "{line}{u}");
        }
        assert_eq!(
            s.socket(Manager::SystemdSystem, Path::new("/x")),
            Path::new("/run/gyges/testnet/gygesd.sock")
        );
        assert_eq!(
            s.socket(Manager::SystemdUser, Path::new("/x")),
            Path::new("/x")
        );
        assert_eq!(
            Manager::SystemdSystem.unit_dir().unwrap(),
            Path::new("/etc/systemd/system")
        );
    }

    #[test]
    fn hardened_accounts_are_created_only_when_missing() {
        let all = Accounts::default().steps("alice");
        let progs: Vec<_> = all.iter().map(|(p, _)| *p).collect();
        assert_eq!(progs, ["groupadd", "useradd", "usermod"]);
        assert_eq!(all[0].1, ["--system", "gyges"]);
        assert!(
            all[1]
                .1
                .ends_with(&["/usr/sbin/nologin".to_string(), "gyges".into()])
        );
        assert!(all[1].1.contains(&"--no-create-home".to_string()));
        assert_eq!(all[2].1, ["--append", "--groups", "gyges", "alice"]);
        let none = Accounts {
            group_exists: true,
            user_exists: true,
            member: true,
        };
        assert!(none.steps("alice").is_empty());
    }

    /// Hardened install and uninstall use the system instance (no `--user`).
    #[test]
    fn hardened_uninstall_uses_the_system_instance() {
        let dir = tempfile::tempdir().unwrap();
        let s = spec(None);
        std::fs::write(dir.path().join(s.unit_name()), "x").unwrap();
        let mut r = Recorder::default();
        uninstall_with(&mut r, Manager::SystemdSystem, dir.path(), &s).unwrap();
        assert_eq!(
            r.calls,
            [
                "systemctl disable --now gygesd-testnet.service",
                "systemctl daemon-reload"
            ]
        );
    }
}
