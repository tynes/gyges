//! `gygesd` binary: flags, daemonising, logging and signals around
//! [`gygesd::Daemon`] (CLI_SPEC.md §2.1 `gyges daemon start`).

#![forbid(unsafe_code)]

use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use clap::Parser;
use gyges_core::{Home, Network};
use gygesd::{Daemon, LogHub, Options};

#[derive(Debug, Parser)]
#[command(
    name = "gygesd",
    version,
    about = "Gyges Zcash wallet daemon (pre-alpha)"
)]
struct Args {
    /// Run in the foreground (do not daemonize).
    #[arg(short, long)]
    foreground: bool,
    /// Disable all network, RPC and Tor interfaces; offline proving and signing only.
    #[arg(long)]
    airgapped: bool,
    /// Network this daemon serves; selects `$GYGES_HOME/<network>/`.
    #[arg(
        short,
        long,
        env = "GYGES_NETWORK",
        default_value = "mainnet",
        value_name = "NET"
    )]
    network: Network,
    /// Override the zakurad JSON-RPC endpoint (e.g. http://127.0.0.1:8232).
    #[arg(long, value_name = "URL")]
    zakura_rpc: Option<String>,
    /// Path to the zakurad RPC auth cookie.
    #[arg(long, value_name = "PATH")]
    zakura_cookie: Option<String>,
    /// Archival lightwalletd/zaino gRPC URL for historical restores (no default).
    #[arg(long, value_name = "GRPC_URL")]
    fallback_lwd: Option<String>,
    /// Reach the fallback endpoint directly instead of over Tor.
    #[arg(long)]
    no_tor: bool,
    /// Root directory; one subdirectory per network.
    #[arg(long, env = "GYGES_HOME", value_name = "DIR", default_value_os_t = default_home())]
    home: PathBuf,
}

/// Set by the daemoniser on the child so that it does not log to the (null)
/// stderr it inherited.
const DAEMONIZED_ENV: &str = "GYGES_DAEMONIZED";

fn default_home() -> PathBuf {
    Home::from_env()
        .map(|h| h.root().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".gyges"))
}

impl Args {
    fn options(&self) -> Options {
        let mut opts = Options::new(Home::new(&self.home), self.network);
        opts.airgapped = self.airgapped;
        opts.zakura_rpc = self.zakura_rpc.clone();
        opts.zakura_cookie = self.zakura_cookie.clone();
        opts.fallback_lwd = self.fallback_lwd.clone();
        opts.no_tor = self.no_tor;
        opts
    }
}

fn main() -> ExitCode {
    // Every file the daemon creates (logs, SQLite, sockets) must be 0600/0700
    // (DATA_MODEL.md §1); a restrictive umask makes that hold without
    // per-site care.
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));

    let args = Args::parse();
    let daemonized = std::env::var_os(DAEMONIZED_ENV).is_some();

    if !args.foreground {
        return match daemonize(&args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("gygesd: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

    let hub = Arc::new(LogHub::default());
    let mut opts = args.options();
    opts.log_hub = Some(hub.clone());
    let daemon = match Daemon::prepare(opts) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("gygesd: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let _log_guard = match init_logging(&hub, &daemon, !daemonized) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("gygesd: cannot initialise logging: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(async move {
        let signals = signals()?;
        daemon.serve(signals).await
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = format!("{e:#}"), "gygesd failed");
            eprintln!("gygesd: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Resolve to a future that completes on SIGTERM or SIGINT. SIGHUP is
/// handled (and ignored) so that a closing terminal cannot kill a daemon
/// started from it.
fn signals() -> anyhow::Result<impl std::future::Future<Output = ()> + Send> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("SIGINT handler")?;
    let mut hup = signal(SignalKind::hangup()).context("SIGHUP handler")?;
    Ok(async move {
        loop {
            tokio::select! {
                _ = term.recv() => { tracing::info!("received SIGTERM"); return; }
                _ = int.recv() => { tracing::info!("received SIGINT"); return; }
                _ = hup.recv() => { tracing::info!("ignoring SIGHUP"); }
            }
        }
    })
}

/// `logs/gygesd.<date>.log` (daily rotation, seven files kept),
/// `logs/audit.log` and the `StreamLogs` tail (DATA_MODEL.md §1,
/// `gygesd::logs`); plus stderr when running in the foreground of a
/// terminal. `RUST_LOG` overrides `daemon.log_level`.
fn init_logging(
    hub: &Arc<LogHub>,
    daemon: &Daemon,
    to_stderr: bool,
) -> anyhow::Result<gygesd::logs::Guards> {
    let filter = gygesd::logs::filter_spec(&daemon.config().daemon.log_level);
    let logs = daemon.home.logs_dir(daemon.network);
    gygesd::logs::init(hub, &logs, &filter, to_stderr)
}

/// Validate the configuration here, where stderr is visible, then re-run
/// ourselves detached with `--foreground` and wait for the socket to accept.
fn daemonize(args: &Args) -> anyhow::Result<ExitCode> {
    let opts = args.options();
    let socket = opts.home.socket_path(opts.network);
    // Runs every startup check and takes the pid lock; dropping it releases
    // the lock (and removes the file) just before the child takes its own.
    drop(Daemon::prepare(opts)?);

    let exe = std::env::current_exe().context("cannot locate the gygesd executable")?;
    let mut child = Command::new(exe)
        .args(std::env::args_os().skip(1))
        .arg("--foreground")
        .env(DAEMONIZED_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .context("cannot spawn the daemon process")?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "the daemon exited during startup ({status}); run `gygesd --foreground` to see why, or check {}",
                args.home.join(args.network.name()).join("logs").display()
            );
        }
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            // The only stdout line this binary prints: `gyges daemon start`
            // relays it.
            #[allow(clippy::print_stdout)]
            {
                println!("gygesd started for {} (pid {})", args.network, child.id());
            }
            return Ok(ExitCode::SUCCESS);
        }
        if Instant::now() > deadline {
            anyhow::bail!(
                "the daemon (pid {}) did not open {} within 15s",
                child.id(),
                socket.display()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
