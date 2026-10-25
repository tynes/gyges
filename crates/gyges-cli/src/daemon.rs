//! `gyges daemon …` (CLI_SPEC.md §2.1, API.md §7).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use gyges_proto::uds;
use gyges_proto::v1::{GetInfoResponse, LogEntry, LogLevel, ShutdownRequest, StreamLogsRequest};

use crate::client::Ctx;
use crate::exit::CliError;
use crate::output::{format_unix, to_json};

#[derive(Debug, Subcommand)]
pub enum DaemonCmd {
    /// Start gygesd for --network and create its Unix socket.
    Start(StartArgs),
    /// Stop gygesd: finish the current batch, checkpoint SQLite, zeroize keys.
    Stop {
        /// Abort in-flight proving and broadcasts instead of waiting for them.
        #[arg(long)]
        force: bool,
    },
    /// Daemon and API version, network, node bounds, Tor and fallback state, keys.
    Status,
    /// Stream structured daemon logs through the StreamLogs RPC.
    Logs {
        /// Keep the stream open after the replay.
        #[arg(short, long)]
        follow: bool,
        /// Replay the last N lines first.
        #[arg(long, default_value_t = 100, value_name = "N")]
        lines: u32,
        /// Stream audit.log instead of the main log.
        #[arg(long)]
        audit: bool,
    },
    /// Write a launchd / systemd --user unit that runs gygesd --foreground.
    Install,
    /// Remove the unit written by `daemon install`.
    Uninstall,
}

/// Flags forwarded to `gygesd`.
#[derive(Debug, Clone, Args)]
pub struct StartArgs {
    /// Run in the foreground (do not daemonize).
    #[arg(short, long)]
    pub foreground: bool,
    /// Disable all network/RPC/Tor interfaces (signer-only profiles, PCZT proving and signing only).
    #[arg(long)]
    pub airgapped: bool,
    /// Override the zakurad JSON-RPC endpoint (e.g. http://127.0.0.1:8232).
    #[arg(long, value_name = "URL")]
    pub zakura_rpc: Option<String>,
    /// Path to the zakurad RPC auth cookie.
    #[arg(long, value_name = "PATH")]
    pub zakura_cookie: Option<String>,
    /// Archival lightwalletd/zaino gRPC URL for historical restores (no default).
    #[arg(long, value_name = "GRPC_URL")]
    pub fallback_lwd: Option<String>,
    /// Reach the fallback endpoint directly instead of over Tor.
    #[arg(long)]
    pub no_tor: bool,
}

/// `GYGES_DAEMON_BIN` overrides where `gygesd` is found.
pub const DAEMON_BIN_ENV: &str = "GYGES_DAEMON_BIN";

pub async fn run(ctx: &Ctx, cmd: DaemonCmd) -> Result<(), CliError> {
    match cmd {
        DaemonCmd::Start(args) => start(ctx, args).await,
        DaemonCmd::Stop { force } => stop(ctx, force).await,
        DaemonCmd::Status => status(ctx).await,
        DaemonCmd::Logs {
            follow,
            lines,
            audit,
        } => logs(ctx, follow, lines, audit).await,
        DaemonCmd::Install => Err(CliError::NotImplemented("daemon install")),
        DaemonCmd::Uninstall => Err(CliError::NotImplemented("daemon uninstall")),
    }
}

/// Locate `gygesd`: `GYGES_DAEMON_BIN`, then next to this executable, then
/// `PATH`.
pub fn daemon_binary() -> PathBuf {
    if let Some(p) = std::env::var_os(DAEMON_BIN_ENV).filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("gygesd");
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("gygesd")
}

fn daemon_args(ctx: &Ctx, args: &StartArgs) -> Vec<String> {
    let mut v = vec!["--network".to_string(), ctx.network_name().to_string()];
    if args.airgapped {
        v.push("--airgapped".into());
    }
    if let Some(u) = &args.zakura_rpc {
        v.extend(["--zakura-rpc".into(), u.clone()]);
    }
    if let Some(p) = &args.zakura_cookie {
        v.extend(["--zakura-cookie".into(), p.clone()]);
    }
    if let Some(u) = &args.fallback_lwd {
        v.extend(["--fallback-lwd".into(), u.clone()]);
    }
    if args.no_tor {
        v.push("--no-tor".into());
    }
    v
}

async fn start(ctx: &Ctx, args: StartArgs) -> Result<(), CliError> {
    // Already running? Then this is a no-op (and the handshake has checked
    // the network).
    match ctx.connect().await {
        Ok(conn) => {
            if ctx.json {
                println!("{}", to_json(&conn.info)?);
            } else if !ctx.quiet {
                eprintln!(
                    "gygesd is already running for {} (since {})",
                    conn.info.network().name(),
                    format_unix(conn.info.started_at)
                );
            }
            return Ok(());
        }
        Err(CliError::Unreachable { .. }) => {}
        Err(e) => return Err(e),
    }

    let bin = daemon_binary();
    let mut cmd = tokio::process::Command::new(&bin);
    cmd.args(daemon_args(ctx, &args));

    if args.foreground {
        // Hand the terminal to the daemon and relay its exit status. SIGINT
        // reaches both processes; the daemon shuts down cleanly and we wait
        // for it rather than dying first.
        cmd.arg("--foreground");
        let mut child = cmd.spawn().map_err(|e| spawn_error(&bin, e))?;
        let ignore_ctrl_c = tokio::spawn(async {
            loop {
                if tokio::signal::ctrl_c().await.is_err() {
                    break;
                }
            }
        });
        let status = child.wait().await?;
        ignore_ctrl_c.abort();
        return if status.success() {
            Ok(())
        } else {
            Err(CliError::Other(anyhow::anyhow!(
                "gygesd exited with {status}"
            )))
        };
    }

    // gygesd daemonises itself, validates first, and prints one line on
    // success; its stderr is the error report.
    let output = cmd
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| spawn_error(&bin, e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Other(anyhow::anyhow!(
            "gygesd failed to start ({}): {}",
            output.status,
            stderr
                .trim()
                .strip_prefix("gygesd: ")
                .unwrap_or(stderr.trim())
        )));
    }
    let conn = ctx.connect().await?;
    if ctx.json {
        println!("{}", to_json(&conn.info)?);
    } else if !ctx.quiet {
        let line = String::from_utf8_lossy(&output.stdout);
        let line = line.trim();
        if line.is_empty() {
            eprintln!("gygesd started for {}", conn.info.network().name());
        } else {
            eprintln!("{line}");
        }
    }
    Ok(())
}

fn spawn_error(bin: &std::path::Path, e: std::io::Error) -> CliError {
    CliError::Other(anyhow::anyhow!(
        "cannot run {} ({e}); set {DAEMON_BIN_ENV} or put gygesd on PATH",
        bin.display()
    ))
}

async fn stop(ctx: &Ctx, force: bool) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .shutdown(ShutdownRequest { graceful: !force })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    // Wait for the socket to go away (the listener, then the file the
    // daemon unlinks on its way out) so that `stop && start` works in
    // scripts and "stopped" means the file is gone.
    let deadline = Instant::now() + Duration::from_secs(60);
    while uds::probe(&ctx.socket).await.is_ok() || ctx.socket.exists() {
        if Instant::now() > deadline {
            return Err(CliError::Other(anyhow::anyhow!(
                "gygesd acknowledged the shutdown but {} is still open after 60s",
                ctx.socket.display()
            )));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else if !ctx.quiet {
        eprintln!("gygesd stopped");
    }
    Ok(())
}

async fn status(ctx: &Ctx) -> Result<(), CliError> {
    let conn = ctx.connect().await?;
    if ctx.json {
        println!("{}", to_json(&conn.info)?);
    } else {
        print!("{}", render_status(&conn.info));
    }
    Ok(())
}

/// Human-readable `daemon status` (CLI_SPEC.md §2.1).
pub fn render_status(info: &GetInfoResponse) -> String {
    use std::fmt::Write as _;
    let api = info.api_version.unwrap_or_default();
    let mut s = String::new();
    let _ = writeln!(
        s,
        "gygesd {} (API {}.{}) on {}{}",
        info.daemon_version,
        api.major,
        api.minor,
        info.network().name(),
        if info.airgapped { ", air-gapped" } else { "" }
    );
    let _ = writeln!(s, "  started:      {}", format_unix(info.started_at));
    match &info.node {
        Some(n) if n.connected => {
            let _ = writeln!(
                s,
                "  node:         connected, tip {} ({}), retained from {}{}",
                n.tip_height,
                &n.tip_hash[..n.tip_hash.len().min(12)],
                n.retained_from,
                if n.pruned {
                    format!(", tx_retention {}", n.tx_retention)
                } else {
                    String::new()
                }
            );
        }
        Some(n) => {
            let _ = writeln!(
                s,
                "  node:         not connected{}",
                if n.last_error.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", n.last_error)
                }
            );
        }
        None => {
            let _ = writeln!(s, "  node:         unknown");
        }
    }
    let tor = info.tor.clone().unwrap_or_default();
    let _ = writeln!(
        s,
        "  tor:          {}",
        match tor.state() {
            // Tor configured but not needed yet (it bootstraps on the first backfill).
            gyges_proto::v1::TorState::Unspecified => "not started".to_string(),
            gyges_proto::v1::TorState::Disabled => "disabled".to_string(),
            gyges_proto::v1::TorState::Bootstrapping =>
                format!("bootstrapping {}%", tor.bootstrap_percent),
            gyges_proto::v1::TorState::Ready => "ready".to_string(),
            gyges_proto::v1::TorState::Failed => format!("failed ({})", tor.last_error),
        }
    );
    match &info.fallback {
        Some(f) if f.enabled => {
            let _ = writeln!(
                s,
                "  fallback:     {} ({}, trust: {})",
                f.grpc_url,
                if f.use_tor { "over Tor" } else { "direct" },
                match f.trust() {
                    gyges_proto::v1::FallbackTrust::Verified => "verified",
                    gyges_proto::v1::FallbackTrust::Untrusted => "UNTRUSTED",
                    _ => "untested",
                }
            );
        }
        _ => {
            let _ = writeln!(s, "  fallback:     disabled");
        }
    }
    let _ = writeln!(
        s,
        "  default key:  {}",
        if info.default_key.is_empty() {
            "(none)"
        } else {
            &info.default_key
        }
    );
    let _ = writeln!(s, "  unlock ttl:   {}s", info.unlock_ttl_secs);
    let _ = writeln!(s, "  min conf:     {}", info.default_min_confirmations);
    if info.keys.is_empty() {
        let _ = writeln!(s, "  keys:         (none)");
    } else {
        let _ = writeln!(s, "  keys:");
        for k in &info.keys {
            let _ = writeln!(
                s,
                "    {:<16} {:<12} {:<8} birthday {} scanned {}{}",
                k.key_id,
                crate::key::mode_name(k.signing_mode()),
                if k.locked { "locked" } else { "UNLOCKED" },
                k.birthday_height,
                k.scanned_tip,
                if k.is_default { " (default)" } else { "" }
            );
            if k.transparent_best_effort_below > 0 {
                let _ = writeln!(
                    s,
                    "      transparent history below {} is best-effort (from the fallback endpoint)",
                    k.transparent_best_effort_below
                );
            }
        }
    }
    s
}

async fn logs(ctx: &Ctx, follow: bool, lines: u32, audit: bool) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let mut stream = conn
        .client
        .stream_logs(StreamLogsRequest {
            lines,
            follow,
            audit,
            ..Default::default()
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    loop {
        let entry = tokio::select! {
            r = stream.message() => r.map_err(CliError::from_status)?,
            _ = tokio::signal::ctrl_c() => return Err(CliError::Cancelled),
        };
        let Some(entry) = entry else { return Ok(()) };
        if ctx.json {
            println!("{}", to_json(&entry)?);
        } else {
            println!("{}", render_log(&entry));
        }
    }
}

fn render_log(e: &LogEntry) -> String {
    let secs = e.timestamp_unix_ms.div_euclid(1000);
    let level = match e.level() {
        LogLevel::Unspecified => "?????",
        LogLevel::Error => "ERROR",
        LogLevel::Warn => " WARN",
        LogLevel::Info => " INFO",
        LogLevel::Debug => "DEBUG",
        LogLevel::Trace => "TRACE",
    };
    let mut s = format!("{} {level} {}: {}", format_unix(secs), e.target, e.message);
    for (k, v) in &e.fields {
        s.push_str(&format!(" {k}={v}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::{ApiVersion, Network, NodeStatus};

    #[test]
    fn status_rendering_mentions_the_essentials() {
        let info = GetInfoResponse {
            network: Network::Regtest as i32,
            daemon_version: "0.1.0".into(),
            api_version: Some(ApiVersion { major: 0, minor: 1 }),
            airgapped: true,
            node: Some(NodeStatus {
                connected: false,
                ..Default::default()
            }),
            default_key: "main".into(),
            unlock_ttl_secs: 300,
            default_min_confirmations: 10,
            ..Default::default()
        };
        let s = render_status(&info);
        assert!(
            s.starts_with("gygesd 0.1.0 (API 0.1) on regtest, air-gapped\n"),
            "{s}"
        );
        assert!(s.contains("node:         not connected"));
        assert!(s.contains("default key:  main"));
        assert!(s.contains("keys:         (none)"));
    }

    #[test]
    fn daemon_args_forward_only_what_was_given() {
        let ctx = Ctx {
            socket: "/x".into(),
            network: Some(Network::Regtest),
            key: String::new(),
            json: false,
            quiet: false,
            prompter: crate::prompt::Prompter {
                non_interactive: true,
                passphrase_fd: None,
            },
        };
        let args = StartArgs {
            foreground: true,
            airgapped: true,
            zakura_rpc: Some("http://127.0.0.1:18232".into()),
            zakura_cookie: None,
            fallback_lwd: None,
            no_tor: true,
        };
        assert_eq!(
            daemon_args(&ctx, &args),
            [
                "--network",
                "regtest",
                "--airgapped",
                "--zakura-rpc",
                "http://127.0.0.1:18232",
                "--no-tor"
            ]
        );
    }
}
