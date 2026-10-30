//! `gyges sync …` (docs/interface.md CLI §2.3, docs/interface.md API §4.4).
//!
//! `status`, `wait`, `run` and `mempool` (docs/architecture.md Sync §7).

use std::fmt::Write as _;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use gyges_proto::v1::{
    ErrorReason, GetSyncStatusRequest, GygesError, KeySyncStatus, RunSyncRequest,
    ScanMempoolRequest, StallReason, SyncProgress, SyncState, SyncTarget, WaitSyncRequest,
};

use crate::client::Ctx;
use crate::exit::CliError;

#[derive(Debug, Subcommand)]
pub enum SyncCmd {
    /// Per-key sync state, scanned tip, blocks remaining and blocks/sec.
    Status(StatusArgs),
    /// Block until a key is spendable (default), scanned, or a txid has N confirmations.
    Wait(WaitArgs),
    /// Scan now; --from rewinds the wallet before rescanning (asks unless --yes).
    Run(RunArgs),
    /// Force one mempool pass now; notes found show as pending in `balance`.
    Mempool,
}

#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    /// Every key, even when --key or GYGES_KEY is set.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Until {
    /// scanned_tip has reached the node's tip.
    Scanned,
    /// Scanned, and no scan range above priority Ignored remains.
    Spendable,
}

#[derive(Debug, Clone, Args)]
pub struct WaitArgs {
    /// What to wait for [default: spendable].
    #[arg(long, value_enum, conflicts_with = "txid")]
    pub until: Option<Until>,
    /// Wait until this transaction has --confirmations confirmations instead.
    #[arg(long, value_name = "TXID", requires = "confirmations")]
    pub txid: Option<String>,
    /// Confirmations required for --txid.
    #[arg(long, value_name = "N")]
    pub confirmations: Option<u32>,
    /// Give up after this long (exit 7), e.g. 30s, 10m.
    #[arg(long, value_name = "DURATION", value_parser = humantime::parse_duration)]
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// Rescan from this height, rewinding the wallet to HEIGHT - 1 first.
    #[arg(long, value_name = "HEIGHT")]
    pub from: Option<u32>,
    /// Stop at this height (not implemented yet).
    #[arg(long, value_name = "HEIGHT")]
    pub to: Option<u32>,
    /// Use the Tor fallback even inside the node's window (not implemented yet).
    #[arg(long)]
    pub force_tor_lwd: bool,
    /// Confirm a rewind without prompting.
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(ctx: &Ctx, cmd: SyncCmd) -> Result<(), CliError> {
    match cmd {
        SyncCmd::Status(args) => status(ctx, args).await,
        SyncCmd::Wait(args) => wait(ctx, args).await,
        SyncCmd::Run(args) => run_sync(ctx, args).await,
        SyncCmd::Mempool => mempool(ctx).await,
    }
}

/// `sync mempool`: every key is scanned; `--key` picks whose notes are
/// counted (all keys without it).
async fn mempool(ctx: &Ctx) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .scan_mempool(ScanMempoolRequest {
            key_id: ctx.key.clone(),
        })
        .await?
        .into_inner();
    // The scan summary is the command's result, so `-q` keeps it.
    ctx.print(&resp, || {
        format!(
            "{}\n",
            render_mempool(resp.transactions_scanned, resp.notes_found)
        )
    })
}

fn render_mempool(transactions: u32, notes: u32) -> String {
    let plural = |n: u32, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    format!(
        "scanned {}, found {}",
        plural(transactions, "transaction", "transactions"),
        plural(notes, "note", "notes")
    )
}

async fn status(ctx: &Ctx, args: StatusArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let key_id = if args.all {
        String::new()
    } else {
        ctx.key.clone()
    };
    let resp = conn
        .client
        .get_sync_status(GetSyncStatusRequest { key_id })
        .await?
        .into_inner();
    ctx.print(&resp, || render_status(&resp.keys))
}

/// The state word of docs/interface.md CLI §2.3: `initializing`, `scanning`,
/// `rewinding`, `synced`, `stalled(<reason>)`.
pub fn state_word(k: &KeySyncStatus) -> String {
    match k.state() {
        SyncState::Stalled => format!(
            "stalled({})",
            match k.stall_reason() {
                StallReason::PrunedPastScanTip => "pruned-past-scan-tip",
                StallReason::ChainInconsistent => "chain-inconsistent",
                StallReason::FallbackUntrusted => "fallback-untrusted",
                StallReason::NodeUnreachable => "offline",
                StallReason::FallbackUnreachable => "fallback-unreachable",
                StallReason::Unspecified => "unknown",
            }
        ),
        SyncState::Scanning => "scanning".into(),
        SyncState::ValidatingHandoff => "backfilling".into(),
        SyncState::Rewinding => "rewinding".into(),
        SyncState::Idle if k.scanned => "synced".into(),
        SyncState::Idle | SyncState::Unspecified => "initializing".into(),
    }
}

/// Human-readable `sync status`.
pub fn render_status(keys: &[KeySyncStatus]) -> String {
    if keys.is_empty() {
        return "no keys with a wallet; create one with `gyges key init --id main`\n".to_string();
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<18} {:<30} {:>10} {:>10} {:>9} {:>8}  FLAGS",
        "KEY", "STATE", "SCANNED", "TIP", "REMAINING", "BLK/S"
    );
    for k in keys {
        let flags = match (k.scanned, k.spendable) {
            (true, true) => "scanned spendable",
            (true, false) => "scanned",
            _ => "",
        };
        let _ = writeln!(
            s,
            "{:<18} {:<30} {:>10} {:>10} {:>9} {:>8.1}  {}",
            k.key_id,
            state_word(k),
            k.scanned_tip,
            k.chain_tip,
            k.blocks_remaining,
            k.blocks_per_sec,
            flags
        );
        if k.state() == SyncState::Stalled && !k.detail.is_empty() {
            let _ = writeln!(s, "{:<18} {}", "", k.detail);
        }
    }
    s
}

/// One progress line for stderr while waiting.
pub fn progress_line(p: &SyncProgress) -> String {
    let Some(k) = &p.status else {
        return String::new();
    };
    let mut line = format!(
        "{}: {} scanned {}/{}",
        k.key_id,
        state_word(k),
        k.scanned_tip,
        k.chain_tip
    );
    if k.blocks_remaining > 0 {
        let _ = write!(line, ", {} to go", k.blocks_remaining);
    }
    if k.blocks_per_sec > 0.0 {
        let _ = write!(line, " ({:.0} blk/s)", k.blocks_per_sec);
    }
    if p.confirmations > 0 {
        let _ = write!(line, ", {} confirmations", p.confirmations);
    }
    line
}

async fn wait(ctx: &Ctx, args: WaitArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let req = WaitSyncRequest {
        key_id: ctx.key.clone(),
        until: match args.until {
            Some(Until::Scanned) => SyncTarget::Scanned,
            Some(Until::Spendable) | None => SyncTarget::Spendable,
        } as i32,
        txid: args.txid.clone().unwrap_or_default(),
        confirmations: args.confirmations.unwrap_or(0),
    };
    let stream = conn.client.wait_sync(req).await?.into_inner();
    follow(ctx, stream, args.timeout).await
}

async fn run_sync(ctx: &Ctx, args: RunArgs) -> Result<(), CliError> {
    // The daemon refuses both; fail like every other unimplemented feature.
    if args.to.is_some() {
        return Err(CliError::NotImplemented("sync run --to"));
    }
    if args.force_tor_lwd {
        return Err(CliError::NotImplemented("sync run --force-tor-lwd"));
    }
    let mut conn = ctx.connect().await?;
    let mut confirm_rewind = false;
    if let Some(from) = args.from {
        // Is it a rewind? Ask the daemon where the key stands.
        let status = conn
            .client
            .get_sync_status(GetSyncStatusRequest {
                key_id: ctx.key.clone(),
            })
            .await?
            .into_inner();
        let scanned_tip = status.keys.first().map_or(0, |k| k.scanned_tip);
        if from <= scanned_tip {
            ctx.prompter.confirm(
                &format!(
                    "Rescanning from {from} rewinds the wallet from {scanned_tip}: notes, nullifiers and \
                     witnesses above {} are rebuilt (unmined transactions are kept). Continue?",
                    from.saturating_sub(1)
                ),
                args.yes,
                "--yes",
            )?;
            confirm_rewind = true;
        }
    }
    let stream = conn
        .client
        .run_sync(RunSyncRequest {
            key_id: ctx.key.clone(),
            from_height: args.from.unwrap_or(0),
            to_height: args.to.unwrap_or(0),
            force_tor_lwd: args.force_tor_lwd,
            confirm_rewind,
        })
        .await?
        .into_inner();
    follow(ctx, stream, None).await
}

/// Print each progress element (stderr line, or one JSON object per line
/// with `--json`) until `done`, an error, Ctrl-C (exit 8) or `timeout`
/// (exit 7 with `NOT_SYNCED`).
async fn follow(
    ctx: &Ctx,
    mut stream: tonic::Streaming<SyncProgress>,
    timeout: Option<Duration>,
) -> Result<(), CliError> {
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t);
    let mut last: Option<SyncProgress> = None;
    loop {
        let next = tokio::select! {
            item = stream.message() => item,
            _ = tokio::signal::ctrl_c() => return Err(CliError::Cancelled),
            () = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await,
                }
            } => {
                let key = last.as_ref().and_then(|p| p.status.as_ref()).map(|k| k.key_id.clone()).unwrap_or_default();
                let mut err = GygesError::new(
                    ErrorReason::NotSynced,
                    format!(
                        "still not there after {}{}",
                        humantime::format_duration(timeout.unwrap_or_default()),
                        last.as_ref().map(|p| format!(" ({})", progress_line(p))).unwrap_or_default()
                    ),
                );
                if !key.is_empty() {
                    err = err.with_key(key);
                }
                return Err(CliError::Daemon(err));
            }
        };
        match next? {
            None => return Ok(()),
            Some(p) => {
                ctx.report(&p, || {
                    eprintln!("{}", progress_line(&p));
                })?;
                let done = p.done;
                last = Some(p);
                if done {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(state: SyncState, scanned: bool, spendable: bool) -> KeySyncStatus {
        KeySyncStatus {
            key_id: "main".into(),
            state: state as i32,
            scanned_tip: 120,
            chain_tip: 125,
            scanned,
            spendable,
            blocks_remaining: 5,
            blocks_per_sec: 42.5,
            ..Default::default()
        }
    }

    #[test]
    fn state_words_follow_the_spec() {
        assert_eq!(
            state_word(&row(SyncState::Idle, false, false)),
            "initializing"
        );
        assert_eq!(state_word(&row(SyncState::Idle, true, true)), "synced");
        assert_eq!(
            state_word(&row(SyncState::Scanning, false, false)),
            "scanning"
        );
        assert_eq!(
            state_word(&row(SyncState::Rewinding, false, false)),
            "rewinding"
        );
        let mut k = row(SyncState::Stalled, false, false);
        k.stall_reason = StallReason::PrunedPastScanTip as i32;
        assert_eq!(state_word(&k), "stalled(pruned-past-scan-tip)");
        k.stall_reason = StallReason::NodeUnreachable as i32;
        assert_eq!(state_word(&k), "stalled(offline)");
    }

    #[test]
    fn status_table_and_progress_line() {
        let s = render_status(&[row(SyncState::Scanning, false, false)]);
        assert!(s.starts_with("KEY"), "{s}");
        assert!(
            s.contains("main") && s.contains("scanning") && s.contains("42.5"),
            "{s}"
        );
        let mut k = row(SyncState::Stalled, false, false);
        k.detail = "node pruned past key".into();
        let s = render_status(&[k]);
        assert!(s.contains("node pruned past key"), "{s}");
        assert!(render_status(&[]).contains("no keys"));

        let p = SyncProgress {
            status: Some(row(SyncState::Scanning, false, false)),
            confirmations: 0,
            done: false,
        };
        let line = progress_line(&p);
        assert_eq!(line, "main: scanning scanned 120/125, 5 to go (42 blk/s)");
    }
}
