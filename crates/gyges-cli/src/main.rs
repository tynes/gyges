//! `gyges` – thin gRPC client for `gygesd` (CLI_SPEC.md, API.md).
//!
//! The CLI reads flags and environment variables only, never `config.toml`
//! (OVERVIEW.md Q-C1). Nothing is implemented yet; the command tree below is
//! the top level of CLI_SPEC.md so that `gyges --help` matches the spec.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// Process exit codes (OVERVIEW.md Q-C3, API.md). Kept in one place so the
/// mapping from the typed `GygesError.reason` lives in a single function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    Ok = 0,
    Failure = 1,
    Usage = 2,
    DaemonUnreachable = 3,
    AuthorizationRequired = 4,
    InsufficientFunds = 5,
    InvalidArgument = 6,
    NotReady = 7,
    Cancelled = 8,
    HardwareSigner = 9,
    NodeRejected = 10,
}

#[derive(Debug, Parser)]
#[command(
    name = "gyges",
    version,
    about = "Gyges Zcash wallet CLI (pre-alpha, not functional)"
)]
struct Cli {
    /// Path to the gygesd Unix Domain Socket.
    #[arg(short, long, env = "GYGES_SOCKET", global = true)]
    socket: Option<String>,
    /// Target key profile; empty means the daemon's `default_key`.
    #[arg(short, long, env = "GYGES_KEY", global = true)]
    key: Option<String>,
    /// Network: mainnet | testnet | regtest. Selects `~/.gyges/<network>/`.
    #[arg(short, long, env = "GYGES_NETWORK", global = true)]
    network: Option<String>,
    /// Emit machine-readable JSON (proto3 JSON of the gRPC response).
    #[arg(short, long, global = true)]
    json: bool,
    /// Suppress progress bars, spinners and banners.
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Never prompt; exit 4 when a passphrase or hardware signature is needed.
    #[arg(long, env = "GYGES_NON_INTERACTIVE", global = true)]
    non_interactive: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start, stop and inspect gygesd.
    Daemon,
    /// Key profiles and vault unlock/lock.
    Key,
    /// Synchronisation status and control.
    Sync,
    /// Addresses and terminal QR codes.
    Address,
    /// Balances per pool.
    Balance,
    /// Decrypted notes and UTXOs.
    Notes,
    /// High-level transactions.
    Tx,
    /// PCZT role pipeline for Unix pipes and air-gapped signing.
    Pczt,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    eprintln!(
        "gyges: `{:?}` is not implemented yet; see ROADMAP.md",
        cli.command
    );
    ExitCode::from(Exit::Failure as u8)
}
