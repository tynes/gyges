//! `gyges` – thin gRPC client for `gygesd` (CLI_SPEC.md, API.md).
//!
//! The CLI reads flags and environment variables only, never `config.toml`
//! (OVERVIEW.md Q-C1). Every invocation connects to the Unix socket, runs the
//! `GetInfo` handshake (API version, network), then issues exactly one RPC.
//! The command groups below `daemon` are declared so that `gyges --help`
//! matches CLI_SPEC.md; those not yet implemented exit 1 with a pointer to
//! ROADMAP.md.

#![forbid(unsafe_code)]
// Printing to stdout is this binary's purpose.
#![allow(clippy::print_stdout)]

mod client;
mod daemon;
mod exit;
mod key;
mod output;
mod prompt;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use gyges_proto::v1::Network;

use crate::client::Ctx;
use crate::exit::CliError;

#[derive(Debug, Parser)]
#[command(name = "gyges", version, about = "Gyges Zcash wallet CLI (pre-alpha)")]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Command,
}

/// Global options (CLI_SPEC.md §1.1).
#[derive(Debug, Clone, Args)]
pub struct Global {
    /// gygesd Unix Domain Socket [default: $GYGES_HOME/<network>/gygesd.sock].
    #[arg(short, long, env = "GYGES_SOCKET", global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Target key profile [default: the daemon's config `default_key`].
    #[arg(short, long, env = "GYGES_KEY", global = true, value_name = "KEY_ID")]
    pub key: Option<String>,
    /// mainnet | testnet | regtest; selects the daemon and is checked against it.
    #[arg(short, long, env = "GYGES_NETWORK", global = true, value_name = "NET", value_parser = parse_network)]
    pub network: Option<Network>,
    /// Emit machine-readable JSON to stdout (one object per line for streams).
    #[arg(short, long, global = true)]
    pub json: bool,
    /// Suppress progress bars, spinners and banners.
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Never prompt; exit 4 when a passphrase or hardware signature is needed.
    #[arg(long, env = "GYGES_NON_INTERACTIVE", global = true)]
    pub non_interactive: bool,
    /// Read the vault passphrase from file descriptor N.
    #[arg(long, global = true, value_name = "N")]
    pub passphrase_fd: Option<u32>,
}

fn parse_network(s: &str) -> Result<Network, String> {
    Network::from_name(s).ok_or_else(|| format!("expected mainnet, testnet or regtest, got `{s}`"))
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start, stop and inspect gygesd.
    #[command(subcommand)]
    Daemon(daemon::DaemonCmd),
    /// Key profiles and vault unlock/lock.
    #[command(subcommand)]
    Key(key::KeyCmd),
    /// Synchronisation status and control.
    Sync(Unimplemented),
    /// Addresses and terminal QR codes.
    Address(Unimplemented),
    /// Balances per pool.
    Balance(Unimplemented),
    /// Decrypted notes and UTXOs.
    Notes(Unimplemented),
    /// High-level transactions.
    Tx(Unimplemented),
    /// PCZT role pipeline for Unix pipes and air-gapped signing.
    Pczt(Unimplemented),
}

/// Accepts any arguments so that `gyges key list` is "not implemented"
/// (exit 1) rather than a usage error (exit 2).
#[derive(Debug, Args)]
struct Unimplemented {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    _rest: Vec<OsString>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.global.json;
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if json {
                println!("{}", output::error_json(&err));
            } else {
                eprintln!("gyges: {}", err.message());
            }
            err.exit().into()
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    let ctx = Ctx::new(cli.global)?;
    match cli.command {
        Command::Daemon(cmd) => daemon::run(&ctx, cmd).await,
        Command::Key(cmd) => key::run(&ctx, cmd).await,
        Command::Sync(_) => Err(CliError::NotImplemented("sync")),
        Command::Address(_) => Err(CliError::NotImplemented("address")),
        Command::Balance(_) => Err(CliError::NotImplemented("balance")),
        Command::Notes(_) => Err(CliError::NotImplemented("notes")),
        Command::Tx(_) => Err(CliError::NotImplemented("tx")),
        Command::Pczt(_) => Err(CliError::NotImplemented("pczt")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn global_flags_parse_anywhere() {
        let cli =
            Cli::try_parse_from(["gyges", "daemon", "status", "-n", "regtest", "--json"]).unwrap();
        assert_eq!(cli.global.network, Some(Network::Regtest));
        assert!(cli.global.json);
        assert!(Cli::try_parse_from(["gyges", "-n", "devnet", "daemon", "status"]).is_err());
    }

    #[test]
    fn unimplemented_groups_accept_any_arguments() {
        Cli::try_parse_from(["gyges", "key", "unlock", "--timeout", "5m"]).unwrap();
        Cli::try_parse_from(["gyges", "tx", "send", "--to", "u1x", "--amount", "1"]).unwrap();
    }

    #[test]
    fn key_commands_parse_per_spec() {
        let cli =
            Cli::try_parse_from(["gyges", "key", "init", "--id", "main", "--set-default"]).unwrap();
        assert!(
            matches!(cli.command, Command::Key(key::KeyCmd::Init(ref a)) if a.id == "main" && a.set_default)
        );
        let cli = Cli::try_parse_from([
            "gyges",
            "key",
            "restore",
            "--id",
            "r",
            "--birthday",
            "100",
            "--stdin",
            "--yes",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Key(key::KeyCmd::Restore(ref a)) if a.birthday == Some(100) && a.stdin && a.yes
        ));
        assert!(
            Cli::try_parse_from(["gyges", "key", "init"]).is_err(),
            "--id is required"
        );
        let cli = Cli::try_parse_from(["gyges", "--passphrase-fd", "3", "key", "list"]).unwrap();
        assert_eq!(cli.global.passphrase_fd, Some(3));
    }
}
