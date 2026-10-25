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

mod address;
mod amount;
mod balance;
mod client;
mod daemon;
mod exit;
mod history;
mod key;
mod notes;
mod output;
mod pczt;
mod prompt;
mod sync;
mod tx;

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
    #[command(subcommand)]
    Sync(sync::SyncCmd),
    /// Addresses and terminal QR codes.
    #[command(subcommand)]
    Address(address::AddressCmd),
    /// Balances per pool.
    Balance(balance::BalanceArgs),
    /// Decrypted notes and UTXOs.
    Notes(notes::NotesArgs),
    /// High-level transactions.
    #[command(subcommand)]
    Tx(tx::TxCmd),
    /// PCZT role pipeline for Unix pipes and air-gapped signing.
    #[command(subcommand)]
    Pczt(pczt::PcztCmd),
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
        Command::Sync(cmd) => sync::run(&ctx, cmd).await,
        Command::Address(cmd) => address::run(&ctx, cmd).await,
        Command::Balance(args) => balance::run(&ctx, args).await,
        Command::Notes(args) => notes::run(&ctx, args).await,
        Command::Tx(cmd) => tx::run(&ctx, cmd).await,
        Command::Pczt(cmd) => pczt::run(&ctx, cmd).await,
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
        Cli::try_parse_from(["gyges", "key", "backup", "-o", "x.tar"]).unwrap();
    }

    #[test]
    fn address_notes_and_history_commands_parse_per_spec() {
        let cli = Cli::try_parse_from(["gyges", "address", "current"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Address(address::AddressCmd::Current(ref a)) if !a.qr
        ));
        let cli = Cli::try_parse_from([
            "gyges",
            "address",
            "new",
            "--receivers",
            "orchard,transparent",
            "--label",
            "shop",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Address(address::AddressCmd::New(ref a))
                if a.receivers == [address::ReceiverArg::Orchard, address::ReceiverArg::Transparent]
                    && a.label.as_deref() == Some("shop")
        ));
        assert!(
            Cli::try_parse_from(["gyges", "address", "new", "--receivers", "sprout"]).is_err(),
            "unknown receivers are a usage error"
        );
        Cli::try_parse_from(["gyges", "address", "qr", "u1x"]).unwrap();
        Cli::try_parse_from(["gyges", "address", "qr"]).unwrap();
        let cli = Cli::try_parse_from(["gyges", "address", "inspect", "t1x"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Address(address::AddressCmd::Inspect { ref address }) if address == "t1x"
        ));
        let cli = Cli::try_parse_from(["gyges", "notes", "--pool", "orchard", "--spent"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Notes(ref a) if a.pool == Some(notes::PoolArg::Orchard) && a.spent
        ));
        assert!(Cli::try_parse_from(["gyges", "notes", "--spent", "--unspent"]).is_err());
        let cli = Cli::try_parse_from(["gyges", "tx", "list", "--limit", "5"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Tx(tx::TxCmd::List(ref a)) if a.limit == Some(5) && a.before.is_none()
        ));
        let cli = Cli::try_parse_from(["gyges", "tx", "status", "ab", "--pir"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Tx(tx::TxCmd::Status(ref a)) if a.txid == "ab" && a.pir
        ));
        assert!(Cli::try_parse_from(["gyges", "tx", "status"]).is_err());
    }

    #[test]
    fn tx_and_balance_commands_parse_per_spec() {
        let cli = Cli::try_parse_from([
            "gyges",
            "tx",
            "send",
            "--to",
            "u1x",
            "--amount",
            "1.25",
            "--memo",
            "hi",
            "--dry-run",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Tx(tx::TxCmd::Send(ref a))
                if a.to == "u1x"
                    && a.amount == crate::amount::ParsedAmount::Zatoshis(125_000_000)
                    && a.memo.as_ref().map(|m| m.0.as_slice()) == Some(b"hi".as_slice())
                    && a.dry_run
                    && !a.yes
        ));
        assert!(
            Cli::try_parse_from(["gyges", "tx", "send", "--to", "u1x", "--amount", "1,000"])
                .is_err(),
            "thousands separators are a usage error"
        );
        assert!(Cli::try_parse_from(["gyges", "tx", "send", "--to", "u1x"]).is_err());
        let cli =
            Cli::try_parse_from(["gyges", "tx", "shield", "--threshold", "0.5", "--yes"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Tx(tx::TxCmd::Shield(ref a)) if a.threshold == Some(50_000_000) && a.yes
        ));
        assert!(Cli::try_parse_from(["gyges", "tx", "shield", "--threshold", "max"]).is_err());
        let cli = Cli::try_parse_from(["gyges", "balance", "--min-conf", "3"]).unwrap();
        assert!(matches!(cli.command, Command::Balance(ref a) if a.min_conf == Some(3)));
        Cli::try_parse_from(["gyges", "tx", "abort", "abcd"]).unwrap();
    }

    #[test]
    fn pczt_commands_parse_per_spec() {
        let cli = Cli::try_parse_from([
            "gyges", "pczt", "create", "--to", "u1x", "--amount", "2.5", "-o", "tx.pczt",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Pczt(pczt::PcztCmd::Create(ref a))
                if a.to == "u1x"
                    && a.amount == crate::amount::ParsedAmount::Zatoshis(250_000_000)
                    && a.out.as_deref() == Some(std::path::Path::new("tx.pczt"))
        ));
        let cli = Cli::try_parse_from(["gyges", "pczt", "prove", "-", "-o", "out.pczt"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Pczt(pczt::PcztCmd::Prove(ref a))
                if a.file.as_deref() == Some(std::path::Path::new("-"))
        ));
        let cli = Cli::try_parse_from(["gyges", "pczt", "sign"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Pczt(pczt::PcztCmd::Sign(ref a)) if a.io.file.is_none() && a.qr_out.is_none()
        ));
        let cli = Cli::try_parse_from(["gyges", "pczt", "combine", "a.pczt", "b.pczt"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Pczt(pczt::PcztCmd::Combine(ref a)) if a.files.len() == 2
        ));
        assert!(
            Cli::try_parse_from(["gyges", "pczt", "combine", "a.pczt"]).is_err(),
            "combine needs two files"
        );
        let cli =
            Cli::try_parse_from(["gyges", "pczt", "broadcast", "c.pczt", "--via-tor"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Pczt(pczt::PcztCmd::Broadcast(ref a)) if a.via_tor
        ));
        Cli::try_parse_from([
            "gyges",
            "pczt",
            "qr-import",
            "--session",
            "x",
            "ur:zcash-pczt/1",
        ])
        .unwrap();
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
        let cli = Cli::try_parse_from(["gyges", "key", "unlock", "--timeout", "15m"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Key(key::KeyCmd::Unlock(ref a))
                if a.timeout == Some(std::time::Duration::from_secs(900)) && a.key.id.is_none()
        ));
        assert!(Cli::try_parse_from(["gyges", "key", "lock", "--all", "--id", "x"]).is_err());
        let cli = Cli::try_parse_from(["gyges", "-k", "main", "key", "export-ufvk"]).unwrap();
        assert_eq!(cli.global.key.as_deref(), Some("main"));
    }

    #[test]
    fn sync_commands_parse_per_spec() {
        let cli = Cli::try_parse_from(["gyges", "sync", "status", "--all"]).unwrap();
        assert!(matches!(cli.command, Command::Sync(sync::SyncCmd::Status(ref a)) if a.all));
        let cli = Cli::try_parse_from([
            "gyges",
            "sync",
            "wait",
            "--until",
            "scanned",
            "--timeout",
            "30s",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Sync(sync::SyncCmd::Wait(ref a))
                if a.until == Some(sync::Until::Scanned)
                    && a.timeout == Some(std::time::Duration::from_secs(30))
        ));
        let cli = Cli::try_parse_from([
            "gyges",
            "sync",
            "wait",
            "--txid",
            "ab",
            "--confirmations",
            "3",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Sync(sync::SyncCmd::Wait(ref a)) if a.confirmations == Some(3)
        ));
        assert!(
            Cli::try_parse_from(["gyges", "sync", "wait", "--txid", "ab"]).is_err(),
            "--txid needs --confirmations"
        );
        let cli = Cli::try_parse_from(["gyges", "sync", "run", "--from", "100", "--yes"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Sync(sync::SyncCmd::Run(ref a)) if a.from == Some(100) && a.yes
        ));
    }
}
