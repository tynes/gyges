//! `gygesd` – the Gyges wallet daemon.
//!
//! Nothing is implemented yet. This binary exists so the workspace compiles
//! and so `cargo run -p gygesd -- --help` shows the intended flags
//! (CLI_SPEC.md §2.1 `gyges daemon start`).

#![forbid(unsafe_code)]

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "gygesd",
    version,
    about = "Gyges Zcash wallet daemon (pre-alpha, not functional)"
)]
struct Args {
    /// Run in the foreground (do not daemonize).
    #[arg(short, long)]
    foreground: bool,
    /// Disable all network, RPC and Tor interfaces; offline proving and signing only.
    #[arg(long)]
    airgapped: bool,
    /// Network this daemon serves; selects `~/.gyges/<network>/`.
    #[arg(short, long, env = "GYGES_NETWORK", default_value = "mainnet")]
    network: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    anyhow::bail!(
        "gygesd is not implemented yet (network={}, foreground={}, airgapped={}); see ROADMAP.md",
        args.network,
        args.foreground,
        args.airgapped
    )
}
