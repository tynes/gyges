//! `gyges address …` (CLI_SPEC.md §2.4): `current` (`GetCurrentAddress`),
//! `new` (`NewAddress`) and `inspect` (`InspectAddress`). The address goes
//! to stdout alone, so `$(gyges address current)` works; its receivers,
//! diversifier index and label go to stderr (quiet with `-q`).
//!
//! `--qr` and `address qr` exit 1 as not implemented until `gyges-qr`
//! renders codes (ROADMAP.md M5); they fail before any RPC is sent.

use clap::{Args, Subcommand, ValueEnum};
use gyges_proto::v1::{
    AddressInfo, AddressKind, ErrorReason, GetCurrentAddressRequest, GygesError,
    InspectAddressRequest, InspectAddressResponse, Network, NewAddressRequest, Pool, Receiver,
};

use crate::balance::pool_name;
use crate::client::Ctx;
use crate::exit::CliError;
use crate::output::to_json;

#[derive(Debug, Subcommand)]
pub enum AddressCmd {
    /// Print the key's current unified address.
    Current(CurrentArgs),
    /// Derive a fresh diversified unified address.
    New(NewArgs),
    /// Static QR code for the current address or ADDRESS (not implemented yet).
    Qr { address: Option<String> },
    /// Parse any Zcash address: checksum, network, receivers, ZIP 320.
    Inspect { address: String },
}

#[derive(Debug, Clone, Args)]
pub struct CurrentArgs {
    /// Render a QR code in the terminal (not implemented yet).
    #[arg(long)]
    pub qr: bool,
}

/// A receiver named on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ReceiverArg {
    Orchard,
    Sapling,
    Transparent,
}

impl ReceiverArg {
    fn to_proto(self) -> Pool {
        match self {
            ReceiverArg::Orchard => Pool::Orchard,
            ReceiverArg::Sapling => Pool::Sapling,
            ReceiverArg::Transparent => Pool::Transparent,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct NewArgs {
    /// Comma-separated: orchard,sapling,transparent [default: orchard,sapling; keystone-qr profiles: orchard,transparent].
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    pub receivers: Vec<ReceiverArg>,
    /// Label stored with the address in the key's wallet.
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,
    /// Render a QR code in the terminal (not implemented yet).
    #[arg(long)]
    pub qr: bool,
}

pub async fn run(ctx: &Ctx, cmd: AddressCmd) -> Result<(), CliError> {
    match cmd {
        AddressCmd::Current(a) if a.qr => Err(CliError::NotImplemented("address current --qr")),
        AddressCmd::New(a) if a.qr => Err(CliError::NotImplemented("address new --qr")),
        AddressCmd::Qr { .. } => Err(CliError::NotImplemented("address qr")),
        AddressCmd::Current(_) => {
            let mut conn = ctx.connect().await?;
            let info = conn
                .client
                .get_current_address(GetCurrentAddressRequest {
                    key_id: ctx.key.clone(),
                })
                .await?
                .into_inner();
            print_address(ctx, &info)
        }
        AddressCmd::New(a) => {
            let mut conn = ctx.connect().await?;
            let info = conn
                .client
                .new_address(NewAddressRequest {
                    key_id: ctx.key.clone(),
                    receivers: a.receivers.iter().map(|r| r.to_proto() as i32).collect(),
                    label: a.label.unwrap_or_default(),
                })
                .await?
                .into_inner();
            print_address(ctx, &info)
        }
        AddressCmd::Inspect { address } => {
            let mut conn = ctx.connect().await?;
            let resp = conn
                .client
                .inspect_address(InspectAddressRequest { address })
                .await?
                .into_inner();
            if !resp.valid {
                // Exit 6 either way (CLI_SPEC.md §2.4); the terminal also
                // gets whatever did parse.
                if !ctx.json && resp.kind != AddressKind::Unspecified as i32 {
                    print!("{}", render_inspection(&resp));
                }
                return Err(CliError::Daemon(GygesError::new(
                    ErrorReason::InvalidArgument,
                    if resp.error.is_empty() {
                        "not a valid address".to_string()
                    } else {
                        resp.error.clone()
                    },
                )));
            }
            if ctx.json {
                println!("{}", to_json(&resp)?);
            } else {
                print!("{}", render_inspection(&resp));
            }
            Ok(())
        }
    }
}

fn print_address(ctx: &Ctx, info: &AddressInfo) -> Result<(), CliError> {
    if ctx.json {
        println!("{}", to_json(info)?);
        return Ok(());
    }
    println!("{}", info.address);
    if !ctx.quiet {
        eprint!("{}", render_details(info));
    }
    Ok(())
}

fn receiver_line(r: &Receiver) -> String {
    let pool = pool_name(r.pool());
    if r.encoded.is_empty() {
        pool.to_string()
    } else {
        format!("{pool:<12} {}", r.encoded)
    }
}

/// Receivers, diversifier index and label (stderr).
pub fn render_details(info: &AddressInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for (i, r) in info.receivers.iter().enumerate() {
        let head = if i == 0 { "receivers:" } else { "" };
        let _ = writeln!(s, "{head:<18} {}", receiver_line(r));
    }
    if !info.diversifier_index.is_empty() {
        let _ = writeln!(s, "{:<18} {}", "diversifier index:", info.diversifier_index);
    }
    if !info.label.is_empty() {
        let _ = writeln!(s, "{:<18} {}", "label:", info.label);
    }
    s
}

fn kind_name(k: AddressKind) -> &'static str {
    match k {
        AddressKind::Unspecified => "unknown",
        AddressKind::Unified => "unified",
        AddressKind::Sapling => "sapling",
        AddressKind::TransparentP2pkh => "transparent (p2pkh)",
        AddressKind::TransparentP2sh => "transparent (p2sh)",
        AddressKind::Tex => "tex (zip 320)",
    }
}

/// `address inspect` for a terminal.
pub fn render_inspection(r: &InspectAddressResponse) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "{:<11} {}", "valid:", if r.valid { "yes" } else { "no" });
    if r.network != Network::Unspecified as i32 {
        let _ = writeln!(s, "{:<11} {}", "network:", r.network().name());
    }
    let _ = writeln!(s, "{:<11} {}", "kind:", kind_name(r.kind()));
    for (i, rc) in r.receivers.iter().enumerate() {
        let head = if i == 0 { "receivers:" } else { "" };
        let _ = writeln!(s, "{head:<11} {}", receiver_line(rc));
    }
    let _ = writeln!(
        s,
        "{:<11} {}",
        "zip 320:",
        if r.transparent_source_only {
            "yes: a payment is sent from transparent funds in two transactions"
        } else {
            "no"
        }
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_list_receivers_index_and_label() {
        let info = AddressInfo {
            address: "u1x".into(),
            diversifier_index: "7".into(),
            receivers: vec![
                Receiver {
                    pool: Pool::Orchard as i32,
                    encoded: String::new(),
                },
                Receiver {
                    pool: Pool::Sapling as i32,
                    encoded: "zs1y".into(),
                },
            ],
            label: "savings".into(),
        };
        let s = render_details(&info);
        assert!(s.contains("receivers:") && s.contains("orchard"), "{s}");
        assert!(s.contains("sapling") && s.contains("zs1y"), "{s}");
        assert!(s.contains("diversifier index: 7"), "{s}");
        assert!(s.contains("savings"), "{s}");
    }

    #[test]
    fn inspection_names_kind_network_and_zip320() {
        let r = InspectAddressResponse {
            valid: true,
            network: Network::Regtest as i32,
            kind: AddressKind::Tex as i32,
            receivers: vec![Receiver {
                pool: Pool::Transparent as i32,
                encoded: "tm1".into(),
            }],
            transparent_source_only: true,
            error: String::new(),
        };
        let s = render_inspection(&r);
        assert!(s.contains("valid:      yes"), "{s}");
        assert!(s.contains("regtest"), "{s}");
        assert!(s.contains("tex (zip 320)"), "{s}");
        assert!(s.contains("two transactions"), "{s}");
    }
}
