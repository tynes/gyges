//! `gyges pczt …` (CLI_SPEC.md §2.6, API.md §4.2, §7.1): the ZIP 374 roles
//! as commands that read a `.pczt` from a positional file (or stdin when
//! absent or `-`) and write one to `-o FILE` (or stdout, never a terminal).
//!
//! Implemented: `create`, `inspect`, `prove`, `sign`, `combine` and
//! `broadcast`. The key is read from the file's `gyges.key_id`; `--key` is
//! an assertion the daemon checks (`KEY_MISMATCH`, exit 6). The QR commands
//! (`qr-export`, `qr-scan`, `qr-import`) wait for ROADMAP.md M5.
//!
//! With `--json` every command prints its RPC response (the PCZT bytes as
//! base64 inside it) on stdout and writes the file only when `-o` is given.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use gyges_proto::v1::{
    BroadcastPcztRequest, CombinePcztRequest, CreatePcztRequest, ErrorReason, GygesError,
    InspectPcztRequest, InspectPcztResponse, Network, PcztRole, ProvePcztRequest, SignPcztRequest,
    sign_pczt_event,
};
use tokio_stream::StreamExt as _;

use crate::amount::{MemoArg, ParsedAmount, parse_amount, parse_memo};
use crate::balance::pool_name;
use crate::client::Ctx;
use crate::exit::CliError;
use crate::key::Unimplemented;
use crate::output::to_json;
use crate::tx::{render_steps, satisfy, shown_key};

#[derive(Debug, Subcommand)]
pub enum PcztCmd {
    /// Propose a payment and write the unsigned PCZT (Creator through Updater).
    Create(CreateArgs),
    /// Show what a PCZT pays, which roles have run, and its key, network and session.
    Inspect(InspectArgs),
    /// Add the zero-knowledge proofs; needs no key.
    Prove(InOutArgs),
    /// Sign with the key the PCZT names; prompts for its passphrase when locked.
    Sign(SignArgs),
    /// Merge two or more PCZTs of the same transaction and key.
    Combine(CombineArgs),
    /// Verify against the proposal stored at `create`, then extract and send to the node.
    Broadcast(BroadcastArgs),
    /// Animate a PCZT as `ur:zcash-pczt` frames (ROADMAP.md M5).
    QrExport(Unimplemented),
    /// Read a Keystone's answer from the camera (ROADMAP.md M5).
    QrScan(Unimplemented),
    /// Read a Keystone's answer from frames (ROADMAP.md M5).
    QrImport(Unimplemented),
}

#[derive(Debug, Clone, Args)]
pub struct CreateArgs {
    /// Recipient: u1, zs1, t1 or t3 (a tex1 recipient needs `tx send`).
    #[arg(long, value_name = "ADDR")]
    pub to: String,
    /// Decimal ZEC (1.25), zatoshis (125000000z) or `max`.
    #[arg(long, value_name = "AMOUNT", value_parser = parse_amount)]
    pub amount: ParsedAmount,
    /// UTF-8 text (at most 512 bytes) or 0x-prefixed hex; shielded recipients only.
    #[arg(long, value_name = "TEXT_OR_HEX", value_parser = parse_memo)]
    pub memo: Option<MemoArg>,
    /// Write the PCZT here instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct InspectArgs {
    /// The PCZT; stdin when absent or `-`.
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct InOutArgs {
    /// The PCZT; stdin when absent or `-`.
    pub file: Option<PathBuf>,
    /// Write the result here instead of stdout.
    #[arg(short, long, value_name = "OUT_FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct SignArgs {
    #[command(flatten)]
    pub io: InOutArgs,
    /// Write Keystone UR frames here instead of animating them (ROADMAP.md M5).
    #[arg(long, value_name = "FILE")]
    pub qr_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct CombineArgs {
    /// Two or more PCZTs (`-` for stdin, at most once).
    #[arg(required = true, num_args = 2..)]
    pub files: Vec<PathBuf>,
    /// Write the combined PCZT here instead of stdout.
    #[arg(short, long, value_name = "OUT_FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct BroadcastArgs {
    /// The signed PCZT; stdin when absent or `-`.
    pub file: Option<PathBuf>,
    /// Broadcast over an isolated Tor circuit (not available in this milestone).
    #[arg(long)]
    pub via_tor: bool,
}

pub async fn run(ctx: &Ctx, cmd: PcztCmd) -> Result<(), CliError> {
    match cmd {
        PcztCmd::Create(args) => create(ctx, args).await,
        PcztCmd::Inspect(args) => inspect(ctx, args).await,
        PcztCmd::Prove(args) => prove(ctx, args).await,
        PcztCmd::Sign(args) => sign(ctx, args).await,
        PcztCmd::Combine(args) => combine(ctx, args).await,
        PcztCmd::Broadcast(args) => broadcast(ctx, args).await,
        PcztCmd::QrExport(_) => Err(CliError::NotImplemented("pczt qr-export")),
        PcztCmd::QrScan(_) => Err(CliError::NotImplemented("pczt qr-scan")),
        PcztCmd::QrImport(_) => Err(CliError::NotImplemented("pczt qr-import")),
    }
}

fn is_stdio(path: Option<&Path>) -> bool {
    path.is_none_or(|p| p.as_os_str() == "-")
}

/// The whole file, or all of stdin.
fn read_pczt(path: Option<&Path>) -> Result<Vec<u8>, CliError> {
    let bytes = if is_stdio(path) {
        let mut buf = Vec::new();
        std::io::stdin().lock().read_to_end(&mut buf).map_err(|e| {
            CliError::Other(anyhow::anyhow!("cannot read the PCZT from stdin: {e}"))
        })?;
        buf
    } else {
        let path = path.expect("not stdio");
        std::fs::read(path)
            .map_err(|e| CliError::Other(anyhow::anyhow!("cannot read {}: {e}", path.display())))?
    };
    if bytes.is_empty() {
        return Err(CliError::Daemon(GygesError::new(
            ErrorReason::InvalidArgument,
            if is_stdio(path) {
                "no PCZT on stdin (pass a file, or pipe one in)".to_string()
            } else {
                format!("{} is empty", path.expect("not stdio").display())
            },
        )));
    }
    Ok(bytes)
}

/// To `-o FILE` (mode 0600) or stdout; a terminal gets nothing binary.
fn write_pczt(path: Option<&Path>, bytes: &[u8]) -> Result<(), CliError> {
    if is_stdio(path) {
        let mut out = std::io::stdout().lock();
        if out.is_terminal() {
            return Err(CliError::Daemon(GygesError::new(
                ErrorReason::InvalidArgument,
                "refusing to write a binary PCZT to the terminal; pass -o FILE or pipe it",
            )));
        }
        out.write_all(bytes)
            .and_then(|()| out.flush())
            .map_err(|e| CliError::Other(anyhow::anyhow!("cannot write the PCZT to stdout: {e}")))
    } else {
        use std::os::unix::fs::OpenOptionsExt as _;
        let path = path.expect("not stdio");
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| f.write_all(bytes))
            .map_err(|e| CliError::Other(anyhow::anyhow!("cannot write {}: {e}", path.display())))
    }
}

/// Where a result goes after the RPC: JSON of `resp` on stdout when
/// `--json` (and the file only with `-o`), else the bytes.
fn deliver<T: serde::Serialize>(
    ctx: &Ctx,
    out: Option<&Path>,
    resp: &T,
    bytes: &[u8],
) -> Result<(), CliError> {
    if ctx.json {
        println!("{}", to_json(resp)?);
        if !is_stdio(out) {
            write_pczt(out, bytes)?;
        }
        Ok(())
    } else {
        write_pczt(out, bytes)
    }
}

async fn create(ctx: &Ctx, args: CreateArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .create_pczt(CreatePcztRequest {
            key_id: ctx.key.clone(),
            to: args.to,
            amount: Some(args.amount.to_proto()),
            memo: args.memo.map(|m| m.0).unwrap_or_default(),
            min_confirmations: 0,
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    let Some(bytes) = resp.pczts.first() else {
        return Err(CliError::Other(anyhow::anyhow!(
            "the daemon returned no PCZT"
        )));
    };
    if !ctx.json && !ctx.quiet {
        if let Some(p) = &resp.proposal {
            eprint!("{}", render_steps(p));
            eprintln!("Expires at height {}", p.expiry_height);
        }
        eprintln!("session {}", resp.session_id);
    }
    deliver(ctx, args.out.as_deref(), &resp, bytes)
}

async fn inspect(ctx: &Ctx, args: InspectArgs) -> Result<(), CliError> {
    let bytes = read_pczt(args.file.as_deref())?;
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .inspect_pczt(InspectPcztRequest {
            pczt: bytes,
            key_id: ctx.key.clone(),
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else {
        print!("{}", render_inspection(&resp));
    }
    Ok(())
}

pub fn role_name(r: PcztRole) -> &'static str {
    match r {
        PcztRole::Creator => "creator",
        PcztRole::Constructor => "constructor",
        PcztRole::IoFinalizer => "io-finalizer",
        PcztRole::Updater => "updater",
        PcztRole::Redactor => "redactor",
        PcztRole::Prover => "prover",
        PcztRole::Signer => "signer",
        PcztRole::Combiner => "combiner",
        PcztRole::SpendFinalizer => "spend-finalizer",
        PcztRole::TransactionExtractor => "transaction-extractor",
        PcztRole::Unspecified => "unknown",
    }
}

/// The tags, the proposal the file implies (same layout as `tx send
/// --dry-run`), the roles and the per-pool state.
pub fn render_inspection(r: &InspectPcztResponse) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Key:     {}", r.key_id);
    let _ = writeln!(
        s,
        "Network: {}",
        Network::try_from(r.network).map_or("unknown", Network::name)
    );
    let _ = writeln!(s, "Session: {}", r.session_id);
    if let Some(p) = &r.summary {
        s.push_str(&render_steps(p));
        let _ = writeln!(s, "Expires at height {}", p.expiry_height);
    }
    let roles: Vec<&str> = r.completed_roles().map(role_name).collect();
    let _ = writeln!(
        s,
        "Roles:   {}",
        if roles.is_empty() {
            "none".to_string()
        } else {
            roles.join(", ")
        }
    );
    for (i, p) in r.pools.iter().enumerate() {
        let _ = writeln!(
            s,
            "{:<9}{}: {} spend(s), {} output(s), proofs {}, signatures {}/{}",
            if i == 0 { "Pools:" } else { "" },
            pool_name(p.pool()),
            p.spends,
            p.outputs,
            if p.pool() == gyges_proto::v1::Pool::Transparent {
                "n/a"
            } else if p.proofs_present {
                "present"
            } else {
                "missing"
            },
            p.signatures_present,
            p.signatures_required
        );
    }
    s
}

async fn prove(ctx: &Ctx, args: InOutArgs) -> Result<(), CliError> {
    let bytes = read_pczt(args.file.as_deref())?;
    let mut conn = ctx.connect().await?;
    if !ctx.quiet && !ctx.json {
        eprintln!("proving…");
    }
    let resp = conn
        .client
        .prove_pczt(ProvePcztRequest {
            pczt: bytes,
            session_token: Vec::new(),
            key_id: ctx.key.clone(),
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if !ctx.quiet && !ctx.json {
        eprintln!("proven");
    }
    let pczt = resp.pczt.clone();
    deliver(ctx, args.out.as_deref(), &resp, &pczt)
}

async fn sign(ctx: &Ctx, args: SignArgs) -> Result<(), CliError> {
    if args.qr_out.is_some() {
        return Err(CliError::NotImplemented("pczt sign --qr-out"));
    }
    let bytes = read_pczt(args.io.file.as_deref())?;
    let mut conn = ctx.connect().await?;
    let key = shown_key(ctx, &conn);
    let mut stream = conn
        .client
        .sign_pczt(SignPcztRequest {
            pczt: bytes,
            session_token: Vec::new(),
            key_id: ctx.key.clone(),
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    loop {
        let next = tokio::select! {
            item = stream.next() => item,
            _ = tokio::signal::ctrl_c() => return Err(CliError::Cancelled),
        };
        let Some(item) = next else {
            return Err(CliError::Other(anyhow::anyhow!(
                "the daemon ended the signing stream without a signed PCZT"
            )));
        };
        let ev = item.map_err(CliError::from_status)?;
        match ev.event {
            Some(sign_pczt_event::Event::SignatureRequired(req)) => {
                satisfy(ctx, &mut conn, &key, &req).await?;
            }
            Some(sign_pczt_event::Event::Signed(ref signed)) => {
                if !ctx.quiet && !ctx.json {
                    eprintln!("signed");
                }
                return deliver(ctx, args.io.out.as_deref(), &ev, signed);
            }
            None => {}
        }
    }
}

async fn combine(ctx: &Ctx, args: CombineArgs) -> Result<(), CliError> {
    if args.files.iter().filter(|p| p.as_os_str() == "-").count() > 1 {
        return Err(CliError::Daemon(GygesError::new(
            ErrorReason::InvalidArgument,
            "stdin (`-`) can be read once",
        )));
    }
    let mut pczts = Vec::with_capacity(args.files.len());
    for f in &args.files {
        pczts.push(read_pczt(Some(f))?);
    }
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .combine_pczt(CombinePcztRequest {
            pczts,
            key_id: ctx.key.clone(),
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    let pczt = resp.pczt.clone();
    deliver(ctx, args.out.as_deref(), &resp, &pczt)
}

async fn broadcast(ctx: &Ctx, args: BroadcastArgs) -> Result<(), CliError> {
    let bytes = read_pczt(args.file.as_deref())?;
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .broadcast_pczt(BroadcastPcztRequest {
            pczt: bytes,
            via_tor: args.via_tor,
            key_id: ctx.key.clone(),
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else {
        println!("{}", resp.txid);
        if !ctx.quiet {
            eprintln!("broadcast");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::{PcztPoolState, Pool, Proposal, ProposalStep, ProposedOutput};

    #[test]
    fn inspection_rendering_lists_tags_roles_and_pools() {
        let r = InspectPcztResponse {
            key_id: "main".into(),
            network: Network::Regtest as i32,
            session_id: "ab".repeat(16),
            summary: Some(Proposal {
                steps: vec![ProposalStep {
                    index: 1,
                    outputs: vec![ProposedOutput {
                        address: "t1abc".into(),
                        pool: Pool::Transparent as i32,
                        value: 50_000_000,
                        ..Default::default()
                    }],
                    fee: 10_000,
                    ..Default::default()
                }],
                total_debit: 50_010_000,
                expiry_height: 1200,
                ..Default::default()
            }),
            completed_roles: vec![
                PcztRole::Creator as i32,
                PcztRole::Updater as i32,
                PcztRole::Prover as i32,
            ],
            pools: vec![
                PcztPoolState {
                    pool: Pool::Transparent as i32,
                    spends: 1,
                    outputs: 1,
                    proofs_present: true,
                    signatures_present: 0,
                    signatures_required: 1,
                },
                PcztPoolState {
                    pool: Pool::Ironwood as i32,
                    spends: 0,
                    outputs: 2,
                    proofs_present: true,
                    signatures_present: 2,
                    signatures_required: 2,
                },
            ],
        };
        let s = render_inspection(&r);
        assert!(s.contains("Key:     main"), "{s}");
        assert!(s.contains("Network: regtest"), "{s}");
        assert!(s.contains("t1abc (transparent) 0.50000000 ZEC"), "{s}");
        assert!(s.contains("Expires at height 1200"), "{s}");
        assert!(s.contains("Roles:   creator, updater, prover"), "{s}");
        assert!(
            s.contains("transparent: 1 spend(s), 1 output(s), proofs n/a, signatures 0/1"),
            "{s}"
        );
        assert!(
            s.contains("ironwood: 0 spend(s), 2 output(s), proofs present, signatures 2/2"),
            "{s}"
        );
    }
}
