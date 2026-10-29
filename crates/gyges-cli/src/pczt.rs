//! `gyges pczt …` (CLI_SPEC.md §2.6, API.md §4.2, §7.1): the ZIP 374 roles
//! as commands that read a `.pczt` from a positional file (or stdin when
//! absent or `-`) and write one to `-o FILE` (or stdout, never a terminal).
//!
//! Implemented: `create`, `inspect`, `prove`, `sign`, `combine` and
//! `broadcast`. The key is read from the file's `gyges.key_id`; `--key` is
//! an assertion the daemon checks (`KEY_MISMATCH`, exit 6). `qr-export
//! --session` shows a Keystone signing session's request, and `qr-scan
//! --session` (camera) and `qr-import --session` (frames) complete it
//! (`crate::keystone`); the same for PCZT files is not implemented
//! (`sign --qr-out`).
//!
//! With `--json` every command prints its RPC response (the PCZT bytes as
//! base64 inside it) on stdout and writes the file only when `-o` is given.

use std::fmt::Write as _;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use clap::{Args, Subcommand};
use gyges_proto::v1::{
    BroadcastPcztRequest, CombinePcztRequest, CompleteKeystoneSignResponse, CreatePcztRequest,
    ErrorReason, GygesError, InspectPcztRequest, InspectPcztResponse, ListSigningSessionsRequest,
    Network, PcztRole, Pool, ProvePcztRequest, SignPcztRequest, SigningSession, sign_pczt_event,
};

use crate::amount::{MemoArg, ParsedAmount, parse_amount, parse_memo};
use crate::balance::pool_name;
use crate::client::Ctx;
use crate::exit::CliError;
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
    /// Show a pending Keystone signing session's request as an animated QR code (or its frames).
    QrExport(QrExportArgs),
    /// Complete a Keystone signing session by scanning the device's answer with the camera.
    QrScan(QrScanArgs),
    /// Complete a Keystone signing session with the device's answer frames.
    QrImport(QrImportArgs),
}

#[derive(Debug, Clone, Args)]
pub struct QrExportArgs {
    /// A PCZT file (not supported yet: a file must be redacted for the device first; use --session).
    pub file: Option<PathBuf>,
    /// The pending Keystone session whose request to show (`gyges tx sessions` lists them).
    #[arg(long, value_name = "ID")]
    pub session: Option<String>,
    /// Frames per second of the animation.
    #[arg(long, value_name = "N", default_value_t = gyges_qr::DEFAULT_FPS)]
    pub fps: u32,
    /// Write the frames here, one per line, instead of animating them.
    #[arg(short, long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct QrScanArgs {
    /// The Keystone session the answer completes (required for now).
    #[arg(long, value_name = "ID")]
    pub session: Option<String>,
    /// Which camera, by index [default: the first].
    #[arg(long, value_name = "N")]
    pub camera: Option<u32>,
    /// Give up after this long, e.g. 90s, 5m.
    #[arg(long, value_name = "DURATION", value_parser = humantime::parse_duration, default_value = "2m")]
    pub timeout: std::time::Duration,
}

#[derive(Debug, Clone, Args)]
pub struct QrImportArgs {
    /// The Keystone session the answer completes (required for now).
    #[arg(long, value_name = "ID")]
    pub session: Option<String>,
    /// Read the frames from this file, one per line, instead of stdin.
    #[arg(long, value_name = "FRAMES_FILE", conflicts_with = "frames")]
    pub from_file: Option<PathBuf>,
    /// The answer's frames (a batch answer is usually one).
    #[arg(value_name = "UR_FRAME")]
    pub frames: Vec<String>,
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
    /// Write Keystone UR frames here instead of animating them (not implemented yet).
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
    /// Broadcast through the fallback endpoint over Tor (exit 7 when none is configured; never the node).
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
        PcztCmd::QrExport(args) => qr_export(ctx, args).await,
        PcztCmd::QrScan(args) => qr_scan(ctx, args).await,
        PcztCmd::QrImport(args) => qr_import(ctx, args).await,
    }
}

/// The file a path argument names; `None` for stdin/stdout (absent or `-`).
fn file_arg(path: Option<&Path>) -> Option<&Path> {
    path.filter(|p| p.as_os_str() != "-")
}

/// The whole file, or all of stdin.
fn read_pczt(path: Option<&Path>) -> Result<Vec<u8>, CliError> {
    let file = file_arg(path);
    let bytes = match file {
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .lock()
                .read_to_end(&mut buf)
                .map_err(|e| anyhow!("cannot read the PCZT from stdin: {e}"))?;
            buf
        }
        Some(path) => {
            std::fs::read(path).map_err(|e| anyhow!("cannot read {}: {e}", path.display()))?
        }
    };
    if bytes.is_empty() {
        return Err(CliError::invalid(match file {
            None => "no PCZT on stdin (pass a file, or pipe one in)".to_string(),
            Some(path) => format!("{} is empty", path.display()),
        }));
    }
    Ok(bytes)
}

/// To `-o FILE` (mode 0600) or stdout; a terminal gets nothing binary.
fn write_pczt(path: Option<&Path>, bytes: &[u8]) -> Result<(), CliError> {
    let Some(path) = file_arg(path) else {
        let mut out = std::io::stdout().lock();
        if out.is_terminal() {
            return Err(CliError::invalid(
                "refusing to write a binary PCZT to the terminal; pass -o FILE or pipe it",
            ));
        }
        return out
            .write_all(bytes)
            .and_then(|()| out.flush())
            .map_err(|e| anyhow!("cannot write the PCZT to stdout: {e}").into());
    };
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| anyhow!("cannot write {}: {e}", path.display()).into())
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
        if file_arg(out).is_none() {
            return Ok(());
        }
    }
    write_pczt(out, bytes)
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
        .await?
        .into_inner();
    let Some(bytes) = resp.pczts.first() else {
        return Err(anyhow!("the daemon returned no PCZT").into());
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
        .await?
        .into_inner();
    ctx.print(&resp, || render_inspection(&resp))
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
            if p.pool() == Pool::Transparent {
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
    ctx.note("proving…");
    let resp = conn
        .client
        .prove_pczt(ProvePcztRequest {
            pczt: bytes,
            session_token: Vec::new(),
            key_id: ctx.key.clone(),
        })
        .await?
        .into_inner();
    ctx.note("proven");
    deliver(ctx, args.out.as_deref(), &resp, &resp.pczt)
}

async fn sign(ctx: &Ctx, args: SignArgs) -> Result<(), CliError> {
    if args.qr_out.is_some() {
        return Err(CliError::NotImplemented("pczt sign --qr-out"));
    }
    let bytes = read_pczt(args.io.file.as_deref())?;
    let mut conn = ctx.connect().await?;
    let key = shown_key(&ctx.key, &conn);
    let mut stream = conn
        .client
        .sign_pczt(SignPcztRequest {
            pczt: bytes,
            session_token: Vec::new(),
            key_id: ctx.key.clone(),
        })
        .await?
        .into_inner();
    while let Some(ev) = Ctx::next_or_cancel(&mut stream).await? {
        match ev.event {
            Some(sign_pczt_event::Event::SignatureRequired(req)) => {
                satisfy(ctx, &mut conn, &key, &req).await?;
            }
            Some(sign_pczt_event::Event::Signed(ref signed)) => {
                ctx.note("signed");
                return deliver(ctx, args.io.out.as_deref(), &ev, signed);
            }
            None => {}
        }
    }
    Err(anyhow!("the daemon ended the signing stream without a signed PCZT").into())
}

async fn combine(ctx: &Ctx, args: CombineArgs) -> Result<(), CliError> {
    if args.files.iter().filter(|p| p.as_os_str() == "-").count() > 1 {
        return Err(CliError::invalid("stdin (`-`) can be read once"));
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
        .await?
        .into_inner();
    deliver(ctx, args.out.as_deref(), &resp, &resp.pczt)
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
        .await?
        .into_inner();
    ctx.print(&resp, || format!("{}\n", resp.txid))?;
    ctx.note("broadcast");
    Ok(())
}

/// `--session` is required for now: a PCZT file is not redacted for the
/// device (THREAT_MODEL.md §5 row 9), so only daemon sessions are shown.
fn session_arg(session: Option<String>, what: &'static str) -> Result<String, CliError> {
    session.ok_or(CliError::NotImplemented(what))
}

/// The pending Keystone session `session_id`, from any key.
async fn pending_session(ctx: &Ctx, session_id: &str) -> Result<SigningSession, CliError> {
    let mut conn = ctx.connect().await?;
    let all = conn
        .client
        .list_signing_sessions(ListSigningSessionsRequest {
            key_id: String::new(),
            include_finished: false,
        })
        .await?
        .into_inner();
    all.sessions
        .into_iter()
        .find(|s| s.session_id == session_id && !s.payload.is_empty())
        .ok_or_else(|| {
            CliError::Daemon(
                GygesError::new(
                    ErrorReason::SessionNotFound,
                    "no Keystone signing session awaiting the device has this id (`gyges tx sessions` lists them)",
                )
                .with_session(session_id),
            )
        })
}

/// `pczt qr-export --session ID`: the request again, animated on a
/// terminal, else (or with `-o`) as frames one per line.
async fn qr_export(ctx: &Ctx, args: QrExportArgs) -> Result<(), CliError> {
    if args.file.is_some() {
        return Err(CliError::NotImplemented(
            "pczt qr-export FILE (use --session)",
        ));
    }
    let session_id = session_arg(args.session, "pczt qr-export without --session")?;
    let session = pending_session(ctx, &session_id).await?;
    let frames = crate::keystone::frames(session.kind(), &session.payload)?;
    if let Some(path) = &args.out {
        let lines = crate::keystone::frame_lines(frames)?;
        std::fs::write(path, lines.join("\n") + "\n")?;
        ctx.note(format_args!(
            "{} frame(s) written to {}",
            lines.len(),
            path.display()
        ));
        return Ok(());
    }
    if ctx.json {
        let lines = crate::keystone::frame_lines(frames)?;
        let v = serde_json::json!({ "session_id": session_id, "frames": lines });
        println!("{}", to_json(&v)?);
        return Ok(());
    }
    if !crate::keystone::can_animate(ctx) {
        for line in crate::keystone::frame_lines(frames)? {
            println!("{line}");
        }
        return Ok(());
    }
    eprintln!("Scan this QR code with the Keystone, then press Enter.");
    crate::keystone::animate_until_enter(frames, args.fps.max(1)).await
}

/// `pczt qr-scan --session ID`: the device's answer from the camera
/// (feature `camera`), through `CompleteKeystoneSign`; prints the txid.
async fn qr_scan(ctx: &Ctx, args: QrScanArgs) -> Result<(), CliError> {
    let session_id = session_arg(args.session, "pczt qr-scan without --session")?;
    let session = pending_session(ctx, &session_id).await?;
    let (_, answer) = crate::keystone::ur_types(session.kind())?;
    let cbor = crate::keystone::scan(args.camera, answer, &session.payload, args.timeout).await?;
    let resp = crate::keystone::complete(ctx, &session_id, cbor).await?;
    print_completed(ctx, &session_id, &resp)
}

/// `pczt qr-import --session ID`: the device's answer from positional
/// frames, `--from-file` or stdin, through `CompleteKeystoneSign`; prints
/// the broadcast txid.
async fn qr_import(ctx: &Ctx, args: QrImportArgs) -> Result<(), CliError> {
    let session_id = session_arg(args.session, "pczt qr-import without --session")?;
    let session = pending_session(ctx, &session_id).await?;
    let (_, answer) = crate::keystone::ur_types(session.kind())?;
    let text = if !args.frames.is_empty() {
        args.frames.join("\n")
    } else if let Some(path) = &args.from_file {
        std::fs::read_to_string(path)?
    } else {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    };
    let cbor = crate::keystone::assemble(text.lines(), answer)?;
    let resp = crate::keystone::complete(ctx, &session_id, cbor).await?;
    print_completed(ctx, &session_id, &resp)
}

/// The txids a `CompleteKeystoneSign` broadcast, one per line (or the
/// response with `--json`).
fn print_completed(
    ctx: &Ctx,
    session_id: &str,
    resp: &CompleteKeystoneSignResponse,
) -> Result<(), CliError> {
    ctx.print(resp, || {
        crate::keystone::txids(resp)
            .iter()
            .map(|txid| format!("{txid}\n"))
            .collect()
    })?;
    ctx.note(format_args!(
        "session {session_id} signed on the Keystone and broadcast"
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::{PcztPoolState, Proposal, ProposalStep, ProposedOutput};

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
