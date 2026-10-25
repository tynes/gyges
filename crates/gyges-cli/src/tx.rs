//! `gyges tx …` (CLI_SPEC.md §2.5, API.md §4.1, §4.3, §6).
//!
//! Implemented: `send` (including ZIP 320 `tex1` recipients), `shield`,
//! `sessions` (signing sessions and ZIP 320 transfers), `abort SESSION_ID`,
//! `abort TXID` and `resume TXID` here; `list` and `status` in
//! [`crate::history`] (`status --pir` is not implemented yet).
//!
//! `send` runs the `SendTransaction` stream and answers its
//! `SignatureRequired` event in place: the passphrase is prompted (or read
//! from `--passphrase-fd` / `GYGES_PASSPHRASE_FILE`) and sent back with
//! `UnlockKey { session_id }` on the same connection, so the key is held
//! only for the signing step. Without a terminal and without a passphrase
//! source the session is aborted and the command exits 4 naming the fix
//! (CLI_SPEC.md §1.2).

use clap::{Args, Subcommand};
use gyges_proto::v1::{
    AbortSigningSessionRequest, AbortTexTransferRequest, ErrorReason, GygesError,
    ListSigningSessionsRequest, Pool, Proposal, ResumeTexTransferRequest, SendEvent,
    SendTransactionRequest, SessionStatus, ShieldFundsRequest, SignatureKind, SignatureRequired,
    SigningSession, TexQueueEntry, TexState, UnlockKeyRequest, UnlockScope, send_event,
};
use tokio_stream::StreamExt as _;

use crate::amount::{MemoArg, ParsedAmount, format_zec, parse_amount, parse_memo, parse_zatoshis};
use crate::balance::pool_name;
use crate::client::{Conn, Ctx};
use crate::exit::CliError;
use crate::output::{format_unix, to_json};

#[derive(Debug, Subcommand)]
pub enum TxCmd {
    /// Propose, prove, sign and broadcast a payment.
    Send(SendArgs),
    /// Sweep transparent UTXOs into the key's Orchard pool.
    Shield(ShieldArgs),
    /// Transaction history, newest first.
    List(crate::history::ListArgs),
    /// Confirmation status of one transaction, from the node.
    Status(crate::history::StatusArgs),
    /// Pending signing sessions.
    Sessions(SessionsArgs),
    /// Abort a signing session (32 hex) or a ZIP 320 transfer still `built` (64 hex).
    Abort { id: String },
    /// Retry a ZIP 320 transfer by its step-1 txid; rebuilds step 2 when step 1 was mined and step 2 expired.
    Resume { txid: String },
}

#[derive(Debug, Clone, Args)]
pub struct SendArgs {
    /// Recipient: u1, zs1, t1, t3 or tex1 (ZIP 320, two transactions).
    #[arg(long, value_name = "ADDR")]
    pub to: String,
    /// Decimal ZEC (1.25), zatoshis (125000000z) or `max`.
    #[arg(long, value_name = "AMOUNT", value_parser = parse_amount)]
    pub amount: ParsedAmount,
    /// UTF-8 text (at most 512 bytes) or 0x-prefixed hex; shielded recipients only.
    #[arg(long, value_name = "TEXT_OR_HEX", value_parser = parse_memo)]
    pub memo: Option<MemoArg>,
    /// Broadcast over an isolated Tor circuit (not available in this milestone).
    #[arg(long)]
    pub via_tor: bool,
    /// Print the full proposal (every step, every fee) and exit without signing.
    #[arg(long)]
    pub dry_run: bool,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// Keep the stream open until the transaction is mined.
    #[arg(long)]
    pub wait: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ShieldArgs {
    /// Only shield when at least this much is unshielded (decimal ZEC or zatoshis with `z`).
    #[arg(long, value_name = "AMOUNT", value_parser = parse_zatoshis)]
    pub threshold: Option<u64>,
    /// Print the proposal and exit without signing.
    #[arg(long)]
    pub dry_run: bool,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// Keep the stream open until the transaction is mined.
    #[arg(long)]
    pub wait: bool,
}

#[derive(Debug, Clone, Args)]
pub struct SessionsArgs {
    /// Every key, not only --key.
    #[arg(long)]
    pub all: bool,
    /// Include completed, expired, aborted and failed sessions.
    #[arg(long)]
    pub include_finished: bool,
}

pub async fn run(ctx: &Ctx, cmd: TxCmd) -> Result<(), CliError> {
    match cmd {
        TxCmd::Send(args) => send(ctx, args).await,
        TxCmd::Shield(args) => shield(ctx, args).await,
        TxCmd::List(args) => crate::history::list(ctx, args).await,
        TxCmd::Status(args) => crate::history::status(ctx, args).await,
        TxCmd::Sessions(args) => sessions(ctx, args).await,
        TxCmd::Abort { id } => abort(ctx, id).await,
        TxCmd::Resume { txid } => resume(ctx, txid).await,
    }
}

/// The key name shown in prompts: `--key`, else the daemon's default.
pub(crate) fn shown_key(ctx: &Ctx, conn: &Conn) -> String {
    if ctx.key.is_empty() {
        conn.info.default_key.clone()
    } else {
        ctx.key.clone()
    }
}

async fn send(ctx: &Ctx, args: SendArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let request = |dry_run: bool| SendTransactionRequest {
        key_id: ctx.key.clone(),
        to: args.to.clone(),
        amount: Some(args.amount.to_proto()),
        memo: args.memo.clone().map(|m| m.0).unwrap_or_default(),
        via_tor: args.via_tor,
        dry_run,
        session_token: Vec::new(),
        min_confirmations: 0,
        wait_for_mined: args.wait,
    };
    // The proposal is approved before anything is signed: when a
    // confirmation is due, a dry run shows it first and the real send
    // follows only on a yes (the daemon never waits on a prompt).
    let mut shown = false;
    if !args.dry_run && !args.yes {
        let proposal = dry_run(&mut conn, SendOrShield::Send(request(true))).await?;
        confirm(ctx, &proposal, "Send")?;
        shown = true;
    }
    let stream = conn
        .client
        .send_transaction(request(args.dry_run))
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    let key = shown_key(ctx, &conn);
    follow(ctx, &mut conn, &key, stream, shown).await
}

async fn shield(ctx: &Ctx, args: ShieldArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let request = |dry_run: bool| ShieldFundsRequest {
        key_id: ctx.key.clone(),
        threshold: i64::try_from(args.threshold.unwrap_or(0)).unwrap_or(i64::MAX),
        dry_run,
        session_token: Vec::new(),
        wait_for_mined: args.wait,
    };
    let mut shown = false;
    if !args.dry_run && !args.yes {
        let proposal = dry_run(&mut conn, SendOrShield::Shield(request(true))).await?;
        confirm(ctx, &proposal, "Shield")?;
        shown = true;
    }
    let stream = conn
        .client
        .shield_funds(request(args.dry_run))
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    let key = shown_key(ctx, &conn);
    follow(ctx, &mut conn, &key, stream, shown).await
}

enum SendOrShield {
    Send(SendTransactionRequest),
    Shield(ShieldFundsRequest),
}

/// Run the request as a dry run and return its proposal.
async fn dry_run(conn: &mut Conn, req: SendOrShield) -> Result<Proposal, CliError> {
    let mut stream = match req {
        SendOrShield::Send(r) => conn.client.send_transaction(r).await,
        SendOrShield::Shield(r) => conn.client.shield_funds(r).await,
    }
    .map_err(CliError::from_status)?
    .into_inner();
    while let Some(item) = stream.next().await {
        let ev = item.map_err(CliError::from_status)?;
        if let Some(send_event::Event::Proposed(p)) = ev.event {
            return Ok(p);
        }
    }
    Err(CliError::Other(anyhow::anyhow!(
        "the daemon ended the dry run without a proposal"
    )))
}

/// Show the proposal and ask (`--yes` skips; no terminal is exit 4).
fn confirm(ctx: &Ctx, proposal: &Proposal, verb: &str) -> Result<(), CliError> {
    if ctx.json {
        println!("{}", to_json(proposal)?);
    } else {
        eprint!("{}", render_proposal(proposal));
    }
    ctx.prompter.confirm(
        &format!("{verb} {} ZEC in total?", format_zec(proposal.total_debit)),
        false,
        "--yes",
    )
}

/// Consume the stream, answering `SignatureRequired` (API.md §4.1, §4.3).
async fn follow(
    ctx: &Ctx,
    conn: &mut Conn,
    key: &str,
    mut stream: tonic::Streaming<SendEvent>,
    proposal_shown: bool,
) -> Result<(), CliError> {
    loop {
        let next = tokio::select! {
            item = stream.next() => item,
            _ = tokio::signal::ctrl_c() => return Err(CliError::Cancelled),
        };
        let Some(item) = next else {
            return Ok(());
        };
        let ev = item.map_err(CliError::from_status)?;
        if ctx.json {
            println!("{}", to_json(&ev)?);
        }
        match ev.event {
            Some(send_event::Event::Proposed(p)) => {
                if !ctx.json && !proposal_shown {
                    eprint!("{}", render_proposal(&p));
                }
            }
            Some(send_event::Event::Proving(p)) => {
                if !ctx.quiet && !ctx.json {
                    if p.actions_done == 0 {
                        eprintln!(
                            "proving {} {} action(s)…",
                            p.actions_total,
                            pool_name(p.pool())
                        );
                    } else {
                        eprintln!("proven");
                    }
                }
            }
            Some(send_event::Event::SignatureRequired(req)) => {
                satisfy(ctx, conn, key, &req).await?;
            }
            Some(send_event::Event::Signed(s)) => {
                if !ctx.quiet && !ctx.json {
                    eprintln!("step {} signed", s.step);
                }
            }
            Some(send_event::Event::Broadcast(b)) => {
                if !ctx.json {
                    println!("{}", b.txid);
                }
                if !ctx.quiet && !ctx.json {
                    eprintln!("step {} broadcast", b.step);
                }
            }
            Some(send_event::Event::TexQueued(t)) => {
                if !ctx.quiet && !ctx.json {
                    eprintln!(
                        "tex pending (step 2 of 2): {} then {}",
                        t.step1_txid, t.step2_txid
                    );
                }
            }
            Some(send_event::Event::Mined(m)) if !ctx.quiet && !ctx.json => {
                eprintln!("step {} mined at height {}", m.step, m.height);
            }
            Some(send_event::Event::Mined(_)) => {}
            None => {}
        }
    }
}

/// How many wrong passphrases a terminal user may enter per session.
const PASSPHRASE_ATTEMPTS: u32 = 3;

/// Answer one `SignatureRequired` (shared with `pczt sign`).
pub(crate) async fn satisfy(
    ctx: &Ctx,
    conn: &mut Conn,
    key: &str,
    req: &SignatureRequired,
) -> Result<(), CliError> {
    let session_id = req.session_id.clone();
    match req.kind() {
        SignatureKind::Passphrase => {}
        other => {
            // Keystone sessions survive; the CLI's QR path arrives with M5.
            return Err(CliError::Daemon(
                GygesError::new(
                    ErrorReason::SignatureRequired,
                    format!(
                        "a {other:?} signature is required and this gyges cannot provide it; \
                         complete the session later with `gyges pczt qr-import --session`"
                    ),
                )
                .with_key(key)
                .with_session(session_id),
            ));
        }
    }
    let key_shown = if req.key_id.is_empty() {
        key
    } else {
        req.key_id.as_str()
    };
    let attempts = if ctx.prompter.has_passphrase_source() || !ctx.prompter.interactive() {
        1
    } else {
        PASSPHRASE_ATTEMPTS
    };
    for attempt in 1..=attempts {
        let passphrase = match ctx.prompter.passphrase(
            &format!("Enter passphrase to unlock key '{key_shown}'"),
            false,
        ) {
            Ok(p) => p,
            Err(e) => {
                // No terminal and no source (CLI_SPEC.md §1.2): nothing to
                // resume, so the session is aborted.
                abort_session(conn, &session_id).await;
                return Err(match e {
                    CliError::Daemon(err) if err.reason() == ErrorReason::VaultLocked => {
                        CliError::Daemon(
                            GygesError::new(
                                ErrorReason::VaultLocked,
                                format!(
                                    "key '{key_shown}' is locked; run 'gyges key unlock' or pass --passphrase-fd"
                                ),
                            )
                            .with_key(key_shown)
                            .with_session(session_id),
                        )
                    }
                    other => other,
                });
            }
        };
        let result = conn
            .client
            .unlock_key(UnlockKeyRequest {
                key_id: req.key_id.clone(),
                passphrase: passphrase.to_string(),
                ttl_secs: 0,
                session_id: session_id.clone(),
                scope: UnlockScope::Unspecified as i32,
            })
            .await;
        drop(passphrase);
        match result {
            Ok(_) => return Ok(()),
            Err(status) => {
                let err = CliError::from_status(status);
                let wrong = matches!(&err, CliError::Daemon(e) if e.reason() == ErrorReason::InvalidPassphrase);
                if wrong && attempt < attempts {
                    eprintln!("wrong passphrase");
                    continue;
                }
                abort_session(conn, &session_id).await;
                return Err(err);
            }
        }
    }
    unreachable!("the loop returns")
}

/// Best-effort abort of a session the CLI cannot satisfy.
async fn abort_session(conn: &mut Conn, session_id: &str) {
    let _ = conn
        .client
        .abort_signing_session(AbortSigningSessionRequest {
            session_id: session_id.to_string(),
        })
        .await;
}

/// CLI_SPEC.md §2.5: inputs per pool, outputs, the ZIP 317 fee per step,
/// the total debit, then the anchor, expiry and confirmations line.
pub fn render_proposal(p: &Proposal) -> String {
    use std::fmt::Write as _;
    let mut s = render_steps(p);
    let _ = writeln!(
        s,
        "Anchor height {}, expires at height {}, {} confirmations",
        p.anchor_height, p.expiry_height, p.min_confirmations
    );
    s
}

/// The steps and the total debit (shared with `pczt inspect`, whose file
/// knows no anchor height).
pub fn render_steps(p: &Proposal) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let n = p.steps.len();
    for step in &p.steps {
        let _ = writeln!(s, "Step {} of {n}:", step.index);
        for (i, inp) in step.inputs.iter().enumerate() {
            let _ = writeln!(
                s,
                "  {:<9} {} {} {} ({} ZEC)",
                if i == 0 { "inputs:" } else { "" },
                inp.count,
                pool_name(inp.pool()),
                if inp.pool() == Pool::Transparent {
                    "utxo(s)"
                } else {
                    "note(s)"
                },
                format_zec(inp.value)
            );
        }
        for (i, out) in step.outputs.iter().enumerate() {
            let what = if out.is_ephemeral {
                "ephemeral".to_string()
            } else if out.is_change {
                format!("change ({})", pool_name(out.pool()))
            } else {
                format!("{} ({})", out.address, pool_name(out.pool()))
            };
            let _ = writeln!(
                s,
                "  {:<9} {} {} ZEC{}",
                if i == 0 { "outputs:" } else { "" },
                what,
                format_zec(out.value),
                if out.has_memo { " + memo" } else { "" }
            );
        }
        let _ = writeln!(s, "  {:<9} {} ZEC (ZIP 317)", "fee:", format_zec(step.fee));
    }
    let _ = writeln!(s, "Total debit: {} ZEC", format_zec(p.total_debit));
    s
}

async fn sessions(ctx: &Ctx, args: SessionsArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .list_signing_sessions(ListSigningSessionsRequest {
            key_id: if args.all {
                String::new()
            } else {
                ctx.key.clone()
            },
            include_finished: args.include_finished,
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else {
        print!("{}", render_sessions(&resp.sessions));
        print!("{}", render_tex(&resp.tex_transfers));
    }
    Ok(())
}

pub fn tex_state_name(s: TexState) -> &'static str {
    match s {
        TexState::Built => "built",
        TexState::Step1Broadcast => "step1_broadcast",
        TexState::Step2Broadcast => "step2_broadcast",
        TexState::Step1Mined => "step1_mined",
        TexState::Step2Mined => "step2_mined",
        TexState::Step2Failed => "step2_failed",
        TexState::Expired => "expired",
        TexState::Failed => "failed",
        TexState::Aborted => "aborted",
        TexState::Unspecified => "unknown",
    }
}

/// CLI_SPEC.md §2.5: the ZIP 320 rows under the sessions.
pub fn render_tex(rows: &[TexQueueEntry]) -> String {
    use std::fmt::Write as _;
    if rows.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<64} {:<18} {:<16} {:<8} {:<10} AMOUNT",
        "TEX STEP 1 TXID", "KEY", "STATE", "EXPIRES", "ATTEMPTS"
    );
    for r in rows {
        let _ = writeln!(
            s,
            "{:<64} {:<18} {:<16} {:<8} {:<10} {} ZEC{}",
            r.step1_txid,
            r.key_id,
            tex_state_name(r.state()),
            r.expiry_height,
            r.attempts,
            format_zec(r.amount),
            if r.last_error.is_empty() {
                String::new()
            } else {
                format!("  ({})", r.last_error)
            }
        );
    }
    s
}

fn print_tex(ctx: &Ctx, entry: &TexQueueEntry) -> Result<(), CliError> {
    if ctx.json {
        println!("{}", to_json(entry)?);
    } else {
        println!("{}", entry.step2_txid);
        if !ctx.quiet {
            eprintln!(
                "tex transfer {}: {} (step 2 {})",
                entry.step1_txid,
                tex_state_name(entry.state()),
                entry.step2_txid
            );
        }
    }
    Ok(())
}

fn parse_txid_arg(id: &str) -> Result<(), CliError> {
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CliError::Daemon(GygesError::new(
            ErrorReason::InvalidArgument,
            "expected the 64-hex step-1 txid `tx send` printed",
        )))
    }
}

/// How long `tx resume` waits for the daemon to rebuild step 2 after the
/// passphrase was accepted.
const RESUME_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// `tx resume TXID` (API.md §6.5): unary; when the daemon needs a passphrase
/// it answers `SIGNATURE_REQUIRED` with a session, the CLI satisfies it and
/// then polls until the row has its new step 2 (or the session failed).
async fn resume(ctx: &Ctx, txid: String) -> Result<(), CliError> {
    parse_txid_arg(&txid)?;
    let mut conn = ctx.connect().await?;
    let key = shown_key(ctx, &conn);
    let request = || ResumeTexTransferRequest {
        key_id: ctx.key.clone(),
        step1_txid: txid.clone(),
        session_token: Vec::new(),
    };
    let err = match conn.client.resume_tex_transfer(request()).await {
        Ok(resp) => return print_tex(ctx, &resp.into_inner()),
        Err(status) => CliError::from_status(status),
    };
    let session_id = match &err {
        CliError::Daemon(e)
            if e.reason() == ErrorReason::SignatureRequired && !e.session_id.is_empty() =>
        {
            e.session_id.clone()
        }
        _ => return Err(err),
    };
    let key_id = match &err {
        CliError::Daemon(e) if !e.key_id.is_empty() => e.key_id.clone(),
        _ => key.clone(),
    };
    satisfy(
        ctx,
        &mut conn,
        &key,
        &SignatureRequired {
            key_id,
            kind: SignatureKind::Passphrase as i32,
            session_id: session_id.clone(),
            step: 2,
            ..Default::default()
        },
    )
    .await?;
    if !ctx.quiet && !ctx.json {
        eprintln!("building a new step 2…");
    }
    let deadline = tokio::time::Instant::now() + RESUME_WAIT;
    loop {
        let sessions = conn
            .client
            .list_signing_sessions(ListSigningSessionsRequest {
                key_id: ctx.key.clone(),
                include_finished: true,
            })
            .await
            .map_err(CliError::from_status)?
            .into_inner();
        if let Some(s) = sessions
            .sessions
            .iter()
            .find(|s| s.session_id == session_id)
            && s.status() == SessionStatus::Failed
        {
            return Err(CliError::Daemon(
                GygesError::new(ErrorReason::Internal, s.last_error.clone())
                    .with_key(&key)
                    .with_session(session_id),
            ));
        }
        if let Some(row) = sessions.tex_transfers.iter().find(|r| r.step1_txid == txid)
            && row.state() != TexState::Step2Failed
        {
            return print_tex(ctx, row);
        }
        if tokio::time::Instant::now() > deadline {
            return Err(CliError::Other(anyhow::anyhow!(
                "the daemon is still building step 2; check `gyges tx sessions`"
            )));
        }
        tokio::select! {
            () = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
            _ = tokio::signal::ctrl_c() => return Err(CliError::Cancelled),
        }
    }
}

pub fn render_sessions(sessions: &[SigningSession]) -> String {
    use std::fmt::Write as _;
    if sessions.is_empty() {
        return "no signing sessions\n".to_string();
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<34} {:<18} {:<12} {:<20} {:<22} DEBIT",
        "SESSION", "KEY", "KIND", "STATUS", "EXPIRES"
    );
    for x in sessions {
        let status = match x.status() {
            SessionStatus::AwaitingSignature => "awaiting-signature",
            SessionStatus::Completed => "completed",
            SessionStatus::Expired => "expired",
            SessionStatus::Aborted => "aborted",
            SessionStatus::Failed => "failed",
            SessionStatus::Unspecified => "unknown",
        };
        let kind = match x.kind() {
            SignatureKind::Passphrase => "passphrase",
            SignatureKind::KeystoneSinglePczt => "keystone-pczt",
            SignatureKind::KeystoneBatch => "keystone-batch",
            SignatureKind::Unspecified => "unknown",
        };
        let _ = writeln!(
            s,
            "{:<34} {:<18} {:<12} {:<20} {:<22} {}",
            x.session_id,
            x.key_id,
            kind,
            status,
            format_unix(x.expires_at),
            x.summary
                .as_ref()
                .map(|p| format!("{} ZEC", format_zec(p.total_debit)))
                .unwrap_or_default()
        );
    }
    s
}

async fn abort(ctx: &Ctx, id: String) -> Result<(), CliError> {
    let is_hex = id.bytes().all(|b| b.is_ascii_hexdigit());
    match id.len() {
        32 if is_hex => {}
        64 if is_hex => {
            // A ZIP 320 transfer still `built` (API.md §4.3).
            let mut conn = ctx.connect().await?;
            let entry = conn
                .client
                .abort_tex_transfer(AbortTexTransferRequest {
                    key_id: ctx.key.clone(),
                    step1_txid: id,
                })
                .await
                .map_err(CliError::from_status)?
                .into_inner();
            if ctx.json {
                println!("{}", to_json(&entry)?);
            } else if !ctx.quiet {
                eprintln!("tex transfer {} aborted", entry.step1_txid);
            }
            return Ok(());
        }
        _ => {
            return Err(CliError::Daemon(GygesError::new(
                ErrorReason::InvalidArgument,
                "expected a 32-hex session id or a 64-hex txid",
            )));
        }
    }
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .abort_signing_session(AbortSigningSessionRequest { session_id: id })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else if !ctx.quiet {
        eprintln!("session {} aborted", resp.session_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::{ProposalStep, ProposedInput, ProposedOutput};

    #[test]
    fn proposal_rendering_shows_every_number() {
        let p = Proposal {
            steps: vec![ProposalStep {
                index: 1,
                inputs: vec![ProposedInput {
                    pool: Pool::Orchard as i32,
                    count: 2,
                    value: 150_000_000,
                }],
                outputs: vec![
                    ProposedOutput {
                        address: "u1abc".into(),
                        pool: Pool::Orchard as i32,
                        value: 100_000_000,
                        has_memo: true,
                        ..Default::default()
                    },
                    ProposedOutput {
                        address: "change".into(),
                        pool: Pool::Orchard as i32,
                        value: 49_985_000,
                        is_change: true,
                        ..Default::default()
                    },
                ],
                fee: 15_000,
                transparent_only: false,
            }],
            total_debit: 100_015_000,
            total_fee: 15_000,
            anchor_height: 100,
            expiry_height: 150,
            min_confirmations: 10,
            upstream_proposal: vec![],
        };
        let s = render_proposal(&p);
        assert!(s.contains("Step 1 of 1"), "{s}");
        assert!(s.contains("2 orchard note(s) (1.50000000 ZEC)"), "{s}");
        assert!(s.contains("u1abc (orchard) 1.00000000 ZEC + memo"), "{s}");
        assert!(s.contains("change (orchard) 0.49985000 ZEC"), "{s}");
        assert!(s.contains("fee:      0.00015000 ZEC (ZIP 317)"), "{s}");
        assert!(s.contains("Total debit: 1.00015000 ZEC"), "{s}");
        assert!(
            s.contains("Anchor height 100, expires at height 150"),
            "{s}"
        );
    }

    #[test]
    fn session_table() {
        assert!(render_sessions(&[]).contains("no signing sessions"));
        let s = render_sessions(&[SigningSession {
            session_id: "ab".repeat(16),
            key_id: "main".into(),
            kind: SignatureKind::Passphrase as i32,
            status: SessionStatus::AwaitingSignature as i32,
            expires_at: 0,
            summary: Some(Proposal {
                total_debit: 5,
                ..Default::default()
            }),
            ..Default::default()
        }]);
        assert!(
            s.contains("awaiting-signature") && s.contains("passphrase"),
            "{s}"
        );
        assert!(s.contains("0.00000005 ZEC"), "{s}");
    }
}
