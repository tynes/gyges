//! `gyges tx list` (`ListTransactions`) and `gyges tx status`
//! (`GetTransactionStatus`), CLI_SPEC.md §2.5. `tx status --pir` exits 1
//! as not implemented, before any RPC is sent.

use clap::Args;
use gyges_proto::v1::{
    GetTransactionStatusRequest, GetTransactionStatusResponse, ListTransactionsRequest,
    ListTransactionsResponse, StatusSource, TransactionStatus, TransactionSummary,
};

use crate::amount::format_zec;
use crate::balance::pool_name;
use crate::client::Ctx;
use crate::exit::CliError;
use crate::output::{format_unix, to_json};
use crate::tx::tex_state_name;

#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// At most this many transactions [default: 50].
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Only transactions older than this txid (the last one of the previous page).
    #[arg(long, value_name = "TXID")]
    pub before: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    pub txid: String,
    /// Ask zakura-pir-status instead of the node (experimental; not implemented yet).
    #[arg(long)]
    pub pir: bool,
}

pub async fn list(ctx: &Ctx, args: ListArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .list_transactions(ListTransactionsRequest {
            key_id: ctx.key.clone(),
            limit: args.limit.unwrap_or(0),
            before_txid: args.before.unwrap_or_default(),
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else {
        print!("{}", render_list(&resp));
    }
    Ok(())
}

pub async fn status(ctx: &Ctx, args: StatusArgs) -> Result<(), CliError> {
    if args.pir {
        return Err(CliError::NotImplemented("tx status --pir"));
    }
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .get_transaction_status(GetTransactionStatusRequest {
            key_id: ctx.key.clone(),
            txid: args.txid,
            via_pir: false,
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else {
        println!("{}", render_status(&resp));
    }
    Ok(())
}

/// The CLI spelling of a status (CLI_SPEC.md §2.5).
pub fn status_name(s: TransactionStatus) -> &'static str {
    match s {
        TransactionStatus::Unspecified => "unknown",
        TransactionStatus::AwaitingSignature => "awaiting-signature",
        TransactionStatus::Pending => "pending",
        TransactionStatus::Mined => "mined",
        TransactionStatus::Expired => "expired",
        TransactionStatus::Failed => "failed",
        TransactionStatus::TexPending => "tex-pending",
    }
}

/// One line for `tx status`.
pub fn render_status(r: &GetTransactionStatusResponse) -> String {
    let mut s = match r.status() {
        TransactionStatus::Mined => format!(
            "mined at height {} ({} confirmation{})",
            r.height,
            r.confirmations,
            if r.confirmations == 1 { "" } else { "s" }
        ),
        TransactionStatus::Pending => "pending: not mined yet".to_string(),
        TransactionStatus::TexPending => {
            "tex-pending: the ZIP 320 transfer is not finished; see `gyges tx sessions`".to_string()
        }
        TransactionStatus::Expired => "expired: it can no longer be mined".to_string(),
        TransactionStatus::Failed => "failed; see `gyges tx sessions`".to_string(),
        other => status_name(other).to_string(),
    };
    if r.source() == StatusSource::Unspecified && r.status() == TransactionStatus::Mined {
        s.push_str(" (the node no longer holds it; height from the wallet's scan)");
    }
    s
}

fn memo_text(memo: &[u8]) -> Option<String> {
    if memo.is_empty() {
        return None;
    }
    Some(match std::str::from_utf8(memo) {
        Ok(t) => format!("{:?}", t),
        Err(_) => format!("0x{}", hex::encode(memo)),
    })
}

fn render_one(s: &mut String, t: &TransactionSummary) {
    use std::fmt::Write as _;
    let when = if t.timestamp == 0 {
        "-".to_string()
    } else {
        format_unix(t.timestamp)
    };
    let height = if t.height == 0 {
        "-".to_string()
    } else {
        t.height.to_string()
    };
    let _ = writeln!(
        s,
        "{when:<21} {:<19} {height:>8} {:>18} {:>12} {}",
        status_name(t.status()),
        format_zec(t.net_value),
        format_zec(t.fee),
        t.txid
    );
    for o in t.outputs.iter().filter(|o| !o.is_change) {
        let to = if o.is_ephemeral {
            "ephemeral".to_string()
        } else if o.address.is_empty() {
            "(this wallet)".to_string()
        } else {
            o.address.clone()
        };
        let _ = write!(
            s,
            "    -> {:<12} {:>18} {to}",
            pool_name(o.pool()),
            format_zec(o.value)
        );
        if let Some(m) = memo_text(&o.memo) {
            let _ = write!(s, "  memo {m}");
        }
        let _ = writeln!(s);
    }
    if let Some(tex) = &t.tex {
        let _ = writeln!(
            s,
            "    tex {} (step 1 {}, step 2 {})",
            tex_state_name(tex.state()),
            tex.step1_txid,
            tex.step2_txid
        );
    }
}

/// `tx list` for a terminal: one line per transaction, then its
/// non-change outputs and its ZIP 320 row.
pub fn render_list(r: &ListTransactionsResponse) -> String {
    use std::fmt::Write as _;
    if r.transactions.is_empty() {
        return "no transactions\n".to_string();
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<21} {:<19} {:>8} {:>18} {:>12} TXID",
        "TIME", "STATUS", "HEIGHT", "NET", "FEE"
    );
    for t in &r.transactions {
        render_one(&mut s, t);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::{Pool, TexQueueEntry, TexState, TransactionOutput};

    #[test]
    fn list_shows_status_values_outputs_and_tex() {
        let r = ListTransactionsResponse {
            transactions: vec![
                TransactionSummary {
                    txid: "ab".repeat(32),
                    status: TransactionStatus::Mined as i32,
                    height: 104,
                    timestamp: 0,
                    net_value: -100_010_000,
                    fee: 10_000,
                    outputs: vec![
                        TransactionOutput {
                            pool: Pool::Ironwood as i32,
                            address: "uregtest1x".into(),
                            value: 100_000_000,
                            memo: b"lunch".to_vec(),
                            ..Default::default()
                        },
                        TransactionOutput {
                            pool: Pool::Ironwood as i32,
                            value: 5,
                            is_change: true,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                TransactionSummary {
                    txid: "cd".repeat(32),
                    status: TransactionStatus::TexPending as i32,
                    tex: Some(TexQueueEntry {
                        state: TexState::Step1Mined as i32,
                        step1_txid: "cd".repeat(32),
                        step2_txid: "ef".repeat(32),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
        };
        let s = render_list(&r);
        assert!(s.contains("mined") && s.contains("104"), "{s}");
        assert!(s.contains("-1.00010000") && s.contains("0.00010000"), "{s}");
        assert!(s.contains("uregtest1x") && s.contains("\"lunch\""), "{s}");
        assert!(!s.contains("0.00000005"), "change is not listed: {s}");
        assert!(
            s.contains("tex-pending") && s.contains("tex step1_mined"),
            "{s}"
        );
        assert_eq!(
            render_list(&ListTransactionsResponse::default()),
            "no transactions\n"
        );
    }

    #[test]
    fn status_lines() {
        let r = GetTransactionStatusResponse {
            status: TransactionStatus::Mined as i32,
            height: 10,
            confirmations: 1,
            source: StatusSource::Node as i32,
        };
        assert_eq!(render_status(&r), "mined at height 10 (1 confirmation)");
        let r = GetTransactionStatusResponse {
            status: TransactionStatus::Mined as i32,
            height: 10,
            confirmations: 3,
            source: StatusSource::Unspecified as i32,
        };
        assert!(render_status(&r).contains("3 confirmations"));
        assert!(render_status(&r).contains("wallet's scan"));
        let r = GetTransactionStatusResponse {
            status: TransactionStatus::Pending as i32,
            source: StatusSource::Node as i32,
            ..Default::default()
        };
        assert!(render_status(&r).starts_with("pending"));
    }
}
