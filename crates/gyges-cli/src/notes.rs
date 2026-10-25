//! `gyges notes` (CLI_SPEC.md §2.4): decrypted notes and UTXOs from
//! `ListNotes`, with heights, values, memo previews and witness readiness.

use clap::{Args, ValueEnum};
use gyges_proto::v1::{ListNotesRequest, ListNotesResponse, Note, Pool, SpentFilter};

use crate::amount::format_zec;
use crate::balance::pool_name;
use crate::client::Ctx;
use crate::exit::CliError;
use crate::output::to_json;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PoolArg {
    Orchard,
    Ironwood,
    Sapling,
    Transparent,
}

impl PoolArg {
    fn to_proto(self) -> Pool {
        match self {
            PoolArg::Orchard => Pool::Orchard,
            PoolArg::Ironwood => Pool::Ironwood,
            PoolArg::Sapling => Pool::Sapling,
            PoolArg::Transparent => Pool::Transparent,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct NotesArgs {
    /// Only this pool [default: every pool].
    #[arg(long, value_name = "POOL")]
    pub pool: Option<PoolArg>,
    /// Only unspent notes (the default).
    #[arg(long, conflicts_with_all = ["spent", "all"])]
    pub unspent: bool,
    /// Only spent notes.
    #[arg(long, conflicts_with = "all")]
    pub spent: bool,
    /// Spent and unspent notes.
    #[arg(long)]
    pub all: bool,
}

impl NotesArgs {
    fn filter(&self) -> SpentFilter {
        if self.all {
            SpentFilter::All
        } else if self.spent {
            SpentFilter::Spent
        } else {
            SpentFilter::Unspent
        }
    }
}

pub async fn run(ctx: &Ctx, args: NotesArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .list_notes(ListNotesRequest {
            key_id: ctx.key.clone(),
            pool: args.pool.map_or(Pool::Unspecified, PoolArg::to_proto) as i32,
            spent: args.filter() as i32,
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else {
        print!("{}", render(&resp));
    }
    Ok(())
}

fn flags(n: &Note) -> String {
    let mut f = vec![if n.spent { "spent" } else { "unspent" }];
    if !n.spent {
        f.push(if n.witness_ready {
            "witness-ready"
        } else {
            "no-witness"
        });
    }
    if n.ephemeral {
        f.push("ephemeral");
    }
    f.join(",")
}

/// Human-readable table, oldest first.
pub fn render(r: &ListNotesResponse) -> String {
    use std::fmt::Write as _;
    if r.notes.is_empty() {
        return "no notes\n".to_string();
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<12} {:>20} {:>8}  {:<26} {:<67} MEMO",
        "POOL", "VALUE", "HEIGHT", "STATE", "OUTPOINT"
    );
    for n in &r.notes {
        let height = if n.height == 0 {
            "pending".to_string()
        } else {
            n.height.to_string()
        };
        let _ = writeln!(
            s,
            "{:<12} {:>20} {:>8}  {:<26} {:<67} {}",
            pool_name(n.pool()),
            format_zec(n.value),
            height,
            flags(n),
            format!("{}:{}", n.txid, n.output_index),
            n.memo_preview.replace(['\n', '\r', '\t'], " "),
        );
    }
    let total: i64 = r.notes.iter().filter(|n| !n.spent).map(|n| n.value).sum();
    let _ = writeln!(
        s,
        "{} notes, {} unspent ZEC",
        r.notes.len(),
        format_zec(total)
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_shows_pool_value_state_and_memo() {
        let r = ListNotesResponse {
            notes: vec![
                Note {
                    pool: Pool::Ironwood as i32,
                    txid: "ab".repeat(32),
                    output_index: 1,
                    value: 100_000_000,
                    height: 42,
                    memo_preview: "thanks\nfor lunch".into(),
                    witness_ready: true,
                    ..Default::default()
                },
                Note {
                    pool: Pool::Transparent as i32,
                    txid: "cd".repeat(32),
                    value: 5,
                    ephemeral: true,
                    ..Default::default()
                },
            ],
        };
        let s = render(&r);
        assert!(s.contains("ironwood") && s.contains("1.00000000"), "{s}");
        assert!(s.contains("unspent,witness-ready"), "{s}");
        assert!(s.contains(&format!("{}:1", "ab".repeat(32))), "{s}");
        assert!(s.contains("thanks for lunch"), "{s}");
        assert!(s.contains("pending") && s.contains("ephemeral"), "{s}");
        assert!(s.contains("2 notes, 1.00000005 unspent ZEC"), "{s}");
        assert_eq!(render(&ListNotesResponse::default()), "no notes\n");
    }

    #[test]
    fn the_default_filter_is_unspent() {
        let a = NotesArgs {
            pool: None,
            unspent: false,
            spent: false,
            all: false,
        };
        assert_eq!(a.filter(), SpentFilter::Unspent);
    }
}
