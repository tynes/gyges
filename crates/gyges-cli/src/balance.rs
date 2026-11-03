//! `gyges balance` (docs/interface.md CLI §2.4): spendable and pending value per
//! pool from `GetBalance`.

use std::fmt::Write as _;

use clap::Args;
use gyges_proto::v1::{GetBalanceRequest, GetBalanceResponse, Pool};

use crate::amount::format_zec;
use crate::client::Ctx;
use crate::exit::CliError;

#[derive(Debug, Clone, Args)]
pub struct BalanceArgs {
    /// Confirmations a note needs to count as spendable [default: the daemon's policy.min_confirmations].
    #[arg(long, value_name = "N")]
    pub min_conf: Option<u32>,
}

pub async fn run(ctx: &Ctx, args: BalanceArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .get_balance(GetBalanceRequest {
            key_id: ctx.key.clone(),
            min_confirmations: args.min_conf.unwrap_or(0),
        })
        .await?
        .into_inner();
    ctx.print(&resp, || render(&resp))
}

pub fn pool_name(pool: Pool) -> &'static str {
    match pool {
        Pool::Unspecified => "unknown",
        Pool::Transparent => "transparent",
        Pool::Sapling => "sapling",
        Pool::Orchard => "orchard",
        Pool::Ironwood => "ironwood",
    }
}

/// Human-readable table.
pub fn render(b: &GetBalanceResponse) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "{:<12} {:>20} {:>20}", "POOL", "SPENDABLE", "PENDING");
    for p in &b.pools {
        let _ = writeln!(
            s,
            "{:<12} {:>20} {:>20}",
            pool_name(p.pool()),
            format_zec(p.spendable),
            format_zec(p.pending)
        );
    }
    let _ = writeln!(
        s,
        "{:<12} {:>20} {:>20}",
        "total",
        format_zec(b.total_spendable),
        format_zec(b.total_pending)
    );
    let _ = writeln!(
        s,
        "(spendable at {} confirmations, as of height {})",
        b.min_confirmations, b.as_of_height
    );
    // The pools follow the wallet's note rules; `tx send` also needs the
    // key synced, and says so with this same sentence.
    if !b.not_spendable_reason.is_empty() {
        let _ = writeln!(
            s,
            "warning: `tx send` refuses these funds until sync completes: {}",
            b.not_spendable_reason
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::PoolBalance;

    #[test]
    fn table_lists_pools_and_totals() {
        let b = GetBalanceResponse {
            pools: vec![
                PoolBalance {
                    pool: Pool::Orchard as i32,
                    spendable: 150_000_000,
                    pending: 0,
                    pending_spend: 0,
                },
                PoolBalance {
                    pool: Pool::Transparent as i32,
                    spendable: 70_000,
                    pending: 5,
                    pending_spend: 0,
                },
            ],
            total_spendable: 150_070_000,
            total_pending: 5,
            min_confirmations: 10,
            as_of_height: 42,
            not_spendable_reason: String::new(),
        };
        let s = render(&b);
        assert!(s.contains("orchard") && s.contains("1.50000000"), "{s}");
        assert!(s.contains("transparent") && s.contains("0.00070000"), "{s}");
        assert!(s.contains("total") && s.contains("1.50070000"), "{s}");
        assert!(s.contains("10 confirmations, as of height 42"), "{s}");
        assert!(!s.contains("warning"), "{s}");
    }

    #[test]
    fn a_key_that_cannot_send_says_so_under_the_table() {
        let reason = "key 'alice' is not spendable yet (stalled(pruned-past-scan-tip): node pruned \
                      past key 'alice'); run `gyges sync wait`";
        let b = GetBalanceResponse {
            pools: vec![PoolBalance {
                pool: Pool::Ironwood as i32,
                spendable: 100_000_000,
                ..Default::default()
            }],
            total_spendable: 100_000_000,
            min_confirmations: 10,
            as_of_height: 4_579_076,
            not_spendable_reason: reason.into(),
            ..Default::default()
        };
        let s = render(&b);
        let last = s.lines().last().expect("a line");
        assert_eq!(
            last,
            format!("warning: `tx send` refuses these funds until sync completes: {reason}")
        );
    }
}
