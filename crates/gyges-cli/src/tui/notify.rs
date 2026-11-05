//! Received-value notifications, as a diff of successive history snapshots.
//!
//! There is no event feed to subscribe to, so each fresh `ListTransactions`
//! result is compared with the last one seen for that key:
//! - the first snapshot of a key only fills the seen set, so opening the TUI
//!   never announces old history;
//! - a txid not seen before with `net_value > 0` is a receipt (pending, or
//!   already mined if it arrived between two polls);
//! - a seen txid that moved from unmined to mined is a confirmation, for
//!   sends as well as receipts.
//!
//! Notifications stay inside the TUI (a toast and the terminal bell), so no
//! amount is shown outside it (decisions.md Q-C7).

use std::collections::HashMap;

use gyges_proto::v1::{TransactionStatus, TransactionSummary};

/// What a toast announces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A new transaction that pays this key.
    Received {
        key_id: String,
        txid: String,
        value: i64,
        mined: bool,
    },
    /// A transaction already seen that is now mined.
    Mined {
        key_id: String,
        txid: String,
        value: i64,
        height: u32,
    },
}

impl Notice {
    /// Whether this one rings the bell: money arriving does, confirmations
    /// do not.
    pub fn rings(&self) -> bool {
        matches!(self, Notice::Received { .. })
    }
}

/// The txids seen per key, with whether each was mined.
#[derive(Debug, Default)]
pub struct Seen {
    by_key: HashMap<String, HashMap<String, bool>>,
}

fn is_mined(t: &TransactionSummary) -> bool {
    t.status() == TransactionStatus::Mined
}

impl Seen {
    /// Record `txs` as the latest history of `key_id` and return what is new
    /// in it, oldest first.
    pub fn diff(&mut self, key_id: &str, txs: &[TransactionSummary]) -> Vec<Notice> {
        let Some(known) = self.by_key.get_mut(key_id) else {
            let seeded = txs.iter().map(|t| (t.txid.clone(), is_mined(t))).collect();
            self.by_key.insert(key_id.to_string(), seeded);
            return Vec::new();
        };
        let mut out = Vec::new();
        // `ListTransactions` is newest first; announce in arrival order.
        for t in txs.iter().rev() {
            let mined = is_mined(t);
            match known.insert(t.txid.clone(), mined) {
                None if t.net_value > 0 => out.push(Notice::Received {
                    key_id: key_id.to_string(),
                    txid: t.txid.clone(),
                    value: t.net_value,
                    mined,
                }),
                Some(false) if mined => out.push(Notice::Mined {
                    key_id: key_id.to_string(),
                    txid: t.txid.clone(),
                    value: t.net_value,
                    height: t.height,
                }),
                _ => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(txid: &str, value: i64, status: TransactionStatus, height: u32) -> TransactionSummary {
        TransactionSummary {
            txid: txid.into(),
            net_value: value,
            status: status as i32,
            height,
            ..Default::default()
        }
    }

    #[test]
    fn the_first_snapshot_is_silent() {
        let mut seen = Seen::default();
        let history = [
            tx("b", 5, TransactionStatus::Pending, 0),
            tx("a", 7, TransactionStatus::Mined, 10),
        ];
        assert!(seen.diff("main", &history).is_empty());
        assert!(seen.diff("main", &history).is_empty(), "nothing changed");
    }

    #[test]
    fn a_new_incoming_txid_is_announced_and_a_new_send_is_not() {
        let mut seen = Seen::default();
        seen.diff("main", &[tx("a", 7, TransactionStatus::Mined, 10)]);
        let got = seen.diff(
            "main",
            &[
                tx("send", -3, TransactionStatus::Pending, 0),
                tx("in2", 9, TransactionStatus::Mined, 12),
                tx("in1", 5, TransactionStatus::Pending, 0),
                tx("a", 7, TransactionStatus::Mined, 10),
            ],
        );
        assert_eq!(
            got,
            vec![
                Notice::Received {
                    key_id: "main".into(),
                    txid: "in1".into(),
                    value: 5,
                    mined: false
                },
                Notice::Received {
                    key_id: "main".into(),
                    txid: "in2".into(),
                    value: 9,
                    mined: true
                },
            ],
            "oldest first; the outgoing send is not a receipt"
        );
        assert!(got.iter().all(Notice::rings));
    }

    #[test]
    fn a_move_to_mined_is_announced_once_for_sends_and_receipts() {
        let mut seen = Seen::default();
        seen.diff(
            "main",
            &[
                tx("in", 5, TransactionStatus::Pending, 0),
                tx("out", -2, TransactionStatus::Pending, 0),
            ],
        );
        let mined = [
            tx("in", 5, TransactionStatus::Mined, 20),
            tx("out", -2, TransactionStatus::Mined, 20),
        ];
        let got = seen.diff("main", &mined);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(
            got.iter()
                .all(|n| matches!(n, Notice::Mined { height: 20, .. }))
        );
        assert!(!got.iter().any(Notice::rings));
        assert!(seen.diff("main", &mined).is_empty(), "only once");
    }

    #[test]
    fn keys_are_tracked_apart() {
        let mut seen = Seen::default();
        seen.diff("main", &[]);
        // A second key's first snapshot is silent even though `main` is seeded.
        assert!(
            seen.diff("cold", &[tx("x", 1, TransactionStatus::Mined, 1)])
                .is_empty()
        );
        let got = seen.diff("main", &[tx("x", 1, TransactionStatus::Mined, 1)]);
        assert_eq!(got.len(), 1, "the same txid is new to `main`");
    }
}
