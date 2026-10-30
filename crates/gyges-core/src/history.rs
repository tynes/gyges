//! What the wallet has received and sent (docs/interface.md CLI §2.4–2.5,
//! docs/interface.md API `ListNotes`, `ListTransactions`, `GetTransactionStatus`): the
//! decrypted notes and UTXOs, and the transaction history with each
//! transaction's outputs.
//!
//! Upstream offers transaction summaries (`transaction_history_summaries`,
//! accounting as in `v_transactions`) but no production API for notes or
//! per-transaction outputs. Those are read from upstream's documented views
//! (`v_received_outputs`, `v_received_output_spends`, `v_tx_outputs`)
//! through the extension handle (`crate::db::history`).
//!
//! Two definitions the views leave to the reader:
//! * a note is **spent** when a transaction spending it is mined, or is
//!   unmined and not yet expired (upstream's own rule for spendability); a
//!   note received in an unmined transaction that has expired is not
//!   listed at all;
//! * a shielded note is **witness-ready** when it is mined at or below the
//!   wallet's fully scanned height and has a commitment tree position, the
//!   two things a spend's witness needs; a UTXO when it is mined.
//!
//! Compact blocks carry no memos, so a received note shows its memo when
//! the wallet holds the full transaction: always for the wallet's own sends
//! (their `sent_notes` row is the fallback), for incoming payments once
//! transaction enhancement fetches them (not yet).

use zcash_client_backend::data_api::WalletRead as _;
use zcash_protocol::memo::{Memo, MemoBytes};

use crate::Pool;
use crate::db::{self, with_db};
use crate::registry::Wallet;
use crate::tx::{TxError, account_of, internal};

/// Bytes of a text memo shown in a note listing (`Note.memo_preview`).
pub const MEMO_PREVIEW_BYTES: usize = 64;

/// Upstream's pool code in its views (`0` transparent, `2` Sapling, `3`
/// Orchard, `4` Ironwood); not the wire enum.
pub fn pool_of_code(code: i64) -> Option<Pool> {
    match code {
        0 => Some(Pool::Transparent),
        2 => Some(Pool::Sapling),
        3 => Some(Pool::Orchard),
        4 => Some(Pool::Ironwood),
        _ => None,
    }
}

/// One received note or UTXO (`gyges.v1.Note`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteRow {
    pub pool: Pool,
    /// Internal byte order.
    pub txid: [u8; 32],
    pub output_index: u32,
    pub value: u64,
    /// `None` while unmined.
    pub height: Option<u32>,
    pub memo_preview: String,
    /// The spending transaction, when [`NoteRow::spent`].
    pub spent_txid: Option<[u8; 32]>,
    pub witness_ready: bool,
    /// A ZIP 320 ephemeral transparent output.
    pub ephemeral: bool,
    pub is_change: bool,
}

impl NoteRow {
    pub fn spent(&self) -> bool {
        self.spent_txid.is_some()
    }
}

/// One output of a transaction (`gyges.v1.TransactionOutput`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    pub pool: Pool,
    /// The recipient the wallet recorded, or the receiving address; `None`
    /// for wallet-internal outputs the view has no address for.
    pub address: Option<String>,
    pub value: u64,
    pub is_change: bool,
    pub is_ephemeral: bool,
    /// The memo's text for a text memo, its raw bytes otherwise; empty for
    /// none.
    pub memo: Vec<u8>,
}

/// One transaction of the key's account (`gyges.v1.TransactionSummary`
/// before the daemon adds the ZIP 320 row and the status).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRow {
    /// Internal byte order.
    pub txid: [u8; 32],
    pub mined_height: Option<u32>,
    pub expiry_height: Option<u32>,
    /// Unmined with an expiry at or below the wallet's tip.
    pub expired_unmined: bool,
    /// Block time, else the time the wallet built it, else 0.
    pub timestamp: i64,
    /// Received minus spent, fees included.
    pub net_value: i64,
    pub fee: Option<u64>,
    pub outputs: Vec<TxOutput>,
    /// Position in its block, for ordering.
    pub tx_index: Option<u32>,
}

fn txid_from_hex(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

fn memo_from_hex(s: &str) -> Option<Memo> {
    if s.is_empty() {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    let mb = MemoBytes::from_bytes(&bytes).ok()?;
    Memo::try_from(mb).ok()
}

/// The first [`MEMO_PREVIEW_BYTES`] of a text memo, cut at a character
/// boundary; empty for any other memo.
pub fn memo_preview(memo: Option<&Memo>) -> String {
    let Some(Memo::Text(t)) = memo else {
        return String::new();
    };
    let s: &str = t;
    let mut end = s.len().min(MEMO_PREVIEW_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn memo_bytes(memo: Option<&Memo>) -> Vec<u8> {
    match memo {
        None | Some(Memo::Empty) => Vec::new(),
        Some(Memo::Text(t)) => t.as_bytes().to_vec(),
        Some(Memo::Arbitrary(b)) => b.to_vec(),
        Some(Memo::Future(b)) => b.as_slice().to_vec(),
    }
}

/// The wallet's tip and fully scanned height, 0 before the first scan.
fn heights(wallet: &Wallet) -> Result<(u32, u32), TxError> {
    let tip = wallet
        .chain_height()
        .map_err(|e| internal("chain height", e))?
        .map_or(0, u32::from);
    let scanned = wallet
        .block_fully_scanned()
        .map_err(|e| internal("fully scanned height", e))?
        .map_or(0, |m| u32::from(m.block_height()));
    Ok((tip, scanned))
}

/// Upstream's `key_scope` for ZIP 320 ephemeral addresses.
const EPHEMERAL_SCOPE: i64 = 2;

/// Every note and UTXO the account received, oldest first (unmined last).
pub fn notes(wallet: &mut Wallet) -> Result<Vec<NoteRow>, TxError> {
    let (tip, scanned) = heights(wallet)?;
    let raw = with_db(wallet, |db| db::history::received_outputs(db, tip))
        .map_err(|e| internal("reading the wallet", e))?;
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let (Some(pool), Some(txid)) = (pool_of_code(r.pool), txid_from_hex(&r.txid)) else {
            continue;
        };
        let mined_scanned = r.height.is_some_and(|h| h <= scanned);
        let witness_ready = match pool {
            Pool::Transparent => r.height.is_some(),
            _ => mined_scanned && r.pos.is_some(),
        };
        let memo = memo_from_hex(&r.memo);
        out.push(NoteRow {
            pool,
            txid,
            output_index: r.idx,
            value: r.value,
            height: r.height,
            memo_preview: memo_preview(memo.as_ref()),
            spent_txid: r.spent.as_deref().and_then(txid_from_hex),
            witness_ready,
            ephemeral: r.scope == Some(EPHEMERAL_SCOPE),
            is_change: r.change.unwrap_or(0) != 0,
        });
    }
    out.sort_by_key(|n| (n.height.is_none(), n.height, n.txid, n.pool, n.output_index));
    Ok(out)
}

/// The account's transactions, newest first: unmined ones (by the time the
/// wallet built them) before mined ones (by height, then position in the
/// block). Upstream returns them unordered.
fn sorted_summaries(wallet: &Wallet) -> Result<Vec<TxRow>, TxError> {
    let account = account_of(wallet)?;
    let summaries = wallet
        .transaction_history_summaries(account)
        .map_err(|e| internal("transaction history", e))?;
    let mut rows: Vec<TxRow> = summaries
        .into_iter()
        .map(|s| TxRow {
            txid: *s.txid.as_ref(),
            mined_height: s.mined_height.map(u32::from),
            expiry_height: s.expiry_height.map(u32::from).filter(|&h| h != 0),
            expired_unmined: s.expired_unmined,
            timestamp: s
                .block_time
                .and_then(|t| i64::try_from(t).ok())
                .or(s.created_time)
                .unwrap_or(0),
            net_value: s.account_balance_delta,
            fee: s.fee,
            outputs: Vec::new(),
            tx_index: s.tx_index,
        })
        .collect();
    rows.sort_by_key(|r| {
        std::cmp::Reverse((
            r.mined_height.is_none(),
            r.mined_height,
            r.tx_index,
            r.timestamp,
            r.txid,
        ))
    });
    Ok(rows)
}

/// Fill in each row's outputs with one read over `v_tx_outputs`.
fn add_outputs(wallet: &mut Wallet, rows: &mut [TxRow]) -> Result<(), TxError> {
    if rows.is_empty() {
        return Ok(());
    }
    let txids: Vec<[u8; 32]> = rows.iter().map(|r| r.txid).collect();
    let raw = with_db(wallet, |db| db::history::tx_outputs(db, &txids))
        .map_err(|e| internal("reading the wallet", e))?;
    for o in raw {
        let (Some(pool), Some(txid)) = (pool_of_code(o.pool), txid_from_hex(&o.txid)) else {
            continue;
        };
        let Some(row) = rows.iter_mut().find(|r| r.txid == txid) else {
            continue;
        };
        let memo = memo_from_hex(&o.memo);
        row.outputs.push(TxOutput {
            pool,
            address: o.address,
            value: o.value,
            is_change: o.change.unwrap_or(0) != 0,
            is_ephemeral: o.scope == Some(EPHEMERAL_SCOPE),
            memo: memo_bytes(memo.as_ref()),
        });
    }
    Ok(())
}

/// One page of history: at most `limit` transactions older than `before`
/// (by txid, internal byte order), newest first. An unknown `before` is
/// `INVALID_ARGUMENT`.
pub fn transactions(
    wallet: &mut Wallet,
    limit: usize,
    before: Option<[u8; 32]>,
) -> Result<Vec<TxRow>, TxError> {
    let all = sorted_summaries(wallet)?;
    let start = match before {
        None => 0,
        Some(id) => {
            all.iter().position(|r| r.txid == id).ok_or_else(|| {
                TxError::InvalidArgument("before_txid is not a transaction of this key".into())
            })? + 1
        }
    };
    let mut page: Vec<TxRow> = all.into_iter().skip(start).take(limit).collect();
    add_outputs(wallet, &mut page)?;
    Ok(page)
}

/// One transaction of the account, with its outputs, if the wallet has it.
pub fn transaction(wallet: &mut Wallet, txid: [u8; 32]) -> Result<Option<TxRow>, TxError> {
    let Some(row) = sorted_summaries(wallet)?
        .into_iter()
        .find(|r| r.txid == txid)
    else {
        return Ok(None);
    };
    let mut rows = [row];
    add_outputs(wallet, &mut rows)?;
    let [row] = rows;
    Ok(Some(row))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_codes_are_upstreams_not_the_wire_enum() {
        assert_eq!(pool_of_code(0), Some(Pool::Transparent));
        assert_eq!(pool_of_code(1), None, "1 is the wire enum's transparent");
        assert_eq!(pool_of_code(2), Some(Pool::Sapling));
        assert_eq!(pool_of_code(3), Some(Pool::Orchard));
        assert_eq!(pool_of_code(4), Some(Pool::Ironwood));
    }

    #[test]
    fn memo_previews_are_text_only_and_cut_at_a_boundary() {
        let text = |s: &str| Memo::from_bytes(s.as_bytes()).unwrap();
        assert_eq!(memo_preview(Some(&text("hello"))), "hello");
        assert_eq!(memo_preview(None), "");
        assert_eq!(memo_preview(Some(&Memo::Empty)), "");
        let long = "é".repeat(40); // 80 bytes
        let p = memo_preview(Some(&text(&long)));
        assert_eq!(p.len(), 64);
        assert!(long.starts_with(&p));
        let odd = format!("a{}", "é".repeat(40));
        assert_eq!(memo_preview(Some(&text(&odd))).len(), 63);
        assert_eq!(memo_bytes(Some(&text("hi"))), b"hi");
        assert!(memo_bytes(Some(&Memo::Empty)).is_empty());
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(txid_from_hex(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(txid_from_hex(""), None);
        assert_eq!(txid_from_hex("abcd"), None);
        assert!(memo_from_hex("").is_none());
        let mut empty = vec![0xf6];
        empty.resize(512, 0);
        assert_eq!(memo_from_hex(&hex::encode(empty)), Some(Memo::Empty));
    }
}
