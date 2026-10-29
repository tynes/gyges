//! The persisted side of the `TexQueue` (docs/architecture.md Components §3.3, docs/architecture.md Data model
//! §5.1, docs/decisions.md Q-T1): one row per ZIP 320 transfer in
//! `ext_gyges_tex_queue`, holding both signed transactions so that the
//! daemon can finish a transfer after a restart without signing again.
//!
//! The state machine itself (what to broadcast when, and what the node
//! says) runs in `gygesd::tex`; this module knows nothing about the node.

use rusqlite::named_params;

use super::{Db, DbError, json_array, with_db};
use crate::TexState;
use crate::registry::Wallet;

/// One ZIP 320 transfer (`TexQueueEntry` on the wire, plus the bytes the
/// daemon rebroadcasts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TexRow {
    /// Internal byte order, like every txid in Gyges.
    pub step1_txid: [u8; 32],
    pub step2_txid: [u8; 32],
    /// The `gyges.v1.Proposal` the user approved, serialised, for `tx list`
    /// and for the summary a `tx resume` session shows.
    pub proposal: Vec<u8>,
    pub step1_raw: Vec<u8>,
    pub step2_raw: Vec<u8>,
    /// The `t1…` the first step pays and the second spends.
    pub ephemeral_addr: String,
    /// The `tex1…` / `textest1…` recipient as given.
    pub recipient: String,
    /// What the recipient receives, in zatoshis (step 2's single output).
    pub amount: u64,
    /// Shared by both steps; a fresh step 2 from `tx resume` gets its own.
    pub expiry_height: u32,
    pub state: TexState,
    pub created_at: i64,
    pub last_attempt_at: Option<i64>,
    pub attempts: u32,
    pub last_error: Option<String>,
}

const TABLE: &str = "ext_gyges_tex_queue";

fn not_found(step1_txid: [u8; 32]) -> DbError {
    DbError::NotFound {
        table: TABLE,
        key: hex::encode(step1_txid),
    }
}

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TexRow> {
    Ok(TexRow {
        step1_txid: r.get("step1_txid")?,
        step2_txid: r.get("step2_txid")?,
        proposal: r.get("proposal")?,
        step1_raw: r.get("step1_raw")?,
        step2_raw: r.get("step2_raw")?,
        ephemeral_addr: r.get("ephemeral_addr")?,
        recipient: r.get("recipient")?,
        amount: r.get("amount")?,
        expiry_height: r.get("expiry_height")?,
        state: r.get("state")?,
        created_at: r.get("created_at")?,
        last_attempt_at: r.get("last_attempt_at")?,
        attempts: r.get("attempts")?,
        last_error: r.get("last_error")?,
    })
}

fn get_in(db: &Db<'_>, step1_txid: [u8; 32]) -> rusqlite::Result<Option<TexRow>> {
    db.optional_row(
        "SELECT * FROM ext_gyges_tex_queue WHERE step1_txid = :s1",
        named_params! { ":s1": step1_txid },
        read_row,
    )
}

fn ids_in(db: &Db<'_>, states: &[TexState]) -> Result<Vec<[u8; 32]>, DbError> {
    let hex_ids: Vec<String> = db.json(
        "SELECT json_group_array(hex(step1_txid)) FROM (
             SELECT step1_txid FROM ext_gyges_tex_queue
             WHERE state IN (SELECT value FROM json_each(:states))
             ORDER BY created_at, step1_txid)",
        named_params! { ":states": json_array(states.iter().map(|s| s.as_str())) },
    )?;
    hex_ids
        .iter()
        .map(|h| {
            hex::decode(h)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| {
                    DbError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        format!("malformed step-1 txid {h:?}").into(),
                    ))
                })
        })
        .collect()
}

/// Insert a freshly built transfer (state `built`).
pub fn insert(wallet: &mut Wallet, row: &TexRow) -> Result<(), DbError> {
    with_db(wallet, |db| {
        db.execute(
            "INSERT INTO ext_gyges_tex_queue (
                 step1_txid, step2_txid, proposal, step1_raw, step2_raw, ephemeral_addr,
                 recipient, amount, expiry_height, state, created_at, last_attempt_at,
                 attempts, last_error)
             VALUES (:s1, :s2, :proposal, :raw1, :raw2, :eph, :recipient, :amount, :expiry,
                     :state, :created, :attempt, :attempts, :err)",
            named_params! {
                ":s1": row.step1_txid,
                ":s2": row.step2_txid,
                ":proposal": row.proposal,
                ":raw1": row.step1_raw,
                ":raw2": row.step2_raw,
                ":eph": row.ephemeral_addr,
                ":recipient": row.recipient,
                ":amount": row.amount,
                ":expiry": row.expiry_height,
                ":state": row.state,
                ":created": row.created_at,
                ":attempt": row.last_attempt_at,
                ":attempts": row.attempts,
                ":err": row.last_error,
            },
        )?;
        Ok(())
    })
}

/// One row by its step-1 txid.
pub fn get(wallet: &mut Wallet, step1_txid: [u8; 32]) -> Result<Option<TexRow>, DbError> {
    with_db(wallet, |db| Ok(get_in(db, step1_txid)?))
}

/// The step-1 txids of every row in one of `states`, oldest first.
pub fn list_ids(wallet: &mut Wallet, states: &[TexState]) -> Result<Vec<[u8; 32]>, DbError> {
    with_db(wallet, |db| ids_in(db, states))
}

/// Every row (for `tx sessions`), oldest first; terminal rows included
/// when `include_finished`.
pub fn list(wallet: &mut Wallet, include_finished: bool) -> Result<Vec<TexRow>, DbError> {
    let states: Vec<TexState> = TexState::ALL
        .into_iter()
        .filter(|s| include_finished || !s.is_terminal())
        .collect();
    with_db(wallet, |db| {
        let mut out = Vec::new();
        for id in ids_in(db, &states)? {
            out.extend(get_in(db, id)?);
        }
        Ok(out)
    })
}

/// Move a row to `state`, replacing `last_error` (`None` clears it).
pub fn set_state(
    wallet: &mut Wallet,
    step1_txid: [u8; 32],
    state: TexState,
    last_error: Option<&str>,
) -> Result<(), DbError> {
    let n = with_db(wallet, |db| {
        db.execute(
            "UPDATE ext_gyges_tex_queue SET state = :state, last_error = :err
             WHERE step1_txid = :s1",
            named_params! { ":state": state, ":err": last_error, ":s1": step1_txid },
        )
    })?;
    if n == 0 {
        return Err(not_found(step1_txid));
    }
    Ok(())
}

/// Count a broadcast attempt at `now`, recording its outcome.
pub fn record_attempt(
    wallet: &mut Wallet,
    step1_txid: [u8; 32],
    now: i64,
    error: Option<&str>,
) -> Result<(), DbError> {
    with_db(wallet, |db| {
        db.execute(
            "UPDATE ext_gyges_tex_queue
             SET attempts = attempts + 1, last_attempt_at = :now, last_error = :err
             WHERE step1_txid = :s1",
            named_params! { ":now": now, ":err": error, ":s1": step1_txid },
        )?;
        Ok(())
    })
}

/// `tx resume` built a fresh second step: store it and put the row back
/// to `step1_mined`, where the queue will broadcast it.
pub fn replace_step2(
    wallet: &mut Wallet,
    step1_txid: [u8; 32],
    step2_txid: [u8; 32],
    step2_raw: &[u8],
    expiry_height: u32,
) -> Result<(), DbError> {
    let n = with_db(wallet, |db| {
        db.execute(
            "UPDATE ext_gyges_tex_queue
             SET step2_txid = :s2, step2_raw = :raw2, expiry_height = :expiry,
                 state = :state, last_error = NULL
             WHERE step1_txid = :s1",
            named_params! {
                ":s2": step2_txid,
                ":raw2": step2_raw,
                ":expiry": expiry_height,
                ":state": TexState::Step1Mined,
                ":s1": step1_txid,
            },
        )
    })?;
    if n == 0 {
        return Err(not_found(step1_txid));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_wallet;

    fn row(n: u8) -> TexRow {
        TexRow {
            step1_txid: [n; 32],
            step2_txid: [n + 100; 32],
            proposal: vec![1, 2, 3],
            step1_raw: vec![4; 10],
            step2_raw: vec![5; 10],
            ephemeral_addr: "tmEphemeral".into(),
            recipient: "textest1recipient".into(),
            amount: 123_456,
            expiry_height: 140,
            state: TexState::Built,
            created_at: 1_700_000_000 + i64::from(n),
            last_attempt_at: None,
            attempts: 0,
            last_error: None,
        }
    }

    #[test]
    fn rows_round_trip_and_move_through_states() {
        let (_dir, mut w) = test_wallet();
        assert!(list(&mut w, true).unwrap().is_empty());
        insert(&mut w, &row(1)).unwrap();
        insert(&mut w, &row(2)).unwrap();
        assert_eq!(get(&mut w, [1; 32]).unwrap().unwrap(), row(1));
        assert!(get(&mut w, [9; 32]).unwrap().is_none());
        // A duplicate step-1 txid is refused by the primary key.
        assert!(insert(&mut w, &row(1)).is_err());

        set_state(&mut w, [1; 32], TexState::Step1Broadcast, None).unwrap();
        record_attempt(&mut w, [1; 32], 42, Some("busy")).unwrap();
        let r = get(&mut w, [1; 32]).unwrap().unwrap();
        assert_eq!(r.state, TexState::Step1Broadcast);
        assert_eq!(r.attempts, 1);
        assert_eq!(r.last_attempt_at, Some(42));
        assert_eq!(r.last_error.as_deref(), Some("busy"));

        set_state(&mut w, [2; 32], TexState::Step2Mined, None).unwrap();
        assert_eq!(
            list_ids(&mut w, &[TexState::Step1Broadcast]).unwrap(),
            vec![[1; 32]]
        );
        assert!(list_ids(&mut w, &[]).unwrap().is_empty());
        let pending = list(&mut w, false).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].step1_txid, [1; 32]);
        assert_eq!(list(&mut w, true).unwrap().len(), 2);

        replace_step2(&mut w, [1; 32], [7; 32], &[9, 9], 200).unwrap();
        let r = get(&mut w, [1; 32]).unwrap().unwrap();
        assert_eq!(r.step2_txid, [7; 32]);
        assert_eq!(r.step2_raw, vec![9, 9]);
        assert_eq!(r.expiry_height, 200);
        assert_eq!(r.state, TexState::Step1Mined);
        assert!(r.last_error.is_none());

        assert!(matches!(
            set_state(&mut w, [3; 32], TexState::Failed, None),
            Err(DbError::NotFound { .. })
        ));
    }

    /// The CHECK list in schema.sql takes every state and nothing else.
    #[test]
    fn schema_accepts_exactly_the_states() {
        let (_dir, mut w) = test_wallet();
        for (i, s) in TexState::ALL.into_iter().enumerate() {
            let mut r = row(u8::try_from(i).unwrap());
            r.state = s;
            insert(&mut w, &r).unwrap();
            assert_eq!(get(&mut w, r.step1_txid).unwrap().unwrap().state, s);
        }
        let bad = with_db(&mut w, |db| {
            db.execute(
                "UPDATE ext_gyges_tex_queue SET state = 'done' WHERE step1_txid = :s1",
                named_params! { ":s1": [0u8; 32] },
            )
        });
        assert!(bad.is_err());
    }

    #[test]
    fn state_names_round_trip() {
        for s in TexState::ALL {
            assert_eq!(TexState::parse(s.as_str()), Some(s));
        }
        assert!(!TexState::Step2Failed.is_terminal());
        assert!(TexState::Aborted.is_terminal());
    }
}
