//! The persisted side of the `TexQueue` (ARCHITECTURE.md §3.3, DATA_MODEL.md
//! §5.1, OVERVIEW.md Q-T1): one row per ZIP 320 transfer, in the key's own
//! `wallet.sqlite`, holding both signed transactions so that the daemon can
//! finish a transfer after a restart without signing again.
//!
//! The table lives next to the upstream schema through the extension
//! mechanism `zcash_client_sqlite` provides: an external migration creates
//! it, and every read and write goes through
//! `WalletDb::transactionally_with_extension`, which only lets statements
//! touch tables named `ext_*`. That prefix is upstream's, not ours, so the
//! table is `ext_gyges_tex_queue` rather than the `gyges_tex_queue` the
//! first draft of `DATA_MODEL.md` named.
//!
//! The state machine itself (what to broadcast when, and what the node
//! says) runs in `gygesd::tex`; this module knows nothing about the node.

use rusqlite::{OptionalExtension as _, named_params};
use uuid::Uuid;

use crate::TexState;
use crate::ext::{ExtTable, query_ids, with_ext};
use crate::registry::Wallet;

/// The external migration's id (random, fixed forever).
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x5f0e_c3a4_7b2d_4e81_9a6c_d1f3_2b7e_8c45);

const TABLE: &str = "ext_gyges_tex_queue";

/// Creates `ext_gyges_tex_queue`. Registered with
/// `WalletMigrator::with_external_migrations` by the registry when it opens
/// a wallet.
pub const MIGRATION: ExtTable = ExtTable {
    id: MIGRATION_ID,
    table: TABLE,
    description: "Creates the Gyges ZIP 320 queue (ext_gyges_tex_queue).",
    create: create_table,
};

fn create_table() -> String {
    let states = TexState::ALL
        .iter()
        .map(|s| format!("'{}'", s.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "CREATE TABLE {TABLE} (
            step1_txid       BLOB NOT NULL PRIMARY KEY,
            step2_txid       BLOB NOT NULL,
            proposal         BLOB NOT NULL,
            step1_raw        BLOB NOT NULL,
            step2_raw        BLOB NOT NULL,
            ephemeral_addr   TEXT NOT NULL,
            recipient        TEXT NOT NULL,
            amount           INTEGER NOT NULL,
            expiry_height    INTEGER NOT NULL,
            state            TEXT NOT NULL CHECK (state IN ({states})),
            created_at       INTEGER NOT NULL,
            last_attempt_at  INTEGER,
            attempts         INTEGER NOT NULL DEFAULT 0,
            last_error       TEXT
        );
        CREATE INDEX {TABLE}_state ON {TABLE} (state);"
    )
}

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

/// Why a queue operation failed.
#[derive(Debug, thiserror::Error)]
pub enum TexQueueError {
    #[error("tex queue: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("tex queue: row {0} has an unknown state {1:?}")]
    BadState(String, String),
    #[error("tex queue: no row for step-1 txid {0}")]
    NotFound(String),
}

fn read_row(r: &rusqlite::Row<'_>) -> Result<TexRow, rusqlite::Error> {
    let txid = |i: usize| -> Result<[u8; 32], rusqlite::Error> {
        let v: Vec<u8> = r.get(i)?;
        <[u8; 32]>::try_from(v).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                i,
                rusqlite::types::Type::Blob,
                "txid is not 32 bytes".into(),
            )
        })
    };
    let state: String = r.get(9)?;
    Ok(TexRow {
        step1_txid: txid(0)?,
        step2_txid: txid(1)?,
        proposal: r.get(2)?,
        step1_raw: r.get(3)?,
        step2_raw: r.get(4)?,
        ephemeral_addr: r.get(5)?,
        recipient: r.get(6)?,
        amount: r.get::<_, i64>(7)?.try_into().unwrap_or(0),
        expiry_height: r.get::<_, i64>(8)?.try_into().unwrap_or(0),
        // Checked by the caller; the CHECK constraint keeps it valid.
        state: TexState::parse(&state).unwrap_or(TexState::Failed),
        created_at: r.get(10)?,
        last_attempt_at: r.get(11)?,
        attempts: r.get::<_, i64>(12)?.try_into().unwrap_or(0),
        last_error: r.get(13)?,
    })
}

const COLUMNS: &str = "step1_txid, step2_txid, proposal, step1_raw, step2_raw, ephemeral_addr, \
                       recipient, amount, expiry_height, state, created_at, last_attempt_at, \
                       attempts, last_error";

/// Insert a freshly built transfer (state `built`).
pub fn insert(wallet: &mut Wallet, row: &TexRow) -> Result<(), TexQueueError> {
    with_ext(wallet, |ext| {
        ext.execute(
            &format!(
                "INSERT INTO {TABLE} ({COLUMNS}) VALUES (:s1, :s2, :proposal, :raw1, :raw2, \
                 :eph, :recipient, :amount, :expiry, :state, :created, :attempt, :attempts, :err)"
            ),
            named_params! {
                ":s1": row.step1_txid.as_slice(),
                ":s2": row.step2_txid.as_slice(),
                ":proposal": row.proposal,
                ":raw1": row.step1_raw,
                ":raw2": row.step2_raw,
                ":eph": row.ephemeral_addr,
                ":recipient": row.recipient,
                ":amount": i64::try_from(row.amount).unwrap_or(i64::MAX),
                ":expiry": i64::from(row.expiry_height),
                ":state": row.state.as_str(),
                ":created": row.created_at,
                ":attempt": row.last_attempt_at,
                ":attempts": i64::from(row.attempts),
                ":err": row.last_error,
            },
        )?;
        Ok(())
    })
}

/// One row by its step-1 txid.
pub fn get(wallet: &mut Wallet, step1_txid: [u8; 32]) -> Result<Option<TexRow>, TexQueueError> {
    with_ext(wallet, |ext| {
        Ok(ext
            .query_row(
                &format!("SELECT {COLUMNS} FROM {TABLE} WHERE step1_txid = :s1"),
                named_params! { ":s1": step1_txid.as_slice() },
                read_row,
            )
            .optional()?)
    })
}

/// The step-1 txids of every row in one of `states`, oldest first.
pub fn list_ids(wallet: &mut Wallet, states: &[TexState]) -> Result<Vec<[u8; 32]>, TexQueueError> {
    if states.is_empty() {
        return Ok(Vec::new());
    }
    let filter = states
        .iter()
        .map(|s| format!("'{}'", s.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    let rest = format!("FROM {TABLE} WHERE state IN ({filter}) ORDER BY created_at, step1_txid");
    let mut out = Vec::new();
    for h in query_ids(wallet, "hex(step1_txid)", &rest)? {
        let bytes = hex::decode(h).map_err(|e| {
            TexQueueError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                e.to_string().into(),
            ))
        })?;
        if let Ok(id) = <[u8; 32]>::try_from(bytes) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Every row (for `tx sessions`), oldest first; terminal rows included
/// when `include_finished`.
pub fn list(wallet: &mut Wallet, include_finished: bool) -> Result<Vec<TexRow>, TexQueueError> {
    let states: Vec<TexState> = TexState::ALL
        .into_iter()
        .filter(|s| include_finished || !s.is_terminal())
        .collect();
    let ids = list_ids(wallet, &states)?;
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(row) = get(wallet, id)? {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Move a row to `state`, replacing `last_error` (`None` clears it).
pub fn set_state(
    wallet: &mut Wallet,
    step1_txid: [u8; 32],
    state: TexState,
    last_error: Option<&str>,
) -> Result<(), TexQueueError> {
    let n = with_ext(wallet, |ext| {
        ext.execute(
            &format!("UPDATE {TABLE} SET state = :state, last_error = :err WHERE step1_txid = :s1"),
            named_params! {
                ":state": state.as_str(),
                ":err": last_error,
                ":s1": step1_txid.as_slice(),
            },
        )
    })?;
    if n == 0 {
        return Err(TexQueueError::NotFound(hex::encode(step1_txid)));
    }
    Ok(())
}

/// Count a broadcast attempt at `now`, recording its outcome.
pub fn record_attempt(
    wallet: &mut Wallet,
    step1_txid: [u8; 32],
    now: i64,
    error: Option<&str>,
) -> Result<(), TexQueueError> {
    with_ext(wallet, |ext| {
        ext.execute(
            &format!(
                "UPDATE {TABLE} SET attempts = attempts + 1, last_attempt_at = :now, \
                 last_error = :err WHERE step1_txid = :s1"
            ),
            named_params! {
                ":now": now,
                ":err": error,
                ":s1": step1_txid.as_slice(),
            },
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
) -> Result<(), TexQueueError> {
    let n = with_ext(wallet, |ext| {
        ext.execute(
            &format!(
                "UPDATE {TABLE} SET step2_txid = :s2, step2_raw = :raw2, expiry_height = :expiry, \
                 state = :state, last_error = NULL WHERE step1_txid = :s1"
            ),
            named_params! {
                ":s2": step2_txid.as_slice(),
                ":raw2": step2_raw,
                ":expiry": i64::from(expiry_height),
                ":state": TexState::Step1Mined.as_str(),
                ":s1": step1_txid.as_slice(),
            },
        )
    })?;
    if n == 0 {
        return Err(TexQueueError::NotFound(hex::encode(step1_txid)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;
    use zcash_client_backend::data_api::status::TransactionStatusMode;
    use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;
    use zcash_client_sqlite::WalletDb;
    use zcash_client_sqlite::util::SystemClock;
    use zcash_client_sqlite::wallet::init::WalletMigrator;

    fn wallet() -> (tempfile::TempDir, Wallet) {
        let dir = tempfile::tempdir().unwrap();
        let mut w = WalletDb::for_path(
            dir.path().join("wallet.sqlite"),
            Network::Regtest.consensus_params(),
            SystemClock,
            rand::rand_core::UnwrapErr(rand::rngs::SysRng),
        )
        .unwrap()
        .with_transparent_ledger_mode(TransparentLedgerMode::Public)
        .with_status_mode(TransactionStatusMode::Public);
        WalletMigrator::new()
            .with_external_migrations(vec![Box::new(MIGRATION)])
            .init_or_migrate(&mut w)
            .unwrap();
        (dir, w)
    }

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
        let (_dir, mut w) = wallet();
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
            Err(TexQueueError::NotFound(_))
        ));
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
