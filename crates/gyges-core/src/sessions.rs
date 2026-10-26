//! The persisted signing sessions (DATA_MODEL.md §5.2, API.md §6.1): one
//! row per PCZT that left the daemon as a file, holding the proposal the
//! user approved so that `BroadcastPczt` can run the Verifier against it
//! days later and after restarts (ARCHITECTURE.md §3.5). Passphrase
//! sessions of `tx send` stay in memory (`gygesd::tx::SessionHub`); the
//! Keystone kinds arrive with ROADMAP.md M5 and will share this table.
//!
//! Like the ZIP 320 queue the table lives in the key's own `wallet.sqlite`
//! under upstream's `ext_` prefix (`ext_gyges_signing_sessions`), created by
//! an external migration and reached only through
//! `transactionally_with_extension`.

use rusqlite::{OptionalExtension as _, named_params};
use uuid::Uuid;

use crate::ext::{ExtTable, with_ext};
use crate::registry::Wallet;

/// The external migration's id (random, fixed forever).
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x2c9b_41e7_8d05_4f6a_b3d2_7e18_c0a5_9f31);

const TABLE: &str = "ext_gyges_signing_sessions";

/// Creates `ext_gyges_signing_sessions`.
pub const MIGRATION: ExtTable = ExtTable {
    id: MIGRATION_ID,
    table: TABLE,
    description: "Creates the Gyges signing sessions table (ext_gyges_signing_sessions).",
    create: create_migration,
};

fn create_migration() -> String {
    format!(
        "CREATE TABLE {TABLE} (
            session_id   TEXT NOT NULL PRIMARY KEY,
            protocol     TEXT NOT NULL CHECK (protocol IN ('passphrase', 'keystone-batch', 'keystone-pczt', 'file')),
            status       TEXT NOT NULL CHECK (status IN ('awaiting-signature', 'signed', 'broadcast', 'aborted', 'expired')),
            created_at   INTEGER NOT NULL,
            expires_at   INTEGER NOT NULL,
            proposal     BLOB NOT NULL,
            expected     BLOB NOT NULL,
            txid         BLOB,
            last_error   TEXT
        );
        CREATE INDEX {TABLE}_status ON {TABLE} (status, expires_at);"
    )
}

/// Where a session stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    AwaitingSignature,
    Signed,
    Broadcast,
    Aborted,
    Expired,
}

impl SessionState {
    pub const ALL: [SessionState; 5] = [
        SessionState::AwaitingSignature,
        SessionState::Signed,
        SessionState::Broadcast,
        SessionState::Aborted,
        SessionState::Expired,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SessionState::AwaitingSignature => "awaiting-signature",
            SessionState::Signed => "signed",
            SessionState::Broadcast => "broadcast",
            SessionState::Aborted => "aborted",
            SessionState::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// The transport a session's signature travels by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Passphrase,
    KeystoneBatch,
    KeystonePczt,
    /// A `.pczt` file or pipe (`gyges pczt …`).
    File,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Passphrase => "passphrase",
            Protocol::KeystoneBatch => "keystone-batch",
            Protocol::KeystonePczt => "keystone-pczt",
            Protocol::File => "file",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Protocol::Passphrase,
            Protocol::KeystoneBatch,
            Protocol::KeystonePczt,
            Protocol::File,
        ]
        .into_iter()
        .find(|p| p.as_str() == s)
    }
}

/// One row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    /// 32 hex characters, the PCZT's `gyges.session_id`.
    pub session_id: String,
    pub protocol: Protocol,
    pub state: SessionState,
    pub created_at: i64,
    pub expires_at: i64,
    /// The `gyges.v1.Proposal` the user approved, serialised.
    pub proposal: Vec<u8>,
    /// `gyges_core::tx::Expected`, as its JSON form: what the Verifier
    /// checks the signed PCZT against.
    pub expected: Vec<u8>,
    /// Set once broadcast, internal byte order.
    pub txid: Option<[u8; 32]>,
    pub last_error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("signing sessions: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("signing sessions: row {0} has an unknown {1} {2:?}")]
    BadColumn(String, &'static str, String),
    #[error("signing sessions: no row for session {0}")]
    NotFound(String),
}

fn read_row(r: &rusqlite::Row<'_>) -> Result<SessionRow, SessionError> {
    let session_id: String = r.get(0)?;
    let protocol: String = r.get(1)?;
    let status: String = r.get(2)?;
    let txid: Option<Vec<u8>> = r.get(7)?;
    let txid = match txid {
        None => None,
        Some(v) => Some(
            <[u8; 32]>::try_from(v)
                .map_err(|v| SessionError::BadColumn(session_id.clone(), "txid", hex::encode(v)))?,
        ),
    };
    Ok(SessionRow {
        protocol: Protocol::parse(&protocol)
            .ok_or_else(|| SessionError::BadColumn(session_id.clone(), "protocol", protocol))?,
        state: SessionState::parse(&status)
            .ok_or_else(|| SessionError::BadColumn(session_id.clone(), "status", status))?,
        created_at: r.get(3)?,
        expires_at: r.get(4)?,
        proposal: r.get(5)?,
        expected: r.get(6)?,
        txid,
        last_error: r.get(8)?,
        session_id,
    })
}

const COLUMNS: &str =
    "session_id, protocol, status, created_at, expires_at, proposal, expected, txid, last_error";

pub fn insert(wallet: &mut Wallet, row: &SessionRow) -> Result<(), SessionError> {
    with_ext(wallet, |ext| {
        ext.execute(
            &format!(
                "INSERT INTO {TABLE} ({COLUMNS})
                 VALUES (:session_id, :protocol, :status, :created_at, :expires_at,
                         :proposal, :expected, :txid, :last_error)"
            ),
            named_params! {
                ":session_id": row.session_id,
                ":protocol": row.protocol.as_str(),
                ":status": row.state.as_str(),
                ":created_at": row.created_at,
                ":expires_at": row.expires_at,
                ":proposal": row.proposal,
                ":expected": row.expected,
                ":txid": row.txid.as_ref().map(|t| t.to_vec()),
                ":last_error": row.last_error,
            },
        )?;
        Ok(())
    })
}

pub fn get(wallet: &mut Wallet, session_id: &str) -> Result<Option<SessionRow>, SessionError> {
    with_ext(wallet, |ext| {
        ext.query_row(
            &format!("SELECT {COLUMNS} FROM {TABLE} WHERE session_id = :session_id"),
            named_params! { ":session_id": session_id },
            |r| Ok(read_row(r)),
        )
        .optional()?
        .transpose()
    })
}

/// Move a row to `state`, recording the txid (for `Broadcast`) or the
/// reason (for the failures).
pub fn set_state(
    wallet: &mut Wallet,
    session_id: &str,
    state: SessionState,
    txid: Option<[u8; 32]>,
    last_error: Option<&str>,
) -> Result<(), SessionError> {
    with_ext(wallet, |ext| {
        let n = ext.execute(
            &format!(
                "UPDATE {TABLE} SET status = :status, txid = COALESCE(:txid, txid),
                 last_error = :last_error WHERE session_id = :session_id"
            ),
            named_params! {
                ":status": state.as_str(),
                ":txid": txid.as_ref().map(|t| t.to_vec()),
                ":last_error": last_error,
                ":session_id": session_id,
            },
        )?;
        if n == 0 {
            return Err(SessionError::NotFound(session_id.to_string()));
        }
        Ok(())
    })
}

/// Every row, newest first; only those awaiting a signature unless
/// `include_finished`. The extension handle answers single rows only, so
/// the ids come back as one `group_concat` and the rows one by one.
pub fn list(wallet: &mut Wallet, include_finished: bool) -> Result<Vec<SessionRow>, SessionError> {
    let filter = if include_finished {
        String::new()
    } else {
        " WHERE status = 'awaiting-signature'".to_string()
    };
    let joined: Option<String> = with_ext(wallet, |ext| {
        ext.query_row(
            &format!(
                "SELECT group_concat(session_id, ',') FROM \
                 (SELECT session_id FROM {TABLE}{filter} ORDER BY created_at DESC, session_id)"
            ),
            [],
            |r| r.get(0),
        )
    })?;
    let mut rows = Vec::new();
    for id in joined
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
    {
        if let Some(row) = get(wallet, id)? {
            rows.push(row);
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for s in SessionState::ALL {
            assert_eq!(SessionState::parse(s.as_str()), Some(s));
        }
        for p in [
            Protocol::Passphrase,
            Protocol::KeystoneBatch,
            Protocol::KeystonePczt,
            Protocol::File,
        ] {
            assert_eq!(Protocol::parse(p.as_str()), Some(p));
        }
        assert!(SessionState::parse("done").is_none());
    }
}
