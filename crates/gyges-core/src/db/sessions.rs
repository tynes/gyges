//! The persisted signing sessions (docs/architecture.md Data model §5.2, docs/interface.md API §6.1): one
//! row in `ext_gyges_signing_sessions` per PCZT that left the daemon as a
//! file or for a Keystone, holding the proposal the user approved so that
//! the Verifier can run against it days later and after restarts
//! (docs/architecture.md Components §3.5). Passphrase sessions of `tx send` stay in memory
//! (`gygesd::tx::SessionHub`).
//!
//! A Keystone session carries its device-side
//! half ([`KeystoneRow`]) in the same row: the proven PCZT the device's
//! answer is applied to, the request it was shown, and how to broadcast it,
//! so it can be completed after a restart.

use rusqlite::named_params;

use super::{Db, DbError, with_db};
use crate::registry::Wallet;

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

/// The transport a persisted session's signature travels by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    KeystoneBatch,
    KeystonePczt,
    /// A `.pczt` file or pipe (`gyges pczt …`).
    File,
}

impl Protocol {
    pub const ALL: [Protocol; 3] = [
        Protocol::KeystoneBatch,
        Protocol::KeystonePczt,
        Protocol::File,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::KeystoneBatch => "keystone-batch",
            Protocol::KeystonePczt => "keystone-pczt",
            Protocol::File => "file",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }

    pub fn is_keystone(self) -> bool {
        matches!(self, Protocol::KeystoneBatch | Protocol::KeystonePczt)
    }
}

/// One session.
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
    /// The device-side half; present exactly for Keystone protocols.
    pub keystone: Option<KeystoneRow>,
}

/// The device-side half of a Keystone session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeystoneRow {
    /// The proven, unsigned PCZT the device's answer is applied to (the
    /// authoritative copy; the device only ever saw a redacted one).
    pub pczt: Vec<u8>,
    /// The CBOR body shown to the device (`zcash-sign-batch` or
    /// `zcash-pczt`), kept so `pczt qr-export --session` can show it again.
    pub payload: Vec<u8>,
    /// The batch protocol's request id, echoed by the device.
    pub request_id: Option<Vec<u8>>,
    /// Broadcast through the fallback endpoint's Tor client.
    pub via_tor: bool,
    /// The transaction's `nExpiryHeight`; past it, completing is refused.
    pub expiry_height: u32,
}

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    let pczt: Option<Vec<u8>> = r.get("pczt")?;
    let keystone = match pczt {
        None => None,
        Some(pczt) => Some(KeystoneRow {
            pczt,
            payload: r.get("payload")?,
            request_id: r.get("request_id")?,
            via_tor: r.get("via_tor")?,
            expiry_height: r.get("expiry_height")?,
        }),
    };
    Ok(SessionRow {
        session_id: r.get("session_id")?,
        protocol: r.get("protocol")?,
        state: r.get("status")?,
        created_at: r.get("created_at")?,
        expires_at: r.get("expires_at")?,
        proposal: r.get("proposal")?,
        expected: r.get("expected")?,
        txid: r.get("txid")?,
        last_error: r.get("last_error")?,
        keystone,
    })
}

fn get_in(db: &Db<'_>, session_id: &str) -> rusqlite::Result<Option<SessionRow>> {
    db.optional_row(
        "SELECT * FROM ext_gyges_signing_sessions WHERE session_id = :session_id",
        named_params! { ":session_id": session_id },
        read_row,
    )
}

/// Insert a session, with its device-side half when it has one.
pub fn insert(wallet: &mut Wallet, row: &SessionRow) -> Result<(), DbError> {
    let ks = row.keystone.as_ref();
    with_db(wallet, |db| {
        db.execute(
            "INSERT INTO ext_gyges_signing_sessions (
                 session_id, protocol, status, created_at, expires_at, proposal, expected,
                 txid, last_error, pczt, payload, request_id, via_tor, expiry_height)
             VALUES (:session_id, :protocol, :status, :created_at, :expires_at, :proposal,
                     :expected, :txid, :last_error, :pczt, :payload, :request_id, :via_tor,
                     :expiry_height)",
            named_params! {
                ":session_id": row.session_id,
                ":protocol": row.protocol,
                ":status": row.state,
                ":created_at": row.created_at,
                ":expires_at": row.expires_at,
                ":proposal": row.proposal,
                ":expected": row.expected,
                ":txid": row.txid,
                ":last_error": row.last_error,
                ":pczt": ks.map(|k| &k.pczt),
                ":payload": ks.map(|k| &k.payload),
                ":request_id": ks.and_then(|k| k.request_id.as_ref()),
                ":via_tor": ks.map(|k| k.via_tor),
                ":expiry_height": ks.map(|k| k.expiry_height),
            },
        )?;
        Ok(())
    })
}

pub fn get(wallet: &mut Wallet, session_id: &str) -> Result<Option<SessionRow>, DbError> {
    with_db(wallet, |db| Ok(get_in(db, session_id)?))
}

/// Every row, newest first; only those awaiting a signature unless
/// `include_finished`.
pub fn list(wallet: &mut Wallet, include_finished: bool) -> Result<Vec<SessionRow>, DbError> {
    with_db(wallet, |db| {
        let ids: Vec<String> = db.json(
            "SELECT json_group_array(session_id) FROM (
                 SELECT session_id FROM ext_gyges_signing_sessions
                 WHERE :all OR status = 'awaiting-signature'
                 ORDER BY created_at DESC, session_id)",
            named_params! { ":all": include_finished },
        )?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.extend(get_in(db, &id)?);
        }
        Ok(out)
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
) -> Result<(), DbError> {
    let n = with_db(wallet, |db| {
        db.execute(
            "UPDATE ext_gyges_signing_sessions
             SET status = :status, txid = COALESCE(:txid, txid), last_error = :last_error
             WHERE session_id = :session_id",
            named_params! {
                ":status": state,
                ":txid": txid,
                ":last_error": last_error,
                ":session_id": session_id,
            },
        )
    })?;
    if n == 0 {
        return Err(DbError::NotFound {
            table: "ext_gyges_signing_sessions",
            key: session_id.to_string(),
        });
    }
    Ok(())
}

/// Move a row from awaiting a signature to `to`, and only from there:
/// `false` when it had already left that state. This is how a completion
/// claims a session exactly once, and why an abort or an expiry can never
/// overwrite a finished row.
pub fn leave_awaiting(
    wallet: &mut Wallet,
    session_id: &str,
    to: SessionState,
    last_error: Option<&str>,
) -> Result<bool, DbError> {
    let n = with_db(wallet, |db| {
        db.execute(
            "UPDATE ext_gyges_signing_sessions SET status = :status, last_error = :last_error
             WHERE session_id = :session_id AND status = 'awaiting-signature'",
            named_params! {
                ":status": to,
                ":last_error": last_error,
                ":session_id": session_id,
            },
        )
    })?;
    Ok(n == 1)
}

/// Record why a completion attempt failed while the row stays awaiting a
/// signature, so the user can scan the device again.
pub fn note_error(wallet: &mut Wallet, session_id: &str, error: &str) -> Result<(), DbError> {
    with_db(wallet, |db| {
        db.execute(
            "UPDATE ext_gyges_signing_sessions SET last_error = :last_error
             WHERE session_id = :session_id AND status = 'awaiting-signature'",
            named_params! { ":last_error": error, ":session_id": session_id },
        )?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_wallet;

    fn file_row(id: &str, created_at: i64) -> SessionRow {
        SessionRow {
            session_id: id.into(),
            protocol: Protocol::File,
            state: SessionState::AwaitingSignature,
            created_at,
            expires_at: created_at + 600,
            proposal: vec![1, 2],
            expected: b"{}".to_vec(),
            txid: None,
            last_error: None,
            keystone: None,
        }
    }

    fn keystone_row(id: &str, created_at: i64) -> SessionRow {
        SessionRow {
            protocol: Protocol::KeystoneBatch,
            keystone: Some(KeystoneRow {
                pczt: vec![9; 8],
                payload: vec![7; 4],
                request_id: Some(vec![3; 16]),
                via_tor: true,
                expiry_height: 321,
            }),
            ..file_row(id, created_at)
        }
    }

    #[test]
    fn rows_round_trip_and_are_claimed_once() {
        let (_dir, mut w) = test_wallet();
        assert!(list(&mut w, true).unwrap().is_empty());
        insert(&mut w, &file_row("a", 1)).unwrap();
        insert(&mut w, &keystone_row("b", 2)).unwrap();
        assert_eq!(get(&mut w, "a").unwrap().unwrap(), file_row("a", 1));
        assert_eq!(get(&mut w, "b").unwrap().unwrap(), keystone_row("b", 2));
        assert!(get(&mut w, "zz").unwrap().is_none());

        note_error(&mut w, "b", "bad scan").unwrap();
        assert_eq!(
            get(&mut w, "b").unwrap().unwrap().last_error.as_deref(),
            Some("bad scan")
        );

        assert!(leave_awaiting(&mut w, "b", SessionState::Signed, None).unwrap());
        assert!(!leave_awaiting(&mut w, "b", SessionState::Aborted, None).unwrap());
        // A finished row takes no more device errors.
        note_error(&mut w, "b", "late").unwrap();
        let b = get(&mut w, "b").unwrap().unwrap();
        assert_eq!(b.state, SessionState::Signed);
        assert!(b.last_error.is_none());

        set_state(&mut w, "b", SessionState::Broadcast, Some([5; 32]), None).unwrap();
        // A later state change without a txid keeps the one recorded.
        set_state(&mut w, "b", SessionState::Broadcast, None, Some("x")).unwrap();
        assert_eq!(get(&mut w, "b").unwrap().unwrap().txid, Some([5; 32]));
        assert!(matches!(
            set_state(&mut w, "zz", SessionState::Aborted, None, None),
            Err(DbError::NotFound { .. })
        ));

        let awaiting: Vec<_> = list(&mut w, false).unwrap();
        assert_eq!(awaiting.len(), 1);
        assert_eq!(awaiting[0].session_id, "a");
        let all: Vec<_> = list(&mut w, true)
            .unwrap()
            .into_iter()
            .map(|r| r.session_id)
            .collect();
        assert_eq!(all, vec!["b", "a"]);
    }

    /// The CHECK lists take every variant, refuse anything else, and tie
    /// the device-side half to the Keystone protocols.
    #[test]
    fn schema_matches_the_enums() {
        let (_dir, mut w) = test_wallet();
        for (i, s) in SessionState::ALL.into_iter().enumerate() {
            let mut r = file_row(&format!("s{i}"), 0);
            r.state = s;
            insert(&mut w, &r).unwrap();
            assert_eq!(get(&mut w, &r.session_id).unwrap().unwrap().state, s);
        }
        for p in Protocol::ALL {
            let mut r = keystone_row(p.as_str(), 0);
            r.protocol = p;
            if !p.is_keystone() {
                r.keystone = None;
            }
            insert(&mut w, &r).unwrap();
            assert_eq!(get(&mut w, p.as_str()).unwrap().unwrap(), r);
        }
        let mut r = file_row("no-half", 0);
        r.protocol = Protocol::KeystonePczt;
        assert!(insert(&mut w, &r).is_err(), "Keystone row without a pczt");
        let mut r = keystone_row("extra-half", 0);
        r.protocol = Protocol::File;
        assert!(insert(&mut w, &r).is_err(), "file row with a pczt");
        let bad = with_db(&mut w, |db| {
            db.execute(
                "UPDATE ext_gyges_signing_sessions SET status = 'done' WHERE session_id = 's0'",
                [],
            )
        });
        assert!(bad.is_err());
    }

    #[test]
    fn names_round_trip() {
        for s in SessionState::ALL {
            assert_eq!(SessionState::parse(s.as_str()), Some(s));
        }
        for p in Protocol::ALL {
            assert_eq!(Protocol::parse(p.as_str()), Some(p));
        }
        assert!(SessionState::parse("done").is_none());
        assert!(Protocol::parse("passphrase").is_none());
    }
}
