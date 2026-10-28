//! Every SQL statement Gyges runs against a key's `wallet.sqlite`
//! (DATA_MODEL.md §5).
//!
//! Gyges' own tables sit next to the upstream schema under the `ext_`
//! prefix `zcash_client_sqlite` reserves for applications. One external
//! migration ([`MIGRATION`], registered by the registry when it opens a
//! wallet) creates them from `schema.sql`, and every statement goes through
//! `WalletDb::transactionally_with_extension`, whose authorizer lets a
//! statement read anything but write only `ext_*` tables.
//!
//! That handle answers one row per statement (`execute`, `query_row`), so a
//! read of many rows aggregates them into a single JSON cell
//! ([`Db::json`]) or reads ids first and rows one by one inside the same
//! transaction.
//!
//! Every statement here is a `&'static str` and every value a bound
//! parameter: [`Db`] accepts nothing else, so SQL cannot be assembled at
//! run time.

pub(crate) mod history;
pub(crate) mod labels;
pub mod sessions;
pub mod tex;

use std::collections::HashSet;

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{OptionalExtension as _, Params, Row};
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_sqlite::wallet::init::WalletMigrationError;

use crate::TexState;
use crate::registry::Wallet;
use sessions::{Protocol, SessionState};

/// Why a read or write of Gyges' tables failed.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("wallet database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("wallet database: cannot decode an aggregate read: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wallet database: no {table} row for {key}")]
    NotFound { table: &'static str, key: String },
}

impl From<DbError> for crate::TxError {
    fn from(e: DbError) -> Self {
        Self::Internal(e.to_string())
    }
}

/// The extension handle, restricted to static SQL.
pub(crate) struct Db<'a>(&'a zcash_client_sqlite::ExtensionTransaction<'a>);

impl Db<'_> {
    /// Run one statement; the number of rows changed.
    pub(crate) fn execute(
        &self,
        sql: &'static str,
        params: impl Params,
    ) -> rusqlite::Result<usize> {
        self.0.execute(sql, params)
    }

    /// Exactly one row.
    pub(crate) fn row<T>(
        &self,
        sql: &'static str,
        params: impl Params,
        f: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        self.0.query_row(sql, params, f)
    }

    /// At most one row.
    pub(crate) fn optional_row<T>(
        &self,
        sql: &'static str,
        params: impl Params,
        f: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<Option<T>> {
        self.0.query_row(sql, params, f).optional()
    }

    /// A statement whose single cell is a `json_group_array(…)`, decoded.
    /// An aggregate over no rows is `[]`, and a NULL cell reads as empty.
    pub(crate) fn json<T: serde::de::DeserializeOwned>(
        &self,
        sql: &'static str,
        params: impl Params,
    ) -> Result<Vec<T>, DbError> {
        let cell: Option<String> = self.row(sql, params, |r| r.get(0))?;
        match cell {
            None => Ok(Vec::new()),
            Some(s) => Ok(serde_json::from_str(&s)?),
        }
    }
}

/// Run `f` inside one wallet transaction.
pub(crate) fn with_db<T, E: From<rusqlite::Error>>(
    wallet: &mut Wallet,
    f: impl FnOnce(&Db<'_>) -> Result<T, E>,
) -> Result<T, E> {
    wallet.transactionally_with_extension(|_wdb, ext| f(&Db(ext)))
}

/// A JSON array of `items`, for binding a set to `json_each(:param)`.
fn json_array<S: serde::Serialize>(items: impl IntoIterator<Item = S>) -> String {
    let items: Vec<S> = items.into_iter().collect();
    // A Vec of strings always serialises.
    serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// The external migration creating every `ext_gyges_*` table. Later schema
/// changes are new migrations that depend on this one.
#[derive(Debug)]
pub(crate) struct Migration;

/// Registered with `WalletMigrator::with_external_migrations`.
pub(crate) const MIGRATION: Migration = Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        // Random, fixed forever.
        Uuid::from_u128(0x9e3b_6d10_4c7a_4f25_8b91_2a6e_d0c4_71f8)
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        // No `ext_` table references the wallet schema.
        HashSet::new()
    }

    fn description(&self) -> &'static str {
        "Creates the Gyges tables (ext_gyges_*)."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(include_str!("schema.sql"))?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "DROP TABLE ext_gyges_tex_queue;
             DROP TABLE ext_gyges_signing_sessions;
             DROP TABLE ext_gyges_address_labels;",
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Column types
// ---------------------------------------------------------------------------

/// `ToSql`/`FromSql` for an enum stored as its `as_str()` text. An unknown
/// stored value is an error, never a default.
macro_rules! text_column {
    ($t:ty) => {
        impl ToSql for $t {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                Ok(ToSqlOutput::from(self.as_str()))
            }
        }

        impl FromSql for $t {
            fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                let s = value.as_str()?;
                <$t>::parse(s).ok_or_else(|| {
                    FromSqlError::Other(format!("unknown {} {s:?}", stringify!($t)).into())
                })
            }
        }
    };
}

text_column!(TexState);
text_column!(SessionState);
text_column!(Protocol);

/// A test wallet with the Gyges tables, for the tests of this module's
/// children.
#[cfg(test)]
pub(crate) fn test_wallet() -> (tempfile::TempDir, Wallet) {
    use zcash_client_backend::data_api::status::TransactionStatusMode;
    use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;
    use zcash_client_sqlite::WalletDb;
    use zcash_client_sqlite::util::SystemClock;
    use zcash_client_sqlite::wallet::init::WalletMigrator;

    let dir = tempfile::tempdir().unwrap();
    let mut w = WalletDb::for_path(
        dir.path().join("wallet.sqlite"),
        crate::Network::Regtest.consensus_params(),
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
