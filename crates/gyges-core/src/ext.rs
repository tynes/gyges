//! The `ext_` tables Gyges adds to each key's `wallet.sqlite`, created by
//! external migrations registered with
//! `WalletMigrator::with_external_migrations` and reached only through
//! upstream's `ExtensionTransaction` (DATA_MODEL.md §5).

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_sqlite::wallet::init::WalletMigrationError;

use crate::registry::Wallet;

pub(crate) type Ext<'a> = zcash_client_sqlite::ExtensionTransaction<'a>;

/// One `ext_` table and the migration that creates it.
#[derive(Debug)]
pub struct ExtTable {
    /// The migration's id (random, fixed forever).
    pub id: Uuid,
    pub table: &'static str,
    pub description: &'static str,
    /// The `CREATE` statements. A function, not a constant, because a CHECK
    /// list may be built from an enum at run time.
    pub create: fn() -> String,
}

impl schemerz::Migration<Uuid> for ExtTable {
    fn id(&self) -> Uuid {
        self.id
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        // No `ext_` table references the wallet schema.
        HashSet::new()
    }

    fn description(&self) -> &'static str {
        self.description
    }
}

impl RusqliteMigration for ExtTable {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(&(self.create)())?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(&format!("DROP TABLE {};", self.table))?;
        Ok(())
    }
}

/// Run `f` inside one wallet transaction with the extension handle.
pub(crate) fn with_ext<T, E: From<rusqlite::Error>>(
    wallet: &mut Wallet,
    f: impl FnOnce(&Ext<'_>) -> Result<T, E>,
) -> Result<T, E> {
    wallet.transactionally_with_extension(|_wdb, ext| f(ext))
}

/// `column` of every row that `rest` (`FROM … [WHERE …] ORDER BY …`)
/// selects, in order. The extension handle answers single rows only, so
/// the values come back as one `group_concat`.
pub(crate) fn query_ids(
    wallet: &mut Wallet,
    column: &str,
    rest: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let sql = format!("SELECT group_concat(id, ',') FROM (SELECT {column} AS id {rest})");
    let joined: Option<String> = with_ext(wallet, |ext| ext.query_row(&sql, [], |r| r.get(0)))?;
    Ok(joined
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}
