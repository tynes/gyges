//! `ext_gyges_address_labels` (DATA_MODEL.md §5.3): the labels given with
//! `address new --label`, keyed on the encoded address.

use rusqlite::named_params;

use super::{DbError, with_db};
use crate::registry::Wallet;

/// Set (or replace) the label of `address`.
pub(crate) fn set(
    wallet: &mut Wallet,
    address: &str,
    label: &str,
    now: i64,
) -> Result<(), DbError> {
    with_db(wallet, |db| {
        db.execute(
            "INSERT INTO ext_gyges_address_labels (address, label, created_at)
             VALUES (:address, :label, :now)
             ON CONFLICT (address) DO UPDATE SET label = excluded.label",
            named_params! { ":address": address, ":label": label, ":now": now },
        )?;
        Ok(())
    })
}

/// The label of `address`, if it has one.
pub(crate) fn get(wallet: &mut Wallet, address: &str) -> Result<Option<String>, DbError> {
    with_db(wallet, |db| {
        Ok(db.optional_row(
            "SELECT label FROM ext_gyges_address_labels WHERE address = :address",
            named_params! { ":address": address },
            |r| r.get(0),
        )?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_wallet;

    #[test]
    fn labels_upsert() {
        let (_dir, mut w) = test_wallet();
        assert_eq!(get(&mut w, "u1a").unwrap(), None);
        set(&mut w, "u1a", "rent", 1).unwrap();
        set(&mut w, "u1a", "savings", 2).unwrap();
        assert_eq!(get(&mut w, "u1a").unwrap().as_deref(), Some("savings"));
    }
}
