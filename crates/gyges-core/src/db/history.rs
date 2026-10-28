//! Reads of upstream's documented views (`v_received_outputs`,
//! `v_received_output_spends`, `v_tx_outputs`) behind `crate::history`.
//! Each is one `json_group_array`; BLOB columns go through `hex()` because
//! JSON cannot hold a BLOB.
//!
//! A transaction is "live" when it is mined, has no expiry, or expires
//! above `:tip`; the predicate is written out for each alias it applies to.

use rusqlite::named_params;
use serde::Deserialize;

use super::{Db, DbError, json_array};

/// One received note or UTXO, as the view gives it.
#[derive(Deserialize)]
pub(crate) struct RawNote {
    pub pool: i64,
    pub txid: String,
    pub idx: u32,
    pub value: u64,
    pub height: Option<u32>,
    pub memo: String,
    pub change: Option<i64>,
    pub scope: Option<i64>,
    pub pos: Option<i64>,
    pub spent: Option<String>,
}

/// Every live note and UTXO the wallet received, with the first live
/// transaction spending it.
pub(crate) fn received_outputs(db: &Db<'_>, tip: u32) -> Result<Vec<RawNote>, DbError> {
    db.json(
        "SELECT json_group_array(json_object(
            'pool', pool, 'txid', txid, 'idx', idx, 'value', value, 'height', height,
            'memo', memo, 'change', change, 'scope', scope, 'pos', pos, 'spent', spent))
         FROM (
            SELECT ro.pool AS pool, hex(t.txid) AS txid, ro.output_index AS idx,
                   ro.value AS value, t.mined_height AS height,
                   hex(COALESCE(ro.memo,
                                (SELECT memo FROM sent_notes WHERE id = ro.sent_note_id))) AS memo,
                   ro.is_change AS change, a.key_scope AS scope,
                   CASE ro.pool
                       WHEN 2 THEN (SELECT commitment_tree_position FROM sapling_received_notes
                                    WHERE id = ro.id_within_pool_table)
                       WHEN 3 THEN (SELECT commitment_tree_position FROM orchard_received_notes
                                    WHERE id = ro.id_within_pool_table)
                       WHEN 4 THEN (SELECT commitment_tree_position FROM ironwood_received_notes
                                    WHERE id = ro.id_within_pool_table)
                   END AS pos,
                   (SELECT hex(st.txid)
                    FROM v_received_output_spends s
                    JOIN transactions st ON st.id_tx = s.transaction_id
                    WHERE s.pool = ro.pool AND s.received_output_id = ro.id_within_pool_table
                      AND (st.mined_height IS NOT NULL OR st.expiry_height IS NULL
                           OR st.expiry_height = 0 OR st.expiry_height > :tip)
                    ORDER BY st.mined_height IS NULL, st.mined_height
                    LIMIT 1) AS spent
            FROM v_received_outputs ro
            JOIN transactions t ON t.id_tx = ro.transaction_id
            LEFT JOIN addresses a ON a.id = ro.address_id
            WHERE (t.mined_height IS NOT NULL OR t.expiry_height IS NULL
                   OR t.expiry_height = 0 OR t.expiry_height > :tip)
         )",
        named_params! { ":tip": tip },
    )
}

/// One output of a transaction, as the view gives it.
#[derive(Deserialize)]
pub(crate) struct RawOutput {
    pub txid: String,
    pub pool: i64,
    pub address: Option<String>,
    pub value: u64,
    pub change: Option<i64>,
    pub memo: String,
    pub scope: Option<i64>,
}

/// The outputs of the transactions `txids`, by pool then index.
pub(crate) fn tx_outputs(db: &Db<'_>, txids: &[[u8; 32]]) -> Result<Vec<RawOutput>, DbError> {
    db.json(
        "SELECT json_group_array(json_object(
            'txid', hex(txid), 'pool', output_pool, 'address', to_address, 'value', value,
            'change', is_change, 'memo', hex(memo), 'scope', recipient_key_scope))
         FROM (SELECT * FROM v_tx_outputs
               WHERE txid IN (SELECT unhex(value) FROM json_each(:ids))
               ORDER BY output_pool, output_index)",
        named_params! { ":ids": json_array(txids.iter().map(hex::encode)) },
    )
}
