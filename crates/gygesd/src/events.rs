//! `WatchEvents` (docs/interface.md API §4.8): what changed, as it changes,
//! for clients that would otherwise poll (`gyges tui`).
//!
//! Each stream is a task that compares the daemon's state with what it last
//! sent. It wakes on every sync-progress change and once a second
//! otherwise. The node's tip, Tor's state and each key's state word are
//! cheap to read and are compared every wake. History is read (the newest
//! `HISTORY` rows per key) only when a scheduler tick has completed or the
//! tip moved, since that is when a mempool pass or a block can have found a
//! transaction.
//!
//! The stream opens with the current tip, Tor state and each key's sync
//! state; the history found at that point only seeds the comparison, so a
//! client is never told about transactions it could already list.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use gyges_proto::v1::{
    KeySyncStatus, ListTransactionsRequest, TipAdvanced, TorStatus, TransactionDetected,
    TransactionMined, TransactionStatus, WalletEvent, WatchEventsRequest, wallet_event,
};
use tokio::sync::mpsc;
use tonic::Status;

use crate::service::DaemonState;

/// History rows compared per key.
const HISTORY: u32 = 50;
/// Heartbeat between progress changes.
const IDLE: Duration = Duration::from_secs(1);

pub(crate) type EventStream = tonic::codegen::BoxStream<WalletEvent>;

/// What a key's sync state is compared on: not the scanned height, which
/// moves every batch.
fn sync_mark(s: &KeySyncStatus) -> (i32, i32, bool, bool) {
    (s.state, s.stall_reason, s.scanned, s.spendable)
}

fn tor_mark(t: &TorStatus) -> (i32, u32, String) {
    (t.state, t.bootstrap_percent, t.last_error.clone())
}

pub(crate) fn watch_events(
    state: Arc<DaemonState>,
    req: WatchEventsRequest,
) -> Result<EventStream, Status> {
    let only = if req.key_id.is_empty() {
        None
    } else {
        Some(
            crate::sync::resolve_synced_key(&state, &req.key_id)?
                .key_id()
                .to_string(),
        )
    };
    let (tx, rx) = mpsc::channel::<Result<WalletEvent, Status>>(32);
    tokio::spawn(async move {
        let mut changes = state.sync.subscribe();
        let mut tip: Option<(u32, String)> = None;
        let mut tor: Option<(i32, u32, String)> = None;
        let mut sync: HashMap<String, (i32, i32, bool, bool)> = HashMap::new();
        // txid -> mined, per key; absent until the key's first read.
        let mut seen: HashMap<String, HashMap<String, bool>> = HashMap::new();
        let mut ticks_done = None;
        loop {
            let mut out = Vec::new();

            let node = state.node_status();
            let now_tip = (node.tip_height, node.tip_hash.clone());
            let tip_moved = node.connected && tip.as_ref() != Some(&now_tip);
            if tip_moved {
                out.push(wallet_event::Event::Tip(TipAdvanced {
                    height: now_tip.0,
                    hash: now_tip.1.clone(),
                }));
                tip = Some(now_tip);
            }

            let t = crate::backfill::tor_status(&state);
            if tor.as_ref() != Some(&tor_mark(&t)) {
                tor = Some(tor_mark(&t));
                out.push(wallet_event::Event::Tor(t));
            }

            let keys: Vec<String> = state
                .wallet_keys()
                .iter()
                .map(|k| k.key_id().to_string())
                .filter(|k| only.as_ref().is_none_or(|o| o == k))
                .collect();
            for key_id in &keys {
                let s = crate::sync::to_proto(&state.sync.progress(key_id));
                if sync.get(key_id) != Some(&sync_mark(&s)) {
                    sync.insert(key_id.clone(), sync_mark(&s));
                    out.push(wallet_event::Event::Sync(s));
                }
            }

            let done = state.sync.ticks().1;
            if tip_moved || ticks_done != Some(done) {
                ticks_done = Some(done);
                for key_id in &keys {
                    history_events(&state, key_id, &mut seen, &mut out).await;
                }
            }

            for event in out {
                let ev = WalletEvent { event: Some(event) };
                if tx.send(Ok(ev)).await.is_err() {
                    return;
                }
            }
            tokio::select! {
                changed = changes.changed() => if changed.is_err() { return },
                () = tokio::time::sleep(IDLE) => {}
                () = tx.closed() => return,
            }
        }
    });
    Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
}

/// Compare one key's newest history with what the stream has seen. The
/// first read of a key only seeds.
async fn history_events(
    state: &Arc<DaemonState>,
    key_id: &str,
    seen: &mut HashMap<String, HashMap<String, bool>>,
    out: &mut Vec<wallet_event::Event>,
) {
    let Ok(resp) = crate::wallet::list_transactions(
        state.clone(),
        ListTransactionsRequest {
            key_id: key_id.to_string(),
            limit: HISTORY,
            before_txid: String::new(),
        },
    )
    .await
    else {
        return;
    };
    let first = !seen.contains_key(key_id);
    let known = seen.entry(key_id.to_string()).or_default();
    // Newest first on the wire; announce in arrival order.
    for t in resp.transactions.iter().rev() {
        let mined = t.status() == TransactionStatus::Mined;
        let before = known.insert(t.txid.clone(), mined);
        if first {
            continue;
        }
        match before {
            None => out.push(wallet_event::Event::Detected(TransactionDetected {
                key_id: key_id.to_string(),
                txid: t.txid.clone(),
                net_value: t.net_value,
                mined,
            })),
            Some(false) if mined => out.push(wallet_event::Event::Mined(TransactionMined {
                key_id: key_id.to_string(),
                txid: t.txid.clone(),
                net_value: t.net_value,
                height: t.height,
            })),
            _ => {}
        }
    }
}
