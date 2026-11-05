//! The background poller: one long-lived connection that reads the daemon's
//! state and sends it to the event loop as [`Event`]s.
//!
//! Every cycle asks `GetInfo` and `GetSyncStatus`. Balances, notes and
//! history are reloaded only when that state changes (a new tip, a key added
//! or removed, a key's sync state moving), plus a slow sweep so that a
//! mempool arrival, which changes neither, is still seen.
//!
//! A daemon of API 0.3 or later also serves `WatchEvents`: while that stream
//! runs, each event (a new tip, a transaction found or mined, a sync or Tor
//! change) runs a cycle at once. A daemon that answers `UNIMPLEMENTED` is
//! polled only, as before.
//!
//! This connection only reads. It never calls `UnlockKey`, so it never holds
//! a connection-scoped unlock token (docs/interface.md API §6.3) however long
//! the TUI stays open; sends get a connection of their own.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use gyges_proto::v1::gyges_client::GygesClient;
use gyges_proto::v1::{
    GetBalanceRequest, GetInfoRequest, GetInfoResponse, GetSyncStatusRequest, KeySyncStatus,
    ListNotesRequest, ListTransactionsRequest, SigningMode, SpentFilter, WatchEventsRequest,
};
use tokio::sync::{Notify, mpsc};
use tonic::transport::Channel;

use crate::client::Ctx;
use crate::exit::CliError;

use super::app::{Event, WalletSnapshot};

/// While only `scanned_tip` moves (a long scan), reload at most this often.
const SCAN_RELOAD: Duration = Duration::from_secs(10);
/// Reload anyway after this long, for mempool arrivals.
const SWEEP: Duration = Duration::from_secs(30);
/// History rows fetched per key.
pub const HISTORY_LIMIT: u32 = 50;

/// Asks the poller to run a cycle now and reload everything.
#[derive(Clone, Debug)]
pub struct RefreshHandle(Arc<Notify>);

impl RefreshHandle {
    pub fn request(&self) {
        self.0.notify_one();
    }
}

#[derive(Debug)]
pub struct Poller {
    ctx: Ctx,
    interval: Duration,
    tx: mpsc::UnboundedSender<Event>,
    refresh: Arc<Notify>,
}

/// What decides whether wallet data must be reloaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub tip_hash: String,
    pub keys: Vec<KeyMark>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMark {
    pub key_id: String,
    pub state: i32,
    pub scanned: bool,
    pub spendable: bool,
    pub scanned_tip: u32,
}

impl Fingerprint {
    pub fn of(info: &GetInfoResponse, sync: &[KeySyncStatus]) -> Self {
        let mut keys: Vec<KeyMark> = info
            .keys
            .iter()
            .map(|k| {
                let s = sync.iter().find(|s| s.key_id == k.key_id);
                KeyMark {
                    key_id: k.key_id.clone(),
                    state: s.map_or(0, |s| s.state),
                    scanned: s.is_some_and(|s| s.scanned),
                    spendable: s.is_some_and(|s| s.spendable),
                    scanned_tip: s.map_or(0, |s| s.scanned_tip),
                }
            })
            .collect();
        keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Self {
            tip_hash: info
                .node
                .as_ref()
                .map(|n| n.tip_hash.clone())
                .unwrap_or_default(),
            keys,
        }
    }

    /// Whether the change from `old` to `self` asks for a reload now.
    /// `since` is the time since the last reload.
    pub fn needs_reload(&self, old: Option<&Fingerprint>, since: Duration) -> bool {
        let Some(old) = old else { return true };
        if since >= SWEEP || self.tip_hash != old.tip_hash || self.keys.len() != old.keys.len() {
            return true;
        }
        let mut only_scan_moved = false;
        for (a, b) in self.keys.iter().zip(&old.keys) {
            if a.key_id != b.key_id
                || a.state != b.state
                || a.scanned != b.scanned
                || a.spendable != b.spendable
            {
                return true;
            }
            only_scan_moved |= a.scanned_tip != b.scanned_tip;
        }
        only_scan_moved && since >= SCAN_RELOAD
    }
}

impl Poller {
    pub fn new(ctx: Ctx, interval: Duration, tx: mpsc::UnboundedSender<Event>) -> Self {
        Self {
            ctx,
            interval,
            tx,
            refresh: Arc::new(Notify::new()),
        }
    }

    pub fn refresh_handle(&self) -> RefreshHandle {
        RefreshHandle(self.refresh.clone())
    }

    pub async fn run(self) {
        let mut client: Option<GygesClient<Channel>> = None;
        let mut last: Option<Fingerprint> = None;
        let mut last_load = Instant::now();
        let mut force = true;
        let mut watcher = Watcher::default();
        loop {
            match self
                .cycle(&mut client, &mut last, &mut last_load, force)
                .await
            {
                Ok(airgapped) => {
                    if !airgapped {
                        watcher.ensure(&self.ctx, &self.tx, &self.refresh);
                    }
                }
                Err(error) => {
                    client = None;
                    last = None;
                    // A daemon that comes back may be a newer one.
                    watcher.reset();
                    if self.tx.send(Event::Down { error }).is_err() {
                        return;
                    }
                }
            }
            force = tokio::select! {
                _ = tokio::time::sleep(self.interval) => false,
                _ = self.refresh.notified() => true,
            };
        }
    }

    /// One poll: `Ok(true)` when the daemon is air-gapped (it serves none of
    /// the wallet reads, nor `WatchEvents`). An `Err` means the daemon is
    /// unreachable (or the handshake failed): the connection is dropped and
    /// rebuilt next time.
    async fn cycle(
        &self,
        client: &mut Option<GygesClient<Channel>>,
        last: &mut Option<Fingerprint>,
        last_load: &mut Instant,
        force: bool,
    ) -> Result<bool, String> {
        let (c, info) = match client.take() {
            Some(mut c) => match c.get_info(GetInfoRequest {}).await {
                Ok(r) => (c, r.into_inner()),
                Err(s) => return Err(CliError::from_status(s).message()),
            },
            None => {
                let conn = self.ctx.connect().await.map_err(|e| e.message())?;
                (conn.client, conn.info)
            }
        };
        let c = client.insert(c);
        self.send(Event::Info(Box::new(info.clone())));
        if info.airgapped {
            // GetSyncStatus and the wallet reads are refused air-gapped
            // (docs/interface.md API §8); the screen says so instead.
            self.send(Event::Loaded);
            return Ok(true);
        }
        let sync = match c.get_sync_status(GetSyncStatusRequest::default()).await {
            Ok(r) => {
                let keys = r.into_inner().keys;
                self.send(Event::Sync(Ok(keys.clone())));
                keys
            }
            Err(s) => {
                self.send(Event::Sync(Err(CliError::from_status(s).message())));
                Vec::new()
            }
        };
        let fp = Fingerprint::of(&info, &sync);
        if force || fp.needs_reload(last.as_ref(), last_load.elapsed()) {
            for key in &info.keys {
                // A signer-only profile has no wallet database to read.
                if key.signing_mode() == SigningMode::SignerOnly {
                    continue;
                }
                let snap = load_wallet(c, &key.key_id).await;
                self.send(Event::Wallet(Box::new(snap)));
            }
            *last_load = Instant::now();
            *last = Some(fp);
        }
        self.send(Event::Loaded);
        Ok(false)
    }

    fn send(&self, ev: Event) {
        let _ = self.tx.send(ev);
    }
}

/// How the TUI learns that something changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventsMode {
    /// Not known yet.
    Unknown,
    /// `WatchEvents` (API 0.3): changes wake a reload as they happen.
    Streaming,
    /// Polling only, and why.
    Polling(String),
}

/// The `WatchEvents` stream, while it runs. Each event asks the poller for
/// a cycle now, so a payment shows (and toasts) as soon as the daemon sees
/// it instead of at the next tip change or sweep.
#[derive(Debug, Default)]
struct Watcher {
    task: Option<tokio::task::JoinHandle<()>>,
    /// The daemon answered `UNIMPLEMENTED` (older than API 0.3): do not ask
    /// again until it reconnects.
    unsupported: Arc<AtomicBool>,
}

impl Watcher {
    /// Start the stream unless it runs, or this daemon never serves it.
    fn ensure(&mut self, ctx: &Ctx, tx: &mpsc::UnboundedSender<Event>, refresh: &Arc<Notify>) {
        if self.unsupported.load(Ordering::Relaxed)
            || self.task.as_ref().is_some_and(|t| !t.is_finished())
        {
            return;
        }
        let (ctx, tx, refresh) = (ctx.clone(), tx.clone(), refresh.clone());
        // The task records whether this daemon serves `WatchEvents` at all.
        let unsupported = self.unsupported.clone();
        self.task = Some(tokio::spawn(async move {
            let (mode, never) = watch(&ctx, &tx, &refresh).await;
            unsupported.store(never, Ordering::Relaxed);
            let _ = tx.send(Event::Events(mode));
        }));
    }

    /// Stop the stream and forget what this daemon serves.
    fn reset(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
        self.unsupported.store(false, Ordering::Relaxed);
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.reset();
    }
}

/// Follow `WatchEvents` until it ends: what to fall back to and why, and
/// whether this daemon never serves it (so it is not asked again).
async fn watch(
    ctx: &Ctx,
    tx: &mpsc::UnboundedSender<Event>,
    refresh: &Notify,
) -> (EventsMode, bool) {
    let polling = |why: String| (EventsMode::Polling(why), false);
    let mut conn = match ctx.connect().await {
        Ok(c) => c,
        Err(e) => return polling(e.message()),
    };
    let mut stream = match conn
        .client
        .watch_events(WatchEventsRequest::default())
        .await
    {
        Ok(s) => s.into_inner(),
        Err(s) if s.code() == tonic::Code::Unimplemented => {
            return (
                EventsMode::Polling("the daemon is older than API 0.3".into()),
                true,
            );
        }
        Err(s) => return polling(CliError::from_status(s).message()),
    };
    let _ = tx.send(Event::Events(EventsMode::Streaming));
    loop {
        match stream.message().await {
            Ok(Some(_)) => refresh.notify_one(),
            Ok(None) => return polling("the event stream ended".into()),
            Err(s) => return polling(CliError::from_status(s).message()),
        }
    }
}

/// Balance, every note and the latest history of one key. Each read fails on
/// its own, so one refused RPC leaves the other panes filled.
pub async fn load_wallet(c: &mut GygesClient<Channel>, key_id: &str) -> WalletSnapshot {
    let balance = c
        .get_balance(GetBalanceRequest {
            key_id: key_id.to_string(),
            min_confirmations: 0,
        })
        .await
        .map(|r| r.into_inner())
        .map_err(|s| CliError::from_status(s).message());
    let notes = c
        .list_notes(ListNotesRequest {
            key_id: key_id.to_string(),
            pool: 0,
            spent: SpentFilter::All as i32,
        })
        .await
        .map(|r| r.into_inner().notes)
        .map_err(|s| CliError::from_status(s).message());
    let txs = c
        .list_transactions(ListTransactionsRequest {
            key_id: key_id.to_string(),
            limit: HISTORY_LIMIT,
            before_txid: String::new(),
        })
        .await
        .map(|r| r.into_inner().transactions)
        .map_err(|s| CliError::from_status(s).message());
    WalletSnapshot {
        key_id: key_id.to_string(),
        balance,
        notes,
        txs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::{KeySummary, NodeStatus, SyncState};

    fn info(tip: &str, keys: &[&str]) -> GetInfoResponse {
        GetInfoResponse {
            node: Some(NodeStatus {
                tip_hash: tip.into(),
                ..Default::default()
            }),
            keys: keys
                .iter()
                .map(|k| KeySummary {
                    key_id: (*k).into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    fn sync(key: &str, state: SyncState, scanned_tip: u32) -> KeySyncStatus {
        KeySyncStatus {
            key_id: key.into(),
            state: state as i32,
            scanned_tip,
            ..Default::default()
        }
    }

    #[test]
    fn reload_follows_the_tip_and_the_sync_state() {
        let short = Duration::from_secs(1);
        let a = Fingerprint::of(&info("aa", &["main"]), &[sync("main", SyncState::Idle, 10)]);
        assert!(a.needs_reload(None, short), "the first load always runs");
        assert!(!a.needs_reload(Some(&a), short), "nothing changed");
        assert!(a.needs_reload(Some(&a), SWEEP), "the slow sweep");

        let new_tip = Fingerprint::of(&info("bb", &["main"]), &[sync("main", SyncState::Idle, 10)]);
        assert!(new_tip.needs_reload(Some(&a), short));

        let new_key = Fingerprint::of(&info("aa", &["main", "b"]), &[]);
        assert!(new_key.needs_reload(Some(&a), short));

        let scanning = Fingerprint::of(
            &info("aa", &["main"]),
            &[sync("main", SyncState::Scanning, 10)],
        );
        assert!(scanning.needs_reload(Some(&a), short), "state moved");

        let scanned_more = Fingerprint::of(
            &info("aa", &["main"]),
            &[sync("main", SyncState::Scanning, 500)],
        );
        assert!(
            !scanned_more.needs_reload(Some(&scanning), short),
            "a moving scan is throttled"
        );
        assert!(scanned_more.needs_reload(Some(&scanning), SCAN_RELOAD));
    }
}
