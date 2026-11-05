//! The TUI's state and the only code that changes it.
//!
//! [`App`] takes key presses ([`App::on_key`]) and daemon events
//! ([`App::on_event`]) and asks for side effects by queueing [`Action`]s,
//! which the event loop performs. Nothing here does I/O, so every behaviour
//! is unit-tested by feeding events in.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use gyges_proto::v1::{
    GetBalanceResponse, GetInfoResponse, KeySummary, KeySyncStatus, Note, TransactionSummary,
};

use crate::amount::format_zec;

use super::notify::{Notice, Seen};

/// How long a toast stays up.
pub const TOAST_FOR: Duration = Duration::from_secs(8);
/// At most this many toasts are kept; older ones go first.
const MAX_TOASTS: usize = 4;

/// What the poller (and later, other tasks) tell the state.
#[derive(Debug)]
pub enum Event {
    /// The daemon could not be reached, or the handshake failed.
    Down {
        error: String,
    },
    Info(Box<GetInfoResponse>),
    Sync(Result<Vec<KeySyncStatus>, String>),
    Wallet(Box<WalletSnapshot>),
    /// A poll cycle finished.
    Loaded,
}

/// One key's wallet reads. Each one fails on its own.
#[derive(Debug, Clone)]
pub struct WalletSnapshot {
    pub key_id: String,
    pub balance: Result<GetBalanceResponse, String>,
    pub notes: Result<Vec<Note>, String>,
    pub txs: Result<Vec<TransactionSummary>, String>,
}

/// Side effects the state asks the event loop for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Poll now and reload every wallet.
    Refresh,
    /// Ring the terminal bell (value arrived).
    Bell,
}

/// A short message in the top-right corner that goes away by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    pub text: String,
    pub level: Level,
    pub until: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Good,
    Info,
}

/// Which notes the Notes tab lists (`f` cycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotesFilter {
    Unspent,
    Spent,
    All,
}

impl NotesFilter {
    pub fn name(self) -> &'static str {
        match self {
            NotesFilter::Unspent => "unspent",
            NotesFilter::Spent => "spent",
            NotesFilter::All => "all",
        }
    }

    fn next(self) -> Self {
        match self {
            NotesFilter::Unspent => NotesFilter::Spent,
            NotesFilter::Spent => NotesFilter::All,
            NotesFilter::All => NotesFilter::Unspent,
        }
    }

    pub fn keeps(self, n: &Note) -> bool {
        match self {
            NotesFilter::Unspent => !n.spent,
            NotesFilter::Spent => n.spent,
            NotesFilter::All => true,
        }
    }
}

/// Whether the daemon answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Daemon {
    Connecting,
    Down { error: String },
    Up,
}

/// The main area's tabs, in hotkey order (`1`, `2`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Notes,
    Transactions,
}

impl Tab {
    pub const ALL: &'static [Tab] = &[Tab::Overview, Tab::Notes, Tab::Transactions];

    /// `--tab`: the title, any case.
    pub fn from_name(s: &str) -> Option<Tab> {
        Tab::ALL
            .iter()
            .copied()
            .find(|t| t.title().eq_ignore_ascii_case(s))
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Notes => "Notes",
            Tab::Transactions => "Transactions",
        }
    }
}

#[derive(Debug)]
pub struct App {
    pub interval: Duration,
    pub daemon: Daemon,
    pub info: Option<GetInfoResponse>,
    pub sync: Result<Vec<KeySyncStatus>, String>,
    pub wallets: BTreeMap<String, WalletSnapshot>,
    /// The selected key, by id, so it survives keys being added.
    pub selected: Option<String>,
    pub tab: Tab,
    pub help: bool,
    pub notes_filter: NotesFilter,
    /// Row selected in the Notes tab, within the filtered list.
    pub notes_cursor: usize,
    /// Row selected in the Transactions tab.
    pub tx_cursor: usize,
    /// Newest last.
    pub toasts: Vec<Toast>,
    seen: Seen,
    /// At least one poll cycle finished.
    pub loaded: bool,
    pub quit: bool,
    pub now: Instant,
    actions: Vec<Action>,
}

impl App {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            daemon: Daemon::Connecting,
            info: None,
            sync: Ok(Vec::new()),
            wallets: BTreeMap::new(),
            selected: None,
            tab: Tab::Overview,
            help: false,
            notes_filter: NotesFilter::Unspent,
            notes_cursor: 0,
            tx_cursor: 0,
            toasts: Vec::new(),
            seen: Seen::default(),
            loaded: false,
            quit: false,
            now: Instant::now(),
            actions: Vec::new(),
        }
    }

    /// The actions queued since the last call.
    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    fn act(&mut self, a: Action) {
        self.actions.push(a);
    }

    /// `--dump` draws once this holds: the first cycle is done, or the
    /// daemon is known to be down.
    pub fn settled(&self) -> bool {
        self.loaded || matches!(self.daemon, Daemon::Down { .. })
    }

    pub fn keys(&self) -> &[KeySummary] {
        self.info.as_ref().map_or(&[], |i| i.keys.as_slice())
    }

    pub fn selected_key(&self) -> Option<&KeySummary> {
        let id = self.selected.as_deref()?;
        self.keys().iter().find(|k| k.key_id == id)
    }

    pub fn sync_for(&self, key_id: &str) -> Option<&KeySyncStatus> {
        self.sync.as_ref().ok()?.iter().find(|s| s.key_id == key_id)
    }

    pub fn wallet_for(&self, key_id: &str) -> Option<&WalletSnapshot> {
        self.wallets.get(key_id)
    }

    pub fn airgapped(&self) -> bool {
        self.info.as_ref().is_some_and(|i| i.airgapped)
    }

    /// The selected key's notes under the current filter, oldest first.
    pub fn visible_notes(&self) -> Vec<&Note> {
        let Some(k) = self.selected.as_deref() else {
            return Vec::new();
        };
        match self.wallets.get(k).map(|w| &w.notes) {
            Some(Ok(notes)) => notes
                .iter()
                .filter(|n| self.notes_filter.keeps(n))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The selected key's history, newest first.
    pub fn visible_txs(&self) -> &[TransactionSummary] {
        let Some(k) = self.selected.as_deref() else {
            return &[];
        };
        match self.wallets.get(k).map(|w| &w.txs) {
            Some(Ok(txs)) => txs,
            _ => &[],
        }
    }

    pub fn toast(&mut self, level: Level, text: impl Into<String>) {
        self.toasts.push(Toast {
            text: text.into(),
            level,
            until: self.now + TOAST_FOR,
        });
        if self.toasts.len() > MAX_TOASTS {
            self.toasts.remove(0);
        }
    }

    fn announce(&mut self, n: &Notice) {
        let text = match n {
            Notice::Received {
                key_id,
                value,
                mined,
                ..
            } => format!(
                "+{} ZEC received by {key_id} ({})",
                format_zec(*value),
                if *mined { "mined" } else { "pending" }
            ),
            Notice::Mined {
                key_id,
                value,
                height,
                ..
            } if *value > 0 => format!(
                "{} ZEC received by {key_id} confirmed at height {height}",
                format_zec(*value)
            ),
            Notice::Mined {
                key_id,
                value,
                height,
                ..
            } => format!(
                "{} ZEC sent from {key_id} mined at height {height}",
                format_zec(value.saturating_neg())
            ),
        };
        let level = if n.rings() { Level::Good } else { Level::Info };
        self.toast(level, text);
    }

    pub fn on_event(&mut self, ev: Event) {
        match ev {
            Event::Down { error } => {
                self.daemon = Daemon::Down { error };
                self.info = None;
                self.sync = Ok(Vec::new());
                self.wallets.clear();
            }
            Event::Info(info) => {
                self.daemon = Daemon::Up;
                self.info = Some(*info);
                self.fix_selection();
            }
            Event::Sync(s) => self.sync = s,
            Event::Wallet(w) => {
                if let Ok(txs) = &w.txs {
                    let notices = self.seen.diff(&w.key_id, txs);
                    if notices.iter().any(Notice::rings) {
                        self.act(Action::Bell);
                    }
                    for n in &notices {
                        self.announce(n);
                    }
                }
                self.wallets.insert(w.key_id.clone(), *w);
                self.clamp_cursors();
            }
            Event::Loaded => self.loaded = true,
        }
    }

    /// Keep the selection on an existing key: the daemon's default first,
    /// then the first key.
    fn fix_selection(&mut self) {
        let keys = self.keys();
        if self
            .selected
            .as_deref()
            .is_some_and(|id| keys.iter().any(|k| k.key_id == id))
        {
            return;
        }
        let pick = keys
            .iter()
            .find(|k| k.is_default)
            .or_else(|| keys.first())
            .map(|k| k.key_id.clone());
        self.selected = pick;
    }

    fn move_selection(&mut self, delta: isize) {
        let keys = self.keys();
        if keys.is_empty() {
            return;
        }
        let at = self
            .selected
            .as_deref()
            .and_then(|id| keys.iter().position(|k| k.key_id == id))
            .unwrap_or(0);
        let n = keys.len() as isize;
        let next = (at as isize + delta).rem_euclid(n) as usize;
        self.selected = Some(keys[next].key_id.clone());
        self.notes_cursor = 0;
        self.tx_cursor = 0;
    }

    fn clamp_cursors(&mut self) {
        let notes = self.visible_notes().len();
        let txs = self.visible_txs().len();
        self.notes_cursor = self.notes_cursor.min(notes.saturating_sub(1));
        self.tx_cursor = self.tx_cursor.min(txs.saturating_sub(1));
    }

    /// Move the current tab's row cursor by `delta` (clamped).
    fn move_cursor(&mut self, delta: isize) {
        let cursor = match self.tab {
            Tab::Notes => &mut self.notes_cursor,
            Tab::Transactions => &mut self.tx_cursor,
            Tab::Overview => return,
        };
        *cursor = (*cursor as isize).saturating_add(delta).max(0) as usize;
        self.clamp_cursors();
    }

    pub fn on_tick(&mut self, now: Instant) {
        self.now = now;
        self.toasts.retain(|t| t.until > now);
    }

    pub fn on_paste(&mut self, _text: &str) {}

    pub fn on_key(&mut self, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(k.code, KeyCode::Char('c')) {
            self.quit = true;
            return;
        }
        if self.help {
            // Any key closes the help overlay; `q` still quits.
            self.help = false;
            if k.code == KeyCode::Char('q') {
                self.quit = true;
            }
            return;
        }
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Tab => self.move_selection(1),
            KeyCode::BackTab => self.move_selection(-1),
            KeyCode::Char('R') => self.act(Action::Refresh),
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::PageUp => self.move_cursor(-10),
            KeyCode::PageDown => self.move_cursor(10),
            KeyCode::Home => self.move_cursor(isize::MIN),
            KeyCode::End => self.move_cursor(isize::MAX),
            KeyCode::Char('f') if self.tab == Tab::Notes => {
                self.notes_filter = self.notes_filter.next();
                self.notes_cursor = 0;
            }
            KeyCode::Esc => self.toasts.clear(),
            KeyCode::Char(c @ '1'..='9') => {
                let i = (c as usize) - ('1' as usize);
                if let Some(t) = Tab::ALL.get(i) {
                    self.tab = *t;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use gyges_proto::v1::{Network, SigningMode, SyncState};

    pub fn key(id: &str, default: bool) -> KeySummary {
        KeySummary {
            key_id: id.into(),
            is_default: default,
            signing_mode: SigningMode::LocalSeed as i32,
            locked: true,
            ..Default::default()
        }
    }

    pub fn info_with(keys: Vec<KeySummary>) -> GetInfoResponse {
        GetInfoResponse {
            network: Network::Regtest as i32,
            daemon_version: "0.1.0".into(),
            keys,
            ..Default::default()
        }
    }

    pub fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn selection_starts_on_the_default_key_and_cycles() {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info_with(vec![
            key("a", false),
            key("main", true),
            key("z", false),
        ]))));
        assert_eq!(app.selected.as_deref(), Some("main"));
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.selected.as_deref(), Some("z"));
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.selected.as_deref(), Some("a"), "wraps around");
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.selected.as_deref(), Some("z"));

        // The selection survives a reload, and moves when its key goes away.
        app.on_event(Event::Info(Box::new(info_with(vec![
            key("main", true),
            key("z", false),
        ]))));
        assert_eq!(app.selected.as_deref(), Some("z"));
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        assert_eq!(app.selected.as_deref(), Some("main"));
    }

    #[test]
    fn a_down_daemon_clears_its_data_and_settles_a_dump() {
        let mut app = App::new(Duration::from_secs(2));
        assert!(!app.settled());
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        app.on_event(Event::Sync(Ok(vec![KeySyncStatus {
            key_id: "main".into(),
            state: SyncState::Idle as i32,
            ..Default::default()
        }])));
        assert!(app.sync_for("main").is_some());
        app.on_event(Event::Down {
            error: "gygesd is not running".into(),
        });
        assert!(app.settled());
        assert!(app.info.is_none() && app.sync_for("main").is_none());
    }

    #[test]
    fn keys_quit_help_and_refresh() {
        let mut app = App::new(Duration::from_secs(2));
        press(&mut app, KeyCode::Char('?'));
        assert!(app.help);
        press(&mut app, KeyCode::Char('x'));
        assert!(!app.help && !app.quit, "any key closes help");
        press(&mut app, KeyCode::Char('R'));
        assert_eq!(app.take_actions(), vec![Action::Refresh]);
        assert!(app.take_actions().is_empty());
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.quit);
    }

    pub fn snapshot(
        key_id: &str,
        notes: Vec<Note>,
        txs: Vec<TransactionSummary>,
    ) -> WalletSnapshot {
        WalletSnapshot {
            key_id: key_id.into(),
            balance: Ok(GetBalanceResponse::default()),
            notes: Ok(notes),
            txs: Ok(txs),
        }
    }

    pub fn tx(txid: &str, value: i64, status: TransactionStatus) -> TransactionSummary {
        TransactionSummary {
            txid: txid.into(),
            net_value: value,
            status: status as i32,
            ..Default::default()
        }
    }

    use gyges_proto::v1::TransactionStatus;

    #[test]
    fn a_receipt_after_the_first_load_toasts_and_rings_then_expires() {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        let old = tx("old", 1_000, TransactionStatus::Mined);
        app.on_event(Event::Wallet(Box::new(snapshot(
            "main",
            vec![],
            vec![old.clone()],
        ))));
        assert!(app.toasts.is_empty(), "history is not announced");
        assert!(app.take_actions().is_empty());

        let new = tx("new", 50_000_000, TransactionStatus::Pending);
        app.on_event(Event::Wallet(Box::new(snapshot(
            "main",
            vec![],
            vec![new.clone(), old.clone()],
        ))));
        assert_eq!(app.take_actions(), vec![Action::Bell]);
        assert_eq!(app.toasts.len(), 1);
        assert_eq!(
            app.toasts[0].text,
            "+0.50000000 ZEC received by main (pending)"
        );

        // Mined later: a quieter toast, no bell.
        let mut mined = new;
        mined.status = TransactionStatus::Mined as i32;
        mined.height = 77;
        app.on_event(Event::Wallet(Box::new(snapshot(
            "main",
            vec![],
            vec![mined, old],
        ))));
        assert!(app.take_actions().is_empty());
        assert_eq!(
            app.toasts[1].text,
            "0.50000000 ZEC received by main confirmed at height 77"
        );
        assert_eq!(app.toasts[1].level, Level::Info);

        let later = app.now + TOAST_FOR + Duration::from_secs(1);
        app.on_tick(later);
        assert!(app.toasts.is_empty());
    }

    #[test]
    fn the_notes_filter_and_cursor() {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        let note = |v: i64, spent: bool| Note {
            value: v,
            spent,
            ..Default::default()
        };
        app.on_event(Event::Wallet(Box::new(snapshot(
            "main",
            vec![note(1, false), note(2, true), note(3, false)],
            vec![],
        ))));
        press(&mut app, KeyCode::Char('2'));
        assert_eq!(app.tab, Tab::Notes);
        assert_eq!(app.visible_notes().len(), 2, "unspent by default");
        press(&mut app, KeyCode::End);
        assert_eq!(app.notes_cursor, 1, "clamped to the last row");
        press(&mut app, KeyCode::Char('f'));
        assert_eq!(app.notes_filter, NotesFilter::Spent);
        assert_eq!(app.visible_notes().len(), 1);
        assert_eq!(app.notes_cursor, 0);
        press(&mut app, KeyCode::Char('f'));
        assert_eq!(app.visible_notes().len(), 3);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.notes_cursor, 2);
        press(&mut app, KeyCode::Home);
        assert_eq!(app.notes_cursor, 0);
    }
}
