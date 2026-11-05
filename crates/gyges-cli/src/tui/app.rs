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
}

impl Tab {
    pub const ALL: &'static [Tab] = &[Tab::Overview];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
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
                self.wallets.insert(w.key_id.clone(), *w);
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
    }

    pub fn on_tick(&mut self, now: Instant) {
        self.now = now;
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
}
