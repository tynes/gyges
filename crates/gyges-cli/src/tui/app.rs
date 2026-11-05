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
    AddressInfo, GetBalanceResponse, GetInfoResponse, InspectAddressResponse, KeySummary,
    KeySyncStatus, LogEntry, Note, SigningMode, TransactionSummary,
};

use crate::amount::format_zec;

use super::addresses::{AddrView, AddressBook, Modal};
use super::logs::{LogRequest, LogStatus, LogView};
use super::notify::{Notice, Seen};
use super::send::{Flow, SendReply, SendSpec, SendUpdate, Stage};

/// The longest label `n` accepts.
const MAX_LABEL: usize = 64;

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
    /// A `GetCurrentAddress` answer.
    Address {
        key_id: String,
        view: AddrView,
        result: Result<AddressInfo, String>,
    },
    /// A `NewAddress` answer.
    AddressMade {
        key_id: String,
        result: Result<AddressInfo, String>,
    },
    /// One `StreamLogs` entry of stream `generation`.
    Log {
        generation: u64,
        entry: Box<LogEntry>,
    },
    /// Stream `generation` ended; `error` unless it was asked to.
    LogsEnded {
        generation: u64,
        error: Option<String>,
    },
    /// Send `id` moved on.
    Send {
        id: u64,
        update: SendUpdate,
    },
    /// An `InspectAddress` answer for the send form.
    Inspected {
        address: String,
        result: Result<InspectAddressResponse, String>,
    },
    /// The camera's `(resolved, total)` fragments.
    #[cfg_attr(not(feature = "camera"), allow(dead_code))]
    ScanProgress((usize, usize)),
    /// The camera read the device's answer, or gave up.
    Scanned(Result<Vec<u8>, String>),
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
    /// `GetCurrentAddress` for one form of a key's current address.
    LoadAddress { key_id: String, view: AddrView },
    /// `NewAddress` with the profile's default receivers.
    NewAddress { key_id: String, label: String },
    /// Put text on the terminal's clipboard (OSC 52).
    Copy(String),
    /// Open a `StreamLogs` stream, closing any earlier one.
    StartLogs(LogRequest),
    /// Close the log stream.
    StopLogs,
    /// `InspectAddress` for the send form's recipient.
    Inspect(String),
    /// The dry run of send `id`, on a connection of its own.
    DryRun { id: u64, spec: SendSpec },
    /// The real request of send `id`, on a connection of its own.
    Execute { id: u64, spec: SendSpec },
    /// Answer the running send's signature request.
    Reply(SendReply),
    /// Read the Keystone's answer with the camera.
    ScanCamera {
        answer: &'static str,
        request: Vec<u8>,
    },
    /// Stop a camera scan.
    StopScan,
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
    Bad,
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
    Addresses,
    Endpoints,
    Logs,
}

impl Tab {
    pub const ALL: &'static [Tab] = &[
        Tab::Overview,
        Tab::Notes,
        Tab::Transactions,
        Tab::Addresses,
        Tab::Endpoints,
        Tab::Logs,
    ];

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
            Tab::Addresses => "Addresses",
            Tab::Endpoints => "Endpoints",
            Tab::Logs => "Logs",
        }
    }
}

#[derive(Debug)]
pub struct App {
    pub interval: Duration,
    /// The socket the TUI talks to, for the Endpoints tab.
    pub socket: String,
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
    /// The form of the current address shown (`p`).
    pub addr_view: AddrView,
    pub book: AddressBook,
    /// The Logs tab's stream and buffer.
    pub logs: LogView,
    /// The send / shield modal.
    pub send: Option<Stage>,
    /// The current send's number; answers for an older one are dropped.
    pub(super) send_id: u64,
    /// The receive overlays (QR, new-address prompt).
    pub modal: Option<Modal>,
    /// `c` pressed before the address was loaded: copy it when it arrives.
    copy_pending: Option<(String, AddrView)>,
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
            socket: String::new(),
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
            addr_view: AddrView::Unified,
            book: AddressBook::default(),
            logs: LogView::default(),
            send: None,
            send_id: 0,
            modal: None,
            copy_pending: None,
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

    pub(super) fn act(&mut self, a: Action) {
        self.actions.push(a);
    }

    /// `--dump` draws once this holds: the first cycle is done, or the
    /// daemon is known to be down.
    pub fn settled(&self) -> bool {
        // On the Logs tab, `--dump` streams without following and waits for
        // the replay to end.
        let logs_done = self.tab != Tab::Logs || matches!(self.logs.status, LogStatus::Ended(_));
        (self.loaded && !self.book.has_pending() && logs_done)
            || matches!(self.daemon, Daemon::Down { .. })
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
                self.book.clear();
            }
            Event::Info(info) => {
                self.daemon = Daemon::Up;
                self.info = Some(*info);
                self.fix_selection();
                if self.tab == Tab::Addresses || self.modal == Some(Modal::Qr) {
                    self.want_address();
                }
                // Open the log stream on first contact, and again after it
                // failed (the daemon went away and came back).
                if self.tab == Tab::Logs
                    && matches!(self.logs.status, LogStatus::Off | LogStatus::Ended(Some(_)))
                {
                    self.start_logs();
                }
            }
            Event::Log { generation, entry } => self.logs.push(generation, *entry),
            Event::LogsEnded { generation, error } => self.logs.ended(generation, error),
            Event::Send { id, update } => self.on_send_update(id, update),
            Event::Inspected { address, result } => self.on_inspected(address, result),
            Event::ScanProgress(p) => self.on_scan_progress(p),
            Event::Scanned(r) => self.on_scanned(r),
            Event::Address {
                key_id,
                view,
                result,
            } => {
                if let (Some((k, v)), Ok(info)) = (&self.copy_pending, &result)
                    && *k == key_id
                    && *v == view
                {
                    let text = info.address.clone();
                    self.copy_pending = None;
                    self.copy(text);
                }
                self.book.store(&key_id, view, result);
            }
            Event::AddressMade { key_id, result } => match result {
                Ok(info) => {
                    self.book.made(&key_id, info);
                    self.addr_view = AddrView::Unified;
                    self.toast(Level::Good, format!("new address for {key_id}"));
                    // A new address is for handing out: show its code.
                    self.modal = Some(Modal::Qr);
                    self.want_address();
                }
                Err(e) => {
                    if let Some(Modal::NewAddress { busy, error, .. }) = &mut self.modal {
                        *busy = false;
                        *error = Some(e);
                    } else {
                        self.toast(Level::Bad, e);
                    }
                }
            },
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

    /// Whether the selected key can hand out addresses here.
    fn can_receive(&self) -> Option<String> {
        let k = self.selected_key()?;
        (!self.airgapped() && k.signing_mode() != SigningMode::SignerOnly).then(|| k.key_id.clone())
    }

    /// Load the selected key's current address in the shown form, and the
    /// Orchard-only form the QR code falls back to, unless known.
    fn want_address(&mut self) {
        let Some(key_id) = self.can_receive() else {
            return;
        };
        let mut views = vec![self.addr_view];
        if self.addr_view == AddrView::Unified {
            views.push(AddrView::Ironwood);
        }
        for view in views {
            if self.book.want(&key_id, view) {
                self.act(Action::LoadAddress {
                    key_id: key_id.clone(),
                    view,
                });
            }
        }
    }

    fn copy(&mut self, text: String) {
        self.toast(
            Level::Info,
            "address copied to the clipboard (OSC 52; some terminals ask first)",
        );
        self.act(Action::Copy(text));
    }

    /// `c`: copy the shown address now, or once it has loaded.
    fn copy_address(&mut self) {
        let Some(key_id) = self.can_receive() else {
            return;
        };
        match self.book.address(&key_id, self.addr_view) {
            Some(a) => {
                let a = a.to_string();
                self.copy(a);
            }
            None => {
                self.copy_pending = Some((key_id, self.addr_view));
                self.want_address();
            }
        }
    }

    fn set_tab(&mut self, t: Tab) {
        let was = self.tab;
        self.tab = t;
        if t == Tab::Addresses {
            self.want_address();
        }
        // The log stream runs only while its tab is open.
        if was == Tab::Logs && t != Tab::Logs {
            self.logs.stop();
            self.act(Action::StopLogs);
        }
        if t == Tab::Logs && was != Tab::Logs && self.daemon == Daemon::Up {
            self.start_logs();
        }
    }

    fn start_logs(&mut self) {
        let req = self.logs.restart();
        self.act(Action::StartLogs(req));
    }

    /// Keys while a receive overlay is open.
    fn on_modal_key(&mut self, k: KeyEvent) {
        match self.modal.as_mut() {
            Some(Modal::Qr) => match k.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('r') => {
                    self.modal = None;
                }
                KeyCode::Char('c') => self.copy_address(),
                KeyCode::Char('p') => {
                    self.addr_view = self.addr_view.next();
                    self.want_address();
                }
                _ => {}
            },
            Some(Modal::NewAddress { label, busy, error }) => {
                if *busy {
                    return;
                }
                match k.code {
                    KeyCode::Esc => self.modal = None,
                    KeyCode::Enter => {
                        let label = label.trim().to_string();
                        *busy = true;
                        *error = None;
                        if let Some(key_id) = self.can_receive() {
                            self.act(Action::NewAddress { key_id, label });
                        }
                    }
                    KeyCode::Backspace => {
                        label.pop();
                    }
                    KeyCode::Char(c) if label.chars().count() < MAX_LABEL => label.push(c),
                    _ => {}
                }
            }
            None => {}
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
        if self.tab == Tab::Addresses {
            self.want_address();
        }
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
            // Up moves back in time: the scroll counts lines from the newest.
            Tab::Logs => return self.logs.scroll_by(delta.saturating_neg()),
            Tab::Overview | Tab::Addresses | Tab::Endpoints => return,
        };
        *cursor = (*cursor as isize).saturating_add(delta).max(0) as usize;
        self.clamp_cursors();
    }

    pub fn on_tick(&mut self, now: Instant) {
        self.now = now;
        self.toasts.retain(|t| t.until > now);
        self.on_send_tick(now);
    }

    pub fn on_paste(&mut self, text: &str) {
        if self.send.is_some() {
            return self.on_send_paste(text);
        }
        if let Some(Modal::NewAddress {
            label, busy: false, ..
        }) = &mut self.modal
        {
            for c in text.chars().filter(|c| !c.is_control()) {
                if label.chars().count() >= MAX_LABEL {
                    break;
                }
                label.push(c);
            }
        }
    }

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
        if self.send.is_some() {
            self.on_send_key(k);
            return;
        }
        if self.modal.is_some() {
            self.on_modal_key(k);
            return;
        }
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('s') => self.open_send(Flow::Send),
            KeyCode::Char('S') => self.open_send(Flow::Shield),
            KeyCode::Char('r') if self.can_receive().is_some() => {
                self.modal = Some(Modal::Qr);
                self.want_address();
            }
            KeyCode::Char('n') if self.can_receive().is_some() => {
                self.modal = Some(Modal::NewAddress {
                    label: String::new(),
                    busy: false,
                    error: None,
                });
            }
            KeyCode::Char('c') => self.copy_address(),
            KeyCode::Char('p') if self.tab == Tab::Addresses => {
                self.addr_view = self.addr_view.next();
                self.want_address();
            }
            KeyCode::Char('L') => self.set_tab(Tab::Logs),
            KeyCode::Char('v') if self.tab == Tab::Logs => {
                self.logs.next_level();
                self.start_logs();
            }
            KeyCode::Char('a') if self.tab == Tab::Logs => {
                self.logs.audit = !self.logs.audit;
                self.start_logs();
            }
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
                    self.set_tab(*t);
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
