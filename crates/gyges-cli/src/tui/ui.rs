//! Drawing [`App`] with ratatui. Pure: the same state draws the same frame,
//! which is what the `TestBackend` tests below rely on.
//!
//! Layout: a two-line header (daemon, node, Tor, fallback), the wallet list
//! on the left, the tabbed main area on the right and the hotkey line at the
//! bottom. Overlays (help) are drawn last, over everything.

use gyges_proto::v1::{
    FallbackTrust, GetBalanceResponse, GetInfoResponse, KeySummary, KeySyncStatus, SigningMode,
    SyncState, TorState,
};
use gyges_proto::{API_MAJOR, API_MINOR};
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize as _};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Clear, List, ListItem, Paragraph, Row, Table, Tabs, Wrap};

use crate::amount::format_zec;
use crate::balance::pool_name;
use crate::key::mode_name;
use crate::output::format_unix;
use crate::sync::state_word;

use super::addresses::{self, Modal};
use super::app::{App, Daemon, Level, Tab};
use super::{endpoints, lists, logs};

/// Width of the wallet list.
const SIDEBAR: u16 = 30;

pub fn ok() -> Style {
    Style::new().fg(Color::Green)
}
pub fn warn() -> Style {
    Style::new().fg(Color::Yellow)
}
pub fn bad() -> Style {
    Style::new().fg(Color::Red)
}
pub fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}
pub fn key_style() -> Style {
    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
}

pub fn draw(f: &mut Frame, app: &App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(f.area());
    draw_header(f, header, app);
    match &app.daemon {
        Daemon::Connecting => draw_notice(f, body, "Connecting to gygesd…", dim()),
        Daemon::Down { error } => draw_down(f, body, error, app),
        Daemon::Up => {
            let [side, main] =
                Layout::horizontal([Constraint::Length(SIDEBAR), Constraint::Min(0)]).areas(body);
            draw_wallets(f, side, app);
            draw_main(f, main, app);
        }
    }
    draw_footer(f, footer, app);
    // Overlays are drawn whatever the poller last saw: keys go to an open
    // overlay, and a send runs on a connection of its own, so a missed poll
    // must not hide the field being typed into.
    match &app.modal {
        Some(Modal::Qr) => addresses::draw_qr_modal(f, body, app),
        Some(Modal::NewAddress { label, busy, error }) => {
            addresses::draw_new_modal(f, body, label, *busy, error.as_deref())
        }
        None => {}
    }
    if let Some(stage) = &app.send {
        super::send::draw(f, body, stage);
    }
    draw_toasts(f, body, app);
    if app.help {
        draw_help(f, f.area());
    }
}

/// Toasts stack in the body's top-right corner, newest at the bottom.
fn draw_toasts(f: &mut Frame, area: Rect, app: &App) {
    let mut y = area.y + 1;
    for t in &app.toasts {
        let width = (t.text.chars().count() as u16 + 4).min(area.width);
        if y + 3 > area.y + area.height {
            break;
        }
        let rect = Rect {
            x: area.x + area.width - width,
            y,
            width,
            height: 3,
        };
        let style = match t.level {
            Level::Good => ok().add_modifier(Modifier::BOLD),
            Level::Info => Style::new(),
            Level::Bad => bad(),
        };
        f.render_widget(Clear, rect);
        f.render_widget(
            Paragraph::new(Line::styled(t.text.clone(), style))
                .block(Block::bordered().border_style(style)),
            rect,
        );
        y += 3;
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

fn sep() -> Span<'static> {
    Span::styled(" │ ", dim())
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let Some(info) = &app.info else {
        let line = Line::from(vec![
            " gyges".bold(),
            sep(),
            Span::styled("no daemon", dim()),
        ]);
        f.render_widget(Paragraph::new(vec![line, Line::default()]), area);
        return;
    };
    f.render_widget(Paragraph::new(header_lines(info)), area);
}

pub fn header_lines(info: &GetInfoResponse) -> Vec<Line<'static>> {
    let api = info.api_version.unwrap_or_default();
    let mut first = vec![
        " gyges".bold(),
        sep(),
        Span::styled(info.network().name().to_string(), key_style()),
        sep(),
        Span::raw(format!(
            "gygesd {} · API {}.{}",
            info.daemon_version, api.major, api.minor
        )),
    ];
    if api.major == API_MAJOR && api.minor > API_MINOR {
        first.push(sep());
        first.push(Span::styled(
            format!("daemon API is newer than this gyges ({API_MAJOR}.{API_MINOR}); some panes may be incomplete"),
            warn(),
        ));
    }
    if info.airgapped {
        first.push(sep());
        first.push(Span::styled(
            "air-gapped",
            warn().add_modifier(Modifier::BOLD),
        ));
    }

    let mut second = vec![Span::raw(" ")];
    match &info.node {
        Some(n) if n.connected => {
            second.push(Span::raw(format!("tip {}", group(n.tip_height))));
            second.push(Span::styled(
                format!(" {}…", &n.tip_hash[..n.tip_hash.len().min(10)]),
                dim(),
            ));
            second.push(sep());
            second.push(Span::styled("node ● connected", ok()));
        }
        Some(n) if !info.airgapped => {
            second.push(Span::styled("node ✗ not connected", bad()));
            if !n.last_error.is_empty() {
                second.push(Span::styled(format!(" ({})", n.last_error), dim()));
            }
        }
        _ => second.push(Span::styled("node off", dim())),
    }
    second.push(sep());
    second.push(tor_span(info));
    second.push(sep());
    second.push(fallback_span(info));
    vec![Line::from(first), Line::from(second)]
}

fn tor_span(info: &GetInfoResponse) -> Span<'static> {
    let tor = info.tor.clone().unwrap_or_default();
    match tor.state() {
        TorState::Ready => Span::styled("Tor ● on", ok()),
        TorState::Bootstrapping => Span::styled(
            format!("Tor ◐ bootstrapping {}%", tor.bootstrap_percent),
            warn(),
        ),
        TorState::Failed => Span::styled(
            if tor.last_error.is_empty() {
                "Tor ✗ failed".to_string()
            } else {
                format!("Tor ✗ failed: {}", tor.last_error)
            },
            bad(),
        ),
        TorState::Disabled | TorState::Unspecified => Span::styled("Tor ○ off", dim()),
    }
}

fn fallback_span(info: &GetInfoResponse) -> Span<'static> {
    let fb = info.fallback.clone().unwrap_or_default();
    if !fb.enabled {
        return Span::styled("fallback off", dim());
    }
    let via = if fb.use_tor { " via Tor" } else { " direct" };
    match fb.trust() {
        FallbackTrust::Verified => Span::styled(format!("fallback ● verified{via}"), ok()),
        FallbackTrust::Untrusted => Span::styled(format!("fallback ✗ untrusted{via}"), bad()),
        FallbackTrust::Untested | FallbackTrust::Unspecified => {
            Span::styled(format!("fallback ○ untested{via}"), warn())
        }
    }
}

// ---------------------------------------------------------------------------
// Body
// ---------------------------------------------------------------------------

fn draw_notice(f: &mut Frame, area: Rect, text: &str, style: Style) {
    let p = Paragraph::new(Line::styled(text.to_string(), style))
        .alignment(Alignment::Center)
        .block(Block::bordered());
    f.render_widget(p, area);
}

fn draw_down(f: &mut Frame, area: Rect, error: &str, app: &App) {
    let text = vec![
        Line::default(),
        Line::styled(
            "gygesd is not reachable",
            bad().add_modifier(Modifier::BOLD),
        ),
        Line::default(),
        Line::raw(error.to_string()),
        Line::default(),
        Line::styled(
            format!(
                "Retrying every {}.",
                humantime::format_duration(app.interval)
            ),
            dim(),
        ),
    ];
    let p = Paragraph::new(text)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(Block::bordered());
    f.render_widget(p, area);
}

/// How far a key's scan has come, from its birthday to the chain tip.
pub fn sync_percent(k: &KeySummary, s: &KeySyncStatus) -> u32 {
    let start = k.birthday_height.saturating_sub(1);
    let span = s.chain_tip.saturating_sub(start);
    if span == 0 || s.scanned {
        return 100;
    }
    let done = s.scanned_tip.saturating_sub(start).min(span);
    ((u64::from(done) * 100) / u64::from(span)) as u32
}

fn lock_word(k: &KeySummary) -> Span<'static> {
    match k.signing_mode() {
        SigningMode::WatchOnly => Span::styled("view only", dim()),
        SigningMode::KeystoneQr => Span::styled("Keystone", dim()),
        _ if k.locked => Span::styled("locked", dim()),
        _ if k.unlock_expires_at > 0 => Span::styled("UNLOCKED", warn()),
        _ => Span::styled("UNLOCKED", warn()),
    }
}

fn draw_wallets(f: &mut Frame, area: Rect, app: &App) {
    let selected = app.selected.as_deref();
    let items: Vec<ListItem> = app
        .keys()
        .iter()
        .map(|k| {
            let is_sel = Some(k.key_id.as_str()) == selected;
            let mut first = vec![
                Span::raw(if is_sel { "▸ " } else { "  " }),
                Span::styled(k.key_id.clone(), Style::new().add_modifier(Modifier::BOLD)),
            ];
            if k.is_default {
                first.push(Span::styled(" ★", warn()));
            }
            let second = Line::from(vec![
                Span::raw("  "),
                Span::styled(mode_name(k.signing_mode()), dim()),
                Span::styled(" · ", dim()),
                lock_word(k),
            ]);
            let third = match (k.signing_mode(), app.sync_for(&k.key_id)) {
                (SigningMode::SignerOnly, _) => Line::styled("  no wallet (signer)", dim()),
                (_, Some(s)) => {
                    let word = state_word(s);
                    let style = match s.state() {
                        SyncState::Stalled => bad(),
                        SyncState::Idle if s.scanned => ok(),
                        _ => warn(),
                    };
                    let pct = if s.scanned {
                        String::new()
                    } else {
                        format!(" {}%", sync_percent(k, s))
                    };
                    Line::styled(format!("  {word}{pct}"), style)
                }
                (_, None) if app.airgapped() => Line::styled("  not syncing (air-gapped)", dim()),
                (_, None) => Line::styled("  …", dim()),
            };
            let item = ListItem::new(vec![Line::from(first), second, third]);
            if is_sel {
                item.style(Style::new().bg(Color::Indexed(236)))
            } else {
                item
            }
        })
        .collect();
    let block = Block::bordered().title(" Wallets ");
    if items.is_empty() {
        let p = Paragraph::new(vec![
            Line::styled("No keys yet.", dim()),
            Line::styled("Create one with", dim()),
            Line::raw("gyges key init --id main"),
        ])
        .wrap(Wrap { trim: true })
        .block(block);
        f.render_widget(p, area);
    } else {
        f.render_widget(List::new(items).block(block), area);
    }
}

fn draw_main(f: &mut Frame, area: Rect, app: &App) {
    let [tabs_area, content] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!("{} {}", i + 1, t.title())))
        .collect();
    let at = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
    f.render_widget(
        Tabs::new(titles)
            .select(at)
            .highlight_style(key_style().add_modifier(Modifier::REVERSED))
            .divider(Span::styled("│", dim())),
        tabs_area,
    );
    match app.tab {
        Tab::Overview => draw_overview(f, content, app),
        Tab::Notes => lists::draw_notes(f, content, app),
        Tab::Transactions => lists::draw_txs(f, content, app),
        Tab::Addresses => addresses::draw_tab(f, content, app),
        Tab::Endpoints => endpoints::draw(f, content, app),
        Tab::Logs => logs::draw(f, content, &app.logs),
    }
}

/// A reason the selected key has no wallet data to show, if there is one.
fn no_wallet_reason(app: &App, k: &KeySummary) -> Option<&'static str> {
    if app.airgapped() {
        Some(
            "Air-gapped daemon: balances, notes and history are not served. \
             Signing works through `gyges pczt`.",
        )
    } else if k.signing_mode() == SigningMode::SignerOnly {
        Some("signer-only profile: there is no wallet database to read.")
    } else {
        None
    }
}

fn draw_overview(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" Overview ");
    let Some(k) = app.selected_key() else {
        let p = Paragraph::new(Line::styled(
            "No key selected. Create one with `gyges key init --id main`.",
            dim(),
        ))
        .block(block);
        f.render_widget(p, area);
        return;
    };
    let inner = block.inner(area);
    f.render_widget(block, area);
    if let Some(reason) = no_wallet_reason(app, k) {
        let mut lines = key_lines(k, app);
        lines.push(Line::default());
        lines.push(Line::styled(reason, warn()));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
        return;
    }
    let balance_rows = match app.wallet_for(&k.key_id).map(|w| &w.balance) {
        Some(Ok(b)) => b.pools.len() as u16 + 2,
        _ => 1,
    };
    let [bal, notes, info] = Layout::vertical([
        Constraint::Length(balance_rows + 1),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .areas(inner);
    match app.wallet_for(&k.key_id).map(|w| &w.balance) {
        None => f.render_widget(Paragraph::new(Line::styled("loading balance…", dim())), bal),
        Some(Err(e)) => f.render_widget(
            Paragraph::new(Line::styled(format!("balance unavailable: {e}"), bad()))
                .wrap(Wrap { trim: true }),
            bal,
        ),
        Some(Ok(b)) => f.render_widget(balance_table(b), bal),
    }
    let mut under = Vec::new();
    if let Some(Ok(b)) = app.wallet_for(&k.key_id).map(|w| &w.balance) {
        under.push(Line::styled(
            format!(
                "spendable at {} confirmations, as of height {}",
                b.min_confirmations,
                group(b.as_of_height)
            ),
            dim(),
        ));
        if !b.not_spendable_reason.is_empty() {
            under.push(Line::styled(
                format!("can't send yet: {}", b.not_spendable_reason),
                warn(),
            ));
        }
    }
    f.render_widget(Paragraph::new(under).wrap(Wrap { trim: true }), notes);
    let mut lines = key_lines(k, app);
    if let Some(w) = app.wallet_for(&k.key_id) {
        lines.push(Line::from(vec![
            Span::styled("holdings ", dim()),
            Span::raw(holdings(w)),
        ]));
    }
    let recent: Vec<_> = app.visible_txs().iter().take(RECENT).collect();
    let key_rows = lines.len() as u16;
    let [key_area, recent_area] =
        Layout::vertical([Constraint::Length(key_rows + 1), Constraint::Min(0)]).areas(info);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), key_area);
    if !recent.is_empty() {
        let table = Table::new(recent.into_iter().map(lists::tx_row), lists::tx_widths())
            .header(lists::tx_header())
            .block(Block::new().title(Line::styled("recent (all in tab 3)", dim())));
        f.render_widget(table, recent_area);
    }
}

/// History rows the Overview shows.
const RECENT: usize = 3;

/// `3 unspent notes · 12 transactions`, or what failed.
fn holdings(w: &super::app::WalletSnapshot) -> String {
    let notes = match &w.notes {
        Ok(n) => {
            let unspent = n.iter().filter(|n| !n.spent).count();
            format!("{unspent} unspent notes")
        }
        Err(e) => format!("notes unavailable ({e})"),
    };
    let txs = match &w.txs {
        Ok(t) => format!("{} transactions", t.len()),
        Err(e) => format!("history unavailable ({e})"),
    };
    format!("{notes} · {txs}")
}

pub fn balance_table(b: &GetBalanceResponse) -> Table<'static> {
    let mut rows: Vec<Row> = b
        .pools
        .iter()
        .map(|p| {
            Row::new(vec![
                pool_name(p.pool()).to_string(),
                format_zec(p.spendable),
                format_zec(p.pending),
            ])
        })
        .collect();
    rows.push(
        Row::new(vec![
            "total".to_string(),
            format_zec(b.total_spendable),
            format_zec(b.total_pending),
        ])
        .style(Style::new().add_modifier(Modifier::BOLD)),
    );
    Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(18),
            Constraint::Length(18),
        ],
    )
    .header(Row::new(vec!["POOL", "SPENDABLE ZEC", "PENDING ZEC"]).style(dim()))
}

/// The selected key's mode, lock and sync lines.
fn key_lines(k: &KeySummary, app: &App) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let lock = match k.signing_mode() {
        SigningMode::WatchOnly => "watch-only: this key cannot sign".to_string(),
        SigningMode::KeystoneQr => "signs on the Keystone".to_string(),
        _ if k.locked => "locked (sends ask for the passphrase)".to_string(),
        _ if k.unlock_expires_at > 0 => {
            format!("UNLOCKED until {}", format_unix(k.unlock_expires_at))
        }
        _ => "UNLOCKED".to_string(),
    };
    lines.push(Line::from(vec![
        Span::styled("key      ", dim()),
        Span::raw(format!(
            "{} · {} · {lock}",
            k.key_id,
            mode_name(k.signing_mode())
        )),
    ]));
    if k.signing_mode() != SigningMode::SignerOnly {
        lines.push(Line::from(vec![
            Span::styled("pools    ", dim()),
            Span::raw(format!(
                "spends {} · receives {}",
                pool_list(&k.spend_pools),
                pool_list(&k.receive_pools)
            )),
        ]));
        lines.push(Line::from(vec![
            Span::styled("birthday ", dim()),
            Span::raw(group(k.birthday_height)),
        ]));
    }
    if let Some(s) = app.sync_for(&k.key_id) {
        let mut text = format!(
            "{} · scanned {} of {}",
            state_word(s),
            group(s.scanned_tip),
            group(s.chain_tip)
        );
        if s.blocks_remaining > 0 {
            text.push_str(&format!(" · {} blocks left", group(s.blocks_remaining)));
        }
        if s.blocks_per_sec > 0.0 {
            text.push_str(&format!(" · {:.0} blocks/s", s.blocks_per_sec));
        }
        if s.notes_awaiting_witness > 0 {
            text.push_str(&format!(
                " · {} notes awaiting witnesses",
                s.notes_awaiting_witness
            ));
        }
        let style = if s.state() == SyncState::Stalled {
            bad()
        } else {
            Style::new()
        };
        lines.push(Line::from(vec![
            Span::styled("sync     ", dim()),
            Span::styled(text, style),
        ]));
        // `detail` is the stall's reason; other states may carry a word too.
        if s.state() == SyncState::Stalled && !s.detail.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("         ", dim()),
                Span::styled(s.detail.clone(), bad()),
            ]));
        }
    } else if let Err(e) = &app.sync {
        lines.push(Line::styled(format!("sync status unavailable: {e}"), bad()));
    }
    lines
}

fn pool_list(pools: &[i32]) -> String {
    let names: Vec<&str> = pools
        .iter()
        .map(|p| pool_name(gyges_proto::v1::Pool::try_from(*p).unwrap_or_default()))
        .collect();
    if names.is_empty() {
        "-".into()
    } else {
        names.join(",")
    }
}

/// `1234567` as `1,234,567`.
pub fn group(n: u32) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// Footer and overlays
// ---------------------------------------------------------------------------

/// The hotkeys, as (key, what) pairs. The footer shows them and the help
/// overlay lists them with more words.
pub fn hotkeys(app: &App) -> Vec<(&'static str, &'static str)> {
    if app.send.is_some() {
        return vec![("Enter", "next"), ("Esc", "back / cancel")];
    }
    match &app.modal {
        Some(Modal::Qr) => return vec![("p", "form"), ("c", "copy"), ("Esc", "close")],
        Some(Modal::NewAddress { .. }) => return vec![("Enter", "derive"), ("Esc", "cancel")],
        None => {}
    }
    let mut keys = vec![("1-9", "tabs"), ("⇥", "next wallet")];
    match app.tab {
        Tab::Notes => keys.extend([("↑↓", "move"), ("f", "filter")]),
        Tab::Transactions => keys.push(("↑↓", "move")),
        Tab::Addresses => keys.push(("p", "form")),
        Tab::Logs => keys.extend([
            ("↑↓", "scroll"),
            ("End", "follow"),
            ("v", "level"),
            ("a", "audit"),
        ]),
        Tab::Overview | Tab::Endpoints => keys.push(("L", "logs")),
    }
    keys.extend([
        ("s", "send"),
        ("r", "receive"),
        ("n", "new address"),
        ("c", "copy"),
    ]);
    keys.extend([("R", "refresh"), ("?", "help"), ("q", "quit")]);
    keys
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![Span::raw(" ")];
    for (k, what) in hotkeys(app) {
        spans.push(Span::styled(k, key_style()));
        spans.push(Span::raw(format!(" {what}  ")));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A centred rectangle of at most `w` x `h` inside `area`.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

const HELP: &[(&str, &str)] = &[
    ("1-9", "switch tab"),
    ("Tab / Shift-Tab", "next / previous wallet"),
    ("↑↓ j k", "move in a list (PgUp, PgDn, Home, End)"),
    ("f", "Notes: unspent, spent or all"),
    ("s", "send: form, dry run, confirm, sign"),
    ("S", "shield transparent funds"),
    ("r", "receive: the current address as a QR code"),
    ("n", "derive a new address (with a label)"),
    ("c", "copy the current address (OSC 52)"),
    ("p", "Addresses: unified, ironwood, sapling, transparent"),
    ("L", "open the live logs (tab 6)"),
    ("v / a", "Logs: minimum level / daemon or audit log"),
    ("Esc", "dismiss notifications"),
    ("R", "poll the daemon now and reload every wallet"),
    ("?", "this help"),
    ("q, Ctrl-C", "quit"),
];

fn draw_help(f: &mut Frame, area: Rect) {
    let mut lines: Vec<Line> = HELP
        .iter()
        .map(|(k, what)| {
            Line::from(vec![
                Span::styled(format!("{k:>16}  "), key_style()),
                Span::raw(*what),
            ])
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::styled("any key closes this", dim()));
    let rect = centered(area, 64, lines.len() as u16 + 2);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(Text::from(lines)).block(Block::bordered().title(" Help ")),
        rect,
    );
}

/// A drawn buffer as plain text, one line per row with trailing spaces cut
/// (`--dump` and the tests).
pub fn buffer_text(buf: &Buffer) -> String {
    let w = buf.area.width as usize;
    let mut out = String::new();
    for row in buf.content.chunks(w.max(1)) {
        let mut line = String::new();
        for cell in row {
            line.push_str(cell.symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use super::*;
    use crate::tui::app::tests::{info_with, key};
    use crate::tui::app::{Event, WalletSnapshot};
    use gyges_proto::v1::{FallbackStatus, NodeStatus, Pool, PoolBalance, TorStatus};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    pub fn render(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        buffer_text(t.backend().buffer())
    }

    pub fn up_app() -> App {
        let mut app = App::new(Duration::from_secs(2));
        let mut info = info_with(vec![key("main", true), key("cold", false)]);
        info.node = Some(NodeStatus {
            connected: true,
            tip_height: 1_234_567,
            tip_hash: "00ab12cd34ef".into(),
            ..Default::default()
        });
        info.tor = Some(TorStatus {
            state: TorState::Ready as i32,
            ..Default::default()
        });
        info.fallback = Some(FallbackStatus {
            enabled: true,
            use_tor: true,
            trust: FallbackTrust::Verified as i32,
            ..Default::default()
        });
        app.on_event(Event::Info(Box::new(info)));
        app.on_event(Event::Sync(Ok(vec![KeySyncStatus {
            key_id: "main".into(),
            state: SyncState::Idle as i32,
            scanned: true,
            spendable: true,
            scanned_tip: 1_234_567,
            chain_tip: 1_234_567,
            ..Default::default()
        }])));
        app.on_event(Event::Wallet(Box::new(WalletSnapshot {
            key_id: "main".into(),
            balance: Ok(GetBalanceResponse {
                pools: vec![PoolBalance {
                    pool: Pool::Ironwood as i32,
                    spendable: 150_000_000,
                    pending: 2_500_000,
                    pending_spend: 0,
                }],
                total_spendable: 150_000_000,
                total_pending: 2_500_000,
                min_confirmations: 10,
                as_of_height: 1_234_567,
                not_spendable_reason: String::new(),
            }),
            notes: Ok(vec![]),
            txs: Ok(vec![]),
        })));
        app.on_event(Event::Loaded);
        app
    }

    #[test]
    fn the_overview_shows_tip_tor_wallets_and_balance() {
        let s = render(&up_app(), 120, 30);
        assert!(s.contains("regtest"), "{s}");
        assert!(s.contains("tip 1,234,567"), "{s}");
        assert!(s.contains("node ● connected"), "{s}");
        assert!(s.contains("Tor ● on"), "{s}");
        assert!(s.contains("fallback ● verified via Tor"), "{s}");
        assert!(s.contains("▸ main ★"), "{s}");
        assert!(s.contains("cold"), "{s}");
        assert!(s.contains("synced"), "{s}");
        assert!(s.contains("ironwood") && s.contains("1.50000000"), "{s}");
        assert!(s.contains("0.02500000"), "{s}");
        assert!(s.contains("as of height 1,234,567"), "{s}");
        assert!(s.contains("1 Overview"), "{s}");
        assert!(s.contains("? help"), "{s}");
    }

    #[test]
    fn a_down_daemon_says_how_to_start_it() {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Down {
            error: "gygesd is not running; start it with 'gyges daemon start'".into(),
        });
        let s = render(&app, 100, 20);
        assert!(s.contains("gygesd is not reachable"), "{s}");
        assert!(s.contains("Retrying every 2s"), "{s}");
    }

    #[test]
    fn panes_degrade_air_gapped_and_for_signer_only_keys() {
        let mut app = App::new(Duration::from_secs(2));
        let mut info = info_with(vec![key("offline", true)]);
        info.airgapped = true;
        app.on_event(Event::Info(Box::new(info)));
        let s = render(&app, 120, 24);
        assert!(s.contains("air-gapped"), "{s}");
        assert!(s.contains("not served"), "{s}");

        let mut app = App::new(Duration::from_secs(2));
        let mut signer = key("signer", true);
        signer.signing_mode = SigningMode::SignerOnly as i32;
        app.on_event(Event::Info(Box::new(info_with(vec![signer]))));
        let s = render(&app, 120, 24);
        assert!(s.contains("no wallet database"), "{s}");
    }

    #[test]
    fn a_failed_read_shows_in_its_pane_only() {
        let mut app = up_app();
        app.on_event(Event::Wallet(Box::new(WalletSnapshot {
            key_id: "main".into(),
            balance: Err("key 'main': not synced".into()),
            notes: Ok(vec![]),
            txs: Ok(vec![]),
        })));
        let s = render(&app, 120, 30);
        assert!(
            s.contains("balance unavailable: key 'main': not synced"),
            "{s}"
        );
        assert!(s.contains("tip 1,234,567"), "the header still draws: {s}");
    }

    #[test]
    fn help_lists_the_hotkeys() {
        let mut app = up_app();
        app.help = true;
        let s = render(&app, 120, 30);
        assert!(s.contains("next / previous wallet"), "{s}");
    }

    #[test]
    fn numbers_are_grouped_and_progress_is_a_percentage() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1000), "1,000");
        assert_eq!(group(1_234_567), "1,234,567");
        let k = KeySummary {
            birthday_height: 101,
            ..Default::default()
        };
        let s = KeySyncStatus {
            scanned_tip: 150,
            chain_tip: 200,
            ..Default::default()
        };
        assert_eq!(sync_percent(&k, &s), 50);
    }
}
