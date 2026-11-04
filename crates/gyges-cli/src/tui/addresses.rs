//! Receiving: the Addresses tab, the QR modal and the new-address prompt.
//!
//! Addresses are not part of the poll: they are read on demand
//! (`GetCurrentAddress`) when the tab, the QR modal or a copy needs one, and
//! derived with `NewAddress`. There is no RPC that lists every address a key
//! has handed out, so the tab shows the current one and those derived in
//! this session.
//!
//! The QR code is drawn white on black whatever the terminal's colours, so
//! it scans the same on a light theme. A full unified address with three
//! receivers is a large code; when it does not fit, the Orchard-only form of
//! the same address (`GetCurrentAddress { pool: IRONWOOD }`, much shorter) is
//! shown instead, and if that does not fit either the modal says how large
//! the terminal must be.

use std::collections::{BTreeMap, BTreeSet};

use gyges_proto::v1::{AddressInfo, Pool, Receiver};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::balance::pool_name;

use super::app::App;
use super::ui::{bad, centered, dim, key_style, warn};

/// Which form of the current address is shown (`p` cycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddrView {
    /// The unified address with every receiver it has.
    Unified,
    /// A unified address holding only its Orchard receiver (paid into Ironwood).
    Ironwood,
    /// Its Sapling receiver as a `zs` address.
    Sapling,
    /// Its transparent receiver as a `t` address.
    Transparent,
}

impl AddrView {
    pub const ALL: [AddrView; 4] = [
        AddrView::Unified,
        AddrView::Ironwood,
        AddrView::Sapling,
        AddrView::Transparent,
    ];

    pub fn name(self) -> &'static str {
        match self {
            AddrView::Unified => "unified",
            AddrView::Ironwood => "ironwood only",
            AddrView::Sapling => "sapling",
            AddrView::Transparent => "transparent",
        }
    }

    /// `GetCurrentAddressRequest.pool`.
    pub fn pool(self) -> Pool {
        match self {
            AddrView::Unified => Pool::Unspecified,
            AddrView::Ironwood => Pool::Ironwood,
            AddrView::Sapling => Pool::Sapling,
            AddrView::Transparent => Pool::Transparent,
        }
    }

    pub fn next(self) -> AddrView {
        let i = AddrView::ALL.iter().position(|v| *v == self).unwrap_or(0);
        AddrView::ALL[(i + 1) % AddrView::ALL.len()]
    }
}

/// The addresses read so far, per key and view.
#[derive(Debug, Default)]
pub struct AddressBook {
    entries: BTreeMap<(String, AddrView), Result<AddressInfo, String>>,
    /// Requests in flight, so a key press does not send a second one.
    pending: BTreeSet<(String, AddrView)>,
    /// Addresses derived in this session, oldest first.
    made: BTreeMap<String, Vec<AddressInfo>>,
}

impl AddressBook {
    pub fn get(&self, key_id: &str, view: AddrView) -> Option<&Result<AddressInfo, String>> {
        self.entries.get(&(key_id.to_string(), view))
    }

    pub fn address(&self, key_id: &str, view: AddrView) -> Option<&str> {
        match self.get(key_id, view) {
            Some(Ok(a)) => Some(a.address.as_str()),
            _ => None,
        }
    }

    /// Whether a read should be sent: nothing is known and none is in flight.
    /// Marks it in flight when so.
    pub fn want(&mut self, key_id: &str, view: AddrView) -> bool {
        let k = (key_id.to_string(), view);
        if self.entries.contains_key(&k) || self.pending.contains(&k) {
            return false;
        }
        self.pending.insert(k);
        true
    }

    pub fn store(&mut self, key_id: &str, view: AddrView, r: Result<AddressInfo, String>) {
        let k = (key_id.to_string(), view);
        self.pending.remove(&k);
        self.entries.insert(k, r);
    }

    /// A new address became the current one: every cached view of the key
    /// is stale.
    pub fn made(&mut self, key_id: &str, info: AddressInfo) {
        self.entries.retain(|(k, _), _| k != key_id);
        self.pending.retain(|(k, _)| k != key_id);
        self.entries
            .insert((key_id.to_string(), AddrView::Unified), Ok(info.clone()));
        self.made.entry(key_id.to_string()).or_default().push(info);
    }

    pub fn made_by(&self, key_id: &str) -> &[AddressInfo] {
        self.made.get(key_id).map_or(&[], |v| v.as_slice())
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Forget everything (the daemon went away).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.pending.clear();
    }
}

/// The overlays the receive flow opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    /// The selected key's current address, large, as a QR code.
    Qr,
    /// The label prompt before `NewAddress`.
    NewAddress {
        label: String,
        busy: bool,
        error: Option<String>,
    },
}

/// A code as text lines, `Err` when it cannot be encoded.
pub fn qr_lines(address: &str) -> Result<Vec<String>, String> {
    gyges_qr::render_str(address)
        .map(|s| s.lines().map(str::to_string).collect())
        .map_err(|e| e.to_string())
}

/// (columns, rows) a code needs.
pub fn qr_size(lines: &[String]) -> (u16, u16) {
    let w = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    (w as u16, lines.len() as u16)
}

/// The code drawn white on black: blocks are the light modules.
fn qr_widget(lines: &[String]) -> Paragraph<'static> {
    let style = Style::new().fg(Color::White).bg(Color::Black);
    Paragraph::new(
        lines
            .iter()
            .map(|l| Line::styled(l.clone(), style))
            .collect::<Vec<_>>(),
    )
}

/// What the QR area shows for the selected key: the code of the chosen view
/// when it fits, else the Orchard-only form when it fits, else how much room
/// is needed.
pub enum QrChoice<'a> {
    Code {
        address: &'a str,
        lines: Vec<String>,
        fallback: bool,
    },
    TooSmall {
        need: (u16, u16),
    },
    Missing(String),
}

pub fn choose_qr<'a>(app: &'a App, key_id: &str, room: (u16, u16)) -> QrChoice<'a> {
    let view = app.addr_view;
    let primary = match app.book.get(key_id, view) {
        None => return QrChoice::Missing("loading the address…".into()),
        Some(Err(e)) => return QrChoice::Missing(e.clone()),
        Some(Ok(a)) => a.address.as_str(),
    };
    let fits = |lines: &[String]| {
        let (w, h) = qr_size(lines);
        w <= room.0 && h <= room.1
    };
    let lines = match qr_lines(primary) {
        Ok(l) => l,
        Err(e) => return QrChoice::Missing(e),
    };
    if fits(&lines) {
        return QrChoice::Code {
            address: primary,
            lines,
            fallback: false,
        };
    }
    let need = qr_size(&lines);
    if view == AddrView::Unified
        && let Some(short) = app.book.address(key_id, AddrView::Ironwood)
        && let Ok(short_lines) = qr_lines(short)
    {
        if fits(&short_lines) {
            return QrChoice::Code {
                address: short,
                lines: short_lines,
                fallback: true,
            };
        }
        return QrChoice::TooSmall {
            need: qr_size(&short_lines),
        };
    }
    QrChoice::TooSmall { need }
}

fn receiver_text(r: &Receiver) -> String {
    let pool = pool_name(r.pool());
    if r.encoded.is_empty() {
        pool.to_string()
    } else {
        format!("{pool} {}", r.encoded)
    }
}

/// Why the selected key has no address to show, when it has none.
fn no_address_reason(app: &App) -> Option<String> {
    let Some(k) = app.selected_key() else {
        return Some("No key selected.".into());
    };
    if app.airgapped() {
        return Some("Air-gapped daemon: addresses are not served.".into());
    }
    if k.signing_mode() == gyges_proto::v1::SigningMode::SignerOnly {
        return Some("signer-only profile: it has no wallet to receive into.".into());
    }
    None
}

pub fn draw_tab(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(format!(
        " Addresses · {} · p form · n new · r QR · c copy ",
        app.addr_view.name()
    ));
    if let Some(reason) = no_address_reason(app) {
        f.render_widget(
            Paragraph::new(Line::styled(reason, warn())).block(block),
            area,
        );
        return;
    }
    let Some(k) = app.selected_key() else { return };
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [text_area, qr_area] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Min(0)]).areas(inner);
    let mut lines = Vec::new();
    match app.book.get(&k.key_id, app.addr_view) {
        None => lines.push(Line::styled("loading the address…", dim())),
        Some(Err(e)) => lines.push(Line::styled(e.clone(), bad())),
        Some(Ok(a)) => {
            lines.push(Line::styled(
                format!("current address ({})", app.addr_view.name()),
                dim(),
            ));
            lines.push(Line::raw(a.address.clone()));
            lines.push(Line::default());
            for r in &a.receivers {
                lines.push(Line::from(vec![
                    Span::styled("receiver ", dim()),
                    Span::raw(receiver_text(r)),
                ]));
            }
            if !a.diversifier_index.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("index    ", dim()),
                    Span::raw(a.diversifier_index.clone()),
                ]));
            }
            if !a.label.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("label    ", dim()),
                    Span::raw(a.label.clone()),
                ]));
            }
        }
    }
    let made = app.book.made_by(&k.key_id);
    if !made.is_empty() {
        lines.push(Line::default());
        lines.push(Line::styled("derived in this session", dim()));
        for a in made.iter().rev() {
            let label = if a.label.is_empty() {
                String::new()
            } else {
                format!("  [{}]", a.label)
            };
            lines.push(Line::raw(format!("{}{label}", a.address)));
        }
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), text_area);
    draw_qr_area(f, qr_area, app, &k.key_id);
}

fn draw_qr_area(f: &mut Frame, area: Rect, app: &App, key_id: &str) {
    let room = (area.width, area.height.saturating_sub(1));
    match choose_qr(app, key_id, room) {
        QrChoice::Code {
            lines, fallback, ..
        } => {
            let (w, h) = qr_size(&lines);
            let x = area.x + (area.width.saturating_sub(w)) / 2;
            f.render_widget(
                qr_widget(&lines),
                Rect {
                    x,
                    y: area.y,
                    width: w,
                    height: h,
                },
            );
            if fallback && h < area.height {
                f.render_widget(
                    Paragraph::new(Line::styled(
                        "ironwood-only form; enlarge for the full address",
                        dim(),
                    ))
                    .centered(),
                    Rect {
                        y: area.y + h,
                        height: 1,
                        ..area
                    },
                );
            }
        }
        QrChoice::TooSmall { need } => f.render_widget(
            Paragraph::new(Line::styled(
                format!(
                    "The QR code needs {}x{}; press r for a larger view.",
                    need.0, need.1
                ),
                dim(),
            ))
            .wrap(Wrap { trim: true }),
            area,
        ),
        QrChoice::Missing(_) => {}
    }
}

/// The QR modal: the whole body, the code centred, the address under it.
pub fn draw_qr_modal(f: &mut Frame, area: Rect, app: &App) {
    f.render_widget(Clear, area);
    let block = Block::bordered()
        .title(format!(
            " Receive · {} · p form · c copy · Esc close ",
            app.addr_view.name()
        ))
        .border_style(key_style());
    let inner = block.inner(area);
    f.render_widget(block, area);
    let Some(k) = app.selected_key() else { return };
    if let Some(reason) = no_address_reason(app) {
        f.render_widget(Paragraph::new(Line::styled(reason, warn())), inner);
        return;
    }
    // Two lines under the code: the address and the note.
    let room = (inner.width, inner.height.saturating_sub(3));
    match choose_qr(app, &k.key_id, room) {
        QrChoice::Code {
            address,
            lines,
            fallback,
        } => {
            let (w, h) = qr_size(&lines);
            let x = inner.x + inner.width.saturating_sub(w) / 2;
            f.render_widget(
                qr_widget(&lines),
                Rect {
                    x,
                    y: inner.y,
                    width: w,
                    height: h,
                },
            );
            let mut under = vec![Line::raw(address.to_string()).centered()];
            if fallback {
                under.push(
                    Line::styled(
                        "The full unified address does not fit; this is its Orchard-only form (paid into Ironwood). Enlarge the terminal for the full one.",
                        warn(),
                    )
                    .centered(),
                );
            }
            f.render_widget(
                Paragraph::new(under).wrap(Wrap { trim: true }),
                Rect {
                    y: inner.y + h,
                    height: inner.height.saturating_sub(h),
                    ..inner
                },
            );
        }
        QrChoice::TooSmall { need } => {
            let text = vec![
                Line::styled(
                    format!(
                        "Enlarge the terminal to at least {}x{} to show the QR code.",
                        need.0 + 2,
                        need.1 + 5
                    ),
                    warn(),
                ),
                Line::default(),
                Line::raw(
                    app.book
                        .address(&k.key_id, app.addr_view)
                        .unwrap_or("")
                        .to_string(),
                ),
            ];
            f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), inner);
        }
        QrChoice::Missing(why) => {
            f.render_widget(Paragraph::new(Line::styled(why, dim())), inner);
        }
    }
}

/// The label prompt for `n`.
pub fn draw_new_modal(f: &mut Frame, area: Rect, label: &str, busy: bool, error: Option<&str>) {
    let rect = centered(area, 64, 8);
    f.render_widget(Clear, rect);
    let mut lines = vec![
        Line::raw("Derive a fresh diversified address (default receivers)."),
        Line::default(),
        Line::from(vec![
            Span::styled("label: ", dim()),
            Span::raw(label.to_string()),
            Span::styled(if busy { "" } else { "▏" }, key_style()),
        ]),
        Line::default(),
    ];
    if busy {
        lines.push(Line::styled("deriving…", dim()));
    } else if let Some(e) = error {
        lines.push(Line::styled(e.to_string(), bad()));
    } else {
        lines.push(Line::styled(
            "Enter derive · Esc cancel · label optional",
            dim(),
        ));
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::bordered()
                .title(" New address ")
                .border_style(key_style()),
        ),
        rect,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(addr: &str) -> AddressInfo {
        AddressInfo {
            address: addr.into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_book_asks_once_and_a_new_address_invalidates_the_key() {
        let mut b = AddressBook::default();
        assert!(b.want("main", AddrView::Unified));
        assert!(!b.want("main", AddrView::Unified), "in flight");
        b.store("main", AddrView::Unified, Ok(info("u1old")));
        assert!(!b.want("main", AddrView::Unified), "known");
        b.store("main", AddrView::Sapling, Ok(info("zs1old")));
        b.store("cold", AddrView::Unified, Ok(info("u1cold")));
        b.made("main", info("u1new"));
        assert_eq!(b.address("main", AddrView::Unified), Some("u1new"));
        assert!(
            b.get("main", AddrView::Sapling).is_none(),
            "stale view dropped"
        );
        assert_eq!(b.address("cold", AddrView::Unified), Some("u1cold"));
        assert_eq!(b.made_by("main").len(), 1);
    }

    #[test]
    fn views_cycle_and_map_to_pools() {
        assert_eq!(AddrView::Unified.next(), AddrView::Ironwood);
        assert_eq!(AddrView::Transparent.next(), AddrView::Unified);
        assert_eq!(AddrView::Sapling.pool(), Pool::Sapling);
        assert_eq!(AddrView::Unified.pool(), Pool::Unspecified);
    }

    use crate::tui::app::tests::{info_with, key, press};
    use crate::tui::app::{Action, Event};
    use crate::tui::ui::tests::render;
    use crossterm::event::KeyCode;
    use std::time::Duration;

    /// A unified address long enough to need a large code.
    fn long_ua() -> String {
        format!("uregtest1{}", "q".repeat(250))
    }

    fn receiving_app() -> App {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        app
    }

    fn answer(app: &mut App, view: AddrView, addr: &str) {
        app.on_event(Event::Address {
            key_id: "main".into(),
            view,
            result: Ok(info(addr)),
        });
    }

    #[test]
    fn r_opens_the_qr_and_loads_both_forms() {
        let mut app = receiving_app();
        press(&mut app, KeyCode::Char('r'));
        assert_eq!(app.modal, Some(Modal::Qr));
        assert_eq!(
            app.take_actions(),
            vec![
                Action::LoadAddress {
                    key_id: "main".into(),
                    view: AddrView::Unified
                },
                Action::LoadAddress {
                    key_id: "main".into(),
                    view: AddrView::Ironwood
                },
            ]
        );
        assert!(render(&app, 120, 40).contains("loading the address"));
        answer(&mut app, AddrView::Unified, "uregtest1short");
        let s = render(&app, 120, 40);
        assert!(s.contains("█"), "the code is drawn: {s}");
        assert!(s.contains("uregtest1short"), "{s}");
        press(&mut app, KeyCode::Esc);
        assert!(app.modal.is_none());
    }

    #[test]
    fn a_code_that_does_not_fit_falls_back_then_asks_for_room() {
        let mut app = receiving_app();
        press(&mut app, KeyCode::Char('r'));
        answer(&mut app, AddrView::Unified, &long_ua());
        answer(&mut app, AddrView::Ironwood, "uregtest1orchardonly");
        let s = render(&app, 100, 34);
        assert!(s.contains("uregtest1orchardonly"), "{s}");
        assert!(s.contains("Orchard-only form"), "{s}");
        // Big enough for the full code: no fallback.
        let s = render(&app, 160, 80);
        assert!(s.contains(&long_ua()[..40]), "{s}");
        assert!(!s.contains("Orchard-only form"), "{s}");
        // Too small for either.
        let s = render(&app, 40, 14);
        assert!(s.contains("Enlarge the terminal"), "{s}");
    }

    #[test]
    fn n_derives_with_a_label_and_shows_the_new_code() {
        let mut app = receiving_app();
        press(&mut app, KeyCode::Char('n'));
        for c in "shop".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        app.on_paste(" front\n");
        assert!(render(&app, 100, 30).contains("label: shop front"));
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            app.take_actions(),
            vec![Action::NewAddress {
                key_id: "main".into(),
                label: "shop front".into()
            }]
        );
        app.on_event(Event::AddressMade {
            key_id: "main".into(),
            result: Err("key 'main': not synced".into()),
        });
        assert!(
            render(&app, 100, 30).contains("not synced"),
            "the prompt shows why"
        );
        press(&mut app, KeyCode::Enter);
        app.take_actions();
        let mut made = info("uregtest1fresh");
        made.label = "shop front".into();
        app.on_event(Event::AddressMade {
            key_id: "main".into(),
            result: Ok(made),
        });
        assert_eq!(app.modal, Some(Modal::Qr), "a new address shows its code");
        assert_eq!(
            app.book.address("main", AddrView::Unified),
            Some("uregtest1fresh")
        );
        app.modal = None;
        press(&mut app, KeyCode::Char('4'));
        let s = render(&app, 160, 40);
        assert!(s.contains("derived in this session"), "{s}");
        assert!(s.contains("uregtest1fresh  [shop front]"), "{s}");
    }

    #[test]
    fn c_copies_now_or_once_loaded() {
        let mut app = receiving_app();
        press(&mut app, KeyCode::Char('c'));
        let acts = app.take_actions();
        assert!(
            matches!(acts.as_slice(), [Action::LoadAddress { .. }, ..]),
            "{acts:?}"
        );
        answer(&mut app, AddrView::Unified, "uregtest1copy");
        assert_eq!(
            app.take_actions(),
            vec![Action::Copy("uregtest1copy".into())]
        );
        press(&mut app, KeyCode::Char('c'));
        assert_eq!(
            app.take_actions(),
            vec![Action::Copy("uregtest1copy".into())]
        );
    }

    #[test]
    fn signer_only_and_air_gapped_keys_do_not_receive() {
        let mut app = App::new(Duration::from_secs(2));
        let mut k = key("signer", true);
        k.signing_mode = gyges_proto::v1::SigningMode::SignerOnly as i32;
        app.on_event(Event::Info(Box::new(info_with(vec![k]))));
        press(&mut app, KeyCode::Char('r'));
        assert!(app.modal.is_none() && app.take_actions().is_empty());
        press(&mut app, KeyCode::Char('4'));
        assert!(render(&app, 120, 20).contains("no wallet to receive into"));
    }

    #[test]
    fn a_long_address_makes_a_larger_code() {
        let short = qr_lines("uregtest1short").unwrap();
        let long = qr_lines(&"u".repeat(300)).unwrap();
        let (sw, sh) = qr_size(&short);
        let (lw, lh) = qr_size(&long);
        assert!(lw > sw && lh > sh);
        assert_eq!(sw, 29, "version 1 plus the quiet zone");
    }
}
