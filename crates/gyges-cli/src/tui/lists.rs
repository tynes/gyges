//! The Notes and Transactions tabs: a scrolling table of the selected key's
//! rows, and for history the selected transaction's outputs underneath.

use gyges_proto::v1::{TransactionStatus, TransactionSummary};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Row, Table, TableState, Wrap};

use crate::amount::format_zec;
use crate::balance::pool_name;
use crate::history::{memo_text, status_name};
use crate::output::format_unix;
use crate::tx::tex_state_name;

use super::app::App;
use super::ui::{bad, dim, group, ok, warn};

/// The selected row's highlight in both tables.
fn highlight() -> Style {
    Style::new().add_modifier(Modifier::REVERSED)
}

/// A pane that has nothing to list says why instead.
fn placeholder(f: &mut Frame, area: Rect, block: Block, text: String, style: Style) {
    f.render_widget(
        Paragraph::new(Line::styled(text, style))
            .wrap(Wrap { trim: true })
            .block(block),
        area,
    );
}

/// Why the selected key's `field` cannot be listed, when it cannot.
fn unavailable<T>(
    app: &App,
    field: impl Fn(&super::app::WalletSnapshot) -> &Result<T, String>,
) -> Option<(String, Style)> {
    let Some(k) = app.selected_key() else {
        return Some(("No key selected.".into(), dim()));
    };
    if app.airgapped() {
        return Some((
            "Air-gapped daemon: wallet reads are not served.".into(),
            warn(),
        ));
    }
    if k.signing_mode() == gyges_proto::v1::SigningMode::SignerOnly {
        return Some((
            "signer-only profile: there is no wallet database to read.".into(),
            warn(),
        ));
    }
    match app.wallet_for(&k.key_id).map(field) {
        None => Some(("loading…".into(), dim())),
        Some(Err(e)) => Some((format!("unavailable: {e}"), bad())),
        Some(Ok(_)) => None,
    }
}

pub fn draw_notes(f: &mut Frame, area: Rect, app: &App) {
    let notes = app.visible_notes();
    let total: i64 = notes.iter().map(|n| n.value).sum();
    let title = format!(
        " Notes · {} · {} · {} ZEC · f filter ",
        app.notes_filter.name(),
        notes.len(),
        format_zec(total)
    );
    let block = Block::bordered().title(title);
    if let Some((text, style)) = unavailable(app, |w| &w.notes) {
        return placeholder(f, area, block, text, style);
    }
    if notes.is_empty() {
        return placeholder(
            f,
            area,
            block,
            format!("No {} notes.", app.notes_filter.name()),
            dim(),
        );
    }
    let rows: Vec<Row> = notes
        .iter()
        .map(|n| {
            let state = if n.spent {
                Span::styled("spent", dim())
            } else if n.height == 0 {
                Span::styled("unmined", warn())
            } else if !n.witness_ready {
                Span::styled("no witness", warn())
            } else {
                Span::styled("unspent", ok())
            };
            let pool = if n.ephemeral {
                format!("{} (ephemeral)", pool_name(n.pool()))
            } else {
                pool_name(n.pool()).to_string()
            };
            Row::new(vec![
                Line::raw(pool),
                Line::raw(format_zec(n.value)).right_aligned(),
                Line::raw(if n.height == 0 {
                    "-".into()
                } else {
                    group(n.height)
                })
                .right_aligned(),
                Line::from(state),
                Line::raw(format!("{}:{}", short(&n.txid), n.output_index)),
                Line::raw(n.memo_preview.clone()),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(24),
            Constraint::Length(18),
            Constraint::Length(11),
            Constraint::Length(10),
            Constraint::Length(17),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec![
            "POOL",
            "VALUE ZEC",
            "HEIGHT",
            "STATE",
            "OUTPOINT",
            "MEMO",
        ])
        .style(dim()),
    )
    .row_highlight_style(highlight())
    .block(block);
    let mut state = TableState::default().with_selected(Some(app.notes_cursor));
    f.render_stateful_widget(table, area, &mut state);
}

/// `abcd1234…` from a txid.
pub fn short(txid: &str) -> String {
    format!("{}…", &txid[..txid.len().min(8)])
}

fn status_style(s: TransactionStatus) -> Style {
    match s {
        TransactionStatus::Mined => ok(),
        TransactionStatus::Pending
        | TransactionStatus::AwaitingSignature
        | TransactionStatus::TexPending => warn(),
        TransactionStatus::Expired | TransactionStatus::Failed => bad(),
        TransactionStatus::Unspecified => dim(),
    }
}

/// One history row: when, status, net value, fee, height, txid.
pub fn tx_row(t: &TransactionSummary) -> Row<'static> {
    let value_style = if t.net_value > 0 { ok() } else { Style::new() };
    let value = if t.net_value > 0 {
        format!("+{}", format_zec(t.net_value))
    } else {
        format_zec(t.net_value)
    };
    Row::new(vec![
        Line::raw(if t.timestamp == 0 {
            "-".to_string()
        } else {
            format_unix(t.timestamp)
        }),
        Line::styled(status_name(t.status()), status_style(t.status())),
        Line::styled(value, value_style).right_aligned(),
        Line::raw(format_zec(t.fee)).right_aligned(),
        Line::raw(if t.height == 0 {
            "-".into()
        } else {
            group(t.height)
        })
        .right_aligned(),
        Line::raw(short(&t.txid)),
    ])
}

pub fn tx_widths() -> [Constraint; 6] {
    [
        Constraint::Length(21),
        Constraint::Length(19),
        Constraint::Length(19),
        Constraint::Length(12),
        Constraint::Length(11),
        Constraint::Min(10),
    ]
}

pub fn tx_header() -> Row<'static> {
    Row::new(vec!["WHEN", "STATUS", "NET ZEC", "FEE", "HEIGHT", "TXID"]).style(dim())
}

pub fn draw_txs(f: &mut Frame, area: Rect, app: &App) {
    let txs = app.visible_txs();
    let block = Block::bordered().title(format!(" Transactions · latest {} ", txs.len()));
    if let Some((text, style)) = unavailable(app, |w| &w.txs) {
        return placeholder(f, area, block, text, style);
    }
    if txs.is_empty() {
        return placeholder(f, area, block, "No transactions yet.".into(), dim());
    }
    let [list, detail] =
        Layout::vertical([Constraint::Percentage(60), Constraint::Min(5)]).areas(area);
    let table = Table::new(txs.iter().map(tx_row), tx_widths())
        .header(tx_header())
        .row_highlight_style(highlight())
        .block(block);
    let mut state = TableState::default().with_selected(Some(app.tx_cursor));
    f.render_stateful_widget(table, list, &mut state);
    if let Some(t) = txs.get(app.tx_cursor) {
        f.render_widget(
            Paragraph::new(tx_detail(t))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title(" Details ")),
            detail,
        );
    }
}

/// The selected transaction: full txid, expiry, outputs with memos, ZIP 320
/// state and signing session.
pub fn tx_detail(t: &TransactionSummary) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::styled("txid    ", dim()),
        Span::raw(t.txid.clone()),
    ])];
    let mut facts = format!(
        "{} · fee {} ZEC",
        status_name(t.status()),
        format_zec(t.fee)
    );
    if t.expiry_height > 0 && t.status() != TransactionStatus::Mined {
        facts.push_str(&format!(" · expires at height {}", group(t.expiry_height)));
    }
    lines.push(Line::from(vec![
        Span::styled("status  ", dim()),
        Span::raw(facts),
    ]));
    for o in t.outputs.iter().filter(|o| !o.is_change) {
        let to = if o.is_ephemeral {
            "ephemeral".to_string()
        } else if o.address.is_empty() {
            "(this wallet)".to_string()
        } else {
            o.address.clone()
        };
        let mut s = format!("{} {} ZEC → {to}", pool_name(o.pool()), format_zec(o.value));
        if let Some(m) = memo_text(&o.memo) {
            s.push_str(&format!("  memo {m}"));
        }
        lines.push(Line::from(vec![
            Span::styled("output  ", dim()),
            Span::raw(s),
        ]));
    }
    if let Some(tex) = &t.tex {
        lines.push(Line::from(vec![
            Span::styled("tex     ", dim()),
            Span::raw(format!(
                "{} (step 1 {}, step 2 {})",
                tex_state_name(tex.state()),
                short(&tex.step1_txid),
                short(&tex.step2_txid)
            )),
        ]));
    }
    if !t.session_id.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("session ", dim()),
            Span::raw(t.session_id.clone()),
        ]));
    }
    lines
}

#[cfg(test)]
mod tests {
    use crate::tui::app::tests::{info_with, key, press, snapshot, tx};
    use crate::tui::app::{App, Event};
    use crate::tui::ui::tests::render;
    use crossterm::event::KeyCode;
    use gyges_proto::v1::{Note, Pool, TransactionOutput, TransactionStatus};
    use std::time::Duration;

    fn app_with_rows() -> App {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        let mut paid = tx(&"ab".repeat(32), 50_000_000, TransactionStatus::Mined);
        paid.height = 1_200;
        paid.outputs = vec![TransactionOutput {
            pool: Pool::Ironwood as i32,
            value: 50_000_000,
            memo: b"thanks!".to_vec(),
            ..Default::default()
        }];
        let sent = tx(&"cd".repeat(32), -10_010_000, TransactionStatus::Pending);
        app.on_event(Event::Wallet(Box::new(snapshot(
            "main",
            vec![
                Note {
                    pool: Pool::Ironwood as i32,
                    txid: "ab".repeat(32),
                    value: 50_000_000,
                    height: 1_200,
                    witness_ready: true,
                    memo_preview: "thanks!".into(),
                    ..Default::default()
                },
                Note {
                    pool: Pool::Transparent as i32,
                    txid: "ef".repeat(32),
                    value: 7,
                    spent: true,
                    ..Default::default()
                },
            ],
            vec![sent, paid],
        ))));
        app
    }

    #[test]
    fn the_notes_tab_lists_unspent_notes_and_filters() {
        let mut app = app_with_rows();
        press(&mut app, KeyCode::Char('2'));
        let s = render(&app, 140, 24);
        assert!(s.contains("Notes · unspent · 1 · 0.50000000 ZEC"), "{s}");
        assert!(
            s.contains("ironwood") && s.contains("1,200") && s.contains("thanks!"),
            "{s}"
        );
        assert!(!s.contains("transparent"), "spent notes are hidden: {s}");
        press(&mut app, KeyCode::Char('f'));
        let s = render(&app, 140, 24);
        assert!(s.contains("transparent") && s.contains("spent"), "{s}");
    }

    #[test]
    fn the_transactions_tab_shows_the_selected_outputs() {
        let mut app = app_with_rows();
        press(&mut app, KeyCode::Char('3'));
        let s = render(&app, 140, 30);
        assert!(s.contains("-0.10010000") && s.contains("pending"), "{s}");
        assert!(s.contains("+0.50000000") && s.contains("mined"), "{s}");
        assert!(
            s.contains(&"cd".repeat(32)),
            "details of the first row: {s}"
        );
        press(&mut app, KeyCode::Down);
        let s = render(&app, 140, 30);
        assert!(s.contains("memo \"thanks!\""), "{s}");
        assert!(s.contains("(this wallet)"), "{s}");
    }

    #[test]
    fn an_empty_or_failed_list_says_so() {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        let mut snap = snapshot("main", vec![], vec![]);
        snap.txs = Err("node unreachable".into());
        app.on_event(Event::Wallet(Box::new(snap)));
        press(&mut app, KeyCode::Char('2'));
        assert!(render(&app, 120, 20).contains("No unspent notes."));
        press(&mut app, KeyCode::Char('3'));
        assert!(render(&app, 120, 20).contains("unavailable: node unreachable"));
    }
}
