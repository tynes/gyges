//! The Endpoints tab: everything the daemon is attached to, from `GetInfo`.
//!
//! The TUI reads no `config.toml` (Q-C1), so the URLs come from the API:
//! `NodeStatus.rpc_url` / `indexer_url` and `FallbackStatus` (API 0.2). The
//! daemon removes any userinfo from them. A daemon older than 0.2 sends no
//! node URLs, and the tab says so rather than showing blanks.

use gyges_proto::v1::{FallbackTrust, GetInfoResponse, TorState};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Row, Table, Wrap};

use super::app::App;
use super::poll::EventsMode;
use super::ui::{bad, dim, group, ok, warn};

/// The first API minor that reports node URLs.
const URLS_SINCE_MINOR: u32 = 2;

fn cell(text: impl Into<String>, style: Style) -> Line<'static> {
    Line::styled(text.into(), style)
}

/// (endpoint, address, state) rows.
pub fn rows(info: &GetInfoResponse, socket: &str) -> Vec<[Line<'static>; 3]> {
    let api_minor = info.api_version.unwrap_or_default().minor;
    let old = api_minor < URLS_SINCE_MINOR;
    let unknown = || cell("(not reported by this daemon's API)", dim());
    let mut out = Vec::new();

    out.push([
        cell("daemon socket", Style::new()),
        cell(socket, Style::new()),
        cell(
            format!(
                "gygesd {} on {}",
                info.daemon_version,
                info.network().name()
            ),
            ok(),
        ),
    ]);

    let node = info.node.clone().unwrap_or_default();
    let node_state = if info.airgapped {
        cell("off: air-gapped", dim())
    } else if node.connected {
        let mut s = format!("connected · tip {}", group(node.tip_height));
        if node.pruned {
            s.push_str(&format!(
                " · pruned, holds from {}",
                group(node.retained_from)
            ));
        }
        cell(s, ok())
    } else {
        cell(format!("not connected: {}", node.last_error), bad())
    };
    out.push([
        cell("node JSON-RPC", Style::new()),
        if info.airgapped {
            cell("-", dim())
        } else if old {
            unknown()
        } else {
            cell(node.rpc_url.clone(), Style::new())
        },
        node_state,
    ]);

    out.push([
        cell("node indexer gRPC", Style::new()),
        if info.airgapped {
            cell("-", dim())
        } else if old {
            unknown()
        } else if node.indexer_url.is_empty() {
            cell("not configured", dim())
        } else {
            cell(node.indexer_url.clone(), Style::new())
        },
        if node.indexer_stream {
            cell("streaming", ok())
        } else {
            cell("not in use: polling JSON-RPC", dim())
        },
    ]);

    let fb = info.fallback.clone().unwrap_or_default();
    let fb_route = if fb.use_tor { "over Tor" } else { "direct" };
    out.push([
        cell("archival fallback", Style::new()),
        if fb.grpc_url.is_empty() {
            cell("not configured", dim())
        } else {
            cell(fb.grpc_url.clone(), Style::new())
        },
        if !fb.enabled {
            cell("disabled", dim())
        } else {
            match fb.trust() {
                FallbackTrust::Verified => cell(format!("verified · {fb_route}"), ok()),
                FallbackTrust::Untrusted => cell(
                    format!("untrusted: handoff check failed · {fb_route}"),
                    bad(),
                ),
                _ => cell(format!("untested · {fb_route}"), warn()),
            }
        },
    ]);

    out.push([
        cell("broadcasts", Style::new()),
        if fb.broadcast_via_tor {
            cell("the archival fallback, over Tor", Style::new())
        } else {
            cell("the node", Style::new())
        },
        if old {
            cell("(a daemon before API 0.2 does not say)", dim())
        } else if fb.broadcast_via_tor {
            cell("broadcast_via_tor = true", ok())
        } else {
            cell("`--via-tor` per send", dim())
        },
    ]);

    let tor = info.tor.clone().unwrap_or_default();
    out.push([
        cell("Tor", Style::new()),
        cell("embedded arti client", dim()),
        match tor.state() {
            TorState::Ready => cell("on", ok()),
            TorState::Bootstrapping => {
                cell(format!("bootstrapping {}%", tor.bootstrap_percent), warn())
            }
            TorState::Failed => cell(format!("failed: {}", tor.last_error), bad()),
            _ => cell("off", dim()),
        },
    ]);
    out
}

/// How changes reach the TUI: the `WatchEvents` stream, or polling.
pub fn events_row(mode: &EventsMode) -> [Line<'static>; 3] {
    [
        cell("wallet events", Style::new()),
        cell("WatchEvents on the daemon socket", dim()),
        match mode {
            EventsMode::Streaming => cell("streaming: changes show at once", ok()),
            EventsMode::Polling(why) => cell(format!("polling only: {why}"), warn()),
            EventsMode::Unknown => cell("…", dim()),
        },
    ]
}

/// `s` cut to `width` characters in the middle, keeping both ends: a socket
/// path or URL is told apart by its start and its end.
pub fn middle_ellipsis(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width || width < 5 {
        return s.chars().take(width).collect();
    }
    let head = (width - 1) / 3;
    let tail = width - 1 - head;
    let start: String = s.chars().take(head).collect();
    let end: String = s.chars().skip(n - tail).collect();
    format!("{start}…{end}")
}

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" Endpoints ");
    let Some(info) = &app.info else {
        f.render_widget(
            Paragraph::new(Line::styled("no daemon", dim())).block(block),
            area,
        );
        return;
    };
    // The address column's share: the table splits what the first column
    // leaves in two, less the column gaps.
    let col = (area.width.saturating_sub(2 + 19 + 2) / 2) as usize;
    let rows: Vec<Row> = rows(info, &app.socket)
        .into_iter()
        .chain([events_row(&app.events)])
        .map(|[a, mut b, c]| {
            let text: String = b.spans.iter().map(|s| s.content.as_ref()).collect();
            if text.chars().count() > col {
                b = Line::styled(middle_ellipsis(&text, col), b.style);
            }
            Row::new(vec![a, b, c])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(19),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ],
    )
    .header(Row::new(vec!["ENDPOINT", "ADDRESS", "STATE"]).style(dim()))
    .block(block);
    f.render_widget(table, area);
    let note = Rect {
        y: area.y + area.height.saturating_sub(2),
        height: 1,
        x: area.x + 1,
        width: area.width.saturating_sub(2),
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![Span::styled(
            "URLs come from the daemon with any credentials removed; the TUI reads no config file.",
            dim(),
        )]))
        .wrap(Wrap { trim: true }),
        note,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::tests::{info_with, key, press};
    use crate::tui::app::{App, Event};
    use crate::tui::ui::tests::render;
    use crossterm::event::KeyCode;
    use gyges_proto::v1::{ApiVersion, FallbackStatus, NodeStatus, TorStatus};
    use std::time::Duration;

    fn info(minor: u32) -> GetInfoResponse {
        let mut i = info_with(vec![key("main", true)]);
        i.api_version = Some(ApiVersion { major: 0, minor });
        i.node = Some(NodeStatus {
            connected: true,
            tip_height: 4_000,
            pruned: true,
            retained_from: 3_000,
            rpc_url: "http://127.0.0.1:18232".into(),
            ..Default::default()
        });
        i.fallback = Some(FallbackStatus {
            enabled: true,
            grpc_url: "https://zec.rocks:443".into(),
            use_tor: true,
            trust: FallbackTrust::Untested as i32,
            broadcast_via_tor: true,
        });
        i.tor = Some(TorStatus {
            state: TorState::Bootstrapping as i32,
            bootstrap_percent: 40,
            ..Default::default()
        });
        i
    }

    fn tab(i: GetInfoResponse) -> String {
        let mut app = App::new(Duration::from_secs(2));
        app.socket = "/home/u/.gyges/regtest/gygesd.sock".into();
        app.on_event(Event::Info(Box::new(i)));
        press(&mut app, KeyCode::Char('5'));
        render(&app, 150, 24)
    }

    #[test]
    fn every_endpoint_and_its_state() {
        let s = tab(info(2));
        assert!(s.contains("/home/u/.gyges/regtest/gygesd.sock"), "{s}");
        assert!(s.contains("http://127.0.0.1:18232"), "{s}");
        assert!(
            s.contains("connected · tip 4,000 · pruned, holds from 3,000"),
            "{s}"
        );
        assert!(s.contains("not configured"), "no indexer: {s}");
        assert!(s.contains("https://zec.rocks:443"), "{s}");
        assert!(s.contains("untested · over Tor"), "{s}");
        assert!(s.contains("the archival fallback, over Tor"), "{s}");
        assert!(s.contains("bootstrapping 40%"), "{s}");
        assert!(s.contains("wallet events"), "{s}");
    }

    #[test]
    fn the_event_stream_or_its_absence_is_shown() {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info(3))));
        press(&mut app, KeyCode::Char('5'));
        app.on_event(Event::Events(EventsMode::Streaming));
        assert!(render(&app, 150, 24).contains("streaming: changes show at once"));
        app.on_event(Event::Events(EventsMode::Polling(
            "the daemon is older than API 0.3".into(),
        )));
        assert!(render(&app, 150, 24).contains("polling only: the daemon is older than API 0.3"));
    }

    #[test]
    fn an_older_daemon_is_said_to_not_report_urls() {
        let mut i = info(1);
        i.node.as_mut().unwrap().rpc_url.clear();
        let s = tab(i);
        assert!(s.contains("not reported by this daemon's API"), "{s}");
    }

    #[test]
    fn long_paths_keep_both_ends() {
        let s = middle_ellipsis("/var/folders/t5/x18snf/T/.tmpabc/regtest/gygesd.sock", 30);
        assert_eq!(s.chars().count(), 30);
        assert_eq!(s, "/var/fold…/regtest/gygesd.sock");
        assert_eq!(middle_ellipsis("short", 30), "short");
    }

    #[test]
    fn air_gapped_has_no_node() {
        let mut i = info(2);
        i.airgapped = true;
        let s = tab(i);
        assert!(s.contains("off: air-gapped"), "{s}");
    }
}
