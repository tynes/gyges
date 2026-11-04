//! The Logs tab: the daemon's log (or audit log) streamed live.
//!
//! The stream runs only while the tab is open. Opening it asks
//! `StreamLogs { lines: 200, follow: true }` on a connection of its own, so
//! nothing is missed between visits: the daemon keeps its last 1,000 entries
//! of each log in memory (interface.md API §4.5). The TUI keeps at most
//! [`CAP`] entries too, dropping the oldest. Entries are redacted at source,
//! so nothing here can show an address, amount or key.
//!
//! Every (re)start gets a new generation number; entries and ends from an
//! older stream (a level or log change, a revisit) are ignored.

use std::collections::VecDeque;

use gyges_proto::v1::{LogEntry, LogLevel};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use super::ui::{bad, dim, key_style, ok, warn};

/// Entries kept, as the daemon keeps.
pub const CAP: usize = 1_000;
/// Entries replayed when the stream opens.
pub const REPLAY: u32 = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogStatus {
    /// The tab has not been opened, or was left.
    Off,
    Starting,
    Streaming,
    /// The stream ended: `None` when it was asked to (no follow), else why.
    Ended(Option<String>),
}

#[derive(Debug)]
pub struct LogView {
    pub entries: VecDeque<LogEntry>,
    /// `StreamLogsRequest.min_level`; `Unspecified` is the daemon's filter.
    pub level: LogLevel,
    pub audit: bool,
    /// Lines up from the newest; 0 follows new entries.
    pub scroll: usize,
    pub status: LogStatus,
    pub generation: u64,
}

impl Default for LogView {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            level: LogLevel::Unspecified,
            audit: false,
            scroll: 0,
            status: LogStatus::Off,
            generation: 0,
        }
    }
}

/// What a (re)start asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRequest {
    pub generation: u64,
    pub level: LogLevel,
    pub audit: bool,
}

impl LogView {
    /// Clear and begin a new stream; returns what to ask the daemon for.
    pub fn restart(&mut self) -> LogRequest {
        self.generation += 1;
        self.entries.clear();
        self.scroll = 0;
        self.status = LogStatus::Starting;
        LogRequest {
            generation: self.generation,
            level: self.level,
            audit: self.audit,
        }
    }

    pub fn stop(&mut self) {
        self.generation += 1;
        self.status = LogStatus::Off;
    }

    pub fn push(&mut self, generation: u64, e: LogEntry) {
        if generation != self.generation {
            return;
        }
        self.status = LogStatus::Streaming;
        if self.entries.len() == CAP {
            self.entries.pop_front();
        }
        self.entries.push_back(e);
        // Keep the view still while scrolled back.
        if self.scroll > 0 {
            self.scroll = (self.scroll + 1).min(self.entries.len().saturating_sub(1));
        }
    }

    pub fn ended(&mut self, generation: u64, error: Option<String>) {
        if generation == self.generation {
            self.status = LogStatus::Ended(error);
        }
    }

    pub fn scroll_by(&mut self, delta: isize) {
        let max = self.entries.len().saturating_sub(1) as isize;
        self.scroll = (self.scroll as isize).saturating_add(delta).clamp(0, max) as usize;
    }

    /// The next `min_level` in `v`'s cycle.
    pub fn next_level(&mut self) {
        self.level = match self.level {
            LogLevel::Unspecified => LogLevel::Error,
            LogLevel::Error => LogLevel::Warn,
            LogLevel::Warn => LogLevel::Info,
            LogLevel::Info => LogLevel::Debug,
            LogLevel::Debug => LogLevel::Trace,
            LogLevel::Trace => LogLevel::Unspecified,
        };
    }
}

pub fn level_name(l: LogLevel) -> &'static str {
    match l {
        LogLevel::Unspecified => "daemon's",
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    }
}

fn level_span(l: LogLevel) -> Span<'static> {
    match l {
        LogLevel::Error => Span::styled("ERROR", bad().add_modifier(Modifier::BOLD)),
        LogLevel::Warn => Span::styled(" WARN", warn()),
        LogLevel::Info => Span::styled(" INFO", ok()),
        LogLevel::Debug => Span::styled("DEBUG", dim()),
        LogLevel::Trace => Span::styled("TRACE", dim()),
        LogLevel::Unspecified => Span::styled("    ?", dim()),
    }
}

/// `HH:MM:SS.mmm` (UTC) from Unix milliseconds.
pub fn clock(ms: i64) -> String {
    let ms = ms.rem_euclid(86_400_000);
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        ms / 3_600_000,
        ms / 60_000 % 60,
        ms / 1_000 % 60,
        ms % 1_000
    )
}

pub fn entry_line(e: &LogEntry) -> Line<'static> {
    let mut spans = vec![
        Span::styled(clock(e.timestamp_unix_ms), dim()),
        Span::raw(" "),
        level_span(e.level()),
        Span::raw(" "),
        Span::styled(format!("{}:", e.target), dim()),
        Span::raw(format!(" {}", e.message)),
    ];
    let mut fields: Vec<_> = e.fields.iter().collect();
    fields.sort();
    for (k, v) in fields {
        spans.push(Span::styled(format!(" {k}="), key_style()));
        spans.push(Span::raw(v.clone()));
    }
    Line::from(spans)
}

pub fn draw(f: &mut Frame, area: Rect, view: &LogView) {
    let which = if view.audit {
        "audit log"
    } else {
        "daemon log"
    };
    let state = match &view.status {
        LogStatus::Off | LogStatus::Starting => Span::styled("connecting…", dim()),
        LogStatus::Streaming if view.scroll > 0 => Span::styled(
            format!("scrolled back {} · End follows", view.scroll),
            warn(),
        ),
        LogStatus::Streaming => Span::styled("following", ok()),
        LogStatus::Ended(None) => Span::styled("replayed", dim()),
        LogStatus::Ended(Some(e)) => Span::styled(format!("stopped: {e}"), bad()),
    };
    let title = Line::from(vec![
        Span::raw(format!(
            " Logs · {which} · level {} · {} kept · ",
            level_name(view.level),
            view.entries.len()
        )),
        state,
        Span::raw(" · v level · a audit "),
    ]);
    let block = Block::bordered().title(title);
    let inner = block.inner(area);
    let rows = inner.height as usize;
    let end = view.entries.len().saturating_sub(view.scroll);
    let start = end.saturating_sub(rows);
    let lines: Vec<Line> = view.entries.range(start..end).map(entry_line).collect();
    let body = if lines.is_empty() {
        Paragraph::new(Line::styled(
            match view.status {
                LogStatus::Ended(_) | LogStatus::Streaming => "no entries at this level",
                _ => "",
            },
            dim(),
        ))
    } else {
        Paragraph::new(lines)
    };
    f.render_widget(body.block(block).style(Style::new()), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(msg: &str) -> LogEntry {
        LogEntry {
            timestamp_unix_ms: 3_723_004,
            level: LogLevel::Info as i32,
            target: "gyges_core::sync".into(),
            message: msg.into(),
            fields: [("key_id".to_string(), "main".to_string())].into(),
        }
    }

    #[test]
    fn the_buffer_is_capped_and_old_generations_are_ignored() {
        let mut v = LogView::default();
        let req = v.restart();
        for i in 0..CAP + 5 {
            v.push(req.generation, entry(&i.to_string()));
        }
        assert_eq!(v.entries.len(), CAP);
        assert_eq!(v.entries.front().unwrap().message, "5");
        let next = v.restart();
        assert!(v.entries.is_empty());
        v.push(req.generation, entry("stale"));
        v.ended(req.generation, Some("stale".into()));
        assert!(v.entries.is_empty() && v.status == LogStatus::Starting);
        v.push(next.generation, entry("fresh"));
        assert_eq!(v.status, LogStatus::Streaming);
    }

    #[test]
    fn scrolling_back_holds_the_view_still() {
        let mut v = LogView::default();
        let g = v.restart().generation;
        for i in 0..10 {
            v.push(g, entry(&i.to_string()));
        }
        v.scroll_by(3);
        v.push(g, entry("new"));
        assert_eq!(v.scroll, 4, "the same lines stay on screen");
        v.scroll_by(isize::MIN);
        assert_eq!(v.scroll, 0);
        v.scroll_by(isize::MAX);
        assert_eq!(v.scroll, v.entries.len() - 1);
    }

    use crate::tui::app::tests::{info_with, key, press};
    use crate::tui::app::{Action, App, Event, Tab};
    use crate::tui::ui::tests::render;
    use crossterm::event::KeyCode;
    use std::time::Duration;

    fn started(app: &mut App) -> LogRequest {
        match app.take_actions().as_slice() {
            [Action::StartLogs(r)] => r.clone(),
            other => panic!("expected one StartLogs, got {other:?}"),
        }
    }

    #[test]
    fn the_stream_runs_only_while_the_tab_is_open() {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        press(&mut app, KeyCode::Char('L'));
        assert_eq!(app.tab, Tab::Logs);
        let r = started(&mut app);
        assert!(!r.audit && r.level == LogLevel::Unspecified);
        app.on_event(Event::Log {
            generation: r.generation,
            entry: Box::new(entry("listening on the socket")),
        });
        let s = render(&app, 140, 20);
        assert!(
            s.contains("listening on the socket") && s.contains("following"),
            "{s}"
        );

        press(&mut app, KeyCode::Char('a'));
        let audit = started(&mut app);
        assert!(audit.audit && audit.generation > r.generation);
        assert!(render(&app, 140, 20).contains("audit log"));
        press(&mut app, KeyCode::Char('v'));
        assert_eq!(started(&mut app).level, LogLevel::Error);

        press(&mut app, KeyCode::Char('1'));
        assert_eq!(app.take_actions(), vec![Action::StopLogs]);
        assert_eq!(app.logs.status, LogStatus::Off);
    }

    #[test]
    fn a_failed_stream_restarts_when_the_daemon_answers_again() {
        let mut app = App::new(Duration::from_secs(2));
        app.tab = Tab::Logs;
        app.on_event(Event::Info(Box::new(info_with(vec![]))));
        let r = started(&mut app);
        app.on_event(Event::LogsEnded {
            generation: r.generation,
            error: Some("gygesd is not running".into()),
        });
        assert!(render(&app, 140, 20).contains("stopped: gygesd is not running"));
        app.on_event(Event::Info(Box::new(info_with(vec![]))));
        assert!(started(&mut app).generation > r.generation);
        // A clean end (a --dump replay) is not restarted, and settles the dump.
        let g = app.logs.generation;
        app.on_event(Event::LogsEnded {
            generation: g,
            error: None,
        });
        app.on_event(Event::Loaded);
        app.on_event(Event::Info(Box::new(info_with(vec![]))));
        assert!(app.take_actions().is_empty());
        assert!(app.settled());
    }

    #[test]
    fn levels_cycle_and_lines_read_well() {
        let mut v = LogView::default();
        v.next_level();
        assert_eq!(v.level, LogLevel::Error);
        for _ in 0..5 {
            v.next_level();
        }
        assert_eq!(v.level, LogLevel::Unspecified);
        assert_eq!(clock(3_723_004), "01:02:03.004");
        let text: String = entry_line(&entry("batch scanned"))
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(
            text,
            "01:02:03.004  INFO gyges_core::sync: batch scanned key_id=main"
        );
    }
}
