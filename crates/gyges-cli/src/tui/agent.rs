//! The agent bar: a line at the bottom of the TUI to type requests to an
//! assistant ("send 0.5 to the shop's address"), with its answers above it.
//!
//! There is no assistant yet. [`AgentBackend`] is the seam a provider will
//! plug into, and [`StubBackend`], the only one, answers that none is
//! configured.
//!
//! **The rule every backend lives under** (docs/decisions.md Q-C7):
//! - An agent may only *fill in the send form* ([`SendDraft`]). The TUI
//!   opens the form with the draft's fields; from there the user reviews it,
//!   the dry run proposes, the user confirms, and the user signs, exactly as
//!   for a send typed by hand. No agent call can confirm, sign or broadcast.
//! - An agent never sees key material or passphrases. [`AgentRequest`] holds
//!   the conversation and the selected key's id only; the passphrase field
//!   lives in the send modal and is never part of a request.
//! - Whatever a backend is given leaves the TUI. For a remote model that
//!   means the provider sees the user's messages, so a backend that adds
//!   wallet data to its prompt (balances, addresses, history) must say so
//!   before it is turned on; a privacy wallet should prefer a local model.

use std::fmt;

use futures_util::future::BoxFuture;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::ui::{dim, key_style, warn};

/// Turns kept on screen and sent as history.
pub const MAX_TURNS: usize = 50;
/// The longest message the bar accepts.
pub const MAX_INPUT: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speaker {
    User,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    pub who: Speaker,
    pub text: String,
}

/// Everything a backend is given. Nothing else reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRequest {
    /// The conversation so far, oldest first, ending with the new message.
    pub history: Vec<Turn>,
    /// The wallet the user has selected, by id, for drafts.
    pub key_id: Option<String>,
}

/// A send the agent proposes: only what a person would type into the form.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SendDraft {
    pub to: String,
    /// In the amount grammar (docs/interface.md CLI §1.4), as typed.
    pub amount: String,
    pub memo: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentReply {
    pub text: String,
    /// Opens the send form filled in, for the user to review and confirm.
    pub draft: Option<SendDraft>,
}

/// An assistant provider. Implementations get an [`AgentRequest`] and
/// answer with text and, at most, a [`SendDraft`]; see the module docs for
/// the rule they live under.
pub trait AgentBackend: Send + Sync + fmt::Debug {
    /// Shown in the bar's title.
    fn name(&self) -> &str;
    fn respond(&self, request: AgentRequest) -> BoxFuture<'_, Result<AgentReply, String>>;
}

/// The only backend for now: it says there is none.
#[derive(Debug, Default)]
pub struct StubBackend;

/// The stub's one answer.
pub const NOT_CONFIGURED: &str = "No agent backend is configured yet, so nothing was done. When one is, it will be able to fill in the send form for you to review, confirm and sign; it will never sign or see your keys.";

impl AgentBackend for StubBackend {
    fn name(&self) -> &str {
        "backend not configured"
    }

    fn respond(&self, _request: AgentRequest) -> BoxFuture<'_, Result<AgentReply, String>> {
        Box::pin(async {
            Ok(AgentReply {
                text: NOT_CONFIGURED.to_string(),
                draft: None,
            })
        })
    }
}

/// The bar's state.
#[derive(Debug, Default)]
pub struct AgentPane {
    pub input: String,
    /// Keys go to the bar (`/` focuses, `Esc` leaves).
    pub focused: bool,
    pub turns: Vec<Turn>,
    /// A request is out.
    pub busy: bool,
    pub backend_name: String,
}

impl AgentPane {
    pub fn push(&mut self, who: Speaker, text: String) {
        self.turns.push(Turn { who, text });
        if self.turns.len() > MAX_TURNS {
            self.turns.remove(0);
        }
    }

    /// Rows the bar takes: one, plus the transcript while focused.
    pub fn height(&self, room: u16) -> u16 {
        if self.focused {
            (room / 3).clamp(3, 12)
        } else {
            1
        }
    }
}

fn turn_line(t: &Turn) -> Line<'static> {
    match t.who {
        Speaker::User => Line::from(vec![
            Span::styled("you   ", key_style()),
            Span::raw(t.text.clone()),
        ]),
        Speaker::Agent => Line::from(vec![
            Span::styled("agent ", warn()),
            Span::raw(t.text.clone()),
        ]),
    }
}

pub fn draw(f: &mut Frame, area: Rect, pane: &AgentPane) {
    let prompt = Line::from(vec![
        Span::styled("agent › ", if pane.focused { key_style() } else { dim() }),
        if pane.input.is_empty() && !pane.focused {
            Span::styled(format!("press / to ask ({})", pane.backend_name), dim())
        } else {
            Span::raw(pane.input.clone())
        },
        if pane.focused && !pane.busy {
            Span::styled("▏", key_style())
        } else {
            Span::raw("")
        },
        if pane.busy {
            Span::styled("  thinking…", dim())
        } else {
            Span::raw("")
        },
    ]);
    if !pane.focused {
        f.render_widget(Paragraph::new(prompt), area);
        return;
    }
    let block = Block::new()
        .borders(Borders::TOP)
        .border_style(dim())
        .title(Line::styled(
            format!(
                " Agent · {} · Enter send · Esc leave · it can only fill in the send form ",
                pane.backend_name
            ),
            Style::new().add_modifier(Modifier::DIM),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let rows = inner.height.saturating_sub(1) as usize;
    let mut lines: Vec<Line> = pane.turns.iter().map(turn_line).collect();
    let skip = lines.len().saturating_sub(rows);
    lines.drain(..skip);
    let transcript = Rect {
        height: inner.height.saturating_sub(1),
        ..inner
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), transcript);
    f.render_widget(
        Paragraph::new(prompt),
        Rect {
            y: inner.y + inner.height.saturating_sub(1),
            height: 1,
            ..inner
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::tests::{info_with, key, press};
    use crate::tui::app::{Action, App, Event};
    use crate::tui::send::{Field, Stage};
    use crate::tui::ui::tests::render;
    use crossterm::event::KeyCode;
    use std::time::Duration;

    fn app() -> App {
        let mut app = App::new(Duration::from_secs(2));
        app.on_event(Event::Info(Box::new(info_with(vec![key("main", true)]))));
        app
    }

    #[tokio::test]
    async fn the_stub_says_it_is_not_configured() {
        let reply = StubBackend
            .respond(AgentRequest {
                history: vec![],
                key_id: None,
            })
            .await
            .unwrap();
        assert_eq!(reply.text, NOT_CONFIGURED);
        assert!(reply.draft.is_none());
    }

    #[test]
    fn slash_focuses_the_bar_and_enter_asks_with_the_history() {
        let mut app = app();
        assert!(render(&app, 120, 30).contains("press / to ask"));
        press(&mut app, KeyCode::Char('/'));
        for c in "send 1 to bob".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        // Keys typed into the bar are not hotkeys.
        assert!(app.send.is_none() && !app.quit);
        press(&mut app, KeyCode::Enter);
        let acts = app.take_actions();
        assert_eq!(
            acts,
            vec![Action::Ask(AgentRequest {
                history: vec![Turn {
                    who: Speaker::User,
                    text: "send 1 to bob".into()
                }],
                key_id: Some("main".into()),
            })]
        );
        assert!(app.agent.busy && app.agent.input.is_empty());
        app.on_event(Event::AgentReply(Ok(AgentReply {
            text: NOT_CONFIGURED.into(),
            draft: None,
        })));
        let s = render(&app, 140, 40);
        assert!(s.contains("you   send 1 to bob"), "{s}");
        assert!(
            s.contains("agent No agent backend is configured yet"),
            "{s}"
        );
        press(&mut app, KeyCode::Esc);
        assert!(!app.agent.focused);
        press(&mut app, KeyCode::Char('q'));
        assert!(app.quit, "hotkeys again once the bar is left");
    }

    #[test]
    fn a_draft_only_fills_in_the_send_form() {
        let mut app = app();
        press(&mut app, KeyCode::Char('/'));
        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Enter);
        app.take_actions();
        app.on_event(Event::AgentReply(Ok(AgentReply {
            text: "Here is the send; check it.".into(),
            draft: Some(SendDraft {
                to: "uregtest1shop".into(),
                amount: "0.5".into(),
                memo: "order 7".into(),
            }),
        })));
        // The form is open and filled; nothing was proposed, confirmed or
        // signed, and no action went out.
        assert!(app.take_actions().is_empty());
        match &app.send {
            Some(Stage::Form(f)) => {
                assert_eq!(
                    (f.to.as_str(), f.amount.as_str(), f.memo.as_str()),
                    ("uregtest1shop", "0.5", "order 7")
                );
                assert_eq!(f.focus, Field::To);
            }
            other => panic!("{other:?}"),
        }
        assert!(!app.agent.focused, "the form has the keys now");
        assert!(app.toasts.iter().any(|t| t.text.contains("review")));
    }

    #[test]
    fn a_draft_for_a_key_that_cannot_sign_is_not_opened() {
        let mut app = App::new(Duration::from_secs(2));
        let mut k = key("watch", true);
        k.signing_mode = gyges_proto::v1::SigningMode::WatchOnly as i32;
        app.on_event(Event::Info(Box::new(info_with(vec![k]))));
        app.on_event(Event::AgentReply(Ok(AgentReply {
            text: "ok".into(),
            draft: Some(SendDraft::default()),
        })));
        assert!(app.send.is_none());
    }
}
