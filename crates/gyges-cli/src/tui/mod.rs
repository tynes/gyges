//! `gyges tui` (docs/interface.md CLI §2.7, docs/decisions.md Q-C7): a
//! full-screen dashboard over the daemon's gRPC API.
//!
//! The TUI is another API client, like the commands. It never calls a
//! command's `run()`, `Prompter` or `Ctx::next_or_cancel`: those print to
//! stdout and stderr, prompt on the tty and wait on SIGINT, and every one of
//! them would break a raw-mode screen. It reuses only the pure pieces: the
//! connection and handshake (`Ctx::connect`), the amount grammar and the
//! renderers that return strings.
//!
//! Layout of the module:
//! - [`app`]: the state and every key and daemon event that changes it. No I/O.
//! - [`poll`]: the background task that polls the daemon and sends [`app::Event`]s.
//! - [`ui`]: drawing the state with ratatui. No I/O.
//! - this file: the terminal, the event loop and the effects of [`app::Action`]s.

mod addresses;
mod app;
mod endpoints;
mod lists;
mod logs;
mod notify;
mod poll;
mod send;
mod send_task;
mod tasks;
mod ui;

use std::io::IsTerminal as _;
use std::time::Duration;

use clap::Args;
use crossterm::event::{Event as TermEvent, EventStream, KeyEventKind};
use futures_util::StreamExt as _;
use ratatui::Terminal;
use ratatui::backend::{Backend, TestBackend};
use tokio::sync::mpsc;

use crate::client::Ctx;
use crate::exit::CliError;

use self::app::{Action, App, Event};

/// How long `--dump` waits for the first full load before drawing anyway.
const DUMP_TIMEOUT: Duration = Duration::from_secs(30);
/// Redraw cadence when nothing else happens: the Keystone request's frame
/// rate, so its animation is not slowed down.
const TICK: Duration = Duration::from_millis(1000 / gyges_qr::DEFAULT_FPS as u64);

#[derive(Debug, Clone, Args)]
pub struct TuiArgs {
    /// How often to ask the daemon for its tip and sync state. Balances,
    /// notes and history reload only when those change.
    #[arg(long, value_name = "DURATION", default_value = "2s", value_parser = humantime::parse_duration)]
    pub interval: Duration,
    /// Draw one frame of COLSxROWS to stdout after the first full load and
    /// exit, without a terminal (for scripts and tests).
    #[arg(long, value_name = "COLSxROWS", value_parser = parse_size)]
    pub dump: Option<(u16, u16)>,
    /// The tab to open on, by name (overview, notes, transactions, …).
    #[arg(long, value_name = "NAME", default_value = "overview", value_parser = parse_tab)]
    pub tab: app::Tab,
}

fn parse_tab(s: &str) -> Result<app::Tab, String> {
    app::Tab::from_name(s).ok_or_else(|| {
        let names: Vec<String> = app::Tab::ALL
            .iter()
            .map(|t| t.title().to_lowercase())
            .collect();
        format!("expected one of {}", names.join(", "))
    })
}

fn parse_size(s: &str) -> Result<(u16, u16), String> {
    let (w, h) = s
        .split_once('x')
        .ok_or_else(|| format!("expected COLSxROWS such as 120x40, got `{s}`"))?;
    let w: u16 = w.parse().map_err(|_| format!("bad column count `{w}`"))?;
    let h: u16 = h.parse().map_err(|_| format!("bad row count `{h}`"))?;
    if w < 20 || h < 8 {
        return Err("the smallest frame is 20x8".into());
    }
    Ok((w, h))
}

pub async fn run(ctx: &Ctx, args: TuiArgs) -> Result<(), CliError> {
    // The handshake must not print its newer-minor warning to stderr under
    // the screen; the header shows it instead.
    let mut ctx = ctx.clone();
    ctx.quiet = true;
    ctx.json = false;

    let (tx, rx) = mpsc::unbounded_channel();
    let poller = poll::Poller::new(ctx.clone(), args.interval, tx.clone());
    let refresh = poller.refresh_handle();
    let poll_task = tokio::spawn(poller.run());
    let mut app = App::new(args.interval);
    app.tab = args.tab;
    app.socket = ctx.socket.display().to_string();
    let mut effects = Effects {
        ctx: ctx.clone(),
        tx,
        refresh,
        terminal: args.dump.is_none(),
        logs: None,
        send_reply: None,
        scan_stop: None,
    };

    let result = match args.dump {
        Some((w, h)) => dump(app, rx, &mut effects, w, h).await,
        None => {
            if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
                poll_task.abort();
                return Err(CliError::invalid(
                    "gyges tui needs a terminal; use --dump COLSxROWS for a one-shot frame",
                ));
            }
            interactive(app, rx, &mut effects).await
        }
    };
    poll_task.abort();
    result
}

/// Executes the [`Action`]s the state asks for.
struct Effects {
    ctx: Ctx,
    tx: mpsc::UnboundedSender<Event>,
    refresh: poll::RefreshHandle,
    /// False for `--dump`, whose stdout is the frame: no bell, no clipboard.
    terminal: bool,
    /// The Logs tab's stream, while it runs.
    logs: Option<tokio::task::JoinHandle<()>>,
    /// Answers to the running send's signature request.
    send_reply: Option<mpsc::UnboundedSender<send::SendReply>>,
    /// Stops the camera scan, while one runs.
    scan_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl Drop for Effects {
    fn drop(&mut self) {
        if let Some(t) = self.logs.take() {
            t.abort();
        }
        self.stop_scan();
    }
}

impl Effects {
    fn perform(&mut self, action: Action) {
        use std::io::Write as _;
        match action {
            Action::Refresh => self.refresh.request(),
            Action::Bell if self.terminal => {
                let mut out = std::io::stdout();
                let _ = out.write_all(b"\x07");
                let _ = out.flush();
            }
            Action::Copy(text) if self.terminal => {
                let _ = crossterm::execute!(
                    std::io::stdout(),
                    crossterm::clipboard::CopyToClipboard::to_clipboard_from(text)
                );
            }
            Action::Bell | Action::Copy(_) => {}
            Action::LoadAddress { key_id, view } => {
                tasks::load_address(&self.ctx, &self.tx, key_id, view)
            }
            Action::NewAddress { key_id, label } => {
                tasks::new_address(&self.ctx, &self.tx, key_id, label)
            }
            Action::StartLogs(req) => {
                if let Some(t) = self.logs.take() {
                    t.abort();
                }
                let follow = self.terminal;
                self.logs = Some(tasks::stream_logs(&self.ctx, &self.tx, req, follow));
            }
            Action::StopLogs => {
                if let Some(t) = self.logs.take() {
                    t.abort();
                }
            }
            Action::Inspect(address) => tasks::inspect(&self.ctx, &self.tx, address),
            Action::DryRun { id, spec } => send_task::dry_run(&self.ctx, &self.tx, id, spec),
            Action::Execute { id, spec } => {
                self.send_reply = Some(send_task::execute(&self.ctx, &self.tx, id, spec));
            }
            Action::Reply(reply) => {
                if let Some(r) = &self.send_reply {
                    let _ = r.send(reply);
                }
            }
            Action::ScanCamera { answer, request } => {
                self.stop_scan();
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                self.scan_stop = Some(stop.clone());
                send_task::scan(&self.tx, answer, request, stop);
            }
            Action::StopScan => self.stop_scan(),
        }
    }

    fn stop_scan(&mut self) {
        if let Some(s) = self.scan_stop.take() {
            s.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn drain(&mut self, app: &mut App) {
        for action in app.take_actions() {
            self.perform(action);
        }
    }
}

async fn interactive(
    mut app: App,
    mut rx: mpsc::UnboundedReceiver<Event>,
    effects: &mut Effects,
) -> Result<(), CliError> {
    let mut terminal = term::enter()?;
    let result = event_loop(&mut terminal, &mut app, &mut rx, effects).await;
    term::leave();
    result
}

async fn event_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    rx: &mut mpsc::UnboundedReceiver<Event>,
    effects: &mut Effects,
) -> Result<(), CliError>
where
    B::Error: Send + Sync + 'static,
{
    let mut keys = EventStream::new();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while !app.quit {
        terminal
            .draw(|f| ui::draw(f, app))
            .map_err(|e| CliError::Other(anyhow::anyhow!("drawing the screen: {e}")))?;
        tokio::select! {
            ev = keys.next() => match ev {
                Some(Ok(TermEvent::Key(k))) if k.kind != KeyEventKind::Release => app.on_key(k),
                Some(Ok(TermEvent::Paste(s))) => app.on_paste(&s),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(CliError::Other(anyhow::anyhow!("reading the terminal: {e}"))),
                None => break,
            },
            Some(ev) = rx.recv() => app.on_event(ev),
            _ = tick.tick() => app.on_tick(std::time::Instant::now()),
        }
        effects.drain(app);
    }
    Ok(())
}

/// `--dump`: wait for the first full load (or the daemon to be found down),
/// draw one frame into an in-memory buffer and print it.
async fn dump(
    mut app: App,
    mut rx: mpsc::UnboundedReceiver<Event>,
    effects: &mut Effects,
    w: u16,
    h: u16,
) -> Result<(), CliError> {
    let deadline = tokio::time::sleep(DUMP_TIMEOUT);
    tokio::pin!(deadline);
    while !app.settled() {
        tokio::select! {
            Some(ev) = rx.recv() => app.on_event(ev),
            _ = &mut deadline => break,
        }
        effects.drain(&mut app);
    }
    let mut terminal = Terminal::new(TestBackend::new(w, h))
        .map_err(|e| CliError::Other(anyhow::anyhow!("{e}")))?;
    terminal
        .draw(|f| ui::draw(f, &app))
        .map_err(|e| CliError::Other(anyhow::anyhow!("{e}")))?;
    print!("{}", ui::buffer_text(terminal.backend().buffer()));
    Ok(())
}

/// Entering and leaving raw mode, with a panic hook that always leaves it.
mod term {
    use std::io::stdout;

    use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
    use crossterm::execute;
    use ratatui::DefaultTerminal;

    use crate::exit::CliError;

    pub fn enter() -> Result<DefaultTerminal, CliError> {
        // `ratatui::try_init` enters raw mode and the alternate screen, and
        // installs a panic hook that restores the terminal before the
        // previous hook prints the panic. Ours wraps it to undo the paste mode.
        let terminal = ratatui::try_init()
            .map_err(|e| CliError::Other(anyhow::anyhow!("setting up the terminal: {e}")))?;
        let _ = execute!(stdout(), EnableBracketedPaste);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = execute!(stdout(), DisableBracketedPaste);
            previous(info);
        }));
        Ok(terminal)
    }

    pub fn leave() {
        let _ = execute!(stdout(), DisableBracketedPaste);
        ratatui::restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_size_parses() {
        assert_eq!(parse_size("120x40").unwrap(), (120, 40));
        assert!(parse_size("120").is_err());
        assert!(parse_size("10x5").is_err());
        assert!(parse_size("ax40").is_err());
    }

    #[test]
    fn tabs_parse_by_name() {
        assert_eq!(parse_tab("notes").unwrap(), app::Tab::Notes);
        assert_eq!(parse_tab("Transactions").unwrap(), app::Tab::Transactions);
        assert!(parse_tab("nope").unwrap_err().contains("overview, notes"));
    }
}
