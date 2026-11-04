//! Sending and shielding from the TUI: the form, the proposal, the signature
//! and the result, as one modal that moves through [`Stage`]s.
//!
//! The order is the CLI's (interface.md CLI §2.5): a dry run proposes, the
//! proposal is shown and confirmed, and only then does the real request
//! start. The real request runs on a connection of its own
//! ([`super::send_task`]) that lives as long as the send:
//! - **Passphrase keys.** The stream pauses on `SignatureRequired`; the
//!   masked passphrase is sent as `UnlockKey { session_id }` on that same
//!   connection, which signs the pending step and keeps nothing. Up to three
//!   tries; cancelling aborts the session.
//! - **Keystone keys.** The request is animated as a `ur:` QR code; the
//!   device's answer is pasted (a phone's QR reader gives it as text) or
//!   scanned with the camera (builds with the `camera` feature), and goes to
//!   `CompleteKeystoneSign`. A refused answer can be scanned again; leaving
//!   keeps the session open for `gyges pczt qr-import`.
//!
//! The TUI's reading connection is never involved, so no unlock outlives a
//! send. The passphrase lives in a [`Secret`], which zeroizes on drop and
//! never prints.

use std::fmt;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};
use gyges_proto::v1::{
    Amount, InspectAddressResponse, Pool, Proposal, SendTransactionRequest, ShieldFundsRequest,
    SignatureKind, SignatureRequired, SigningMode, SpendOptions,
};
use gyges_qr::{Assembler, DEFAULT_FPS, Frames};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use zeroize::Zeroizing;

use crate::amount::{ParsedAmount, format_zec, parse_amount, parse_memo, parse_zatoshis};
use crate::balance::pool_name;
use crate::tx::render_proposal;

use super::app::{Action, App, Level};
use super::ui::{bad, dim, key_style, ok, warn};

/// How long typing pauses before the recipient is checked.
const INSPECT_AFTER: Duration = Duration::from_millis(300);
/// Wrong passphrases allowed per send, as on the CLI.
pub const PASSPHRASE_ATTEMPTS: u32 = 3;
/// Refused Keystone answers allowed per send, as on the CLI.
pub const ANSWER_ATTEMPTS: u32 = 3;

/// A passphrase: zeroized on drop, never printed.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
    fn push(&mut self, c: char) {
        self.0.push(c);
    }
    fn pop(&mut self) {
        self.0.pop();
    }
    fn len(&self) -> usize {
        self.0.chars().count()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(…)")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(Zeroizing::new(s.to_string()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Send,
    Shield,
}

impl Flow {
    fn verb(self) -> &'static str {
        match self {
            Flow::Send => "Send",
            Flow::Shield => "Shield",
        }
    }
}

/// A validated request, both for the dry run and the real one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendSpec {
    pub flow: Flow,
    pub key_id: String,
    pub to: String,
    pub amount: Option<ParsedAmount>,
    pub memo: Vec<u8>,
    pub via_tor: bool,
    pub output_pool: Pool,
    pub from_pools: Vec<Pool>,
    /// Shield only, in zatoshis; 0 is any.
    pub threshold: u64,
}

impl SendSpec {
    pub fn send_request(&self, dry_run: bool) -> SendTransactionRequest {
        let options =
            (self.output_pool != Pool::Unspecified || !self.from_pools.is_empty()).then(|| {
                SpendOptions {
                    output_pool: self.output_pool as i32,
                    from_pools: self.from_pools.iter().map(|p| *p as i32).collect(),
                    ..Default::default()
                }
            });
        SendTransactionRequest {
            key_id: self.key_id.clone(),
            to: self.to.clone(),
            amount: Some(
                self.amount
                    .map(ParsedAmount::to_proto)
                    .unwrap_or(Amount { value: None }),
            ),
            memo: self.memo.clone(),
            via_tor: self.via_tor,
            dry_run,
            session_token: Vec::new(),
            min_confirmations: 0,
            wait_for_mined: false,
            options,
        }
    }

    pub fn shield_request(&self, dry_run: bool) -> ShieldFundsRequest {
        ShieldFundsRequest {
            key_id: self.key_id.clone(),
            threshold: i64::try_from(self.threshold).unwrap_or(i64::MAX),
            dry_run,
            session_token: Vec::new(),
            wait_for_mined: false,
        }
    }
}

/// What the form asks for, in focus order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    To,
    Amount,
    Memo,
    Pool,
    From,
    ViaTor,
    Threshold,
}

/// `--pool`: the recipient's receiver to pay.
const OUT_POOLS: [(Pool, &str); 4] = [
    (Pool::Unspecified, "the address decides"),
    (Pool::Ironwood, "ironwood"),
    (Pool::Sapling, "sapling"),
    (Pool::Transparent, "transparent"),
];

/// `--from-pool`: where the funds come from.
const FROM_POOLS: [(Option<Pool>, &str); 5] = [
    (None, "any pool the key spends"),
    (Some(Pool::Ironwood), "ironwood only"),
    (Some(Pool::Orchard), "orchard only"),
    (Some(Pool::Sapling), "sapling only"),
    (Some(Pool::Transparent), "transparent only"),
];

#[derive(Debug, Clone)]
pub struct Form {
    pub flow: Flow,
    pub key_id: String,
    pub to: String,
    pub amount: String,
    pub memo: String,
    pub out_pool: usize,
    pub from: usize,
    pub via_tor: bool,
    pub threshold: String,
    pub focus: Field,
    /// The last `InspectAddress` answer, for the address it was asked about.
    pub inspect: Option<(String, Result<InspectAddressResponse, String>)>,
    inspect_due: Option<Instant>,
    pub error: Option<String>,
}

impl Form {
    pub fn new(flow: Flow, key_id: String) -> Self {
        Self {
            flow,
            key_id,
            to: String::new(),
            amount: String::new(),
            memo: String::new(),
            out_pool: 0,
            from: 0,
            via_tor: false,
            threshold: String::new(),
            focus: match flow {
                Flow::Send => Field::To,
                Flow::Shield => Field::Threshold,
            },
            inspect: None,
            inspect_due: None,
            error: None,
        }
    }

    pub fn fields(&self) -> &'static [Field] {
        match self.flow {
            Flow::Send => &[
                Field::To,
                Field::Amount,
                Field::Memo,
                Field::Pool,
                Field::From,
                Field::ViaTor,
            ],
            Flow::Shield => &[Field::Threshold],
        }
    }

    fn text_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            Field::To => Some(&mut self.to),
            Field::Amount => Some(&mut self.amount),
            Field::Memo => Some(&mut self.memo),
            Field::Threshold => Some(&mut self.threshold),
            Field::Pool | Field::From | Field::ViaTor => None,
        }
    }

    fn edited(&mut self, now: Instant) {
        self.error = None;
        if self.focus == Field::To {
            self.inspect_due = Some(now + INSPECT_AFTER);
        }
    }

    fn move_focus(&mut self, delta: isize) {
        let f = self.fields();
        let at = f.iter().position(|x| *x == self.focus).unwrap_or(0) as isize;
        self.focus = f[(at + delta).rem_euclid(f.len() as isize) as usize];
    }

    /// The inspection of the address now in the field, if it is in.
    pub fn inspected(&self) -> Option<&Result<InspectAddressResponse, String>> {
        match &self.inspect {
            Some((addr, r)) if *addr == self.to.trim() => Some(r),
            _ => None,
        }
    }

    /// The request the fields make, or what is wrong with them.
    pub fn validate(&self) -> Result<SendSpec, String> {
        let mut spec = SendSpec {
            flow: self.flow,
            key_id: self.key_id.clone(),
            to: self.to.trim().to_string(),
            amount: None,
            memo: Vec::new(),
            via_tor: self.via_tor,
            output_pool: OUT_POOLS[self.out_pool].0,
            from_pools: FROM_POOLS[self.from].0.into_iter().collect(),
            threshold: 0,
        };
        if self.flow == Flow::Shield {
            let t = self.threshold.trim();
            if !t.is_empty() {
                spec.threshold = parse_zatoshis(t).map_err(|e| format!("threshold: {e}"))?;
            }
            return Ok(spec);
        }
        if spec.to.is_empty() {
            return Err("enter the recipient's address".into());
        }
        if let Some(Ok(i)) = self.inspected()
            && !i.valid
        {
            return Err(format!("the address is not valid: {}", i.error));
        }
        spec.amount = Some(parse_amount(&self.amount).map_err(|e| format!("amount: {e}"))?);
        if !self.memo.is_empty() {
            if let Some(Ok(i)) = self.inspected()
                && i.kind() != gyges_proto::v1::AddressKind::Unified
                && i.kind() != gyges_proto::v1::AddressKind::Sapling
            {
                return Err("a memo goes to shielded recipients only".into());
            }
            spec.memo = parse_memo(&self.memo).map_err(|e| format!("memo: {e}"))?.0;
        }
        Ok(spec)
    }
}

/// The Keystone half of a signature in progress.
#[derive(Debug)]
pub struct KeystoneSign {
    pub session_id: String,
    pub kind: SignatureKind,
    /// The UR type of the device's answer.
    pub answer: &'static str,
    /// The request as sent, so a camera catching it can be told apart.
    pub payload: Vec<u8>,
    pub frames: Frames,
    /// The frame on screen, as QR text lines.
    pub qr: Vec<String>,
    next_frame_at: Instant,
    pub asm: Assembler,
    /// Typed frames not yet fed to the assembler.
    pub line: String,
    pub scanning: bool,
    /// The camera's `(resolved, total)` fragments.
    pub scan_progress: (usize, usize),
    pub busy: bool,
    pub error: Option<String>,
}

impl KeystoneSign {
    fn new(req: &SignatureRequired, now: Instant) -> Result<Self, String> {
        let kind = req.kind();
        let (_, answer) = crate::keystone::ur_types(kind).map_err(|e| e.message())?;
        let frames = crate::keystone::frames(kind, &req.payload).map_err(|e| e.message())?;
        let mut s = Self {
            session_id: req.session_id.clone(),
            kind,
            answer,
            payload: req.payload.clone(),
            frames,
            qr: Vec::new(),
            next_frame_at: now,
            asm: Assembler::new(),
            line: String::new(),
            scanning: false,
            scan_progress: (0, 0),
            busy: false,
            error: None,
        };
        s.advance(now);
        Ok(s)
    }

    /// Show the next fountain frame when it is due.
    fn advance(&mut self, now: Instant) {
        if now < self.next_frame_at || (self.frames.is_single() && !self.qr.is_empty()) {
            return;
        }
        self.next_frame_at = now + Duration::from_millis(1000 / u64::from(DEFAULT_FPS.max(1)));
        match self
            .frames
            .next_frame()
            .and_then(|f| gyges_qr::render_frame(&f))
        {
            Ok(s) => self.qr = s.lines().map(str::to_string).collect(),
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// Feed text holding frames; the answer's CBOR once it is complete.
    fn feed(&mut self, text: &str) -> Option<Vec<u8>> {
        for frame in text.split_whitespace() {
            if let Err(e) = self.asm.receive(frame) {
                self.error = Some(format!("ignored a frame: {e}"));
            }
        }
        if !self.asm.is_complete() {
            return None;
        }
        match self.asm.ur_type() {
            Some(t) if t != self.answer => {
                self.error = Some(format!(
                    "that is ur:{t}, not the device's ur:{} answer (is it the request?)",
                    self.answer
                ));
                self.asm = Assembler::new();
                None
            }
            _ => match self.asm.message() {
                Ok(Some((_, cbor))) => Some(cbor),
                Ok(None) => None,
                Err(e) => {
                    self.error = Some(e.to_string());
                    self.asm = Assembler::new();
                    None
                }
            },
        }
    }
}

/// A signature the stream is waiting for.
#[derive(Debug)]
pub enum Signing {
    Passphrase {
        key_id: String,
        input: Secret,
        busy: bool,
        error: Option<String>,
    },
    Keystone(Box<KeystoneSign>),
}

/// The real request, while it runs.
#[derive(Debug)]
pub struct Running {
    pub spec: SendSpec,
    pub proposal: Proposal,
    pub progress: Vec<String>,
    pub txids: Vec<String>,
    pub signing: Option<Signing>,
}

#[derive(Debug)]
pub enum Stage {
    Form(Form),
    /// The dry run is out.
    Proposing(Form),
    Confirm {
        form: Form,
        spec: SendSpec,
        proposal: Proposal,
    },
    Running(Running),
    Done {
        verb: &'static str,
        txids: Vec<String>,
        error: Option<String>,
    },
}

/// What the send task tells the state.
#[derive(Debug)]
pub enum SendUpdate {
    DryRun(Result<Proposal, String>),
    Proving {
        pool: Pool,
        done: u32,
        total: u32,
    },
    NeedPassphrase {
        key_id: String,
    },
    PassphraseRefused(String),
    NeedKeystone(Box<SignatureRequired>),
    KeystoneRefused(String),
    Signed(u32),
    Broadcast {
        step: u32,
        txid: String,
    },
    TexQueued {
        step1: String,
        step2: String,
    },
    /// The stream ended; `Err` with why.
    Ended(Result<(), String>),
}

/// What the state tells a running send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendReply {
    Passphrase(Secret),
    Keystone(Vec<u8>),
    Cancel,
}

/// Why the selected key cannot send here, if it cannot.
pub fn cannot_send(app: &App) -> Option<String> {
    let k = app.selected_key()?;
    if app.airgapped() {
        return Some(
            "Air-gapped daemon: build the transaction with `gyges pczt create` online.".into(),
        );
    }
    match k.signing_mode() {
        SigningMode::WatchOnly => Some(format!(
            "{} is watch-only: it cannot sign. Create a PCZT with `gyges pczt create` and sign it elsewhere.",
            k.key_id
        )),
        SigningMode::SignerOnly => Some(format!(
            "{} is signer-only: it has no wallet to spend.",
            k.key_id
        )),
        _ => None,
    }
}

impl App {
    /// `s` / `S`: open the form for the selected key.
    pub(super) fn open_send(&mut self, flow: Flow) {
        let Some(k) = self.selected_key() else { return };
        if let Some(why) = cannot_send(self) {
            self.toast(Level::Bad, why);
            return;
        }
        let key_id = k.key_id.clone();
        self.send = Some(Stage::Form(Form::new(flow, key_id)));
    }

    /// An agent's draft: the form opens filled in, and from there it is a
    /// send like any other (review, confirm, sign by the user).
    pub(super) fn open_send_draft(&mut self, draft: super::agent::SendDraft) {
        self.open_send(Flow::Send);
        if let Some(Stage::Form(f)) = &mut self.send {
            f.to = draft.to;
            f.amount = draft.amount;
            f.memo = draft.memo;
            f.inspect_due = Some(self.now);
            self.agent.focused = false;
            self.toast(
                Level::Info,
                "the agent filled in the send form: review it, then Enter for the dry run",
            );
        }
    }

    pub(super) fn on_send_tick(&mut self, now: Instant) {
        let mut inspect = None;
        match &mut self.send {
            Some(Stage::Form(f)) => {
                if f.inspect_due.is_some_and(|t| now >= t) {
                    f.inspect_due = None;
                    let to = f.to.trim().to_string();
                    if !to.is_empty() {
                        inspect = Some(to);
                    }
                }
            }
            Some(Stage::Running(Running {
                signing: Some(Signing::Keystone(k)),
                ..
            })) => k.advance(now),
            _ => {}
        }
        if let Some(address) = inspect {
            self.act(Action::Inspect(address));
        }
    }

    pub(super) fn on_inspected(
        &mut self,
        address: String,
        r: Result<InspectAddressResponse, String>,
    ) {
        if let Some(Stage::Form(f)) = &mut self.send {
            f.inspect = Some((address, r));
        }
    }

    pub(super) fn on_send_paste(&mut self, text: &str) {
        let now = self.now;
        let mut answer = None;
        match &mut self.send {
            Some(Stage::Form(f)) => {
                if let Some(t) = f.text_mut() {
                    t.push_str(text.trim_end_matches(['\n', '\r']));
                    f.edited(now);
                }
            }
            Some(Stage::Running(Running {
                signing: Some(Signing::Keystone(k)),
                ..
            })) if !k.busy => {
                answer = k.feed(text);
                if answer.is_some() {
                    k.busy = true;
                }
            }
            // A password manager pastes; a trailing newline is not part of it.
            Some(Stage::Running(Running {
                signing:
                    Some(Signing::Passphrase {
                        input, busy: false, ..
                    }),
                ..
            })) => {
                for c in text.trim_end_matches(['\n', '\r']).chars() {
                    if !c.is_control() {
                        input.push(c);
                    }
                }
            }
            _ => {}
        }
        if let Some(cbor) = answer {
            self.act(Action::StopScan);
            self.act(Action::Reply(SendReply::Keystone(cbor)));
        }
    }

    /// Keys while the send modal is open.
    pub(super) fn on_send_key(&mut self, k: KeyEvent) {
        let now = self.now;
        let Some(stage) = self.send.take() else {
            return;
        };
        self.send = match stage {
            Stage::Form(mut f) => match k.code {
                KeyCode::Esc => None,
                KeyCode::Tab | KeyCode::Down => {
                    f.move_focus(1);
                    Some(Stage::Form(f))
                }
                KeyCode::BackTab | KeyCode::Up => {
                    f.move_focus(-1);
                    Some(Stage::Form(f))
                }
                KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                    if matches!(f.focus, Field::Pool | Field::From | Field::ViaTor) =>
                {
                    let step: isize = if k.code == KeyCode::Left { -1 } else { 1 };
                    match f.focus {
                        Field::Pool => {
                            f.out_pool = (f.out_pool as isize + step)
                                .rem_euclid(OUT_POOLS.len() as isize)
                                as usize
                        }
                        Field::From => {
                            f.from = (f.from as isize + step).rem_euclid(FROM_POOLS.len() as isize)
                                as usize
                        }
                        _ => f.via_tor = !f.via_tor,
                    }
                    Some(Stage::Form(f))
                }
                KeyCode::Enter => match f.validate() {
                    Ok(spec) => {
                        self.send_id += 1;
                        self.act(Action::DryRun {
                            id: self.send_id,
                            spec,
                        });
                        Some(Stage::Proposing(f))
                    }
                    Err(e) => {
                        f.error = Some(e);
                        Some(Stage::Form(f))
                    }
                },
                KeyCode::Backspace => {
                    if let Some(t) = f.text_mut() {
                        t.pop();
                        f.edited(now);
                    }
                    Some(Stage::Form(f))
                }
                KeyCode::Char(c) => {
                    if let Some(t) = f.text_mut()
                        && t.len() < 1024
                    {
                        t.push(c);
                        f.edited(now);
                    }
                    Some(Stage::Form(f))
                }
                _ => Some(Stage::Form(f)),
            },
            Stage::Proposing(f) => match k.code {
                // The dry run signs nothing; its answer is dropped.
                KeyCode::Esc => {
                    self.send_id += 1;
                    Some(Stage::Form(f))
                }
                _ => Some(Stage::Proposing(f)),
            },
            Stage::Confirm {
                form,
                spec,
                proposal,
            } => match k.code {
                KeyCode::Enter | KeyCode::Char('y') => {
                    self.send_id += 1;
                    self.act(Action::Execute {
                        id: self.send_id,
                        spec: spec.clone(),
                    });
                    Some(Stage::Running(Running {
                        spec,
                        proposal,
                        progress: vec!["started".into()],
                        txids: Vec::new(),
                        signing: None,
                    }))
                }
                KeyCode::Esc | KeyCode::Char('n') => Some(Stage::Form(form)),
                _ => Some(Stage::Confirm {
                    form,
                    spec,
                    proposal,
                }),
            },
            Stage::Running(mut r) => {
                self.on_signing_key(&mut r, k);
                Some(Stage::Running(r))
            }
            Stage::Done { .. } if matches!(k.code, KeyCode::Enter | KeyCode::Esc) => None,
            other => Some(other),
        };
    }

    fn on_signing_key(&mut self, r: &mut Running, k: KeyEvent) {
        match &mut r.signing {
            Some(Signing::Passphrase {
                input, busy, error, ..
            }) if !*busy => match k.code {
                KeyCode::Esc => {
                    *busy = true;
                    self.act(Action::Reply(SendReply::Cancel));
                }
                KeyCode::Enter if input.len() > 0 => {
                    *busy = true;
                    *error = None;
                    let secret = std::mem::take(input);
                    self.act(Action::Reply(SendReply::Passphrase(secret)));
                }
                KeyCode::Backspace => input.pop(),
                KeyCode::Char(c) => input.push(c),
                _ => {}
            },
            Some(Signing::Keystone(ks)) if !ks.busy => match k.code {
                KeyCode::Esc => {
                    ks.busy = true;
                    self.act(Action::StopScan);
                    self.act(Action::Reply(SendReply::Cancel));
                }
                KeyCode::F(2) if !ks.scanning => {
                    ks.scanning = true;
                    ks.error = None;
                    self.act(Action::ScanCamera {
                        answer: ks.answer,
                        request: ks.payload.clone(),
                    });
                }
                KeyCode::Enter => {
                    let line = std::mem::take(&mut ks.line);
                    if let Some(cbor) = ks.feed(&line) {
                        ks.busy = true;
                        self.act(Action::StopScan);
                        self.act(Action::Reply(SendReply::Keystone(cbor)));
                    }
                }
                KeyCode::Backspace => {
                    ks.line.pop();
                }
                KeyCode::Char(c) => ks.line.push(c),
                _ => {}
            },
            _ => {}
        }
    }

    pub(super) fn on_scan_progress(&mut self, fragments: (usize, usize)) {
        if let Some(Stage::Running(Running {
            signing: Some(Signing::Keystone(ks)),
            ..
        })) = &mut self.send
        {
            ks.scan_progress = fragments;
        }
    }

    /// The camera's answer (or why it gave none).
    pub(super) fn on_scanned(&mut self, r: Result<Vec<u8>, String>) {
        if let Some(Stage::Running(Running {
            signing: Some(Signing::Keystone(ks)),
            ..
        })) = &mut self.send
        {
            ks.scanning = false;
            match r {
                Ok(cbor) if !ks.busy => {
                    ks.busy = true;
                    self.act(Action::Reply(SendReply::Keystone(cbor)));
                }
                Ok(_) => {}
                Err(e) => ks.error = Some(format!("camera: {e}; paste the frames instead")),
            }
        }
    }

    pub(super) fn on_send_update(&mut self, id: u64, u: SendUpdate) {
        if id != self.send_id {
            return;
        }
        let now = self.now;
        let Some(stage) = self.send.take() else {
            return;
        };
        self.send = match (stage, u) {
            (Stage::Proposing(form), SendUpdate::DryRun(Ok(proposal))) => match form.validate() {
                Ok(spec) => Some(Stage::Confirm {
                    form,
                    spec,
                    proposal,
                }),
                Err(e) => {
                    let mut form = form;
                    form.error = Some(e);
                    Some(Stage::Form(form))
                }
            },
            (Stage::Proposing(mut form), SendUpdate::DryRun(Err(e))) => {
                form.error = Some(e);
                Some(Stage::Form(form))
            }
            (Stage::Running(mut r), u) => {
                self.on_running(&mut r, u, now).or(Some(Stage::Running(r)))
            }
            (other, _) => Some(other),
        };
    }

    /// One update of the real request; `Some` replaces the stage.
    fn on_running(&mut self, r: &mut Running, u: SendUpdate, now: Instant) -> Option<Stage> {
        match u {
            SendUpdate::Proving { pool, done, total } => {
                r.progress.push(if done == 0 {
                    format!("proving {total} {} action(s)…", pool_name(pool))
                } else {
                    "proven".to_string()
                });
            }
            SendUpdate::NeedPassphrase { key_id } => {
                r.progress.push("waiting for the passphrase".into());
                r.signing = Some(Signing::Passphrase {
                    key_id,
                    input: Secret::default(),
                    busy: false,
                    error: None,
                });
            }
            SendUpdate::PassphraseRefused(e) => {
                if let Some(Signing::Passphrase { busy, error, .. }) = &mut r.signing {
                    *busy = false;
                    *error = Some(e);
                }
            }
            SendUpdate::NeedKeystone(req) => match KeystoneSign::new(&req, now) {
                Ok(ks) => {
                    r.progress.push("waiting for the Keystone".into());
                    r.signing = Some(Signing::Keystone(Box::new(ks)));
                }
                Err(e) => r.progress.push(format!("cannot show the request: {e}")),
            },
            SendUpdate::KeystoneRefused(e) => {
                if let Some(Signing::Keystone(ks)) = &mut r.signing {
                    ks.busy = false;
                    ks.asm = Assembler::new();
                    ks.error = Some(format!(
                        "the daemon refused the answer: {e}; redo it on the device and scan again"
                    ));
                }
            }
            SendUpdate::Signed(step) => {
                r.signing = None;
                r.progress.push(format!("step {step} signed"));
            }
            SendUpdate::Broadcast { step, txid } => {
                r.progress.push(format!("step {step} broadcast: {txid}"));
                r.txids.push(txid);
            }
            SendUpdate::TexQueued { step1, step2 } => {
                r.progress.push(format!(
                    "tex pending (step 2 of 2): {step1} then {step2}; the queue finishes it"
                ));
            }
            SendUpdate::Ended(result) => {
                let verb = r.spec.flow.verb();
                let txids = std::mem::take(&mut r.txids);
                match &result {
                    Ok(()) if !txids.is_empty() => {
                        self.toast(
                            Level::Good,
                            format!("{verb}: broadcast {}", short_list(&txids)),
                        );
                        self.act(Action::Refresh);
                    }
                    Ok(()) => {}
                    Err(e) => self.toast(Level::Bad, format!("{verb} failed: {e}")),
                }
                return Some(Stage::Done {
                    verb,
                    txids,
                    error: result.err(),
                });
            }
            SendUpdate::DryRun(_) => {}
        }
        None
    }
}

fn short_list(txids: &[String]) -> String {
    txids
        .iter()
        .map(|t| format!("{}…", &t[..t.len().min(12)]))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

fn field_line<'a>(
    label: &'a str,
    value: String,
    focused: bool,
    hint: Option<Span<'a>>,
) -> Line<'a> {
    let mut spans = vec![
        Span::styled(
            format!("{label:>10}  "),
            if focused { key_style() } else { dim() },
        ),
        Span::styled(
            value,
            if focused {
                Style::new().add_modifier(Modifier::UNDERLINED)
            } else {
                Style::new()
            },
        ),
    ];
    if focused {
        spans.push(Span::styled("▏", key_style()));
    }
    if let Some(h) = hint {
        spans.push(Span::raw("  "));
        spans.push(h);
    }
    Line::from(spans)
}

fn inspect_hint(f: &Form) -> Option<Span<'static>> {
    match f.inspected()? {
        Ok(i) if !i.valid => Some(Span::styled(format!("invalid: {}", i.error), bad())),
        Ok(i) if i.transparent_source_only => Some(Span::styled(
            "tex: paid from transparent funds in two steps",
            warn(),
        )),
        Ok(i) => {
            let receivers: Vec<&str> = i.receivers.iter().map(|r| pool_name(r.pool())).collect();
            Some(Span::styled(format!("✓ {}", receivers.join(", ")), ok()))
        }
        Err(e) => Some(Span::styled(e.clone(), dim())),
    }
}

fn form_lines(f: &Form) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for field in f.fields() {
        let focused = f.focus == *field;
        let line = match field {
            Field::To => field_line("to", f.to.clone(), focused, inspect_hint(f)),
            Field::Amount => {
                let hint = match parse_amount(&f.amount) {
                    _ if f.amount.is_empty() => Span::styled("1.25, 125000000z or max", dim()),
                    Ok(ParsedAmount::Max) => {
                        Span::styled("everything spendable, less the fee", dim())
                    }
                    Ok(ParsedAmount::Zatoshis(z)) => {
                        Span::styled(format!("{} ZEC", format_zec(z as i64)), ok())
                    }
                    Err(e) => Span::styled(e, bad()),
                };
                field_line("amount", f.amount.clone(), focused, Some(hint))
            }
            Field::Memo => field_line(
                "memo",
                f.memo.clone(),
                focused,
                Some(Span::styled("optional; shielded recipients only", dim())),
            ),
            Field::Pool => field_line(
                "pay into",
                format!("‹ {} ›", OUT_POOLS[f.out_pool].1),
                focused,
                None,
            ),
            Field::From => field_line(
                "spend",
                format!("‹ {} ›", FROM_POOLS[f.from].1),
                focused,
                None,
            ),
            Field::ViaTor => field_line(
                "via Tor",
                if f.via_tor {
                    "[x] broadcast through the fallback over Tor"
                } else {
                    "[ ] broadcast through the node"
                }
                .to_string(),
                focused,
                None,
            ),
            Field::Threshold => field_line(
                "threshold",
                f.threshold.clone(),
                focused,
                Some(Span::styled(
                    "only when transparent funds reach this; empty is any",
                    dim(),
                )),
            ),
        };
        lines.push(line);
    }
    lines.push(Line::default());
    if let Some(e) = &f.error {
        lines.push(Line::styled(e.clone(), bad()));
    }
    lines.push(Line::styled(
        "Tab/↑↓ field · ←→/Space choose · Enter review (dry run) · Esc close",
        dim(),
    ));
    lines
}

fn qr_paragraph(lines: &[String]) -> Paragraph<'static> {
    let style = Style::new().fg(Color::White).bg(Color::Black);
    Paragraph::new(
        lines
            .iter()
            .map(|l| Line::styled(l.clone(), style))
            .collect::<Vec<_>>(),
    )
}

fn draw_keystone(f: &mut Frame, area: Rect, ks: &KeystoneSign) {
    let (w, h) = super::addresses::qr_size(&ks.qr);
    let [qr_area, text_area] = Layout::vertical([
        Constraint::Length(h.min(area.height.saturating_sub(5))),
        Constraint::Min(5),
    ])
    .areas(area);
    if w <= qr_area.width && h <= qr_area.height {
        let x = qr_area.x + (qr_area.width - w) / 2;
        f.render_widget(
            qr_paragraph(&ks.qr),
            Rect {
                x,
                width: w,
                ..qr_area
            },
        );
    }
    let (resolved, total) = ks.asm.progress();
    let protocol = if ks.kind == SignatureKind::KeystoneBatch {
        "batch"
    } else {
        "single-PCZT"
    };
    let mut lines = Vec::new();
    if w > qr_area.width || h > qr_area.height {
        lines.push(Line::styled(
            format!(
                "Enlarge the terminal to at least {}x{} to show the request, or show it from another terminal with `gyges pczt qr-export --session {}`.",
                w + 4,
                h + 12,
                ks.session_id
            ),
            warn(),
        ));
    }
    lines.push(Line::raw(format!(
        "Scan this with the Keystone ({protocol}, {} frame(s)), check the recipients and amounts, approve, then give the answer here:",
        ks.frames.fragment_count()
    )));
    lines.push(Line::from(vec![
        Span::styled("paste the answer's ur: frames", key_style()),
        Span::raw(if cfg!(feature = "camera") {
            " · F2 scan with the camera"
        } else {
            ""
        }),
        Span::raw(" · Esc leave (the session stays open)"),
    ]));
    if ks.scanning {
        let (r, t) = ks.scan_progress;
        lines.push(Line::styled(
            if t > 0 {
                format!("scanning with the camera… {r} of {t} fragments")
            } else {
                "scanning with the camera… point it at the Keystone's answer".to_string()
            },
            warn(),
        ));
    }
    if total > 0 {
        lines.push(Line::styled(
            format!("answer: {resolved} of {total} fragments"),
            ok(),
        ));
    }
    if !ks.line.is_empty() {
        lines.push(Line::raw(format!("> {}", ks.line)));
    }
    if ks.busy {
        lines.push(Line::styled("completing the signature…", dim()));
    }
    if let Some(e) = &ks.error {
        lines.push(Line::styled(e.clone(), bad()));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), text_area);
}

pub fn draw(f: &mut Frame, area: Rect, stage: &Stage) {
    f.render_widget(Clear, area);
    let title = match stage {
        Stage::Form(form) | Stage::Proposing(form) | Stage::Confirm { form, .. } => {
            format!(" {} from {} ", form.flow.verb(), form.key_id)
        }
        Stage::Running(r) => format!(" {} from {} ", r.spec.flow.verb(), r.spec.key_id),
        Stage::Done { verb, .. } => format!(" {verb} "),
    };
    let block = Block::bordered().title(title).border_style(key_style());
    let inner = block.inner(area);
    f.render_widget(block, area);
    match stage {
        Stage::Form(form) => f.render_widget(
            Paragraph::new(form_lines(form)).wrap(Wrap { trim: false }),
            inner,
        ),
        Stage::Proposing(_) => f.render_widget(
            Paragraph::new(Line::styled(
                "Proposing (dry run; nothing is signed)… Esc back",
                dim(),
            )),
            inner,
        ),
        Stage::Confirm { form, proposal, .. } => {
            let mut lines: Vec<Line> = render_proposal(proposal)
                .lines()
                .map(|l| Line::raw(l.to_string()))
                .collect();
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled(
                    format!(
                        "{} {} ZEC in total? ",
                        form.flow.verb(),
                        format_zec(proposal.total_debit)
                    ),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::styled("Enter/y yes · Esc/n back", key_style()),
            ]));
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
        Stage::Running(r) => match &r.signing {
            Some(Signing::Keystone(ks)) => draw_keystone(f, inner, ks),
            sign => {
                let mut lines = vec![
                    Line::styled(
                        format!(
                            "{} ZEC in total, {} ZEC in fees, {} step(s)",
                            format_zec(r.proposal.total_debit),
                            format_zec(r.proposal.total_fee),
                            r.proposal.steps.len()
                        ),
                        Style::new().add_modifier(Modifier::BOLD),
                    ),
                    Line::default(),
                ];
                lines.extend(r.progress.iter().map(|p| Line::raw(p.clone())));
                if let Some(Signing::Passphrase {
                    key_id,
                    input,
                    busy,
                    error,
                }) = sign
                {
                    lines.push(Line::default());
                    lines.push(Line::from(vec![
                        Span::styled(format!("passphrase for {key_id}: "), key_style()),
                        Span::raw("•".repeat(input.len())),
                        Span::styled(if *busy { "" } else { "▏" }, key_style()),
                    ]));
                    if *busy {
                        lines.push(Line::styled("unlocking…", dim()));
                    } else {
                        lines.push(Line::styled(
                            "Enter sign · Esc cancel (nothing is signed). The key is used for this send only.",
                            dim(),
                        ));
                    }
                    if let Some(e) = error {
                        lines.push(Line::styled(e.clone(), bad()));
                    }
                }
                f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
            }
        },
        Stage::Done { txids, error, .. } => {
            let mut lines = Vec::new();
            for t in txids {
                lines.push(Line::from(vec![
                    Span::styled("txid  ", dim()),
                    Span::raw(t.clone()),
                ]));
            }
            match error {
                None => lines.push(Line::styled("Done.", ok())),
                Some(e) => lines.push(Line::styled(e.clone(), bad())),
            }
            lines.push(Line::default());
            lines.push(Line::styled("Enter/Esc close", dim()));
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
    }
}

#[cfg(test)]
#[path = "send_tests.rs"]
mod tests;
