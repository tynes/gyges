//! The send's own connection: the dry run, then the real `SendTransaction`
//! / `ShieldFunds` stream and the answers to its `SignatureRequired`.
//!
//! The passphrase goes to `UnlockKey { session_id }` on the connection that
//! holds the paused stream (interface.md API §6.2): a clone of the client
//! shares its HTTP/2 connection. The connection closes when the send ends,
//! so no unlock outlives it (API §6.3).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gyges_proto::v1::gyges_client::GygesClient;
use gyges_proto::v1::{
    AbortSigningSessionRequest, CompleteKeystoneSignRequest, ErrorReason, SendEvent, SignatureKind,
    SignatureRequired, UnlockKeyRequest, UnlockScope, send_event,
};
use tokio::sync::mpsc;
use tonic::transport::Channel;

use crate::client::Ctx;
use crate::exit::CliError;

use super::app::Event;
use super::send::{ANSWER_ATTEMPTS, Flow, PASSPHRASE_ATTEMPTS, SendReply, SendSpec, SendUpdate};

type Tx = mpsc::UnboundedSender<Event>;

fn msg(s: tonic::Status) -> String {
    CliError::from_status(s).message()
}

fn update(tx: &Tx, id: u64, u: SendUpdate) {
    let _ = tx.send(Event::Send { id, update: u });
}

async fn open(
    c: &mut GygesClient<Channel>,
    spec: &SendSpec,
    dry_run: bool,
) -> Result<tonic::Streaming<SendEvent>, String> {
    let r = match spec.flow {
        Flow::Send => c.send_transaction(spec.send_request(dry_run)).await,
        Flow::Shield => c.shield_funds(spec.shield_request(dry_run)).await,
    };
    Ok(r.map_err(msg)?.into_inner())
}

/// The dry run, on a connection that closes with it.
pub fn dry_run(ctx: &Ctx, tx: &Tx, id: u64, spec: SendSpec) {
    let ctx = ctx.clone();
    let tx = tx.clone();
    tokio::spawn(async move {
        let result = async {
            let mut conn = ctx.connect().await.map_err(|e| e.message())?;
            let mut stream = open(&mut conn.client, &spec, true).await?;
            while let Some(ev) = stream.message().await.map_err(msg)? {
                if let Some(send_event::Event::Proposed(p)) = ev.event {
                    return Ok(p);
                }
            }
            Err("the daemon ended the dry run without a proposal".to_string())
        }
        .await;
        update(&tx, id, SendUpdate::DryRun(result));
    });
}

/// The real request. The returned sender carries the user's answers.
pub fn execute(ctx: &Ctx, tx: &Tx, id: u64, spec: SendSpec) -> mpsc::UnboundedSender<SendReply> {
    let (reply_tx, mut replies) = mpsc::unbounded_channel();
    let ctx = ctx.clone();
    let tx = tx.clone();
    tokio::spawn(async move {
        let result = run(&ctx, &tx, id, &spec, &mut replies).await;
        update(&tx, id, SendUpdate::Ended(result));
    });
    reply_tx
}

async fn run(
    ctx: &Ctx,
    tx: &Tx,
    id: u64,
    spec: &SendSpec,
    replies: &mut mpsc::UnboundedReceiver<SendReply>,
) -> Result<(), String> {
    let mut conn = ctx.connect().await.map_err(|e| e.message())?;
    // Same channel, same connection: what the paused stream needs.
    let mut side = conn.client.clone();
    let mut stream = open(&mut conn.client, spec, false).await?;
    while let Some(ev) = stream.message().await.map_err(msg)? {
        match ev.event {
            Some(send_event::Event::Proposed(_)) | None => {}
            Some(send_event::Event::Proving(p)) => update(
                tx,
                id,
                SendUpdate::Proving {
                    pool: p.pool(),
                    done: p.actions_done,
                    total: p.actions_total,
                },
            ),
            Some(send_event::Event::SignatureRequired(req)) => match req.kind() {
                SignatureKind::KeystoneBatch | SignatureKind::KeystoneSinglePczt => {
                    keystone(&mut side, tx, id, req, replies).await?
                }
                _ => passphrase(&mut side, tx, id, &req, replies).await?,
            },
            Some(send_event::Event::Signed(s)) => update(tx, id, SendUpdate::Signed(s.step)),
            Some(send_event::Event::Broadcast(b)) => update(
                tx,
                id,
                SendUpdate::Broadcast {
                    step: b.step,
                    txid: b.txid,
                },
            ),
            Some(send_event::Event::TexQueued(t)) => update(
                tx,
                id,
                SendUpdate::TexQueued {
                    step1: t.step1_txid,
                    step2: t.step2_txid,
                },
            ),
            Some(send_event::Event::Mined(_)) => {}
        }
    }
    Ok(())
}

async fn abort(c: &mut GygesClient<Channel>, session_id: &str) {
    let _ = c
        .abort_signing_session(AbortSigningSessionRequest {
            session_id: session_id.to_string(),
        })
        .await;
}

async fn passphrase(
    c: &mut GygesClient<Channel>,
    tx: &Tx,
    id: u64,
    req: &SignatureRequired,
    replies: &mut mpsc::UnboundedReceiver<SendReply>,
) -> Result<(), String> {
    update(
        tx,
        id,
        SendUpdate::NeedPassphrase {
            key_id: req.key_id.clone(),
        },
    );
    let mut attempt = 0;
    loop {
        match replies.recv().await {
            Some(SendReply::Passphrase(secret)) => {
                attempt += 1;
                let result = c
                    .unlock_key(UnlockKeyRequest {
                        key_id: req.key_id.clone(),
                        passphrase: secret.expose().to_string(),
                        ttl_secs: 0,
                        session_id: req.session_id.clone(),
                        scope: UnlockScope::Unspecified as i32,
                    })
                    .await;
                drop(secret);
                match result {
                    Ok(_) => return Ok(()),
                    Err(s) => {
                        let err = CliError::from_status(s);
                        // Too soon after a wrong one (the per-key back-off,
                        // API §6.3): nothing was checked, so it is no attempt.
                        if let CliError::Daemon(e) = &err
                            && e.reason() == ErrorReason::RateLimited
                        {
                            attempt -= 1;
                            update(tx, id, SendUpdate::PassphraseRefused(err.message()));
                            continue;
                        }
                        let wrong = matches!(&err, CliError::Daemon(e) if e.reason() == ErrorReason::InvalidPassphrase);
                        if wrong && attempt < PASSPHRASE_ATTEMPTS {
                            update(
                                tx,
                                id,
                                SendUpdate::PassphraseRefused(format!(
                                    "wrong passphrase ({attempt} of {PASSPHRASE_ATTEMPTS})"
                                )),
                            );
                            continue;
                        }
                        abort(c, &req.session_id).await;
                        return Err(err.message());
                    }
                }
            }
            Some(SendReply::Keystone(_)) => {}
            Some(SendReply::Cancel) | None => {
                abort(c, &req.session_id).await;
                return Err("cancelled: nothing was signed".into());
            }
        }
    }
}

async fn keystone(
    c: &mut GygesClient<Channel>,
    tx: &Tx,
    id: u64,
    req: SignatureRequired,
    replies: &mut mpsc::UnboundedReceiver<SendReply>,
) -> Result<(), String> {
    let session_id = req.session_id.clone();
    let left_open = || {
        format!(
            "the Keystone session is left open: complete it with `gyges pczt qr-import --session {session_id}` (frames again: `gyges pczt qr-export --session {session_id}`)"
        )
    };
    update(tx, id, SendUpdate::NeedKeystone(Box::new(req)));
    let mut attempt = 0;
    loop {
        match replies.recv().await {
            Some(SendReply::Keystone(payload)) => {
                attempt += 1;
                let result = c
                    .complete_keystone_sign(CompleteKeystoneSignRequest {
                        session_id: session_id.clone(),
                        payload,
                    })
                    .await;
                match result {
                    Ok(_) => return Ok(()),
                    Err(s) => {
                        let err = CliError::from_status(s);
                        match &err {
                            CliError::Daemon(e)
                                if e.reason() == ErrorReason::HardwareSigner
                                    && attempt < ANSWER_ATTEMPTS =>
                            {
                                update(tx, id, SendUpdate::KeystoneRefused(e.detail.clone()));
                            }
                            _ => return Err(format!("{}; {}", err.message(), left_open())),
                        }
                    }
                }
            }
            Some(SendReply::Passphrase(_)) => {}
            Some(SendReply::Cancel) | None => return Err(left_open()),
        }
    }
}

/// Read the device's answer with the first camera until `stop` is set.
/// Progress and the answer come back as events.
#[cfg(feature = "camera")]
pub fn scan(tx: &Tx, answer: &'static str, request: Vec<u8>, stop: Arc<AtomicBool>) {
    let tx = tx.clone();
    tokio::task::spawn_blocking(move || {
        let result = (|| {
            let mut camera = gyges_qr::camera::Camera::open(None).map_err(|e| e.to_string())?;
            let progress_tx = tx.clone();
            gyges_qr::scan_answer(
                &mut camera,
                answer,
                Some(request),
                std::time::Duration::from_secs(120),
                || stop.load(Ordering::Relaxed),
                |p| {
                    let _ = progress_tx.send(Event::ScanProgress(p.fragments));
                },
            )
            .map_err(|e| e.to_string())
        })();
        if !stop.load(Ordering::Relaxed) {
            let _ = tx.send(Event::Scanned(result));
        }
    });
}

/// This build has no camera.
#[cfg(not(feature = "camera"))]
pub fn scan(tx: &Tx, _answer: &'static str, _request: Vec<u8>, stop: Arc<AtomicBool>) {
    let _ = stop.load(Ordering::Relaxed);
    let _ = tx.send(Event::Scanned(Err(
        "this gyges was built without the camera (`--features camera`)".into(),
    )));
}
