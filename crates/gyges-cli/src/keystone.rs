//! The CLI's half of a Keystone signature (API.md §4.3, CLI_SPEC.md §2.6):
//! show the device the daemon's request as an animated QR code, read the
//! device's answer back as `ur:` frames, and hand it to
//! `CompleteKeystoneSign`.
//!
//! On a terminal `tx send` and `tx shield` do it in place: the request
//! loops until Enter, then the answer is read with the camera (feature
//! `camera`, unless `GYGES_NO_CAMERA` is set), falling back to its frames
//! pasted one per line (a phone's QR reader gives them as text). Without a
//! terminal, or with `--qr-out`, the
//! frames are printed or written and the command exits 4 leaving the
//! session open: `pczt qr-export --session` shows them again and
//! `pczt qr-import --session` completes it.

use std::io::{BufRead as _, IsTerminal as _};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::anyhow;
use gyges_proto::v1::{
    CompleteKeystoneSignRequest, CompleteKeystoneSignResponse, ErrorReason, GygesError,
    SignatureKind, SignatureRequired, complete_keystone_sign_response,
};
use gyges_qr::{Animation, Assembler, DEFAULT_FPS, DEFAULT_FRAGMENT_LEN, Frames};

use crate::client::Ctx;
use crate::exit::CliError;

/// How many answers a terminal user may try before the command gives up
/// (the session stays open for `pczt qr-import --session`).
const ANSWER_ATTEMPTS: u32 = 3;

/// The UR type of the request for `kind`, and of the answer it expects.
pub(crate) fn ur_types(kind: SignatureKind) -> Result<(&'static str, &'static str), CliError> {
    match kind {
        SignatureKind::KeystoneBatch => Ok((
            gyges_qr::ur_types::ZCASH_SIGN_BATCH,
            gyges_qr::ur_types::ZCASH_BATCH_SIG_RESULT,
        )),
        SignatureKind::KeystoneSinglePczt => Ok((
            gyges_qr::ur_types::ZCASH_PCZT,
            gyges_qr::ur_types::ZCASH_PCZT,
        )),
        other => Err(anyhow!("not a Keystone signature kind: {other:?}").into()),
    }
}

/// The request's frames.
pub(crate) fn frames(kind: SignatureKind, payload: &[u8]) -> Result<Frames, CliError> {
    let (request, _) = ur_types(kind)?;
    Frames::new(request, payload, DEFAULT_FRAGMENT_LEN).map_err(|e| CliError::Other(e.into()))
}

/// Every fragment once, which is enough to reassemble: what `--qr-out` and
/// a non-terminal print, one per line.
pub(crate) fn frame_lines(mut frames: Frames) -> Result<Vec<String>, CliError> {
    (0..frames.fragment_count())
        .map(|_| frames.next_frame().map_err(|e| CliError::Other(e.into())))
        .collect()
}

/// Loop the frames on stderr until the user presses Enter; Ctrl-C is
/// `Cancelled`. (Once the stream has been followed, tokio owns SIGINT, so
/// every blocking prompt here races Ctrl-C itself.)
pub(crate) async fn animate_until_enter(frames: Frames, fps: u32) -> Result<(), CliError> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        flag.store(true, Ordering::Relaxed);
    });
    let halt = stop.clone();
    let play = tokio::task::spawn_blocking(move || {
        let mut anim = Animation::new(frames, fps);
        let mut err = std::io::stderr();
        let single = anim.frames().is_single();
        anim.play(&mut err, || stop.load(Ordering::Relaxed))?;
        if single {
            // Drawn once; it stays on screen until Enter.
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        Ok::<_, gyges_qr::QrError>(())
    });
    tokio::select! {
        played = play => played
            .map_err(|e| CliError::Other(e.into()))?
            .map_err(|e| CliError::Other(e.into())),
        _ = tokio::signal::ctrl_c() => {
            halt.store(true, Ordering::Relaxed);
            Err(CliError::Cancelled)
        }
    }
}

/// [`read_answer`], or `Cancelled` on Ctrl-C.
async fn read_answer_or_cancel(answer: &'static str) -> Result<Vec<u8>, CliError> {
    let read = tokio::task::spawn_blocking(move || read_answer(answer));
    tokio::select! {
        got = read => got.map_err(|e| CliError::Other(e.into()))?,
        _ = tokio::signal::ctrl_c() => Err(CliError::Cancelled),
    }
}

/// Wait for Enter after `prompt`; `Cancelled` on Ctrl-C or end of input.
async fn wait_for_enter(prompt: &str) -> Result<(), CliError> {
    eprintln!("{prompt}");
    let read = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).map(|n| n > 0)
    });
    tokio::select! {
        got = read => match got.map_err(|e| CliError::Other(e.into()))?? {
            true => Ok(()),
            false => Err(CliError::Cancelled),
        },
        _ = tokio::signal::ctrl_c() => Err(CliError::Cancelled),
    }
}

/// Assemble `answer` type frames from `lines`; an incomplete or foreign set
/// is exit 6.
pub(crate) fn assemble<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    answer: &str,
) -> Result<Vec<u8>, CliError> {
    let mut asm = Assembler::new();
    for line in lines {
        for frame in line.split_whitespace() {
            asm.receive(frame)
                .map_err(|e| CliError::invalid(format!("not the device's answer: {e}")))?;
        }
    }
    finish(&asm, answer).map_err(CliError::invalid)
}

fn finish(asm: &Assembler, answer: &str) -> Result<Vec<u8>, String> {
    match asm.ur_type() {
        None => return Err(format!("no ur:{answer} frame given")),
        Some(t) if t != answer => {
            return Err(format!(
                "expected the device's ur:{answer} answer, got ur:{t} (is that the request?)"
            ));
        }
        Some(_) => {}
    }
    if !asm.is_complete() {
        let (resolved, total) = asm.progress();
        return Err(format!(
            "the answer is incomplete ({resolved} of {total} fragments); pass every frame"
        ));
    }
    asm.message()
        .map_err(|e| e.to_string())?
        .map(|(_, cbor)| cbor)
        .ok_or_else(|| "the answer is incomplete".to_string())
}

/// Read the answer's frames from the terminal, one per line, until they
/// reassemble.
fn read_answer(answer: &str) -> Result<Vec<u8>, CliError> {
    eprintln!(
        "Scan the device's answer (a phone's QR reader gives the ur:{answer} frames as text) and \
         paste them here, one per line:"
    );
    let mut asm = Assembler::new();
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        let Some(line) = lines.next() else {
            return Err(CliError::Cancelled);
        };
        for frame in line?.split_whitespace() {
            if let Err(e) = asm.receive(frame) {
                eprintln!("  ignored: {e}");
            }
        }
        if asm.is_complete() {
            return finish(&asm, answer).map_err(CliError::invalid);
        }
        let (resolved, total) = asm.progress();
        if total > 0 {
            eprintln!("  {resolved} of {total} fragments; keep pasting");
        }
    }
}

/// `CompleteKeystoneSign` on a connection of its own.
pub(crate) async fn complete(
    ctx: &Ctx,
    session_id: &str,
    payload: Vec<u8>,
) -> Result<CompleteKeystoneSignResponse, CliError> {
    let mut conn = ctx.connect().await?;
    Ok(conn
        .client
        .complete_keystone_sign(CompleteKeystoneSignRequest {
            session_id: session_id.to_string(),
            payload,
        })
        .await?
        .into_inner())
}

/// The txids a completion broadcast.
pub(crate) fn txids(resp: &CompleteKeystoneSignResponse) -> Vec<String> {
    match &resp.result {
        Some(complete_keystone_sign_response::Result::Broadcast(t)) => t.txids.clone(),
        _ => Vec::new(),
    }
}

/// Exit 4 naming the session and how to finish it.
fn left_open(key: &str, session_id: &str, how: &str) -> CliError {
    CliError::Daemon(
        GygesError::new(
            ErrorReason::SignatureRequired,
            format!(
                "a Keystone signature is required: {how}, then complete it with \
                 `gyges pczt qr-import --session {session_id}` (frames again: \
                 `gyges pczt qr-export --session {session_id}`)"
            ),
        )
        .with_key(key)
        .with_session(session_id),
    )
}

/// Answer one Keystone `SignatureRequired` of a `tx send` / `tx shield`
/// stream. `Ok` once the session is completed: the stream then carries the
/// `Signed` and `Broadcast` events.
pub(crate) async fn satisfy(
    ctx: &Ctx,
    key: &str,
    req: &SignatureRequired,
    qr_out: Option<&Path>,
) -> Result<(), CliError> {
    let kind = req.kind();
    let (_, answer) = ur_types(kind)?;
    let frames = frames(kind, &req.payload)?;
    let session_id = req.session_id.as_str();
    let protocol = match kind {
        SignatureKind::KeystoneBatch => "batch",
        _ => "single-PCZT",
    };

    if let Some(path) = qr_out {
        let lines = frame_lines(frames)?;
        std::fs::write(path, lines.join("\n") + "\n")?;
        return Err(left_open(
            key,
            session_id,
            &format!("{} frame(s) written to {}", lines.len(), path.display()),
        ));
    }
    if ctx.json || !ctx.prompter.interactive() {
        if !ctx.json {
            // The frames on stdout, for a phone or a later `qr-export`.
            for line in frame_lines(frames)? {
                println!("{line}");
            }
        }
        return Err(left_open(
            key,
            session_id,
            "show the device the frames above (or the payload in the JSON event)",
        ));
    }

    eprintln!(
        "Sign on the Keystone ({protocol} protocol, {} frame(s)): scan the QR code below with the \
         device, check that it shows the recipients and amounts above, approve, then press Enter.",
        frames.fragment_count()
    );
    if let Err(e) = animate_until_enter(frames, DEFAULT_FPS).await {
        return Err(match e {
            CliError::Cancelled => left_open(key, session_id, "the request was not scanned"),
            other => other,
        });
    }
    let mut last = None;
    let mut use_camera = camera_wanted();
    for attempt in 1..=ANSWER_ATTEMPTS {
        let scanned = if use_camera {
            match scan(None, answer, &req.payload, INLINE_SCAN_TIMEOUT).await {
                Ok(c) => Some(c),
                Err(reason) => {
                    eprintln!("camera: {}; paste the frames instead", reason.message());
                    use_camera = false;
                    None
                }
            }
        } else {
            None
        };
        let cbor = match scanned {
            Some(c) => Ok(c),
            None => read_answer_or_cancel(answer).await,
        };
        let cbor = match cbor {
            Ok(c) => c,
            Err(CliError::Cancelled) => {
                return Err(left_open(key, session_id, "no answer was read"));
            }
            Err(e) => {
                eprintln!("{}", e.message());
                last = Some(e);
                continue;
            }
        };
        match complete(ctx, session_id, cbor).await {
            Ok(_) => return Ok(()),
            Err(CliError::Daemon(e))
                if e.reason() == ErrorReason::HardwareSigner && attempt < ANSWER_ATTEMPTS =>
            {
                eprintln!(
                    "the daemon refused the answer: {}; scan the device again",
                    e.detail
                );
                last = Some(CliError::Daemon(e));
                if use_camera {
                    // The device most likely still shows the refused
                    // answer; scan only once the user has redone it.
                    if wait_for_enter("Redo it on the device, then press Enter to scan again.")
                        .await
                        .is_err()
                    {
                        return Err(left_open(key, session_id, "no answer was accepted"));
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| left_open(key, session_id, "no answer was accepted")))
}

/// How long `tx send` scans before falling back to pasted frames.
const INLINE_SCAN_TIMEOUT: Duration = Duration::from_secs(60);

/// The camera is tried when this build has one and `GYGES_NO_CAMERA` is
/// unset.
fn camera_wanted() -> bool {
    cfg!(feature = "camera") && std::env::var_os("GYGES_NO_CAMERA").is_none()
}

/// Read the device's `answer`-type reply with camera `index` (the first
/// when `None`), showing progress on stderr; Ctrl-C stops the scan. `request`
/// is what the device was shown, so the camera catching it is ignored.
#[cfg(feature = "camera")]
pub(crate) async fn scan(
    index: Option<u32>,
    answer: &'static str,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, CliError> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let ctrl_c = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            flag.store(true, Ordering::Relaxed);
        }
    });
    let request = request.to_vec();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut camera = gyges_qr::camera::Camera::open(index).map_err(|e| anyhow!("{e}"))?;
        eprintln!(
            "Point {} at the Keystone's answer (Ctrl-C to stop; GYGES_NO_CAMERA=1 skips the camera).",
            camera.name()
        );
        let mut shown = (0, 0);
        let got = gyges_qr::scan_answer(
            &mut camera,
            answer,
            Some(request),
            timeout,
            || stop.load(Ordering::Relaxed),
            |p| {
                if p.fragments != shown && p.fragments.1 > 0 {
                    shown = p.fragments;
                    eprintln!("  {} of {} fragments", p.fragments.0, p.fragments.1);
                }
            },
        );
        got.map_err(|e| match e {
            gyges_qr::ScanEnd::Stopped => CliError::Cancelled,
            other => anyhow!("{other}").into(),
        })
    })
    .await;
    ctrl_c.abort();
    outcome.map_err(|e| CliError::Other(e.into()))?
}

/// This build has no camera (feature `camera`).
#[cfg(not(feature = "camera"))]
pub(crate) async fn scan(
    _index: Option<u32>,
    _answer: &'static str,
    _request: &[u8],
    _timeout: Duration,
) -> Result<Vec<u8>, CliError> {
    Err(anyhow!(
        "this gyges was built without the camera; rebuild with `--features camera`, or use \
         `gyges pczt qr-import`"
    )
    .into())
}

/// Whether the terminal can show an animation.
pub(crate) fn can_animate(ctx: &Ctx) -> bool {
    !ctx.json && std::io::stderr().is_terminal() && std::io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(ur_type: &'static str, data: &[u8], len: usize) -> Vec<String> {
        frame_lines(Frames::new(ur_type, data, len).unwrap()).unwrap()
    }

    #[test]
    fn the_answer_reassembles_from_pasted_lines() {
        let data: Vec<u8> = (0..900u32).map(|i| (i * 7) as u8).collect();
        let answer = gyges_qr::ur_types::ZCASH_BATCH_SIG_RESULT;
        let mut frames = lines(answer, &data, 100);
        frames.reverse();
        // Two frames on one line, uppercase, as a scanner may give them.
        let pasted = format!("{} {}", frames[0], frames[1]).to_ascii_uppercase();
        let mut all = vec![pasted];
        all.extend(frames[2..].iter().cloned());
        let got = assemble(all.iter().map(String::as_str), answer).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn the_wrong_type_or_too_few_frames_are_exit_6() {
        let data = vec![7u8; 900];
        let request = lines(gyges_qr::ur_types::ZCASH_SIGN_BATCH, &data, 100);
        let err = assemble(
            request.iter().map(String::as_str),
            gyges_qr::ur_types::ZCASH_BATCH_SIG_RESULT,
        )
        .unwrap_err();
        assert!(matches!(err.exit(), crate::exit::Exit::InvalidArgument));
        assert!(
            err.message().contains("is that the request?"),
            "{}",
            err.message()
        );

        let answer = lines(gyges_qr::ur_types::ZCASH_PCZT, &data, 100);
        let err = assemble([answer[0].as_str()], gyges_qr::ur_types::ZCASH_PCZT).unwrap_err();
        assert!(err.message().contains("incomplete"), "{}", err.message());
        let err = assemble(["not a frame"], gyges_qr::ur_types::ZCASH_PCZT).unwrap_err();
        assert!(
            err.message().contains("not the device's answer"),
            "{}",
            err.message()
        );
        let err = assemble([""], gyges_qr::ur_types::ZCASH_PCZT).unwrap_err();
        assert!(
            err.message().contains("no ur:zcash-pczt"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn kinds_map_to_their_request_and_answer_types() {
        assert_eq!(
            ur_types(SignatureKind::KeystoneBatch).unwrap(),
            ("zcash-sign-batch", "zcash-batch-sig-result")
        );
        assert_eq!(
            ur_types(SignatureKind::KeystoneSinglePczt).unwrap(),
            ("zcash-pczt", "zcash-pczt")
        );
        assert!(ur_types(SignatureKind::Passphrase).is_err());
    }
}
