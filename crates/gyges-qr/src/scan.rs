//! Reading a Keystone's answer from a camera:
//! decode the QR codes in each greyscale frame and feed the `ur:` ones to an
//! [`Assembler`] until the answer reassembles.
//!
//! A camera sees whatever is in front of it, so the scanner keeps only
//! frames of the expected answer type (an [`Assembler`] locks onto the type
//! of its first frame). It starts over after a run of frames that do not
//! fit the message it is assembling, and drops a completed message that is
//! the request itself: for the single-PCZT protocol the request and the
//! answer are both `zcash-pczt`, and the camera may have caught the
//! terminal before the device.
//!
//! The camera itself is behind the `camera` feature (module `camera`);
//! everything here is plain Rust that tests drive with synthetic frames.

use std::time::{Duration, Instant};

use crate::QrError;
use crate::fountain::{Assembler, ur_type_of};

/// One greyscale frame, row-major, one byte per pixel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LumaFrame {
    pub width: usize,
    pub height: usize,
    pub data: Vec<u8>,
}

/// Where frames come from: a camera, or a test.
pub trait FrameSource {
    /// The next frame; an error ends the scan.
    fn next_frame(&mut self) -> Result<LumaFrame, QrError>;
}

/// Frames wider than this are downscaled before detection: a QR code on a
/// device screen needs no more, and detection time grows with the area.
const MAX_WIDTH: usize = 960;

/// Consecutive frames that do not fit the message being assembled before
/// the scanner starts over with a fresh one.
const RESET_AFTER: u32 = 3;

/// The text of every QR code in `frame`. When nothing decodes, the frame is
/// tried mirrored too, as some webcams deliver it.
pub fn decode(frame: &LumaFrame) -> Vec<String> {
    let found = decode_once(frame, false);
    if !found.is_empty() {
        return found;
    }
    decode_once(frame, true)
}

fn decode_once(frame: &LumaFrame, mirror: bool) -> Vec<String> {
    if frame.width == 0 || frame.height == 0 || frame.data.len() < frame.width * frame.height {
        return Vec::new();
    }
    let step = frame.width.div_ceil(MAX_WIDTH).max(1);
    let (w, h) = (frame.width / step, frame.height / step);
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
        let sx = if mirror { w - 1 - x } else { x } * step;
        frame.data[y * step * frame.width + sx]
    });
    img.detect_grids()
        .into_iter()
        .filter_map(|g| g.decode().ok().map(|(_, text)| text))
        .collect()
}

/// What a scan has seen so far, for a progress line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub frames: u64,
    /// Codes of the expected type taken.
    pub taken: u64,
    /// `(resolved, total)` fragments of the message being assembled.
    pub fragments: (usize, usize),
}

/// Assembles one answer of `expected` type from decoded QR texts.
#[derive(Debug)]
pub struct Scanner {
    expected: String,
    request: Option<Vec<u8>>,
    asm: Assembler,
    misfits: u32,
    progress: Progress,
}

impl Scanner {
    /// `request` is the payload the device was shown; a completed message
    /// equal to it is the camera reading the request back, and is dropped.
    pub fn new(expected: &str, request: Option<Vec<u8>>) -> Self {
        Self {
            expected: expected.to_ascii_lowercase(),
            request,
            asm: Assembler::new(),
            misfits: 0,
            progress: Progress::default(),
        }
    }

    pub fn progress(&self) -> Progress {
        self.progress
    }

    /// Take one decoded text. `Some(payload)` once the answer is complete.
    pub fn take(&mut self, text: &str) -> Option<Vec<u8>> {
        let frame = text.trim().to_ascii_lowercase();
        if ur_type_of(&frame) != Some(self.expected.as_str()) {
            return None;
        }
        self.progress.taken += 1;
        if self.asm.receive(&frame).is_err() {
            self.misfits += 1;
            if self.misfits >= RESET_AFTER {
                self.asm = Assembler::new();
                self.misfits = 0;
                let _ = self.asm.receive(&frame);
            }
        } else {
            self.misfits = 0;
        }
        self.progress.fragments = self.asm.progress();
        if !self.asm.is_complete() {
            return None;
        }
        let message = self.asm.message().ok().flatten().map(|(_, m)| m);
        self.asm = Assembler::new();
        self.progress.fragments = (0, 0);
        match message {
            Some(m) if Some(&m) == self.request.as_ref() => None,
            other => other,
        }
    }

    /// Decode `frame` and take every code in it.
    pub fn feed(&mut self, frame: &LumaFrame) -> Option<Vec<u8>> {
        self.progress.frames += 1;
        decode(frame).iter().find_map(|t| self.take(t))
    }
}

/// Read frames from `source` until an answer of `expected` type
/// reassembles, `stop` returns true, or `timeout` passes. `progress` is
/// called after every frame.
pub fn scan_answer(
    source: &mut impl FrameSource,
    expected: &str,
    request: Option<Vec<u8>>,
    timeout: Duration,
    mut stop: impl FnMut() -> bool,
    mut progress: impl FnMut(Progress),
) -> Result<Vec<u8>, ScanEnd> {
    let deadline = Instant::now() + timeout;
    let mut scanner = Scanner::new(expected, request);
    loop {
        if stop() {
            return Err(ScanEnd::Stopped);
        }
        if Instant::now() >= deadline {
            return Err(ScanEnd::TimedOut(scanner.progress()));
        }
        let frame = source.next_frame().map_err(ScanEnd::Source)?;
        let done = scanner.feed(&frame);
        progress(scanner.progress());
        if let Some(answer) = done {
            return Ok(answer);
        }
    }
}

/// Why a scan ended without an answer.
#[derive(Debug, thiserror::Error)]
pub enum ScanEnd {
    #[error("the scan was stopped")]
    Stopped,
    #[error(
        "no complete answer within the time allowed ({} frames read, {} codes of the answer's type)",
        .0.frames,
        .0.taken
    )]
    TimedOut(Progress),
    #[error("the camera failed: {0}")]
    Source(QrError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fountain::Frames;
    use crate::fountain::tests::Rng;
    use crate::ur_types;
    use qrcode::{Color, EcLevel, QrCode};

    /// A camera frame: `text`'s QR code (uppercased, as the device shows a
    /// `ur:` frame), `scale` pixels per module, at (`x`, `y`) in a
    /// `w`×`h` frame of mid-grey noise, with a light quiet zone.
    fn shot(
        text: &str,
        w: usize,
        h: usize,
        x: usize,
        y: usize,
        scale: usize,
        rng: &mut Rng,
    ) -> LumaFrame {
        let code =
            QrCode::with_error_correction_level(text.to_ascii_uppercase(), EcLevel::L).unwrap();
        let n = code.width();
        let colors = code.to_colors();
        let mut data: Vec<u8> = (0..w * h).map(|_| 90 + (rng.next() % 60) as u8).collect();
        let quiet = 4 * scale;
        for py in y.saturating_sub(quiet)..(y + n * scale + quiet).min(h) {
            for px in x.saturating_sub(quiet)..(x + n * scale + quiet).min(w) {
                data[py * w + px] = 235;
            }
        }
        for (i, c) in colors.iter().enumerate() {
            if *c == Color::Dark {
                let (mx, my) = (i % n, i / n);
                for dy in 0..scale {
                    for dx in 0..scale {
                        data[(y + my * scale + dy) * w + x + mx * scale + dx] = 20;
                    }
                }
            }
        }
        LumaFrame {
            width: w,
            height: h,
            data,
        }
    }

    fn blank(w: usize, h: usize) -> LumaFrame {
        LumaFrame {
            width: w,
            height: h,
            data: vec![128; w * h],
        }
    }

    fn mirrored(f: &LumaFrame) -> LumaFrame {
        let mut data = f.data.clone();
        for row in data.chunks_mut(f.width) {
            row.reverse();
        }
        LumaFrame { data, ..f.clone() }
    }

    struct Replay(std::vec::IntoIter<LumaFrame>);

    impl FrameSource for Replay {
        fn next_frame(&mut self) -> Result<LumaFrame, QrError> {
            self.0
                .next()
                .ok_or_else(|| QrError::Ur("the recording ended".into()))
        }
    }

    fn frames_of(ur_type: &'static str, data: &[u8], len: usize, n: usize) -> Vec<String> {
        let mut f = Frames::new(ur_type, data, len).unwrap();
        (0..n).map(|_| f.next_frame().unwrap()).collect()
    }

    #[test]
    fn a_code_in_a_noisy_frame_decodes_mirrored_too() {
        let mut rng = Rng::new(1);
        let text = "ur:zcash-batch-sig-result/lfaohdcxbsrnfz";
        let f = shot(text, 640, 480, 200, 90, 6, &mut rng);
        assert_eq!(decode(&f), vec![text.to_ascii_uppercase()]);
        assert_eq!(decode(&mirrored(&f)), vec![text.to_ascii_uppercase()]);
        // Large frames are downscaled first and still decode.
        let big = shot(text, 1920, 1080, 700, 300, 12, &mut rng);
        assert_eq!(decode(&big), vec![text.to_ascii_uppercase()]);
        assert!(decode(&blank(640, 480)).is_empty());
    }

    /// The single-PCZT case: request and answer share the `zcash-pczt`
    /// type. The camera first sees blank frames, an unrelated code and the
    /// request (its frames, then the request complete, which is dropped);
    /// then the answer's fountain parts out of order and repeated.
    #[test]
    fn the_answer_assembles_past_noise_and_the_echoed_request() {
        let mut rng = Rng::new(2);
        let request = rng.bytes(700);
        let answer = rng.bytes(900);
        let mut shots = vec![blank(640, 480)];
        shots.push(shot(
            "https://example.com/not-ur",
            640,
            480,
            40,
            40,
            5,
            &mut rng,
        ));
        shots.push(shot(
            &frames_of(ur_types::ZCASH_SIGN_BATCH, &request, 100, 1)[0],
            640,
            480,
            100,
            60,
            4,
            &mut rng,
        ));
        for f in frames_of(ur_types::ZCASH_PCZT, &request, 100, 12) {
            shots.push(shot(&f, 640, 480, 120, 40, 4, &mut rng));
        }
        let mut answer_frames = frames_of(ur_types::ZCASH_PCZT, &answer, 100, 30);
        for i in (1..answer_frames.len()).rev() {
            answer_frames.swap(i, rng.below(i + 1));
        }
        for f in answer_frames.iter().chain(answer_frames.iter()) {
            shots.push(blank(640, 480));
            shots.push(shot(
                f,
                640,
                480,
                60 + rng.below(100),
                20 + rng.below(60),
                4,
                &mut rng,
            ));
        }
        let mut seen = 0;
        let got = scan_answer(
            &mut Replay(shots.into_iter()),
            ur_types::ZCASH_PCZT,
            Some(request.clone()),
            Duration::from_secs(60),
            || false,
            |p| seen = p.frames,
        )
        .unwrap();
        assert_eq!(got, answer);
        assert!(seen > 15, "{seen}");
    }

    /// Frames of another message of the same type interleaved before the
    /// answer: after a few that do not fit, the scanner starts over.
    #[test]
    fn a_stale_message_is_abandoned_for_the_new_one() {
        let mut rng = Rng::new(3);
        let stale = frames_of(ur_types::ZCASH_PCZT, &rng.bytes(800), 100, 3);
        let answer = rng.bytes(800);
        let mut s = Scanner::new(ur_types::ZCASH_PCZT, None);
        for f in &stale {
            assert!(s.take(f).is_none());
        }
        let mut got = None;
        for f in frames_of(ur_types::ZCASH_PCZT, &answer, 100, 40) {
            if let Some(m) = s.take(&f) {
                got = Some(m);
                break;
            }
        }
        assert_eq!(got, Some(answer));
    }

    #[test]
    fn a_single_frame_answer_and_the_scan_ends() {
        let mut rng = Rng::new(4);
        let answer = rng.bytes(60);
        let frame = &frames_of(ur_types::ZCASH_BATCH_SIG_RESULT, &answer, 200, 1)[0];
        let mut s = Scanner::new(ur_types::ZCASH_BATCH_SIG_RESULT, None);
        assert_eq!(
            s.feed(&shot(frame, 640, 480, 150, 100, 6, &mut rng)),
            Some(answer)
        );

        let blanks = || Replay(vec![blank(64, 48); 50].into_iter());
        let mut calls = 0;
        let end = scan_answer(
            &mut blanks(),
            ur_types::ZCASH_PCZT,
            None,
            Duration::from_secs(60),
            || {
                calls += 1;
                calls > 3
            },
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(end, ScanEnd::Stopped), "{end}");
        let end = scan_answer(
            &mut blanks(),
            ur_types::ZCASH_PCZT,
            None,
            Duration::ZERO,
            || false,
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(end, ScanEnd::TimedOut(_)), "{end}");
        let end = scan_answer(
            &mut Replay(Vec::new().into_iter()),
            ur_types::ZCASH_PCZT,
            None,
            Duration::from_secs(60),
            || false,
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(end, ScanEnd::Source(_)), "{end}");
    }
}
