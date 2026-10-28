//! An animated QR loop in the terminal: each frame is redrawn over the
//! previous one with ANSI cursor movement, so the scrollback keeps one code.

use std::io::Write;
use std::time::Duration;

use crate::QrError;
use crate::fountain::Frames;
use crate::render::render_frame;

/// Frames per second a phone or laptop camera keeps up with (Q-K2).
pub const DEFAULT_FPS: u32 = 8;

#[derive(Debug)]
pub struct Animation {
    frames: Frames,
    fps: u32,
}

impl Animation {
    pub fn new(frames: Frames, fps: u32) -> Self {
        Self {
            frames,
            fps: fps.max(1),
        }
    }

    pub fn frames(&self) -> &Frames {
        &self.frames
    }

    /// Draw frames to `out` until `stop` returns true. A single-frame
    /// payload is drawn once and returns at once: there is nothing to
    /// animate, and the caller decides how long it stays on screen.
    pub fn play<W: Write>(
        &mut self,
        out: &mut W,
        mut stop: impl FnMut() -> bool,
    ) -> Result<(), QrError> {
        let period = Duration::from_secs(1) / self.fps;
        let mut drawn_lines = 0;
        while !stop() {
            let qr = render_frame(&self.frames.next_frame()?)?;
            if drawn_lines > 0 {
                // Up to the first line of the previous code, then clear
                // everything below it.
                write!(out, "\x1b[{drawn_lines}A\x1b[J")?;
            }
            out.write_all(qr.as_bytes())?;
            out.flush()?;
            drawn_lines = qr.lines().count();
            if self.frames.is_single() {
                break;
            }
            std::thread::sleep(period);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fountain::tests::Rng;
    use crate::ur_types;

    #[test]
    fn redraws_in_place_until_stopped() {
        let data = Rng::new(3).bytes(2000);
        let frames = Frames::new(ur_types::ZCASH_PCZT, &data, 200).unwrap();
        let mut anim = Animation::new(frames, 1000);
        let mut out = Vec::new();
        let mut ticks = 0;
        anim.play(&mut out, || {
            ticks += 1;
            ticks > 3
        })
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        // Three codes, two cursor-up redraws.
        assert_eq!(s.matches("\x1b[J").count(), 2, "{s}");
        let first_code_lines = s.split("\x1b[").next().unwrap().lines().count();
        assert!(s.contains(&format!("\x1b[{first_code_lines}A")), "{s}");
    }

    #[test]
    fn a_single_frame_is_drawn_once() {
        let frames = Frames::new(ur_types::ZCASH_PCZT, b"tiny", 200).unwrap();
        let mut anim = Animation::new(frames, DEFAULT_FPS);
        let mut out = Vec::new();
        anim.play(&mut out, || false).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains('\x1b'), "{s}");
        assert!(s.contains('█'));
    }
}
