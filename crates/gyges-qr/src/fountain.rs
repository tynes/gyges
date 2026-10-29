//! BC-UR framing over the `ur` crate: a payload that fits in one fragment
//! is a single `ur:<type>/<body>` frame, a longer one an endless
//! fountain-coded sequence `ur:<type>/<seq>-<len>/<body>` from which any
//! large enough subset reassembles the message.

use std::fmt;

use crate::QrError;

/// Fragment length used when the caller has no reason to choose another:
/// small enough that each frame is a QR code a phone or laptop camera reads
/// from a terminal, large enough that a 12 KiB PCZT is about 60 frames.
pub const DEFAULT_FRAGMENT_LEN: usize = 200;

/// The frames of one payload, in display order.
pub struct Frames {
    ur_type: &'static str,
    inner: Inner,
}

enum Inner {
    Single(String),
    Multi(ur::Encoder<'static>),
}

impl fmt::Debug for Frames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frames")
            .field("ur_type", &self.ur_type)
            .field("fragment_count", &self.fragment_count())
            .finish()
    }
}

impl Frames {
    /// Split `message` into frames of at most `max_fragment_len` payload
    /// bytes each. `ur_type` is one of [`crate::ur_types`] or another
    /// lowercase UR type.
    pub fn new(
        ur_type: &'static str,
        message: &[u8],
        max_fragment_len: usize,
    ) -> Result<Self, QrError> {
        if message.is_empty() {
            return Err(QrError::Ur("empty payload".into()));
        }
        let encoder = ur::Encoder::new(message, max_fragment_len, ur_type).map_err(ur_error)?;
        let inner = if encoder.fragment_count() == 1 {
            Inner::Single(ur::try_encode(message, &ur::Type::Custom(ur_type)).map_err(ur_error)?)
        } else {
            Inner::Multi(encoder)
        };
        Ok(Self { ur_type, inner })
    }

    pub fn ur_type(&self) -> &'static str {
        self.ur_type
    }

    /// Number of fragments the message was split into; 1 for a single frame.
    pub fn fragment_count(&self) -> usize {
        match &self.inner {
            Inner::Single(_) => 1,
            Inner::Multi(e) => e.fragment_count(),
        }
    }

    pub fn is_single(&self) -> bool {
        matches!(self.inner, Inner::Single(_))
    }

    /// The next frame to show. A single frame repeats; a multi-part payload
    /// gives its fragments in order and then mixed fountain parts forever.
    pub fn next_frame(&mut self) -> Result<String, QrError> {
        match &mut self.inner {
            Inner::Single(s) => Ok(s.clone()),
            Inner::Multi(e) => e.next_part().map_err(ur_error),
        }
    }
}

/// Collects frames, from a camera, a file or pasted text, until the
/// payload is complete. Frames may arrive in any order, repeated, or with
/// gaps; all must carry the same UR type.
#[derive(Default)]
pub struct Assembler {
    ur_type: Option<String>,
    decoder: ur::Decoder,
    single: Option<Vec<u8>>,
}

impl fmt::Debug for Assembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assembler")
            .field("ur_type", &self.ur_type)
            .field("progress", &self.progress())
            .finish()
    }
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one frame. Surrounding whitespace and letter case are ignored
    /// (scanners often report alphanumeric QR text in uppercase).
    pub fn receive(&mut self, frame: &str) -> Result<(), QrError> {
        let frame = frame.trim().to_ascii_lowercase();
        let ur_type = ur_type_of(&frame).ok_or_else(|| QrError::Ur("not a ur: frame".into()))?;
        if let Some(expected) = &self.ur_type
            && expected != ur_type
        {
            return Err(QrError::MixedTypes {
                expected: expected.clone(),
                got: ur_type.to_string(),
            });
        }
        let (kind, data) = ur::decode(&frame).map_err(ur_error)?;
        match kind {
            ur::ur::Kind::SinglePart => self.single = Some(data),
            ur::ur::Kind::MultiPart => self.decoder.receive(&frame).map_err(ur_error)?,
        }
        self.ur_type = Some(ur_type.to_string());
        Ok(())
    }

    /// The UR type of the frames received so far.
    pub fn ur_type(&self) -> Option<&str> {
        self.ur_type.as_deref()
    }

    /// `(resolved, total)` fragments, for a progress line; `(0, 0)` before
    /// the first frame.
    pub fn progress(&self) -> (usize, usize) {
        if self.single.is_some() {
            return (1, 1);
        }
        match self.decoder.resolved_fragment_count() {
            Some(n) => (n, self.decoder.fragment_count()),
            None => (0, 0),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.single.is_some() || self.decoder.complete()
    }

    /// The UR type and the reassembled payload, once complete.
    pub fn message(&self) -> Result<Option<(String, Vec<u8>)>, QrError> {
        let Some(ur_type) = self.ur_type.clone() else {
            return Ok(None);
        };
        if let Some(data) = &self.single {
            return Ok(Some((ur_type, data.clone())));
        }
        Ok(self
            .decoder
            .message()
            .map_err(ur_error)?
            .map(|data| (ur_type, data)))
    }
}

/// The type of a trimmed, lowercased `ur:<type>/...` frame.
pub(crate) fn ur_type_of(frame: &str) -> Option<&str> {
    frame.strip_prefix("ur:")?.split_once('/').map(|(t, _)| t)
}

fn ur_error(e: ur::ur::Error) -> QrError {
    QrError::Ur(e.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ur_types;

    /// xorshift64*, so the shuffles are the same on every run.
    pub(crate) struct Rng(u64);

    impl Rng {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed | 1)
        }

        pub(crate) fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        pub(crate) fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        pub(crate) fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// docs/testing.md §4: a 12 KiB PCZT at several fragment sizes, the frames
    /// shuffled and a fifth of them dropped, still reassembles exactly.
    #[test]
    fn fountain_round_trip_survives_shuffling_and_loss() {
        let mut rng = Rng::new(0x67_79_67_65_73);
        let pczt = rng.bytes(12 * 1024);
        for fragment_len in [100, 200, 400] {
            let mut frames = Frames::new(ur_types::ZCASH_PCZT, &pczt, fragment_len).unwrap();
            let n = frames.fragment_count();
            assert!(n > 1, "{fragment_len}");
            // Twice the fragment count: the pure fragments, then fountain
            // parts, which is what a camera sees after one full loop.
            let mut sent: Vec<String> = (0..2 * n).map(|_| frames.next_frame().unwrap()).collect();
            for i in (1..sent.len()).rev() {
                sent.swap(i, rng.below(i + 1));
            }
            sent.truncate(sent.len() * 4 / 5);

            let mut asm = Assembler::new();
            for f in &sent {
                if asm.is_complete() {
                    break;
                }
                asm.receive(f).unwrap();
            }
            // Keep feeding fresh fountain parts if the lost fifth left a
            // gap, as a camera would on the next loop.
            let mut extra = 0;
            while !asm.is_complete() {
                asm.receive(&frames.next_frame().unwrap()).unwrap();
                extra += 1;
                assert!(
                    extra < 4 * n,
                    "fragment_len {fragment_len}: never completed"
                );
            }
            let (ur_type, data) = asm.message().unwrap().unwrap();
            assert_eq!(ur_type, ur_types::ZCASH_PCZT);
            assert_eq!(data, pczt, "fragment_len {fragment_len}");
            let (resolved, total) = asm.progress();
            assert_eq!((resolved, total), (n, n));
        }
    }

    #[test]
    fn a_short_payload_is_one_frame_without_indices() {
        let mut frames = Frames::new(ur_types::ZCASH_PCZT, b"tiny", DEFAULT_FRAGMENT_LEN).unwrap();
        assert!(frames.is_single());
        let frame = frames.next_frame().unwrap();
        assert!(frame.starts_with("ur:zcash-pczt/"), "{frame}");
        assert_eq!(frame.matches('/').count(), 1, "{frame}");
        assert_eq!(frames.next_frame().unwrap(), frame);

        let mut asm = Assembler::new();
        assert_eq!(asm.progress(), (0, 0));
        assert!(asm.message().unwrap().is_none());
        // Uppercase and surrounding whitespace, as a scanner may give it.
        asm.receive(&format!("  {}\n", frame.to_ascii_uppercase()))
            .unwrap();
        assert!(asm.is_complete());
        assert_eq!(asm.progress(), (1, 1));
        assert_eq!(
            asm.message().unwrap(),
            Some(("zcash-pczt".to_string(), b"tiny".to_vec()))
        );
    }

    #[test]
    fn frames_of_another_type_or_not_ur_are_refused() {
        let mut rng = Rng::new(7);
        let data = rng.bytes(1000);
        let mut pczt = Frames::new(ur_types::ZCASH_PCZT, &data, 100).unwrap();
        let mut batch = Frames::new(ur_types::ZCASH_SIGN_BATCH, &data, 100).unwrap();
        let mut asm = Assembler::new();
        asm.receive(&pczt.next_frame().unwrap()).unwrap();
        let err = asm.receive(&batch.next_frame().unwrap()).unwrap_err();
        assert!(
            matches!(&err, QrError::MixedTypes { expected, got }
                if expected == "zcash-pczt" && got == "zcash-sign-batch"),
            "{err}"
        );
        assert!(matches!(
            asm.receive("https://example.com"),
            Err(QrError::Ur(_))
        ));
        assert!(matches!(
            asm.receive("ur:zcash-pczt/1-9/notbytewords"),
            Err(QrError::Ur(_))
        ));
        // The refusals left the assembler as it was.
        assert_eq!(asm.ur_type(), Some("zcash-pczt"));
        assert!(!asm.is_complete());
    }

    #[test]
    fn an_empty_payload_is_refused() {
        assert!(Frames::new(ur_types::ZCASH_PCZT, &[], 100).is_err());
    }
}
