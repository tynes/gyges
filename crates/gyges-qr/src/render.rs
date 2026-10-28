//! UTF-8 half-block QR rendering: two module rows per text line, so a code
//! stays square in a terminal whose cells are about twice as tall as wide.

use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};

use crate::QrError;

/// Render `data` (byte mode) with error correction level L.
///
/// A module that is dark in the code is drawn as a space and a light one as
/// a block, quiet zone included. On the usual light-on-dark terminal the
/// blocks show light, so the code reads dark-on-light as scanners expect.
pub fn render(data: &[u8]) -> Result<String, QrError> {
    let code = QrCode::with_error_correction_level(data, EcLevel::L)
        .map_err(|e| QrError::TooLong(e.to_string()))?;
    let mut s = code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    s.push('\n');
    Ok(s)
}

/// Render a string as given (an address: bech32 strings are not uppercased,
/// since some wallets refuse an uppercase unified address).
pub fn render_str(s: &str) -> Result<String, QrError> {
    render(s.as_bytes())
}

/// Render one `ur:` frame. UR text is case-insensitive and every character
/// of its uppercase form is in the QR alphanumeric set, which packs 5.5 bits
/// per character instead of 8, so frames are uppercased first.
pub fn render_frame(frame: &str) -> Result<String, QrError> {
    render(frame.to_ascii_uppercase().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_module_rows_per_line_with_a_quiet_zone() {
        let data = b"uregtest1example";
        let code = QrCode::with_error_correction_level(&data[..], EcLevel::L).unwrap();
        let modules = code.width();
        // A version 1 code is 21 modules wide.
        assert_eq!(modules, 21);
        let s = render(data).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        // Four modules of quiet zone on every side, two rows per line.
        assert_eq!(lines.len(), (modules + 8).div_ceil(2));
        for line in &lines {
            assert_eq!(line.chars().count(), modules + 8, "{line:?}");
            assert!(line.chars().all(|c| " █▀▄".contains(c)), "{line:?}");
        }
        // The quiet zone is light, so the first line is solid blocks.
        assert!(lines[0].chars().all(|c| c == '█'), "{:?}", lines[0]);
    }

    #[test]
    fn frames_are_rendered_in_alphanumeric_mode() {
        // A full 200-byte fragment, as the animation shows.
        let data: Vec<u8> = (0..2000u32).map(|i| (i * 37) as u8).collect();
        let frame = crate::Frames::new(crate::ur_types::ZCASH_PCZT, &data, 200)
            .unwrap()
            .next_frame()
            .unwrap();
        let upper =
            QrCode::with_error_correction_level(frame.to_ascii_uppercase().as_bytes(), EcLevel::L)
                .unwrap();
        let lower = QrCode::with_error_correction_level(frame.as_bytes(), EcLevel::L).unwrap();
        assert!(
            upper.width() < lower.width(),
            "{} {}",
            upper.width(),
            lower.width()
        );
        let s = render_frame(&frame).unwrap();
        assert_eq!(s.lines().count(), (upper.width() + 8).div_ceil(2));
    }

    #[test]
    fn data_beyond_version_40_is_refused() {
        // Byte mode tops out at 2,953 bytes at level L.
        let err = render(&[0xff; 3000]).unwrap_err();
        assert!(matches!(err, QrError::TooLong(_)), "{err}");
    }
}
