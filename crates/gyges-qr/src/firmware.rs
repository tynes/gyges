//! The Keystone firmware version a `zcash-accounts` export reports, and the
//! minimum Gyges accepts.
//!
//! The pairing QR carries the raw `SOFTWARE_VERSION_MAJOR.MINOR.BUILD` of
//! the firmware (keystone3-firmware PR #2138, merged 2026-05-26), while the
//! device's About screen shows the major number less
//! `SOFTWARE_VERSION_MAJOR_OFFSET` (10): `13.2.0` in the QR is `v3.2.0` on
//! the device. Older firmware reports nothing.

use std::fmt;

/// `SOFTWARE_VERSION_MAJOR_OFFSET` in the firmware's `version.h`.
pub const DISPLAY_MAJOR_OFFSET: u32 = 10;

/// The oldest firmware that signs after NU6.3: Zodl's "If your Keystone
/// firmware is below v3.0.2, you must upgrade it for Ironwood (NU6.3)"
/// (support.zodl.com/article/49, July 2026). v3.0.2 on the device is 13.0.2
/// in the pairing QR.
pub const MIN_FIRMWARE: Firmware = Firmware {
    major: 13,
    minor: 0,
    build: 2,
};

/// A version as the pairing QR reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Firmware {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

impl Firmware {
    /// The leading `MAJOR.MINOR.BUILD` of a reported string; any suffix
    /// (`-C`, `-cypherpunk`) is ignored. `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let end = s
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(s.len());
        let mut parts = s[..end].split('.');
        let mut next = || parts.next()?.parse::<u32>().ok();
        let v = Firmware {
            major: next()?,
            minor: next()?,
            build: next()?,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(v)
    }

    /// As the device's About screen shows it (`v3.0.2`).
    pub fn displayed(&self) -> String {
        match self.major.checked_sub(DISPLAY_MAJOR_OFFSET) {
            Some(major) => format!("v{major}.{}.{}", self.minor, self.build),
            None => format!("v{self}"),
        }
    }
}

impl fmt::Display for Firmware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

/// What a reported `device_version` means for an import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirmwareCheck {
    Supported(Firmware),
    TooOld(Firmware),
    /// Not reported, or not a version this parser understands.
    Unknown,
}

/// Classify a `zcash-accounts` export's `device_version`.
pub fn check(device_version: Option<&str>) -> FirmwareCheck {
    match device_version.and_then(Firmware::parse) {
        Some(v) if v >= MIN_FIRMWARE => FirmwareCheck::Supported(v),
        Some(v) => FirmwareCheck::TooOld(v),
        None => FirmwareCheck::Unknown,
    }
}

/// The refusal text for firmware below the minimum.
pub fn too_old_message(v: Firmware) -> String {
    format!(
        "the Keystone reports firmware {v} ({} on the device); signing after NU6.3 needs the \
         Cypherpunk firmware {} ({MIN_FIRMWARE} in the pairing QR) or later: update it, then \
         export the accounts again",
        v.displayed(),
        MIN_FIRMWARE.displayed(),
    )
}

/// What to tell the user about a device that reports no usable version.
/// Every release since v3.0.0 puts its version in the pairing QR (the
/// `firmwareVersion` field is in `gui_connect_wallet_widgets.c` at the
/// `3.0.0` and `3.0.2` tags), so a device that reports none is older than
/// the minimum.
pub fn unknown_message(reported: Option<&str>) -> String {
    let what = match reported {
        Some(s) => format!("reports a firmware version this release cannot read ({s:?})"),
        None => "does not report its firmware version, which every firmware since v3.0.0 \
                 does, so it is almost certainly too old to sign"
            .to_string(),
    };
    format!(
        "the Keystone {what}; signing after NU6.3 needs the Cypherpunk firmware {} or later \
         (Settings > About on the device)",
        MIN_FIRMWARE.displayed()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_raw_triple_and_ignores_suffixes() {
        let v = |major, minor, build| Firmware {
            major,
            minor,
            build,
        };
        assert_eq!(Firmware::parse("13.2.0"), Some(v(13, 2, 0)));
        assert_eq!(Firmware::parse(" 13.0.2-C "), Some(v(13, 0, 2)));
        assert_eq!(Firmware::parse("2.4.0-cypherpunk"), Some(v(2, 4, 0)));
        for bad in ["", "13", "13.2", "13.2.0.1", "v13.2.0", "13.x.0", "-1.0.0"] {
            assert_eq!(Firmware::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_floor_is_v3_0_2_on_the_device() {
        assert_eq!(MIN_FIRMWARE.to_string(), "13.0.2");
        assert_eq!(MIN_FIRMWARE.displayed(), "v3.0.2");
        assert_eq!(
            check(Some("13.0.2")),
            FirmwareCheck::Supported(MIN_FIRMWARE)
        );
        assert!(matches!(check(Some("13.2.0")), FirmwareCheck::Supported(_)));
        assert!(matches!(
            check(Some("14.0.0-C")),
            FirmwareCheck::Supported(_)
        ));
        // v3.0.1 on the device, and the About-screen form by mistake.
        assert!(matches!(check(Some("13.0.1")), FirmwareCheck::TooOld(_)));
        assert!(matches!(check(Some("3.2.0")), FirmwareCheck::TooOld(_)));
        assert_eq!(check(None), FirmwareCheck::Unknown);
        assert_eq!(check(Some("cypherpunk")), FirmwareCheck::Unknown);
    }

    #[test]
    fn messages_show_both_numberings() {
        let m = too_old_message(Firmware::parse("12.4.0").unwrap());
        assert!(m.contains("12.4.0 (v2.4.0 on the device)"), "{m}");
        assert!(m.contains("v3.0.2 (13.0.2 in the pairing QR)"), "{m}");
        assert!(unknown_message(None).contains("does not report"));
        assert!(unknown_message(Some("abc")).contains("\"abc\""));
    }
}
