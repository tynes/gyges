//! Redaction by type (docs/decisions.md Q-O1, docs/security.md A10).
//!
//! Anything that identifies a payment or a key (addresses, amounts, memos,
//! txids, passphrases, key material) is wrapped in [`Sensitive`] before it
//! can reach a `tracing` field or an error message, so that the value cannot
//! be formatted by accident: both `Debug` and `Display` print
//! [`REDACTED`]. The value is reachable only through [`Sensitive::expose`],
//! which makes every deliberate use greppable.
//!
//! The level policy this backs (docs/interface.md API §4.5): `info` carries heights, counts,
//! key ids and durations only; `debug` may carry txids; nothing at any level
//! carries memos, passphrases or key material.

use std::fmt;

/// What a redacted value prints as.
pub const REDACTED: &str = "[redacted]";

/// A value whose `Debug` and `Display` output is [`REDACTED`].
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The wrapped value. Every call site is a deliberate disclosure.
    pub const fn expose(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Sensitive<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    #[allow(dead_code)]
    struct Payment {
        to: Sensitive<String>,
        zatoshis: Sensitive<u64>,
        height: u32,
    }

    #[test]
    fn debug_and_display_print_the_placeholder() {
        let s = Sensitive::new("t1VisibleAddress".to_string());
        assert_eq!(format!("{s}"), REDACTED);
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(format!("{:#?}", s), REDACTED);
        assert_eq!(s.expose(), "t1VisibleAddress");
        assert_eq!(s.clone().into_inner(), "t1VisibleAddress");
    }

    #[test]
    fn derived_debug_of_a_container_stays_redacted() {
        let p = Payment {
            to: "u1secretaddress".to_string().into(),
            zatoshis: Sensitive::new(123_456_789),
            height: 42,
        };
        let text = format!("{p:?}");
        assert!(!text.contains("u1secretaddress"), "{text}");
        assert!(!text.contains("123456789"), "{text}");
        assert!(text.contains("height: 42"), "{text}");
        assert_eq!(text.matches(REDACTED).count(), 2);
    }

    #[test]
    fn padding_and_width_do_not_leak_the_value() {
        let s = Sensitive::new(7u8);
        assert_eq!(format!("{s:>12}"), REDACTED);
        assert_eq!(format!("{s:04}"), REDACTED);
    }
}
