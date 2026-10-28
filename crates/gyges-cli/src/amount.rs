//! The amount grammar (CLI_SPEC.md §1.4) and memo rules (§1.5), shared by
//! `tx send`, `tx shield --threshold` and `pczt create`.

use gyges_proto::v1::{Amount, amount};

/// Zatoshis per ZEC.
pub const COIN: u64 = 100_000_000;
/// The money supply, in zatoshis: the largest amount that parses.
pub const MAX_MONEY: u64 = 21_000_000 * COIN;

/// What `--amount` parsed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParsedAmount {
    Zatoshis(u64),
    Max,
}

impl ParsedAmount {
    /// The wire form.
    pub fn to_proto(self) -> Amount {
        Amount {
            value: Some(match self {
                ParsedAmount::Zatoshis(z) => {
                    amount::Value::Zatoshis(i64::try_from(z).unwrap_or(i64::MAX))
                }
                ParsedAmount::Max => amount::Value::Max(true),
            }),
        }
    }
}

/// `1.25`, `0.00000001`, `125000000z`, `max`. Thousands separators and a
/// leading `+` are rejected; the result is in `[1, 21_000_000 ZEC]`.
pub fn parse_amount(s: &str) -> Result<ParsedAmount, String> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("max") {
        return Ok(ParsedAmount::Max);
    }
    let zat = parse_zatoshis(s)?;
    Ok(ParsedAmount::Zatoshis(zat))
}

/// Like [`parse_amount`] but without `max` (for `--threshold`).
pub fn parse_zatoshis(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("expected an amount such as 1.25, 125000000z or max".into());
    }
    if s.starts_with('+') || s.starts_with('-') {
        return Err("the amount must be unsigned".into());
    }
    if s.contains(',') || s.contains('_') {
        return Err("thousands separators are not allowed".into());
    }
    let zat = if let Some(digits) = s.strip_suffix('z') {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err("a `z` amount is a whole number of zatoshis, e.g. 125000000z".into());
        }
        digits
            .parse::<u64>()
            .map_err(|_| "the amount is too large".to_string())?
    } else {
        let (whole, frac) = match s.split_once('.') {
            Some((w, f)) => (w, f),
            None => (s, ""),
        };
        if whole.is_empty() && frac.is_empty() {
            return Err("expected digits".into());
        }
        if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return Err("expected a decimal ZEC amount such as 1.25".into());
        }
        if frac.len() > 8 {
            return Err("at most 8 decimal places are allowed".into());
        }
        let whole: u64 = if whole.is_empty() {
            0
        } else {
            whole
                .parse()
                .map_err(|_| "the amount is too large".to_string())?
        };
        let mut frac_zat = 0u64;
        for (i, b) in frac.bytes().enumerate() {
            frac_zat += u64::from(b - b'0') * 10u64.pow(7 - i as u32);
        }
        whole
            .checked_mul(COIN)
            .and_then(|w| w.checked_add(frac_zat))
            .ok_or_else(|| "the amount is too large".to_string())?
    };
    if zat == 0 {
        return Err("the amount must be at least one zatoshi".into());
    }
    if zat > MAX_MONEY {
        return Err("the amount exceeds 21,000,000 ZEC".into());
    }
    Ok(zat)
}

/// Zatoshis as a ZEC string with eight decimals, e.g. `1.25000000`.
pub fn format_zec(zatoshis: i64) -> String {
    let sign = if zatoshis < 0 { "-" } else { "" };
    let z = zatoshis.unsigned_abs();
    format!("{sign}{}.{:08}", z / COIN, z % COIN)
}

/// A parsed `--memo` (a newtype so clap treats it as one value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoArg(pub Vec<u8>);

/// `--memo`: `0x…` (even length, at most 1024 hex digits) is raw bytes;
/// anything else is UTF-8 text of at most 512 bytes.
pub fn parse_memo(s: &str) -> Result<MemoArg, String> {
    memo_bytes(s).map(MemoArg)
}

fn memo_bytes(s: &str) -> Result<Vec<u8>, String> {
    if let Some(hex_digits) = s.strip_prefix("0x") {
        if hex_digits.is_empty() || hex_digits.len() % 2 != 0 || hex_digits.len() > 1024 {
            return Err(
                "a hex memo is 0x followed by an even number of up to 1024 hex digits".into(),
            );
        }
        return hex::decode(hex_digits).map_err(|e| format!("invalid hex memo: {e}"));
    }
    if s.len() > 512 {
        return Err(format!(
            "the memo is {} bytes as UTF-8; at most 512 are allowed",
            s.len()
        ));
    }
    Ok(s.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_round_trips_and_rejects_per_spec() {
        assert_eq!(
            parse_amount("1.25").unwrap(),
            ParsedAmount::Zatoshis(125_000_000)
        );
        assert_eq!(
            parse_amount("0.00000001").unwrap(),
            ParsedAmount::Zatoshis(1)
        );
        assert_eq!(
            parse_amount("125000000z").unwrap(),
            ParsedAmount::Zatoshis(125_000_000)
        );
        assert_eq!(parse_amount("max").unwrap(), ParsedAmount::Max);
        assert_eq!(parse_amount("MAX").unwrap(), ParsedAmount::Max);
        assert_eq!(parse_amount("3").unwrap(), ParsedAmount::Zatoshis(3 * COIN));
        assert_eq!(
            parse_amount(".5").unwrap(),
            ParsedAmount::Zatoshis(COIN / 2)
        );
        assert_eq!(
            parse_amount("21000000").unwrap(),
            ParsedAmount::Zatoshis(MAX_MONEY)
        );
        for bad in [
            "",
            "1,000",
            "+1",
            "-1",
            "0",
            "0.0",
            "1.123456789",
            "21000001",
            "abc",
            "1z5",
            "z",
            "1.2.3",
            "0x10",
        ] {
            assert!(parse_amount(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(parse_zatoshis("max").is_err());
        for z in [1u64, 100, COIN, 123_456_789, MAX_MONEY] {
            let s = format_zec(z as i64);
            assert_eq!(parse_zatoshis(&s).unwrap(), z, "{s}");
        }
        assert_eq!(format_zec(125_000_000), "1.25000000");
        assert_eq!(format_zec(-15_000), "-0.00015000");
    }

    #[test]
    fn memo_rules() {
        assert_eq!(parse_memo("hi").unwrap().0, b"hi");
        assert_eq!(parse_memo("0xdead").unwrap().0, vec![0xde, 0xad]);
        assert!(parse_memo("0xabc").is_err());
        assert!(parse_memo("0x").is_err());
        assert!(parse_memo(&"a".repeat(513)).is_err());
        assert!(parse_memo(&"a".repeat(512)).is_ok());
        assert!(parse_memo(&format!("0x{}", "ab".repeat(513))).is_err());
    }
}
