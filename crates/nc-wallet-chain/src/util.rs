//! Small helpers shared by the families: hex numbers, decimals read without a
//! float, and an RFC 3339 time without a date library.

use serde_json::Value;

use crate::error::{ChainError, ChainResult};

/// A `0x` quantity as a `u128` (`0x0`, `0x1b4`); anything else is `None`.
#[must_use]
pub fn u128_from_hex(text: &str) -> Option<u128> {
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))?;
    if digits.is_empty() || digits.len() > 32 {
        return None;
    }
    u128::from_str_radix(digits, 16).ok()
}

/// A `0x` quantity as a `u64`.
#[must_use]
pub fn u64_from_hex(text: &str) -> Option<u64> {
    u128_from_hex(text).and_then(|value| u64::try_from(value).ok())
}

/// `0x`-prefixed hex bytes, any length (even, or odd and then padded).
#[must_use]
pub fn bytes_from_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    if digits.len() % 2 == 1 {
        hex::decode(format!("0{digits}")).ok()
    } else {
        hex::decode(digits).ok()
    }
}

/// `0x` and the bytes in lower-case hex.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// An ABI word (32 bytes, big-endian) as a `u128`, or `None` where it does not
/// fit: a token balance past 2^128 is not one this wallet shows.
#[must_use]
pub fn word_to_u128(bytes: &[u8]) -> Option<u128> {
    if bytes.len() < 32 {
        return None;
    }
    let (high, low) = bytes[..32].split_at(16);
    if high.iter().any(|b| *b != 0) {
        return None;
    }
    Some(u128::from_be_bytes(low.try_into().ok()?))
}

/// The ABI word of a `u128`.
#[must_use]
pub fn pad_u128(value: u128) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// The ABI word of a 20-byte address.
#[must_use]
pub fn pad_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(address);
    word
}

/// A plain decimal (`12`, `0.131`, `5056.25`) in thousandths, any finer part
/// rounded up. `None` for anything else (a sign, an exponent, text, an empty
/// part) and for a value too large to hold. Rates are whole numbers of a small
/// unit here, never an `f64`.
#[must_use]
pub fn thousandths(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() || !whole.bytes().chain(fraction.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text.contains('.') && fraction.is_empty() {
        return None;
    }
    let mut kept = fraction.bytes().take(3).map(|b| u64::from(b - b'0')).collect::<Vec<_>>();
    kept.resize(3, 0);
    let mut milli = kept.iter().fold(0_u64, |acc, digit| acc * 10 + digit);
    if fraction.bytes().skip(3).any(|b| b != b'0') {
        milli += 1;
    }
    whole.parse::<u64>().ok()?.checked_mul(1000)?.checked_add(milli)
}

/// `1500` thousandths as `1.5`; `1000` as `1`.
#[must_use]
pub fn from_thousandths(milli: u64) -> String {
    let (whole, fraction) = (milli / 1000, milli % 1000);
    if fraction == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{fraction:03}").trim_end_matches('0').to_owned()
    }
}

/// Stellar's amounts (`"5.0000000"`) in stroops (seven decimals).
#[must_use]
pub fn stroops(text: &str) -> Option<u128> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() || fraction.len() > 7 {
        return None;
    }
    if !whole.bytes().chain(fraction.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let padded = format!("{fraction:0<7}");
    whole.parse::<u128>().ok()?.checked_mul(10_000_000)?.checked_add(padded.parse().ok()?)
}

/// A JSON number or a decimal string as a `u128`: some nodes write integers
/// either way.
#[must_use]
pub fn json_u128(value: &Value) -> Option<u128> {
    match value {
        Value::Number(number) => number.as_u64().map(u128::from),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

/// The time as `2026-10-26T21:06:13Z`.
#[must_use]
pub fn rfc3339(unix_seconds: u64) -> String {
    let days = i64::try_from(unix_seconds / 86_400).unwrap_or(0);
    let rest = unix_seconds % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// An RFC 3339 time in UTC (`2026-10-26T21:06:13Z`, optionally with a
/// fraction) as Unix seconds.
#[must_use]
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let text = text.trim();
    let (date, time) = text.split_once('T')?;
    let mut d = date.split('-');
    let (year, month, day): (i64, i64, i64) =
        (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let time = time.strip_suffix('Z').or_else(|| time.strip_suffix("+00:00"))?;
    let time = time.split('.').next()?;
    let mut t = time.split(':');
    let (hour, minute, second): (u64, u64, u64) =
        (t.next()?.parse().ok()?, t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    // (A year past four digits is not a time a ledger closed; the arithmetic below stays well inside an i64.)
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Days from civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y.rem_euclid(400);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * mp + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days).ok()?.checked_mul(86_400)?.checked_add(hour * 3600 + minute * 60 + second)
}

/// Reads a JSON text, or says the answer was not what the endpoint documents.
pub fn parse_json(body: &[u8]) -> ChainResult<Value> {
    serde_json::from_slice(body).map_err(|_| ChainError::Unavailable)
}

/// Digits only, fitting 128 bits: an amount in base units.
pub fn parse_amount(text: &str) -> ChainResult<u128> {
    let fine = !text.is_empty()
        && text.len() <= 39
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    fine.then(|| text.parse().ok()).flatten().ok_or_else(|| {
        ChainError::InvalidRequest(
            "amount is a whole number of base units, in digits only".to_owned(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_quantities_are_read_strictly() {
        assert_eq!(u128_from_hex("0x0"), Some(0));
        assert_eq!(u128_from_hex("0x1b4"), Some(436));
        assert_eq!(u64_from_hex("0xffffffffffffffff"), Some(u64::MAX));
        assert_eq!(u128_from_hex("1b4"), None);
        assert_eq!(u128_from_hex("0x"), None);
        assert_eq!(u128_from_hex("0xzz"), None);
    }

    #[test]
    fn decimals_are_read_in_thousandths_and_rounded_up() {
        assert_eq!(thousandths("0"), Some(0));
        assert_eq!(thousandths("0.131"), Some(131));
        assert_eq!(thousandths("5056.25"), Some(5_056_250));
        assert_eq!(thousandths("0.0001"), Some(1), "any finer part rounds up");
        assert_eq!(thousandths("0.0000"), Some(0));
        for bad in ["", ".5", "1.", "-1", "1e3", "NaN", " 1", "0x10", "1.2.3"] {
            assert_eq!(thousandths(bad), None, "{bad:?}");
        }
        assert_eq!(from_thousandths(1500), "1.5");
        assert_eq!(from_thousandths(1000), "1");
        assert_eq!(from_thousandths(131), "0.131");
    }

    #[test]
    fn stellar_amounts_are_stroops() {
        assert_eq!(stroops("5.0000000"), Some(50_000_000));
        assert_eq!(stroops("0.0000001"), Some(1));
        assert_eq!(stroops("320999.3548500"), Some(3_209_993_548_500));
        assert_eq!(stroops("1.00000001"), None);
        assert_eq!(stroops("-1"), None);
    }

    #[test]
    fn times_round_trip() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_793_058_193), "2026-10-26T23:43:13Z");
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        for t in [0, 951_782_400, 1_709_164_800, 1_793_058_193, 4_102_444_800] {
            assert_eq!(parse_rfc3339(&rfc3339(t)), Some(t));
        }
        assert_eq!(parse_rfc3339("2026-10-26T21:06:13.123Z"), Some(1_793_048_773));
        assert_eq!(parse_rfc3339("2026-13-26T21:06:13Z"), None);
        // A year no ledger closed in is no time (and its arithmetic never reaches an overflow).
        for year in [
            "9223372036854775807",
            "-9223372036854775807",
            "99999999999999999",
            "10000",
            "1969",
            "0",
        ] {
            assert_eq!(parse_rfc3339(&format!("{year}-01-01T00:00:00Z")), None, "{year}");
        }
    }

    #[test]
    fn abi_words_round_trip() {
        assert_eq!(word_to_u128(&pad_u128(291_368_219)), Some(291_368_219));
        let mut big = pad_u128(1);
        big[0] = 1;
        assert_eq!(word_to_u128(&big), None, "past 128 bits is not shown");
        assert_eq!(word_to_u128(&[0; 31]), None);
    }

    #[test]
    fn amounts_are_digits_without_leading_zeros() {
        assert_eq!(parse_amount("0").unwrap(), 0);
        assert_eq!(parse_amount("1500000").unwrap(), 1_500_000);
        for bad in ["", "01", "-1", "1.5", "1e3", " 1", &"9".repeat(40)] {
            assert!(parse_amount(bad).is_err(), "{bad:?}");
        }
    }
}
