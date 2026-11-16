//! Hexadecimal text for requests and answers.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of `bytes`, no prefix.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// `0x` and the lowercase hex of `bytes`.
pub(crate) fn encode_0x(bytes: &[u8]) -> String {
    format!("0x{}", encode(bytes))
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The bytes of hex text without a prefix; `None` for an odd length or a
/// character that is not a hex digit.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

/// The bytes of `0x`-prefixed hex text (`0x` alone is no bytes).
pub(crate) fn decode_0x(text: &str) -> Option<Vec<u8>> {
    decode(text.strip_prefix("0x")?)
}

/// Exactly `N` bytes from hex text, with or without a `0x`.
pub(crate) fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    <[u8; N]>::try_from(decode(digits)?).ok()
}
