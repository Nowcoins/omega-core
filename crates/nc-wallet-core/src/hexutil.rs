//! Hexadecimal text, in the few places the signing code needs it (typed data
//! and addresses arrive as hex; hashes and raw transactions leave as hex).

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
pub(crate) fn encode_prefixed(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    out.push_str(&encode(bytes));
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The bytes of hex text without a prefix; `None` for an odd length or any
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
pub(crate) fn decode_prefixed(text: &str) -> Option<Vec<u8>> {
    decode(text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))?)
}

/// Exactly `N` bytes from `0x`-prefixed hex text.
pub(crate) fn decode_prefixed_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    <[u8; N]>::try_from(decode_prefixed(text)?).ok()
}

/// The bytes of `0x`-prefixed hex text, an odd number of digits read with a
/// zero in front (`0x101` is `0x0101`, `0x0` is `0x00`), the way MetaMask
/// reads the hex a dApp sends as typed data. `0x` alone is no bytes.
pub(crate) fn decode_prefixed_lenient(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))?;
    if digits.len() % 2 == 1 { decode(&format!("0{digits}")) } else { decode(digits) }
}
