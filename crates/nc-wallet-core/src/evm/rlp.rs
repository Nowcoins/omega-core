//! Minimal RLP encoding (the Ethereum yellow paper, appendix B), checked
//! against the RLP vectors of
//! `ethereum/tests` (`RLPTests/rlptest.json`) in `tests/evm_encoding.rs`.
//!
//! Only encoding is needed: transactions are built here and decoded by the
//! network. It has no dependencies, on purpose: a subtle change in an RLP
//! library's behaviour would produce a transaction that looks valid and moves
//! the wrong amount.

/// Encodes a byte string.
#[must_use]
pub fn bytes(input: &[u8]) -> Vec<u8> {
    // A single byte below 0x80 is its own encoding.
    if input.len() == 1 && input[0] < 0x80 {
        return vec![input[0]];
    }
    let mut out = Vec::with_capacity(input.len() + 9);
    write_header(&mut out, input.len(), 0x80, 0xb7);
    out.extend_from_slice(input);
    out
}

/// Encodes a list from its already-encoded items.
#[must_use]
pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload_len + 9);
    write_header(&mut out, payload_len, 0xc0, 0xf7);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Encodes an unsigned integer: big-endian with no leading zeros, and zero as
/// the empty string (not a zero byte).
#[must_use]
pub fn uint(value: u128) -> Vec<u8> {
    if value == 0 {
        return bytes(&[]);
    }
    let be = value.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    bytes(&be[first..])
}

/// Encodes a 256-bit value given as big-endian bytes, trimming leading zeros.
#[must_use]
pub fn uint256(value: &[u8; 32]) -> Vec<u8> {
    let first = value.iter().position(|b| *b != 0).unwrap_or(32);
    if first == 32 { bytes(&[]) } else { bytes(&value[first..]) }
}

/// Writes a length header: short form below 56 bytes, long form above.
fn write_header(out: &mut Vec<u8>, len: usize, short_base: u8, long_base: u8) {
    if len < 56 {
        out.push(short_base.wrapping_add(u8::try_from(len).unwrap_or(0)));
        return;
    }
    let be = len.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let length_bytes = &be[first..];
    out.push(long_base.wrapping_add(u8::try_from(length_bytes.len()).unwrap_or(0)));
    out.extend_from_slice(length_bytes);
}
