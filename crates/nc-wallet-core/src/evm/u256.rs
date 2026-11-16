//! A 256-bit unsigned integer, for the amounts the EVM carries: a token
//! amount in calldata, an `approve` allowance, a typed-data `uint256`.
//!
//! Only what the signing code needs: parsing (decimal, hexadecimal), printing
//! (decimal), comparison and the two's-complement step `int256` needs. No
//! arithmetic beyond that: nothing here adds money up.

use std::fmt::{self, Write as _};

/// 10^19, the largest power of ten in a `u64`: printing divides by it.
const CHUNK: u64 = 10_000_000_000_000_000_000;

/// A 256-bit unsigned integer, held as 32 big-endian bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct U256([u8; 32]);

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 32]);
    /// 2^256 - 1: what an "unlimited" ERC-20 allowance is.
    pub const MAX: Self = Self([0xff; 32]);
    /// 2^255: the bound from which an allowance is shown as unlimited.
    pub const TWO_POW_255: Self = {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x80;
        Self(bytes)
    };

    /// Whether an allowance of this size is, to any person, "everything, always".
    ///
    /// No token's supply in base units comes near 2^128 (3.4e20 whole tokens of 18
    /// decimals), so everything from the 128-bit maximum up is unlimited: the
    /// 256-bit maximum most dApps ask for, Permit2's 160-bit maximum, and the 128-bit
    /// one. The 96-bit maximum is added because it is what UNI, COMP and their kin
    /// turn a request for the 256-bit maximum into. Any other finite figure is shown
    /// as the number it is.
    #[must_use]
    pub fn is_unlimited(self) -> bool {
        self >= Self::from_u128(u128::MAX) || self == Self::from_u128((1 << 96) - 1)
    }

    /// 2 to the power `exp`; `None` from 256 up, where it does not fit.
    #[must_use]
    pub fn pow2(exp: u32) -> Option<Self> {
        if exp >= 256 {
            return None;
        }
        let mut bytes = [0u8; 32];
        let from_right = usize::try_from(exp / 8).ok()?;
        bytes[31 - from_right] = 1u8 << (exp % 8);
        Some(Self(bytes))
    }

    /// The number whose big-endian bytes are `bytes`.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The number as 32 big-endian bytes, the ABI word.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// A number that fits 128 bits.
    #[must_use]
    pub fn from_u128(value: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    /// The number as a `u128`, if it fits.
    #[must_use]
    pub fn to_u128(self) -> Option<u128> {
        if self.0[..16].iter().any(|b| *b != 0) {
            return None;
        }
        let mut low = [0u8; 16];
        low.copy_from_slice(&self.0[16..]);
        Some(u128::from_be_bytes(low))
    }

    /// Whether the number is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    /// How many bits the number needs (0 for zero).
    #[must_use]
    pub fn bit_len(self) -> u32 {
        for (i, byte) in self.0.iter().enumerate() {
            if *byte != 0 {
                let leading = u32::try_from(i).unwrap_or(0) * 8 + byte.leading_zeros();
                return 256 - leading;
            }
        }
        0
    }

    /// `2^256 - self`, the two's-complement negation: how a negative `int256`
    /// is written.
    #[must_use]
    pub fn wrapping_neg(self) -> Self {
        let mut out = [0u8; 32];
        let mut carry = true;
        for i in (0..32).rev() {
            let (value, overflow) = (!self.0[i]).overflowing_add(u8::from(carry));
            out[i] = value;
            carry = overflow;
        }
        Self(out)
    }

    /// Parses a decimal number (digits only, no sign, no separators); `None`
    /// if it is empty, has anything else in it, or does not fit 256 bits.
    #[must_use]
    pub fn from_decimal_str(text: &str) -> Option<Self> {
        if text.is_empty() {
            return None;
        }
        let mut limbs = [0u64; 4];
        for c in text.bytes() {
            if !c.is_ascii_digit() {
                return None;
            }
            let mut carry = u128::from(c - b'0');
            for limb in &mut limbs {
                let value = u128::from(*limb) * 10 + carry;
                *limb = u64::try_from(value & u128::from(u64::MAX)).ok()?;
                carry = value >> 64;
            }
            if carry != 0 {
                return None;
            }
        }
        Some(Self::from_limbs(limbs))
    }

    /// Parses `0x` and up to 64 hexadecimal digits (any case); `None`
    /// otherwise. `0x` alone is refused: a number has digits.
    #[must_use]
    pub fn from_hex_str(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))?;
        if digits.is_empty() || digits.len() > 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        // Fill from the right, a nibble at a time.
        for (i, c) in digits.bytes().rev().enumerate() {
            let nibble = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return None,
            };
            let at = 31 - i / 2;
            bytes[at] |= if i % 2 == 0 { nibble } else { nibble << 4 };
        }
        Some(Self(bytes))
    }

    fn from_limbs(limbs: [u64; 4]) -> Self {
        let mut bytes = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            let at = 32 - 8 * (i + 1);
            bytes[at..at + 8].copy_from_slice(&limb.to_be_bytes());
        }
        Self(bytes)
    }

    fn to_limbs(self) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let at = 32 - 8 * (i + 1);
            let mut word = [0u8; 8];
            word.copy_from_slice(&self.0[at..at + 8]);
            *limb = u64::from_be_bytes(word);
        }
        limbs
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u128(u128::from(value))
    }
}

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

/// Decimal, as an amount is written.
impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return f.write_str("0");
        }
        let mut limbs = self.to_limbs();
        let mut chunks: Vec<u64> = Vec::new();
        while limbs.iter().any(|l| *l != 0) {
            let mut remainder: u128 = 0;
            for limb in limbs.iter_mut().rev() {
                let value = (remainder << 64) | u128::from(*limb);
                *limb = u64::try_from(value / u128::from(CHUNK)).unwrap_or(0);
                remainder = value % u128::from(CHUNK);
            }
            chunks.push(u64::try_from(remainder).unwrap_or(0));
        }
        let mut text = String::new();
        for (i, chunk) in chunks.iter().rev().enumerate() {
            if i == 0 {
                text.push_str(&chunk.to_string());
            } else {
                let _ = write!(text, "{chunk:019}");
            }
        }
        f.write_str(&text)
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U256({self})")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decimal_round_trips_at_the_edges() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(U256::from_decimal_str(max), Some(U256::MAX));
        assert_eq!(U256::MAX.to_string(), max);
        // One more does not fit.
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert_eq!(U256::from_decimal_str(over), None);
        assert_eq!(U256::ZERO.to_string(), "0");
        assert_eq!(U256::from_decimal_str("0"), Some(U256::ZERO));
        assert_eq!(U256::from_u128(u128::MAX).to_string(), u128::MAX.to_string());
        assert_eq!(
            U256::from_decimal_str("18446744073709551616").unwrap().to_string(),
            "18446744073709551616",
            "2^64"
        );
        assert_eq!(U256::from_decimal_str(""), None);
        assert_eq!(U256::from_decimal_str("-1"), None);
        assert_eq!(U256::from_decimal_str("1_0"), None);
        assert_eq!(U256::from_decimal_str("0x10"), None);
    }

    #[test]
    fn hex_parses_any_length_up_to_a_word() {
        assert_eq!(U256::from_hex_str("0x0"), Some(U256::ZERO));
        assert_eq!(U256::from_hex_str("0xff").unwrap().to_u128(), Some(255));
        assert_eq!(U256::from_hex_str("0x1FF").unwrap().to_u128(), Some(511));
        assert_eq!(U256::from_hex_str(&format!("0x{}", "f".repeat(64))), Some(U256::MAX));
        assert_eq!(U256::from_hex_str(&format!("0x1{}", "0".repeat(64))), None);
        assert_eq!(U256::from_hex_str("0x"), None);
        assert_eq!(U256::from_hex_str("ff"), None);
        assert_eq!(U256::from_hex_str("0xfg"), None);
    }

    #[test]
    fn unlimited_is_judged_at_the_realistic_maximums() {
        assert!(U256::MAX.is_unlimited());
        assert!(U256::TWO_POW_255.is_unlimited());
        let mut bytes = [0u8; 32];
        bytes[12..].fill(0xff);
        assert!(U256::from_be_bytes(bytes).is_unlimited(), "the uint160 maximum");
        assert!(U256::from_u128(u128::MAX).is_unlimited(), "the uint128 maximum");
        assert!(U256::from_u128((1 << 96) - 1).is_unlimited(), "the uint96 maximum");
        assert!(!U256::from_u128(1 << 96).is_unlimited());
        assert!(
            !U256::from_u128(10_u128.pow(30)).is_unlimited(),
            "a trillion tokens of 18 decimals"
        );
        assert!(!U256::from_u128(u128::MAX - 1).is_unlimited());
    }

    #[test]
    fn the_unlimited_bound_is_two_to_the_255() {
        assert_eq!(U256::TWO_POW_255.bit_len(), 256);
        assert_eq!(U256::MAX.bit_len(), 256);
        assert_eq!(U256::from_u128(1).bit_len(), 1);
        assert_eq!(U256::ZERO.bit_len(), 0);
        assert!(U256::MAX > U256::TWO_POW_255);
        assert!(U256::from_u128(u128::MAX) < U256::TWO_POW_255);
        assert_eq!(
            U256::TWO_POW_255.to_string(),
            "57896044618658097711785492504343953926634992332820282019728792003956564819968"
        );
    }

    #[test]
    fn powers_of_two() {
        assert_eq!(U256::pow2(0), Some(U256::from_u128(1)));
        assert_eq!(U256::pow2(7).unwrap().to_u128(), Some(128));
        assert_eq!(U256::pow2(8).unwrap().to_u128(), Some(256));
        assert_eq!(U256::pow2(127).unwrap().to_u128(), Some(1 << 127));
        assert_eq!(U256::pow2(255), Some(U256::TWO_POW_255));
        assert_eq!(U256::pow2(256), None);
    }

    #[test]
    fn negation_is_twos_complement() {
        assert_eq!(U256::from_u128(1).wrapping_neg(), U256::MAX);
        assert_eq!(U256::ZERO.wrapping_neg(), U256::ZERO);
        assert_eq!(U256::from_u128(255).wrapping_neg().wrapping_neg().to_u128(), Some(255));
    }
}
