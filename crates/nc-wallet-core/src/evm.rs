//! EVM chains (Ethereum, BNB Chain, Polygon, Base, …): secp256k1 at
//! `m/44'/60'/0'/0/{index}`, the path MetaMask and Trust Wallet use; the
//! address is the last 20 bytes of the Keccak-256 of the public key, written
//! with the EIP-55 mixed-case checksum.
//!
//! Signing: [`tx`] (legacy and EIP-1559 transactions), [`abi`] (ERC-20
//! calldata), [`message`] (`personal_sign`), [`typed_data`] (EIP-712) and
//! [`decode`] (what a call does, for an approval screen).

pub mod abi;
pub mod decode;
pub mod message;
pub mod rlp;
pub mod tx;
pub mod typed_data;
pub mod u256;

#[cfg(test)]
mod permit2_tests;
#[cfg(test)]
mod vector_tests;

pub use decode::{Call, classify_call};
pub use message::{personal_message_hash, sign_personal_message};
pub use tx::{EvmChain, EvmTransaction, Fees, SignedTransaction, TxType};
pub use typed_data::{
    DomainInfo, PERMIT2, Permit2Allowance, Permit2Token, TypedData, TypedDataKind,
    TypedDataSummary, known_contract_name,
};
pub use u256::U256;

/// Why a piece of text is not an EVM address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    /// Not `0x` and 40 hex digits.
    #[error("an EVM address is 0x and 40 hexadecimal digits")]
    Format,
    /// Upper and lower case letters are mixed, and they are not the EIP-55
    /// checksum of the address: a character was mistyped or the case was
    /// changed.
    #[error("the address's capital letters are not its EIP-55 checksum")]
    Checksum,
    /// The all-zero address, which nobody holds the key of.
    #[error("the all-zero address is nobody's")]
    Zero,
}

/// Reads an EVM address, as a person types or pastes one: `0x` and 40 hex
/// digits. A mixed-case address must carry its EIP-55 checksum; an all
/// lower-case or all upper-case one is read as it is, as MetaMask reads it.
///
/// This refuses the all-zero address, which a transfer from this wallet must
/// not go to; [`parse_address_any`] does not.
pub fn parse_address(text: &str) -> Result<[u8; 20], AddressError> {
    let address = parse_address_any(text)?;
    if address == [0u8; 20] {
        return Err(AddressError::Zero);
    }
    Ok(address)
}

/// [`parse_address`] without the refusal of the all-zero address (a dApp's
/// transaction may be addressed to it, and the approval screen then shows it).
pub fn parse_address_any(text: &str) -> Result<[u8; 20], AddressError> {
    let digits = text.strip_prefix("0x").ok_or(AddressError::Format)?;
    let address = hexutil::decode(digits)
        .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
        .ok_or(AddressError::Format)?;
    let letters = digits.chars().filter(char::is_ascii_alphabetic);
    let (mut upper, mut lower) = (false, false);
    for c in letters {
        if c.is_ascii_uppercase() {
            upper = true;
        } else {
            lower = true;
        }
    }
    if upper && lower && checksum_address(&address) != text {
        return Err(AddressError::Checksum);
    }
    Ok(address)
}

use sha3::{Digest as _, Keccak256};

use crate::error::Error;
use crate::hd;
use crate::hexutil;
use crate::key::{Account, SigningKey};
use crate::mnemonic::Seed;
use crate::network::Network;

/// The private key of account `index`.
pub fn signing_key(seed: &Seed, index: u32) -> Result<SigningKey, Error> {
    let index = hd::check_index(index)?;
    hd::secp256k1_key(seed.expose_secret(), &Network::Evm.derivation_path(index))
        .ok_or(Error::InvalidKey(index))
}

/// The address and public key of account `index`.
pub fn account(seed: &Seed, index: u32) -> Result<Account, Error> {
    let key = signing_key(seed, index)?;
    account_of(&key, index)
}

pub(crate) fn account_of(key: &SigningKey, index: u32) -> Result<Account, Error> {
    let address = address_from_public_key(key.public_key()).ok_or(Error::InvalidKey(index))?;
    Ok(Account { address, public_key: key.public_key().to_vec() })
}

/// The EIP-55 address of a compressed secp256k1 public key (33 bytes);
/// `None` if the bytes are not a point on the curve.
pub fn address_from_public_key(compressed: &[u8]) -> Option<String> {
    let xy = hd::secp256k1_uncompressed_xy(compressed)?;
    Some(checksum_address(&keccak_tail(&xy)))
}

/// The last 20 bytes of the Keccak-256 of `data`: how EVM and TRON turn a
/// public key (X and Y, 64 bytes) into an account.
pub(crate) fn keccak_tail(data: &[u8]) -> [u8; 20] {
    let hash = Keccak256::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// A 20-byte address in EIP-55 form: `0x`, then the lowercase hex with every
/// letter capitalised where the matching hex digit of the Keccak-256 of that
/// lowercase text is 8 or more.
pub fn checksum_address(address: &[u8; 20]) -> String {
    let lower = hex_lower(address);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = if i % 2 == 0 { hash[i / 2] >> 4 } else { hash[i / 2] & 0x0f };
        out.push(if nibble >= 8 { c.to_ascii_uppercase() } else { c });
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// ERC-55 (EIP-55), "Test Cases": addresses whose checksum form is all
    /// capitals, all lowercase, or mixed. Copied from
    /// <https://github.com/ethereum/ercs/blob/4891ba3b86d2058d0f472dbf1500af6bb056caf2/ERCS/erc-55.md>.
    const ERC55: &str = include_str!("../tests/vectors/erc-55-test-cases.md");

    #[test]
    fn eip55_test_cases() {
        let mut checked = 0;
        for line in ERC55.lines().filter(|l| l.starts_with("0x")) {
            let bytes: [u8; 20] = hex::decode(&line[2..]).unwrap().try_into().unwrap();
            assert_eq!(checksum_address(&bytes), line);
            // The checksum is of the lowercase form, so case in must not matter.
            let lower: [u8; 20] =
                hex::decode(line[2..].to_lowercase()).unwrap().try_into().unwrap();
            assert_eq!(checksum_address(&lower), line);
            checked += 1;
        }
        assert_eq!(checked, 8);
    }

    #[test]
    fn addresses_are_read_as_people_write_them() {
        let mut mixed = 0;
        for line in ERC55.lines().filter(|l| l.starts_with("0x")) {
            let bytes = parse_address(line).unwrap();
            assert_eq!(parse_address(&line.to_lowercase()).unwrap(), bytes);
            assert_eq!(parse_address(&format!("0x{}", line[2..].to_uppercase())).unwrap(), bytes);
            let has_both = line[2..].chars().any(|c| c.is_ascii_uppercase())
                && line[2..].chars().any(|c| c.is_ascii_lowercase());
            if has_both {
                mixed += 1;
                // One letter's case flipped is a failed checksum.
                let at =
                    line.char_indices().skip(2).find(|(_, c)| c.is_ascii_alphabetic()).unwrap().0;
                let mut flipped = line.to_owned();
                let c = flipped.remove(at);
                flipped.insert(
                    at,
                    if c.is_ascii_uppercase() {
                        c.to_ascii_lowercase()
                    } else {
                        c.to_ascii_uppercase()
                    },
                );
                assert_eq!(parse_address(&flipped), Err(AddressError::Checksum));
            }
        }
        assert!(mixed >= 4);
    }

    #[test]
    fn what_is_not_an_address_is_refused() {
        for bad in [
            "",
            "0x",
            "0x1234",
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0X5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaedaa",
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaeg",
            " 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        ] {
            assert_eq!(parse_address(bad), Err(AddressError::Format), "{bad:?}");
        }
        let zero = format!("0x{}", "0".repeat(40));
        assert_eq!(parse_address(&zero), Err(AddressError::Zero));
        assert_eq!(parse_address_any(&zero), Ok([0u8; 20]));
    }

    #[test]
    fn a_point_off_the_curve_has_no_address() {
        // 0x00 and 0x05 are not SEC1 prefixes.
        assert!(address_from_public_key(&[0u8; 33]).is_none());
        assert!(address_from_public_key(&[5u8; 33]).is_none());
        assert!(address_from_public_key(&[]).is_none());
    }
}
