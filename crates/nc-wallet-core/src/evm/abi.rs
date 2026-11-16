//! The ABI shapes a wallet writes and reads: ERC-20's `transfer`, `approve`
//! and `transferFrom`, and the `setApprovalForAll` of ERC-721 and ERC-1155.
//!
//! Decoding exists for approval screens, and it never executes anything. It is strict by
//! design: calldata that is not exactly the canonical shape (extra bytes, an
//! address word with garbage above the 20 bytes, a boolean that is neither 0
//! nor 1) is not recognised, and the caller shows it as an unknown contract
//! call.

use sha3::{Digest as _, Keccak256};

use super::u256::U256;

/// `transfer(address,uint256)`: `keccak256` of the text, first four bytes.
pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// `approve(address,uint256)`.
pub const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
/// `transferFrom(address,address,uint256)`.
pub const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
/// `setApprovalForAll(address,bool)`.
pub const SET_APPROVAL_FOR_ALL: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65];

/// The four-byte selector of a function signature such as
/// `transfer(address,uint256)`.
#[must_use]
pub fn selector(signature: &str) -> [u8; 4] {
    let hash = Keccak256::digest(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

/// Left-pads an address to a 32-byte ABI word.
#[must_use]
pub fn pad_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

/// `transfer(address,uint256)` calldata.
#[must_use]
pub fn erc20_transfer(to: &[u8; 20], amount: &U256) -> Vec<u8> {
    address_amount(TRANSFER, to, amount)
}

/// `approve(address,uint256)` calldata.
#[must_use]
pub fn erc20_approve(spender: &[u8; 20], amount: &U256) -> Vec<u8> {
    address_amount(APPROVE, spender, amount)
}

fn address_amount(selector: [u8; 4], address: &[u8; 20], amount: &U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 64);
    data.extend_from_slice(&selector);
    data.extend_from_slice(&pad_address(address));
    data.extend_from_slice(&amount.to_be_bytes());
    data
}

/// A recognised token call, read from calldata. Addresses are the 20 bytes of
/// the ABI word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenCall {
    /// `transfer(to, amount)`.
    Transfer {
        /// The recipient.
        to: [u8; 20],
        /// The amount, in the token's base units.
        amount: U256,
    },
    /// `approve(spender, amount)`.
    Approve {
        /// Who may spend.
        spender: [u8; 20],
        /// How much, in base units.
        amount: U256,
    },
    /// `transferFrom(from, to, amount)`.
    TransferFrom {
        /// The account debited.
        from: [u8; 20],
        /// The recipient.
        to: [u8; 20],
        /// The amount, in base units.
        amount: U256,
    },
    /// `setApprovalForAll(operator, approved)`: an operator's right over
    /// every token of a collection.
    SetApprovalForAll {
        /// Who is granted (or denied) the right.
        operator: [u8; 20],
        /// Granted or revoked.
        approved: bool,
    },
}

/// Reads `data` as one of the token calls above, if it is exactly one.
#[must_use]
pub fn decode_token_call(data: &[u8]) -> Option<TokenCall> {
    decode_with(data, false)
}

/// [`decode_token_call`] for TRON, where wallets write an address word two
/// ways: eleven zero bytes, `0x41` and the 20 bytes (`TronLink` and the
/// exchanges, as the mainnet transactions in the tests show), or twelve zero
/// bytes and the 20 bytes (`TronWeb`). The TVM reads the same account from both.
#[must_use]
pub(crate) fn decode_token_call_tron(data: &[u8]) -> Option<TokenCall> {
    decode_with(data, true)
}

fn decode_with(data: &[u8], tron: bool) -> Option<TokenCall> {
    let (selector, args) = data.split_first_chunk::<4>()?;
    match *selector {
        TRANSFER if args.len() == 64 => Some(TokenCall::Transfer {
            to: address_word(&args[..32], tron)?,
            amount: amount_word(&args[32..64]),
        }),
        APPROVE if args.len() == 64 => Some(TokenCall::Approve {
            spender: address_word(&args[..32], tron)?,
            amount: amount_word(&args[32..64]),
        }),
        TRANSFER_FROM if args.len() == 96 => Some(TokenCall::TransferFrom {
            from: address_word(&args[..32], tron)?,
            to: address_word(&args[32..64], tron)?,
            amount: amount_word(&args[64..96]),
        }),
        SET_APPROVAL_FOR_ALL if args.len() == 64 => Some(TokenCall::SetApprovalForAll {
            operator: address_word(&args[..32], tron)?,
            approved: bool_word(&args[32..64])?,
        }),
        _ => None,
    }
}

/// An address word: twelve zero bytes, then the 20 bytes (on TRON, the
/// twelfth byte may be the `0x41` prefix). Anything else is not an address
/// the contract would read as written.
fn address_word(word: &[u8], tron: bool) -> Option<[u8; 20]> {
    if word.len() != 32 || word[..11].iter().any(|b| *b != 0) {
        return None;
    }
    if word[11] != 0 && !(tron && word[11] == 0x41) {
        return None;
    }
    <[u8; 20]>::try_from(&word[12..]).ok()
}

fn amount_word(word: &[u8]) -> U256 {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(word);
    U256::from_be_bytes(bytes)
}

/// A boolean word: 31 zero bytes, then 0 or 1.
fn bool_word(word: &[u8]) -> Option<bool> {
    if word.len() != 32 || word[..31].iter().any(|b| *b != 0) {
        return None;
    }
    match word[31] {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}
