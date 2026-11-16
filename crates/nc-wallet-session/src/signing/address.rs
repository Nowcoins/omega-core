//! Checking an address the person typed, for the network it is going to. The
//! checks are the core's, so a checksum is checked and the answer is the one
//! the wallet API would give (`invalid_address`).

use nc_wallet_core::evm::{self, AddressError};
use nc_wallet_core::{bitcoin, bittensor, solana, stellar, tron};

use crate::types::NetworkId;

/// The longest text [`validate_address`] reads; anything longer is not an address (`format`), without being
/// decoded.
///
/// No address of a network the wallet serves comes near it: an EVM address is 42 characters, a TRON, Solana,
/// Bittensor or legacy Bitcoin one under 50, a Bitcoin segwit one 62, a Stellar `G…` one 56 and a muxed `M…` one
/// 69. The longest string any of these formats could take is 90, the limit of a bech32 string (BIP-173), and
/// this leaves room above that. It is here because base58 is decoded in time that grows with the square of the
/// length (60,000 characters took about 0.8 s), and a clipboard can hold more than that.
pub const MAX_ADDRESS_LEN: usize = 128;

/// What [`validate_address`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressCheck {
    /// Whether the text is an address on that network.
    pub valid: bool,
    /// The address in its canonical form: the EIP-55 checksum form for the EVM
    /// networks, the text itself for the others. `None` when not valid.
    pub normalized: Option<String>,
    /// Why not: `empty`, `format` (also any text longer than [`MAX_ADDRESS_LEN`]),
    /// `checksum` (an EVM address with mixed case that is not its checksum),
    /// `zero_address`, or `unsupported_network`.
    pub reason: Option<&'static str>,
}

impl AddressCheck {
    fn ok(normalized: String) -> Self {
        Self { valid: true, normalized: Some(normalized), reason: None }
    }

    fn no(reason: &'static str) -> Self {
        Self { valid: false, normalized: None, reason: Some(reason) }
    }
}

/// Whether `text` is an address on `network` (a wallet-API id: `ethereum`,
/// `bsc`, `polygon`, `base`, `tron`, `bitcoin`, `solana`, `stellar`,
/// `bittensor`). The text is checked as it is; trim it first.
///
/// | Network | Accepted |
/// |---|---|
/// | the EVM four | `0x` and 40 hex digits, a mixed-case one with its EIP-55 checksum |
/// | TRON | base58check `T…` |
/// | Bitcoin | mainnet `bc1q…`, `bc1p…`, `1…`, `3…` |
/// | Solana | base58 of 32 bytes |
/// | Stellar | `G…`, or a muxed `M…` (SEP-23); not `S…` |
/// | Bittensor | SS58 with prefix 42 (`5…`) |
///
/// The all-zero address is refused everywhere, and so is any text longer than
/// [`MAX_ADDRESS_LEN`] bytes (`format`), before anything is decoded.
#[must_use]
pub fn validate_address(network: &str, text: &str) -> AddressCheck {
    let Some(network) = NetworkId::from_api_id(network) else {
        return AddressCheck::no("unsupported_network");
    };
    if text.len() > MAX_ADDRESS_LEN {
        return AddressCheck::no("format");
    }
    if text.trim().is_empty() {
        return AddressCheck::no("empty");
    }
    match network {
        NetworkId::Ethereum | NetworkId::BnbChain | NetworkId::Polygon | NetworkId::Base => {
            match evm::parse_address(text) {
                Ok(bytes) => AddressCheck::ok(evm::checksum_address(&bytes)),
                Err(AddressError::Format) => AddressCheck::no("format"),
                Err(AddressError::Checksum) => AddressCheck::no("checksum"),
                Err(AddressError::Zero) => AddressCheck::no("zero_address"),
            }
        }
        NetworkId::Tron => match tron::parse_address(text) {
            Ok(bytes) if bytes[1..].iter().all(|b| *b == 0) => AddressCheck::no("zero_address"),
            Ok(_) => AddressCheck::ok(text.to_owned()),
            Err(_) => AddressCheck::no("format"),
        },
        NetworkId::Bitcoin => match bitcoin::script::script_for_address(text) {
            Ok(_) => AddressCheck::ok(text.to_owned()),
            Err(_) => AddressCheck::no("format"),
        },
        NetworkId::Solana => key_check(solana::parse_address(text), text),
        NetworkId::Stellar => key_check(stellar::parse_destination(text).map(|d| d.key), text),
        NetworkId::Bittensor => key_check(bittensor::parse_address(text), text),
    }
}

fn key_check(key: Option<[u8; 32]>, text: &str) -> AddressCheck {
    match key {
        Some(key) if key == [0u8; 32] => AddressCheck::no("zero_address"),
        Some(_) => AddressCheck::ok(text.to_owned()),
        None => AddressCheck::no("format"),
    }
}
