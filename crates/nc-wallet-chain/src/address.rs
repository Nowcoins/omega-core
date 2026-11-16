//! Addresses, checked for the network before anything is asked of it.
//!
//! The checks are the signing core's own, plus a look at the shape first, so
//! what a family's parser is lenient about (an EVM address without `0x`, a TRON
//! address in hex, whitespace around anything) is not accepted here and
//! nothing odd is ever sent to an endpoint. A bad address is `invalid_address`
//! and the message never repeats it.

use nc_wallet_core::evm::{self, AddressError};
use nc_wallet_core::{bitcoin, bittensor, solana, stellar, tron};

use crate::error::{ChainError, ChainResult};
use crate::networks::{Family, Network};

/// An address, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The canonical text: EIP-55 for EVM, lower case for bech32, otherwise as given.
    pub text: String,
    /// The bytes the family works with.
    pub raw: Raw,
}

/// The bytes of an address by family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Raw {
    /// 20 bytes.
    Evm([u8; 20]),
    /// `0x41` and 20 bytes.
    Tron([u8; 21]),
    /// The output script that pays it.
    Bitcoin(Vec<u8>),
    /// 32 bytes.
    Key([u8; 32]),
}

impl Address {
    /// The 20 bytes of an EVM address.
    pub fn evm(&self) -> ChainResult<[u8; 20]> {
        match self.raw {
            Raw::Evm(bytes) => Ok(bytes),
            _ => Err(ChainError::Internal),
        }
    }

    /// The 21 bytes of a TRON address.
    pub fn tron(&self) -> ChainResult<[u8; 21]> {
        match self.raw {
            Raw::Tron(bytes) => Ok(bytes),
            _ => Err(ChainError::Internal),
        }
    }

    /// The 32 bytes of a Solana, Stellar or Bittensor address.
    pub fn key(&self) -> ChainResult<[u8; 32]> {
        match self.raw {
            Raw::Key(bytes) => Ok(bytes),
            _ => Err(ChainError::Internal),
        }
    }

    /// The script of a Bitcoin address.
    pub fn script(&self) -> ChainResult<&[u8]> {
        match &self.raw {
            Raw::Bitcoin(script) => Ok(script),
            _ => Err(ChainError::Internal),
        }
    }
}

/// The longest address text looked at at all.
const MAX_TEXT: usize = 100;

/// Checks `text` as an address on `network`.
pub fn parse(network: Network, text: &str) -> ChainResult<Address> {
    let bad =
        || ChainError::InvalidAddress(format!("that is not a valid {} address", network.name()));
    if text.is_empty() || text.len() > MAX_TEXT || !text.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad());
    }
    let shaped = match network.family() {
        Family::Evm => text.starts_with("0x") && text.len() == 42,
        Family::Tron => text.starts_with('T') && text.len() == 34,
        Family::Stellar => text.starts_with('G') && text.len() == 56,
        Family::Solana => (32..=44).contains(&text.len()),
        Family::Substrate => text.starts_with('5') && (46..=48).contains(&text.len()),
        Family::Bitcoin => true,
    };
    if !shaped {
        return Err(bad());
    }
    match network.family() {
        Family::Evm => match evm::parse_address(text) {
            Ok(bytes) => Ok(Address { text: evm::checksum_address(&bytes), raw: Raw::Evm(bytes) }),
            Err(AddressError::Format | AddressError::Checksum | AddressError::Zero) => Err(bad()),
        },
        Family::Tron => match tron::parse_address(text) {
            Ok(bytes) if bytes[1..].iter().any(|b| *b != 0) => {
                Ok(Address { text: text.to_owned(), raw: Raw::Tron(bytes) })
            }
            _ => Err(bad()),
        },
        Family::Bitcoin => {
            let script = bitcoin::script::script_for_address(text).map_err(|_| bad())?;
            // Bech32 is case-insensitive; one case is the canonical one.
            let canonical = if text.to_ascii_lowercase().starts_with("bc1") {
                text.to_ascii_lowercase()
            } else {
                text.to_owned()
            };
            Ok(Address { text: canonical, raw: Raw::Bitcoin(script) })
        }
        Family::Solana => key(solana::parse_address(text), text, bad),
        Family::Stellar => key(stellar::parse_address(text), text, bad),
        Family::Substrate => key(bittensor::parse_address(text), text, bad),
    }
}

fn key(parsed: Option<[u8; 32]>, text: &str, bad: impl Fn() -> ChainError) -> ChainResult<Address> {
    match parsed {
        Some(bytes) if bytes != [0; 32] => {
            Ok(Address { text: text.to_owned(), raw: Raw::Key(bytes) })
        }
        _ => Err(bad()),
    }
}

/// The addresses of a request: `primary` first, then the others, checked and
/// without repeats; at most [`crate::common::MAX_ADDRESSES`] together.
pub fn list(network: Network, primary: &Address, others: &[String]) -> ChainResult<Vec<Address>> {
    let mut all = vec![primary.clone()];
    for (index, text) in others.iter().enumerate() {
        let parsed = parse(network, text).map_err(|_| {
            ChainError::InvalidAddress(format!(
                "addresses[{index}] is not a valid {} address",
                network.name()
            ))
        })?;
        if !all.contains(&parsed) {
            all.push(parsed);
        }
        if all.len() > crate::common::MAX_ADDRESSES {
            return Err(ChainError::invalid(format!(
                "at most {} addresses, the one in the path included",
                crate::common::MAX_ADDRESSES
            )));
        }
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_evm_address_is_checked_and_returned_in_its_checksum_form() {
        let lower = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        let parsed = parse(Network::Ethereum, lower).unwrap();
        assert_eq!(parsed.text, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        // A mixed-case address must carry its checksum.
        assert!(parse(Network::Ethereum, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96046").is_err());
        assert!(parse(Network::Ethereum, "d8da6bf26964af9d7eed9e03e53415d37aa96045").is_err());
        assert!(parse(Network::Ethereum, &format!("0x{}", "0".repeat(40))).is_err());
        assert!(parse(Network::Ethereum, " 0xd8da6bf26964af9d7eed9e03e53415d37aa96045").is_err());
    }

    #[test]
    fn each_family_takes_its_own_addresses_only() {
        assert!(parse(Network::Tron, "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9").is_ok());
        assert!(parse(Network::Tron, "0xd8da6bf26964af9d7eed9e03e53415d37aa96045").is_err());
        assert!(parse(Network::Bitcoin, "bc1q9qkjc8x853msxzsykp5qc5hjc0uav8ak4wwj5q").is_ok());
        assert!(parse(Network::Bitcoin, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").is_err());
        assert!(parse(Network::Solana, "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9").is_ok());
        assert!(
            parse(Network::Stellar, "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
                .is_ok()
        );
        assert!(parse(Network::Stellar, "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9").is_err());
        assert!(
            parse(Network::Bittensor, "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").is_ok()
        );
        assert!(parse(Network::Bittensor, "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9").is_err());
    }

    #[test]
    fn a_bad_address_is_not_repeated_in_the_error() {
        let error = parse(Network::Ethereum, "0xnot").unwrap_err();
        assert_eq!(error.code(), "invalid_address");
        assert!(!error.message().contains("0xnot"));
    }

    #[test]
    fn a_list_has_the_primary_first_and_no_repeats() {
        let me = parse(Network::Bitcoin, "bc1q9qkjc8x853msxzsykp5qc5hjc0uav8ak4wwj5q").unwrap();
        let other = "bc1qg3f7exyzcgpw48ysh58rgpuu7vyh9wnu64mae8".to_owned();
        let all = list(Network::Bitcoin, &me, &[other.clone(), me.text.clone(), other]).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], me);
        assert!(list(Network::Bitcoin, &me, &["nope".to_owned()]).is_err());
    }
}
