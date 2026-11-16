//! TRON: secp256k1 at `m/44'/195'/0'/0/{index}`, the path `TronLink` and Trust
//! Wallet use. The address is EVM's 20 bytes behind a `0x41` version byte,
//! written in base58check (a double-SHA-256 checksum), which gives `T…`.
//!
//! Signing: [`tx`] (TRX and TRC-20 transactions as protobuf `raw_data`),
//! [`message`] (`signMessageV2`), [`decode`] (what a call does) and [`raw`] (reading the
//! `raw_data` a web page built, strictly, so that it can be shown and signed).

pub mod decode;
pub mod message;
pub mod raw;
pub mod tx;

#[cfg(test)]
mod vector_tests;

pub use decode::{Call, classify_contract_call};
pub use message::{message_hash, sign_message};
pub use raw::RawDataError;
pub use tx::{
    AddressBytes, Contract, DEFAULT_EXPIRATION_MS, ReferenceBlock, SignedTransaction,
    TronTransaction, address_from_hash, format_address, parse_address,
};

use crate::error::Error;
use crate::evm::keccak_tail;
use crate::hd;
use crate::key::{Account, SigningKey};
use crate::mnemonic::Seed;
use crate::network::Network;

/// The version byte of a TRON mainnet address.
const VERSION: u8 = 0x41;

/// The private key of account `index`.
pub fn signing_key(seed: &Seed, index: u32) -> Result<SigningKey, Error> {
    let index = hd::check_index(index)?;
    hd::secp256k1_key(seed.expose_secret(), &Network::Tron.derivation_path(index))
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

/// The `T…` address of a compressed secp256k1 public key (33 bytes); `None`
/// if the bytes are not a point on the curve.
pub fn address_from_public_key(compressed: &[u8]) -> Option<String> {
    let xy = hd::secp256k1_uncompressed_xy(compressed)?;
    let mut payload = [0u8; 21];
    payload[0] = VERSION;
    payload[1..].copy_from_slice(&keccak_tail(&xy));
    Some(bs58::encode(payload).with_check().into_string())
}

/// The 20-byte account hash of a compressed secp256k1 public key.
pub(crate) fn address_hash_of_public_key(compressed: &[u8]) -> Option<[u8; 20]> {
    let xy = hd::secp256k1_uncompressed_xy(compressed)?;
    Some(keccak_tail(&xy))
}
