//! Bitcoin: BIP-84 native segwit (P2WPKH, `bc1q…`), secp256k1 at
//! `m/84'/0'/{account}'/{0|1}/{index}`; the receive chain is `0`, the change chain
//! `1`. Electrum, Sparrow and Trust Wallet use the same paths. The wallet's account
//! number is the BIP-84 *account*, and the account is the whole of it: every address of
//! both chains (found by looking, see `nc-wallet-chain`), the one it shows to be paid
//! being index 0 of the receive chain.
//!
//! The address is the Bech32 (BIP-173) encoding of witness version 0 and the
//! 20-byte HASH160 (RIPEMD-160 of SHA-256) of the compressed public key.
//!
//! Spending: [`plan()`] chooses the outputs and lays the payment out,
//! [`Plan::sign`] signs it (BIP-143), [`tx`] and [`script`] are the encoder.

pub mod plan;
pub mod script;
pub mod tx;

#[cfg(test)]
mod vector_tests;

pub use plan::{Amount, FeeRate, Plan, Quote, Request, SignedTransaction, Utxo, plan, quote};
pub use tx::{Transaction, TxIn, TxOut};

use bip32::Prefix;
use ripemd::Ripemd160;
use sha2::{Digest as _, Sha256};

use crate::error::Error;
use crate::hd;
use crate::key::{Account, SigningKey};
use crate::mnemonic::Seed;

/// Which of an account's two address chains (the BIP-44 `change` level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    /// `m/84'/0'/0'/0/{index}`: addresses given out to be paid.
    Receive,
    /// `m/84'/0'/0'/1/{index}`: addresses that receive the wallet's own change.
    Change,
}

/// The path of BIP-84 account `account`, whose extended public key is [`account_zpub`].
fn account_path(account: u32) -> String {
    format!("m/84'/0'/{account}'")
}

fn path(account: u32, chain: Chain, index: u32) -> String {
    let chain = match chain {
        Chain::Receive => 0,
        Chain::Change => 1,
    };
    format!("{}/{chain}/{index}", account_path(account))
}

/// The private key of address `index` on `chain` of BIP-84 account `account`.
pub fn signing_key(
    seed: &Seed,
    account: u32,
    chain: Chain,
    index: u32,
) -> Result<SigningKey, Error> {
    let account = hd::check_index(account)?;
    let index = hd::check_index(index)?;
    hd::secp256k1_key(seed.expose_secret(), &path(account, chain, index))
        .ok_or(Error::InvalidKey(index))
}

/// The address and public key of address `index` on `chain` of BIP-84 account `account`.
pub fn account(seed: &Seed, account: u32, chain: Chain, index: u32) -> Result<Account, Error> {
    let key = signing_key(seed, account, chain, index)?;
    account_of(&key, index)
}

pub(crate) fn account_of(key: &SigningKey, index: u32) -> Result<Account, Error> {
    let address = address_from_public_key(key.public_key()).ok_or(Error::InvalidKey(index))?;
    Ok(Account { address, public_key: key.public_key().to_vec() })
}

/// The `bc1q…` address of a compressed secp256k1 public key (33 bytes);
/// `None` if the bytes are not a compressed point on the curve.
pub fn address_from_public_key(compressed: &[u8]) -> Option<String> {
    if compressed.len() != 33 || hd::secp256k1_uncompressed_xy(compressed).is_none() {
        return None;
    }
    let hash = Ripemd160::digest(Sha256::digest(compressed));
    bech32::segwit::encode_v0(bech32::hrp::BC, &hash).ok()
}

/// The `bc1q…` addresses `from..from + count` of `chain`, derived from an
/// account's extended public key (`zpub…`, as [`account_zpub`] writes it) with
/// no private key: what a history scan walks to find every address of the
/// account that has been used. `None` if the key is not a `zpub`/`xpub` of an
/// account, or an index is past the last normal element.
#[must_use]
pub fn addresses_from_zpub(zpub: &str, chain: Chain, from: u32, count: u32) -> Option<Vec<String>> {
    use std::str::FromStr as _;
    let account = bip32::XPub::from_str(zpub).ok()?;
    let level = match chain {
        Chain::Receive => 0,
        Chain::Change => 1,
    };
    let chain_key = account.derive_child(bip32::ChildNumber::new(level, false).ok()?).ok()?;
    (from..from.checked_add(count)?)
        .map(|index| {
            let child = chain_key.derive_child(bip32::ChildNumber::new(index, false).ok()?).ok()?;
            address_from_public_key(&bip32::PublicKey::to_bytes(child.public_key()))
        })
        .collect()
}

/// The extended public key of BIP-84 account `account` (`m/84'/0'/{account}'`) in `zpub…`
/// form (SLIP-132 version `0x04b24746`), for a watch-only reading: it derives every receive
/// and change address of the account, and no private key.
pub fn account_zpub(seed: &Seed, account: u32) -> Result<String, Error> {
    let account = hd::check_index(account)?;
    let node = hd::secp256k1_node(seed.expose_secret(), &account_path(account))
        .ok_or(Error::InvalidKey(account))?;
    Ok(node.public_key().to_string(Prefix::ZPUB))
}
