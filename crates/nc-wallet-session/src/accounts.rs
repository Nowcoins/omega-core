//! The nine accounts of an unlocked wallet. Public data only.

use nc_wallet_core::{ImportedKey, ImportedKeyKind, Mnemonic, Network, account_from_seed, derive};

use crate::error::SessionError;
use crate::types::{NetworkAccount, NetworkId};

/// The nine accounts. The BIP-39 seed (2048 rounds of PBKDF2) is made once
/// for the five networks that start from it.
pub(crate) fn accounts_of(
    mnemonic: &Mnemonic,
    passphrase: &str,
    index: u32,
) -> Result<Vec<NetworkAccount>, SessionError> {
    let seed = mnemonic.to_seed(passphrase);
    let entry =
        |network: NetworkId, family: Network, account: &nc_wallet_core::Account| NetworkAccount {
            network,
            address: account.address.clone(),
            public_key_hex: hex(&account.public_key),
            path: family.derivation_path(index),
        };
    let evm = account_from_seed(&seed, Network::Evm, index)?;
    let tron = account_from_seed(&seed, Network::Tron, index)?;
    let bitcoin = account_from_seed(&seed, Network::Bitcoin, index)?;
    let solana = account_from_seed(&seed, Network::Solana, index)?;
    let stellar = account_from_seed(&seed, Network::Stellar, index)?;
    let bittensor = derive(mnemonic, passphrase, Network::Bittensor, index)?;
    Ok(vec![
        entry(NetworkId::Ethereum, Network::Evm, &evm),
        entry(NetworkId::BnbChain, Network::Evm, &evm),
        entry(NetworkId::Polygon, Network::Evm, &evm),
        entry(NetworkId::Base, Network::Evm, &evm),
        entry(NetworkId::Tron, Network::Tron, &tron),
        entry(NetworkId::Bitcoin, Network::Bitcoin, &bitcoin),
        entry(NetworkId::Solana, Network::Solana, &solana),
        entry(NetworkId::Stellar, Network::Stellar, &stellar),
        entry(NetworkId::Bittensor, Network::Bittensor, &bittensor),
    ])
}

/// The accounts of a wallet that is one imported private key: the same key on each network
/// of its kind. There is no derivation path: the key was not derived here.
pub(crate) fn accounts_of_key(key: &ImportedKey) -> Result<Vec<NetworkAccount>, SessionError> {
    let entry = |network: NetworkId, family: Network| -> Result<NetworkAccount, SessionError> {
        let account = key.account(family)?;
        Ok(NetworkAccount {
            network,
            address: account.address,
            public_key_hex: hex(&account.public_key),
            path: String::new(),
        })
    };
    match key.kind() {
        ImportedKeyKind::Secp256k1 => Ok(vec![
            entry(NetworkId::Ethereum, Network::Evm)?,
            entry(NetworkId::BnbChain, Network::Evm)?,
            entry(NetworkId::Polygon, Network::Evm)?,
            entry(NetworkId::Base, Network::Evm)?,
            entry(NetworkId::Tron, Network::Tron)?,
        ]),
        ImportedKeyKind::Ed25519 => Ok(vec![entry(NetworkId::Solana, Network::Solana)?]),
    }
}

/// The Solana account Trust Wallet shows for a phrase, at its own path: public data only.
pub(crate) fn trust_wallet_solana_account(
    mnemonic: &Mnemonic,
    passphrase: &str,
) -> Result<NetworkAccount, SessionError> {
    let account = nc_wallet_core::solana::trust_wallet_account(&mnemonic.to_seed(passphrase))?;
    Ok(NetworkAccount {
        network: NetworkId::Solana,
        address: account.address,
        public_key_hex: hex(&account.public_key),
        path: nc_wallet_core::solana::TRUST_WALLET_PATH.to_owned(),
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
