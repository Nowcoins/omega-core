//! The addresses of the unlocked wallet. Public data only.

use super::error::WalletError;
use crate::engine::engine;

/// The nine networks the wallet shows. Ethereum, BNB Chain, Polygon and Base
/// share one key and one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkId {
    /// Ethereum.
    Ethereum,
    /// BNB Chain.
    BnbChain,
    /// Polygon.
    Polygon,
    /// Base.
    Base,
    /// TRON.
    Tron,
    /// Bitcoin (native segwit).
    Bitcoin,
    /// Solana.
    Solana,
    /// Stellar.
    Stellar,
    /// Bittensor (SS58 prefix 42).
    Bittensor,
}

/// One account on one network: where to receive, and what the chain sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAccount {
    /// Which network.
    pub network: NetworkId,
    /// The address in the network's own format.
    pub address: String,
    /// The public key, hex: 33 bytes for secp256k1, 32 for ed25519 and sr25519.
    pub public_key_hex: String,
    /// The derivation path, as other wallets write it (`""` for Bittensor
    /// account 0, `//i` after).
    pub path: String,
}

/// The accounts of all nine networks at account number `index`, derived from
/// the unlocked wallet. Addresses and public keys only.
pub fn derive_accounts(index: u32) -> Result<Vec<NetworkAccount>, WalletError> {
    Ok(engine().accounts(index)?.into_iter().map(Into::into).collect())
}

/// The Solana account Trust Wallet shows for the phrase (`m/44'/501'/0'`), for the wallet being imported
/// (before it is sealed, when the person is looking at what they bring in) or the unlocked one. This wallet's
/// own Solana account 0 is at Phantom's path (`m/44'/501'/0'/0'`), so a phrase that came from Trust Wallet has
/// its Solana funds at this address and not at account 0's: read its balance and history like any address's
/// (`chain_call`), and tell the person where their funds are. The address and the public key only: no key
/// for this path leaves the core, so nothing can be signed for it.
pub fn derive_trust_wallet_solana_account() -> Result<NetworkAccount, WalletError> {
    Ok(engine().solana_trust_wallet_account()?.into())
}
