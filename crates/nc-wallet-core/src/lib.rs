//! The signing core of Nowcoin Omega, the self-custody wallet: recovery
//! phrases, key derivation and addresses, and transaction
//! building and signing.
//!
//! The crate has no I/O and no async, and takes no dependency on a chain
//! client, `tokio` or `reqwest`. It builds for the Android app (native, through
//! `flutter_rust_bridge`) and for the Chrome extension (`wasm32-unknown-unknown`).
//! New phrases take their randomness from the operating system, and from the
//! browser's `crypto.getRandomValues` on WebAssembly; if that source is
//! missing, the build (wasm) or the call (everywhere) fails. There is no
//! fallback to a weaker source.
//!
//! # Using it
//!
//! ```
//! use nc_wallet_core::{Mnemonic, Network, WordCount, derive};
//!
//! // A new 12-word phrase (or `Mnemonic::parse` for an imported one)...
//! let phrase = Mnemonic::generate(WordCount::Twelve).unwrap();
//! // ...and the address of the first EVM account, with no passphrase.
//! let account = derive(&phrase, "", Network::Evm, 0).unwrap();
//! assert!(account.address.starts_with("0x"));
//! ```
//!
//! [`derive()`] returns the public half, an [`Account`]. The private half comes
//! out only through [`signing_key`], which is for the signing code.
//!
//! # Networks, paths and where each is checked
//!
//! The paths are the ones MetaMask, Trust Wallet, `TronLink`, Electrum, Phantom,
//! Lobstr and `btcli` use, so a phrase moved between them shows the same
//! addresses, on every network but one: **Solana**. Phantom and Solflare use
//! `m/44'/501'/i'/0'`, as here, but Trust Wallet's first Solana account is at
//! `m/44'/501'/0'`, so a phrase from Trust Wallet shows another Solana address
//! (`solana::trust_wallet_account` is that address, for an import to look for
//! funds there). Every row is pinned by test vectors taken from the sources
//! named; the tests carry the exact reference (repository, file and commit)
//! next to each value.
//!
//! | Network | Path (account `i`) | Key and address | Vectors from |
//! |---|---|---|---|
//! | EVM | `m/44'/60'/0'/0/i` | secp256k1, EIP-55 | Trezor firmware, Trust Wallet Core, Polkadot.js, py-substrate-interface (ECDSA), the EIP-55 text |
//! | TRON | `m/44'/195'/0'/0/i` | secp256k1, base58check, `0x41` | Trezor firmware, Trust Wallet Core |
//! | Bitcoin | account `i` is BIP-84 account `m/84'/0'/i'`: it shows `/0/0` and holds every `/0/n` and `/1/n`; its `zpub` is at `m/84'/0'/i'` | secp256k1, P2WPKH `bc1q…` | BIP-84, Trust Wallet Core |
//! | Solana | `m/44'/501'/i'/0'` (Trust Wallet's: `m/44'/501'/0'`) | ed25519 (SLIP-10), base58 | Trezor firmware, SLIP-10, Trust Wallet Core (its path) |
//! | Stellar | `m/44'/148'/i'` | ed25519 (SLIP-10), strkey `G…` | SEP-0005, Trezor firmware, Trust Wallet Core |
//! | Bittensor | root key for `i = 0`, hard junction `//i` for `i >= 1` | sr25519, SS58 prefix 42 | Substrate (`sp-core`, `substrate-bip39`), Polkadot.js, py-substrate-interface |
//!
//! Underneath: BIP-39 (Trezor's vectors), BIP-32 (the BIP's vectors) and
//! SLIP-10 for ed25519 (the SLIP's vectors).
//!
//! # Signing: EVM, TRON and Bitcoin
//!
//! Everything a transaction needs from the network (the nonce, the fee
//! rates, the unspent outputs, the reference block, the time) is an input:
//! nothing here reads a chain. A signing function takes the [`SigningKey`] for
//! one account and returns the bytes to broadcast.
//!
//! ```
//! use nc_wallet_core::evm::{EvmChain, EvmTransaction, Fees};
//! use nc_wallet_core::{Mnemonic, Network, WordCount, signing_key};
//!
//! let phrase = Mnemonic::generate(WordCount::Twelve).unwrap();
//! let key = signing_key(&phrase, "", Network::Evm, 0).unwrap();
//! let transfer = EvmTransaction {
//!     chain_id: EvmChain::Base.chain_id(),
//!     nonce: 0,
//!     to: [0x11; 20],
//!     value: 1_000_000_000_000_000,
//!     data: Vec::new(),
//!     gas_limit: 21_000,
//!     fees: Fees::Eip1559 { max_fee_per_gas: 2_000_000_000, max_priority_fee_per_gas: 1_000_000 },
//! };
//! let signed = transfer.sign(&key).unwrap();
//! assert_eq!(signed.raw[0], 0x02); // an EIP-1559 transaction
//! assert!(signed.hash_hex().starts_with("0x"));
//! ```
//!
//! | Network | What is built and signed | Module |
//! |---|---|---|
//! | EVM (Ethereum, BNB Chain, Polygon, Base) | legacy and EIP-1559 transactions, ERC-20 `transfer` and `approve`, `personal_sign`, EIP-712 typed data | [`evm`] |
//! | TRON | TRX and TRC-20 transactions (protobuf `raw_data`), `signMessageV2` | [`tron`] |
//! | Bitcoin | P2WPKH payments (BIP-143), coin selection, change, replace-by-fee | [`bitcoin`] |
//!
//! For an approval screen, [`evm::classify_call`], [`evm::TypedData::summary`]
//! and [`tron::classify_contract_call`] read what a request would do (a
//! native transfer, a token `transfer`, `approve` (flagged when unlimited) or
//! `transferFrom`, `setApprovalForAll`, an EIP-2612 `permit`, or an unknown
//! contract call). They only read bytes; nothing is executed.
//!
//! Each encoder is pinned by vectors from outside this crate: the README
//! lists the sources.
//!
//! # The vault
//!
//! [`vault`] seals a phrase under a password (Argon2id, then AES-256-GCM) into
//! one versioned blob an app keeps on the device, and opens it again; see its
//! module documentation for the format. [`wordlist`] is the BIP-39 English list,
//! for screens that take a phrase as typed input.
//!
//! # Secrets
//!
//! A [`Mnemonic`], a [`Seed`] and a [`SigningKey`] wipe themselves when
//! dropped, print nothing of themselves under `Debug` and have no `Display`.
//! Each one is read through a method named for it (`expose_phrase`,
//! `expose_secret`), so a search finds every reader. Wiping is best-effort
//! for what the dependencies hold in their own temporaries.
//!
//! # Not covered here
//!
//! Soft and public derivation of sr25519, other wordlists than English, and
//! the Bittensor-EVM gas account (which stays an EVM account).

pub mod bitcoin;
pub mod bittensor;
pub mod cache;
pub mod evm;
pub mod limits;
pub mod solana;
pub mod stellar;
pub mod text;
pub mod tron;
pub mod vault;
pub mod wordlist;

mod ecdsa;
mod error;
mod hd;
mod hexutil;
mod key;
mod mnemonic;
mod network;
mod tx_error;

pub use ecdsa::RecoverableSignature;
pub use error::{Error, MnemonicError};
pub use key::{Account, KeyScheme, SigningKey};
pub use mnemonic::{Mnemonic, Seed, WordCount};
pub use network::Network;
pub use tx_error::TxError;

/// The address and public key of account `index` on `network`, from a
/// recovery phrase and its optional BIP-39 passphrase (`""` for none).
///
/// For Bitcoin this is the receive address; the change chain and the account
/// `zpub` are in [`bitcoin`].
pub fn derive(
    mnemonic: &Mnemonic,
    passphrase: &str,
    network: Network,
    index: u32,
) -> Result<Account, Error> {
    match network {
        Network::Bittensor => bittensor::account(mnemonic, passphrase, index),
        _ => account_from_seed(&mnemonic.to_seed(passphrase), network, index),
    }
}

/// The private key of account `index` on `network`. This is the one door
/// through which a private key leaves the crate; it is for the signing code
/// which should hold the key only as long as one signature takes.
pub fn signing_key(
    mnemonic: &Mnemonic,
    passphrase: &str,
    network: Network,
    index: u32,
) -> Result<SigningKey, Error> {
    match network {
        Network::Bittensor => bittensor::signing_key(mnemonic, passphrase, index),
        _ => signing_key_from_seed(&mnemonic.to_seed(passphrase), network, index),
    }
}

/// [`derive()`] for the networks that start from the BIP-39 seed, when the seed
/// is already computed (it costs 2048 PBKDF2 rounds, so do it once for all
/// networks).
///
/// Bittensor does not start from the seed; for it this returns
/// [`Error::NeedsPhrase`], and [`derive()`] must be used.
pub fn account_from_seed(seed: &Seed, network: Network, index: u32) -> Result<Account, Error> {
    match network {
        Network::Evm => evm::account(seed, index),
        Network::Tron => tron::account(seed, index),
        Network::Bitcoin => bitcoin::account(seed, index, bitcoin::Chain::Receive, 0),
        Network::Solana => solana::account(seed, index),
        Network::Stellar => stellar::account(seed, index),
        Network::Bittensor => Err(Error::NeedsPhrase),
    }
}

/// [`signing_key()`] for the networks that start from the BIP-39 seed; see
/// [`account_from_seed`].
pub fn signing_key_from_seed(
    seed: &Seed,
    network: Network,
    index: u32,
) -> Result<SigningKey, Error> {
    match network {
        Network::Evm => evm::signing_key(seed, index),
        Network::Tron => tron::signing_key(seed, index),
        Network::Bitcoin => bitcoin::signing_key(seed, index, bitcoin::Chain::Receive, 0),
        Network::Solana => solana::signing_key(seed, index),
        Network::Stellar => stellar::signing_key(seed, index),
        Network::Bittensor => Err(Error::NeedsPhrase),
    }
}
