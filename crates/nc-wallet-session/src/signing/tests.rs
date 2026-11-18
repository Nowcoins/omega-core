//! Tests of the signing requests. The wallet is the BIP-39 reference phrase
//! (entropy all zero), whose addresses every wallet documents; the vectors are
//! the core's own (`nc-wallet-core/tests/vectors`).
//!
//! The rule for every kind: decode, sign, then prove the signature belongs to
//! the account (recover the secp256k1 signer, or verify the ed25519 / sr25519
//! signature against the derived public key).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::similar_names,
    clippy::needless_pass_by_value,
    clippy::items_after_statements
)]

mod address;
mod approval;
mod evm;
mod send;
mod solana;
mod tron;
mod warnings;

use nc_wallet_core::Mnemonic;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Decoded, SigningError};
use crate::engine::{Engine, Secrets};

pub(super) const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Account 0 of the reference phrase on the EVM networks (MetaMask's address
/// for it).
pub(super) const EVM_0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

pub(super) fn secrets() -> Secrets {
    Secrets::Phrase {
        mnemonic: Mnemonic::parse(ABANDON).unwrap(),
        passphrase: Zeroizing::new(String::new()),
    }
}

pub(super) fn engine() -> Engine {
    let mut engine = Engine::new();
    engine.set_session_for_tests(secrets());
    engine
}

/// The reference phrase's account 0 on `family`, written as its owner would export the key:
/// 64 hexadecimal digits, or Solana's base58 of the seed and the public key.
pub(super) fn exported_key(family: nc_wallet_core::Network) -> String {
    let key =
        nc_wallet_core::signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", family, 0).unwrap();
    nc_wallet_core::ImportedKey::from_parts(
        if family == nc_wallet_core::Network::Solana {
            nc_wallet_core::ImportedKeyKind::Ed25519
        } else {
            nc_wallet_core::ImportedKeyKind::Secp256k1
        },
        key.expose_secret(),
    )
    .unwrap()
    .expose_text()
    .to_string()
}

/// A wallet that is one imported private key, unlocked.
pub(super) fn key_engine(text: &str) -> Engine {
    let mut engine = Engine::new();
    engine.set_session_for_tests(Secrets::Key(nc_wallet_core::ImportedKey::parse(text).unwrap()));
    engine
}

pub(super) fn decode(
    engine: &Engine,
    index: u32,
    request: &Value,
) -> Result<Decoded, SigningError> {
    engine.decode_request(index, &request.to_string())
}

/// Decodes and signs a request, as the extension does.
pub(super) fn sign(engine: &Engine, index: u32, request: &Value) -> Value {
    let text = request.to_string();
    let decoded = engine.decode_request(index, &text).unwrap();
    engine.sign_request(index, &text, &decoded.approval).unwrap()
}

pub(super) fn code(result: Result<impl std::fmt::Debug, SigningError>) -> &'static str {
    result.unwrap_err().code()
}

pub(super) fn hex(text: &str) -> Vec<u8> {
    super::hexs::decode(text.trim_start_matches("0x")).unwrap()
}
