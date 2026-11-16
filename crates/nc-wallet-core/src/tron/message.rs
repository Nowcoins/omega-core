//! `signMessageV2`: TRON's counterpart of `personal_sign`.

use sha3::{Digest as _, Keccak256};

use crate::ecdsa::{RecoverableSignature, sign_digest};
use crate::key::SigningKey;
use crate::tx_error::TxError;

/// The prefix of a TRON signed message, before the length.
const PREFIX: &[u8] = b"\x19TRON Signed Message:\n";

/// The digest `signMessageV2` signs: `keccak256("\x19TRON Signed Message:\n"
/// ‖ decimal length ‖ message)`, the length being the message's in bytes.
#[must_use]
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    let length = message.len().to_string();
    let mut hasher = Keccak256::new();
    hasher.update(PREFIX);
    hasher.update(length.as_bytes());
    hasher.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Signs `message` as `TronWeb`'s `signMessageV2` does. The wire form is
/// [`RecoverableSignature::to_rsv`] with a `v` offset of 27, in hex.
pub fn sign_message(key: &SigningKey, message: &[u8]) -> Result<RecoverableSignature, TxError> {
    sign_digest(key, &message_hash(message))
}
