//! Signing messages: `personal_sign` (EIP-191, version `0x45`).

use super::tx::keccak;
use crate::ecdsa::{RecoverableSignature, sign_digest};
use crate::key::SigningKey;
use crate::tx_error::TxError;

/// The prefix of an EIP-191 `personal_sign` message, before the length.
const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";

/// The digest `personal_sign` signs: `keccak256("\x19Ethereum Signed
/// Message:\n" ‖ decimal length ‖ message)`. The length is of the message in
/// bytes.
#[must_use]
pub fn personal_message_hash(message: &[u8]) -> [u8; 32] {
    let length = message.len().to_string();
    let mut preimage = Vec::with_capacity(PREFIX.len() + length.len() + message.len());
    preimage.extend_from_slice(PREFIX);
    preimage.extend_from_slice(length.as_bytes());
    preimage.extend_from_slice(message);
    keccak(&preimage)
}

/// Signs `message` as `personal_sign` does. The wire form is
/// [`RecoverableSignature::to_rsv`] with a `v` offset of 27.
pub fn sign_personal_message(
    key: &SigningKey,
    message: &[u8],
) -> Result<RecoverableSignature, TxError> {
    sign_digest(key, &personal_message_hash(message))
}
