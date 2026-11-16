//! secp256k1 ECDSA over a 32-byte digest, the one signing primitive EVM,
//! TRON and Bitcoin share. Deterministic (RFC 6979, so the same key and
//! digest always give the same signature, and a retry is the same
//! transaction), recoverable, and always in the lower half of the curve order
//! (EIP-2; Bitcoin relays refuse the other form).

use k256::ecdsa::SigningKey as EcdsaKey;

use crate::key::{KeyScheme, SigningKey};
use crate::tx_error::TxError;

/// A secp256k1 signature with the recovery id that names the signer's key:
/// `r` and `s` big-endian, `s` in the lower half of the order, and the
/// recovery id 0 or 1 (the parity of the nonce point's `y`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverableSignature {
    /// The `r` value, 32 bytes big-endian.
    pub r: [u8; 32],
    /// The `s` value, 32 bytes big-endian, never above half the order.
    pub s: [u8; 32],
    /// 0 or 1.
    pub recovery_id: u8,
}

impl RecoverableSignature {
    /// `r ‖ s ‖ v` with `v` as written: the recovery id plus `v_offset` (27
    /// for `personal_sign`, typed data and TRON's `signMessageV2`; 0 for a
    /// TRON transaction's signature).
    #[must_use]
    pub fn to_rsv(&self, v_offset: u8) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.recovery_id.wrapping_add(v_offset);
        out
    }
}

/// Signs `digest` with `key`, which must be a secp256k1 key.
pub(crate) fn sign_digest(
    key: &SigningKey,
    digest: &[u8; 32],
) -> Result<RecoverableSignature, TxError> {
    if key.scheme() != KeyScheme::Secp256k1 {
        return Err(TxError::WrongKeyScheme);
    }
    let signer = EcdsaKey::from_slice(key.expose_secret()).map_err(|_| TxError::Signing)?;
    let (signature, recovery_id) = signer.sign_prehash_recoverable(digest);
    // Low-S, with the recovery id flipped along with it. k256 already
    // returns this form; the check keeps the promise whatever it does.
    let (signature, recovery_id) = low_s(signature, recovery_id.to_byte());
    let recovery_id = k256::ecdsa::RecoveryId::from_byte(recovery_id).ok_or(TxError::Signing)?;
    let (r, s) = signature.split_bytes();
    Ok(RecoverableSignature { r: r.into(), s: s.into(), recovery_id: recovery_id.to_byte() })
}

/// The signature with `s` in the lower half of the curve order, and the
/// recovery id that goes with it: negating `s` leaves the signature valid but
/// swaps which of the two candidate keys the id names.
fn low_s(signature: k256::ecdsa::Signature, recovery_id: u8) -> (k256::ecdsa::Signature, u8) {
    let low = signature.normalize_s();
    if low == signature { (signature, recovery_id) } else { (low, recovery_id ^ 1) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    use super::*;

    #[test]
    fn a_high_s_is_brought_down_and_the_recovery_id_flips() {
        // A signature of a fixed key, made high by negating s.
        let key = EcdsaKey::from_slice(&[7u8; 32]).unwrap();
        let digest = [9u8; 32];
        let (low, id) = key.sign_prehash_recoverable(&digest);
        assert_eq!(low.normalize_s(), low, "k256 signs in the lower half");
        let high = Signature::from_scalars(low.r(), -*low.s()).unwrap();
        assert_ne!(high.normalize_s(), high);

        let (brought_down, brought_id) = low_s(high, id.to_byte() ^ 1);
        assert_eq!(brought_down, low);
        assert_eq!(brought_id, id.to_byte());
        // The low one is left as it is.
        assert_eq!(low_s(low, id.to_byte()), (low, id.to_byte()));
        // The low form recovers to the key with its id.
        let recovered = VerifyingKey::recover_from_prehash(
            &digest,
            &brought_down,
            RecoveryId::from_byte(brought_id).unwrap(),
        )
        .unwrap();
        assert_eq!(&recovered, key.verifying_key());
    }
}
