//! Bitcoin transactions: their wire format, their ids, their size, and the
//! BIP-143 digest a P2WPKH input is signed over (the writing half; this
//! wallet reads no blocks), pinned by
//! BIP-143's published vector and by real mainnet transactions
//! (`tests/bitcoin_signing.rs`).

use sha2::{Digest as _, Sha256};

use crate::ecdsa::{RecoverableSignature, sign_digest};
use crate::key::SigningKey;
use crate::tx_error::TxError;

use super::script::{hash160, p2pkh_script};

/// Every bitcoin there will ever be, in satoshis. An output claiming more is
/// not one a valid block can hold.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// The only sighash type the wallet signs with: every input and every
/// output, so nothing about a signed transaction can be changed.
pub const SIGHASH_ALL: u32 = 1;

/// The sequence number every input the wallet writes carries: below
/// `0xFFFFFFFE`, which signals that the transaction may be replaced by one
/// paying more (BIP-125, replace-by-fee).
pub const RBF_SEQUENCE: u32 = 0xFFFF_FFFD;

/// The version the wallet writes: 2, what wallets have written for years.
pub const TX_VERSION: u32 = 2;

/// Non-witness bytes of an input spending a segwit output: the outpoint (36),
/// an empty script's length (1) and the sequence (4).
pub const SEGWIT_INPUT_BASE_BYTES: u64 = 41;

/// Witness bytes of a P2WPKH input, at most: the item count, a signature of up
/// to 72 bytes (a 71-byte DER encoding when `r` has its top bit set, and the
/// sighash byte) with its length, and a 33-byte key with its length.
pub const P2WPKH_WITNESS_MAX_BYTES: u64 = 1 + 1 + 72 + 1 + 33;

/// One input: the output it spends, and what unlocks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// The transaction whose output this spends, in internal byte order: the
    /// reverse of how its id is written.
    pub prev_txid: [u8; 32],
    /// Which of that transaction's outputs.
    pub prev_vout: u32,
    /// The unlocking script. Empty for a segwit spend, whose witness unlocks
    /// it instead.
    pub script_sig: Vec<u8>,
    /// The sequence number.
    pub sequence: u32,
    /// The witness stack. Empty until the input is signed.
    pub witness: Vec<Vec<u8>>,
}

/// One output: an amount, and the script that must be satisfied to spend it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// In satoshis.
    pub value: u64,
    /// The locking script, which is what an address stands for.
    pub script_pubkey: Vec<u8>,
}

/// A transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The version.
    pub version: u32,
    /// What it spends.
    pub inputs: Vec<TxIn>,
    /// What it creates.
    pub outputs: Vec<TxOut>,
    /// The height or time before which it cannot be mined; zero for none.
    pub lock_time: u32,
}

impl Transaction {
    /// Whether any input carries a witness, and so whether the transaction is
    /// written in the segwit form.
    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// The transaction as it is sent and mined: the segwit form when it
    /// carries witnesses, the original form otherwise.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.write(self.has_witness())
    }

    /// The transaction without its witnesses: what its id is the hash of.
    #[must_use]
    pub fn encode_without_witness(&self) -> Vec<u8> {
        self.write(false)
    }

    fn write(&self, with_witness: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            10 + self.inputs.len() * 150 + self.outputs.len() * 44 + usize::from(with_witness),
        );
        out.extend_from_slice(&self.version.to_le_bytes());
        if with_witness {
            out.extend_from_slice(&[0x00, 0x01]);
        }
        write_compact_size(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.prev_txid);
            out.extend_from_slice(&input.prev_vout.to_le_bytes());
            write_bytes(&mut out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact_size(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            write_output(&mut out, output);
        }
        if with_witness {
            for input in &self.inputs {
                write_compact_size(&mut out, input.witness.len() as u64);
                for item in &input.witness {
                    write_bytes(&mut out, item);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// The transaction id, in internal byte order: the hash of the
    /// transaction without its witnesses, so it is fixed before anything is
    /// signed.
    #[must_use]
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.encode_without_witness())
    }

    /// The transaction id as it is written: hex, in reversed byte order.
    #[must_use]
    pub fn txid_hex(&self) -> String {
        hash_to_hex(&self.txid())
    }

    /// The weight: each byte outside the witnesses counts four times, each
    /// byte inside them once.
    #[must_use]
    pub fn weight(&self) -> u64 {
        let base = self.encode_without_witness().len() as u64;
        let total = self.encode().len() as u64;
        base * 3 + total
    }

    /// The virtual size a fee rate is charged on: the weight over four,
    /// rounded up.
    #[must_use]
    pub fn vsize(&self) -> u64 {
        self.weight().div_ceil(4)
    }

    /// Signs input `index`, which spends a P2WPKH output of `value`
    /// satoshis, with `key`: the BIP-143 `SIGHASH_ALL` digest, signed
    /// deterministically (RFC 6979), written as the witness `[signature ‖
    /// 0x01, public key]`.
    ///
    /// For a transaction with many inputs, [`SighashCache`] is faster.
    pub fn sign_p2wpkh_input(
        &mut self,
        index: usize,
        value: u64,
        key: &SigningKey,
    ) -> Result<(), TxError> {
        let cache = SighashCache::new(self);
        self.sign_p2wpkh_input_cached(&cache, index, value, key)
    }

    /// [`Self::sign_p2wpkh_input`] with the shared digest parts computed once.
    pub fn sign_p2wpkh_input_cached(
        &mut self,
        cache: &SighashCache,
        index: usize,
        value: u64,
        key: &SigningKey,
    ) -> Result<(), TxError> {
        let public = <[u8; 33]>::try_from(key.public_key()).map_err(|_| TxError::WrongKeyScheme)?;
        let digest = cache
            .p2wpkh_digest(self, index, &hash160(&public), value)
            .ok_or(TxError::invalid("input", "there is no such input"))?;
        let signature = sign_digest(key, &digest)?;
        let mut witness_signature = der_signature(&signature);
        witness_signature.push(u8::try_from(SIGHASH_ALL).unwrap_or(1));
        self.inputs[index].witness = vec![witness_signature, public.to_vec()];
        Ok(())
    }
}

/// The virtual size of a transaction spending `inputs` P2WPKH outputs into
/// outputs with these scripts, once signed: what its fee is priced on.
///
/// Every signature is taken at its largest, so the transaction as signed is at
/// most this size and never pays below the rate it was priced at. It comes
/// out a quarter of a virtual byte smaller for each signature whose `r`
/// happens to need no padding byte, which is about half of them.
#[must_use]
pub fn estimate_vsize(inputs: usize, output_scripts: &[&[u8]]) -> u64 {
    let inputs = inputs as u64;
    let outputs: u64 = output_scripts.iter().map(|script| output_bytes(script.len())).sum();
    let base = 4
        + compact_size_len(inputs)
        + inputs * SEGWIT_INPUT_BASE_BYTES
        + compact_size_len(output_scripts.len() as u64)
        + outputs
        + 4;
    // The marker and flag, then each input's witness.
    let witness = if inputs == 0 { 0 } else { 2 + inputs * P2WPKH_WITNESS_MAX_BYTES };
    (base * 4 + witness).div_ceil(4)
}

/// Bytes an output with a script of `script_len` bytes takes: the value, the
/// script's length and the script.
#[must_use]
pub fn output_bytes(script_len: usize) -> u64 {
    8 + compact_size_len(script_len as u64) + script_len as u64
}

/// The parts of a BIP-143 digest every input of a transaction shares:
/// computed once, rather than once per input, which would make signing a
/// transaction with many inputs take time quadratic in their number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SighashCache {
    prevouts: [u8; 32],
    sequences: [u8; 32],
    outputs: [u8; 32],
}

impl SighashCache {
    /// Computes the shared parts for `transaction`.
    #[must_use]
    pub fn new(transaction: &Transaction) -> Self {
        let mut prevouts = Vec::with_capacity(transaction.inputs.len() * 36);
        let mut sequences = Vec::with_capacity(transaction.inputs.len() * 4);
        for input in &transaction.inputs {
            prevouts.extend_from_slice(&input.prev_txid);
            prevouts.extend_from_slice(&input.prev_vout.to_le_bytes());
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }
        let mut outputs = Vec::with_capacity(transaction.outputs.len() * 34);
        for output in &transaction.outputs {
            write_output(&mut outputs, output);
        }
        Self {
            prevouts: sha256d(&prevouts),
            sequences: sha256d(&sequences),
            outputs: sha256d(&outputs),
        }
    }

    /// The digest input `index` signs with `SIGHASH_ALL` (BIP-143): for an
    /// output locked by `script_code` and holding `value` satoshis. `None` if
    /// there is no such input.
    #[must_use]
    pub fn digest(
        &self,
        transaction: &Transaction,
        index: usize,
        script_code: &[u8],
        value: u64,
    ) -> Option<[u8; 32]> {
        let input = transaction.inputs.get(index)?;
        let mut preimage = Vec::with_capacity(160 + script_code.len());
        preimage.extend_from_slice(&transaction.version.to_le_bytes());
        preimage.extend_from_slice(&self.prevouts);
        preimage.extend_from_slice(&self.sequences);
        preimage.extend_from_slice(&input.prev_txid);
        preimage.extend_from_slice(&input.prev_vout.to_le_bytes());
        write_bytes(&mut preimage, script_code);
        preimage.extend_from_slice(&value.to_le_bytes());
        preimage.extend_from_slice(&input.sequence.to_le_bytes());
        preimage.extend_from_slice(&self.outputs);
        preimage.extend_from_slice(&transaction.lock_time.to_le_bytes());
        preimage.extend_from_slice(&SIGHASH_ALL.to_le_bytes());
        Some(sha256d(&preimage))
    }

    /// The digest input `index` signs when it spends a P2WPKH output of
    /// `value` satoshis paying the key hash `pubkey_hash`. Its script code is
    /// the P2PKH script for the same hash, as BIP-143 has it.
    #[must_use]
    pub fn p2wpkh_digest(
        &self,
        transaction: &Transaction,
        index: usize,
        pubkey_hash: &[u8; 20],
        value: u64,
    ) -> Option<[u8; 32]> {
        self.digest(transaction, index, &p2pkh_script(pubkey_hash), value)
    }
}

/// SHA-256 twice: the hash of transactions, blocks and headers alike.
#[must_use]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let once = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(once));
    out
}

/// A hash as it is written: hex, in reversed byte order.
#[must_use]
pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    let mut reversed = *hash;
    reversed.reverse();
    crate::hexutil::encode(&reversed)
}

/// A hash from how it is written, back in internal byte order. `None` for
/// anything but 64 hex digits.
#[must_use]
pub fn hash_from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut hash: [u8; 32] = crate::hexutil::decode(text)?.try_into().ok()?;
    hash.reverse();
    Some(hash)
}

/// Bytes a count takes in the compact form counts are written in.
#[must_use]
pub const fn compact_size_len(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Writes a count in its compact form: one byte below `0xfd`, otherwise a
/// marker byte and two, four or eight bytes.
fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(u8::try_from(n).unwrap_or(0xfc)),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_output(out: &mut Vec<u8>, output: &TxOut) {
    out.extend_from_slice(&output.value.to_le_bytes());
    write_bytes(out, &output.script_pubkey);
}

/// A signature in the strict DER form nodes require (BIP-66): each integer in
/// as few bytes as it takes, with a zero byte in front where its top bit would
/// otherwise read as a sign.
#[must_use]
pub fn der_signature(signature: &RecoverableSignature) -> Vec<u8> {
    let r = der_integer(&signature.r);
    let s = der_integer(&signature.s);
    let mut out = Vec::with_capacity(6 + r.len() + s.len());
    out.push(0x30);
    out.push(u8::try_from(4 + r.len() + s.len()).unwrap_or(u8::MAX));
    for integer in [r, s] {
        out.push(0x02);
        out.push(u8::try_from(integer.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(&integer);
    }
    out
}

fn der_integer(bytes: &[u8; 32]) -> Vec<u8> {
    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(31);
    let trimmed = &bytes[start..];
    let mut out = Vec::with_capacity(33);
    if trimmed.first().is_some_and(|byte| byte & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(trimmed);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn counts_take_their_shortest_form() {
        for (n, encoded) in [
            (0_u64, "00"),
            (0xfc, "fc"),
            (0xfd, "fdfd00"),
            (0xffff, "fdffff"),
            (0x1_0000, "fe00000100"),
            (0x1_0000_0000, "ff0000000001000000"),
        ] {
            let mut out = Vec::new();
            write_compact_size(&mut out, n);
            assert_eq!(crate::hexutil::encode(&out), encoded);
            assert_eq!(out.len() as u64, compact_size_len(n));
        }
    }

    #[test]
    fn der_integers_are_minimal_and_positive() {
        let mut r = [0u8; 32];
        r[31] = 1;
        let mut s = [0xffu8; 32];
        s[0] = 0x7f;
        let der = der_signature(&RecoverableSignature { r, s, recovery_id: 0 });
        assert_eq!(&der[..5], &[0x30, 4 + 1 + 32, 0x02, 1, 1]);
        assert_eq!(&der[5..7], &[0x02, 32], "no pad when the top bit is clear");

        let high = [0x80u8; 32];
        let der = der_signature(&RecoverableSignature { r: high, s: high, recovery_id: 0 });
        assert_eq!(&der[..5], &[0x30, 4 + 33 + 33, 0x02, 33, 0x00], "a pad keeps it positive");
    }

    #[test]
    fn hashes_are_written_in_reverse() {
        let text = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let hash = hash_from_hex(text).unwrap();
        assert_eq!(hash[31], 0x00, "the leading zeros of a block hash are its last bytes");
        assert_eq!(hash_to_hex(&hash), text);
        assert!(hash_from_hex("00").is_none());
        assert!(hash_from_hex(&"zz".repeat(32)).is_none());
    }
}
