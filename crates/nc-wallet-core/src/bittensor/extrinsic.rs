//! Signed transfers, hand-encoded.
//!
//! Only what a wallet sends: a
//! `Balances.transfer_keep_alive` in a signed extrinsic of format 4 from an
//! sr25519 key:
//!
//! ```text
//! Compact(length) ‖ 0x84 ‖ 0x00 sender ‖ 0x01 signature ‖ explicit ‖ call
//! ```
//!
//! The signature covers `call ‖ explicit ‖ implicit`, where the explicit part
//! travels in the extrinsic and the implicit part is what the chain already
//! knows and each validator supplies for itself:
//!
//! ```text
//! explicit = era ‖ Compact(nonce) ‖ Compact(tip) ‖ metadata-hash mode 0
//! implicit = spec version ‖ transaction version ‖ genesis ‖ era birth hash ‖ None
//! ```
//!
//! That layout follows from the transaction extensions Finney's runtime lists,
//! in order; the four of its own (sudo, shielded, subtensor, drand) add nothing
//! to either part. The wallet's API checks the runtime's version before it
//! hands out the inputs here: a runtime that changed the list would also bump
//! its spec version, and a signature made for the old layout then fails to
//! verify rather than doing something else.

use rand_core::{CryptoRng, RngCore};
use schnorrkel::context::SigningTranscript;
use schnorrkel::{ExpansionMode, MiniSecretKey, PublicKey, Signature, signing_context};
use std::cell::RefCell;
use zeroize::Zeroize as _;

use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;

use crate::key::{KeyScheme, SigningKey};

/// The Balances pallet's index in the runtime.
pub const BALANCES: u8 = 5;
/// `Balances.transfer_keep_alive(dest, value)`'s index in the pallet.
pub const TRANSFER_KEEP_ALIVE: u8 = 3;

/// Signed, format 4: the high bit says signed, the rest is the version.
const SIGNED_V4: u8 = 0x84;
/// `MultiAddress::Id`: a plain 32-byte account.
const MULTI_ADDRESS_ID: u8 = 0;
/// `MultiSignature::Sr25519`.
const SR25519: u8 = 1;
/// `CheckMetadataHash` disabled: the signature does not commit to a hash of
/// the metadata, which is what hardware wallets use it for.
const METADATA_HASH_DISABLED: u8 = 0;
/// The implicit counterpart: no metadata hash.
const NO_METADATA_HASH: u8 = 0;
/// A signing payload longer than this is signed as its BLAKE2-256 hash.
const MAX_UNHASHED_PAYLOAD: usize = 256;

/// The signing context of every sr25519 signature a Substrate runtime
/// verifies.
pub const SR25519_CONTEXT: &[u8] = b"substrate";

/// Finney's genesis hash: every signature covers it, so a transaction built for
/// another chain (or for a node's lie about which chain this is) can never be
/// valid here. The engine pins it rather than taking it from its inputs.
pub const FINNEY_GENESIS: [u8; 32] = [
    0x2f, 0x05, 0x55, 0xcc, 0x76, 0xfc, 0x28, 0x40, 0xa2, 0x5a, 0x6e, 0xa3, 0xb9, 0x63, 0x71, 0x46,
    0x80, 0x6f, 0x1f, 0x44, 0xb0, 0x90, 0xc1, 0x75, 0xff, 0xde, 0x2a, 0x7e, 0x5a, 0xb3, 0x6c, 0x03,
];

/// Where a call lives in the runtime: its pallet's index, then its own index in
/// the pallet. They come from the runtime's metadata; the engine pins
/// [`CallIndex::BALANCES_TRANSFER_KEEP_ALIVE`] and refuses any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallIndex {
    /// The pallet's index.
    pub pallet: u8,
    /// The call's index within the pallet.
    pub call: u8,
}

impl CallIndex {
    /// `Balances.transfer_keep_alive` on Finney: pallet 5, call 3.
    pub const BALANCES_TRANSFER_KEEP_ALIVE: Self =
        Self { pallet: BALANCES, call: TRANSFER_KEEP_ALIVE };
}

/// How long a transaction lives: a mortal era, in Substrate's terms.
///
/// A period (a power of two from 4 to 65,536) and a phase, the birth block's
/// place within the period. The transaction is valid from its birth block
/// until `period` blocks later, and commits to the birth block's hash, so it
/// cannot be replayed on another fork either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Era {
    period: u64,
    phase: u64,
}

impl Era {
    /// The era of `period` blocks that begins at block `current`, with the
    /// rounding Substrate applies: the period up to a power of two between 4
    /// and 65,536, and for periods over 4,096 the phase down to a multiple of
    /// `period / 4096`.
    #[must_use]
    pub fn mortal(period: u64, current: u64) -> Self {
        let period = period.checked_next_power_of_two().unwrap_or(1 << 16).clamp(4, 1 << 16);
        let phase = current % period;
        let quantum = (period >> 12).max(1);
        Self { period, phase: phase / quantum * quantum }
    }

    /// Its length in blocks.
    #[must_use]
    pub const fn period(self) -> u64 {
        self.period
    }

    /// Its birth block's position within the period.
    #[must_use]
    pub const fn phase(self) -> u64 {
        self.phase
    }

    /// Its two bytes: the period's exponent, less one, in the low four bits
    /// and the (quantized) phase above them, little-endian.
    #[must_use]
    pub fn encode(self) -> [u8; 2] {
        let quantum = (self.period >> 12).max(1);
        let exponent = u64::from(self.period.trailing_zeros().saturating_sub(1).clamp(1, 15));
        let encoded = exponent | ((self.phase / quantum) << 4);
        let bytes = encoded.to_le_bytes();
        [bytes[0], bytes[1]]
    }

    /// Reads a mortal era's two bytes, as Substrate does. `None` for bytes
    /// that describe no era; an immortal era is a single zero byte and is
    /// never read here.
    #[must_use]
    pub fn decode(bytes: [u8; 2]) -> Option<Self> {
        if bytes[0] == 0 {
            return None;
        }
        let encoded = u64::from(u16::from_le_bytes(bytes));
        let period = 2_u64 << (encoded % (1 << 4));
        let quantum = (period >> 12).max(1);
        let phase = (encoded >> 4) * quantum;
        (period >= 4 && phase < period).then_some(Self { period, phase })
    }

    /// The birth block of the era, as seen from block `current`: the latest
    /// block no later than `current` whose position in the period is the
    /// phase.
    #[must_use]
    pub const fn birth(self, current: u64) -> u64 {
        let current = if current > self.phase { current } else { self.phase };
        (current - self.phase) / self.period * self.period + self.phase
    }

    /// The first block in which a transaction of this era, as seen from block
    /// `current`, is no longer valid.
    #[must_use]
    pub const fn death(self, current: u64) -> u64 {
        self.birth(current).saturating_add(self.period)
    }
}

/// Why a transfer cannot be encoded or signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    /// A transfer of nothing is not a transfer.
    #[error("the amount must be more than zero")]
    ZeroValue,
    /// The era's period must be a power of two from 4 to 4,096 blocks, where
    /// the era needs no rounding and its birth block is exactly the block
    /// whose hash was given.
    #[error("the era's period must be a power of two from 4 to 4096")]
    EraPeriod,
    /// The key is not an sr25519 key.
    #[error("a Bittensor transaction is signed with an sr25519 key")]
    WrongKeyScheme,
    /// The transfer's sender is another account than the key's.
    #[error("the key is not the transfer's sender")]
    NotTheSender,
    /// The system's random source failed. No signature is made without it.
    #[error("the system's secure random source is unavailable")]
    Randomness,
}

/// A transfer ready to sign: everything its signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// The sending account: an sr25519 public key.
    pub sender: [u8; 32],
    /// The recipient's account.
    pub dest: [u8; 32],
    /// Rao to pay (10^-9 TAO). Balances are `u64` on Bittensor.
    pub value: u64,
    /// Where `Balances.transfer_keep_alive` is in the runtime.
    pub call_index: CallIndex,
    /// The sender's nonce it uses. The runtime's nonce is a `u32`.
    pub nonce: u32,
    /// The tip, in rao, for the block author: zero for none.
    pub tip: u64,
    /// How many blocks it lives for: a power of two from 4 to 4,096.
    pub period: u64,
    /// The block its era begins at: the block `birth_hash` is the hash of.
    pub birth: u64,
    /// That block's hash, which the signature commits to.
    pub birth_hash: [u8; 32],
    /// The runtime's spec version. A runtime upgrade that raises it makes the
    /// transaction's signature fail to verify, so it can never run under rules
    /// it was not built for.
    pub spec_version: u32,
    /// The runtime's transaction version.
    pub transaction_version: u32,
    /// The network's genesis hash.
    pub genesis_hash: [u8; 32],
}

impl Transfer {
    fn check(&self) -> Result<(), TransferError> {
        if self.value == 0 {
            return Err(TransferError::ZeroValue);
        }
        if !self.period.is_power_of_two() || !(4..=4096).contains(&self.period) {
            return Err(TransferError::EraPeriod);
        }
        Ok(())
    }

    /// Its era.
    #[must_use]
    pub fn era(&self) -> Era {
        Era::mortal(self.period, self.birth)
    }

    /// The last block it can be included in.
    #[must_use]
    pub fn last_valid_block(&self) -> u64 {
        self.era().death(self.birth).saturating_sub(1)
    }

    /// The call as the runtime reads it: pallet index, call index, then the
    /// arguments. The recipient is a `MultiAddress::Id`.
    #[must_use]
    pub fn call(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&[self.call_index.pallet, self.call_index.call, MULTI_ADDRESS_ID]);
        out.extend_from_slice(&self.dest);
        encode_compact(u128::from(self.value), &mut out);
        out
    }

    /// The part of the extensions the extrinsic carries: the era, the nonce,
    /// the tip, and the metadata-hash check switched off.
    #[must_use]
    pub fn explicit(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&self.era().encode());
        encode_compact(u128::from(self.nonce), &mut out);
        encode_compact(u128::from(self.tip), &mut out);
        out.push(METADATA_HASH_DISABLED);
        out
    }

    /// The part the signature covers but the extrinsic does not carry: the
    /// runtime versions, the genesis hash, the era's birth block hash, and no
    /// metadata hash.
    #[must_use]
    pub fn implicit(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(73);
        out.extend_from_slice(&self.spec_version.to_le_bytes());
        out.extend_from_slice(&self.transaction_version.to_le_bytes());
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.birth_hash);
        out.push(NO_METADATA_HASH);
        out
    }

    /// What the sender's key signs: `call ‖ explicit ‖ implicit`, or its
    /// BLAKE2-256 hash when that is longer than 256 bytes. A transfer never
    /// is, but the rule is the chain's, and applied.
    ///
    /// # Errors
    /// [`TransferError`] for a transfer the chain would refuse.
    pub fn signing_payload(&self) -> Result<Vec<u8>, TransferError> {
        self.check()?;
        let mut payload = self.call();
        payload.extend_from_slice(&self.explicit());
        payload.extend_from_slice(&self.implicit());
        Ok(reduce_payload(payload))
    }

    /// The signed extrinsic, length prefix and all: the bytes submitted, and
    /// the bytes its hash is taken over.
    ///
    /// # Errors
    /// [`TransferError`] for a transfer the chain would refuse.
    pub fn encode_signed(&self, signature: &[u8; 64]) -> Result<Vec<u8>, TransferError> {
        self.check()?;
        let call = self.call();
        let explicit = self.explicit();
        let mut body = Vec::with_capacity(2 + 32 + 1 + 64 + explicit.len() + call.len());
        body.push(SIGNED_V4);
        body.push(MULTI_ADDRESS_ID);
        body.extend_from_slice(&self.sender);
        body.push(SR25519);
        body.extend_from_slice(signature);
        body.extend_from_slice(&explicit);
        body.extend_from_slice(&call);

        let mut out = Vec::with_capacity(body.len() + 4);
        encode_compact(body.len() as u128, &mut out);
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// A signed extrinsic, ready to submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedExtrinsic {
    /// The extrinsic as `author_submitExtrinsic` takes it.
    pub extrinsic: Vec<u8>,
    /// Its hash: BLAKE2-256 over the encoding, length prefix included. What
    /// `author_submitExtrinsic` returns and explorers show.
    pub hash: [u8; 32],
    /// The signature.
    pub signature: [u8; 64],
}

/// Signs a transfer with `key`: sr25519 under the `substrate` context over the
/// transfer's signing payload.
///
/// The signature is randomised (schnorrkel mixes fresh randomness with the
/// key's own nonce seed), so signing twice gives two different signatures,
/// both valid. The randomness is the core's own source: the operating system's,
/// or the browser's `crypto.getRandomValues` on WebAssembly. If that fails, no
/// signature is made.
///
/// # Errors
/// [`TransferError`] if the key is not the sender's sr25519 key, the transfer
/// is one the chain would refuse, or the random source fails.
pub fn sign_transfer(
    key: &SigningKey,
    transfer: &Transfer,
) -> Result<SignedExtrinsic, TransferError> {
    sign_with_source(key, transfer, system_random)
}

/// [`sign_transfer`] with the random source given, so that its failure can be
/// tested.
pub(crate) fn sign_with_source(
    key: &SigningKey,
    transfer: &Transfer,
    source: impl FnMut(&mut [u8]) -> bool,
) -> Result<SignedExtrinsic, TransferError> {
    if key.scheme() != KeyScheme::Sr25519 {
        return Err(TransferError::WrongKeyScheme);
    }
    if key.public_key() != transfer.sender.as_slice() {
        return Err(TransferError::NotTheSender);
    }
    let payload = transfer.signing_payload()?;
    let mini = MiniSecretKey::from_bytes(key.expose_secret())
        .map_err(|_| TransferError::WrongKeyScheme)?;
    // The keypair wipes its secret half when dropped, as the mini-secret does.
    let keypair = mini.expand_to_keypair(ExpansionMode::Ed25519);

    let mut rng = CoreRng { source, failed: false };
    let transcript = Hedged {
        inner: signing_context(SR25519_CONTEXT).bytes(&payload),
        rng: RefCell::new(&mut rng),
    };
    let signature: Signature = keypair.sign(transcript);
    if rng.failed {
        return Err(TransferError::Randomness);
    }
    // A signature the runtime would refuse is never handed out.
    let public: &PublicKey = &keypair.public;
    if public.verify_simple(SR25519_CONTEXT, &payload, &signature).is_err() {
        return Err(TransferError::Randomness);
    }
    let signature = signature.to_bytes();
    let extrinsic = transfer.encode_signed(&signature)?;
    Ok(SignedExtrinsic { hash: blake2_256(&extrinsic), extrinsic, signature })
}

/// The operating system's random bytes (the browser's on WebAssembly), and
/// `false` if the source fails or hands back only zeros.
fn system_random(dest: &mut [u8]) -> bool {
    getrandom::getrandom(dest).is_ok() && dest.iter().any(|byte| *byte != 0)
}

/// A random generator over a source that can fail. `RngCore::fill_bytes` cannot
/// report a failure, so a failure is noted here and the signature that was made
/// with it is thrown away.
struct CoreRng<S> {
    source: S,
    failed: bool,
}

impl<S: FnMut(&mut [u8]) -> bool> CoreRng<S> {
    fn fill(&mut self, dest: &mut [u8]) {
        if !(self.source)(dest) {
            self.failed = true;
            dest.zeroize();
        }
    }
}

impl<S: FnMut(&mut [u8]) -> bool> RngCore for CoreRng<S> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill(dest);
        Ok(())
    }
}

impl<S: FnMut(&mut [u8]) -> bool> CryptoRng for CoreRng<S> {}

/// A signing transcript whose witness randomness comes from the core's source
/// instead of schnorrkel's `getrandom_or_panic`, which on WebAssembly without
/// a source would panic.
struct Hedged<'a, T, S> {
    inner: T,
    rng: RefCell<&'a mut CoreRng<S>>,
}

impl<T: SigningTranscript, S: FnMut(&mut [u8]) -> bool> SigningTranscript for Hedged<'_, T, S> {
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.inner.commit_bytes(label, bytes);
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        self.inner.challenge_bytes(label, dest);
    }

    fn witness_bytes(&self, label: &'static [u8], dest: &mut [u8], nonce_seeds: &[&[u8]]) {
        let mut rng = self.rng.borrow_mut();
        self.inner.witness_bytes_rng(label, dest, nonce_seeds, &mut **rng);
    }

    fn witness_bytes_rng<R: RngCore + CryptoRng>(
        &self,
        label: &'static [u8],
        dest: &mut [u8],
        nonce_seeds: &[&[u8]],
        rng: R,
    ) {
        self.inner.witness_bytes_rng(label, dest, nonce_seeds, rng);
    }
}

/// A signing payload as it is signed: itself, or its hash if it is longer than
/// 256 bytes.
#[must_use]
pub fn reduce_payload(payload: Vec<u8>) -> Vec<u8> {
    if payload.len() > MAX_UNHASHED_PAYLOAD { blake2_256(&payload).to_vec() } else { payload }
}

/// BLAKE2 with a 256-bit output: what extrinsics are named by, and what a
/// signing payload longer than 256 bytes is reduced to.
#[must_use]
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(data).into()
}

/// Appends `value` in SCALE's compact form.
///
/// Four modes, chosen by size: one byte up to 63, two bytes up to 16,383, four
/// up to 2^30 − 1, and above that a length byte followed by as few
/// little-endian bytes as hold the value, never fewer than four. The low two
/// bits of the first byte say which.
pub fn encode_compact(value: u128, out: &mut Vec<u8>) {
    if value < 1 << 6 {
        out.extend_from_slice(&(value << 2).to_le_bytes()[..1]);
    } else if value < 1 << 14 {
        out.extend_from_slice(&((value << 2) | 0b01).to_le_bytes()[..2]);
    } else if value < 1 << 30 {
        out.extend_from_slice(&((value << 2) | 0b10).to_le_bytes()[..4]);
    } else {
        let significant = (128 - value.leading_zeros()).div_ceil(8).max(4);
        // At most sixteen bytes, so the length byte is at most 0b0011_1111.
        let length = u8::try_from(((significant - 4) << 2) | 0b11).unwrap_or(u8::MAX);
        out.push(length);
        let bytes = value.to_le_bytes();
        out.extend_from_slice(&bytes[..usize::try_from(significant).unwrap_or(16)]);
    }
}

/// `value` in SCALE's compact form.
#[must_use]
pub fn compact(value: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    encode_compact(value, &mut out);
    out
}
