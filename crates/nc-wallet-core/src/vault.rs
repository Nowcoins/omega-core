//! The vault: a recovery phrase (and the optional BIP-39 passphrase) sealed
//! under the user's password, as one blob the apps keep on the device.
//!
//! * **Key:** Argon2id (RFC 9106, version 1.3) over the password and a random
//!   16-byte salt makes a 256-bit key. The cost parameters are stored in the
//!   blob, so a later version can raise them and still open an old vault.
//! * **Seal:** AES-256-GCM with a random 96-bit nonce. The whole header is the
//!   associated data, so a changed parameter, salt or nonce fails to open.
//! * **Shape:** the plaintext is padded to a multiple of 256 bytes, so a
//!   12-word phrase and a 24-word one make blobs of the same length.
//!
//! A wrong password and a damaged blob both end in [`VaultError::Authentication`]:
//! AES-GCM cannot tell them apart, and the vault keeps no password check
//! beside it (that would be one more thing to attack offline).
//!
//! # Blob format, version 1
//!
//! All integers are big-endian.
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | magic `NCWV` |
//! | 4 | 1 | format version, `1` |
//! | 5 | 1 | KDF: `1` = Argon2id v1.3, 32-byte output |
//! | 6 | 4 | memory cost, KiB |
//! | 10 | 4 | iterations (passes) |
//! | 14 | 4 | lanes (parallelism) |
//! | 18 | 16 | salt |
//! | 34 | 1 | cipher: `1` = AES-256-GCM |
//! | 35 | 12 | nonce |
//! | 47 | n + 16 | ciphertext and 16-byte tag |
//!
//! The first 47 bytes are the associated data. The plaintext, before it is
//! padded with zeros to a multiple of 256 bytes, is:
//!
//! | Size | Field |
//! |---|---|
//! | 1 | payload version, `1` |
//! | 2 | phrase length `m` |
//! | `m` | the phrase, words separated by single spaces |
//! | 2 | passphrase length `p` (0 for none) |
//! | `p` | the BIP-39 passphrase, UTF-8 |
//!
//! A wallet that is one imported private key ([`crate::imported`]) is sealed the
//! same way, with a payload of its own:
//!
//! | Size | Field |
//! |---|---|
//! | 1 | payload version, `2` |
//! | 1 | the key's kind: `1` = secp256k1, `2` = ed25519 (Solana) |
//! | 32 | the key |
//!
//! [`open`] and its kin read a phrase and answer [`VaultError::HoldsAKey`] for such a
//! vault; [`open_any`] and its kin read either ([`Held`]).
//!
//! # The password
//!
//! The password is normalised to Unicode NFKD before it is used, so the same
//! characters typed on two keyboards open the same vault. It must not be
//! empty; how strong it has to be is the app's rule.
//!
//! # Keys that open a vault without the password
//!
//! [`derive_key`] returns the Argon2id key itself. An app may keep it behind
//! the operating system's own lock (Android's biometric-bound Keystore key)
//! and open the vault with [`open_with_key`] later, without asking for the
//! password. The key opens only the vault it was derived for: a new password
//! makes a new salt and so a new key.

use std::fmt;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{
    Aead as _, AeadInPlace as _, KeyInit as _, Payload, generic_array::GenericArray,
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use unicode_normalization::UnicodeNormalization as _;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::imported::{ImportedKey, ImportedKeyKind};
use crate::mnemonic::Mnemonic;

const MAGIC: &[u8; 4] = b"NCWV";
/// The format this crate writes, and the only one it reads.
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID_V13: u8 = 1;
const CIPHER_AES_256_GCM: u8 = 1;
const PAYLOAD_VERSION: u8 = 1;
/// The payload of a wallet that is one imported private key.
const PAYLOAD_KEY: u8 = 2;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Everything before the ciphertext: magic to nonce. It is the associated data.
const HEADER_LEN: usize = 4 + 1 + 1 + 4 + 4 + 4 + SALT_LEN + 1 + NONCE_LEN;
/// The plaintext is zero-padded to a multiple of this.
const PAD_TO: usize = 256;
/// Longest passphrase kept, in bytes. (A 24-word phrase is at most 215 bytes.)
const MAX_PASSPHRASE_LEN: usize = 1024;

/// Memory, passes and lanes that Argon2 is asked for.
///
/// [`VaultParams::PHONE`] is the setting the apps use. [`VaultParams::new`]
/// refuses anything weaker than the floor below, so a caller cannot seal a
/// vault the offline attacker finds cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultParams {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl VaultParams {
    /// 64 MiB, 3 passes, 1 lane: about the cost of one second on a mid-range
    /// phone, which is what an unlock waits for. One lane because a phone's
    /// cores are not all fast, and the lanes only help an attacker's GPU.
    pub const PHONE: Self = Self { memory_kib: 65_536, iterations: 3, lanes: 1 };

    /// 256 MiB, 3 passes, 1 lane: the Chrome extension's vaults. That vault
    /// sits in the browser profile, where malware or a copied profile reaches
    /// it, so each guess costs four times the memory and four times the work of
    /// [`VaultParams::PHONE`]. One lane: WebAssembly runs it on one thread.
    ///
    /// Measured on the build server (8 shared cores, busy), in Node 22's V8
    /// with the release WebAssembly build: an unlock in a fresh instance (as a
    /// woken service worker does it) took 1.30 to 1.43 s, 1.06 to 1.25 s when
    /// the memory was already grown, against 0.32 to 0.35 s (0.22 to 0.25 s)
    /// for `PHONE`; sealing took 1.3 to 1.4 s. Chrome runs the same V8, so a
    /// recent laptop should take about a second; an old or low-power one, two
    /// or more. WebAssembly memory does not shrink, so the worker holds about
    /// 320 MiB from its first unlock until Chrome stops it.
    pub const EXTENSION: Self = Self { memory_kib: 262_144, iterations: 3, lanes: 1 };

    /// The least memory `new` accepts: 16 MiB.
    pub const MIN_MEMORY_KIB: u32 = 16 * 1024;
    /// The fewest passes `new` accepts.
    pub const MIN_ITERATIONS: u32 = 2;
    /// The most memory a blob may ask for when it is opened: 1 GiB. A blob that
    /// asks for more is refused before anything is allocated. (An app may hold
    /// the vaults it opens to less: [`VaultLimits`].)
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    /// The most passes a blob may ask for when it is opened.
    pub const MAX_ITERATIONS: u32 = 32;
    /// The most lanes a blob may ask for when it is opened.
    pub const MAX_LANES: u32 = 8;

    /// Parameters for sealing a new vault, checked against the floor and the
    /// ceiling.
    pub fn new(memory_kib: u32, iterations: u32, lanes: u32) -> Result<Self, VaultError> {
        let params = Self { memory_kib, iterations, lanes };
        params.check_feasible()?;
        if memory_kib < Self::MIN_MEMORY_KIB || iterations < Self::MIN_ITERATIONS {
            return Err(VaultError::BadParams);
        }
        Ok(params)
    }

    /// Memory cost in KiB.
    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Number of passes.
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Number of lanes.
    pub fn lanes(&self) -> u32 {
        self.lanes
    }

    /// Within Argon2's own limits and this crate's ceilings. A blob's
    /// parameters are checked with this before they are used, no floor: the
    /// header is only authenticated by opening, and what it asks for must not
    /// be able to exhaust the phone first.
    fn check_feasible(&self) -> Result<(), VaultError> {
        let ok = (1..=Self::MAX_LANES).contains(&self.lanes)
            && (1..=Self::MAX_ITERATIONS).contains(&self.iterations)
            && self.memory_kib >= 8 * self.lanes
            && self.memory_kib <= Self::MAX_MEMORY_KIB;
        if ok { Ok(()) } else { Err(VaultError::BadParams) }
    }

    fn argon2(&self) -> Result<Argon2<'static>, VaultError> {
        let params = Params::new(self.memory_kib, self.iterations, self.lanes, Some(KEY_LEN))
            .map_err(|_| VaultError::BadParams)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    /// Parameters for the tests: any feasible setting, no floor.
    #[cfg(test)]
    pub(crate) fn for_tests(memory_kib: u32, iterations: u32, lanes: u32) -> Self {
        let params = Self { memory_kib, iterations, lanes };
        assert!(params.check_feasible().is_ok());
        params
    }
}

impl Default for VaultParams {
    fn default() -> Self {
        Self::PHONE
    }
}

/// The most a vault's header may ask Argon2 for when the vault is opened or
/// its header read. A header that asks for more is refused
/// ([`VaultError::BadParams`]) as soon as it is read: before Argon2 runs and
/// before any memory is reserved for it. The header is only authenticated by
/// opening, so these numbers are whatever the stored blob says.
///
/// [`open`], [`derive_key`], [`open_with_key`] and [`info`] apply
/// [`VaultLimits::PHONE`], the crate's own ceiling; the `_within` functions
/// take limits of their own, and the crate's ceiling applies to them as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultLimits {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl VaultLimits {
    /// 1 GiB, 32 passes, 8 lanes ([`VaultParams::MAX_MEMORY_KIB`] and the
    /// rest): the crate's own ceiling, which the Android app opens its vaults
    /// within.
    pub const PHONE: Self = Self {
        memory_kib: VaultParams::MAX_MEMORY_KIB,
        iterations: VaultParams::MAX_ITERATIONS,
        lanes: VaultParams::MAX_LANES,
    };

    /// 512 MiB, 10 passes, 1 lane: the Chrome extension's. Its service worker
    /// runs Argon2 in WebAssembly, on one thread, in memory that never
    /// shrinks, and the vault sits in the browser profile, where a program on
    /// the computer can write one: a vault that asks for more is refused as
    /// damaged instead of making the worker reserve a gigabyte or work for
    /// minutes. Twice the memory and more than three times the passes of
    /// [`VaultParams::EXTENSION`], room for a later version to raise them;
    /// [`VaultParams::PHONE`] (every extension vault before) is well within.
    pub const EXTENSION: Self = Self { memory_kib: 512 * 1024, iterations: 10, lanes: 1 };

    /// Limits of one's own. The crate's ceiling ([`VaultLimits::PHONE`])
    /// applies as well.
    pub const fn new(max_memory_kib: u32, max_iterations: u32, max_lanes: u32) -> Self {
        Self { memory_kib: max_memory_kib, iterations: max_iterations, lanes: max_lanes }
    }

    /// The most memory, in KiB.
    pub const fn max_memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// The most passes.
    pub const fn max_iterations(&self) -> u32 {
        self.iterations
    }

    /// The most lanes.
    pub const fn max_lanes(&self) -> u32 {
        self.lanes
    }

    /// Whether a vault of `params` is within these limits.
    pub const fn admits(&self, params: &VaultParams) -> bool {
        params.memory_kib <= self.memory_kib
            && params.iterations <= self.iterations
            && params.lanes <= self.lanes
    }
}

impl Default for VaultLimits {
    fn default() -> Self {
        Self::PHONE
    }
}

/// Why a vault could not be sealed or opened. None of the values carries a
/// word, a password or a key: it is safe to log and to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The password is empty.
    #[error("the password is empty")]
    EmptyPassword,

    /// The BIP-39 passphrase is longer than the vault keeps (1024 bytes).
    #[error("the passphrase is longer than 1024 bytes")]
    PassphraseTooLong,

    /// Argon2 parameters outside what the vault allows.
    #[error("the key derivation parameters are not acceptable")]
    BadParams,

    /// The bytes are not a vault: too short, or the wrong magic.
    #[error("this is not a Nowcoin Omega vault")]
    NotAVault,

    /// A vault of a newer (or unknown) format.
    #[error("this vault has format version {0}, which this app cannot read")]
    UnsupportedVersion(u8),

    /// A key derivation or cipher this app does not know.
    #[error("this vault uses an algorithm this app cannot read")]
    UnsupportedAlgorithm,

    /// The password or key is wrong, or the vault was changed after it was
    /// sealed. AES-GCM cannot tell the two apart.
    #[error("wrong password, or the vault is damaged")]
    Authentication,

    /// The vault opened but what is inside is not a recovery phrase and a
    /// passphrase. A vault this app sealed never ends here.
    #[error("the vault opened but its contents are not valid")]
    Corrupt,

    /// The vault holds an imported private key, and a recovery phrase was asked for.
    #[error("this vault holds a private key, not a recovery phrase")]
    HoldsAKey,

    /// A key of the wrong length.
    #[error("a vault key is 32 bytes")]
    BadKey,

    /// The key derivation could not run (for example, no memory for it).
    #[error("the key derivation could not run")]
    Kdf,

    /// The system's secure random source failed or returned only zeros.
    #[error("the system's secure random source is unavailable")]
    Randomness,
}

/// The public facts in a vault's header: nothing here is secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultInfo {
    /// The blob format version.
    pub version: u8,
    /// The Argon2id parameters the key is made with.
    pub params: VaultParams,
}

/// The 32-byte key Argon2id makes from the password and the vault's salt.
///
/// It opens that one vault ([`open_with_key`]) and nothing else. Wiped when
/// dropped; `Debug` prints nothing of it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

impl VaultKey {
    /// A key read back from where the app kept it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        let key: [u8; KEY_LEN] = bytes.try_into().map_err(|_| VaultError::BadKey)?;
        Ok(Self(key))
    }

    /// The key's bytes. Named like this on purpose: grep for it to find every
    /// place a vault key leaves the crate.
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

/// What a vault holds, once opened. It wipes itself when dropped (the phrase
/// and the passphrase each do); `Debug` prints nothing of it.
pub struct Opened {
    mnemonic: Mnemonic,
    passphrase: Zeroizing<String>,
}

impl Opened {
    /// The recovery phrase.
    pub fn mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    /// The BIP-39 passphrase (`""` for none). Named like this on purpose: grep
    /// for it to find every place it is read.
    pub fn expose_passphrase(&self) -> &str {
        &self.passphrase
    }

    /// The phrase and the passphrase, to hold apart from each other.
    pub fn into_parts(self) -> (Mnemonic, Zeroizing<String>) {
        (self.mnemonic, self.passphrase)
    }
}

impl fmt::Debug for Opened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Opened(<redacted>)")
    }
}

/// What a vault holds, phrase or private key: what [`open_any`] gives. Both wipe
/// themselves when dropped; `Debug` prints nothing of either.
pub enum Held {
    /// A recovery phrase and its passphrase.
    Phrase(Opened),
    /// One imported private key.
    Key(ImportedKey),
}

impl fmt::Debug for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Phrase(_) => "Held::Phrase(<redacted>)",
            Self::Key(_) => "Held::Key(<redacted>)",
        })
    }
}

/// The header of a vault, read and checked.
struct Header<'a> {
    params: VaultParams,
    salt: &'a [u8; SALT_LEN],
    nonce: &'a [u8; NONCE_LEN],
    /// Magic to nonce, as written: the associated data.
    raw: &'a [u8],
    /// Ciphertext and tag.
    sealed: &'a [u8],
}

impl<'a> Header<'a> {
    /// The header, if its parameters are feasible and within `limits`: what
    /// they ask for is checked before anything is done with them.
    fn parse(blob: &'a [u8], limits: VaultLimits) -> Result<Self, VaultError> {
        if blob.len() < HEADER_LEN + TAG_LEN || blob.get(..4) != Some(MAGIC.as_slice()) {
            return Err(VaultError::NotAVault);
        }
        let version = blob[4];
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        if blob[5] != KDF_ARGON2ID_V13 || blob[34] != CIPHER_AES_256_GCM {
            return Err(VaultError::UnsupportedAlgorithm);
        }
        let params = VaultParams {
            memory_kib: be_u32(&blob[6..10]),
            iterations: be_u32(&blob[10..14]),
            lanes: be_u32(&blob[14..18]),
        };
        params.check_feasible()?;
        if !limits.admits(&params) {
            return Err(VaultError::BadParams);
        }
        let salt = blob[18..18 + SALT_LEN].try_into().map_err(|_| VaultError::NotAVault)?;
        let nonce = blob[35..35 + NONCE_LEN].try_into().map_err(|_| VaultError::NotAVault)?;
        Ok(Self { params, salt, nonce, raw: &blob[..HEADER_LEN], sealed: &blob[HEADER_LEN..] })
    }
}

fn be_u32(bytes: &[u8]) -> u32 {
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    u32::from_be_bytes(out)
}

/// Seals `mnemonic` and `passphrase` under `password` with
/// [`VaultParams::PHONE`].
pub fn seal(mnemonic: &Mnemonic, passphrase: &str, password: &str) -> Result<Vec<u8>, VaultError> {
    seal_with_params(mnemonic, passphrase, password, VaultParams::PHONE)
}

/// [`seal()`] with the given Argon2id parameters. A fresh random salt and nonce
/// are drawn each time, so sealing the same phrase twice gives two blobs.
pub fn seal_with_params(
    mnemonic: &Mnemonic,
    passphrase: &str,
    password: &str,
    params: VaultParams,
) -> Result<Vec<u8>, VaultError> {
    seal_keeping_key_with_params(mnemonic, passphrase, password, params).map(|(blob, _)| blob)
}

/// [`seal()`] that also returns the key it sealed with, for an app that offers
/// biometric unlock right after the vault is made and so needs the key without
/// asking for the password a second time (another Argon2id run).
pub fn seal_keeping_key(
    mnemonic: &Mnemonic,
    passphrase: &str,
    password: &str,
) -> Result<(Vec<u8>, VaultKey), VaultError> {
    seal_keeping_key_with_params(mnemonic, passphrase, password, VaultParams::PHONE)
}

/// [`seal_keeping_key`] with the given Argon2id parameters, held to the same
/// floor as [`seal_with_params`].
pub fn seal_keeping_key_with_params(
    mnemonic: &Mnemonic,
    passphrase: &str,
    password: &str,
    params: VaultParams,
) -> Result<(Vec<u8>, VaultKey), VaultError> {
    // The floor applies to what is written; opening only applies the ceiling.
    if params.memory_kib < VaultParams::MIN_MEMORY_KIB
        || params.iterations < VaultParams::MIN_ITERATIONS
    {
        return Err(VaultError::BadParams);
    }
    seal_inner(
        mnemonic,
        passphrase,
        password,
        params,
        random::<SALT_LEN>()?,
        random::<NONCE_LEN>()?,
    )
}

/// Seals an imported private key under `password`, as [`seal_keeping_key_with_params`]
/// seals a phrase: the same header, cipher and padding, so nothing outside the vault
/// tells the two apart, and the key it sealed with for an app that unlocks without the
/// password afterwards.
pub fn seal_imported_keeping_key_with_params(
    imported: &ImportedKey,
    password: &str,
    params: VaultParams,
) -> Result<(Vec<u8>, VaultKey), VaultError> {
    if params.memory_kib < VaultParams::MIN_MEMORY_KIB
        || params.iterations < VaultParams::MIN_ITERATIONS
    {
        return Err(VaultError::BadParams);
    }
    seal_plaintext(
        &encode_key_payload(imported),
        password,
        params,
        random::<SALT_LEN>()?,
        random::<NONCE_LEN>()?,
    )
}

/// The sealing itself, with the salt and nonce given (so a test can pin the
/// bytes) and no floor on the parameters.
#[cfg(test)]
fn seal_unchecked(
    mnemonic: &Mnemonic,
    passphrase: &str,
    password: &str,
    params: VaultParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, VaultError> {
    seal_inner(mnemonic, passphrase, password, params, salt, nonce).map(|(blob, _)| blob)
}

fn seal_inner(
    mnemonic: &Mnemonic,
    passphrase: &str,
    password: &str,
    params: VaultParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<(Vec<u8>, VaultKey), VaultError> {
    params.check_feasible()?;
    if passphrase.len() > MAX_PASSPHRASE_LEN {
        return Err(VaultError::PassphraseTooLong);
    }
    seal_plaintext(&encode_payload(mnemonic, passphrase)?, password, params, salt, nonce)
}

/// Seals a payload already laid out and padded.
fn seal_plaintext(
    plaintext: &[u8],
    password: &str,
    params: VaultParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<(Vec<u8>, VaultKey), VaultError> {
    params.check_feasible()?;
    let key = kdf(password, &salt, &params)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.push(KDF_ARGON2ID_V13);
    header.extend_from_slice(&params.memory_kib.to_be_bytes());
    header.extend_from_slice(&params.iterations.to_be_bytes());
    header.extend_from_slice(&params.lanes.to_be_bytes());
    header.extend_from_slice(&salt);
    header.push(CIPHER_AES_256_GCM);
    header.extend_from_slice(&nonce);
    debug_assert_eq!(header.len(), HEADER_LEN);

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let sealed = cipher
        .encrypt(GenericArray::from_slice(&nonce), Payload { msg: plaintext, aad: &header })
        .map_err(|_| VaultError::Authentication)?;

    let mut blob = header;
    blob.extend_from_slice(&sealed);
    Ok((blob, key))
}

/// Opens a vault with the password.
///
/// Takes one Argon2id run (about a second on a phone). A wrong password and a
/// changed blob both give [`VaultError::Authentication`].
pub fn open(blob: &[u8], password: &str) -> Result<Opened, VaultError> {
    open_within(blob, password, VaultLimits::PHONE)
}

/// [`open`] of a vault whose header asks for no more than `limits`; one that
/// asks for more is [`VaultError::BadParams`], before any Argon2id work.
pub fn open_within(blob: &[u8], password: &str, limits: VaultLimits) -> Result<Opened, VaultError> {
    let header = Header::parse(blob, limits)?;
    let key = kdf(password, header.salt, &header.params)?;
    open_parsed(&header, &key)
}

/// The key Argon2id makes from `password` and the vault's salt. It is not
/// checked here: a wrong password gives a key that fails in [`open_with_key`].
pub fn derive_key(blob: &[u8], password: &str) -> Result<VaultKey, VaultError> {
    derive_key_within(blob, password, VaultLimits::PHONE)
}

/// [`derive_key`] within `limits`, as [`open_within`].
pub fn derive_key_within(
    blob: &[u8],
    password: &str,
    limits: VaultLimits,
) -> Result<VaultKey, VaultError> {
    let header = Header::parse(blob, limits)?;
    kdf(password, header.salt, &header.params)
}

/// Opens a vault with the key [`derive_key`] made for it. No Argon2id run.
pub fn open_with_key(blob: &[u8], key: &VaultKey) -> Result<Opened, VaultError> {
    open_with_key_within(blob, key, VaultLimits::PHONE)
}

/// [`open_with_key`] within `limits`, as [`open_within`]: a vault the key
/// opens but whose header asks for more than the app would ever run is
/// refused all the same.
pub fn open_with_key_within(
    blob: &[u8],
    key: &VaultKey,
    limits: VaultLimits,
) -> Result<Opened, VaultError> {
    let header = Header::parse(blob, limits)?;
    open_parsed(&header, key)
}

/// The public facts in a vault's header, without opening it.
pub fn info(blob: &[u8]) -> Result<VaultInfo, VaultError> {
    info_within(blob, VaultLimits::PHONE)
}

/// [`info`] within `limits`: a header that asks for more is
/// [`VaultError::BadParams`].
pub fn info_within(blob: &[u8], limits: VaultLimits) -> Result<VaultInfo, VaultError> {
    let header = Header::parse(blob, limits)?;
    Ok(VaultInfo { version: FORMAT_VERSION, params: header.params })
}

fn open_parsed(header: &Header<'_>, key: &VaultKey) -> Result<Opened, VaultError> {
    match open_parsed_any(header, key)? {
        Held::Phrase(opened) => Ok(opened),
        Held::Key(_) => Err(VaultError::HoldsAKey),
    }
}

fn open_parsed_any(header: &Header<'_>, key: &VaultKey) -> Result<Held, VaultError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let mut buffer = Zeroizing::new(header.sealed.to_vec());
    cipher
        .decrypt_in_place(GenericArray::from_slice(header.nonce), header.raw, &mut *buffer)
        .map_err(|_| VaultError::Authentication)?;
    if buffer.first() == Some(&PAYLOAD_KEY) {
        decode_key_payload(&buffer).map(Held::Key)
    } else {
        decode_payload(&buffer).map(Held::Phrase)
    }
}

/// Opens a vault with the password, whatever it holds: a recovery phrase or an
/// imported private key. As [`open`] in every other way.
pub fn open_any(blob: &[u8], password: &str) -> Result<Held, VaultError> {
    open_any_within(blob, password, VaultLimits::PHONE)
}

/// [`open_any`] for a vault whose header asks for no more than `limits`.
pub fn open_any_within(
    blob: &[u8],
    password: &str,
    limits: VaultLimits,
) -> Result<Held, VaultError> {
    let header = Header::parse(blob, limits)?;
    let key = kdf(password, header.salt, &header.params)?;
    open_parsed_any(&header, &key)
}

/// [`open_with_key`] for a vault that may hold either.
pub fn open_any_with_key(blob: &[u8], key: &VaultKey) -> Result<Held, VaultError> {
    open_any_with_key_within(blob, key, VaultLimits::PHONE)
}

/// [`open_any_with_key`] for a vault whose header asks for no more than `limits`.
pub fn open_any_with_key_within(
    blob: &[u8],
    key: &VaultKey,
    limits: VaultLimits,
) -> Result<Held, VaultError> {
    open_parsed_any(&Header::parse(blob, limits)?, key)
}

/// The password through NFKD and Argon2id.
fn kdf(password: &str, salt: &[u8], params: &VaultParams) -> Result<VaultKey, VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }
    let normalised: Zeroizing<String> = Zeroizing::new(password.nfkd().collect());
    argon2id(normalised.as_bytes(), salt, params)
}

/// Argon2id v1.3 with a 32-byte output, working in memory that is wiped when
/// it is done. (The arguments are bytes, so the reference vectors can be fed
/// in directly.)
fn argon2id(password: &[u8], salt: &[u8], params: &VaultParams) -> Result<VaultKey, VaultError> {
    let argon2 = params.argon2()?;
    let blocks = argon2.params().block_count();
    let mut memory: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    memory.try_reserve_exact(blocks).map_err(|_| VaultError::Kdf)?;
    memory.resize(blocks, Block::default());
    let mut key = VaultKey([0u8; KEY_LEN]);
    argon2
        .hash_password_into_with_memory(password, salt, &mut key.0, &mut memory[..])
        .map_err(|_| VaultError::Kdf)?;
    Ok(key)
}

fn random<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).map_err(|_| VaultError::Randomness)?;
    // 96 random bits are all zero with probability 2^-96: a zero block means
    // the source is not random.
    if bytes.iter().all(|b| *b == 0) {
        return Err(VaultError::Randomness);
    }
    Ok(bytes)
}

fn encode_payload(mnemonic: &Mnemonic, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let phrase = mnemonic.expose_phrase();
    let (phrase, passphrase) = (phrase.as_bytes(), passphrase.as_bytes());
    let used = 1 + 2 + phrase.len() + 2 + passphrase.len();
    let padded = used.div_ceil(PAD_TO) * PAD_TO;
    let mut out = Zeroizing::new(Vec::with_capacity(padded));
    out.push(PAYLOAD_VERSION);
    out.extend_from_slice(
        &u16::try_from(phrase.len()).map_err(|_| VaultError::Corrupt)?.to_be_bytes(),
    );
    out.extend_from_slice(phrase);
    out.extend_from_slice(
        &u16::try_from(passphrase.len()).map_err(|_| VaultError::PassphraseTooLong)?.to_be_bytes(),
    );
    out.extend_from_slice(passphrase);
    out.resize(padded, 0);
    Ok(out)
}

fn decode_payload(bytes: &[u8]) -> Result<Opened, VaultError> {
    let corrupt = || VaultError::Corrupt;
    if bytes.first() != Some(&PAYLOAD_VERSION) {
        return Err(corrupt());
    }
    let (phrase, rest) = take_field(&bytes[1..]).ok_or_else(corrupt)?;
    let (passphrase, padding) = take_field(rest).ok_or_else(corrupt)?;
    if padding.iter().any(|b| *b != 0) || passphrase.len() > MAX_PASSPHRASE_LEN {
        return Err(corrupt());
    }
    let phrase = std::str::from_utf8(phrase).map_err(|_| corrupt())?;
    let mnemonic = Mnemonic::parse(phrase).map_err(|_| corrupt())?;
    let passphrase = Zeroizing::new(String::from_utf8(passphrase.to_vec()).map_err(|_| corrupt())?);
    Ok(Opened { mnemonic, passphrase })
}

/// The payload of an imported key: its version, its kind and its 32 bytes, padded as a phrase is.
fn encode_key_payload(imported: &ImportedKey) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(PAD_TO));
    out.push(PAYLOAD_KEY);
    out.push(imported.kind().code());
    out.extend_from_slice(imported.expose_secret());
    out.resize(PAD_TO, 0);
    out
}

fn decode_key_payload(bytes: &[u8]) -> Result<ImportedKey, VaultError> {
    let corrupt = || VaultError::Corrupt;
    if bytes.len() != PAD_TO || bytes.first() != Some(&PAYLOAD_KEY) {
        return Err(corrupt());
    }
    let kind = ImportedKeyKind::from_code(bytes[1]).ok_or_else(corrupt)?;
    if bytes[34..].iter().any(|b| *b != 0) {
        return Err(corrupt());
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&bytes[2..34]);
    ImportedKey::from_parts(kind, &secret).map_err(|_| corrupt())
}

/// A 2-byte length and that many bytes; the rest after them.
fn take_field(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = usize::from(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]));
    let rest = bytes.get(2..)?;
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
mod tests;
