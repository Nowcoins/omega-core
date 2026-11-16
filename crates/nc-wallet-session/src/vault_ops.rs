//! Operations on a stored vault: the blob and a password or a key in, an
//! unlocked wallet or public data out.
//!
//! Each opens a vault whose header asks Argon2id for no more than the crate's
//! own ceiling ([`VaultLimits::PHONE`]); its `_within` twin takes the app's
//! limits instead (the extension's [`VaultLimits::EXTENSION`]), and refuses a
//! vault that asks for more as [`SessionError::NotAVault`] before any work.

use nc_wallet_core::vault::{self, VaultKey, VaultLimits, VaultParams};
use nc_wallet_core::{Mnemonic, WordCount};
use zeroize::Zeroizing;

use crate::engine::{Secrets, Unlocked, words_of};
use crate::error::SessionError;
use crate::types::VaultFacts;

/// Opens the vault with the password. Takes about a second: Argon2id.
pub fn open_with_password(
    blob: &[u8],
    password: &Zeroizing<String>,
) -> Result<Unlocked, SessionError> {
    open_with_password_within(blob, password, VaultLimits::PHONE)
}

/// [`open_with_password`] within `limits`.
pub fn open_with_password_within(
    blob: &[u8],
    password: &Zeroizing<String>,
    limits: VaultLimits,
) -> Result<Unlocked, SessionError> {
    let (mnemonic, passphrase) = vault::open_within(blob, password, limits)?.into_parts();
    Ok(Unlocked(Secrets { mnemonic, passphrase }))
}

/// Opens the vault with the password and also returns the 32-byte vault key
/// Argon2id made on the way, so an app that keeps the key somewhere with a
/// lock of its own (the extension's memory-only session store) does not run
/// Argon2id a second time. The key is checked against the vault before it is
/// returned.
pub fn open_with_password_keeping_key(
    blob: &[u8],
    password: &Zeroizing<String>,
) -> Result<(Unlocked, Vec<u8>), SessionError> {
    open_with_password_keeping_key_within(blob, password, VaultLimits::PHONE)
}

/// [`open_with_password_keeping_key`] within `limits`.
pub fn open_with_password_keeping_key_within(
    blob: &[u8],
    password: &Zeroizing<String>,
    limits: VaultLimits,
) -> Result<(Unlocked, Vec<u8>), SessionError> {
    let key = vault::derive_key_within(blob, password, limits)?;
    let (mnemonic, passphrase) = vault::open_with_key_within(blob, &key, limits)?.into_parts();
    Ok((Unlocked(Secrets { mnemonic, passphrase }), key.expose_secret().to_vec()))
}

/// Opens the vault with the key [`export_unlock_key`] (or
/// [`open_with_password_keeping_key`]) returned. Quick: no Argon2id.
pub fn open_with_key(blob: &[u8], key: &Zeroizing<Vec<u8>>) -> Result<Unlocked, SessionError> {
    open_with_key_within(blob, key, VaultLimits::PHONE)
}

/// [`open_with_key`] within `limits`.
pub fn open_with_key_within(
    blob: &[u8],
    key: &Zeroizing<Vec<u8>>,
    limits: VaultLimits,
) -> Result<Unlocked, SessionError> {
    let key = VaultKey::from_bytes(key)?;
    let (mnemonic, passphrase) = vault::open_with_key_within(blob, &key, limits)?.into_parts();
    Ok(Unlocked(Secrets { mnemonic, passphrase }))
}

/// The vault's key, after checking the password: 32 bytes that open this one
/// vault and nothing else. A new password makes a new key.
pub fn export_unlock_key(
    blob: &[u8],
    password: &Zeroizing<String>,
) -> Result<Vec<u8>, SessionError> {
    export_unlock_key_within(blob, password, VaultLimits::PHONE)
}

/// [`export_unlock_key`] within `limits`.
pub fn export_unlock_key_within(
    blob: &[u8],
    password: &Zeroizing<String>,
    limits: VaultLimits,
) -> Result<Vec<u8>, SessionError> {
    let key = vault::derive_key_within(blob, password, limits)?;
    // A wrong password gives a key that opens nothing: check before it is kept.
    vault::open_with_key_within(blob, &key, limits)?;
    Ok(key.expose_secret().to_vec())
}

/// The words of the stored phrase, after the password is typed again. Nothing
/// is unlocked or locked by this.
pub fn reveal_phrase(
    blob: &[u8],
    password: &Zeroizing<String>,
) -> Result<Vec<String>, SessionError> {
    reveal_phrase_within(blob, password, VaultLimits::PHONE)
}

/// [`reveal_phrase`] within `limits`.
pub fn reveal_phrase_within(
    blob: &[u8],
    password: &Zeroizing<String>,
    limits: VaultLimits,
) -> Result<Vec<String>, SessionError> {
    let opened = vault::open_within(blob, password, limits)?;
    Ok(words_of(opened.mnemonic()))
}

/// A new vault with the same phrase under a new password (and a new salt).
/// The old vault stays valid until the app replaces it.
pub fn change_password(
    blob: &[u8],
    old: &Zeroizing<String>,
    new: &Zeroizing<String>,
) -> Result<Vec<u8>, SessionError> {
    let opened = vault::open(blob, old)?;
    Ok(vault::seal(opened.mnemonic(), opened.expose_passphrase(), new)?)
}

/// [`change_password`] sealing with `params` (the old vault is opened with the
/// parameters in its header), and also the 32-byte vault key of the new vault
/// (made by the same Argon2id run), for an app that keeps the key in a store of
/// its own and would otherwise run Argon2id a third time to get it. Returns the
/// new vault and its key. With the same password as old and new, it re-seals a
/// vault with heavier parameters.
pub fn change_password_keeping_key(
    blob: &[u8],
    old: &Zeroizing<String>,
    new: &Zeroizing<String>,
    params: VaultParams,
) -> Result<(Vec<u8>, Vec<u8>), SessionError> {
    change_password_keeping_key_within(blob, old, new, params, VaultLimits::PHONE)
}

/// [`change_password_keeping_key`] that opens the old vault within `limits`.
pub fn change_password_keeping_key_within(
    blob: &[u8],
    old: &Zeroizing<String>,
    new: &Zeroizing<String>,
    params: VaultParams,
    limits: VaultLimits,
) -> Result<(Vec<u8>, Vec<u8>), SessionError> {
    let opened = vault::open_within(blob, old, limits)?;
    let (renewed, key) = vault::seal_keeping_key_with_params(
        opened.mnemonic(),
        opened.expose_passphrase(),
        new,
        params,
    )?;
    Ok((renewed, key.expose_secret().to_vec()))
}

/// What a stored vault's header says, without opening it.
pub fn vault_facts(blob: &[u8]) -> Result<VaultFacts, SessionError> {
    vault_facts_within(blob, VaultLimits::PHONE)
}

/// [`vault_facts`] within `limits`: a header that asks for more is
/// [`SessionError::NotAVault`], as a damaged one is.
pub fn vault_facts_within(blob: &[u8], limits: VaultLimits) -> Result<VaultFacts, SessionError> {
    let facts = vault::info_within(blob, limits)?;
    Ok(VaultFacts {
        version: facts.version,
        memory_kib: facts.params.memory_kib(),
        iterations: facts.params.iterations(),
        lanes: facts.params.lanes(),
    })
}

/// The password the throwaway vault of [`throwaway_vault`] is sealed under.
const THROWAWAY_PASSWORD: &str = "measuring the unlock time";

/// A vault of a fresh random phrase, sealed with the phone's parameters
/// ([`VaultParams::PHONE`]), for timing an unlock: the caller times
/// [`open_throwaway`] with its own clock (`std::time::Instant` does not exist
/// in the browser). Holds no wallet.
pub fn throwaway_vault() -> Result<Vec<u8>, SessionError> {
    throwaway_vault_with_params(VaultParams::PHONE)
}

/// [`throwaway_vault`] sealed with `params`: an app times the unlock of the
/// vaults it makes.
pub fn throwaway_vault_with_params(params: VaultParams) -> Result<Vec<u8>, SessionError> {
    let phrase = Mnemonic::generate(WordCount::Twelve)?;
    Ok(vault::seal_with_params(&phrase, "", THROWAWAY_PASSWORD, params)?)
}

/// Opens a vault made by [`throwaway_vault`]: the work of one unlock.
pub fn open_throwaway(blob: &[u8]) -> Result<(), SessionError> {
    open_throwaway_within(blob, VaultLimits::PHONE)
}

/// [`open_throwaway`] within `limits`.
pub fn open_throwaway_within(blob: &[u8], limits: VaultLimits) -> Result<(), SessionError> {
    vault::open_within(blob, THROWAWAY_PASSWORD, limits)?;
    Ok(())
}
