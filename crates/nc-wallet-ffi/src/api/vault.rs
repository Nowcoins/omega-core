//! Sealing, opening and locking the vault.
//!
//! The vault is the blob `nc_wallet_core::vault` writes: the phrase under a
//! password-derived key. The app stores it (wrapped by the Android Keystore)
//! and hands it back in the calls below. Opening one keeps the phrase in this
//! crate until [`lock`].

// The bridge hands each argument over by value; there is no borrowing across it.
#![allow(clippy::needless_pass_by_value)]

use flutter_rust_bridge::frb;
use zeroize::Zeroizing;

use super::error::WalletError;
use crate::engine;

/// The public facts in a vault's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultFacts {
    /// The blob format version.
    pub version: u8,
    /// Argon2id memory cost, KiB.
    pub memory_kib: u32,
    /// Argon2id passes.
    pub iterations: u32,
    /// Argon2id lanes.
    pub lanes: u32,
}

/// Seals the wallet being made (or imported) under `password`. Returns the
/// vault blob for the app to store; once it is safely written the app calls
/// [`commit_pending`], which unlocks the wallet. (Until then the phrase stays
/// pending, so a failed write is retried with the same wallet.) A new wallet
/// whose backup check was not passed is refused.
///
/// Takes about a second: it runs Argon2id.
pub fn seal_pending(password: String) -> Result<Vec<u8>, WalletError> {
    let password = Zeroizing::new(password);
    engine::seal_pending(&password)
}

/// The vault from [`seal_pending`] is stored: unlocks the wallet and clears the
/// pending one. Fails if nothing was sealed.
#[frb(sync)]
pub fn commit_pending() -> Result<(), WalletError> {
    Ok(engine::engine().commit_pending()?)
}

/// The key the vault just made by [`seal_pending`] was sealed with, once, for
/// the app to set up biometric unlock without asking for the password again.
/// The app keeps it behind a biometric-bound Android Keystore key and wipes
/// its copy. Fails if it was already taken or dropped.
#[frb(sync)]
pub fn take_new_unlock_key() -> Result<Vec<u8>, WalletError> {
    Ok(engine::engine().take_new_key()?)
}

/// Forgets the key [`take_new_unlock_key`] would give, when the person does
/// not want biometric unlock.
#[frb(sync)]
pub fn drop_new_unlock_key() {
    engine::engine().drop_new_key();
}

/// Opens the stored vault with the password and keeps the wallet unlocked in
/// Rust. Takes about a second.
pub fn unlock_with_password(vault: Vec<u8>, password: String) -> Result<(), WalletError> {
    engine::unlock_with_password(&vault, &Zeroizing::new(password))
}

/// Opens the stored vault with the key [`export_unlock_key`] returned (the
/// biometric path). Quick: no Argon2id.
pub fn unlock_with_key(vault: Vec<u8>, key: Vec<u8>) -> Result<(), WalletError> {
    engine::unlock_with_key(&vault, &Zeroizing::new(key))
}

/// The vault's key for biometric unlock, after checking the password: 32
/// bytes that open this one vault and nothing else. The app keeps them behind
/// a biometric-bound Android Keystore key and wipes its copy. A new password
/// makes a new key, so after [`change_password`] it is exported again.
pub fn export_unlock_key(vault: Vec<u8>, password: String) -> Result<Vec<u8>, WalletError> {
    engine::export_unlock_key(&vault, &Zeroizing::new(password))
}

/// The words of the stored phrase, for Settings, after the password is typed
/// again. Nothing is unlocked or locked by this.
pub fn reveal_phrase(vault: Vec<u8>, password: String) -> Result<Vec<String>, WalletError> {
    engine::reveal_phrase(&vault, &Zeroizing::new(password))
}

/// A new vault with the same phrase under a new password (and a new salt).
/// The old vault stays valid until the app replaces it.
pub fn change_password(
    vault: Vec<u8>,
    old_password: String,
    new_password: String,
) -> Result<Vec<u8>, WalletError> {
    engine::change_password(&vault, &Zeroizing::new(old_password), &Zeroizing::new(new_password))
}

/// Locks the wallet: the phrase held in Rust is wiped.
#[frb(sync)]
pub fn lock() {
    engine::engine().lock();
}

/// Whether the wallet is unlocked in Rust.
#[frb(sync)]
pub fn is_unlocked() -> bool {
    engine::engine().is_unlocked()
}

/// What a stored vault's header says, without opening it.
#[frb(sync)]
pub fn vault_facts(vault: Vec<u8>) -> Result<VaultFacts, WalletError> {
    engine::vault_facts(&vault)
}

/// How long one unlock takes on this phone, in milliseconds (a throwaway
/// vault is made and opened). For the About screen.
pub fn measure_unlock_ms() -> Result<u32, WalletError> {
    engine::measure_unlock_ms()
}
