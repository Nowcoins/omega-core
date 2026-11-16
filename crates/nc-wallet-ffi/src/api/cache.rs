//! Sealing what the phone keeps about the wallet (its history) at rest.
//!
//! The history lists every address the wallet ever dealt with. It is sealed
//! (AES-256-GCM) under a key that only the wallet's own phrase makes, inside Rust,
//! and only while the wallet is unlocked. What is stored is noise to anyone who
//! copies the file; another wallet cannot open it. The key is never returned.
//!
//! A *label* names what is sealed (for instance `history/ethereum/<address>`). The
//! label is not in the blob: it is given again to open it. [`cache_id`] makes the
//! name to store a blob under, which reveals neither the network nor the address.

// The bridge hands each argument over by value; there is no borrowing across it.
#![allow(clippy::needless_pass_by_value)]

use super::error::WalletError;
use crate::engine::engine;

/// Seals `plaintext` for `label`. The wallet must be unlocked.
pub fn seal_cache(label: String, plaintext: Vec<u8>) -> Result<Vec<u8>, WalletError> {
    Ok(engine().seal_cache(&label, &plaintext)?)
}

/// What [`seal_cache`] sealed for `label`, or `None` where `blob` is not this
/// wallet's for that label (another wallet's, another label's, damaged): start
/// afresh. The wallet must be unlocked.
pub fn open_cache(label: String, blob: Vec<u8>) -> Result<Option<Vec<u8>>, WalletError> {
    Ok(engine().open_cache(&label, &blob)?)
}

/// The name to store the blob for `label` under: 24 hex characters. The wallet
/// must be unlocked.
pub fn cache_id(label: String) -> Result<String, WalletError> {
    Ok(engine().cache_id(&label)?)
}
