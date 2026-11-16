//! The state behind Nowcoin Omega's apps, with no I/O and no bridge.
//!
//! The Android app reaches this crate through `nc-wallet-ffi` (`flutter_rust_bridge`);
//! the Chrome extension reaches it through `nc-wallet-wasm` (wasm-bindgen). Both
//! need the same behaviour, so it lives here once:
//!
//! * **The wallet being made.** A recovery phrase is generated (or imported)
//!   and held here, wiped when dropped.
//! * **The backup quiz.** Three positions of the phrase, each with the right
//!   word among five that are not in the phrase at all. The caller cannot tell
//!   which choice is right without knowing the phrase, and a new wallet is
//!   **not sealed** until all three were answered ([`Engine::seal_pending`]).
//! * **Seal, then commit.** Sealing returns the vault blob and keeps the phrase
//!   pending; only [`Engine::commit_pending`], called once the blob is safely
//!   stored, unlocks the wallet. A write that failed is retried with the same
//!   wallet.
//! * **The unlocked session.** The phrase and passphrase, kept until
//!   [`Engine::lock`]. Everything the screens need after that is public data
//!   ([`Engine::accounts`]).
//! * **Typed phrases.** [`check_phrase`] says what is wrong with typed text, by
//!   word and position; [`suggest`] and [`complete_word`] help fix it.
//! * **Vault operations** ([`open_with_password`], [`open_with_key`],
//!   [`export_unlock_key`], [`reveal_phrase`], [`change_password`],
//!   [`vault_facts`]) that take the stored blob and a password or key. Their
//!   `_within` twins hold the vault's header to the app's own limits
//!   ([`VaultLimits`]): the extension opens nothing that asks for more than
//!   512 MiB, 10 passes and 1 lane.
//!
//! * **Signing** ([`Engine::decode_request`], [`Engine::sign_request`]). A dApp's
//!   transaction, `personal_sign`, EIP-712 typed data, a Solana transaction or
//!   message, and the wallet's own transfer on any of the nine networks, as one
//!   JSON request: decoded into the summary an approval screen shows, then
//!   signed only if it is still the request that was approved (an approval
//!   hash over the exact bytes). The private key is derived, used and wiped
//!   inside the call. [`validate_address`] checks an address for a network, and
//!   [`solana_lookup_tables`] names the tables a Solana transaction needs. See
//!   the `signing` module's source for the request formats.
//!
//! Secrets leave this crate in four places and nowhere else: the pending words
//! ([`Engine::pending_words`]), the words after a re-typed password
//! ([`reveal_phrase`]), the vault key for an app that keeps it behind a lock of
//! its own ([`Engine::take_new_key`], [`export_unlock_key`],
//! [`open_with_password_keeping_key`]), and, going the other way, an imported
//! phrase as the text the person typed. Nothing here logs, and no error value
//! carries a word, a password or a key.
//!
//! Randomness is the operating system's (the browser's `crypto.getRandomValues`
//! on `wasm32-unknown-unknown`), as in the core. Nothing here reads the clock:
//! `std::time::Instant` is not available in the browser, so timing an unlock is
//! the caller's job ([`throwaway_vault`] makes the vault to time).

mod accounts;
mod engine;
mod error;
mod phrase;
mod quiz;
mod signing;
mod types;
mod vault_ops;

pub use engine::{Engine, SealDone, SealJob, Unlocked};
pub use error::SessionError;
/// The Argon2id parameters a vault is sealed with ([`Engine::with_vault_params`]), and
/// the most a vault's header may ask for when it is opened
/// ([`Engine::with_vault_params_and_limits`]).
pub use nc_wallet_core::vault::{VaultLimits, VaultParams};
pub use phrase::{check_phrase, complete_word, suggest};
pub use signing::{
    AddressCheck, Decoded, MAX_ADDRESS_LEN, SigningError, solana_lookup_tables, validate_address,
};
pub use types::{
    BackupQuestion, NetworkAccount, NetworkId, PhraseCheck, PhraseLength, PhraseProblem, VaultFacts,
};
pub use vault_ops::{
    change_password, change_password_keeping_key, change_password_keeping_key_within,
    export_unlock_key, export_unlock_key_within, open_throwaway, open_throwaway_within,
    open_with_key, open_with_key_within, open_with_password, open_with_password_keeping_key,
    open_with_password_keeping_key_within, open_with_password_within, reveal_phrase,
    reveal_phrase_within, throwaway_vault, throwaway_vault_with_params, vault_facts,
    vault_facts_within,
};

#[cfg(test)]
mod tests;
