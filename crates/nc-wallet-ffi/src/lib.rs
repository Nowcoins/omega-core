//! The Dart-facing API of Nowcoin Omega's core.
//!
//! The app (Flutter) calls this crate through `flutter_rust_bridge`; this crate
//! is a thin layer over `nc-wallet-session`, which holds the state and calls
//! `nc-wallet-core` (and which the Chrome extension's WebAssembly shares). Its
//! one rule is where secrets live:
//!
//! * **The recovery phrase stays in Rust.** A new phrase is made here, held
//!   here and sealed here. It crosses to Dart in two places only: the words for
//!   the backup screen ([`api::phrase::pending_phrase`], shown once while the
//!   wallet is being made) and the words in Settings after the password is
//!   typed again ([`api::vault::reveal_phrase`]). An imported phrase crosses
//!   the other way, once, as the text the user typed.
//! * **Unlocking keeps the phrase in Rust.** [`api::vault::unlock_with_password`]
//!   opens the vault and keeps what is inside in this crate's memory until
//!   [`api::vault::lock`], which wipes it. Everything the screens need after
//!   that is public data: addresses ([`api::accounts::derive_accounts`]).
//! * **The one key that leaves** is the vault key for biometric unlock
//!   ([`api::vault::export_unlock_key`]): 32 bytes, derived from the password,
//!   good for that one vault, and not the password itself.
//!
//! * **Signing keeps the key in Rust too.** [`api::signing::decode_request`] says
//!   what a transfer would do (the summary the review screen shows, and an
//!   approval hash); [`api::signing::sign_request`] derives the key inside,
//!   signs only the request that hash was made for, wipes the key and returns
//!   the signed transaction to broadcast. The key is never an argument or a
//!   result of any call.
//!
//! Nothing here logs, and no error value carries a word, a password or a key.

pub mod api;
mod engine;

// The code `flutter_rust_bridge_codegen` writes. It is generated, so neither
// this crate's lints nor the repository's rustfmt apply to it.
#[rustfmt::skip]
#[allow(
    unsafe_code,
    unreachable_pub,
    unused_qualifications,
    missing_debug_implementations,
    rust_2018_idioms,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod frb_generated;
