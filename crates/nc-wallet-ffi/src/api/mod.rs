//! What Dart can call. `flutter_rust_bridge_codegen` reads this module and
//! writes the Dart side (in the app, `lib/src/rust`).
//!
//! A function marked `#[frb(sync)]` runs on the caller's thread and returns at
//! once, so it must be quick. The others run on a worker thread and come back
//! as a `Future`: Argon2id takes about a second, and must not block the UI.

pub mod accounts;
pub mod cache;
pub mod chain;
pub mod error;
pub mod phrase;
pub mod signing;
pub mod vault;
