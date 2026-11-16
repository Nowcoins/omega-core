//! Seals the BIP-39 reference phrase ("abandon ... about") under a password,
//! natively, and writes the vault to a file. Used by `scripts/cross-format.sh`
//! to check that the WebAssembly build opens a vault the native build sealed.
//!
//! `cargo run -p nc-wallet-wasm --example seal_native -- <password> <out-file>`

#![allow(clippy::unwrap_used, clippy::print_stdout)]

use nc_wallet_core::Mnemonic;
use nc_wallet_core::vault;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn main() {
    let mut args = std::env::args().skip(1);
    let password = args.next().expect("password");
    let out = args.next().expect("output file");
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    let blob = vault::seal(&phrase, "", &password).unwrap();
    std::fs::write(&out, &blob).unwrap();
    println!("sealed {} bytes into {out}", blob.len());
}
