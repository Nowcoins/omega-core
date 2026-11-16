//! Opens a vault file natively and checks it holds the BIP-39 reference phrase.
//! Used by `scripts/cross-format.sh` to check that the native build opens a
//! vault the WebAssembly build sealed. Exits non-zero if it does not.
//!
//! `cargo run -p nc-wallet-wasm --example open_native -- <password> <in-file>`

#![allow(clippy::unwrap_used, clippy::print_stdout)]

use nc_wallet_core::vault;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn main() {
    let mut args = std::env::args().skip(1);
    let password = args.next().expect("password");
    let input = args.next().expect("input file");
    let blob = std::fs::read(&input).unwrap();
    let opened = vault::open(&blob, &password).unwrap();
    assert_eq!(opened.mnemonic().expose_phrase().as_str(), ABANDON);
    assert_eq!(opened.expose_passphrase(), "");
    let facts = vault::info(&blob).unwrap();
    println!(
        "opened {input}: format {}, {} KiB, {} passes, {} lane",
        facts.version,
        facts.params.memory_kib(),
        facts.params.iterations(),
        facts.params.lanes()
    );
}
