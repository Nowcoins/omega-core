#!/usr/bin/env bash
# One format, two builds: a vault sealed by the WebAssembly build opens in the
# native build, and the other way round, through the real wasm-bindgen
# JavaScript API (Node). Run from anywhere in the repo.
#
#   crates/nc-wallet-wasm/scripts/cross-format.sh [--update-fixtures]
#
# With --update-fixtures the two vaults are also written to tests/fixtures/
# (native.vault, wasm.vault), which the crate's own tests open in both worlds.
set -euo pipefail
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$root"
export PATH="$HOME/.cargo/bin:$PATH"
if [ -s "$HOME/.nvm/nvm.sh" ]; then . "$HOME/.nvm/nvm.sh" >/dev/null; fi
password="cross-format fixture password"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
here=crates/nc-wallet-wasm

cargo build -q -p nc-wallet-wasm --target wasm32-unknown-unknown --profile release-wasm
wasm-bindgen --target nodejs --out-dir "$work/pkg" \
    target/wasm32-unknown-unknown/release-wasm/nc_wallet_wasm.wasm

# Native seals, wasm opens.
cargo run -q -p nc-wallet-wasm --example seal_native -- "$password" "$work/native.vault"
node "$here/scripts/cross-format.mjs" open "$work/pkg" "$password" "$work/native.vault"

# Wasm seals, native opens.
node "$here/scripts/cross-format.mjs" seal "$work/pkg" "$password" "$work/wasm.vault"
cargo run -q -p nc-wallet-wasm --example open_native -- "$password" "$work/wasm.vault"

if [ "${1:-}" = "--update-fixtures" ]; then
    cp "$work/native.vault" "$here/tests/fixtures/native.vault"
    cp "$work/wasm.vault" "$here/tests/fixtures/wasm.vault"
    echo "fixtures updated"
fi
echo "cross-format: ok"
