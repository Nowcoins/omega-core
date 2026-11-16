#!/usr/bin/env bash
# Runs nc-wallet-wasm's tests as WebAssembly, in Node (wasm-bindgen-test).
# The runner and the crate must be the same version:
#   cargo install wasm-bindgen-cli --version 0.2.129 --locked
#
#   crates/nc-wallet-wasm/scripts/test-wasm.sh          # from anywhere in the repo
set -euo pipefail
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$root"
export PATH="$HOME/.cargo/bin:$PATH"
want="$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')"
have="$(wasm-bindgen --version | awk '{print $2}')"
if [ "$want" != "$have" ]; then
    echo "wasm-bindgen CLI is $have but Cargo.lock has $want: cargo install wasm-bindgen-cli --version $want --locked" >&2
    exit 1
fi
if [ -s "$HOME/.nvm/nvm.sh" ]; then . "$HOME/.nvm/nvm.sh" >/dev/null; fi
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
# The host runs the same tests' native half.
exec cargo test -p nc-wallet-wasm --lib --target wasm32-unknown-unknown "$@"
