# nc-wallet-core

The signing core of **Nowcoin Omega**, the self-custody wallet (Android app and Chrome
extension): recovery phrases, key derivation and addresses; a wallet from one imported
private key; transaction building and signing; and the vault that keeps the phrase, or
the key, under a password.

This is the most security-critical code in the product. A wrong derivation means a user
cannot restore their wallet elsewhere; a leaked secret means stolen coins.

## Rules

* **No I/O, no async.** No chain client, no configuration, no `tokio` or `reqwest`;
  nothing that opens a file, a socket or a thread.
* **Builds for both targets** (`cargo build -p nc-wallet-core --target wasm32-unknown-unknown`,
  and `cargo ndk -t arm64-v8a build -p nc-wallet-core` with the Android NDK installed).
* **Randomness** for new phrases is the operating system's (`getrandom`), and the
  browser's `crypto.getRandomValues` on `wasm32-unknown-unknown`. That target enables
  `getrandom`'s `js` feature in `Cargo.toml`; without it the build fails, so there is no
  silent fallback. A source that fails, or hands back only zeros, is an error.
* **No cryptographic primitive is written here.** BIP-39, BIP-32, `k256`, `ed25519-dalek`,
  `schnorrkel`, `substrate-bip39`, SHA-2, HMAC, Keccak, RIPEMD, Blake2, Bech32, strkey:
  all from maintained crates. SLIP-10 for ed25519 (HMAC-SHA512, about 20 lines) is written
  from the specification because no maintained crate fits, and is pinned by SLIP-0010's
  own vectors.

## Use

```rust
use nc_wallet_core::{Mnemonic, Network, WordCount, derive, signing_key};

let phrase = Mnemonic::generate(WordCount::Twelve)?;      // or Mnemonic::parse("...")?
let account = derive(&phrase, "", Network::Evm, 0)?;      // address + public key, no secret
let key = signing_key(&phrase, "", Network::Evm, 0)?;     // the one door for a private key
```

`Network` is `Evm`, `Tron`, `Bitcoin`, `Solana`, `Stellar` or `Bittensor`. Each network
also has a module with its own functions (`evm::account`, `bitcoin::account_zpub`,
`stellar::export_secret_seed`, ...). `Mnemonic::parse` accepts 12, 15, 18, 21 and 24
words, checks the checksum and returns an error that names the problem (the position of
an unknown word, never the word).

## Networks, paths and vector sources

The index `i` is the account number the wallet shows. Every row is pinned by tests with
values copied from the source named; the tests carry the repository, file and commit next
to each value.

| Network | Path | Key and address | Vectors from |
|---|---|---|---|
| EVM (Ethereum, BNB Chain, Polygon, Base) | `m/44'/60'/0'/0/i` | secp256k1, EIP-55 | Trezor firmware fixtures; Trust Wallet Core `HDWalletTests`; Polkadot.js keyring tests (private key and address); py-substrate-interface ECDSA tests; the ERC-55 test cases |
| TRON | `m/44'/195'/0'/0/i` | secp256k1, base58check, `0x41` | Trezor firmware fixtures; Trust Wallet Core |
| Bitcoin | `m/84'/0'/0'/0/i` (change `m/84'/0'/0'/1/i`); account `zpub` at `m/84'/0'/0'` | secp256k1, P2WPKH `bc1q…` | BIP-84 (addresses, public keys, WIF private keys, root and account extended keys); Trust Wallet Core |
| Solana | `m/44'/501'/i'/0'` | ed25519 by SLIP-10, base58 | Trezor firmware fixtures (account 0, plus two shorter paths); SLIP-0010 |
| Stellar | `m/44'/148'/i'` | ed25519 by SLIP-10, strkey `G…` (`S…` only through `export_secret_seed`) | SEP-0005 (5 phrases of 12, 15 and 24 words, one with a passphrase; 10 accounts each, `G` and `S`); Trezor firmware fixtures; Trust Wallet Core |
| Bittensor | root key for `i = 0`; hard junction `//i` for `i >= 1` | sr25519, SS58 prefix 42 | `sp-core` (`DEV_PHRASE` root and `//Alice`); Polkadot.js (`//Alice`, `//9007199254740991`, mini secret); `substrate-bip39` (24 vectors); py-substrate-interface (root key) |
| (all) | BIP-39 seed; BIP-32 | | BIP-39: Trezor `vectors.json`; BIP-32: the BIP's vectors 1 to 4; SLIP-0010: ed25519 vectors 1 and 2 |

Bittensor is not derived from the BIP-39 seed. Substrate takes the phrase's **entropy**,
runs PBKDF2-HMAC-SHA512 (salt `"mnemonic"` + password, 2048 rounds) and uses the first 32
bytes as an sr25519 mini secret. Account `i` is that key's hard derivation with the chain
code `i` (little-endian `u64`, zero-padded to 32 bytes), as `btcli`, Polkadot.js and
Talisman derive `<phrase>//i`. The passphrase is Substrate's "password" (`<phrase>///password`),
used as typed, without the Unicode normalisation BIP-39 applies to its passphrase.

## Signing: EVM, TRON and Bitcoin

Everything a transaction needs from the network (nonce, fee rates, unspent outputs, the
reference block, the time) is an input. Signing is deterministic (RFC 6979), recoverable
and always low-S.

| Network | Built and signed | Vectors from |
|---|---|---|
| EVM | legacy (EIP-155) and EIP-1559 transactions on chain ids 1, 56, 137, 8453; ERC-20 `transfer` and `approve` calldata; `personal_sign`; EIP-712 typed data from JSON | EIP-155's worked example; `ethereum/tests` RLP tests; Trust Wallet Core's signed transactions (legacy, EIP-1559, ERC-20 transfer and approve); 24 real mainnet transactions (six per chain, both forms, native, transfer, approve: re-encoded to the node's hash, sender recovered); EIP-712's example (type hash, struct hashes, digest, signature, from the EIP text and its `Example.js`); MetaMask `eth-sig-util` (`personal_sign`, `signTypedData` v4 and 74 single-value cases); Trust Wallet Core (typed data and `personal_sign`); ERC-2612's type string |
| EVM approval screens | native transfer, ERC-20 `transfer` / `approve` (unlimited flag at 2^255) / `transferFrom`, `setApprovalForAll`, EIP-2612 and DAI-style `permit` in typed data, "unknown contract call" | the call data of the vectors above; 4byte.directory for the selectors |
| TRON | TRX `TransferContract` and TRC-20 `TriggerSmartContract` (`transfer`, `approve`) as protobuf `raw_data`; id = SHA-256; signature = secp256k1 over it; `signMessageV2` | five real mainnet transactions byte for byte (TRX, two TRX with a memo, USDT transfer and approve) with the blocks they reference; Trust Wallet Core's memo transaction (id and signature); `TronWeb` and Trust Wallet Core `signMessageV2` vectors; `tronprotocol/protocol` field numbers |
| Bitcoin | P2WPKH spends from the account's receive and change addresses (BIP-143, `SIGHASH_ALL`), largest-first coin selection, change above `max(1000, cost to make and spend it)`, a changeless fallback, send max, replace-by-fee signalled, version 2 | BIP-143's native P2WPKH vector (digest, signature and the whole signed transaction); three real mainnet transactions (encoding, id, weight, fee, and every signature verified under our digest); Bitcoin Core's address data (`key_io_valid.json`, `key_io_invalid.json`) and `GetDustThreshold`; BIP-84's account; Trust Wallet Core's send-max vector |

`evm::parse_address` reads an address as a person types it (`0x` and 40 hex digits; a mixed-case address
must carry its EIP-55 checksum; the all-zero address is refused, `parse_address_any` allows it). It is what
the session's `validate_address` and the signing requests use, tested with the ERC-55 cases.

Where the wallet is stricter than the libraries it was checked against, on purpose: typed data
with a missing or `null` member, an integer outside its width, `uint` / `int` without a width,
a fixed array of the wrong length, an address without its `0x`; a transaction with chain id 0,
gas 0 or a tip above the cap; TRON calls without a fee limit; testnet and later-version
witness addresses. Where it is as lenient as MetaMask and Trust Wallet: a `bytesN` shorter
than `N` is zero-padded, and a hex string of odd length is read with a zero in front.

Not covered: contract creation, EIP-2930 access lists (always empty), Permit2 and other
typed-data messages beyond EIP-2612 / DAI permits (shown as "other" with their domain),
Bitcoin inputs other than P2WPKH (legacy, Taproot), bumping a stuck payment (the payment
signals replace-by-fee; building the replacement is not here), and decoding a TRON `raw_data`
handed in by a dApp.

## A wallet from one private key

`ImportedKey::parse` (`src/imported.rs`) reads the text a person pasted. Two kinds are read: a
**secp256k1** key as 64 hexadecimal digits, with or without `0x` (what MetaMask, Trust Wallet and
TronLink export), which is the account on Ethereum, BNB Chain, Polygon and Base and, written
TRON's way, on TRON; and an **ed25519** key for Solana, as the base58 of the 64-byte secret key
(what Phantom and Solflare export) or as the list of 64 numbers Solana's own tools write. The
public half of a Solana secret is checked against its seed, so a mistyped key is refused
(`HalvesDisagree`), never opened as another account.

What is not a key is told apart from one: 40 hexadecimal digits, a `T…` or `bc1…` text, and a
25- or 32-byte base58 are **addresses** (`LooksLikeAnAddress`), the commonest thing pasted by
mistake; a 32-byte base58 is never taken for a seed. There is no Bitcoin here (a key in WIF may
hold coins at address types this wallet does not read), no Stellar and no Bittensor: those are
reached with a phrase, and `ImportedKey::account` answers `KeyDoesNotReach` for them.

The key is wiped when the value is dropped, prints nothing under `Debug`, is not `Clone`, and is
read through `expose_secret` and `expose_text` (the form it would be exported in again).

## The vault

`vault::seal` puts a phrase (and its optional BIP-39 passphrase) under a password, and
`vault::seal_imported_keeping_key_with_params` one imported private key (payload version 2: the
kind and the 32 bytes, padded as a phrase is, so the two cannot be told apart from outside).
`vault::open` takes a phrase out and answers `HoldsAKey` for a vault of a key; `vault::open_any`
takes out whichever the vault holds (`Held`). Argon2id (version 1.3; `VaultParams::PHONE` is 64 MiB, 3 passes, 1 lane, a random
16-byte salt) makes a 256-bit key from the NFKD-normalised password; AES-256-GCM with a random
96-bit nonce seals a payload padded to a multiple of 256 bytes, so a 12-word and a 24-word phrase
make blobs of the same length. The whole 47-byte header (magic `NCWV`, format 1, KDF and cipher
ids, the three cost parameters, the salt, the nonce) is the associated data. The format is
documented byte by byte at the top of `src/vault.rs`.

A blob may ask the KDF for at most 1 GiB, 32 passes and 8 lanes, checked before anything is
allocated; `seal` refuses less than 16 MiB or 2 passes. A wrong password and a damaged blob are one
error (AES-GCM cannot tell them apart). `derive_key` and `open_with_key` let an app keep the
Argon2id key behind the operating system's lock (Android's biometric Keystore key) and open the
vault without the password; the key opens that one vault and nothing else. `wordlist` exposes the
English BIP-39 list for input screens.

Tests (`src/vault/tests.rs`): RFC 9106 section 5.3's Argon2id vector, the reference
implementation's seven Argon2id vectors (phc-winner-argon2 `test.c`) through the vault's own
derivation, McGrew and Viega's AES-256-GCM test case 16 and NIST CAVP vectors, a pinned blob
(byte for byte, confirmed against OpenSSL's AES-GCM), round trips for 12 and 24 words with and
without a passphrase, wrong passwords, every changed bit of a blob, every truncation, hostile
header parameters, and that nothing secret is printed.

## Secrets

`Mnemonic`, `Seed` and `SigningKey` wipe themselves when dropped (`ZeroizeOnDrop`), print
only a placeholder under `Debug`, and have no `Display`. Each is read through a method
named for it (`expose_phrase`, `expose_secret`), so a search finds every reader. Tests
check that `{:?}` and `{:#?}` of each, bare or in an `Option`, `Vec` or `Result`, contain
none of its bytes. Wiping is best effort for what the dependencies hold in their own
temporaries (a hash state, an intermediate array).

## Dependencies

| Crate | Version | Why |
|---|---|---|
| `bip39` | 2.2.2 | BIP-39 phrases, English list, checksum, NFKD, seed |
| `bip32` | 0.6.0 | BIP-32 over secp256k1, `zpub` serialisation. 0.6 is on `k256` 0.14, and brings its own `hmac` 0.13, `sha2` 0.11 and `ripemd` 0.2 beside the 0.12, 0.10 and 0.1 named here |
| `k256` | 0.14.0 | secp256k1 keys and points. Without its default features: `std` turns on the operating system's randomness (`getrandom` 0.4), which does not build for `wasm32-unknown-unknown` without a second browser shim, and nothing here asks `k256` for a random number (ECDSA is RFC 6979). `std` is also what the precomputed base-point tables need; without them an account still derives in about 0.6 ms |
| `ed25519-dalek` | 2.2.0 | ed25519 public keys |
| `schnorrkel` | 0.11.5 | sr25519 (mini secret expansion, hard derivation) |
| `substrate-bip39` | 0.6.1 | Substrate's entropy-to-mini-secret step |
| `hmac`, `sha2` | 0.12.1, 0.10.9 | SLIP-10 |
| `sha3`, `ripemd`, `blake2` | 0.10.9, 0.1.3, 0.10.6 | Keccak-256 (EVM, TRON), HASH160 (Bitcoin), SS58 checksum |
| `bs58` | 0.5.1 (`check`) | base58 and base58check (TRON, Solana, SS58) |
| `bech32` | 0.11.1 | Bitcoin `bc1q…` |
| `stellar-strkey` | 0.0.18 | Stellar `G…` and `S…` (Stellar's own crate; zeroizing encoder for the secret) |
| `getrandom` | 0.2.17 (+ `js` on wasm) | system randomness |
| `argon2`, `aes-gcm` | 0.5.3, 0.10.3 | the vault's key derivation and cipher (RustCrypto; the 0.5 / 0.10 generation, like `sha2` 0.10) |
| `unicode-normalization` | 0.1 | NFKD for the vault password |
| `zeroize`, `thiserror` | 1.9.0, 2.0.20 | wiping; error types |

`serde_json` (EIP-712 typed data arrives as JSON).

Dev only: `hex` and `blake3` (not part of any wasm or Android build).

## Known limits

* English wordlist only. 15, 18 and 21 words are accepted on import; new phrases are 12 or 24.
* RUSTSEC-2026-0387 (secret-dependent branches in some of `crypto-bigint`'s constant-time operations,
  fixed from 0.7.6, with no fix on the 0.5 line that `k256` 0.13 uses) is closed **for this crate**: it names
  `k256` 0.14 (`crypto-bigint` 0.7.10) and `bip32` 0.6, whose `k256` is the same package, and
  `tests/dependencies.rs` reads `Cargo.lock` and fails if either goes back or a `crypto-bigint` under
  the wallet's `k256` is older than 0.7.6. The tests alone still use `k256` 0.13, to check signatures
  independently of the signing path, so `cargo audit` of the whole lockfile names it, for them alone. The move cost the extension's
  WebAssembly 43 KB (3.00 to 3.04 MB); all the vectors (BIP-32, Trezor, Trust Wallet Core, BIP-84,
  EIP-155 and EIP-712, TRON, Bitcoin) pass as they did.
* **The audit for a wallet release** is `scripts/audit-wallet.sh`, not a plain `cargo audit` of the
  workspace. It lists the crates the wallet is built from (the normal dependencies of `nc-wallet-ffi` and
  `nc-wallet-wasm` for wasm32, arm64 and armv7 Android: 240 crates on 2026-11-02) and fails when a vulnerability, an
  unsound warning or a yanked version names one of them, unless the script allows it with a date and a reason (none
  does). Advisories against test-only crates, such as the one above, are not the wallet's, so they leave it green; a
  plain `cargo audit` still names them. `--self-test` shows that an advisory against the wallet's `crypto-bigint` fails
  and one against the tests' 0.5.5 does not. The Android graph's `tokio` was moved from 1.53.1 to 1.53.3 on 2026-11-02
  for RUSTSEC-2026-0386 (`AsyncFd`, which wallet code does not call).
* The `bip32` crate does not wipe the chain codes of the nodes it builds when they are
  dropped (the private keys inside are wiped). Chain codes are not private keys, but with
  one child key they can expose the parent, so they are worth wiping; fixing it means
  writing BIP-32 here instead of using the crate.
* Soft and public derivation for sr25519 are not provided (Bittensor uses hard junctions).
