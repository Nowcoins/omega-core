//! Nowcoin Omega's session engine as WebAssembly, for the Chrome extension.
//!
//! This is the same small surface the Android app gets through `nc-wallet-ffi`,
//! over the same `nc-wallet-session` crate, built with `wasm-bindgen`. It runs
//! in the extension's **service worker and nowhere else**: the popup and the
//! pages talk to the worker, and never hold a phrase or a key.
//!
//! # What crosses into JavaScript
//!
//! A secret leaves WebAssembly memory in these places only:
//!
//! * the backup words while a new wallet is being made
//!   ([`WalletEngine::pending_words`]) and the words after the password is
//!   typed again ([`reveal_phrase`]);
//! * the 32-byte **vault key** that opens the one stored vault without
//!   Argon2id: from [`WalletEngine::unlock_with_password`],
//!   [`WalletEngine::take_new_unlock_key`] and [`export_unlock_key`]. The
//!   extension keeps it in `chrome.storage.session` (memory only, never on
//!   disk, trusted extension contexts only) so a service worker that the browser
//!   stopped can reopen the vault without asking for the password, and wipes it
//!   when the wallet locks;
//! * going the other way, the password and an imported phrase arrive as the
//!   text the person typed.
//!
//! Everything else that returns is public: addresses and public keys,
//! the quiz's choices, what a typed phrase is missing, the vault header.
//! Errors are `Error` objects named `WalletError` with a stable `code`
//! (`WrongPassword`, `NotUnlocked`, ...); none carries a word, a password or a
//! key.
//!
//! JavaScript strings are immutable, so the copies of a password or a word that
//! JavaScript made cannot be wiped; the copies this crate makes are (the
//! password is wrapped in `Zeroizing` on arrival, and the engine wipes what it
//! holds when dropped or locked).
//!
//! The records that are lists (accounts, the quiz, a phrase check, the vault
//! header) are built as JSON by `json.rs` and parsed once on the JavaScript
//! side; their TypeScript types are declared below.

// The chain client lends the browser's `fetch` to `nc-wallet-chain`; its futures are
// the browser's, which are not `Send`, so it exists for WebAssembly only.
#[cfg(target_arch = "wasm32")]
mod chain;
mod json;

#[cfg(target_arch = "wasm32")]
pub use chain::WalletChain;
use js_sys::{Error as JsError, JSON, Reflect};
use nc_wallet_session as session;
use nc_wallet_session::{
    Engine, PhraseLength, SessionError, SigningError, VaultLimits, VaultParams,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** The ids the wallet API names networks by. */
export type NetworkApiId =
  | 'ethereum' | 'bsc' | 'polygon' | 'base' | 'tron'
  | 'bitcoin' | 'solana' | 'stellar' | 'bittensor';

/** One account on one network: public data only. */
export interface WasmNetworkAccount {
  network: NetworkApiId;
  address: string;
  publicKeyHex: string;
  path: string;
}

/** One backup question: which word is number `position`? */
export interface WasmBackupQuestion {
  position: number;
  choices: string[];
}

export type WasmPhraseProblem =
  | 'empty' | 'valid' | 'unknownWord' | 'wrongWordCount' | 'badChecksum';

/** What is wrong with typed text, if anything. */
export interface WasmPhraseCheck {
  problem: WasmPhraseProblem;
  wordCount: number;
  position: number;
  suggestions: string[];
}

/** The public facts in a vault's header. */
export interface WasmVaultFacts {
  version: number;
  memoryKib: number;
  iterations: number;
  lanes: number;
}

/** The `code` of the `WalletError` every failing call throws. */
export type WasmErrorCode =
  | 'WrongPassword' | 'EmptyPassword' | 'NotAVault' | 'UnsupportedVault'
  | 'PassphraseTooLong' | 'InvalidPhrase' | 'NoPendingWallet' | 'NotUnlocked'
  | 'NoQuiz' | 'BackupNotConfirmed' | 'NoNewKey' | 'AccountIndexOutOfRange'
  | 'Unavailable' | 'BadArgument'
  // From signing (`decode_request`, `sign_request`, `solana_lookup_tables`).
  | 'BadRequest' | 'Unsupported' | 'NotASigner' | 'ApprovalMismatch'
  | 'InsufficientFunds' | 'Dust' | 'NoTrustline' | 'MemoRequired'
  | 'RecipientIsTokenAccount' | 'LooksLikeTransaction' | 'FeeTooHigh' | 'FeeNotAccepted'
  | 'ChainMismatch';

/** A signing request read and checked: what the approval screen shows, and the
 *  hash (64 hex digits) that `sign_request` must be given back. */
export interface WasmDecoded {
  /** `request`, `network`, `signer`, `action`, `details`, `fee`, `warnings`
   *  (and `tx` for an EVM transaction). Amounts are decimal strings. */
  summary: Record<string, unknown>;
  approval: string;
}

/** Why an address is not valid on a network. */
export type WasmAddressReason =
  | 'empty' | 'format' | 'checksum' | 'zero_address' | 'unsupported_network';

/** Whether text is an address on a network. */
export interface WasmAddressCheck {
  valid: boolean;
  /** The EIP-55 form for the EVM networks, the text itself otherwise. */
  normalized: string | null;
  reason: WasmAddressReason | null;
}
"#;

/// The `Error` every failing call throws: `name` is `WalletError` and `code` is
/// a [`SessionError::code`] (or `BadArgument`).
fn throw_code(code: &str, message: &str) -> JsValue {
    let error = JsError::new(message);
    error.set_name("WalletError");
    // Setting a property on a fresh object cannot fail.
    let _ = Reflect::set(&error, &JsValue::from_str("code"), &JsValue::from_str(code));
    error.into()
}

fn throw(error: SessionError) -> JsValue {
    throw_code(error.code(), &error.to_string())
}

/// A signing failure: `code` is a [`SigningError::code`], the message its safe
/// `detail` (a field or a rule, never a value or a secret).
fn throw_signing(error: &SigningError) -> JsValue {
    throw_code(error.code(), error.detail())
}

fn to_js(value: &serde_json::Value) -> Result<JsValue, JsValue> {
    JSON::parse(&value.to_string())
        .map_err(|_| throw_code("Unavailable", "the answer could not be read"))
}

fn secret(text: String) -> Zeroizing<String> {
    Zeroizing::new(text)
}

fn key_bytes(key: Vec<u8>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(key)
}

/// The Argon2id parameters of the vaults this build seals: the extension's
/// ([`VaultParams::EXTENSION`]), heavier than the phone's because the vault sits
/// in the browser profile. Opening reads the parameters from the vault's header,
/// so a vault sealed with lighter ones (every extension vault before these)
/// still opens; the service worker re-seals it at its next unlock.
const SEAL_PARAMS: VaultParams = VaultParams::EXTENSION;

/// The most a stored vault's header may ask Argon2id for when this build opens
/// it ([`VaultLimits::EXTENSION`]: 512 MiB, 10 passes, 1 lane). The header is
/// whatever the stored bytes say, and a program on the computer can write them:
/// a vault that asks for more is refused as `NotAVault` (the worker shows it as
/// damaged) before any work, instead of making the worker reserve a gigabyte.
/// Every vault this build seals, and every one it sealed before, is within.
const OPEN_LIMITS: VaultLimits = VaultLimits::EXTENSION;

/// The wallet being made and the unlocked wallet, held in WebAssembly memory.
/// The service worker makes one and keeps it.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WalletEngine {
    inner: Engine,
}

impl Default for WalletEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WalletEngine {
    /// An engine with nothing pending and the wallet locked, that seals new
    /// wallets with the extension's parameters.
    #[wasm_bindgen(constructor)]
    pub fn new() -> WalletEngine {
        WalletEngine { inner: Engine::with_vault_params_and_limits(SEAL_PARAMS, OPEN_LIMITS) }
    }

    // ---- making a wallet ----

    /// Makes a new recovery phrase of 12 or 24 words from the browser's secure
    /// randomness and holds it until it is sealed or discarded.
    pub fn start_new(&mut self, words: u32) -> Result<(), JsValue> {
        let length = match words {
            12 => PhraseLength::Twelve,
            24 => PhraseLength::TwentyFour,
            _ => return Err(throw_code("BadArgument", "a recovery phrase has 12 or 24 words")),
        };
        self.inner.start_new(length).map_err(throw)
    }

    /// Starts an imported wallet from the typed phrase and the optional BIP-39
    /// passphrase (`""` for none).
    pub fn start_import(&mut self, text: String, passphrase: String) -> Result<(), JsValue> {
        let text = secret(text);
        let passphrase = secret(passphrase);
        self.inner.start_import(&text, &passphrase).map_err(throw)
    }

    /// Forgets the wallet being made or imported, wiping its phrase.
    pub fn discard_pending(&mut self) {
        self.inner.discard_pending();
    }

    /// Whether a wallet is being made or imported.
    pub fn has_pending(&self) -> bool {
        self.inner.has_pending()
    }

    /// The words of the phrase being made, for the backup screen. The one
    /// place a new phrase leaves WebAssembly.
    pub fn pending_words(&self) -> Result<Vec<String>, JsValue> {
        self.inner.pending_words().map_err(throw)
    }

    /// 12 or 24, for laying out the backup screen while the words are hidden.
    pub fn pending_word_count(&self) -> Result<u32, JsValue> {
        self.inner.pending_word_count().map_err(throw)
    }

    /// Three questions about the phrase being made, in the order of their
    /// positions. Asked once: calling again gives the same questions.
    #[wasm_bindgen(unchecked_return_type = "WasmBackupQuestion[]")]
    pub fn backup_questions(&mut self) -> Result<JsValue, JsValue> {
        let questions = self.inner.quiz().map_err(throw)?;
        to_js(&json::questions(&questions))
    }

    /// Whether `word` is the word at `position` in the phrase being made. The
    /// position must be one of the quiz's.
    pub fn check_backup_answer(&mut self, position: u32, word: String) -> Result<bool, JsValue> {
        self.inner.check_answer(position, &word).map_err(throw)
    }

    /// Seals the wallet being made under `password` and returns the vault blob
    /// to store. The wallet stays pending, and is unlocked only by
    /// [`WalletEngine::commit_pending`], once the blob is safely stored. A new
    /// wallet whose backup check was not passed is refused. Runs Argon2id.
    pub fn seal_pending(&mut self, password: String) -> Result<Vec<u8>, JsValue> {
        let password = secret(password);
        self.inner.seal_pending(&password).map_err(throw)
    }

    /// The vault from [`WalletEngine::seal_pending`] is stored: unlocks the
    /// wallet and clears the pending one.
    pub fn commit_pending(&mut self) -> Result<(), JsValue> {
        self.inner.commit_pending().map_err(throw)
    }

    /// The key the vault just sealed was sealed with, once, for the session
    /// store. Fails if it was already taken or dropped.
    pub fn take_new_unlock_key(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.take_new_key().map_err(throw)
    }

    /// Forgets the key [`WalletEngine::take_new_unlock_key`] would give.
    pub fn drop_new_unlock_key(&mut self) {
        self.inner.drop_new_key();
    }

    // ---- locking and unlocking ----

    /// Opens the stored vault with the password, keeps the wallet unlocked, and
    /// returns the 32-byte vault key Argon2id made on the way (so the caller
    /// can keep it in the session store without running Argon2id again).
    /// Runs Argon2id.
    pub fn unlock_with_password(
        &mut self,
        vault: &[u8],
        password: String,
    ) -> Result<Vec<u8>, JsValue> {
        let password = secret(password);
        let (unlocked, key) = session::open_with_password_keeping_key_within(
            vault,
            &password,
            self.inner.open_limits(),
        )
        .map_err(throw)?;
        self.inner.install(unlocked);
        Ok(key)
    }

    /// Opens the stored vault with the key kept in the session store. Quick:
    /// no Argon2id.
    pub fn unlock_with_key(&mut self, vault: &[u8], key: Vec<u8>) -> Result<(), JsValue> {
        self.inner.unlock_with_key(vault, &key_bytes(key)).map_err(throw)
    }

    /// Locks the wallet: the phrase held in WebAssembly is wiped.
    pub fn lock(&mut self) {
        self.inner.lock();
    }

    /// Whether the wallet is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    /// The accounts of all nine networks at account number `index`, derived
    /// from the unlocked wallet. Addresses and public keys only.
    #[wasm_bindgen(unchecked_return_type = "WasmNetworkAccount[]")]
    pub fn derive_accounts(&self, index: u32) -> Result<JsValue, JsValue> {
        let accounts = self.inner.accounts(index).map_err(throw)?;
        to_js(&json::accounts(&accounts))
    }

    /// The Solana account Trust Wallet shows for the phrase being imported, or for the unlocked wallet
    /// (`m/44'/501'/0'`): this wallet's own Solana account 0 is at Phantom's path, so a phrase from Trust
    /// Wallet has its Solana funds here and not there. Read the address's balance and history like any
    /// other's, and tell the person where their funds are. Address and public key only; nothing can be
    /// signed for it.
    #[wasm_bindgen(unchecked_return_type = "WasmNetworkAccount")]
    pub fn derive_trust_wallet_solana_account(&self) -> Result<JsValue, JsValue> {
        let account = self.inner.solana_trust_wallet_account().map_err(throw)?;
        to_js(&json::account(&account))
    }

    // ---- signing ----

    /// Reads a signing request (JSON; see `nc-wallet-session`'s `signing`
    /// module) and says what it would do, for account number `index`. Returns
    /// `{ summary, approval }`. Nothing is signed.
    #[wasm_bindgen(unchecked_return_type = "WasmDecoded")]
    pub fn decode_request(&self, index: u32, request: String) -> Result<JsValue, JsValue> {
        let decoded = self.inner.decode_request(index, &request).map_err(|e| throw_signing(&e))?;
        to_js(&json::decoded(&decoded))
    }

    /// Signs the request `approval` (64 hex digits, from `decode_request`) was
    /// made for. A request that differs in any way from the decoded one is an
    /// `ApprovalMismatch`. Returns the answer object for the request's kind.
    /// The key is derived, used and wiped inside.
    #[wasm_bindgen(unchecked_return_type = "Record<string, unknown>")]
    pub fn sign_request(
        &self,
        index: u32,
        request: String,
        approval: String,
    ) -> Result<JsValue, JsValue> {
        let approval = json::parse_approval(&approval)
            .ok_or_else(|| throw_code("BadRequest", "the approval is not 64 hexadecimal digits"))?;
        let signed =
            self.inner.sign_request(index, &request, &approval).map_err(|e| throw_signing(&e))?;
        to_js(&signed)
    }

    /// The extended public key (`zpub…`) of Bitcoin account `index` (BIP-84
    /// `m/84'/0'/index'`): it finds every receive and change address of the account without
    /// any private key. For the chain client alone; never shown, logged or sent to a server.
    pub fn bitcoin_zpub(&self, index: u32) -> Result<String, JsValue> {
        self.inner.bitcoin_zpub(index).map_err(|e| throw_signing(&e))
    }

    // ---- the sealed caches (history at rest) ----

    /// Seals `plaintext` (a history) for `label` under a key only this wallet's phrase
    /// makes (AES-256-GCM, inside WebAssembly). The wallet must be unlocked. The label is
    /// not in the blob: give it again to open it.
    pub fn seal_cache(&mut self, label: String, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.seal_cache(&label, plaintext).map_err(throw)
    }

    /// What `seal_cache` sealed for `label`, or `undefined` where `blob` is not this wallet's
    /// for that label (another wallet's, another label's, damaged): start afresh. The wallet
    /// must be unlocked.
    pub fn open_cache(&mut self, label: String, blob: &[u8]) -> Result<Option<Vec<u8>>, JsValue> {
        self.inner.open_cache(&label, blob).map_err(throw)
    }

    /// The name to store the blob for `label` under: 24 hex characters that reveal neither
    /// the network nor the address. The wallet must be unlocked.
    pub fn cache_id(&mut self, label: String) -> Result<String, JsValue> {
        self.inner.cache_id(&label).map_err(throw)
    }
}

/// Whether `address` is an address on `network` (a wallet-API id), checked by
/// the core, checksums included. Needs no wallet.
#[wasm_bindgen(unchecked_return_type = "WasmAddressCheck")]
pub fn validate_address(network: String, address: String) -> Result<JsValue, JsValue> {
    to_js(&json::address_check(&nc_wallet_session::validate_address(&network, &address)))
}

/// The address lookup tables (base58) a Solana transaction loads accounts
/// through; fetch their data and hand it to a `solana_transaction` request.
#[wasm_bindgen]
pub fn solana_lookup_tables(transaction_base64: String) -> Result<Vec<String>, JsValue> {
    nc_wallet_session::solana_lookup_tables(&transaction_base64).map_err(|e| throw_signing(&e))
}

/// Reads typed text as a recovery phrase and says what is wrong with it, if
/// anything. The text is not kept.
#[wasm_bindgen(unchecked_return_type = "WasmPhraseCheck")]
pub fn check_phrase(text: String) -> Result<JsValue, JsValue> {
    let text = secret(text);
    to_js(&json::phrase_check(&session::check_phrase(&text)))
}

/// Up to `limit` words of the BIP-39 list that start with `prefix`.
#[wasm_bindgen]
pub fn complete_word(prefix: String, limit: u32) -> Vec<String> {
    session::complete_word(&prefix, limit as usize)
}

/// The vault key after checking the password, for a vault the caller holds:
/// 32 bytes that open that one vault and nothing else. A new password makes a
/// new key. Runs Argon2id.
#[wasm_bindgen]
pub fn export_unlock_key(vault: &[u8], password: String) -> Result<Vec<u8>, JsValue> {
    session::export_unlock_key_within(vault, &secret(password), OPEN_LIMITS).map_err(throw)
}

/// The words of the stored phrase, after the password is typed again. Nothing
/// is unlocked or locked by this. Runs Argon2id.
#[wasm_bindgen]
pub fn reveal_phrase(vault: &[u8], password: String) -> Result<Vec<String>, JsValue> {
    session::reveal_phrase_within(vault, &secret(password), OPEN_LIMITS).map_err(throw)
}

/// A new vault with the same phrase under a new password (and a new salt),
/// sealed with the extension's parameters whatever the old vault's were, and
/// that vault's 32-byte key, as `{ vault, key }`. The old vault stays valid
/// until the caller replaces it. Runs Argon2id twice (once to open the old
/// vault, once to seal the new one). The same password as old and new re-seals
/// a vault of lighter parameters.
#[wasm_bindgen(unchecked_return_type = "{ vault: Uint8Array; key: Uint8Array }")]
pub fn change_password(
    vault: &[u8],
    old_password: String,
    new_password: String,
) -> Result<JsValue, JsValue> {
    let (renewed, key) = session::change_password_keeping_key_within(
        vault,
        &secret(old_password),
        &secret(new_password),
        SEAL_PARAMS,
        OPEN_LIMITS,
    )
    .map_err(throw)?;
    let result = js_sys::Object::new();
    let set = |name: &str, bytes: &[u8]| {
        Reflect::set(&result, &JsValue::from_str(name), &js_sys::Uint8Array::from(bytes))
    };
    // Setting a property on a fresh object cannot fail.
    let _ = set("vault", &renewed);
    let _ = set("key", &key);
    Ok(result.into())
}

/// What a stored vault's header says, without opening it. Fails with
/// `NotAVault` or `UnsupportedVault` if the bytes are not a vault this build
/// can read, `NotAVault` also if the header asks for more than
/// [`OPEN_LIMITS`].
#[wasm_bindgen(unchecked_return_type = "WasmVaultFacts")]
pub fn vault_facts(vault: &[u8]) -> Result<JsValue, JsValue> {
    let facts = session::vault_facts_within(vault, OPEN_LIMITS).map_err(throw)?;
    to_js(&json::vault_facts(&facts))
}

/// A vault of a fresh random phrase, sealed with the parameters of the vaults
/// this build seals (the extension's). To time one unlock, time
/// [`open_throwaway_vault`] on it (WebAssembly has no clock of its own: the
/// caller uses `performance.now()`).
#[wasm_bindgen]
pub fn throwaway_vault() -> Result<Vec<u8>, JsValue> {
    session::throwaway_vault_with_params(SEAL_PARAMS).map_err(throw)
}

/// Whether `key` opens `vault`: throws `WrongPassword` if not. Quick (no
/// Argon2id), and touches no wallet the engine holds: the worker checks a
/// re-sealed vault with it before it replaces the stored one.
#[wasm_bindgen]
pub fn check_unlock_key(vault: &[u8], key: Vec<u8>) -> Result<(), JsValue> {
    session::open_with_key_within(vault, &key_bytes(key), OPEN_LIMITS).map(drop).map_err(throw)
}

/// Opens a vault made by [`throwaway_vault`]: the work of one unlock.
#[wasm_bindgen]
pub fn open_throwaway_vault(vault: &[u8]) -> Result<(), JsValue> {
    session::open_throwaway_within(vault, OPEN_LIMITS).map_err(throw)
}

#[cfg(test)]
mod tests;
