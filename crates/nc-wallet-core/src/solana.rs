//! Solana: ed25519 by SLIP-10 at `m/44'/501'/{index}'/0'`, the path Phantom
//! and Solflare use for their accounts (`solana-keygen recover` reads the same
//! one as `?key={index}/0`). The address is the base58 of the 32-byte public
//! key.
//!
//! # Transactions
//!
//! Everything a transaction needs from the network is an input: the recent
//! blockhash, whether the recipient already has a token account, and the
//! priority fee. The wallet builds legacy messages ([`build_sol_transfer`],
//! [`build_spl_transfer`]) and returns the transaction unsigned, with its
//! signature slot zeroed; [`sign_transaction`] fills it. The same function
//! signs a transaction a site hands over, after [`summarize_transaction`] has
//! read it back for the approval screen. [`sign_message`] signs raw bytes for
//! a site's `signMessage`, and refuses bytes that are a transaction message.
//!
//! The tests pin the encoders to Solana's own libraries and to transactions
//! on mainnet.

pub mod message;
pub mod summary;

#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod tests;

pub use message::{LookupTable, MessageError, ParsedMessage, ParsedTransaction, Pubkey};
pub use summary::{
    Danger, InstructionReview, InstructionSummary, TransactionSummary, lookup_tables_needed,
    program_name, summarize_transaction, summarize_transaction_for,
};

use ed25519_dalek::Signer as _;

use crate::error::Error;
use crate::hd;
use crate::key::{Account, KeyScheme, SigningKey};
use crate::mnemonic::Seed;
use crate::network::Network;

/// The private key of account `index`.
pub fn signing_key(seed: &Seed, index: u32) -> Result<SigningKey, Error> {
    let index = hd::check_index(index)?;
    hd::ed25519_key(seed.expose_secret(), &Network::Solana.derivation_path(index))
        .ok_or(Error::InvalidKey(index))
}

/// The address and public key of account `index`.
pub fn account(seed: &Seed, index: u32) -> Result<Account, Error> {
    let key = signing_key(seed, index)?;
    account_of(&key, index)
}

/// Trust Wallet's Solana path. Its registry lists two for the coin, `m/44'/501'/0'` first and
/// `m/44'/501'/0'/0'` (Phantom's, and [`account`]'s for index 0) second, and Trust Wallet shows the first:
/// a phrase from Trust Wallet has its Solana funds at [`trust_wallet_account`], not at [`account`].
pub const TRUST_WALLET_PATH: &str = "m/44'/501'/0'";

/// The address and public key Trust Wallet shows for this phrase's Solana account (its default
/// path, [`TRUST_WALLET_PATH`]). It is another account than [`account`]'s index 0, and the public half
/// is all there is: nothing here hands out its private key, so nothing can be signed with it.
pub fn trust_wallet_account(seed: &Seed) -> Result<Account, Error> {
    let key =
        hd::ed25519_key(seed.expose_secret(), TRUST_WALLET_PATH).ok_or(Error::InvalidKey(0))?;
    account_of(&key, 0)
}

pub(crate) fn account_of(key: &SigningKey, index: u32) -> Result<Account, Error> {
    let address = address_from_public_key(key.public_key()).ok_or(Error::InvalidKey(index))?;
    Ok(Account { address, public_key: key.public_key().to_vec() })
}

/// The address of an ed25519 public key: its base58; `None` unless the key
/// is 32 bytes.
pub fn address_from_public_key(public_key: &[u8]) -> Option<String> {
    (public_key.len() == 32).then(|| bs58::encode(public_key).into_string())
}

/// The base58 address of a 32-byte key.
#[must_use]
pub fn address(key: &Pubkey) -> String {
    message::encode(key)
}

/// Reads a base58 address: exactly 32 bytes.
#[must_use]
pub fn parse_address(text: &str) -> Option<Pubkey> {
    message::decode(text)
}

/// Why a transaction could not be built or signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SolanaError {
    /// The message could not be built, or the bytes could not be read.
    #[error(transparent)]
    Message(#[from] MessageError),
    /// The key is not an ed25519 key.
    #[error("a Solana transaction is signed with an ed25519 key")]
    WrongKeyScheme,
    /// The key's public half is not among the transaction's required signers.
    #[error("this account is not one of the transaction's signers")]
    NotASigner,
    /// An amount of zero is not a transfer.
    #[error("the amount must be more than zero")]
    ZeroAmount,
    /// The transaction would be larger than the network accepts.
    #[error("the transaction is larger than the network accepts")]
    TooLarge,
    /// The bytes to sign as a message are a Solana transaction (or its
    /// message): signing them would authorise it.
    #[error("these bytes are a transaction; sign them as a transaction, not a message")]
    LooksLikeTransaction,
    /// The bytes to sign as a message are not UTF-8 text. A message is text;
    /// anything else could be a transaction in a format this wallet cannot read.
    #[error("a message to sign must be text")]
    NotText,
    /// A program-derived address could not be found.
    #[error("no token account address could be derived")]
    NoTokenAccount,
}

/// A priority fee: the compute the transaction may use and what it pays per
/// unit. Both come from the fee quote the wallet's API gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority {
    /// Compute units the transaction may use.
    pub compute_unit_limit: u32,
    /// Micro-lamports paid per compute unit.
    pub compute_unit_price_micro_lamports: u64,
}

impl Priority {
    fn instructions(self) -> [message::Instruction; 2] {
        [
            message::set_compute_unit_limit(self.compute_unit_limit),
            message::set_compute_unit_price(self.compute_unit_price_micro_lamports),
        ]
    }
}

/// A SOL transfer to build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolTransfer {
    /// The sender, who also pays the fee and signs.
    pub from: Pubkey,
    /// The recipient.
    pub to: Pubkey,
    /// Lamports (1 SOL is 10^9).
    pub lamports: u64,
    /// A recent blockhash, from the network.
    pub recent_blockhash: [u8; 32],
    /// An optional priority fee.
    pub priority: Option<Priority>,
}

/// An SPL token transfer to build (tokens under the Token program, such as
/// USDT and USDC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplTransfer {
    /// The sender's wallet, who also pays the fee and signs.
    pub owner: Pubkey,
    /// The token's mint.
    pub mint: Pubkey,
    /// The mint's decimals, which the transfer asserts.
    pub decimals: u8,
    /// The amount, in the token's smallest unit.
    pub amount: u64,
    /// The recipient's wallet (not a token account): the tokens go to its
    /// associated token account.
    pub recipient: Pubkey,
    /// The token account the tokens leave; `None` for the sender's associated
    /// token account, where wallets hold them.
    pub source: Option<Pubkey>,
    /// Whether the recipient's associated token account already exists. When
    /// it does not, the transaction creates it (idempotently), the sender
    /// paying the rent.
    pub recipient_token_account_exists: bool,
    /// A recent blockhash, from the network.
    pub recent_blockhash: [u8; 32],
    /// An optional priority fee.
    pub priority: Option<Priority>,
}

/// Builds a SOL transfer: an unsigned transaction (its one signature slot
/// zeroed), for [`sign_transaction`].
///
/// # Errors
/// [`SolanaError::ZeroAmount`] for no lamports.
pub fn build_sol_transfer(transfer: &SolTransfer) -> Result<Vec<u8>, SolanaError> {
    if transfer.lamports == 0 {
        return Err(SolanaError::ZeroAmount);
    }
    let mut instructions = Vec::new();
    instructions.extend(transfer.priority.into_iter().flat_map(Priority::instructions));
    instructions.push(message::system_transfer(transfer.from, transfer.to, transfer.lamports));
    unsigned(&transfer.from, &instructions, &transfer.recent_blockhash)
}

/// Builds an SPL token transfer, creating the recipient's associated token
/// account first when it has none: an unsigned transaction, for
/// [`sign_transaction`].
///
/// # Errors
/// [`SolanaError::ZeroAmount`] for no tokens.
pub fn build_spl_transfer(transfer: &SplTransfer) -> Result<Vec<u8>, SolanaError> {
    if transfer.amount == 0 {
        return Err(SolanaError::ZeroAmount);
    }
    let derive = |owner: &Pubkey| {
        message::associated_token_account(owner, &transfer.mint).ok_or(SolanaError::NoTokenAccount)
    };
    let source = match transfer.source {
        Some(source) => source,
        None => derive(&transfer.owner)?,
    };
    let destination = derive(&transfer.recipient)?;
    let mut instructions = Vec::new();
    instructions.extend(transfer.priority.into_iter().flat_map(Priority::instructions));
    if !transfer.recipient_token_account_exists {
        instructions.push(message::create_associated_token_account_idempotent(
            transfer.owner,
            destination,
            transfer.recipient,
            transfer.mint,
        ));
    }
    instructions.push(message::transfer_checked(
        source,
        transfer.mint,
        destination,
        transfer.owner,
        transfer.amount,
        transfer.decimals,
    ));
    unsigned(&transfer.owner, &instructions, &transfer.recent_blockhash)
}

fn unsigned(
    payer: &Pubkey,
    instructions: &[message::Instruction],
    blockhash: &[u8; 32],
) -> Result<Vec<u8>, SolanaError> {
    let message = message::compile(payer, instructions, blockhash)?;
    let transaction = message::transaction(&[[0; 64]], &message);
    if transaction.len() > message::MAX_TRANSACTION_SIZE {
        return Err(SolanaError::TooLarge);
    }
    Ok(transaction)
}

/// A transaction with this wallet's signature in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The serialized transaction: what is sent to the network. Signature
    /// slots of other signers are as they were given.
    pub transaction: Vec<u8>,
    /// The signature this wallet made.
    pub signature: [u8; 64],
}

impl SignedTransaction {
    /// The transaction's id: its first signature, in base58 (the fee payer's).
    #[must_use]
    pub fn id(&self) -> String {
        let first = self.transaction.get(1..65).unwrap_or_default();
        bs58::encode(first).into_string()
    }
}

/// Signs a serialized transaction (legacy or version 0) with `key`: reads it,
/// finds the key among the required signers, signs the message and puts the
/// signature in that signer's slot. Other slots are left as they were, so a
/// transaction another party signs too stays valid.
///
/// Call [`summarize_transaction`] first: the person approves what that
/// returns, and this signs the same bytes.
///
/// # Errors
/// [`SolanaError`] if the key is not ed25519, the bytes are not a transaction
/// or the key is not one of its signers.
pub fn sign_transaction(
    key: &SigningKey,
    transaction: &[u8],
) -> Result<SignedTransaction, SolanaError> {
    if key.scheme() != KeyScheme::Ed25519 {
        return Err(SolanaError::WrongKeyScheme);
    }
    let mut parsed = ParsedTransaction::parse(transaction)?;
    let slot = parsed
        .message
        .signers()
        .iter()
        .position(|signer| signer.as_slice() == key.public_key())
        .ok_or(SolanaError::NotASigner)?;
    let signature = sign_bytes(key, &parsed.message_bytes);
    parsed.signatures[slot] = signature;
    Ok(SignedTransaction {
        transaction: message::transaction(&parsed.signatures, &parsed.message_bytes),
        signature,
    })
}

/// Signs raw bytes for a site's `signMessage`: ed25519 over exactly the bytes
/// given, no prefix.
///
/// Bytes that read as a transaction message are refused. A site could
/// otherwise ask for a transaction's message to be "signed as a message" and
/// the signature would authorise it, without the approval screen that
/// [`sign_transaction`] has.
///
/// # Errors
/// [`SolanaError::WrongKeyScheme`], or [`SolanaError::LooksLikeTransaction`].
pub fn sign_message(key: &SigningKey, bytes: &[u8]) -> Result<[u8; 64], SolanaError> {
    if key.scheme() != KeyScheme::Ed25519 {
        return Err(SolanaError::WrongKeyScheme);
    }
    if ParsedMessage::parse(bytes).is_ok() || ParsedTransaction::parse(bytes).is_ok() {
        return Err(SolanaError::LooksLikeTransaction);
    }
    Ok(sign_bytes(key, bytes))
}

/// What a site's `signMessage` payload must be: UTF-8 text that is not a transaction.
/// [`sign_message`] signs any bytes that are not a transaction (the RFC 8032 vectors
/// are not text); the session engine calls this first for a site's request.
///
/// UTF-8 is the guard that does not depend on knowing every format. A
/// transaction's message holds its signers' public keys, which are 32 random
/// bytes: they are not valid UTF-8 (or not text) except by a chance of about
/// 2^-32, so no future message format that lists its signers can pass for text.
/// A versioned message starts with a byte of 0x80 or more; that is a UTF-8
/// continuation byte (0x80 to 0xBF) or an invalid one for every version but
/// those that would start a multi-byte character, so a message that starts with
/// a non-ASCII *letter* stays signable. The parse checks remain for the two
/// formats that exist.
///
/// # Errors
/// [`SolanaError::NotText`], or [`SolanaError::LooksLikeTransaction`].
pub fn check_message(bytes: &[u8]) -> Result<(), SolanaError> {
    if ParsedMessage::parse(bytes).is_ok() || ParsedTransaction::parse(bytes).is_ok() {
        return Err(SolanaError::LooksLikeTransaction);
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(SolanaError::NotText);
    }
    Ok(())
}

fn sign_bytes(key: &SigningKey, bytes: &[u8]) -> [u8; 64] {
    // The dalek key wipes itself when dropped.
    ed25519_dalek::SigningKey::from_bytes(key.expose_secret()).sign(bytes).to_bytes()
}
