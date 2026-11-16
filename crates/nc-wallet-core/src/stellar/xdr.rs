//! Stellar transactions, hand-encoded in XDR.
//!
//! Only what a wallet sends: a version-1 transaction with time
//! bounds, a memo and one operation, which is a payment (XLM, or an issued
//! asset such as USDC), a trustline for an issued asset, or the creation of an
//! account. Nothing here does I/O: the sequence number and the time bounds are
//! inputs.
//!
//! XDR is big-endian in four-byte units. A union is its discriminant as a
//! `u32` followed by the arm; a string is its length followed by its bytes,
//! padded with zeros to a multiple of four; an optional value is a `u32` 0 or
//! 1, followed by the value when there is one.

use sha2::{Digest as _, Sha256};

/// The public network's passphrase. Its hash is part of what every signature
/// covers, so a transaction signed for one network can never be replayed on
/// another.
pub const PUBLIC_NETWORK_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// The test network's passphrase.
pub const TEST_NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// The most bytes a text memo carries.
pub const MAX_MEMO_TEXT: usize = 28;

/// An ed25519 public key, which is what a Stellar account is.
pub type PublicKey = [u8; 32];

/// `ENVELOPE_TYPE_TX`: tags a v1 transaction, both in its envelope and in what
/// is hashed for signing.
const ENVELOPE_TYPE_TX: u32 = 2;
/// `KEY_TYPE_ED25519` in a muxed account and `PUBLIC_KEY_TYPE_ED25519` in an
/// account id: both zero, both followed by the 32-byte key.
const KEY_TYPE_ED25519: u32 = 0;
/// `KEY_TYPE_MUXED_ED25519`: a muxed account, which is the 64-bit id and then the 32-byte key.
const KEY_TYPE_MUXED_ED25519: u32 = 0x100;
/// `PRECOND_TIME`: the transaction carries time bounds and nothing else.
const PRECOND_TIME: u32 = 1;
const MEMO_NONE: u32 = 0;
const MEMO_TEXT: u32 = 1;
const MEMO_ID: u32 = 2;
const ASSET_TYPE_NATIVE: u32 = 0;
const ASSET_TYPE_CREDIT_ALPHANUM4: u32 = 1;
const ASSET_TYPE_CREDIT_ALPHANUM12: u32 = 2;
const CREATE_ACCOUNT: u32 = 0;
const PAYMENT: u32 = 1;
const CHANGE_TRUST: u32 = 6;

/// Why a value cannot go into a transaction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XdrError {
    /// Asset codes are one to twelve ASCII letters and digits.
    #[error("{0:?} is not an asset code: one to twelve ASCII letters and digits")]
    AssetCode(String),
    /// Text memos hold at most [`MAX_MEMO_TEXT`] bytes.
    #[error("a memo holds at most {MAX_MEMO_TEXT} bytes of text; this one has {0}")]
    MemoTooLong(usize),
    /// A payment must move something.
    #[error("the amount must be more than zero")]
    Amount,
    /// A starting balance, trustline limit, fee or sequence number outside
    /// what the network takes.
    #[error("{0} is out of range")]
    OutOfRange(&'static str),
    /// A trustline is for an issued asset; XLM needs none.
    #[error("XLM has no trustline")]
    NativeTrustline,
    /// Time bounds whose end is before their start.
    #[error("the time bounds end before they begin")]
    TimeBounds,
}

/// An issued asset's code: `USDC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetCode(String);

impl AssetCode {
    /// Checks a code: one to twelve ASCII letters and digits.
    pub fn new(code: &str) -> Result<Self, XdrError> {
        if code.is_empty() || code.len() > 12 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(XdrError::AssetCode(code.to_owned()));
        }
        Ok(Self(code.to_owned()))
    }

    /// The code as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What an operation moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asset {
    /// XLM, the network's own coin.
    Native,
    /// An issued asset. Two with the same code and different issuers are
    /// unrelated, which is why the issuer is part of what identifies one.
    Credit {
        /// Its code.
        code: AssetCode,
        /// The account that issued it.
        issuer: PublicKey,
    },
}

impl Asset {
    /// An issued asset from its code and its issuer's `G…` address.
    pub fn credit(code: &str, issuer: &str) -> Result<Self, XdrError> {
        let issuer = super::parse_address(issuer).ok_or(XdrError::OutOfRange("the issuer"))?;
        Ok(Asset::Credit { code: AssetCode::new(code)?, issuer })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Asset::Native => put_u32(out, ASSET_TYPE_NATIVE),
            Asset::Credit { code, issuer } => {
                // Codes of up to four characters are one type and longer ones
                // another, each padded with zeros to its own width.
                let (kind, width) = if code.0.len() <= 4 {
                    (ASSET_TYPE_CREDIT_ALPHANUM4, 4)
                } else {
                    (ASSET_TYPE_CREDIT_ALPHANUM12, 12)
                };
                put_u32(out, kind);
                let mut padded = code.0.as_bytes().to_vec();
                padded.resize(width, 0);
                out.extend_from_slice(&padded);
                put_account(out, issuer);
            }
        }
    }
}

/// A memo's text, checked against the network's limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoText(String);

impl MemoText {
    /// Checks that `text` fits: [`MAX_MEMO_TEXT`] bytes, not characters.
    pub fn new(text: &str) -> Result<Self, XdrError> {
        if text.len() > MAX_MEMO_TEXT {
            return Err(XdrError::MemoTooLong(text.len()));
        }
        Ok(Self(text.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a transaction tells its recipient: on Stellar, which customer of an
/// exchange a payment into its shared address is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Memo {
    /// Nothing.
    None,
    /// A 64-bit number.
    Id(u64),
    /// Up to 28 bytes of text.
    Text(MemoText),
}

impl Memo {
    /// A text memo.
    pub fn text(text: &str) -> Result<Self, XdrError> {
        MemoText::new(text).map(Memo::Text)
    }

    /// The memo that carries `memo` to a recipient.
    ///
    /// A number written as a number is written (digits, no leading zero,
    /// within 64 bits) goes as an id, the type exchanges that number their
    /// customers ask for. Anything else goes as text, character for character:
    /// "007" stays "007" rather than becoming 7. An empty memo is no memo.
    pub fn parse(memo: &str) -> Result<Self, XdrError> {
        if memo.is_empty() {
            return Ok(Memo::None);
        }
        if let Ok(id) = memo.parse::<u64>()
            && id.to_string() == memo
        {
            return Ok(Memo::Id(id));
        }
        Self::text(memo)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Memo::None => put_u32(out, MEMO_NONE),
            Memo::Id(id) => {
                put_u32(out, MEMO_ID);
                put_u64(out, *id);
            }
            Memo::Text(text) => {
                put_u32(out, MEMO_TEXT);
                put_string(out, text.0.as_bytes());
            }
        }
    }
}

/// The one thing a transaction does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Creates `destination` with `starting_balance` stroops of XLM: the only
    /// way to pay XLM to an account that does not exist yet.
    CreateAccount {
        /// The new account.
        destination: PublicKey,
        /// Stroops it starts with; at least the minimum balance.
        starting_balance: i64,
    },
    /// Pays `amount` stroops of `asset` to `destination`.
    Payment {
        /// Who is paid.
        destination: PublicKey,
        /// The id of a muxed destination (`M…`, SEP-23): the payment is then to the muxed account, as
        /// the address says. `None` for a plain account.
        destination_id: Option<u64>,
        /// What is paid.
        asset: Asset,
        /// How much, in stroops: 1e-7 of the asset.
        amount: i64,
    },
    /// Opens the source's trustline for `asset`, or changes its limit (0
    /// removes it). An account can hold an issued asset only once it has one.
    ChangeTrust {
        /// The asset to trust. Never [`Asset::Native`], which needs none.
        asset: Asset,
        /// The most the account will hold, in stroops.
        limit: i64,
    },
}

impl Operation {
    /// No source of its own: the transaction's source performs it.
    fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, 0);
        match self {
            Operation::CreateAccount { destination, starting_balance } => {
                put_u32(out, CREATE_ACCOUNT);
                put_account(out, destination);
                put_i64(out, *starting_balance);
            }
            Operation::Payment { destination, destination_id, asset, amount } => {
                put_u32(out, PAYMENT);
                put_muxed(out, destination, *destination_id);
                asset.encode(out);
                put_i64(out, *amount);
            }
            Operation::ChangeTrust { asset, limit } => {
                put_u32(out, CHANGE_TRUST);
                // A trustline's asset shares the plain asset's arms for every
                // kind this module builds.
                asset.encode(out);
                put_i64(out, *limit);
            }
        }
    }

    fn check(&self) -> Result<(), XdrError> {
        match self {
            Operation::CreateAccount { starting_balance, .. } if *starting_balance < 0 => {
                Err(XdrError::OutOfRange("the starting balance"))
            }
            Operation::Payment { amount, .. } if *amount <= 0 => Err(XdrError::Amount),
            Operation::ChangeTrust { asset: Asset::Native, .. } => Err(XdrError::NativeTrustline),
            Operation::ChangeTrust { limit, .. } if *limit < 0 => {
                Err(XdrError::OutOfRange("the trustline limit"))
            }
            _ => Ok(()),
        }
    }
}

/// When a transaction may be applied, in Unix seconds, inclusive. Past
/// `max_time` it never can be, which is what lets an unconfirmed payment be
/// safely built again once that time has gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeBounds {
    /// Earliest; zero for "any time".
    pub min_time: u64,
    /// Latest; zero for "no limit".
    pub max_time: u64,
}

/// A v1 transaction with one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The account that pays the fee, uses its sequence number, and performs
    /// the operation.
    pub source: PublicKey,
    /// The most the transaction may be charged, in stroops. The network
    /// charges what the ledger's fee market asks, up to this.
    pub fee: u32,
    /// The source account's current sequence number, as Horizon reports it.
    /// The transaction carries the next one.
    pub account_sequence: i64,
    /// When it may be applied.
    pub time_bounds: TimeBounds,
    /// What the recipient is told.
    pub memo: Memo,
    /// What it does.
    pub operation: Operation,
}

impl Transaction {
    /// The transaction's XDR: what is hashed, signed, and wrapped in an
    /// envelope to be submitted.
    ///
    /// # Errors
    /// [`XdrError`] for an amount, limit, fee, sequence number or time bounds
    /// the network would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, XdrError> {
        self.operation.check()?;
        if self.fee == 0 {
            return Err(XdrError::OutOfRange("the fee"));
        }
        if self.account_sequence < 0 {
            return Err(XdrError::OutOfRange("the sequence number"));
        }
        let sequence = self
            .account_sequence
            .checked_add(1)
            .ok_or(XdrError::OutOfRange("the sequence number"))?;
        if self.time_bounds.max_time != 0 && self.time_bounds.max_time < self.time_bounds.min_time {
            return Err(XdrError::TimeBounds);
        }
        let mut out = Vec::with_capacity(256);
        put_account(&mut out, &self.source);
        put_u32(&mut out, self.fee);
        put_i64(&mut out, sequence);
        put_u32(&mut out, PRECOND_TIME);
        put_u64(&mut out, self.time_bounds.min_time);
        put_u64(&mut out, self.time_bounds.max_time);
        self.memo.encode(&mut out);
        put_u32(&mut out, 1);
        self.operation.encode(&mut out);
        // The transaction's extension: none.
        put_u32(&mut out, 0);
        Ok(out)
    }
}

/// A network's id: the SHA-256 of its passphrase.
#[must_use]
pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

/// The hash a transaction is signed as and known by: SHA-256 of the network
/// id, the envelope type and the transaction's XDR. Fixed before signing, so a
/// payment's hash is known before it is sent.
#[must_use]
pub fn transaction_hash(network_id: &[u8; 32], transaction: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(network_id);
    hasher.update(ENVELOPE_TYPE_TX.to_be_bytes());
    hasher.update(transaction);
    hasher.finalize().into()
}

/// The last four bytes of a key, which travel with its signature so a
/// validator can tell which signer a signature is meant for without trying
/// each.
#[must_use]
pub fn signature_hint(key: &PublicKey) -> [u8; 4] {
    [key[28], key[29], key[30], key[31]]
}

/// A transaction as it is submitted: the envelope type, the transaction, and
/// its signatures, each with its hint.
#[must_use]
pub fn envelope(transaction: &[u8], signatures: &[([u8; 4], [u8; 64])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + transaction.len() + signatures.len() * 72);
    put_u32(&mut out, ENVELOPE_TYPE_TX);
    out.extend_from_slice(transaction);
    put_u32(&mut out, u32::try_from(signatures.len()).unwrap_or(u32::MAX));
    for (hint, signature) in signatures {
        out.extend_from_slice(hint);
        put_string(&mut out, signature);
    }
    out
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// An account, as a muxed account without an id and as an account id alike.
fn put_account(out: &mut Vec<u8>, key: &PublicKey) {
    put_u32(out, KEY_TYPE_ED25519);
    out.extend_from_slice(key);
}

/// A muxed account: the key alone, or, for a muxed address, its id first.
fn put_muxed(out: &mut Vec<u8>, key: &PublicKey, id: Option<u64>) {
    match id {
        Some(id) => {
            put_u32(out, KEY_TYPE_MUXED_ED25519);
            put_u64(out, id);
            out.extend_from_slice(key);
        }
        None => put_account(out, key),
    }
}

/// Variable-length bytes: the length, the bytes, then zeros to a multiple of
/// four.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(bytes);
    out.resize(out.len() + (4 - bytes.len() % 4) % 4, 0);
}
