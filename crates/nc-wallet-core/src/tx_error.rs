//! Why a transaction or a message could not be built or signed (the
//! secp256k1 networks: EVM, TRON and Bitcoin). Like every error in this crate
//! it carries no word, key or passphrase: it is safe to log and to show.

/// A transaction or message that could not be built, decoded or signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TxError {
    /// An input the transaction cannot be built from: `field` says which,
    /// `reason` why.
    #[error("{field}: {reason}")]
    Invalid {
        /// The input at fault, in the words of the network ("chain id", "fee
        /// limit", "recipient").
        field: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },

    /// An address that is not one of the network's (wrong length, checksum,
    /// version or network).
    #[error("{0} is not a valid address for this network")]
    Address(String),

    /// The coins offered do not cover the amount and the fee.
    #[error("the inputs hold {available} satoshis, {needed} are needed for the amount and the fee")]
    InsufficientFunds {
        /// Satoshis needed.
        needed: u64,
        /// Satoshis the inputs hold.
        available: u64,
    },

    /// An output below the amount nodes relay.
    #[error("an output of {amount} satoshis is below the dust limit of {limit}")]
    Dust {
        /// The output's value.
        amount: u64,
        /// The least an output with that script may hold.
        limit: u64,
    },

    /// The key at the input's place in the wallet does not own the output it
    /// is said to spend.
    #[error("input {input} is not paid to the key of the account it names")]
    KeyMismatch {
        /// The input, counting from zero.
        input: usize,
    },

    /// The key handed in is not a secp256k1 key.
    #[error("this network signs with a secp256k1 key")]
    WrongKeyScheme,

    /// EIP-712 typed data that is malformed or inconsistent. The text names
    /// the place in the data (`message.from.wallet`) and the problem.
    #[error("typed data: {0}")]
    TypedData(String),

    /// A key could not be derived for an input.
    #[error(transparent)]
    Key(#[from] crate::error::Error),

    /// The signer failed (the key was refused by the curve code).
    #[error("the signature could not be made")]
    Signing,
}

impl TxError {
    pub(crate) const fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::Invalid { field, reason }
    }
}
