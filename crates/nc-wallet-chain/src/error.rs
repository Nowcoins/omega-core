//! What goes wrong when the device asks a chain, and how it is told.
//!
//! One shape for every failure, the shape the apps already branch on:
//! `{ "code", "message", "retryable", "details"? }`. The code is stable, the
//! words are for people. A message never carries an address, a URL or a key:
//! what a node said is shortened and cleaned before it is passed on.

use serde_json::{Value, json};

/// The most characters of a node's own words passed on.
const NODE_WORDS: usize = 200;

/// A request's failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The network id is not one this wallet lists.
    UnknownNetwork,
    /// The network has no JSON-RPC route for a site (only the EVM networks and Solana do).
    RpcNotAvailable,
    /// An address is not one on that network.
    InvalidAddress(String),
    /// A parameter or the body is malformed or out of range.
    InvalidRequest(String),
    /// The ticker is not listed on the network.
    UnknownAsset(String),
    /// Every endpoint of the network asked the device to wait, or the device is
    /// holding to their published rate.
    Busy {
        /// When to try again.
        retry_after_seconds: u64,
    },
    /// No endpoint of the network answered.
    Unavailable,
    /// The transfer could not be estimated: the node's reason.
    EstimateFailed(String),
    /// A figure that moves money (a fee, a nonce) could not be confirmed by a second,
    /// independent operator, or the operators did not agree. Trying again may.
    Unconfirmed(String),
    /// A figure is above the most this wallet will ever pay (`nc_wallet_core::limits`):
    /// refused, not clamped.
    OverCeiling(String),
    /// The account cannot cover the amount and the fee.
    InsufficientFunds(String),
    /// The bytes are not a transaction of this network.
    InvalidTransaction(String),
    /// The network already has the transaction.
    Duplicate {
        /// Its hash, to follow it as if it had just been sent.
        hash: String,
    },
    /// The nonce (sequence number) was used.
    Nonce(String),
    /// The fee is below what the network takes now.
    InsufficientFee(String),
    /// The transaction's block reference or time bounds have passed.
    Expired(String),
    /// The network refused it.
    Rejected(String),
    /// A bug in the wallet.
    Internal,
}

/// Result alias.
pub type ChainResult<T> = Result<T, ChainError>;

impl ChainError {
    /// The stable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownNetwork => "unknown_network",
            Self::RpcNotAvailable => "rpc_not_available",
            Self::InvalidAddress(_) => "invalid_address",
            Self::InvalidRequest(_) => "invalid_request",
            Self::UnknownAsset(_) => "unknown_asset",
            Self::Busy { .. } => "upstream_busy",
            Self::Unavailable => "upstream_unavailable",
            // The apps show the words of an `estimate_failed`.
            Self::EstimateFailed(_) | Self::Unconfirmed(_) | Self::OverCeiling(_) => {
                "estimate_failed"
            }
            Self::InsufficientFunds(_) => "insufficient_funds",
            Self::InvalidTransaction(_) => "invalid_transaction",
            Self::Duplicate { .. } => "duplicate",
            Self::Nonce(_) => "nonce",
            Self::InsufficientFee(_) => "insufficient_fee",
            Self::Expired(_) => "expired",
            Self::Rejected(_) => "rejected",
            Self::Internal => "internal",
        }
    }

    /// Whether repeating the request unchanged could succeed.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Busy { .. } | Self::Unavailable | Self::Unconfirmed(_) | Self::Internal
        )
    }

    /// For people. Never an address, a URL or a key.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::UnknownNetwork => "that network is not listed in this wallet".to_owned(),
            Self::RpcNotAvailable => {
                "JSON-RPC is served for the EVM networks and Solana only".to_owned()
            }
            Self::InvalidAddress(what) | Self::InvalidRequest(what) => what.clone(),
            Self::UnknownAsset(ticker) => {
                format!("{} is not listed on that network", clean(ticker))
            }
            Self::Busy { retry_after_seconds } => {
                format!(
                    "the network's public endpoints are busy; try again in {retry_after_seconds}s"
                )
            }
            Self::Unavailable => {
                "the network is not answering right now; try again shortly".to_owned()
            }
            Self::EstimateFailed(why)
            | Self::Unconfirmed(why)
            | Self::OverCeiling(why)
            | Self::InsufficientFunds(why)
            | Self::InvalidTransaction(why)
            | Self::Nonce(why)
            | Self::InsufficientFee(why)
            | Self::Expired(why)
            | Self::Rejected(why) => clean(why),
            Self::Duplicate { .. } => "the network already has this transaction".to_owned(),
            Self::Internal => "an internal error occurred".to_owned(),
        }
    }

    /// The error as the apps read it.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut body = json!({
            "code": self.code(),
            "message": self.message(),
            "retryable": self.retryable(),
        });
        match self {
            Self::Duplicate { hash } => body["details"] = json!({ "hash": hash }),
            Self::Busy { retry_after_seconds } => {
                body["details"] = json!({ "retry_after_seconds": retry_after_seconds });
            }
            // Both are `estimate_failed` to the apps; the reason tells them apart without
            // reading words: "unconfirmed" (try again) or "over_ceiling" (the wallet will not pay it).
            Self::Unconfirmed(_) => body["details"] = json!({ "reason": "unconfirmed" }),
            Self::OverCeiling(_) => body["details"] = json!({ "reason": "over_ceiling" }),
            _ => {}
        }
        body
    }

    /// The error as JSON text.
    #[must_use]
    pub fn to_json(&self) -> String {
        self.to_value().to_string()
    }

    /// An invalid-request error with these words.
    pub fn invalid(what: impl Into<String>) -> Self {
        Self::InvalidRequest(what.into())
    }
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for ChainError {}

/// What is said of a refusal whose reason the wallet does not classify. A node's own
/// words are never passed on for this: they come from a public server, and a lying one
/// could write advice there ("send funds to ... to unlock"). The class is the `code`.
pub const REFUSED: &str = "the network refused this transaction";

/// A result code a network names (`op_no_trust`, `tx_failed`) if it looks like one:
/// lower-case letters, digits and underscores, short. Anything else is `unknown`.
#[must_use]
pub fn result_code(code: &str) -> &str {
    let plain = !code.is_empty()
        && code.len() <= 40
        && code.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if plain { code } else { "unknown" }
}

/// A node's or endpoint's words, made safe to pass on: control characters out,
/// whitespace collapsed, shortened.
#[must_use]
pub fn clean(words: &str) -> String {
    let collapsed = words.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().filter(|c| !c.is_control()).take(NODE_WORDS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_busy_network_says_when() {
        let body = ChainError::Busy { retry_after_seconds: 7 }.to_value();
        assert_eq!(body["code"], "upstream_busy");
        assert_eq!(body["retryable"], true);
        assert_eq!(body["details"]["retry_after_seconds"], 7);
    }

    #[test]
    fn a_duplicate_hands_back_the_hash_to_follow() {
        let body = ChainError::Duplicate { hash: "0xabc".to_owned() }.to_value();
        assert_eq!(body["code"], "duplicate");
        assert_eq!(body["details"]["hash"], "0xabc");
        assert_eq!(body["retryable"], false);
    }

    #[test]
    fn a_nodes_words_are_cleaned_and_shortened() {
        let long = format!("nonce too low\n\t{}\u{7}", "x".repeat(500));
        let message = ChainError::Rejected(long).message();
        assert!(message.starts_with("nonce too low xxx"));
        assert!(message.chars().count() <= NODE_WORDS);
        assert!(!message.chars().any(char::is_control));
    }

    #[test]
    fn a_failure_of_ours_says_nothing_of_how() {
        assert_eq!(ChainError::Internal.message(), "an internal error occurred");
        assert!(!ChainError::Unavailable.message().contains("http"));
    }

    #[test]
    fn a_fee_that_could_not_be_confirmed_and_one_that_is_too_high_are_told_apart_by_a_reason() {
        let unconfirmed = ChainError::Unconfirmed("x".to_owned()).to_value();
        let over = ChainError::OverCeiling("x".to_owned()).to_value();
        assert_eq!(unconfirmed["code"], "estimate_failed");
        assert_eq!(over["code"], "estimate_failed");
        assert_eq!(unconfirmed["details"]["reason"], "unconfirmed");
        assert_eq!(over["details"]["reason"], "over_ceiling");
        assert_eq!(unconfirmed["retryable"], true);
        assert_eq!(over["retryable"], false);
    }
}
