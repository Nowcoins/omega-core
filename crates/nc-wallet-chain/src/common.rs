//! What every family hands back, in the shapes the apps and the signing engine
//! already read (the shapes of the old wallet API: the apps' parsers, their
//! fixtures and `nc-wallet-session`'s `send` request all take them).

use serde_json::{Value, json};

use crate::error::{ChainError, ChainResult};
use crate::networks::{Native, Network, Token};
use crate::util::parse_amount;

/// The native coin's balance entry.
#[must_use]
pub fn native_entry(network: Network, amount: u128) -> Value {
    let native = network.native();
    json!({
        "asset": native.symbol,
        "kind": "native",
        "amount": amount.to_string(),
        "decimals": native.decimals,
    })
}

/// A token's balance entry; `None` is a balance that could not be read.
#[must_use]
pub fn token_entry(token: &Token, amount: Option<u128>) -> Value {
    let mut entry = json!({
        "asset": token.symbol,
        "kind": "token",
        "contract": token.contract,
        "amount": amount.map(|a| a.to_string()),
        "decimals": token.decimals,
    });
    if amount.is_none() {
        entry["error"] = json!("unavailable");
    }
    entry
}

/// A fee in the network's native coin.
#[must_use]
pub fn fee_value(native: Native, amount: u128) -> Value {
    json!({ "asset": native.symbol, "amount": amount.to_string(), "decimals": native.decimals })
}

/// A balances answer.
#[must_use]
pub fn balances_body(network: Network, address: &str, entries: &[Value], as_of: &str) -> Value {
    json!({ "network": network.id(), "address": address, "balances": entries, "as_of": as_of })
}

/// A transfer to be sized: the asset and the recipient, checked.
#[derive(Debug, Clone)]
pub struct EstimateArgs {
    /// The sender's address.
    pub from: String,
    /// The recipient's address.
    pub to: String,
    /// `None` for the native coin.
    pub token: Option<&'static Token>,
    /// Base units.
    pub amount: u128,
    /// The app asked for the fee at each speed (`"tiers": true`), where the network has speeds. Left out,
    /// the answer is the one fee, and nothing is asked of any node for the others.
    pub tiers: bool,
}

impl EstimateArgs {
    /// Reads and checks an estimate request.
    pub fn parse(network: Network, request: &Value) -> ChainResult<Self> {
        let text = |key: &str| -> ChainResult<String> {
            request
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| ChainError::invalid(format!("{key} is missing")))
        };
        let asset = text("asset")?;
        let token = if network.is_native(&asset) {
            None
        } else {
            Some(network.token(&asset).ok_or(ChainError::UnknownAsset(asset))?)
        };
        let tiers = match request.get("tiers") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(ChainError::invalid("tiers is true or false")),
        };
        Ok(Self {
            from: text("from")?,
            to: text("to")?,
            token,
            amount: parse_amount(&text("amount")?)?,
            tiers,
        })
    }
}

/// The most addresses a history request may name, the one in the path included (Bitcoin, without a `zpub`).
pub const MAX_ADDRESSES: usize = 40;
