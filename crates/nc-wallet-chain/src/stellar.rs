//! Stellar, through Horizon on public endpoints (the Foundation's, LOBSTR's,
//! Ankr's): the account (`/accounts/{id}`: its balances and trustlines, its
//! sequence, its data entries), the fee market (`/fee_stats`) and the reserve
//! (`/ledgers`), and `POST /transactions`.

use base64::Engine as _;
use serde_json::{Value, json};

use crate::address::{self, Address};
use crate::common::{EstimateArgs, balances_body, fee_value, native_entry, token_entry};
use crate::error::{ChainError, ChainResult, result_code};
use crate::net::Net;
use crate::networks::{Network, Token};
use crate::pool::Need;
use crate::quorum::{Ask, Kind};
use crate::util::{parse_json, parse_rfc3339, stroops, thousandths};
use nc_wallet_core::limits;
use nc_wallet_core::stellar::{self, Destination};

/// A ledger at least this full (thousandths: 0.9) is surge-priced: the fee
/// offered then is the 70th percentile of what was charged.
const SURGE_USAGE_MILLI: u64 = 900;
/// `config.memo_required`'s value, "1", as Horizon shows a data entry.
const MEMO_REQUIRED: &str = "MQ==";
/// How many endpoints a signed transaction is sent to at once.
const BROADCAST_TO: usize = 2;
/// The most a ledger may say each entry's reserve is, in stroops (100 XLM; the network's is 0.5 XLM).
/// A figure past it is not the network's, and would overflow what is worked out from it.
const MOST_RESERVE: u128 = 1_000_000_000;

/// Stellar.
#[derive(Debug, Clone, Copy)]
pub struct Stellar<'a> {
    net: &'a Net,
}

/// A Horizon account, read.
#[derive(Debug, Clone)]
struct Account {
    raw: Value,
}

impl Account {
    fn sequence(&self) -> u128 {
        self.raw.get("sequence").and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    fn balances(&self) -> impl Iterator<Item = &Value> {
        self.raw.get("balances").and_then(Value::as_array).into_iter().flatten()
    }

    fn native(&self) -> u128 {
        self.balances()
            .find(|b| b.get("asset_type").and_then(Value::as_str) == Some("native"))
            .and_then(|b| stroops(b.get("balance")?.as_str()?))
            .unwrap_or(0)
    }

    fn line(&self, token: &Token) -> Option<&Value> {
        self.balances().find(|b| {
            b.get("asset_code").and_then(Value::as_str) == Some(token.symbol)
                && b.get("asset_issuer").and_then(Value::as_str) == Some(token.contract)
        })
    }

    fn count(&self, key: &str) -> u128 {
        u128::from(self.raw.get(key).and_then(Value::as_u64).unwrap_or(0))
    }

    /// The least the account must keep, in stroops, for the entries it holds.
    fn minimum(&self, reserve: u128) -> u128 {
        let entries = 2 + self.count("subentry_count") + self.count("num_sponsoring");
        entries.saturating_sub(self.count("num_sponsored")).saturating_mul(reserve)
    }

    fn memo_required(&self) -> bool {
        self.raw
            .pointer("/data/config.memo_required")
            .and_then(Value::as_str)
            .is_some_and(|v| v == MEMO_REQUIRED)
    }
}

impl<'a> Stellar<'a> {
    /// Stellar over `net`.
    #[must_use]
    pub const fn new(net: &'a Net) -> Self {
        Self { net }
    }

    /// The account, or `None` for one that does not exist yet. Two endpoints
    /// are asked: where they differ the lower sequence number is used (a number
    /// too low is refused by the network, one too high is not), and a memo is
    /// required if either says it is.
    async fn account(&self, address: &Address) -> ChainResult<Option<Account>> {
        let path = format!("/accounts/{}", address.text);
        let answers = self.net.get_many(Need::ANY, 2, &path).await?;
        let mut found: Vec<Account> = Vec::new();
        let mut absent = false;
        for ((status, body), _) in answers {
            match status {
                200..=299 => {
                    if let Ok(raw) = parse_json(&body) {
                        found.push(Account { raw });
                    }
                }
                404 => absent = true,
                _ => {}
            }
        }
        // A destination that requires a memo is one that loses the payment without it (an
        // exchange's deposit address): if either operator says so, it is so. A lone operator
        // that left the flag out would otherwise send the money without its memo.
        let requires_memo = found.iter().any(Account::memo_required);
        found.sort_by_key(Account::sequence);
        match found.into_iter().next() {
            Some(mut account) => {
                if requires_memo && !account.memo_required() {
                    account.raw["data"]["config.memo_required"] = Value::from(MEMO_REQUIRED);
                }
                Ok(Some(account))
            }
            None if absent => Ok(None),
            None => Err(ChainError::Unavailable),
        }
    }

    /// One endpoint's account: for a read nothing depends on.
    async fn account_once(&self, address: &Address) -> ChainResult<Option<Account>> {
        let (status, body) =
            self.net.get(Need::ANY, &format!("/accounts/{}", address.text)).await?;
        match status {
            200..=299 => Ok(Some(Account { raw: parse_json(&body)? })),
            404 => Ok(None),
            _ => Err(ChainError::Unavailable),
        }
    }

    /// The latest ledger: the reserve each entry needs (stroops) and the moment it closed
    /// (Unix seconds, by the network's own clock).
    async fn ledger(&self) -> ChainResult<(u128, Option<u64>)> {
        let (status, body) = self.net.get(Need::ANY, "/ledgers?order=desc&limit=1").await?;
        if !(200..300).contains(&status) {
            return Err(ChainError::Unavailable);
        }
        let body = parse_json(&body)?;
        let record = body.pointer("/_embedded/records/0").ok_or(ChainError::Unavailable)?;
        let reserve = record
            .get("base_reserve_in_stroops")
            .and_then(Value::as_u64)
            .map(u128::from)
            .filter(|reserve| *reserve <= MOST_RESERVE)
            .ok_or(ChainError::Unavailable)?;
        let closed = record.get("closed_at").and_then(Value::as_str).and_then(parse_rfc3339);
        Ok((reserve, closed))
    }

    /// The reserve each entry needs, in stroops.
    async fn reserve(&self) -> ChainResult<u128> {
        self.ledger().await.map(|(reserve, _)| reserve)
    }

    /// The time a transaction's bounds are counted from: when the network's latest ledger
    /// closed, by its own clock, and not the device's. A device clock that is minutes wrong would
    /// otherwise make every send "too late"; a service that lies about the time can at worst
    /// make a send expire (a failed send, never a loss). If the ledger does not say when it closed,
    /// there is no time to count from: the device's clock is not a substitute, and the send is not built.
    fn network_time(closed: Option<u64>) -> ChainResult<u64> {
        closed.ok_or_else(|| {
            ChainError::EstimateFailed(
                "the network's time could not be read; try again in a moment".to_owned(),
            )
        })
    }

    /// The base fee to offer, in stroops per operation, from two operators, held to the
    /// wallet's own bound (`nc_wallet_core::limits`).
    async fn base_fee(&self) -> ChainResult<u64> {
        fn parse(body: &[u8]) -> Option<Vec<u128>> {
            let stats = parse_json(body).ok()?;
            let number = |value: Option<&Value>| value.and_then(Value::as_str)?.parse::<u64>().ok();
            let base = number(stats.get("last_ledger_base_fee"))?;
            let usage =
                stats.get("ledger_capacity_usage").and_then(Value::as_str).and_then(thousandths);
            let offered = if usage.is_some_and(|usage| usage >= SURGE_USAGE_MILLI) {
                number(stats.pointer("/fee_charged/p70")).unwrap_or(base)
            } else {
                number(stats.pointer("/fee_charged/mode")).unwrap_or(base)
            };
            Some(vec![u128::from(offered.max(base))])
        }
        let figures =
            self.net.rest_figures(Need::ANY, Ask::Get("/fee_stats"), parse, &[Kind::Fee]).await?;
        let figure = figures.first().ok_or(ChainError::Internal)?;
        let fee = figure.within(limits::STELLAR_BASE_FEE, "network fee")?;
        u64::try_from(fee).map_err(|_| ChainError::Unavailable)
    }

    /// The coin and every listed token of `address`.
    pub async fn balances(&self, address: &Address, as_of: &str) -> ChainResult<Value> {
        let account = self.account_once(address).await?;
        let mut entries =
            vec![native_entry(Network::Stellar, account.as_ref().map_or(0, Account::native))];
        for token in Network::Stellar.tokens() {
            let line = account.as_ref().and_then(|a| a.line(token));
            let amount = line.and_then(|b| stroops(b.get("balance")?.as_str()?)).unwrap_or(0);
            let mut entry = token_entry(token, Some(amount));
            entry["trustline"] = json!(line.is_some());
            entries.push(entry);
        }
        let mut body = balances_body(Network::Stellar, &address.text, &entries, as_of);
        body["account_exists"] = json!(account.is_some());
        Ok(body)
    }

    /// What a send is built from.
    pub async fn inputs(&self, address: &Address) -> ChainResult<Value> {
        let (account, fee, ledger) =
            futures::join!(self.account(address), self.base_fee(), self.ledger());
        let (account, fee, (reserve, closed)) = (account?, fee?, ledger?);
        let now = Self::network_time(closed)?;
        let Some(account) = account else {
            return Ok(json!({
                "network": "stellar",
                "address": address.text,
                "account_exists": false,
                "base_fee": fee.to_string(),
                "server_time": now,
            }));
        };
        let trustlines: Vec<Value> = account
            .balances()
            .filter(|b| b.get("asset_type").and_then(Value::as_str) != Some("native"))
            .map(|b| {
                json!({
                    "code": b.get("asset_code"),
                    "issuer": b.get("asset_issuer"),
                    "balance": stroops(b.get("balance").and_then(Value::as_str).unwrap_or("0")).unwrap_or(0).to_string(),
                    "limit": b.get("limit").and_then(Value::as_str).and_then(stroops).map(|l| l.to_string()),
                })
            })
            .collect();
        Ok(json!({
            "network": "stellar",
            "address": address.text,
            "account_exists": true,
            "sequence": account.sequence().to_string(),
            "base_fee": fee.to_string(),
            "balance": account.native().to_string(),
            "min_balance": account.minimum(reserve).to_string(),
            "trustlines": trustlines,
            "server_time": now,
        }))
    }

    /// The fee of a transfer and what is known of its recipient. A muxed address (`M…`, SEP-23) is
    /// asked about by the account behind it, and its id is told back.
    pub async fn estimate(&self, args: &EstimateArgs) -> ChainResult<Value> {
        address::parse(Network::Stellar, &args.from)
            .map_err(|_| ChainError::InvalidAddress("from is not a valid address".to_owned()))?;
        let bad_to = || ChainError::InvalidAddress("to is not a valid address".to_owned());
        let (to, muxed_id) = match stellar::parse_destination(&args.to) {
            Some(Destination { key, id: Some(id) }) => {
                let account = stellar::address_from_public_key(&key).ok_or_else(bad_to)?;
                (address::parse(Network::Stellar, &account).map_err(|_| bad_to())?, Some(id))
            }
            _ => (address::parse(Network::Stellar, &args.to).map_err(|_| bad_to())?, None),
        };
        let (fee, recipient, reserve) =
            futures::join!(self.base_fee(), self.account(&to), self.reserve());
        let (fee, recipient, reserve) = (fee?, recipient?, reserve?);
        let exists = recipient.is_some();
        let mut facts = json!({
            "exists": exists,
            "trustline": match (&recipient, args.token) {
                (_, None) => Value::Null,
                (Some(account), Some(token)) => json!(account.line(token).is_some()),
                (None, Some(_)) => json!(false),
            },
            // The id of a muxed address is the memo (SEP-29 asks for none beside it).
            "memo_required": muxed_id.is_none() && recipient.as_ref().is_some_and(Account::memo_required),
        });
        if let Some(id) = muxed_id {
            facts["muxed_id"] = json!(id.to_string());
        }
        if !exists {
            // The first payment to an address makes it, and must fund it.
            facts["minimum_new_account"] = json!((2 * reserve).to_string());
        }
        Ok(json!({
            "network": "stellar",
            "fee": fee_value(Network::Stellar.native(), u128::from(fee)),
            "recipient": facts,
        }))
    }

    /// Sends a signed envelope to two endpoints at once.
    pub async fn broadcast(&self, raw: &[u8], hash: &str) -> ChainResult<String> {
        let envelope = base64::engine::general_purpose::STANDARD.encode(raw);
        let body = format!("tx={}", percent_encode(&envelope));
        let answers = self
            .net
            .post_many(
                Need::ANY,
                BROADCAST_TO,
                "/transactions",
                "application/x-www-form-urlencoded",
                body.as_bytes(),
            )
            .await?;
        let mut accepted = false;
        let mut verdict: Option<ChainError> = None;
        let mut sequence_used = None;
        for ((status, text), _) in answers {
            if (200..300).contains(&status) {
                accepted = true;
                continue;
            }
            let body = parse_json(&text).unwrap_or(Value::Null);
            let code = body
                .pointer("/extras/result_codes/transaction")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let operations: Vec<&str> = body
                .pointer("/extras/result_codes/operations")
                .and_then(Value::as_array)
                .map(|ops| ops.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            match refusal(code, &operations) {
                ChainError::Nonce(why) => sequence_used = Some(why),
                other => verdict = verdict.or(Some(other)),
            }
        }
        if accepted {
            return Ok(hash.to_owned());
        }
        if let Some(why) = sequence_used {
            // A sequence number used is a duplicate if the network has this very transaction.
            let (status, _) = self.net.get(Need::ANY, &format!("/transactions/{hash}")).await?;
            return Err(match status {
                200..=299 => ChainError::Duplicate { hash: hash.to_owned() },
                404 => ChainError::Nonce(why),
                _ => ChainError::Unavailable,
            });
        }
        Err(verdict.unwrap_or(ChainError::Unavailable))
    }

    /// Where a transaction stands.
    pub async fn status(&self, hash: &str) -> ChainResult<Value> {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ChainError::invalid("that is not a transaction hash"));
        }
        let (status, body) = self.net.get(Need::ANY, &format!("/transactions/{hash}")).await?;
        match status {
            404 => Ok(json!({ "status": "not_found" })),
            200..=299 => {
                let body = parse_json(&body)?;
                let ok = body.get("successful").and_then(Value::as_bool) != Some(false);
                Ok(json!({
                    "status": if ok { "confirmed" } else { "failed" },
                    "block": body.get("ledger").and_then(Value::as_u64),
                    "confirmations": 1,
                }))
            }
            _ => Err(ChainError::Unavailable),
        }
    }
}

/// Percent-encodes everything but the unreserved characters.
fn percent_encode(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len() + 8);
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Horizon's result codes, as the code that fits them.
fn refusal(transaction: &str, operations: &[&str]) -> ChainError {
    match transaction {
        "tx_bad_seq" => ChainError::Nonce(
            "that sequence number was already used, or is not the next".to_owned(),
        ),
        "tx_insufficient_fee" => {
            ChainError::InsufficientFee("the fee is below what the network takes now".to_owned())
        }
        "tx_too_late" | "tx_too_early" => ChainError::Expired(
            "the transaction's time bounds have passed; build it again".to_owned(),
        ),
        "tx_insufficient_balance" => ChainError::InsufficientFunds(
            "the account cannot pay the fee and keep its reserve".to_owned(),
        ),
        "tx_failed" | "tx_failed_op" => match operations.first().copied().unwrap_or_default() {
            "op_underfunded" | "op_low_reserve" => ChainError::InsufficientFunds(
                "the account cannot cover the amount and keep its reserve".to_owned(),
            ),
            "op_no_trust" => {
                ChainError::Rejected("the recipient has no trustline for that asset".to_owned())
            }
            "op_no_destination" => {
                ChainError::Rejected("the recipient does not exist yet".to_owned())
            }
            "op_line_full" => ChainError::Rejected("the recipient's trustline is full".to_owned()),
            "op_not_authorized" => {
                ChainError::Rejected("the issuer has not authorised the recipient".to_owned())
            }
            other => ChainError::Rejected(format!("an operation failed ({})", result_code(other))),
        },
        "tx_bad_auth" | "tx_bad_auth_extra" => {
            ChainError::Rejected("the signature is not the account's".to_owned())
        }
        "" => ChainError::Rejected("the network refused the transaction".to_owned()),
        other => ChainError::Rejected(format!("the network refused it ({})", result_code(other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reserve_covers_two_entries_and_each_subentry_less_those_sponsored() {
        let account = Account {
            raw: json!({ "subentry_count": 1, "num_sponsoring": 0, "num_sponsored": 0 }),
        };
        assert_eq!(account.minimum(5_000_000), 15_000_000, "(2 + 1) x 0.5 XLM");
        let sponsored = Account { raw: json!({ "subentry_count": 3, "num_sponsored": 2 }) };
        assert_eq!(sponsored.minimum(5_000_000), 15_000_000);
    }

    #[test]
    fn result_codes_are_told_as_the_codes_that_fit() {
        assert_eq!(refusal("tx_bad_seq", &[]).code(), "nonce");
        assert_eq!(refusal("tx_insufficient_fee", &[]).code(), "insufficient_fee");
        assert_eq!(refusal("tx_too_late", &[]).code(), "expired");
        assert_eq!(refusal("tx_failed", &["op_underfunded"]).code(), "insufficient_funds");
        assert_eq!(refusal("tx_failed", &["op_no_trust"]).code(), "rejected");
        assert_eq!(refusal("", &[]).code(), "rejected");
    }

    #[test]
    fn an_envelope_is_form_encoded_with_nothing_unescaped() {
        assert_eq!(percent_encode("AAAA+/=="), "AAAA%2B%2F%3D%3D");
        assert_eq!(percent_encode("abc-_.~09"), "abc-_.~09");
    }
}
