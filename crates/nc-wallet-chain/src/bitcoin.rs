//! Bitcoin, through Esplora (mempool.space, with Blockstream's as the backup):
//! a node cannot list an address's outputs, and Esplora can.
//!
//! An HD wallet has many addresses, so balances, outputs and estimates take the
//! account's `zpub` and find the addresses that hold coins by looking, the way every
//! wallet does ([`discovery`]). Fee rates come from the mempool's own
//! `fee-estimates`. A transaction is sent to both services at once.

mod discovery;

pub use discovery::{ChainHint, Held, Hint, Reading};

use nc_wallet_core::TxError;
use nc_wallet_core::bitcoin::script::dust_limit;
use nc_wallet_core::bitcoin::tx::MAX_MONEY;
use nc_wallet_core::bitcoin::{FeeRate, quote};
use serde_json::{Value, json};

use crate::address;
use crate::common::{EstimateArgs, balances_body, fee_value, native_entry};
use nc_wallet_core::bitcoin::{Chain, addresses_from_zpub};
use nc_wallet_core::limits;

use crate::error::{ChainError, ChainResult, REFUSED};
use crate::net::Net;
use crate::networks::Network;
use crate::pool::Need;
use crate::quorum::{Figure, Kind, decide, unconfirmed as unconfirmed_error};
use crate::util::{from_thousandths, parse_json, thousandths};

/// Nodes still apply a relay minimum of a satoshi a virtual byte, so no rate
/// offered is lower, whatever the mempool says.
const MIN_RATE_KVB: u64 = 1_000;
/// The most outputs one answer lists.
const MAX_UTXOS: usize = 1_000;

/// Bitcoin.
#[derive(Debug, Clone, Copy)]
pub struct Bitcoin<'a> {
    net: &'a Net,
}

/// One unspent output Esplora listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The transaction.
    pub txid: String,
    /// The output's index in it.
    pub vout: u32,
    /// Satoshis.
    pub value: u64,
    /// Whether it is in a block.
    pub confirmed: bool,
    /// The block's height.
    pub height: Option<u64>,
}

/// The three rates and which of them are fit to use.
#[derive(Debug, Clone, Copy)]
pub struct Rates {
    /// Satoshis per thousand virtual bytes: slow, normal, fast (the raw reading where it is not fit).
    pub kvb: [u64; 3],
    /// Whether each is within the wallet's bounds and confirmed as far as it must be.
    pub ok: [bool; 3],
    /// How many independent services stand behind each.
    pub sources: [usize; 3],
}

/// An account of the wallet, as a request names it.
#[derive(Debug, Clone)]
pub struct Account {
    /// The account's `zpub`.
    pub zpub: String,
    /// The address the app shows (receive 0).
    pub shown: String,
    /// What an earlier reading left, if the app (or this client) has it.
    pub hint: Option<Hint>,
    /// The time, in Unix seconds.
    pub now_s: u64,
}

/// What a reading says beyond the figures it was asked for: the hint to keep, and whether more remains.
fn reading_json(reading: &Reading) -> Value {
    json!({
        "hint": reading.hint.to_json(),
        "next_change": reading.hint.next_change(),
        "lookups": reading.lookups,
        "scanning": reading.scanning,
    })
}

impl<'a> Bitcoin<'a> {
    /// Bitcoin over `net`.
    #[must_use]
    pub const fn new(net: &'a Net) -> Self {
        Self { net }
    }

    async fn get_json(&self, path: &str) -> ChainResult<Value> {
        let (status, body) = self.net.get(Need::ANY, path).await?;
        if !(200..300).contains(&status) {
            return Err(ChainError::Unavailable);
        }
        parse_json(&body)
    }

    /// The height of the chain's tip.
    pub async fn tip(&self) -> ChainResult<u64> {
        let (status, body) = self.net.get(Need::ANY, "/blocks/tip/height").await?;
        if !(200..300).contains(&status) {
            return Err(ChainError::Unavailable);
        }
        std::str::from_utf8(&body)
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .ok_or(ChainError::Unavailable)
    }

    /// The outputs `address` holds (unconfirmed ones included). An output holding nothing is left out
    /// (the planner cannot spend one), and one holding more than there is bitcoin is no answer
    /// of Esplora's.
    pub async fn outputs_at(&self, address: &str) -> ChainResult<Vec<Output>> {
        let body = self.get_json(&format!("/address/{address}/utxo")).await?;
        let list = body.as_array().ok_or(ChainError::Unavailable)?;
        let outputs = list
            .iter()
            .map(|entry| {
                Some(Output {
                    txid: entry.get("txid")?.as_str()?.to_owned(),
                    vout: u32::try_from(entry.get("vout")?.as_u64()?).ok()?,
                    value: entry.get("value")?.as_u64().filter(|value| *value <= MAX_MONEY)?,
                    confirmed: entry.pointer("/status/confirmed")?.as_bool()?,
                    height: entry.pointer("/status/block_height").and_then(Value::as_u64),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(ChainError::Unavailable)?;
        Ok(outputs.into_iter().filter(|output| output.value > 0).collect())
    }

    /// The three rates, in satoshis per thousand virtual bytes: slow, normal, fast, each judged on
    /// its own.
    ///
    /// Read from both services (they are two operators) and believed where they are within a
    /// factor of three of each other, taking the higher; from one alone only up to
    /// 100 sat/vB; never above 1,000 sat/vB whoever says so (a reading past that is set aside as if it
    /// had not come). A speed that fails these is left out, not the whole reading: in extreme
    /// congestion the slow rates are still there when the fast one is past the ceiling. The normal
    /// one is the one a send needs, so without it the answer is why not ("above the most this wallet will
    /// pay", or "could not be confirmed").
    pub async fn rates(&self) -> ChainResult<Rates> {
        let answers = self.net.get_many(Need::ANY.independent(), 2, "/fee-estimates").await?;
        let readings: Vec<[u64; 3]> = answers
            .into_iter()
            .filter(|((status, _), _)| (200..300).contains(status))
            .filter_map(|((_, body), _)| {
                // Esplora writes satoshis a virtual byte as decimals, read here as the text
                // they are: `0.131` is 131 satoshis a thousand bytes.
                let estimates: std::collections::BTreeMap<
                    String,
                    Box<serde_json::value::RawValue>,
                > = serde_json::from_slice(&body).ok()?;
                let estimates =
                    estimates.into_iter().map(|(t, r)| (t, r.get().to_owned())).collect();
                rates_from(&estimates)
            })
            .collect();
        if readings.is_empty() {
            return Err(ChainError::Unavailable);
        }
        let mut rates = Rates { kvb: [0; 3], ok: [false; 3], sources: [0; 3] };
        let (mut over, mut unconfirmed) = (false, false);
        for speed in 0..3 {
            let all: Vec<u128> = readings.iter().map(|r| u128::from(r[speed])).collect();
            let usable: Vec<u128> =
                all.iter().copied().filter(|v| limits::BITCOIN_RATE_KVB.allows(*v)).collect();
            let shown = |v: u128| u64::try_from(v).unwrap_or(u64::MAX);
            if usable.is_empty() {
                rates.kvb[speed] = shown(all.iter().copied().max().unwrap_or(0));
                over = true;
                continue;
            }
            match decide(Kind::Rate, &usable) {
                Some((value, sources)) if limits::BITCOIN_RATE_KVB.trusts(value, sources) => {
                    rates.kvb[speed] = shown(value);
                    rates.ok[speed] = true;
                    rates.sources[speed] = sources;
                }
                other => {
                    rates.kvb[speed] = shown(
                        other.map_or_else(|| usable.iter().copied().max().unwrap_or(0), |(v, _)| v),
                    );
                    unconfirmed = true;
                }
            }
        }
        if !rates.ok[1] {
            return Err(if over && !unconfirmed {
                ChainError::OverCeiling(
                    "the fee rate the network quotes is above the most this wallet will pay"
                        .to_owned(),
                )
            } else {
                unconfirmed_error("fee rate")
            });
        }
        Ok(rates)
    }

    /// The balance of the account: the sum over every address of it that holds coins, found by
    /// looking (see [`discovery`]). The answer carries the hint to keep for the next reading.
    pub async fn balances(&self, account: &Account, as_of: &str) -> ChainResult<Value> {
        let reading =
            self.read_account(&account.zpub, account.hint.as_ref(), account.now_s).await?;
        let (mut confirmed, mut waiting) = (0_i128, 0_i128);
        for held in &reading.held {
            confirmed += held.confirmed;
            waiting += held.waiting;
        }
        let total = u128::try_from(confirmed + waiting).unwrap_or(0);
        let mut entry = native_entry(Network::Bitcoin, total);
        entry["confirmed"] = json!(confirmed.max(0).to_string());
        entry["unconfirmed"] = json!(waiting.to_string());
        let mut body = balances_body(Network::Bitcoin, &account.shown, &[entry], as_of);
        body["bitcoin"] = reading_json(&reading);
        Ok(body)
    }

    /// The outputs of every address that holds coins, the next change address, and the fee rates.
    /// `own` holds the ids of the transactions this device sent (and the network took), lately: an
    /// unconfirmed output is marked `own` only then, and only an own one is ever spent unconfirmed.
    pub async fn inputs(
        &self,
        account: &Account,
        own: &std::collections::HashSet<String>,
    ) -> ChainResult<Value> {
        let reading =
            self.read_account(&account.zpub, account.hint.as_ref(), account.now_s).await?;
        let (listed, rates, tip) =
            futures::join!(self.outputs_of(&reading), self.rates(), self.tip());
        let (rates, tip) = (rates?, tip?);
        let mut utxos = listed?;
        // The largest first; the same order every time.
        utxos.sort_by(|a, b| {
            b.1.value
                .cmp(&a.1.value)
                .then_with(|| a.1.txid.cmp(&b.1.txid))
                .then(a.1.vout.cmp(&b.1.vout))
        });
        let truncated = utxos.len() > MAX_UTXOS;
        utxos.truncate(MAX_UTXOS);
        let utxos: Vec<Value> = utxos
            .iter()
            .map(|(held, output)| {
                let height = output.height.filter(|_| output.confirmed);
                json!({
                    "txid": output.txid,
                    "vout": output.vout,
                    "value": output.value.to_string(),
                    "address": held.address,
                    "chain": u32::from(held.chain == Chain::Change),
                    "index": held.index,
                    "confirmed": output.confirmed,
                    // Money that is not confirmed yet is spent only if this device made it (its own
                    // change); a transaction from outside can be replaced, and then the payment fails.
                    "own": own.contains(&output.txid.to_ascii_lowercase()),
                    "confirmations": height.map_or(0, |h| tip.saturating_sub(h).saturating_add(1)),
                    "block": height,
                })
            })
            .collect();
        let rate = |kvb: u64| json!({ "sat_per_vb": from_thousandths(kvb), "sat_per_kvb": kvb.to_string() });
        let mut fee_rates = serde_json::Map::new();
        for (index, name) in ["slow", "normal", "fast"].into_iter().enumerate() {
            if rates.ok[index] {
                fee_rates.insert(name.to_owned(), rate(rates.kvb[index]));
            }
        }
        let next = reading.hint.next_change();
        let change = addresses_from_zpub(&account.zpub, Chain::Change, next, 1)
            .and_then(|mut list| list.pop())
            .ok_or_else(|| ChainError::invalid("the account key is not a zpub"))?;
        Ok(json!({
            "network": "bitcoin",
            "address": account.shown,
            "utxos": utxos,
            "truncated": truncated,
            // Where the change goes: the first change address nothing has used.
            "change": { "chain": 1, "index": next, "address": change },
            // Only the speeds that are fit to use: a speed past the ceiling is not offered.
            "fee_rates": fee_rates,
            "block": tip,
            "bitcoin": reading_json(&reading),
        }))
    }

    /// The unspent outputs of the addresses a reading found holding coins.
    async fn outputs_of(&self, reading: &Reading) -> ChainResult<Vec<(Held, Output)>> {
        let lists = futures::future::join_all(
            reading
                .held
                .iter()
                .map(|held| async move { (held.clone(), self.outputs_at(&held.address).await) }),
        )
        .await;
        let mut all = Vec::new();
        for (held, outputs) in lists {
            for output in outputs? {
                all.push((held.clone(), output));
            }
        }
        Ok(all)
    }

    /// The fee at each speed for a payment of `amount`, spending the wallet's
    /// outputs largest first.
    pub async fn estimate(
        &self,
        account: &Account,
        args: &EstimateArgs,
        own: &std::collections::HashSet<String>,
    ) -> ChainResult<Value> {
        let to = address::parse(Network::Bitcoin, &args.to)
            .map_err(|_| ChainError::InvalidAddress("to is not a valid address".to_owned()))?;
        let to_script = to.script()?.to_vec();
        let dust = dust_limit(&to_script);
        let amount =
            u64::try_from(args.amount).map_err(|_| ChainError::invalid("amount is too large"))?;
        if amount < dust {
            return Err(ChainError::EstimateFailed(format!(
                "the amount is below the {dust}-satoshi dust limit for that address"
            )));
        }
        let reading =
            self.read_account(&account.zpub, account.hint.as_ref(), account.now_s).await?;
        let (listed, rates) = futures::join!(self.outputs_of(&reading), self.rates());
        let rates = rates?;
        let mut values: Vec<u64> = Vec::new();
        for (held, output) in listed? {
            // What the signer spends and nothing else: money paid in from outside is not spent
            // until it is confirmed (the receive chain); the wallet's own unconfirmed change is, and
            // only what this device sent (a transaction from outside can be replaced).
            if output.confirmed
                || (held.chain == Chain::Change && own.contains(&output.txid.to_ascii_lowercase()))
            {
                values.push(output.value);
            }
        }

        // A P2WPKH change output, which is what the wallet's change is.
        let change_script = [&[0x00_u8, 0x14][..], &[0_u8; 20][..]].concat();
        // What the signing engine's planner makes of these coins at each rate, by the very same rule
        // (`quote`): the fee shown here is the fee signed.
        let mut fees = serde_json::Map::new();
        let mut normal = None;
        for (index, name) in ["slow", "normal", "fast"].into_iter().enumerate() {
            let kvb = rates.kvb[index];
            let rate = FeeRate::from_sat_per_kvb(kvb);
            let quoted =
                rates.ok[index].then(|| quote(&values, amount, rate, &to_script, &change_script));
            let entry = match &quoted {
                Some(Ok(quoted)) => json!({
                    "sat_per_vb": from_thousandths(kvb),
                    "vsize": quoted.vsize.to_string(),
                    "inputs": quoted.inputs,
                    "fee": quoted.fee.to_string(),
                }),
                _ => {
                    json!({ "sat_per_vb": from_thousandths(kvb), "vsize": null, "inputs": null, "fee": null })
                }
            };
            if name == "normal" {
                normal = quoted;
            }
            fees.insert(name.to_owned(), entry);
        }
        let normal_fee = match normal {
            Some(Ok(quoted)) => quoted.fee,
            Some(Err(TxError::InsufficientFunds { .. })) | None => {
                return Err(ChainError::InsufficientFunds(
                    "the wallet's outputs do not cover the amount and the fee".to_owned(),
                ));
            }
            Some(Err(other)) => return Err(ChainError::EstimateFailed(other.to_string())),
        };
        Figure { value: u128::from(normal_fee), sources: rates.sources[1] }
            .within(limits::BITCOIN_TOTAL, "network fee")?;
        Ok(json!({
            "network": "bitcoin",
            "fees": Value::Object(fees),
            "fee": fee_value(Network::Bitcoin.native(), u128::from(normal_fee)),
            "recipient": { "valid": true },
            "bitcoin": reading_json(&reading),
        }))
    }

    /// Sends a signed transaction to both services at once.
    pub async fn broadcast(&self, raw: &[u8], txid: &str) -> ChainResult<String> {
        let body = hex::encode(raw);
        let answers =
            self.net.post_many(Need::ANY, 2, "/tx", "text/plain", body.as_bytes()).await?;
        let mut accepted = false;
        let mut verdict: Option<ChainError> = None;
        for ((status, text), _) in answers {
            if (200..300).contains(&status) {
                accepted = true;
                continue;
            }
            let text = String::from_utf8_lossy(&text);
            let error = refusal(&text, txid);
            // "Already known" next to an acceptance is the first service's
            // work reaching the second.
            if matches!(error, ChainError::Duplicate { .. })
                || !matches!(verdict, Some(ChainError::Duplicate { .. }))
            {
                verdict = Some(error);
            }
        }
        if accepted || matches!(verdict, Some(ChainError::Duplicate { .. })) {
            return Ok(txid.to_owned());
        }
        Err(verdict.unwrap_or(ChainError::Unavailable))
    }

    /// Where a transaction stands.
    pub async fn status(&self, txid: &str) -> ChainResult<Value> {
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ChainError::invalid("that is not a transaction id"));
        }
        let (status, body) = self.net.get(Need::ANY, &format!("/tx/{txid}/status")).await?;
        if status == 404 {
            return Ok(json!({ "status": "not_found" }));
        }
        if !(200..300).contains(&status) {
            return Err(ChainError::Unavailable);
        }
        let body = parse_json(&body)?;
        if body.get("confirmed").and_then(Value::as_bool) != Some(true) {
            return Ok(json!({ "status": "pending", "confirmations": 0 }));
        }
        let height = body.get("block_height").and_then(Value::as_u64);
        let tip = self.tip().await.ok();
        Ok(json!({
            "status": "confirmed",
            "block": height,
            "confirmations": height.zip(tip).map(|(h, t)| t.saturating_sub(h).saturating_add(1)),
        }))
    }
}

/// Slow aims at about 12 blocks, normal at 3, fast at the next: the nearest
/// target Esplora has at or beyond each, and never below the relay minimum.
/// `estimates` are decimals as written, satoshis a virtual byte by target.
fn rates_from(estimates: &std::collections::BTreeMap<String, String>) -> Option<[u64; 3]> {
    let by_target: std::collections::BTreeMap<u32, u64> = estimates
        .iter()
        .filter_map(|(target, rate)| Some((target.parse().ok()?, thousandths(rate)?)))
        .collect();
    let rate = |wanted: u32| -> Option<u64> {
        let (_, kvb) = by_target.range(wanted..).next().or_else(|| by_target.iter().next_back())?;
        // Nothing the relay minimum would refuse. (Whether it is too high to pay is judged by the caller.)
        Some((*kvb).max(MIN_RATE_KVB))
    };
    let (slow, normal, fast) = (rate(12)?, rate(3)?, rate(1)?);
    // A slower target is never dearer.
    let normal = normal.min(fast).max(slow.min(normal));
    Some([slow.min(normal), normal, fast.max(normal)])
}

/// A node's refusal of a transaction, as the code that fits it. Esplora hands
/// on the node's words (`sendrawtransaction RPC error: {"code":-26,...}`).
fn refusal(message: &str, txid: &str) -> ChainError {
    let lower = message.to_ascii_lowercase();
    let has = |phrases: &[&str]| phrases.iter().any(|p| lower.contains(p));
    if has(&[
        "already in mempool",
        "already-in-mempool",
        "already known",
        "txn-already-known",
        "already in block chain",
        "already in the block chain",
        "txn-already-in-mempool",
        "transaction outputs already in utxo set",
    ]) {
        ChainError::Duplicate { hash: txid.to_owned() }
    } else if has(&[
        "fee not met",
        "insufficient fee",
        "min relay fee",
        "fee too low",
        "rejecting replacement",
        "mempool min fee",
    ]) {
        ChainError::InsufficientFee(
            "the fee is below what the Bitcoin network relays now".to_owned(),
        )
    } else if has(&["bad-txns-in-belowout", "insufficient funds"]) {
        ChainError::InsufficientFunds("the inputs do not cover the outputs and the fee".to_owned())
    } else if has(&[
        "inputs-missingorspent",
        "missing inputs",
        "missing-inputs",
        "bad-txns-inputs-missingorspent",
    ]) {
        ChainError::Rejected(
            "an output the transaction spends is spent already, or the node does not know it"
                .to_owned(),
        )
    } else if has(&["mempool-conflict", "txn-mempool-conflict"]) {
        ChainError::Rejected(
            "it conflicts with a transaction already waiting for a block".to_owned(),
        )
    } else if has(&["non-final", "bip68"]) {
        ChainError::Expired("the transaction is not final yet".to_owned())
    } else {
        ChainError::Rejected(REFUSED.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn estimates(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(t, r)| ((*t).to_owned(), (*r).to_owned())).collect()
    }

    #[test]
    fn rates_come_from_the_nearest_target_and_never_below_the_relay_minimum() {
        let rates = rates_from(&estimates(&[
            ("1", "5.5"),
            ("2", "4.25"),
            ("3", "3"),
            ("6", "2"),
            ("12", "1.2"),
            ("144", "0.131"),
        ]));
        assert_eq!(rates, Some([1_200, 3_000, 5_500]));
        // An empty mempool: every rate is the minimum.
        let calm = rates_from(&estimates(&[("1", "0.131"), ("3", "0.131"), ("12", "0.131")]));
        assert_eq!(calm, Some([1_000, 1_000, 1_000]));
        assert_eq!(rates_from(&estimates(&[])), None);
        assert_eq!(rates_from(&estimates(&[("1", "abc")])), None);
        // An absurd rate is read as it is: whether it is too high to pay is judged where it is used.
        assert_eq!(
            rates_from(&estimates(&[("1", "999999999")])),
            Some([999_999_999_000, 999_999_999_000, 999_999_999_000])
        );
    }

    #[test]
    fn a_slower_target_is_never_dearer() {
        let rates = rates_from(&estimates(&[("1", "2"), ("3", "9"), ("12", "5")])).unwrap();
        assert!(rates[0] <= rates[1] && rates[1] <= rates[2], "{rates:?}");
    }

    #[test]
    fn a_nodes_refusal_is_told_by_its_words() {
        let hash = "ab".repeat(32);
        let case = |text: &str| refusal(text, &hash).code();
        assert_eq!(
            case(
                "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction already in block chain\"}"
            ),
            "duplicate"
        );
        assert_eq!(
            case(
                "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"txn-already-in-mempool\"}"
            ),
            "duplicate"
        );
        assert_eq!(case("min relay fee not met, 110 < 141"), "insufficient_fee");
        assert_eq!(case("bad-txns-inputs-missingorspent"), "rejected");
        assert_eq!(
            case("bad-txns-in-belowout, value in (0.1) < value out (0.2)"),
            "insufficient_funds"
        );
        assert_eq!(case("non-BIP68-final"), "expired");
        assert_eq!(case("scriptpubkey"), "rejected");
    }
}
