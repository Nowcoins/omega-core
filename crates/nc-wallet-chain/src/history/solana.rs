//! Solana, from the network's own RPC: `getSignaturesForAddress` lists the
//! account's transactions newest first, and `getTransaction` says what each did.
//!
//! What a transaction did to the account is read from the balances it left, not
//! from its instructions: whichever program moved the coin (a plain transfer, a
//! swap, a staking payout), the SOL and the listed tokens the account held
//! before and after say what happened to it. The rent a transaction paid to open
//! a token account for someone else shows as SOL the account sent, because it
//! was.
//!
//! Each `getTransaction` is a request that public endpoints ration, so the
//! signatures are listed 25 at a time and read a few at a time within the call's
//! budget; the ones not read yet wait in the state (`pending`) for the next
//! call. The newest are always read first.

use std::collections::HashMap;

use serde_json::{Value, json};

use super::store::{Direction, Item, Kind, State, Status};
use super::{Budget, Coverage, Cx};
use crate::error::{ChainError, ChainResult};
use crate::networks::Network;
use crate::pool::Need;

/// Signatures listed at once.
const LIST: usize = 25;
/// Transactions read side by side.
const AT_ONCE: u32 = 4;
/// Version-0 (address lookup table) transactions are read.
const MAX_VERSION: u8 = 0;

/// Where the reading stands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Place {
    /// The newest signature listed.
    top: Option<String>,
    /// The oldest signature listed.
    tail: Option<String>,
    /// Whether the oldest signature has been listed.
    done: bool,
    /// Signatures listed and not read yet, newest first.
    pending: Vec<String>,
}

fn place_of(st: &State) -> Place {
    let Some(s) = st.src.get("sol") else { return Place::default() };
    let t = |k: &str| s.get(k).and_then(Value::as_str).map(str::to_owned);
    Place {
        top: t("top"),
        tail: t("tail"),
        done: s.get("done").and_then(Value::as_bool) == Some(true),
        pending: s
            .get("pending")
            .and_then(Value::as_array)
            .map(|l| l.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
            .unwrap_or_default(),
    }
}

fn put_place(st: &mut State, p: &Place) {
    let mut src = st.src.as_object().cloned().unwrap_or_default();
    src.insert(
        "sol".into(),
        json!({ "top": p.top, "tail": p.tail, "done": p.done, "pending": p.pending }),
    );
    st.src = Value::Object(src);
}

/// The signatures of `getSignaturesForAddress`, newest first. `before` and
/// `until` bound the listing (neither included).
async fn signatures(
    cx: &Cx<'_>,
    b: &mut Budget,
    before: Option<&str>,
    until: Option<&str>,
) -> ChainResult<Vec<String>> {
    if !b.take(cx.net.now()) {
        return Err(ChainError::Busy { retry_after_seconds: 1 });
    }
    let mut options = json!({ "limit": LIST, "commitment": "confirmed" });
    if let Some(before) = before {
        options["before"] = json!(before);
    }
    if let Some(until) = until {
        options["until"] = json!(until);
    }
    let params = json!([cx.req.address.text, options]);
    let answer = cx
        .net
        .rpc(Need::method("getSignaturesForAddress"), "getSignaturesForAddress", &params)
        .await?
        .map_err(|_| ChainError::Unavailable)?;
    let list = answer.as_array().ok_or(ChainError::Unavailable)?;
    Ok(list
        .iter()
        .filter_map(|s| s.get("signature").and_then(Value::as_str).map(str::to_owned))
        .collect())
}

/// Reads the transactions waiting, a few at a time, as many as the budget gives.
async fn read_pending(
    cx: &Cx<'_>,
    b: &mut Budget,
    st: &mut State,
    p: &mut Place,
) -> ChainResult<()> {
    while !p.pending.is_empty() {
        let granted = b.take_up_to(
            AT_ONCE.min(u32::try_from(p.pending.len()).unwrap_or(AT_ONCE)),
            cx.net.now(),
        );
        if granted == 0 {
            return Ok(());
        }
        let batch: Vec<String> = p.pending.iter().take(granted as usize).cloned().collect();
        let me = cx.req.address.text.clone();
        let reads = futures::future::join_all(batch.iter().map(|sig| async move {
            let params = json!([sig, {
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": MAX_VERSION,
                "commitment": "confirmed",
            }]);
            cx.net
                .rpc(Need::method("getTransaction"), "getTransaction", &params)
                .await
                .map(Result::ok)
        }))
        .await;
        let mut done = 0;
        let mut failure = None;
        for (sig, read) in batch.iter().zip(reads) {
            match read {
                // Not found: nothing to show.
                Ok(Some(tx)) if tx.is_null() => done += 1,
                Ok(Some(tx)) => {
                    st.merge(items_in(&tx, sig, &me));
                    done += 1;
                }
                Ok(None) => done += 1,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        st.fee_once_per_hash();
        p.pending.drain(..done);
        if let Some(e) = failure {
            return Err(e);
        }
    }
    Ok(())
}

/// A balance change of one account.
struct Change {
    owner: String,
    delta: i128,
}

/// What a `getTransaction` (jsonParsed) did to `me`.
pub(super) fn items_in(tx: &Value, signature: &str, me: &str) -> Vec<Item> {
    let (Some(meta), Some(message)) = (tx.get("meta"), tx.pointer("/transaction/message")) else {
        return Vec::new();
    };
    let Some(time) = tx.get("blockTime").and_then(Value::as_u64) else { return Vec::new() };
    let slot = tx.get("slot").and_then(Value::as_u64);
    let failed = meta.get("err").is_some_and(|e| !e.is_null());
    let fee: u128 = meta.get("fee").and_then(Value::as_u64).map_or(0, u128::from);
    let native = Network::Solana.native();

    let mut keys: Vec<String> = message
        .get("accountKeys")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|k| {
                    k.get("pubkey")
                        .and_then(Value::as_str)
                        .or_else(|| k.as_str())
                        .unwrap_or_default()
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default();
    let balances = |name: &str| -> Vec<i128> {
        meta.get(name)
            .and_then(Value::as_array)
            .map(|l| l.iter().map(|v| v.as_i64().map_or(0, i128::from)).collect())
            .unwrap_or_default()
    };
    let (before, after) = (balances("preBalances"), balances("postBalances"));
    if keys.len() < before.len() {
        // A version-0 transaction's looked-up accounts follow the rest.
        for kind in ["writable", "readonly"] {
            if let Some(loaded) =
                meta.pointer(&format!("/loadedAddresses/{kind}")).and_then(Value::as_array)
            {
                keys.extend(loaded.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
    }
    let paid = keys.first().map(String::as_str) == Some(me);
    let make = |n: usize,
                kind: Kind,
                dir: Direction,
                asset: &str,
                contract: Option<&str>,
                amount: u128,
                decimals: u8,
                peer: Option<String>| {
        let mut item =
            Item::new(format!("{signature}:{n}"), signature.to_owned(), time, dir, asset);
        item.kind = kind;
        item.order = slot.unwrap_or(0);
        item.contract = contract.map(str::to_owned);
        item.amount = amount;
        item.decimals = decimals;
        item.counterparty = peer;
        item.status = if failed { Status::Failed } else { Status::Confirmed };
        item.block = slot;
        item
    };

    let mut items: Vec<Item> = Vec::new();
    if !failed {
        // SOL: what the account gained or lost, the fee it paid set aside.
        let mut others: Vec<Change> = Vec::new();
        let mut mine = 0_i128;
        for (index, key) in keys.iter().enumerate() {
            let (Some(b), Some(a)) = (before.get(index), after.get(index)) else { continue };
            let mut delta = a - b;
            if index == 0 {
                delta += i128::try_from(fee).unwrap_or(0);
            }
            if key == me {
                mine = delta;
            } else {
                others.push(Change { owner: key.clone(), delta });
            }
        }
        if mine != 0 {
            let sign = mine.signum();
            let peer = others
                .iter()
                .filter(|c| c.delta.signum() == -sign)
                .max_by_key(|c| c.delta.abs())
                .map(|c| c.owner.clone());
            let dir = if sign > 0 { Direction::In } else { Direction::Out };
            items.push(make(
                items.len(),
                Kind::Transfer,
                dir,
                native.symbol,
                None,
                mine.unsigned_abs(),
                native.decimals,
                peer,
            ));
        }

        // Tokens: the listed mints, summed over the owner's token accounts.
        let mut by_mint: HashMap<String, (i128, Vec<Change>)> = HashMap::new();
        for (name, sign) in [("preTokenBalances", -1_i128), ("postTokenBalances", 1)] {
            for entry in meta.get(name).and_then(Value::as_array).into_iter().flatten() {
                let (Some(mint), Some(owner)) = (
                    entry.get("mint").and_then(Value::as_str),
                    entry.get("owner").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if Network::Solana.token_by_contract(mint).is_none() {
                    continue;
                }
                // A token amount is digits and no more than thirty of them (a supply of 10^30 base units is
                // beyond any listed token), whatever the node writes: sums of these cannot overflow.
                let amount: i128 = entry
                    .pointer("/uiTokenAmount/amount")
                    .and_then(Value::as_str)
                    .filter(|t| t.len() <= 30 && t.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0);
                let slot = by_mint.entry(mint.to_owned()).or_default();
                if owner == me {
                    slot.0 += sign * amount;
                } else {
                    slot.1.push(Change { owner: owner.to_owned(), delta: sign * amount });
                }
            }
        }
        let mut mints: Vec<_> = by_mint.into_iter().collect();
        mints.sort_by(|a, b| a.0.cmp(&b.0));
        for (mint, (delta, others)) in mints {
            if delta == 0 {
                continue;
            }
            let Some(token) = Network::Solana.token_by_contract(&mint) else { continue };
            let sign = delta.signum();
            // Several accounts of one owner add up before they are compared.
            let mut per_owner: HashMap<&str, i128> = HashMap::new();
            for c in &others {
                *per_owner.entry(c.owner.as_str()).or_default() += c.delta;
            }
            let peer = per_owner
                .into_iter()
                .filter(|(_, d)| d.signum() == -sign)
                .max_by(|a, b| a.1.abs().cmp(&b.1.abs()).then_with(|| b.0.cmp(a.0)))
                .map(|(o, _)| o.to_owned());
            let dir = if sign > 0 { Direction::In } else { Direction::Out };
            items.push(make(
                items.len(),
                Kind::Transfer,
                dir,
                token.symbol,
                Some(token.contract),
                delta.unsigned_abs(),
                token.decimals,
                peer,
            ));
        }
    }
    // Nothing of a listed asset moved, but the account paid: a call.
    if items.is_empty() && paid {
        items.push(make(
            0,
            Kind::Call,
            Direction::Out,
            native.symbol,
            None,
            0,
            native.decimals,
            None,
        ));
    }
    // The fee the account paid rides on the first item.
    if paid && let Some(first) = items.first_mut() {
        first.fee = Some(fee);
    }
    items
}

/// Lists what is newer than the newest signature known (the newest page, if none
/// is), and reads what is waiting.
pub(super) async fn update(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let mut p = place_of(st);
    let result = async {
        if p.top.is_none() {
            let list = signatures(cx, b, None, None).await?;
            p.top = list.first().cloned();
            p.tail = list.last().cloned();
            p.done = list.len() < LIST;
            p.pending = list;
        } else {
            // Newer than the top, a page at a time, back to what was listed.
            let mut fresh: Vec<String> = Vec::new();
            let mut before: Option<String> = None;
            loop {
                let list = signatures(cx, b, before.as_deref(), p.top.as_deref()).await?;
                let full = list.len() >= LIST;
                before = list.last().cloned();
                fresh.extend(list);
                if !full || !b.any() {
                    break;
                }
            }
            if let Some(newest) = fresh.first() {
                p.top = Some(newest.clone());
            }
            fresh.extend(std::mem::take(&mut p.pending));
            p.pending = fresh;
        }
        read_pending(cx, b, st, &mut p).await
    }
    .await;
    put_place(st, &p);
    result
}

/// Reads what waits; when nothing does, lists the page before the oldest.
pub(super) async fn extend(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let mut p = place_of(st);
    let result = async {
        if p.pending.is_empty() && !p.done && p.tail.is_some() {
            let list = signatures(cx, b, p.tail.as_deref(), None).await?;
            if let Some(oldest) = list.last() {
                p.tail = Some(oldest.clone());
            }
            p.done = list.len() < LIST;
            p.pending = list;
        }
        read_pending(cx, b, st, &mut p).await
    }
    .await;
    put_place(st, &p);
    result
}

pub(super) fn coverage(st: &State) -> Coverage {
    let p = place_of(st);
    Coverage::single("full", p.done && p.pending.is_empty(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";
    const YOU: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn tx(
        keys: &[&str],
        pre: &[i64],
        post: &[i64],
        fee: u64,
        tokens: &Value,
        err: &Value,
    ) -> Value {
        json!({
            "slot": 77, "blockTime": 1_793_000_000,
            "transaction": { "message": { "accountKeys": keys.iter().map(|k| json!({ "pubkey": k })).collect::<Vec<_>>() } },
            "meta": { "err": err, "fee": fee, "preBalances": pre, "postBalances": post,
                      "preTokenBalances": tokens["pre"], "postTokenBalances": tokens["post"] },
        })
    }

    fn balance(owner: &str, amount: &str) -> Value {
        json!({ "mint": USDC, "owner": owner, "uiTokenAmount": { "amount": amount } })
    }

    #[test]
    fn sol_sent_is_what_left_without_the_fee_and_the_fee_rides_on_it() {
        // ME pays: 1 SOL to YOU and a fee of 5,000.
        let t = tx(
            &[ME, YOU],
            &[5_000_000_000, 0],
            &[3_999_995_000, 1_000_000_000],
            5_000,
            &json!({}),
            &Value::Null,
        );
        let items = items_in(&t, "sig", ME);
        assert_eq!(items.len(), 1);
        let i = &items[0];
        assert_eq!(
            (i.direction, i.amount, i.fee, i.asset.as_str()),
            (Direction::Out, 1_000_000_000, Some(5_000), "SOL")
        );
        assert_eq!(
            (i.counterparty.as_deref(), i.block, i.time),
            (Some(YOU), Some(77), 1_793_000_000)
        );
    }

    #[test]
    fn sol_received_costs_nothing_and_a_token_is_the_listed_mints_change_over_the_owners_accounts()
    {
        let received = tx(
            &[YOU, ME],
            &[9_000_000_000, 0],
            &[7_999_995_000, 1_000_000_000],
            5_000,
            &json!({}),
            &Value::Null,
        );
        let i = &items_in(&received, "sig", ME)[0];
        assert_eq!((i.direction, i.amount, i.fee), (Direction::In, 1_000_000_000, None));
        // USDC: YOU's account fell by 12, ME's rose by 12.
        let tokens = json!({
            "pre": [balance(YOU, "20000000"), balance(ME, "1000000")],
            "post": [balance(YOU, "8000000"), balance(ME, "13000000")],
        });
        let t =
            tx(&[YOU, ME], &[9_000_000_000, 5], &[8_999_995_000, 5], 5_000, &tokens, &Value::Null);
        let items = items_in(&t, "sig", ME);
        assert_eq!(items.len(), 1, "the SOL did not move");
        let i = &items[0];
        assert_eq!(
            (i.direction, i.asset.as_str(), i.amount, i.contract.as_deref()),
            (Direction::In, "USDC", 12_000_000, Some(USDC))
        );
        assert_eq!(i.counterparty.as_deref(), Some(YOU));
    }

    #[test]
    fn a_failed_transaction_the_account_paid_for_is_a_call_with_its_fee_and_others_show_nothing() {
        let failed = tx(
            &[ME, YOU],
            &[100, 0],
            &[95, 0],
            5,
            &json!({}),
            &json!({ "InstructionError": [0, "Custom"] }),
        );
        let i = &items_in(&failed, "sig", ME)[0];
        assert_eq!((i.kind, i.status, i.amount, i.fee), (Kind::Call, Status::Failed, 0, Some(5)));
        assert!(items_in(&failed, "sig", "SomeoneElse1111111111111111111111111111111").is_empty());
    }

    #[test]
    fn a_swap_is_two_items_and_the_fee_is_on_the_first() {
        let tokens = json!({ "pre": [balance(ME, "50000000")], "post": [balance(ME, "0")] });
        // SOL in, USDC out, in one transaction ME did not pay for.
        let t = tx(
            &[YOU, ME],
            &[9_000_000_000, 1_000],
            &[7_000_000_000, 2_000_001_000],
            5_000,
            &tokens,
            &Value::Null,
        );
        let items = items_in(&t, "sig", ME);
        assert_eq!(items.len(), 2);
        assert_eq!((items[0].asset.as_str(), items[0].direction), ("SOL", Direction::In));
        assert_eq!(
            (items[1].asset.as_str(), items[1].direction, items[1].amount),
            ("USDC", Direction::Out, 50_000_000)
        );
        assert_eq!((items[0].fee, items[1].fee), (None, None), "someone else paid it");
        assert_ne!(items[0].id, items[1].id);
    }
}

#[cfg(test)]
mod hostile {
    use super::*;

    const ME: &str = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    #[test]
    fn amounts_a_node_makes_up_never_panic() {
        // The one that made `-1 * amount` overflow, the largest of every width, and not numbers at all.
        let made_up = [
            "-170141183460469231731687303715884105728",
            "170141183460469231731687303715884105727",
            "340282366920938463463374607431768211455",
            "99999999999999999999999999999999999999999999",
            "999999999999999999999999999999",
            "-1",
            "1e30",
            "",
        ];
        for pre in made_up {
            for post in made_up {
                let entry = |owner: &str, amount: &str| json!({ "mint": USDC, "owner": owner, "uiTokenAmount": { "amount": amount } });
                let t = json!({
                    "slot": u64::MAX, "blockTime": u64::MAX,
                    "transaction": { "message": { "accountKeys": [{ "pubkey": ME }, { "pubkey": "x" }] } },
                    "meta": {
                        "err": null, "fee": u64::MAX,
                        "preBalances": [i64::MIN, i64::MAX], "postBalances": [i64::MAX, i64::MIN],
                        "preTokenBalances": [entry(ME, pre), entry("x", post), entry("y", pre)],
                        "postTokenBalances": [entry(ME, post), entry("x", pre), entry("y", post)],
                    },
                });
                for item in items_in(&t, "sig", ME) {
                    // Nothing past what a listed token could be is kept.
                    assert!(item.amount <= u128::MAX / 2 || item.asset == "SOL", "{pre} {post}");
                }
            }
        }
    }
}
