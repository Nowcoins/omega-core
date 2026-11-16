//! TRON, from TronGrid (keyless): `/v1/accounts/{address}/transactions` (TRX and
//! every contract call) and `/v1/accounts/{address}/transactions/trc20` (token
//! transfers), each newest first and asked between two times.
//!
//! * **Two lists, one history.** Each list has its own place (`top`, the newest
//!   time read; `tail`, the oldest; `done`). Items older than the oldest page of
//!   a list not yet fully read are held back (`floor`), so that what is listed
//!   is a whole recent stretch, and a token transfer's fee, which sits on its
//!   call in the other list, is attached when both are there.
//! * **Only confirmed** transactions are listed, which is TronGrid's default; a
//!   just-sent one appears about a minute after it is mined, and the app shows
//!   its note until then.
//! * A transfer of a token the network does not list is not shown, though the
//!   call that made it is, as a `call` with its fee when the account sent it.
//! * TronGrid is the one keyless source of this API; the other TRON endpoints do
//!   not have it (`Need::TRON_V1`), and it allows about three requests a second.

use std::collections::HashSet;

use serde_json::{Value, json};

use super::store::{Direction, Item, Kind, State, Status};
use super::{Budget, Coverage, Cx, get_json_from};
use crate::error::ChainResult;
use crate::networks::Network;
use crate::pool::Need;
use nc_wallet_core::tron::{format_address, parse_address};

/// How many records one request asks for.
const LIST: usize = 100;

/// A TronGrid answer: `data` is a list.
fn is_list(v: &Value) -> bool {
    v.get("data").is_some_and(Value::is_array)
        && v.get("success").and_then(Value::as_bool) != Some(false)
}

/// Where one list stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct List {
    /// The newest time (ms) read.
    top: Option<u64>,
    /// The oldest time (ms) read.
    tail: Option<u64>,
    /// Whether the oldest record has been read.
    done: bool,
    /// Catching up to `top`: read back from this time, and the newest of the run.
    catch: Option<(u64, u64)>,
}

fn list_of(st: &State, key: &str) -> List {
    let Some(l) = st.src.get("tron").and_then(|t| t.get(key)) else { return List::default() };
    let n = |k: &str| l.get(k).and_then(Value::as_u64);
    List {
        top: n("top"),
        tail: n("tail"),
        done: l.get("done").and_then(Value::as_bool) == Some(true),
        catch: n("cm").zip(n("cn")),
    }
}

fn put_list(st: &mut State, key: &str, l: List) {
    let mut src = st.src.as_object().cloned().unwrap_or_default();
    let mut tron = src.get("tron").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut o = json!({});
    if let Some(v) = l.top {
        o["top"] = json!(v);
    }
    if let Some(v) = l.tail {
        o["tail"] = json!(v);
    }
    if l.done {
        o["done"] = json!(true);
    }
    if let Some((m, n)) = l.catch {
        o["cm"] = json!(m);
        o["cn"] = json!(n);
    }
    tron.insert(key.into(), o);
    src.insert("tron".into(), Value::Object(tron));
    st.src = Value::Object(src);
}

/// A TRON address as the network writes it (`T…`) from base58 or the `41…` hex
/// the node's own records use.
fn written(text: &str) -> Option<String> {
    if parse_address(text).is_ok() {
        return Some(text.to_owned());
    }
    let bytes: [u8; 21] = hex::decode(text).ok()?.try_into().ok()?;
    Some(format_address(&bytes))
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn direction(sent: bool, got: bool) -> Direction {
    match (sent, got) {
        (true, true) => Direction::SelfSent,
        (true, false) => Direction::Out,
        _ => Direction::In,
    }
}

/// The items of a page of the native list.
fn native_items(records: &[Value], me: &str) -> Vec<Item> {
    let coin = Network::Tron.native();
    let mut out = Vec::new();
    for tx in records {
        let (Some(id), Some(ms)) =
            (text(tx, "txID"), tx.get("block_timestamp").and_then(Value::as_u64))
        else {
            continue;
        };
        let Some(contract) = tx.pointer("/raw_data/contract/0") else { continue };
        let value = contract.pointer("/parameter/value").unwrap_or(&Value::Null);
        let ret = tx.pointer("/ret/0");
        let paid = ret.and_then(|r| r.get("fee")).and_then(Value::as_u64).unwrap_or(0);
        let failed = ret
            .and_then(|r| text(r, "contractRet"))
            .is_some_and(|r| !r.is_empty() && r != "SUCCESS");
        let owner = text(value, "owner_address").and_then(written);
        let sent = owner.as_deref() == Some(me);
        let block = tx.get("blockNumber").and_then(Value::as_u64);
        let make = |kind: Kind, dir: Direction, amount: u128, peer: Option<String>| {
            let mut item = Item::new(format!("n:{id}"), id.to_owned(), ms / 1000, dir, coin.symbol);
            item.kind = kind;
            item.order = ms % 1000;
            item.amount = amount;
            item.decimals = coin.decimals;
            item.counterparty = peer;
            item.fee = sent.then_some(u128::from(paid));
            item.status = if failed { Status::Failed } else { Status::Confirmed };
            item.block = block;
            item
        };
        if text(contract, "type") == Some("TransferContract") {
            let to = text(value, "to_address").and_then(written);
            let amount = u128::from(value.get("amount").and_then(Value::as_u64).unwrap_or(0));
            let got = to.as_deref() == Some(me);
            if !(sent || got) {
                continue;
            }
            if amount > 0 && !failed {
                let peer = if sent && !got { to } else { owner };
                out.push(make(Kind::Transfer, direction(sent, got), amount, peer));
            } else if sent {
                out.push(make(Kind::Call, Direction::Out, 0, to));
            }
        } else if sent {
            // A contract call, a stake, a vote: it cost the account its fee.
            let to = text(value, "contract_address")
                .or_else(|| text(value, "receiver_address"))
                .and_then(written);
            out.push(make(Kind::Call, Direction::Out, 0, to));
        }
    }
    out
}

/// The items of a page of the TRC-20 list: the listed tokens only.
fn token_items(records: &[Value], me: &str) -> Vec<Item> {
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for t in records {
        let (Some(id), Some(ms)) =
            (text(t, "transaction_id"), t.get("block_timestamp").and_then(Value::as_u64))
        else {
            continue;
        };
        let Some(token) = t
            .pointer("/token_info/address")
            .and_then(Value::as_str)
            .and_then(|a| Network::Tron.token_by_contract(a))
        else {
            continue;
        };
        let (Some(from), Some(to)) = (text(t, "from"), text(t, "to")) else { continue };
        let Some(value) = text(t, "value").and_then(|v| v.parse::<u128>().ok()) else { continue };
        let (sent, got) = (from == me, to == me);
        if !(sent || got) {
            continue;
        }
        // Identical transfers in one transaction are told apart by their number.
        let key = format!("t:{id}:{from}:{to}:{value}");
        let n = seen.iter().filter(|k| **k == key).count();
        seen.push(key.clone());
        let mut item = Item::new(
            format!("{key}:{n}"),
            id.to_owned(),
            ms / 1000,
            direction(sent, got),
            token.symbol,
        );
        item.order = ms % 1000;
        item.contract = Some(token.contract.to_owned());
        item.amount = value;
        item.decimals = token.decimals;
        item.counterparty = Some(if sent && !got { to.to_owned() } else { from.to_owned() });
        out.push(item);
    }
    out
}

/// A token transfer takes the fee of the call that made it, and the call, which
/// said no more than that, goes. A call the account sent that made no listed
/// transfer stays, with its fee.
fn reconcile(st: &mut State) {
    let with_tokens: HashSet<String> =
        st.items.iter().filter(|i| i.id.starts_with("t:")).map(|i| i.hash.clone()).collect();
    let calls: Vec<(String, Option<u128>)> = st
        .items
        .iter()
        .filter(|i| i.id.starts_with("n:") && i.kind == Kind::Call && with_tokens.contains(&i.hash))
        .map(|i| (i.hash.clone(), i.fee))
        .collect();
    for (hash, fee) in calls {
        let id = format!("n:{hash}");
        st.items.retain(|i| i.id != id);
        let mut first = true;
        for item in st.items.iter_mut().filter(|i| i.hash == hash && i.id.starts_with("t:")) {
            item.fee = if first && item.direction != Direction::In { fee } else { None };
            first = false;
        }
    }
}

fn query(me: &str, list: &str, min: Option<u64>, max: Option<u64>) -> String {
    let mut q =
        format!("/v1/accounts/{me}/transactions{list}?limit={LIST}&order_by=block_timestamp,desc");
    if let Some(min) = min {
        q = format!("{q}&min_timestamp={min}");
    }
    if let Some(max) = max {
        q = format!("{q}&max_timestamp={max}");
    }
    q
}

const LISTS: [(&str, &str); 2] = [("n", ""), ("t", "/trc20")];

async fn fetch(
    cx: &Cx<'_>,
    b: &mut Budget,
    list: &str,
    min: Option<u64>,
    max: Option<u64>,
) -> ChainResult<Vec<Value>> {
    let path = query(&cx.req.address.text, list, min, max);
    let (status, v) = get_json_from(cx, b, Need::TRON_V1, &path, is_list).await?;
    if status == 404 {
        return Ok(Vec::new());
    }
    Ok(v.get("data").and_then(Value::as_array).cloned().unwrap_or_default())
}

fn times(records: &[Value]) -> impl Iterator<Item = u64> + '_ {
    records.iter().filter_map(|r| r.get("block_timestamp").and_then(Value::as_u64))
}

fn items_of(key: &str, records: &[Value], me: &str) -> Vec<Item> {
    if key == "n" { native_items(records, me) } else { token_items(records, me) }
}

/// Reads what is newer than each list's top, going on past a full page.
pub(super) async fn update(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let me = cx.req.address.text.clone();
    for (key, path) in LISTS {
        let mut l = list_of(st, key);
        let mut gathered: Vec<Value> = Vec::new();
        let result = update_list(cx, b, &mut l, path, &mut gathered).await;
        st.merge(items_of(key, &gathered, &me));
        put_list(st, key, l);
        result?;
    }
    reconcile(st);
    Ok(())
}

async fn update_list(
    cx: &Cx<'_>,
    b: &mut Budget,
    l: &mut List,
    path: &str,
    gathered: &mut Vec<Value>,
) -> ChainResult<()> {
    if l.top.is_none() && l.catch.is_none() {
        // The first reading: the newest page.
        let page = fetch(cx, b, path, None, None).await?;
        l.top = times(&page).max();
        l.tail = times(&page).min();
        l.done = page.len() < LIST;
        gathered.extend(page);
        return Ok(());
    }
    if l.catch.is_none() {
        let page = fetch(cx, b, path, l.top, None).await?;
        let newest = times(&page).max().or(l.top);
        if page.len() >= LIST {
            // Full: there may be more between this page and what was known.
            if let (Some(oldest), Some(n)) = (times(&page).min(), newest) {
                l.catch = Some((oldest, n));
            }
        } else {
            l.top = newest;
        }
        gathered.extend(page);
    }
    while let Some((from, newest)) = l.catch {
        if !b.any() {
            break;
        }
        let page = fetch(cx, b, path, l.top, Some(from)).await?;
        let oldest = times(&page).min();
        let full = page.len() >= LIST;
        gathered.extend(page);
        match oldest {
            // Still full: go on from its oldest time, or past it if it did not move.
            Some(o) if full => {
                let next = if o >= from { from.saturating_sub(1) } else { o };
                l.catch = Some((next, newest));
            }
            _ => {
                l.top = Some(newest);
                l.catch = None;
            }
        }
    }
    Ok(())
}

/// Reads one page further back of the list that has read the least far.
pub(super) async fn extend(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let me = cx.req.address.text.clone();
    // The list whose tail is the newest (or that was never read) limits the floor.
    let pick = LISTS
        .iter()
        .map(|(k, p)| (*k, *p, list_of(st, k)))
        .filter(|(_, _, l)| !l.done)
        .max_by_key(|(_, _, l)| (l.tail.is_none(), l.tail.unwrap_or(0)));
    let Some((key, path, mut l)) = pick else { return Ok(()) };
    let page = fetch(cx, b, path, None, l.tail).await?;
    let oldest = times(&page).min();
    match oldest {
        // No progress (the page is all at the tail's millisecond): step past it.
        Some(o) if Some(o) == l.tail && page.len() >= LIST => l.tail = o.checked_sub(1),
        Some(o) => l.tail = Some(o),
        None => {}
    }
    if l.top.is_none() {
        l.top = times(&page).max();
    }
    l.done = page.len() < LIST;
    st.merge(items_of(key, &page, &me));
    put_list(st, key, l);
    reconcile(st);
    Ok(())
}

/// Items at or before this time (seconds) are held back while a list has older
/// pages unread.
pub(super) fn floor(st: &State) -> Option<u64> {
    LISTS
        .iter()
        .map(|(k, _)| list_of(st, k))
        .filter(|l| !l.done)
        .filter_map(|l| l.tail)
        .max()
        .map(|ms| ms / 1000)
}

pub(super) fn coverage(st: &State) -> Coverage {
    let lists: Vec<List> = LISTS.iter().map(|(k, _)| list_of(st, k)).collect();
    let complete = lists.iter().all(|l| l.done) && lists.iter().all(|l| l.top.is_some() || l.done);
    Coverage::single("full", complete, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb";
    const YOU: &str = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9";
    const USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

    fn hex_of(address: &str) -> String {
        hex::encode(parse_address(address).unwrap())
    }

    fn native(
        id: &str,
        ms: u64,
        kind: &str,
        owner: &str,
        to: Option<&str>,
        amount: u64,
        fee: u64,
        ret: &str,
    ) -> Value {
        let mut value = json!({ "owner_address": hex_of(owner), "amount": amount });
        if let Some(to) = to {
            value["to_address"] = json!(hex_of(to));
        }
        json!({
            "txID": id, "block_timestamp": ms, "blockNumber": 100,
            "ret": [{ "contractRet": ret, "fee": fee }],
            "raw_data": { "contract": [{ "type": kind, "parameter": { "value": value } }] },
        })
    }

    fn token(id: &str, ms: u64, from: &str, to: &str, value: &str, contract: &str) -> Value {
        json!({
            "transaction_id": id, "block_timestamp": ms, "from": from, "to": to, "value": value,
            "token_info": { "address": contract, "decimals": 6, "symbol": "X" },
        })
    }

    #[test]
    fn trx_in_and_out_are_transfers_and_a_failed_send_is_a_call_with_its_fee() {
        let records = [
            native("in", 3_000, "TransferContract", YOU, Some(ME), 5_000_000, 0, "SUCCESS"),
            native("out", 2_000, "TransferContract", ME, Some(YOU), 1_000_000, 270_000, "SUCCESS"),
            native(
                "bad",
                1_000,
                "TransferContract",
                ME,
                Some(YOU),
                9_000_000,
                100_000,
                "OUT_OF_ENERGY",
            ),
        ];
        let items = native_items(&records, ME);
        let by = |id: &str| items.iter().find(|i| i.hash == id).unwrap();
        assert_eq!(
            (by("in").direction, by("in").amount, by("in").fee),
            (Direction::In, 5_000_000, None)
        );
        assert_eq!(by("in").counterparty.as_deref(), Some(YOU));
        assert_eq!((by("out").direction, by("out").fee), (Direction::Out, Some(270_000)));
        assert_eq!(by("out").counterparty.as_deref(), Some(YOU));
        assert_eq!(
            (by("bad").kind, by("bad").status, by("bad").amount, by("bad").fee),
            (Kind::Call, Status::Failed, 0, Some(100_000))
        );
        // Someone else's payment to someone else is nothing of ours.
        let strangers = [native("x", 5, "TransferContract", YOU, Some(YOU), 1, 0, "SUCCESS")];
        assert!(native_items(&strangers, ME).is_empty());
    }

    #[test]
    fn only_listed_tokens_show_and_a_calls_fee_moves_to_its_transfer() {
        let tokens = [
            token("t1", 2_000, ME, YOU, "7000000", USDT),
            token("t2", 1_500, YOU, ME, "3000000", USDT),
            token("junk", 1_400, YOU, ME, "1", "TFNirp6PbqYE1ZTtWuCMUKJWLNZkoCoeFJ"),
        ];
        let calls =
            [native("t1", 2_000, "TriggerSmartContract", ME, None, 0, 6_000_000, "SUCCESS")];
        let mut st = State::new("t", 0);
        st.merge(token_items(&tokens, ME));
        st.merge(native_items(&calls, ME));
        assert_eq!(st.items.len(), 3, "two transfers and the call");
        reconcile(&mut st);
        assert_eq!(st.items.len(), 2, "the call said no more than its transfer");
        let out = st.items.iter().find(|i| i.hash == "t1").unwrap();
        assert_eq!(
            (out.direction, out.fee, out.asset.as_str(), out.amount),
            (Direction::Out, Some(6_000_000), "USDT", 7_000_000)
        );
        assert_eq!(
            st.items.iter().find(|i| i.hash == "t2").unwrap().fee,
            None,
            "received: someone else paid"
        );
        // A contract call that moved nothing listed stays.
        let lone =
            [native("approve", 3_000, "TriggerSmartContract", ME, None, 0, 1_000, "SUCCESS")];
        st.merge(native_items(&lone, ME));
        reconcile(&mut st);
        assert!(st.items.iter().any(|i| i.hash == "approve" && i.kind == Kind::Call));
    }

    #[test]
    fn identical_transfers_in_one_transaction_stay_two_items() {
        let tokens =
            [token("same", 1_000, YOU, ME, "5", USDT), token("same", 1_000, YOU, ME, "5", USDT)];
        let items = token_items(&tokens, ME);
        assert_eq!(items.len(), 2);
        assert_ne!(items[0].id, items[1].id);
    }

    #[test]
    fn a_list_not_fully_read_holds_back_what_is_older_than_its_oldest_page() {
        let mut st = State::new("t", 0);
        put_list(
            &mut st,
            "n",
            List { top: Some(9_000_000), tail: Some(5_000_000), done: false, catch: None },
        );
        put_list(
            &mut st,
            "t",
            List { top: Some(9_500_000), tail: Some(2_000_000), done: false, catch: None },
        );
        assert_eq!(floor(&st), Some(5_000), "the list that has read the least far limits it");
        put_list(
            &mut st,
            "n",
            List { top: Some(9_000_000), tail: Some(1_000), done: true, catch: None },
        );
        assert_eq!(floor(&st), Some(2_000));
        put_list(
            &mut st,
            "t",
            List { top: Some(9_500_000), tail: Some(1_000), done: true, catch: None },
        );
        assert_eq!(floor(&st), None);
        assert!(coverage(&st).complete);
    }

    #[test]
    fn hex_addresses_are_written_as_the_network_writes_them() {
        assert_eq!(written(&hex_of(ME)).as_deref(), Some(ME));
        assert_eq!(written(ME).as_deref(), Some(ME));
        assert_eq!(written("zz"), None);
    }
}

#[cfg(test)]
mod hostile {
    use super::*;

    const ME: &str = "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb";
    const USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

    #[test]
    fn amounts_and_times_a_node_makes_up_never_panic() {
        let me = hex::encode(parse_address(ME).unwrap());
        let big = json!(u64::MAX);
        let tx = json!({
            "txID": "a", "block_timestamp": u64::MAX, "blockNumber": u64::MAX,
            "ret": [{ "contractRet": "SUCCESS", "fee": u64::MAX }],
            "raw_data": { "contract": [{ "type": "TransferContract", "parameter": { "value": {
                "owner_address": me, "to_address": me, "amount": big } } }] },
        });
        let _ = native_items(std::slice::from_ref(&tx), ME);
        let token = |value: &str| {
            json!({
                "transaction_id": "b", "block_timestamp": u64::MAX, "from": ME, "to": ME, "value": value,
                "token_info": { "address": USDT, "decimals": 6, "symbol": "X" },
            })
        };
        let records: Vec<Value> = [
            "340282366920938463463374607431768211455",
            "340282366920938463463374607431768211456",
            "-1",
            "1e30",
            "",
        ]
        .iter()
        .map(|v| token(v))
        .collect();
        let items = token_items(&records, ME);
        // The one that fits is kept as it is; the ones that do not are skipped.
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].amount, u128::MAX);
        // Merged with a call of the same transaction, the fee moves without arithmetic.
        let mut st = State::new("t", 1);
        st.merge([native_items(&[tx], ME), items].concat());
        reconcile(&mut st);
    }
}
