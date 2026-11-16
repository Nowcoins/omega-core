//! Bitcoin, from Esplora (mempool.space, with Blockstream's as the backup): every
//! address of the account, netted into one history.
//!
//! # The account's addresses
//!
//! A BIP-84 wallet has two chains of addresses under its account key, `0`
//! (receive) and `1` (change), and its coins can be on any of them. Given the
//! account's `zpub` the scan walks each chain with the **gap limit** wallets use,
//! 20: an address is used if Esplora has a transaction for it (confirmed or
//! not), and the walk goes on until 20 in a row are not. Without a `zpub` the
//! addresses the app names are all there is. Walking needs no secret: the
//! addresses come from the public key alone (`nc-wallet-core`).
//!
//! # The history
//!
//! Each used address is read a page at a time: `/address/{a}/txs` (what is in
//! the mempool, then the 25 newest confirmed), and `/address/{a}/txs/chain/{last}`
//! for the 25 before one. A transaction is made one item for the whole account:
//!
//! * nothing of the account's was spent: **in**, what was paid to the account,
//!   from the largest input;
//! * the account spent, and some output went elsewhere: **out**, the sum of what
//!   went elsewhere (not the account's own change, not the fee), to the largest
//!   such output;
//! * the account spent and everything came back to it: **self**, a move between
//!   its own addresses, which cost the fee.
//!
//! The fee is shown when the account funded the whole transaction.
//!
//! A newer update reads each address's first page again and, where it is full of
//! transactions not yet known, goes on until it reaches one that is. Items older
//! than the oldest page of an address not yet fully read are held back, so that
//! what is listed is always a whole recent stretch of the history.

use std::collections::HashSet;

use serde_json::{Value, json};

use super::store::{Direction, Item, Kind, State, Status};
use super::{Budget, Coverage, Cx, get_json};
use crate::error::{ChainError, ChainResult};
use crate::pool::Need;
use crate::util::parse_json;
use nc_wallet_core::bitcoin::{Chain, addresses_from_zpub};

/// Esplora gives confirmed transactions this many at a time.
const PAGE: usize = 25;
/// How many unused addresses in a row end the walk of a chain.
const GAP: u32 = 20;
/// Addresses looked up side by side.
const AT_ONCE: u32 = 4;

/// A page is a list of transactions that have an id.
fn is_page(v: &Value) -> bool {
    v.as_array().is_some_and(|l| l.iter().all(|t| t.get("txid").is_some_and(Value::is_string)))
}

/// An address's statistics: it has `chain_stats` and `mempool_stats`.
fn is_stats(v: &Value) -> bool {
    v.pointer("/chain_stats/tx_count").is_some_and(Value::is_u64)
}

/// Where one address's reading stands.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Addr {
    address: String,
    /// The txid of the newest confirmed transaction read.
    top: Option<String>,
    /// The txid to read before, to go further back (`None`: from the top).
    tail: Option<String>,
    /// The time of the oldest confirmed transaction read.
    tail_time: Option<u64>,
    /// Whether the oldest transaction has been read.
    done: bool,
    /// Catching up to `top`: the txid to read before, and the newest of this run.
    catch: Option<(String, String)>,
}

/// Where the walk of one chain stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Walk {
    /// The next index to look at.
    next: u32,
    /// Unused addresses at the end of what was looked at.
    gap: u32,
    /// The last index found used, plus one.
    used_to: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Book {
    addrs: Vec<Addr>,
    receive: Walk,
    change: Walk,
}

fn walk_json(w: Walk) -> Value {
    json!([w.next, w.gap, w.used_to])
}

fn walk_of(v: Option<&Value>) -> Walk {
    let n = |i: usize| {
        v.and_then(|v| v.get(i))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0)
    };
    Walk { next: n(0), gap: n(1), used_to: n(2) }
}

pub(super) fn book_of(st: &State) -> Book {
    let Some(b) = st.src.get("btc") else { return Book::default() };
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let addrs = b
        .get("a")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|a| {
                    Some(Addr {
                        address: text(a, "a")?,
                        top: text(a, "top"),
                        tail: text(a, "tail"),
                        tail_time: a.get("tt").and_then(Value::as_u64),
                        done: a.get("done").and_then(Value::as_bool) == Some(true),
                        catch: text(a, "cc").zip(text(a, "cn")),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Book { addrs, receive: walk_of(b.get("r")), change: walk_of(b.get("c")) }
}

fn put_book(st: &mut State, book: &Book) {
    let list: Vec<Value> = book
        .addrs
        .iter()
        .map(|a| {
            let mut o = json!({ "a": a.address });
            if let Some(t) = &a.top {
                o["top"] = json!(t);
            }
            if let Some(t) = &a.tail {
                o["tail"] = json!(t);
            }
            if let Some(t) = a.tail_time {
                o["tt"] = json!(t);
            }
            if a.done {
                o["done"] = json!(true);
            }
            if let Some((c, n)) = &a.catch {
                o["cc"] = json!(c);
                o["cn"] = json!(n);
            }
            o
        })
        .collect();
    let mut src = st.src.as_object().cloned().unwrap_or_default();
    src.insert(
        "btc".into(),
        json!({ "a": list, "r": walk_json(book.receive), "c": walk_json(book.change) }),
    );
    st.src = Value::Object(src);
}

fn value_of(v: &Value) -> u64 {
    v.get("value").and_then(Value::as_u64).unwrap_or(0)
}

/// A sum of what a service wrote, which may be anything: it saturates and never overflows.
fn total(values: impl Iterator<Item = u64>) -> u64 {
    values.fold(0, u64::saturating_add)
}

/// Whether an Esplora address statistic counts any transaction (the counts are whatever the service wrote).
fn any_transaction(v: &Value) -> bool {
    let n = |p: &str| v.pointer(p).and_then(Value::as_u64).unwrap_or(0);
    n("/chain_stats/tx_count").saturating_add(n("/mempool_stats/tx_count")) > 0
}

fn address_of(v: &Value) -> Option<&str> {
    v.get("scriptpubkey_address").and_then(Value::as_str)
}

/// What a transaction did to the account, if anything.
pub(super) fn item_of(
    tx: &Value,
    own: &HashSet<&str>,
    existing: Option<&Item>,
    now: u64,
) -> Option<Item> {
    let txid = tx.get("txid")?.as_str()?;
    let prevouts: Vec<&Value> =
        tx.get("vin")?.as_array()?.iter().filter_map(|i| i.get("prevout")).collect();
    let outs = tx.get("vout")?.as_array()?;
    let mine = |o: &Value| address_of(o).is_some_and(|a| own.contains(a));
    let own_in = total(prevouts.iter().copied().filter(|o| mine(o)).map(value_of));
    let own_out = total(outs.iter().filter(|o| mine(o)).map(value_of));
    let total_in = total(prevouts.iter().copied().map(value_of));
    if own_in == 0 && own_out == 0 {
        return None;
    }
    let fee = tx.get("fee").and_then(Value::as_u64).unwrap_or(0);
    let others = || {
        outs.iter()
            .filter(|o| !mine(o))
            .filter_map(|o| Some((value_of(o), address_of(o)?.to_owned())))
    };
    let (direction, amount, counterparty, fee) = if own_in == 0 {
        let from = prevouts
            .iter()
            .filter_map(|o| Some((value_of(o), address_of(o)?.to_owned())))
            .max_by_key(|(v, _)| *v)
            .map(|(_, a)| a);
        (Direction::In, own_out, from, None)
    } else if others().next().is_none() {
        (Direction::SelfSent, own_out, None, Some(own_in.saturating_sub(own_out)))
    } else {
        let sent = total(others().map(|(v, _)| v));
        let to = others().max_by_key(|(v, _)| *v).map(|(_, a)| a);
        (Direction::Out, sent, to, (own_in == total_in).then_some(fee))
    };
    let status = tx.get("status")?;
    let confirmed_at = if status.get("confirmed").and_then(Value::as_bool) == Some(true) {
        status
            .get("block_height")
            .and_then(Value::as_u64)
            .zip(status.get("block_time").and_then(Value::as_u64))
    } else {
        None
    };
    let (state, time, block) = match confirmed_at {
        Some((height, time)) => (Status::Confirmed, time, Some(height)),
        // Seen in the mempool: when it was first seen, if it was seen before.
        None => (Status::Pending, existing.map_or(now, |e| e.time), None),
    };
    let native = crate::networks::Network::Bitcoin.native();
    let mut item = Item::new(txid.to_owned(), txid.to_owned(), time, direction, native.symbol);
    item.kind = Kind::Transfer;
    item.order = block.map_or(u64::MAX >> 1, |h| h << 20);
    item.amount = u128::from(amount);
    item.decimals = native.decimals;
    item.counterparty = counterparty;
    item.fee = fee.map(u128::from);
    item.status = state;
    item.block = block;
    Some(item)
}

/// The account's addresses as strings.
pub(super) fn own_set(book: &Book) -> HashSet<&str> {
    book.addrs.iter().map(|a| a.address.as_str()).collect()
}

fn ensure(book: &mut Book, address: &str) {
    if !book.addrs.iter().any(|a| a.address == address) {
        book.addrs.push(Addr {
            address: address.to_owned(),
            top: None,
            tail: None,
            tail_time: None,
            done: false,
            catch: None,
        });
    }
}

/// Looks up `addresses` side by side: which have a transaction.
async fn used(cx: &Cx<'_>, b: &mut Budget, addresses: &[String]) -> ChainResult<Vec<bool>> {
    // A batch side by side is one step of the budget: each lookup is a few hundred
    // bytes, and the endpoints' pace, not the budget, is what spaces them.
    if b.take_up_to(1, cx.net.now()) == 0 {
        return Err(ChainError::Busy { retry_after_seconds: 1 });
    }
    let asked = addresses;
    let answers = futures::future::join_all(asked.iter().map(|a| async move {
        let ((status, body), _) = cx.net.get_from(Need::ANY, &[], &format!("/address/{a}")).await?;
        if !(200..300).contains(&status) {
            return Err(ChainError::Unavailable);
        }
        let v = parse_json(&body)?;
        if !is_stats(&v) {
            return Err(ChainError::Unavailable);
        }
        Ok(any_transaction(&v))
    }))
    .await;
    answers.into_iter().collect()
}

fn walk_of_chain(book: &Book, chain: Chain) -> Walk {
    if chain == Chain::Receive { book.receive } else { book.change }
}

fn set_walk(book: &mut Book, chain: Chain, w: Walk) {
    if chain == Chain::Receive {
        book.receive = w;
    } else {
        book.change = w;
    }
}

/// Walks one chain from where it stood until 20 in a row are unused, or the
/// budget is spent.
async fn walk(
    cx: &Cx<'_>,
    b: &mut Budget,
    book: &mut Book,
    zpub: &str,
    chain: Chain,
) -> ChainResult<()> {
    let mut w = walk_of_chain(book, chain);
    while w.gap < GAP && b.any() {
        let count = AT_ONCE.min(GAP - w.gap).max(1);
        let batch = addresses_from_zpub(zpub, chain, w.next, count)
            .ok_or_else(|| ChainError::invalid("zpub is not an account key"))?;
        let flags = match used(cx, b, &batch).await {
            Ok(flags) => flags,
            // The endpoints are at their pace: what is walked so far is kept, and
            // the walk goes on at the next call.
            Err(ChainError::Busy { .. }) => return Ok(()),
            Err(e) => return Err(e),
        };
        for (offset, is_used) in flags.iter().enumerate() {
            let index = w.next + u32::try_from(offset).unwrap_or(0);
            if *is_used {
                ensure(book, &batch[offset]);
                w.gap = 0;
                w.used_to = index + 1;
            } else {
                w.gap += 1;
            }
        }
        w.next += u32::try_from(flags.len()).unwrap_or(0);
        set_walk(book, chain, w);
    }
    Ok(())
}

/// The first unused address of each chain, looked at again: has it been used since?
async fn look_ahead(cx: &Cx<'_>, b: &mut Budget, book: &mut Book, zpub: &str) -> ChainResult<()> {
    for chain in [Chain::Receive, Chain::Change] {
        let w = walk_of_chain(book, chain);
        if w.gap < GAP || !b.any() {
            continue;
        }
        let Some(one) = addresses_from_zpub(zpub, chain, w.used_to, 1) else { continue };
        if used(cx, b, &one).await?.first() == Some(&true) {
            ensure(book, &one[0]);
            // The walk goes on from it, with a fresh gap.
            let next = Walk { next: w.used_to + 1, gap: 0, used_to: w.used_to + 1 };
            set_walk(book, chain, next);
            walk(cx, b, book, zpub, chain).await?;
        }
    }
    Ok(())
}

async fn tip(cx: &Cx<'_>, b: &mut Budget) -> Option<u64> {
    if !b.take(cx.net.now()) {
        return None;
    }
    let (status, body) = cx.net.get(Need::ANY, "/blocks/tip/height").await.ok()?;
    if !(200..300).contains(&status) {
        return None;
    }
    std::str::from_utf8(&body).ok()?.trim().parse().ok()
}

/// A page of an address's transactions: the first, or the one before `before`.
async fn page_of(
    cx: &Cx<'_>,
    b: &mut Budget,
    address: &str,
    before: Option<&str>,
) -> ChainResult<Vec<Value>> {
    let path = match before {
        None => format!("/address/{address}/txs"),
        Some(last) => format!("/address/{address}/txs/chain/{last}"),
    };
    let (status, v) = get_json(cx, b, &path, is_page).await?;
    if status == 404 {
        return Ok(Vec::new());
    }
    Ok(v.as_array().cloned().unwrap_or_default())
}

fn confirmed(tx: &Value) -> bool {
    tx.pointer("/status/confirmed").and_then(Value::as_bool) == Some(true)
}

fn txid(tx: &Value) -> &str {
    tx.get("txid").and_then(Value::as_str).unwrap_or("")
}

fn make_items(st: &State, book: &Book, txs: &[Value], now: u64) -> Vec<Item> {
    let own = own_set(book);
    txs.iter()
        .filter_map(|tx| {
            let existing = st.items.iter().find(|i| i.id == txid(tx));
            item_of(tx, &own, existing, now)
        })
        .collect()
}

fn with_known(cx: &Cx<'_>, book: &mut Book) {
    ensure(book, &cx.req.address.text);
    for other in &cx.req.others {
        ensure(book, &other.text);
    }
}

/// Reads the first page of every address and goes on where it is full of what is
/// new; discovers addresses first.
pub(super) async fn update(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let mut book = book_of(st);
    with_known(cx, &mut book);
    let result = update_inner(cx, b, st, &mut book).await;
    put_book(st, &book);
    result
}

async fn update_inner(
    cx: &Cx<'_>,
    b: &mut Budget,
    st: &mut State,
    book: &mut Book,
) -> ChainResult<()> {
    if let Some(tip) = tip(cx, b).await {
        st.head = Some(tip);
    }
    let mut seen_pending: HashSet<String> = HashSet::new();
    let mut read_now: HashSet<String> = HashSet::new();
    // What the app named is read first, so that there is something to show; the
    // addresses found by walking are read after.
    read_unread(cx, b, st, book, &mut read_now, &mut seen_pending).await?;
    if let Some(zpub) = cx.req.zpub.clone() {
        look_ahead(cx, b, book, &zpub).await?;
        walk(cx, b, book, &zpub, Chain::Receive).await?;
        walk(cx, b, book, &zpub, Chain::Change).await?;
        read_unread(cx, b, st, book, &mut read_now, &mut seen_pending).await?;
    }
    // What was in the mempool and is no longer anywhere was dropped or replaced
    // (judged only when every address's first page was read this time).
    if read_now.len() == book.addrs.len() {
        st.items.retain(|i| i.status != Status::Pending || seen_pending.contains(&i.id));
    }
    Ok(())
}

/// Reads the first page of each address not read in this call yet, and goes on
/// where it is full of what is new.
async fn read_unread(
    cx: &Cx<'_>,
    b: &mut Budget,
    st: &mut State,
    book: &mut Book,
    read_now: &mut HashSet<String>,
    seen_pending: &mut HashSet<String>,
) -> ChainResult<()> {
    for index in 0..book.addrs.len() {
        let address = book.addrs[index].address.clone();
        if read_now.contains(&address) {
            continue;
        }
        if !b.any() {
            return Ok(());
        }
        read_now.insert(address.clone());
        let first = page_of(cx, b, &address, None).await?;
        let mut gathered: Vec<Value> = first.clone();
        for tx in first.iter().filter(|t| !confirmed(t)) {
            seen_pending.insert(txid(tx).to_owned());
        }
        let confirmed_now: Vec<&Value> = first.iter().filter(|t| confirmed(t)).collect();
        let newest = confirmed_now.first().map(|t| txid(t).to_owned());
        let a = &mut book.addrs[index];
        match (&a.top, &a.catch) {
            // Never read: this page is the start; going back is `extend`'s.
            (None, None) => {
                a.top = newest;
                if let Some(last) = confirmed_now.last() {
                    a.tail = Some(txid(last).to_owned());
                    a.tail_time = last.pointer("/status/block_time").and_then(Value::as_u64);
                }
                a.done = confirmed_now.len() < PAGE;
            }
            (Some(top), None) => {
                let reached = confirmed_now.iter().any(|t| txid(t) == top);
                if !reached && confirmed_now.len() >= PAGE {
                    // More came than one page holds: read back to what was known.
                    if let (Some(last), Some(n)) = (confirmed_now.last(), newest) {
                        a.catch = Some((txid(last).to_owned(), n));
                    }
                } else if let Some(n) = newest {
                    a.top = Some(n);
                }
            }
            (_, Some(_)) => {}
        }
        // Catching up: pages before the last one read, until the known top.
        while let Some((cursor, newest_of_run)) = book.addrs[index].catch.clone() {
            if !b.any() {
                break;
            }
            let older = page_of(cx, b, &address, Some(&cursor)).await?;
            let top = book.addrs[index].top.clone();
            let reached = top.as_ref().is_some_and(|t| older.iter().any(|x| txid(x) == t));
            let last = older.last().map(|t| txid(t).to_owned());
            gathered.extend(older.iter().cloned());
            let a = &mut book.addrs[index];
            match last {
                Some(last) if !reached && older.len() >= PAGE => {
                    a.catch = Some((last, newest_of_run));
                }
                _ => {
                    a.top = Some(newest_of_run);
                    a.catch = None;
                }
            }
        }
        let items = make_items(st, book, &gathered, cx.now);
        st.merge(items);
    }
    Ok(())
}

/// Reads one page further back, of the address whose reading limits the listing.
pub(super) async fn extend(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let mut book = book_of(st);
    with_known(cx, &mut book);
    let result = extend_inner(cx, b, st, &mut book).await;
    put_book(st, &book);
    result
}

async fn extend_inner(
    cx: &Cx<'_>,
    b: &mut Budget,
    st: &mut State,
    book: &mut Book,
) -> ChainResult<()> {
    if let Some(zpub) = cx.req.zpub.clone() {
        walk(cx, b, book, &zpub, Chain::Receive).await?;
        walk(cx, b, book, &zpub, Chain::Change).await?;
    }
    // The address that has read the least far back (the newest tail), or one never read.
    let next = book
        .addrs
        .iter()
        .enumerate()
        .filter(|(_, a)| !a.done)
        .max_by_key(|(_, a)| (a.tail.is_none(), a.tail_time.unwrap_or(u64::MAX)))
        .map(|(i, _)| i);
    let Some(index) = next else { return Ok(()) };
    let address = book.addrs[index].address.clone();
    let before = book.addrs[index].tail.clone();
    let page = page_of(cx, b, &address, before.as_deref()).await?;
    let confirmed_page: Vec<&Value> = page.iter().filter(|t| confirmed(t)).collect();
    let a = &mut book.addrs[index];
    if let Some(last) = confirmed_page.last() {
        a.tail = Some(txid(last).to_owned());
        a.tail_time = last.pointer("/status/block_time").and_then(Value::as_u64);
    }
    if a.top.is_none() {
        a.top = confirmed_page.first().map(|t| txid(t).to_owned());
    }
    a.done = confirmed_page.len() < PAGE;
    let items = make_items(st, book, &page, cx.now);
    st.merge(items);
    Ok(())
}

/// Items at or before this time are held back while an address has pages unread
/// older than them.
pub(super) fn floor(st: &State) -> Option<u64> {
    let book = book_of(st);
    book.addrs.iter().filter(|a| !a.done).filter_map(|a| a.tail_time).max()
}

/// The history is whole when every address is read to its first transaction and
/// the walks have found their gaps.
pub(super) fn coverage(st: &State) -> Coverage {
    let book = book_of(st);
    let started = !book.addrs.is_empty();
    // With a key, the walks must have finished too.
    let walked = |w: Walk| w.gap >= GAP;
    let keyed = book.receive.next > 0 || book.change.next > 0;
    let complete = started
        && book.addrs.iter().all(|a| a.done)
        && (!keyed || (walked(book.receive) && walked(book.change)));
    Coverage::single("full", complete, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "bc1q9qkjc8x853msxzsykp5qc5hjc0uav8ak4wwj5q";
    const CHANGE: &str = "bc1qg3f7exyzcgpw48ysh58rgpuu7vyh9wnu64mae8";
    const OTHER: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

    fn tx(id: &str, ins: &[(&str, u64)], outs: &[(&str, u64)], fee: u64, confirmed: bool) -> Value {
        json!({
            "txid": id,
            "fee": fee,
            "status": if confirmed {
                json!({ "confirmed": true, "block_height": 900_000, "block_time": 1_790_000_000 })
            } else {
                json!({ "confirmed": false })
            },
            "vin": ins.iter().map(|(a, v)| json!({ "prevout": { "scriptpubkey_address": a, "value": v } })).collect::<Vec<_>>(),
            "vout": outs.iter().map(|(a, v)| json!({ "scriptpubkey_address": a, "value": v })).collect::<Vec<_>>(),
        })
    }

    fn own<'a>(list: &[&'a str]) -> HashSet<&'a str> {
        list.iter().copied().collect()
    }

    #[test]
    fn money_paid_in_is_in_from_the_largest_input() {
        let t = tx("a", &[(OTHER, 5_000), ("bc1qsmall", 1_000)], &[(ME, 5_900)], 100, true);
        let i = item_of(&t, &own(&[ME, CHANGE]), None, 0).unwrap();
        assert_eq!((i.direction, i.amount, i.fee), (Direction::In, 5_900, None));
        assert_eq!(i.counterparty.as_deref(), Some(OTHER));
        assert_eq!((i.status, i.block, i.time), (Status::Confirmed, Some(900_000), 1_790_000_000));
    }

    #[test]
    fn a_payment_is_what_left_the_account_not_its_change_and_not_the_fee() {
        // Spends 20,000 from ME; pays 12,000 to OTHER; 7,800 comes back to the change address.
        let t = tx("b", &[(ME, 20_000)], &[(OTHER, 12_000), (CHANGE, 7_800)], 200, true);
        let i = item_of(&t, &own(&[ME, CHANGE]), None, 0).unwrap();
        assert_eq!((i.direction, i.amount, i.fee), (Direction::Out, 12_000, Some(200)));
        assert_eq!(i.counterparty.as_deref(), Some(OTHER));
        // Seen with the change address left out, it would look like a larger payment: the
        // account-level view needs every address of the account, which is what discovery is for.
        let alone = item_of(&t, &own(&[ME]), None, 0).unwrap();
        assert_eq!(alone.amount, 19_800);
    }

    #[test]
    fn a_move_between_the_accounts_own_addresses_costs_the_fee_only() {
        let t = tx("c", &[(ME, 10_000)], &[(CHANGE, 9_850)], 150, true);
        let i = item_of(&t, &own(&[ME, CHANGE]), None, 0).unwrap();
        assert_eq!((i.direction, i.amount, i.fee), (Direction::SelfSent, 9_850, Some(150)));
    }

    #[test]
    fn a_shared_transaction_shows_no_fee_it_did_not_pay_and_a_stranger_shows_nothing() {
        let t = tx("d", &[(ME, 5_000), (OTHER, 5_000)], &[(OTHER, 9_900)], 100, true);
        let i = item_of(&t, &own(&[ME]), None, 0).unwrap();
        assert_eq!((i.direction, i.amount, i.fee), (Direction::Out, 9_900, None));
        let nothing = tx("e", &[(OTHER, 5_000)], &[(OTHER, 4_900)], 100, true);
        assert!(item_of(&nothing, &own(&[ME]), None, 0).is_none());
    }

    #[test]
    fn a_pending_transaction_keeps_the_time_it_was_first_seen() {
        let t = tx("f", &[(OTHER, 5_000)], &[(ME, 4_900)], 100, false);
        let first = item_of(&t, &own(&[ME]), None, 1_000).unwrap();
        assert_eq!((first.status, first.time, first.block), (Status::Pending, 1_000, None));
        let later = item_of(&t, &own(&[ME]), Some(&first), 5_000).unwrap();
        assert_eq!(later.time, 1_000);
    }
}

#[cfg(test)]
mod hostile {
    use super::*;

    #[test]
    fn values_a_service_makes_up_never_overflow() {
        let max = u64::MAX;
        let me = "bc1qme";
        let own: HashSet<&str> = [me].into_iter().collect();
        let side = |address: &str| json!({ "scriptpubkey_address": address, "value": max });
        // Sent: everything the largest it can be, on every side.
        let sent = json!({
            "txid": "aa", "fee": max,
            "status": { "confirmed": true, "block_height": max, "block_time": max },
            "vin": [{ "prevout": side(me) }, { "prevout": side(me) }, { "prevout": side("other") }],
            "vout": [side(me), side(me), side("other"), side("other2")],
        });
        let item = item_of(&sent, &own, None, 1).expect("an item");
        assert_eq!(item.amount, u128::from(max), "saturated, not wrapped");
        // Received.
        let got = json!({
            "txid": "bb",
            "status": { "confirmed": false },
            "vin": [{ "prevout": side("other") }, { "prevout": side("other") }],
            "vout": [side(me), side(me)],
        });
        assert!(item_of(&got, &own, None, 1).is_some());
        // Within the account.
        let moved = json!({
            "txid": "cc", "fee": max, "status": { "confirmed": false },
            "vin": [{ "prevout": side(me) }, { "prevout": side(me) }],
            "vout": [side(me)],
        });
        assert!(item_of(&moved, &own, None, 1).is_some());
        // Counts that add past a u64.
        let counts = json!({
            "chain_stats": { "tx_count": max, "funded_txo_sum": 0, "spent_txo_sum": 0 },
            "mempool_stats": { "tx_count": max, "funded_txo_sum": 0, "spent_txo_sum": 0 },
        });
        assert!(any_transaction(&counts));
    }
}
