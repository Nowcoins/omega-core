//! Ethereum, BNB Chain, Polygon and Base: the listed tokens' transfers from
//! `eth_getLogs`, fees from receipts, and the coin from first sight (see
//! `firstsight`).
//!
//! A token's `Transfer` event names the sender in its second topic and the
//! recipient in its third, so asking a node for the logs of the listed token
//! contracts with the address in one place or the other lists every transfer of
//! those tokens to or from the address: two queries per window of blocks. A log
//! carries its block, its transaction and (on every node that was measured but
//! one) the block's time, so no block has to be fetched.
//!
//! # How far back, and how wide
//!
//! The free endpoints differ a great deal (see `endpoints.rs` and the table in
//! `docs/history.md`): an archive gateway answers a query over the whole
//! chain if the result is under 20,000 logs, `PublicNode` only the last few
//! thousand to few million blocks, others fifty blocks. The scan therefore
//! chooses a window from what the endpoints that can serve its depth allow,
//! asks, and **learns** from a refusal: a result too large halves the window, a
//! range refused teaches the endpoint's cap, a block too old teaches its depth.
//! It reads back from the head toward the first block a listed token could have
//! been used in; where no endpoint reaches further it stops and says
//! `partial` with the date reached.
//!
//! Reading is bounded (a call makes a few requests) and resumable: the scan's
//! two ends, `hi` (the newest block read) and `lo` (the oldest), are in the
//! state. What is newer than `hi` is read forward on the next update.

use std::sync::Mutex;

use serde_json::{Value, json};

use super::store::{Direction, Item, Kind, State, Status};
use super::{Budget, Coverage, Cx, Part};
use crate::error::{ChainError, ChainResult};
use crate::net::{NodeError, Raw};
use crate::networks::Network;
use crate::pool::Need;
use crate::util::{bytes_from_hex, u64_from_hex, u128_from_hex, word_to_u128};

/// `Transfer(address,address,uint256)`.
const TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
/// How many receipts a call reads to fill in fees and settle sends.
const RECEIPTS_PER_CALL: usize = 4;
/// A send that no chain has after this long is forgotten.
pub(super) const NOTE_LIFETIME_SECONDS: u64 = 3 * 86_400;
/// Windows narrowed this many times in one step end the step.
const TRIES: usize = 5;

/// The first block a listed token could have a transfer in (rounded down):
/// Tether's USDT on Ethereum was deployed at block 4,634,748 in 2017 and
/// Circle's USDC at 6,082,465 in 2018. The others are scanned from the start of
/// their chain.
const fn floor_block(network: Network) -> u64 {
    match network {
        Network::Ethereum => 4_600_000,
        _ => 0,
    }
}

/// A block's time, in milliseconds, for working out a date from a block number.
const fn block_ms(network: Network) -> u64 {
    match network {
        Network::Bsc => 450,
        Network::Polygon => 2_100,
        Network::Base => 2_000,
        _ => 12_000,
    }
}

/// The two ends of what the scan has read, and how wide it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Scan {
    /// The newest block read.
    hi: u64,
    /// The oldest block read (`hi + 1` when none yet).
    lo: u64,
    /// The width the last windows were read at (`u64::MAX`: as wide as allowed).
    width: u64,
    /// The time of the head last seen, Unix seconds.
    head_time: u64,
}

fn scan_of(st: &State) -> Option<Scan> {
    let s = st.src.get("scan")?;
    let n = |k: &str| s.get(k).and_then(Value::as_u64);
    Some(Scan { hi: n("hi")?, lo: n("lo")?, width: n("w")?, head_time: n("ht")? })
}

fn put_scan(st: &mut State, scan: Scan) {
    let mut src = st.src.as_object().cloned().unwrap_or_default();
    src.insert(
        "scan".into(),
        json!({ "hi": scan.hi, "lo": scan.lo, "w": scan.width, "ht": scan.head_time }),
    );
    st.src = Value::Object(src);
}

/// The time of `block`, worked out from the head's.
fn time_of(network: Network, scan: &Scan, head: u64, block: u64) -> u64 {
    let behind = head.saturating_sub(block).saturating_mul(block_ms(network)) / 1000;
    scan.head_time.saturating_sub(behind)
}

fn quantity(v: &Value) -> Option<u64> {
    u64_from_hex(v.as_str()?)
}

// ---- reading ---------------------------------------------------------------

/// Why a window could not be read.
#[derive(Debug)]
enum Refused {
    /// Narrower, please: the width to try.
    Narrower(u64),
    /// An endpoint said the blocks are too old for it; it has been told so.
    Deeper,
    /// The budget is spent.
    Budget,
    /// Nobody answered.
    Down(ChainError),
}

/// How a node's refusal of a log query is read.
#[derive(Debug, PartialEq, Eq)]
enum Reading {
    /// Too many results for one answer.
    TooMany,
    /// The range is wider than the endpoint allows; the cap, if it said.
    TooWide(Option<u64>),
    /// The blocks are older than the endpoint serves.
    TooDeep,
    /// Something else.
    Other,
}

fn last_number(message: &str) -> Option<u64> {
    let mut found = None;
    let mut digits = String::new();
    for c in message.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_digit() || (c == ',' && !digits.is_empty()) {
            if c != ',' {
                digits.push(c);
            }
        } else if !digits.is_empty() {
            found = digits.parse().ok().or(found);
            digits.clear();
        }
    }
    found
}

fn read_refusal(error: &NodeError) -> Reading {
    let m = error.lower();
    let has = |p: &[&str]| p.iter().any(|x| m.contains(x));
    if has(&[
        "archive",
        "header not found",
        "missing trie node",
        "pruned",
        "no historical",
        "too old",
        "state not available",
    ]) {
        return Reading::TooDeep;
    }
    if has(&[
        "more than",
        "too many results",
        "response size",
        "results exceeded",
        "10,000 logs",
        "10000 logs",
        "limit of",
    ]) && has(&["result", "log", "response", "query"])
    {
        return Reading::TooMany;
    }
    if has(&[
        "range",
        "ranges over",
        "limited to",
        "too large",
        "must not exceed",
        "block range",
        "up to a",
        "maximum",
        "limit exceeded",
        "invalid block range",
    ]) {
        return Reading::TooWide(last_number(&m).filter(|n| (1..=100_000_000).contains(n)));
    }
    Reading::Other
}

fn topic_of(address: &[u8; 20]) -> String {
    format!("0x{}{}", "0".repeat(24), hex::encode(address))
}

/// The logs of the listed tokens' transfers over `from..=to` in one direction.
async fn logs(
    cx: &Cx<'_>,
    b: &Mutex<&mut Budget>,
    from: u64,
    to: u64,
    head: u64,
    sent: bool,
) -> Result<Vec<Value>, Refused> {
    let me = cx.req.address.evm().map_err(Refused::Down)?;
    let contracts: Vec<&str> = cx.network.tokens().iter().map(|t| t.contract).collect();
    let topics = if sent {
        json!([TRANSFER, topic_of(&me)])
    } else {
        json!([TRANSFER, null, topic_of(&me)])
    };
    let params = json!([{
        "address": contracts,
        "topics": topics,
        "fromBlock": format!("0x{from:x}"),
        "toBlock": format!("0x{to:x}"),
    }]);
    let (span, depth) = (to - from + 1, head.saturating_sub(from));
    let mut avoid: Vec<usize> = Vec::new();
    for _ in 0..TRIES {
        if !b.lock().is_ok_and(|mut b| b.take(cx.net.now())) {
            return Err(Refused::Budget);
        }
        let Raw { index, outcome } =
            cx.net.rpc_raw(Need::logs(span, depth), &avoid, "eth_getLogs", &params).await.map_err(
                |e| match e {
                    // A wide query that no endpoint answered in time is likelier too
                    // heavy than every endpoint down: try a narrower one.
                    ChainError::Unavailable if span > HEAVY_SPAN => Refused::Narrower(span / 4),
                    e => Refused::Down(e),
                },
            )?;
        match outcome {
            Ok(Value::Array(list)) => return Ok(list),
            Ok(_) => avoid.push(index),
            Err(error) => match read_refusal(&error) {
                Reading::TooMany => return Err(Refused::Narrower((span / 2).max(1))),
                Reading::TooWide(cap) => {
                    let cap = cap.map_or(span / 2, |c| c.min(span.saturating_sub(1)).max(1));
                    cx.net.learn_span(index, cap);
                    return Err(Refused::Narrower(cap));
                }
                Reading::TooDeep => {
                    cx.net.learn_depth(index, depth.saturating_sub(1));
                    return Err(Refused::Deeper);
                }
                Reading::Other => avoid.push(index),
            },
        }
    }
    Err(Refused::Down(ChainError::Unavailable))
}

/// A transfer log as an item, if it is a listed token's ERC-20 `Transfer` that
/// involves the address.
fn item_of(cx: &Cx<'_>, scan: &Scan, head: u64, log: &Value) -> Option<Item> {
    let me = cx.req.address.evm().ok()?;
    let topics = log.get("topics")?.as_array()?;
    // An ERC-721 transfer has the token id as a fourth topic.
    if topics.len() != 3 || topics[0].as_str()? != TRANSFER {
        return None;
    }
    let address_of = |t: &Value| -> Option<[u8; 20]> {
        let bytes = bytes_from_hex(t.as_str()?)?;
        bytes.get(12..32)?.try_into().ok()
    };
    let (from, to) = (address_of(&topics[1])?, address_of(&topics[2])?);
    let token = cx.network.token_by_contract(log.get("address")?.as_str()?)?;
    let amount = word_to_u128(&bytes_from_hex(log.get("data")?.as_str()?)?)?;
    let (sent, got) = (from == me, to == me);
    if !(sent || got) {
        return None;
    }
    let block = quantity(log.get("blockNumber")?)?;
    let index = quantity(log.get("logIndex")?).unwrap_or(0);
    let hash = log.get("transactionHash")?.as_str()?.to_ascii_lowercase();
    let time = log
        .get("blockTimestamp")
        .and_then(quantity)
        .unwrap_or_else(|| time_of(cx.network, scan, head, block));
    let direction = match (sent, got) {
        (true, true) => Direction::SelfSent,
        (true, false) => Direction::Out,
        _ => Direction::In,
    };
    let other = if sent && !got { to } else { from };
    let mut item = Item::new(format!("{hash}:{index}"), hash, time, direction, token.symbol);
    item.order = (block << 20) | (index & 0xf_ffff);
    item.contract = Some(token.contract.to_owned());
    item.amount = amount;
    item.decimals = token.decimals;
    item.counterparty = Some(nc_wallet_core::evm::checksum_address(&other));
    item.block = Some(block);
    item.fee_todo = sent;
    Some(item)
}

/// Reads `from..=to` in both directions and merges what it finds.
async fn read(
    cx: &Cx<'_>,
    b: &mut Budget,
    st: &mut State,
    scan: &Scan,
    head: u64,
    from: u64,
    to: u64,
) -> Result<usize, Refused> {
    // The two directions are asked side by side: the wait is one query's, not two.
    let budget = Mutex::new(&mut *b);
    let (received, sent) = futures::future::join(
        logs(cx, &budget, from, to, head, false),
        logs(cx, &budget, from, to, head, true),
    )
    .await;
    let (received, sent) = (received?, sent?);
    let items: Vec<Item> =
        received.iter().chain(sent.iter()).filter_map(|log| item_of(cx, scan, head, log)).collect();
    let found = items.len();
    for item in &items {
        if item.direction == Direction::Out
            && let Some(peer) = &item.counterparty
        {
            st.remember_sent_to(peer);
        }
    }
    st.merge(items);
    Ok(found)
}

/// The least span worth reading with: an endpoint that answers fewer blocks a
/// query is used for nothing the scan does.
const MIN_USEFUL_SPAN: u64 = 1_000;
/// A log query over more blocks than this can be too heavy for an endpoint to
/// answer in time, which looks like the endpoint being down.
const HEAVY_SPAN: u64 = 2_000;
/// A reach under this, over more windows than [`MAX_WINDOWS`], is not walked.
const CRAWL_BELOW: u64 = 5_000;
/// The most windows of a narrow reach the scan will take on.
const MAX_WINDOWS: u64 = 400;

/// What the endpoints can serve now (or at all, for `ever`).
fn deepest(cx: &Cx<'_>, ever: bool) -> Option<u64> {
    if ever {
        cx.net.log_deepest_ever(MIN_USEFUL_SPAN)
    } else {
        cx.net.log_deepest(MIN_USEFUL_SPAN)
    }
}

fn reach(cx: &Cx<'_>, depth: u64, ever: bool) -> Option<u64> {
    if ever {
        cx.net.log_reach_ever(depth, MIN_USEFUL_SPAN)
    } else {
        cx.net.log_reach(depth, &[], MIN_USEFUL_SPAN)
    }
}

/// A window `from..=to` for reading back from `to`, no wider than `width`,
/// within what some endpoint serves. `None`: no endpoint reaches this far back
/// with a span worth reading, or the only ones that do would take too many
/// windows. With `ever`, endpoints resting for now count: is it possible at all?
fn window_back(cx: &Cx<'_>, head: u64, to: u64, width: u64, ever: bool) -> Option<(u64, u64)> {
    let floor = floor_block(cx.network);
    let deepest = deepest(cx, ever)?;
    let mut len = width.min(to + 1 - floor.min(to + 1));
    let nearest = head.saturating_sub(deepest);
    if to < nearest || len == 0 {
        return None;
    }
    // Start from what the nearest end allows, and shrink while the far end asks
    // for more than its endpoints give.
    len = len.min(reach(cx, head.saturating_sub(to), ever)?);
    for _ in 0..4 {
        let from = (to + 1 - len).max(floor).max(nearest);
        let wide = reach(cx, head.saturating_sub(from), ever)?;
        let span = to - from + 1;
        if span <= wide {
            // A narrow reach over a long stretch is a crawl, not a scan.
            if wide < CRAWL_BELOW && (to + 1 - floor) / wide > MAX_WINDOWS {
                return None;
            }
            return Some((from, to));
        }
        len = wide;
    }
    None
}

/// A window `from..=to` for reading forward from `from`.
fn window_forward(cx: &Cx<'_>, head: u64, from: u64, width: u64) -> Option<(u64, u64)> {
    let deepest = deepest(cx, false)?;
    let from = from.max(head.saturating_sub(deepest));
    let mut len = width.min(head - from + 1);
    for _ in 0..4 {
        let wide = reach(cx, head.saturating_sub(from), false)?;
        if len <= wide {
            return Some((from, from + len - 1));
        }
        len = wide;
    }
    None
}

async fn head_block(cx: &Cx<'_>, b: &mut Budget) -> ChainResult<u64> {
    if !b.take(cx.net.now()) {
        return Err(ChainError::Busy { retry_after_seconds: 1 });
    }
    let answer = cx.net.rpc(Need::ANY, "eth_blockNumber", &json!([])).await?;
    // A head past any block number a chain will reach is a node making things up: the arithmetic on
    // block numbers (windows, depths) is done on numbers well inside a u64.
    answer
        .ok()
        .as_ref()
        .and_then(quantity)
        .filter(|head| *head <= MOST_BLOCK)
        .ok_or(ChainError::Unavailable)
}

/// The highest block number believed (2^48: a block a second for nine million years).
const MOST_BLOCK: u64 = 1 << 48;

/// Reads what is newer than the state; with no state, only finds the head.
pub(super) async fn update(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let head = head_block(cx, b).await?;
    st.head = Some(head);
    let scan = match scan_of(st) {
        Some(mut scan) => {
            scan.head_time = cx.now;
            scan
        }
        // Nothing read yet: the reading goes back from here.
        None => Scan { hi: head, lo: head + 1, width: u64::MAX, head_time: cx.now },
    };
    put_scan(st, scan);
    catch_up(cx, b, st, head).await;
    Ok(())
}

/// Reads forward from `hi` to the head, as far as the budget goes.
async fn catch_up(cx: &Cx<'_>, b: &mut Budget, st: &mut State, head: u64) {
    while let Some(mut scan) = scan_of(st) {
        if scan.hi >= head {
            return;
        }
        let Some((from, to)) = window_forward(cx, head, scan.hi + 1, scan.width) else {
            // Nothing reaches this far back: what is between is not read, and the
            // reading starts again from what can be.
            if let Some(deepest) = deepest(cx, false) {
                scan.lo = head.saturating_sub(deepest).max(scan.hi + 1);
                scan.hi = head;
                put_scan(st, scan);
            }
            return;
        };
        if from > scan.hi + 1 {
            // A gap no endpoint reaches: the contiguous history now begins here.
            scan.lo = from;
        }
        match read(cx, b, st, &scan, head, from, to).await {
            Ok(_) => {
                scan.hi = to;
                put_scan(st, scan);
            }
            Err(Refused::Narrower(width)) => {
                scan.width = width;
                put_scan(st, scan);
            }
            Err(Refused::Deeper) => {}
            Err(Refused::Budget | Refused::Down(_)) => return,
        }
        if !b.any() {
            return;
        }
    }
}

/// One step back: reads a window before the oldest block read.
pub(super) async fn extend(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let (Some(mut scan), Some(head)) = (scan_of(st), st.head) else { return Ok(()) };
    if scan.hi < head {
        catch_up(cx, b, st, head).await;
        return Ok(());
    }
    let floor = floor_block(cx.network);
    for _ in 0..TRIES {
        if scan.lo <= floor || scan.lo == 0 {
            return Ok(());
        }
        let Some((from, to)) = window_back(cx, head, scan.lo - 1, scan.width, false) else {
            return Ok(());
        };
        match read(cx, b, st, &scan, head, from, to).await {
            Ok(found) => {
                scan.lo = from;
                // Read quickly when there is little: widen.
                scan.width = if found < 1_000 { scan.width.saturating_mul(2) } else { scan.width };
                put_scan(st, scan);
                return Ok(());
            }
            Err(Refused::Narrower(width)) => {
                scan.width = width.min(to - from + 1);
                put_scan(st, scan);
            }
            Err(Refused::Deeper) => {}
            Err(Refused::Budget) => return Ok(()),
            Err(Refused::Down(e)) => return Err(e),
        }
    }
    Ok(())
}

/// What the state covers: the coin from first sight, the tokens as far back as
/// the scan has gone.
pub(super) fn coverage(cx: &Cx<'_>, st: &State) -> Coverage {
    let coin =
        Part { scope: "coin", kind: "from_first_sight", complete: true, from: Some(st.first_seen) };
    let tokens = match (scan_of(st), st.head) {
        (Some(scan), Some(head)) => {
            let reached = scan.lo <= floor_block(cx.network);
            let caught_up = scan.hi >= head;
            let from = (!reached).then(|| time_of(cx.network, &scan, head, scan.lo));
            let complete = reached && caught_up;
            let kind = if reached { "full" } else { "partial" };
            Part { scope: "tokens", kind, complete, from }
        }
        _ => Part { scope: "tokens", kind: "partial", complete: false, from: None },
    };
    let mut c = Coverage::of_parts(vec![coin, tokens]);
    // Nothing more can be read when no endpoint reaches the next block back.
    if !c.complete
        && let (Some(scan), Some(head)) = (scan_of(st), st.head)
        && scan.hi >= head
        && scan.lo > floor_block(cx.network)
        && window_back(cx, head, scan.lo - 1, u64::MAX, true).is_none()
    {
        c.stuck = true;
    }
    c
}

// ---- receipts: fees, and sends that did or did not happen --------------------

/// The fee a receipt shows: the units used at the price paid, and on an OP-stack
/// rollup the L1 data fee.
fn fee_of(receipt: &Value) -> Option<u128> {
    let hex = |k: &str| receipt.get(k).and_then(Value::as_str).and_then(u128_from_hex);
    let fee = hex("gasUsed")?.checked_mul(hex("effectiveGasPrice")?)?;
    Some(fee.saturating_add(hex("l1Fee").unwrap_or(0)))
}

async fn receipt(cx: &Cx<'_>, b: &mut Budget, hash: &str) -> Option<Value> {
    if !b.take(cx.net.now()) {
        return None;
    }
    let got = cx.net.rpc(Need::RECEIPTS, "eth_getTransactionReceipt", &json!([hash])).await.ok()?;
    got.ok().filter(|r| !r.is_null())
}

/// Settles what the app sent: a send of the coin becomes an item once its
/// receipt exists; a token send that failed becomes a failed call; one nothing
/// has heard of for three days is forgotten. A token send that succeeded is left
/// for the logs to bring (they replace the note).
pub(super) async fn settle_notes(cx: &Cx<'_>, b: &mut Budget, st: &mut State) {
    let notes: Vec<Item> = st.notes.iter().take(RECEIPTS_PER_CALL).cloned().collect();
    for note in notes {
        let Some(r) = receipt(cx, b, &note.hash).await else {
            if cx.now.saturating_sub(note.time) > NOTE_LIFETIME_SECONDS {
                st.notes.retain(|n| n.hash != note.hash);
            }
            continue;
        };
        let ok = r.get("status").and_then(Value::as_str) != Some("0x0");
        let native = cx.network.is_native(&note.asset);
        if ok && !native {
            continue;
        }
        let mut item = note.clone();
        item.id = format!("{}:0", note.hash);
        item.status = if ok { Status::Confirmed } else { Status::Failed };
        item.block = r.get("blockNumber").and_then(quantity);
        item.order = item.block.map_or(0, |b| b << 20);
        item.fee = fee_of(&r).or(note.fee);
        if !ok {
            item.kind = Kind::Call;
            item.amount = 0;
        }
        st.notes.retain(|n| n.hash != note.hash);
        st.merge(vec![item]);
    }
}

/// Fills in the fee of outgoing transfers from their receipts, a few a call.
pub(super) async fn finish(cx: &Cx<'_>, b: &mut Budget, st: &mut State) {
    let todo: Vec<String> = {
        let mut hashes: Vec<String> = Vec::new();
        for item in st.items.iter().filter(|i| i.fee_todo) {
            if !hashes.contains(&item.hash) {
                hashes.push(item.hash.clone());
            }
            if hashes.len() >= RECEIPTS_PER_CALL {
                break;
            }
        }
        hashes
    };
    for hash in todo {
        let Some(r) = receipt(cx, b, &hash).await else { break };
        let fee = fee_of(&r);
        let mut first = true;
        for item in st.items.iter_mut().filter(|i| i.hash == hash) {
            item.fee_todo = false;
            // One fee to a transaction, on its first item.
            item.fee = if first { fee } else { None };
            first = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(message: &str) -> NodeError {
        NodeError { code: -32000, message: message.to_owned(), data: None }
    }

    #[test]
    fn what_the_endpoints_really_said_is_read_as_what_it_means() {
        // Verbatim from the live endpoints, 2026-10-28.
        let cases = [
            (
                "Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode",
                Reading::TooDeep,
            ),
            (
                "ranges over 10000 blocks are not supported on free plan",
                Reading::TooWide(Some(10_000)),
            ),
            ("eth_getLogs is limited to 0 - 50 blocks range", Reading::TooWide(Some(50))),
            (
                "Invalid eth_getLogs request. 'fromBlock'-'toBlock' range too large. Max range: 800",
                Reading::TooWide(Some(800)),
            ),
            (
                "You can make eth_getLogs requests with up to a 10 block range. Based on your parameters",
                Reading::TooWide(Some(10)),
            ),
            ("log query range must not exceed 25 blocks", Reading::TooWide(Some(25))),
            ("exceed maximum block range: 5000", Reading::TooWide(Some(5_000))),
            ("Block range too large for public access", Reading::TooWide(None)),
            (
                "Query returned more than 20000 results. Try with this block range [0x1, 0x2].",
                Reading::TooMany,
            ),
            (
                "Log response size exceeded. You can make eth_getLogs requests with up to a 10,000 logs",
                Reading::TooMany,
            ),
            ("header not found", Reading::TooDeep),
            ("something else went wrong", Reading::Other),
            ("Too Many Requests", Reading::Other),
        ];
        for (words, expected) in cases {
            assert_eq!(read_refusal(&node(words)), expected, "{words}");
        }
    }

    #[test]
    fn a_receipts_fee_is_the_units_used_at_the_price_paid_plus_the_l1_fee() {
        let receipt = json!({ "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00" });
        assert_eq!(fee_of(&receipt), Some(21_000 * 1_000_000_000));
        let base = json!({ "gasUsed": "0x5208", "effectiveGasPrice": "0x1", "l1Fee": "0x10" });
        assert_eq!(fee_of(&base), Some(21_000 + 16));
        assert_eq!(fee_of(&json!({})), None);
    }

    #[test]
    fn a_block_has_a_time_counted_back_from_the_head() {
        let scan = Scan { hi: 0, lo: 0, width: 0, head_time: 1_000_000 };
        assert_eq!(time_of(Network::Ethereum, &scan, 100, 90), 1_000_000 - 120);
        assert_eq!(time_of(Network::Base, &scan, 100, 0), 1_000_000 - 200);
        assert_eq!(time_of(Network::Ethereum, &scan, 100, 200), 1_000_000);
    }

    #[test]
    fn numbers_are_read_out_of_words() {
        assert_eq!(last_number("exceed maximum block range: 5000"), Some(5_000));
        assert_eq!(last_number("up to a 10,000 logs"), Some(10_000));
        assert_eq!(last_number("no digits"), None);
    }
}

#[cfg(test)]
mod hostile {
    use super::*;

    #[test]
    fn a_receipt_made_up_never_overflows_a_fee() {
        let receipt = |used: &str, price: &str, l1: &str| json!({ "gasUsed": used, "effectiveGasPrice": price, "l1Fee": l1 });
        let max = "0xffffffffffffffffffffffffffffffff";
        assert_eq!(fee_of(&receipt(max, max, max)), None, "the product does not fit");
        assert_eq!(fee_of(&receipt("0x1", max, max)), Some(u128::MAX), "the sum saturates");
        assert_eq!(fee_of(&receipt("0x5208", "0x3b9aca00", "0x0")), Some(21_000_000_000_000));
    }

    #[test]
    fn a_time_worked_out_from_a_head_made_up_does_not_wrap() {
        let scan = Scan { hi: u64::MAX, lo: 0, width: u64::MAX, head_time: u64::MAX };
        for network in [Network::Ethereum, Network::Bsc, Network::Polygon, Network::Base] {
            let _ = time_of(network, &scan, u64::MAX, 0);
            let _ = time_of(network, &scan, 0, u64::MAX);
        }
    }
}
