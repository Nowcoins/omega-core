//! A second operator's agreement, before an item is called confirmed.
//!
//! A history is read from one source (a listing endpoint, a log query); one operator, or
//! anything between the device and it, could invent a payment that never was ("received"),
//! or say that a payment which is not mined is. So an item the source calls confirmed (or
//! failed) is shown as `pending` with `unverified: true` until **two independent operators**
//! have the transaction in the same block with the same effect on this account (the
//! machinery is [`Need::independent`]: two operators, never two hosts of one). It is checked
//! once: the item is then `verified` and kept so (in the state, and across a refresh that reads
//! the same facts again).
//!
//! # What it costs the endpoints
//!
//! Lazily, and bounded: at most [`ITEMS_PER_CALL`] items a call, newest first, two requests
//! each (one to each of two operators), inside a budget of [`REQUESTS_PER_CALL`]; only items
//! dated within [`WINDOW_SECONDS`] (a week). An item is checked once ever, so a wallet that
//! receives a payment a day costs two requests a day. An older item is not checked: nothing acts on
//! history that old, and a first sync of a long history does not ask for thousands of
//! second opinions. (A source can date an invented item as old as it likes; that is the
//! limit of the window.)
//!
//! # What each network's second opinion is
//!
//! | Network | Asked | Agreement |
//! |---|---|---|
//! | EVM | `eth_getTransactionReceipt` of two operators | the same outcome in the same block; for a token, a `Transfer` log of the token for this amount to or from this address |
//! | Bitcoin | `/tx/{id}` of two Esplora services | the item read again from each is the same: direction, amount, block |
//! | Solana | `getTransaction` of two operators | the item read again from each is the same |
//! | Stellar | Horizon `/transactions/{hash}` of two operators | successful, in the same ledger |
//! | TRON | `gettransactioninfobyid` of two nodes | in the same block, with a successful result |
//!
//! Stellar and TRON agree on the transaction's place and success, not on its amounts: those
//! rest on the listing source alone. Bittensor has no listing to check (its sends are settled by the
//! account's nonce on chain, from two operators, `firstsight.rs`), so it is not checked here.

use serde_json::{Value, json};

use super::store::{Direction, Item, Kind, State, Status};
use super::{Budget, Cx, bitcoin, solana};
use crate::networks::{Family, Network};
use crate::pool::Need;

/// Items dated within this long ago are checked.
pub(super) const WINDOW_SECONDS: u64 = 7 * 86_400;
/// Items checked in one call.
const ITEMS_PER_CALL: usize = 4;
/// Requests the checks of one call may make.
const REQUESTS_PER_CALL: u32 = 12;
const TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// Whether an item is one the source calls settled that no second operator has agreed to yet.
pub(super) fn awaiting(item: &Item, network: Network, now: u64) -> bool {
    network.family() != Family::Substrate
        && item.status != Status::Pending
        && !item.verified
        && !item.observed
        && !item.hash.is_empty()
        && now.saturating_sub(item.time) <= WINDOW_SECONDS
}

/// Checks a few of the items that await it, newest first, and marks those that two operators
/// confirm.
pub(super) async fn run(cx: &Cx<'_>, st: &mut State) {
    let todo: Vec<Item> = st
        .items
        .iter()
        .filter(|i| awaiting(i, cx.network, cx.now))
        .take(ITEMS_PER_CALL)
        .cloned()
        .collect();
    if todo.is_empty() {
        return;
    }
    let mut b = Budget::new(REQUESTS_PER_CALL, cx.net.now());
    for item in todo {
        if !b.any() {
            break;
        }
        if agrees(cx, &mut b, st, &item).await
            && let Some(held) = st.items.iter_mut().find(|h| h.id == item.id)
        {
            held.verified = true;
        }
    }
}

async fn agrees(cx: &Cx<'_>, b: &mut Budget, st: &State, item: &Item) -> bool {
    // Two requests, one to each of two operators; with fewer granted, no opinion.
    if b.take_up_to(2, cx.net.now()) < 2 {
        return false;
    }
    match cx.network.family() {
        Family::Evm => evm(cx, item).await,
        Family::Bitcoin => bitcoin_tx(cx, st, item).await,
        Family::Solana => solana_tx(cx, item).await,
        Family::Stellar => stellar_tx(cx, item).await,
        Family::Tron => tron_tx(cx, item).await,
        Family::Substrate => false,
    }
}

fn want_hex(hash: &str, digits: usize) -> bool {
    hash.len() == digits && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---- EVM ---------------------------------------------------------------------

async fn evm(cx: &Cx<'_>, item: &Item) -> bool {
    if !(item.hash.len() == 66 && item.hash.starts_with("0x") && want_hex(&item.hash[2..], 64)) {
        return false;
    }
    let Ok(answers) = cx
        .net
        .rpc_many(Need::RECEIPTS.independent(), 2, "eth_getTransactionReceipt", &json!([item.hash]))
        .await
    else {
        return false;
    };
    answers.len() == 2
        && answers
            .iter()
            .all(|(answer, _)| matches!(answer, Ok(receipt) if receipt_fits(cx, item, receipt)))
}

/// Whether a receipt is this item: the outcome and block, and for a token the transfer.
fn receipt_fits(cx: &Cx<'_>, item: &Item, receipt: &Value) -> bool {
    if receipt.is_null() {
        return false;
    }
    let ok = receipt.get("status").and_then(Value::as_str) != Some("0x0");
    let block = receipt
        .get("blockNumber")
        .and_then(Value::as_str)
        .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok());
    if ok != (item.status == Status::Confirmed) || block.is_none() {
        return false;
    }
    if item.block.is_some() && item.block != block {
        return false;
    }
    let (Some(contract), true) = (&item.contract, ok && item.kind == Kind::Transfer) else {
        return true;
    };
    let me = cx.req.address.text.trim_start_matches("0x").to_lowercase();
    let party = |topic: Option<&Value>| {
        topic.and_then(Value::as_str).is_some_and(|t| t.to_lowercase().ends_with(&me))
    };
    receipt.get("logs").and_then(Value::as_array).is_some_and(|logs| {
        logs.iter().any(|log| {
            let topics = log.get("topics").and_then(Value::as_array);
            let topic = |n: usize| topics.and_then(|t| t.get(n));
            let value = log
                .get("data")
                .and_then(Value::as_str)
                .and_then(|d| d.strip_prefix("0x"))
                .filter(|d| d.len() == 64 && d[..32].bytes().all(|b| b == b'0'))
                .and_then(|d| u128::from_str_radix(&d[32..], 16).ok());
            log.get("address")
                .and_then(Value::as_str)
                .is_some_and(|a| a.eq_ignore_ascii_case(contract))
                && topic(0).and_then(Value::as_str) == Some(TRANSFER)
                && value == Some(item.amount)
                && match item.direction {
                    Direction::In => party(topic(2)),
                    Direction::Out => party(topic(1)),
                    Direction::SelfSent => party(topic(1)) && party(topic(2)),
                }
        })
    })
}

// ---- Bitcoin -----------------------------------------------------------------

async fn bitcoin_tx(cx: &Cx<'_>, st: &State, item: &Item) -> bool {
    if !want_hex(&item.hash, 64) {
        return false;
    }
    let Ok(answers) =
        cx.net.get_many(Need::ANY.independent(), 2, &format!("/tx/{}", item.hash)).await
    else {
        return false;
    };
    let book = bitcoin::book_of(st);
    let own = bitcoin::own_set(&book);
    answers.len() == 2
        && answers.iter().all(|((status, body), _)| {
            *status == 200
                && serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|tx| bitcoin::item_of(&tx, &own, None, cx.now))
                    .is_some_and(|read| same_effect(&read, item))
        })
}

// ---- Solana ------------------------------------------------------------------

async fn solana_tx(cx: &Cx<'_>, item: &Item) -> bool {
    let signature = item.hash.as_str();
    let params = json!([signature, {
        "encoding": "jsonParsed",
        "maxSupportedTransactionVersion": 0,
        "commitment": "confirmed",
    }]);
    let Ok(answers) = cx
        .net
        .rpc_many(Need::method("getTransaction").independent(), 2, "getTransaction", &params)
        .await
    else {
        return false;
    };
    answers.len() == 2
        && answers.iter().all(|(answer, _)| {
            matches!(answer, Ok(tx) if !tx.is_null()
                && solana::items_in(tx, signature, &cx.req.address.text)
                    .iter()
                    .any(|read| read.id == item.id && same_effect(read, item)))
        })
}

// ---- Stellar -----------------------------------------------------------------

async fn stellar_tx(cx: &Cx<'_>, item: &Item) -> bool {
    if !want_hex(&item.hash, 64) {
        return false;
    }
    let Ok(answers) =
        cx.net.get_many(Need::ANY.independent(), 2, &format!("/transactions/{}", item.hash)).await
    else {
        return false;
    };
    answers.len() == 2
        && answers.iter().all(|((status, body), _)| {
            let Some(tx) =
                (*status == 200).then(|| serde_json::from_slice::<Value>(body).ok()).flatten()
            else {
                return false;
            };
            tx.get("hash")
                .and_then(Value::as_str)
                .is_some_and(|h| h.eq_ignore_ascii_case(&item.hash))
                && tx.get("successful").and_then(Value::as_bool)
                    == Some(item.status == Status::Confirmed)
                && (item.block.is_none() || tx.get("ledger").and_then(Value::as_u64) == item.block)
        })
}

// ---- TRON --------------------------------------------------------------------

async fn tron_tx(cx: &Cx<'_>, item: &Item) -> bool {
    if !want_hex(&item.hash, 64) {
        return false;
    }
    let body = json!({ "value": item.hash }).to_string();
    let Ok(answers) = cx
        .net
        .post_many(
            Need::ANY.independent(),
            2,
            "/wallet/gettransactioninfobyid",
            "application/json",
            body.as_bytes(),
        )
        .await
    else {
        return false;
    };
    answers.len() == 2
        && answers.iter().all(|((status, body), _)| {
            let Some(info) =
                (*status == 200).then(|| serde_json::from_slice::<Value>(body).ok()).flatten()
            else {
                return false;
            };
            let result = info.pointer("/receipt/result").and_then(Value::as_str);
            info.get("id")
                .and_then(Value::as_str)
                .is_some_and(|h| h.eq_ignore_ascii_case(&item.hash))
                && info.get("blockNumber").and_then(Value::as_u64).is_some()
                && (item.block.is_none()
                    || info.get("blockNumber").and_then(Value::as_u64) == item.block)
                && (item.status != Status::Confirmed || result.is_none_or(|r| r == "SUCCESS"))
        })
}

/// Whether a re-read item has the same effect on the account as the held one.
fn same_effect(read: &Item, held: &Item) -> bool {
    read.status == held.status
        && read.direction == held.direction
        && read.asset == held.asset
        && read.contract == held.contract
        && read.amount == held.amount
        && read.block == held.block
}
