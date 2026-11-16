//! Stellar, from Horizon's `/accounts/{id}/payments` (the Foundation's, LOBSTR's,
//! Ankr's), with each operation's transaction joined in: its fee, who paid it,
//! its memo, its ledger, whether it succeeded.
//!
//! Horizon pages by a token: `order=desc&cursor=<oldest token>` reads back, and
//! `order=asc&cursor=<newest token>` reads what came after. An operation makes
//! the items it moved: a payment is one (or, to oneself, a move); a path payment
//! that swaps an asset for another the account holds is two, what left and what
//! arrived; an account created or merged is a transfer or a call. A failed
//! operation moved nothing, and cost its fee if the account sent it.

use serde_json::Value;

use super::store::{Direction, Item, Kind, State, Status};
use super::{Budget, Coverage, Cx, get_json};
use crate::error::ChainResult;
use crate::networks::Network;
use crate::util::{parse_rfc3339, stroops};

/// Operations asked for at once.
const LIMIT: usize = 40;

fn is_page(v: &Value) -> bool {
    v.pointer("/_embedded/records").is_some_and(Value::is_array)
}

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// A listed asset an operation names, with its ticker, contract and decimals.
type Asset = (&'static str, Option<&'static str>, u8);

/// The listed asset named by `(type, code, issuer)`, and `amount` of it, if it is
/// listed and the amount is more than nothing.
fn listed(kind: &str, code: &str, issuer: &str, amount: &str) -> Option<(Asset, u128)> {
    let amount = stroops(amount).filter(|a| *a > 0)?;
    if kind == "native" {
        let n = Network::Stellar.native();
        return Some(((n.symbol, None, n.decimals), amount));
    }
    let token =
        Network::Stellar.tokens().iter().find(|t| t.symbol == code && t.contract == issuer)?;
    Some(((token.symbol, Some(token.contract), token.decimals), amount))
}

/// What the items of one operation share.
struct Frame<'a> {
    op: &'a Value,
    time: u64,
    order: u64,
    status: Status,
    block: Option<u64>,
    memo: Option<String>,
}

impl Frame<'_> {
    fn make(
        &self,
        n: usize,
        dir: Direction,
        (symbol, contract, decimals): Asset,
        amount: u128,
        peer: Option<&str>,
        kind: Kind,
    ) -> Item {
        let hash = text(self.op, "transaction_hash");
        let mut item = Item::new(
            format!("{}:{n}", text(self.op, "paging_token")),
            hash.to_owned(),
            self.time,
            dir,
            symbol,
        );
        item.kind = kind;
        item.order = self.order;
        item.contract = contract.map(str::to_owned);
        item.amount = amount;
        item.decimals = decimals;
        item.counterparty = peer.filter(|p| !p.is_empty()).map(str::to_owned);
        item.status = self.status;
        item.block = self.block;
        item.memo.clone_from(&self.memo);
        item
    }
}

/// The items one operation made for `me`.
fn items_of(op: &Value, me: &str) -> Vec<Item> {
    let Some(time) = parse_rfc3339(text(op, "created_at")) else { return Vec::new() };
    let tx = op.get("transaction");
    let ok = op.get("transaction_successful").and_then(Value::as_bool) == Some(true);
    let source = text(op, "source_account");
    let payer =
        tx.map(|t| Some(text(t, "fee_account")).filter(|a| !a.is_empty()).unwrap_or(source));
    let fee = (payer == Some(me))
        .then(|| tx.and_then(|t| text(t, "fee_charged").parse::<u128>().ok()))
        .flatten();
    let frame = Frame {
        op,
        time,
        order: text(op, "paging_token").parse().unwrap_or(0),
        status: if ok { Status::Confirmed } else { Status::Failed },
        block: tx.and_then(|t| t.get("ledger")).and_then(Value::as_u64).filter(|l| *l > 0),
        memo: tx
            .filter(|t| {
                matches!(text(t, "memo_type"), "text" | "id") && !text(t, "memo").is_empty()
            })
            .map(|t| text(t, "memo").to_owned()),
    };
    let coin = || {
        let n = Network::Stellar.native();
        (n.symbol, None, n.decimals)
    };
    let mut items: Vec<Item> = Vec::new();
    let kind = text(op, "type");
    if ok {
        match kind {
            "payment" | "path_payment_strict_send" | "path_payment_strict_receive" => {
                let (from, to) = (text(op, "from"), text(op, "to"));
                let (sent, got) = (from == me, to == me);
                let path = kind != "payment";
                let arrives = listed(
                    text(op, "asset_type"),
                    text(op, "asset_code"),
                    text(op, "asset_issuer"),
                    text(op, "amount"),
                );
                let leaves = if path {
                    listed(
                        text(op, "source_asset_type"),
                        text(op, "source_asset_code"),
                        text(op, "source_asset_issuer"),
                        text(op, "source_amount"),
                    )
                } else {
                    arrives
                };
                if sent
                    && (!got || path)
                    && let Some((asset, amount)) = leaves
                {
                    items.push(frame.make(
                        items.len(),
                        Direction::Out,
                        asset,
                        amount,
                        (!got).then_some(to),
                        Kind::Transfer,
                    ));
                }
                if got
                    && (!sent || path)
                    && let Some((asset, amount)) = arrives
                {
                    items.push(frame.make(
                        items.len(),
                        Direction::In,
                        asset,
                        amount,
                        (!sent).then_some(from),
                        Kind::Transfer,
                    ));
                }
                if sent
                    && got
                    && !path
                    && let Some((asset, amount)) = arrives
                {
                    items.push(frame.make(
                        items.len(),
                        Direction::SelfSent,
                        asset,
                        amount,
                        Some(me),
                        Kind::Transfer,
                    ));
                }
            }
            "create_account" => {
                let funds = stroops(text(op, "starting_balance")).filter(|a| *a > 0);
                match funds {
                    Some(amount) if text(op, "funder") == me => {
                        items.push(frame.make(
                            0,
                            Direction::Out,
                            coin(),
                            amount,
                            Some(text(op, "account")),
                            Kind::Transfer,
                        ));
                    }
                    Some(amount) if text(op, "account") == me => {
                        items.push(frame.make(
                            0,
                            Direction::In,
                            coin(),
                            amount,
                            Some(text(op, "funder")),
                            Kind::Transfer,
                        ));
                    }
                    _ => {}
                }
            }
            // The whole balance moves, and the record does not say how much.
            "account_merge" if text(op, "account") == me => {
                items.push(frame.make(
                    0,
                    Direction::Out,
                    coin(),
                    0,
                    Some(text(op, "into")),
                    Kind::Call,
                ));
            }
            _ => {}
        }
    } else {
        // A failed operation moved nothing: if the account sent it, it cost a fee.
        let sender = match kind {
            "create_account" => text(op, "funder"),
            "account_merge" => text(op, "account"),
            _ => text(op, "from"),
        };
        if sender == me || source == me {
            items.push(frame.make(0, Direction::Out, coin(), 0, None, Kind::Call));
        }
    }
    if let Some(first) = items.first_mut() {
        first.fee = fee;
    }
    items
}

fn tokens(records: &[Value]) -> (Option<String>, Option<String>) {
    let token = |r: &Value| r.get("paging_token").and_then(Value::as_str).map(str::to_owned);
    (records.first().and_then(token), records.last().and_then(token))
}

fn records_of(v: &Value) -> Vec<Value> {
    v.pointer("/_embedded/records").and_then(Value::as_array).cloned().unwrap_or_default()
}

fn path(me: &str, order: &str, cursor: Option<&str>) -> String {
    let mut p = format!(
        "/accounts/{me}/payments?order={order}&limit={LIMIT}&join=transactions&include_failed=true"
    );
    if let Some(c) = cursor {
        p.push_str("&cursor=");
        p.push_str(c);
    }
    p
}

/// Where the reading stands: the newest token, the oldest, and whether the
/// oldest operation has been read.
fn position(st: &State) -> (Option<String>, Option<String>, bool) {
    let s = st.src.get("xlm");
    let t = |k: &str| s.and_then(|s| s.get(k)).and_then(Value::as_str).map(str::to_owned);
    (t("top"), t("tail"), s.and_then(|s| s.get("done")).and_then(Value::as_bool) == Some(true))
}

fn put_position(st: &mut State, top: Option<&str>, tail: Option<&str>, done: bool) {
    let mut src = st.src.as_object().cloned().unwrap_or_default();
    src.insert("xlm".into(), serde_json::json!({ "top": top, "tail": tail, "done": done }));
    st.src = Value::Object(src);
}

fn merge(st: &mut State, records: &[Value], me: &str) {
    let items: Vec<Item> = records.iter().flat_map(|r| items_of(r, me)).collect();
    st.merge(items);
    st.fee_once_per_hash();
}

/// The first reading is the newest page; after that, what came after the newest
/// token, a page at a time.
pub(super) async fn update(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let me = cx.req.address.text.clone();
    let (mut top, mut tail, mut done) = position(st);
    let result = async {
        if top.is_none() {
            let (status, v) = get_json(cx, b, &path(&me, "desc", None), is_page).await?;
            let records = if status == 404 { Vec::new() } else { records_of(&v) };
            // An account Horizon has never heard of has no history at all.
            done = status == 404 || records.len() < LIMIT;
            let (newest, oldest) = tokens(&records);
            top = newest;
            tail = oldest;
            merge(st, &records, &me);
            return Ok(());
        }
        while b.any() {
            let (status, v) = get_json(cx, b, &path(&me, "asc", top.as_deref()), is_page).await?;
            let records = if status == 404 { Vec::new() } else { records_of(&v) };
            if let Some(last) =
                records.last().and_then(|r| r.get("paging_token")).and_then(Value::as_str)
            {
                top = Some(last.to_owned());
            }
            merge(st, &records, &me);
            if records.len() < LIMIT {
                break;
            }
        }
        Ok(())
    }
    .await;
    put_position(st, top.as_deref(), tail.as_deref(), done);
    result
}

/// One page further back.
pub(super) async fn extend(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    let me = cx.req.address.text.clone();
    let (top, mut tail, mut done) = position(st);
    if done || tail.is_none() {
        return Ok(());
    }
    let (status, v) = get_json(cx, b, &path(&me, "desc", tail.as_deref()), is_page).await?;
    let records = if status == 404 { Vec::new() } else { records_of(&v) };
    done = records.len() < LIMIT;
    if let (_, Some(oldest)) = tokens(&records) {
        tail = Some(oldest);
    }
    merge(st, &records, &me);
    put_position(st, top.as_deref(), tail.as_deref(), done);
    Ok(())
}

pub(super) fn coverage(st: &State) -> Coverage {
    let (top, _, done) = position(st);
    Coverage::single("full", done && (top.is_some() || st.items.is_empty()), None)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const ME: &str =
        "GBDEVU63Y6NTHJQQZIKVTC23NWLQVP3WJ2RI2OTSJTBO7BAIZA66X6QIBV5RMZZYXK4Q7ZSO52J5C3WQ";
    const YOU: &str = "GAFK7XFZHMLSNV7OJTBO7BAIZA66X6QIBV5RMZZYXK4Q7ZSO52J5C3WQ";

    fn op(value: &Value) -> Vec<Item> {
        items_of(value, ME)
    }

    fn payment(from: &str, to: &str, amount: &str, ok: bool) -> Value {
        json!({
            "type": "payment", "paging_token": "100", "transaction_successful": ok,
            "created_at": "2026-10-26T14:34:11Z", "transaction_hash": "abc", "source_account": from,
            "from": from, "to": to, "amount": amount, "asset_type": "native",
            "transaction": { "ledger": 7, "fee_account": from, "fee_charged": "100", "memo_type": "text", "memo": "rent" },
        })
    }

    #[test]
    fn a_payment_sent_has_the_fee_the_memo_and_the_ledger() {
        let items = op(&payment(ME, YOU, "5.0000000", true));
        assert_eq!(items.len(), 1);
        let i = &items[0];
        assert_eq!(
            (i.direction, i.amount, i.fee, i.block),
            (Direction::Out, 50_000_000, Some(100), Some(7))
        );
        assert_eq!(
            (i.counterparty.as_deref(), i.memo.as_deref(), i.asset.as_str()),
            (Some(YOU), Some("rent"), "XLM")
        );
        assert_eq!(i.time, 1_793_025_251);
    }

    #[test]
    fn a_payment_received_costs_nothing_and_an_unlisted_asset_is_not_shown() {
        let items = op(&payment(YOU, ME, "5.0000000", true));
        assert_eq!((items[0].direction, items[0].fee), (Direction::In, None));
        let mut other = payment(YOU, ME, "5.0000000", true);
        other["asset_type"] = json!("credit_alphanum4");
        other["asset_code"] = json!("SCAM");
        other["asset_issuer"] = json!(YOU);
        assert!(op(&other).is_empty());
        let mut usdc = payment(YOU, ME, "2.5000000", true);
        usdc["asset_type"] = json!("credit_alphanum4");
        usdc["asset_code"] = json!("USDC");
        usdc["asset_issuer"] = json!(ISSUER);
        let i = &op(&usdc)[0];
        assert_eq!(
            (i.asset.as_str(), i.contract.as_deref(), i.amount, i.decimals),
            ("USDC", Some(ISSUER), 25_000_000, 7)
        );
    }

    #[test]
    fn a_failed_operation_moved_nothing_and_cost_its_fee() {
        let items = op(&payment(ME, YOU, "5.0000000", false));
        assert_eq!(
            (items[0].kind, items[0].status, items[0].amount, items[0].fee),
            (Kind::Call, Status::Failed, 0, Some(100))
        );
        assert!(op(&payment(YOU, YOU, "5.0000000", false)).is_empty());
    }

    #[test]
    fn a_swap_is_two_items_what_left_and_what_arrived() {
        let swap = json!({
            "type": "path_payment_strict_send", "paging_token": "200", "transaction_successful": true,
            "created_at": "2026-10-26T14:34:11Z", "transaction_hash": "swap", "source_account": ME,
            "from": ME, "to": ME, "amount": "10.0000000", "asset_type": "credit_alphanum4",
            "asset_code": "USDC", "asset_issuer": ISSUER,
            "source_amount": "40.0000000", "source_asset_type": "native",
            "transaction": { "ledger": 8, "fee_account": ME, "fee_charged": "200" },
        });
        let items = op(&swap);
        assert_eq!(items.len(), 2);
        assert_eq!(
            (items[0].direction, items[0].asset.as_str(), items[0].amount),
            (Direction::Out, "XLM", 400_000_000)
        );
        assert_eq!(
            (items[1].direction, items[1].asset.as_str(), items[1].amount),
            (Direction::In, "USDC", 100_000_000)
        );
        assert_eq!((items[0].fee, items[1].fee), (Some(200), None), "the fee is paid once");
        assert_ne!(items[0].id, items[1].id);
    }

    #[test]
    fn creating_and_merging_accounts() {
        let created = json!({
            "type": "create_account", "paging_token": "300", "transaction_successful": true,
            "created_at": "2026-10-26T14:34:11Z", "transaction_hash": "c", "source_account": YOU,
            "funder": YOU, "account": ME, "starting_balance": "2.0000000",
            "transaction": { "ledger": 9, "fee_account": YOU, "fee_charged": "100" },
        });
        let i = &op(&created)[0];
        assert_eq!(
            (i.direction, i.amount, i.counterparty.as_deref(), i.fee),
            (Direction::In, 20_000_000, Some(YOU), None)
        );
        let merged = json!({
            "type": "account_merge", "paging_token": "400", "transaction_successful": true,
            "created_at": "2026-10-26T14:34:11Z", "transaction_hash": "m", "source_account": ME,
            "account": ME, "into": YOU,
            "transaction": { "ledger": 9, "fee_account": ME, "fee_charged": "100" },
        });
        let i = &op(&merged)[0];
        assert_eq!(
            (i.kind, i.direction, i.amount, i.counterparty.as_deref()),
            (Kind::Call, Direction::Out, 0, Some(YOU))
        );
    }

    #[test]
    fn the_fee_of_a_transaction_of_several_operations_is_kept_once_across_pages() {
        let mut st = State::new("t", 0);
        let mut a = payment(ME, YOU, "1.0000000", true);
        let mut b = payment(ME, YOU, "2.0000000", true);
        a["paging_token"] = json!("10");
        b["paging_token"] = json!("11");
        merge(&mut st, &[a], ME);
        merge(&mut st, &[b], ME);
        assert_eq!(st.items.iter().filter(|i| i.fee.is_some()).count(), 1);
    }
}

#[cfg(test)]
mod hostile {
    use super::*;
    use serde_json::json;

    const ME: &str =
        "GBDEVU63Y6NTHJQQZIKVTC23NWLQVP3WJ2RI2OTSJTBO7BAIZA66X6QIBV5RMZZYXK4Q7ZSO52J5C3WQ";

    #[test]
    fn amounts_fees_and_times_a_node_makes_up_never_panic() {
        let amounts = [
            "922337203685.4775807",
            "99999999999999999999999999999999999999999.9999999",
            "340282366920938463463374607431768211455",
            "-1",
            "1e30",
            "0.00000001",
            "",
        ];
        let years = ["2026", "9999", "99999", "9223372036854775807", "0000"];
        for amount in amounts {
            for year in years {
                let op = json!({
                    "type": "payment", "paging_token": u64::MAX.to_string(), "transaction_successful": true,
                    "created_at": format!("{year}-10-26T14:34:11Z"), "source_account": ME,
                    "from": ME, "to": ME, "amount": amount, "asset_type": "native",
                    "transaction": { "ledger": u64::MAX, "fee_account": ME,
                                     "fee_charged": "340282366920938463463374607431768211455" },
                });
                let _ = items_of(&op, ME);
            }
        }
    }
}
