//! What the device keeps of one address's history, and how a page is cut from it.
//!
//! The whole of it is one value, [`State`], which the app stores (sealed at rest
//! by the engine, so nothing here is encrypted) and hands back on the next call.
//! It is plain JSON with short keys and a version; a state this code does not
//! know the version of is dropped and the history read again, never guessed at.
//!
//! * **Items** are kept newest first, at most [`MAX_ITEMS`] of them: when there
//!   are more, the oldest are dropped and `dropped` says so (the explorer link
//!   covers them, and the scan continues from the newest, so nothing is lost
//!   that a person is likely to look for).
//! * **Notes** are what the app itself sent, shown as pending until the chain
//!   history has the transaction.
//! * **Source cursors** (`src`) are each family's own: where its next update and
//!   its next step back begin. They are opaque here.

use base64::Engine as _;
use serde_json::{Map, Value, json};

use crate::networks::Network;
use crate::util::rfc3339;

/// The most items kept.
pub const MAX_ITEMS: usize = 2_000;
/// The most addresses remembered as sent to (for spotting look-alikes).
pub const MAX_SENT_TO: usize = 200;
/// The most notes of unconfirmed sends kept.
pub const MAX_NOTES: usize = 40;
/// What a page holds unless asked for less or more.
pub const DEFAULT_PAGE: usize = 50;
/// The most a page may hold.
pub const MAX_PAGE: usize = 100;
/// The state's version.
const VERSION: u64 = 1;

/// A transfer, or a transaction that moved nothing of a listed asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An asset moved.
    Transfer,
    /// The address sent a transaction that moved nothing listed: an approval, a
    /// contract call, a failed transaction. It cost the fee.
    Call,
}

/// Which way an asset went, for the address asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Received.
    In,
    /// Sent.
    Out,
    /// From and to the account itself.
    SelfSent,
}

/// How far the transaction got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Seen, not in a block.
    Pending,
    /// In a block.
    Confirmed,
    /// In a block, and did nothing but cost the fee.
    Failed,
}

/// One entry of a history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Tells two items of one transaction apart; unique within the account.
    pub id: String,
    /// The transaction.
    pub hash: String,
    /// When it happened, Unix seconds (for an observed arrival: when it was seen).
    pub time: u64,
    /// Position within one time: the block, or the place in it.
    pub order: u64,
    /// Transfer or call.
    pub kind: Kind,
    /// In, out or self.
    pub direction: Direction,
    /// The ticker.
    pub asset: String,
    /// The token's contract, mint or issuer.
    pub contract: Option<String>,
    /// Base units; a sent amount does not include the fee.
    pub amount: u128,
    /// The asset's decimals.
    pub decimals: u8,
    /// The other side.
    pub counterparty: Option<String>,
    /// The fee this account paid, in the network's native coin.
    pub fee: Option<u128>,
    /// An outgoing transfer whose fee is not read yet (EVM: the receipt).
    pub fee_todo: bool,
    /// How far it got.
    pub status: Status,
    /// The block (Solana: slot; Stellar: ledger).
    pub block: Option<u64>,
    /// A text or id memo.
    pub memo: Option<String>,
    /// An arrival the wallet saw as a change of balance: no hash, no sender.
    pub observed: bool,
    /// The address this transfer imitates, if it is a look-alike's dust.
    pub look_alike_of: Option<String>,
    /// A second, independent operator has the transaction too, in the same block and
    /// with the same effect on this account (`verify.rs`). Until then an item the source
    /// calls confirmed or failed is shown as `pending` and `unverified`.
    pub verified: bool,
    /// The account's nonce this send used (Bittensor, whose nodes keep no index of extrinsics by hash:
    /// the account's nonce on chain is what says whether it came in).
    pub nonce: Option<u32>,
}

impl Item {
    /// A new item with the fields every source has, the rest left empty.
    #[must_use]
    pub fn new(id: String, hash: String, time: u64, direction: Direction, asset: &str) -> Self {
        Self {
            id,
            hash,
            time,
            order: 0,
            kind: Kind::Transfer,
            direction,
            asset: asset.to_owned(),
            contract: None,
            amount: 0,
            decimals: 0,
            counterparty: None,
            fee: None,
            fee_todo: false,
            status: Status::Confirmed,
            block: None,
            memo: None,
            observed: false,
            look_alike_of: None,
            verified: false,
            nonce: None,
        }
    }

    /// The order items are listed in: newest first, the later position first,
    /// then by id so that it is the same every time.
    fn sort_key(&self) -> (std::cmp::Reverse<u64>, std::cmp::Reverse<u64>, &str) {
        (std::cmp::Reverse(self.time), std::cmp::Reverse(self.order), &self.id)
    }

    fn to_state(&self) -> Value {
        let mut o = Map::new();
        o.insert("i".into(), json!(self.id));
        o.insert("h".into(), json!(self.hash));
        o.insert("t".into(), json!(self.time));
        if self.order != 0 {
            o.insert("o".into(), json!(self.order));
        }
        o.insert("k".into(), json!(u8::from(self.kind == Kind::Call)));
        o.insert(
            "d".into(),
            json!(match self.direction {
                Direction::In => 0,
                Direction::Out => 1,
                Direction::SelfSent => 2,
            }),
        );
        o.insert("a".into(), json!(self.asset));
        if let Some(c) = &self.contract {
            o.insert("c".into(), json!(c));
        }
        o.insert("m".into(), json!(self.amount.to_string()));
        o.insert("x".into(), json!(self.decimals));
        if let Some(p) = &self.counterparty {
            o.insert("p".into(), json!(p));
        }
        if let Some(f) = self.fee {
            o.insert("f".into(), json!(f.to_string()));
        }
        if self.fee_todo {
            o.insert("ft".into(), json!(1));
        }
        o.insert(
            "s".into(),
            json!(match self.status {
                Status::Pending => 0,
                Status::Confirmed => 1,
                Status::Failed => 2,
            }),
        );
        if let Some(b) = self.block {
            o.insert("b".into(), json!(b));
        }
        if let Some(n) = &self.memo {
            o.insert("n".into(), json!(n));
        }
        if self.observed {
            o.insert("ob".into(), json!(1));
        }
        if let Some(l) = &self.look_alike_of {
            o.insert("la".into(), json!(l));
        }
        if self.verified {
            o.insert("vf".into(), json!(1));
        }
        if let Some(n) = self.nonce {
            o.insert("nc".into(), json!(n));
        }
        Value::Object(o)
    }

    fn from_state(v: &Value) -> Option<Self> {
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let number = |k: &str| v.get(k).and_then(Value::as_u64);
        Some(Self {
            id: text("i")?,
            hash: text("h")?,
            time: number("t")?,
            order: number("o").unwrap_or(0),
            kind: if number("k")? == 1 { Kind::Call } else { Kind::Transfer },
            direction: match number("d")? {
                0 => Direction::In,
                1 => Direction::Out,
                2 => Direction::SelfSent,
                _ => return None,
            },
            asset: text("a")?,
            contract: text("c"),
            amount: text("m")?.parse().ok()?,
            decimals: u8::try_from(number("x")?).ok()?,
            counterparty: text("p"),
            fee: text("f").and_then(|f| f.parse().ok()),
            fee_todo: number("ft") == Some(1),
            status: match number("s")? {
                0 => Status::Pending,
                1 => Status::Confirmed,
                2 => Status::Failed,
                _ => return None,
            },
            block: number("b"),
            memo: text("n"),
            observed: number("ob") == Some(1),
            look_alike_of: text("la"),
            verified: number("vf") == Some(1),
            nonce: number("nc").and_then(|n| u32::try_from(n).ok()),
        })
    }

    /// The item as the apps read it. `head` is the chain's head block, for the
    /// depth; `network` names the native coin the fee is paid in.
    #[must_use]
    pub fn to_api(&self, network: Network, head: Option<u64>, now: u64) -> Value {
        let unverified = super::verify::awaiting(self, network, now);
        let native = network.native();
        let mut o = Map::new();
        o.insert("hash".into(), json!(self.hash));
        o.insert("time".into(), json!(rfc3339(self.time)));
        o.insert("kind".into(), json!(if self.kind == Kind::Call { "call" } else { "transfer" }));
        o.insert(
            "direction".into(),
            json!(match self.direction {
                Direction::In => "in",
                Direction::Out => "out",
                Direction::SelfSent => "self",
            }),
        );
        o.insert("asset".into(), json!(self.asset));
        if let Some(c) = &self.contract {
            o.insert("contract".into(), json!(c));
        }
        o.insert("amount".into(), json!(self.amount.to_string()));
        o.insert("decimals".into(), json!(self.decimals));
        o.insert("counterparty".into(), json!(self.counterparty));
        o.insert(
            "fee".into(),
            self.fee.map_or(Value::Null, |f| {
                json!({ "asset": native.symbol, "amount": f.to_string(), "decimals": native.decimals })
            }),
        );
        // What one operator calls confirmed or failed is `pending` until a second agrees.
        o.insert(
            "status".into(),
            json!(match (self.status, unverified) {
                (Status::Pending, _) | (_, true) => "pending",
                (Status::Confirmed, false) => "confirmed",
                (Status::Failed, false) => "failed",
            }),
        );
        if unverified {
            o.insert("unverified".into(), json!(true));
            o.insert(
                "reported".into(),
                json!(if self.status == Status::Failed { "failed" } else { "confirmed" }),
            );
        }
        let depth = match (self.block, head, self.status) {
            _ if unverified => Some(0),
            (_, _, Status::Pending) => Some(0),
            (Some(b), Some(h), _) if h >= b => Some((h - b).saturating_add(1)),
            _ => None,
        };
        o.insert("confirmations".into(), json!(depth));
        o.insert("block".into(), json!(self.block));
        if let Some(n) = &self.memo {
            o.insert("memo".into(), json!(n));
        }
        if self.observed {
            o.insert("observed".into(), json!(true));
        }
        if let Some(l) = &self.look_alike_of {
            o.insert("poisoned".into(), json!(true));
            o.insert("look_alike_of".into(), json!(l));
        }
        Value::Object(o)
    }
}

/// Everything kept of one address.
#[derive(Debug, Clone, PartialEq)]
pub struct State {
    /// Whose it is: the network and the address, so that a state kept for
    /// another is not used.
    pub who: String,
    /// Newest first.
    pub items: Vec<Item>,
    /// What the app sent that the chain history does not have yet.
    pub notes: Vec<Item>,
    /// When the wallet first looked, Unix seconds.
    pub first_seen: u64,
    /// The native balance last seen, in base units (networks with no history
    /// source for their coin).
    pub balance: Option<u128>,
    /// A balance higher than the sends explain, and when it was first seen: it becomes an arrival only if
    /// a later reading, some time after, still says so (one lagging or stale reading is not an arrival).
    pub rise: Option<(u128, u64)>,
    /// Addresses this account has sent to, most recent first.
    pub sent_to: Vec<String>,
    /// Whether items past the cap were dropped.
    pub dropped: bool,
    /// The chain's head as last seen: a block, or a time.
    pub head: Option<u64>,
    /// Each family's own cursors.
    pub src: Value,
}

impl State {
    /// A history of nothing, first looked at `now`.
    #[must_use]
    pub fn new(who: &str, now: u64) -> Self {
        Self {
            who: who.to_owned(),
            items: Vec::new(),
            notes: Vec::new(),
            first_seen: now,
            balance: None,
            rise: None,
            sent_to: Vec::new(),
            dropped: false,
            head: None,
            src: Value::Null,
        }
    }

    /// Reads a state the app stored. Anything that is not one, or is of another
    /// version, is `None`: the history is then read again from the start.
    #[must_use]
    pub fn load(text: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(text).ok()?;
        if v.get("v").and_then(Value::as_u64) != Some(VERSION) {
            return None;
        }
        let list = |k: &str| -> Option<Vec<Item>> {
            v.get(k)?.as_array()?.iter().map(Item::from_state).collect()
        };
        Some(Self {
            who: v.get("who")?.as_str()?.to_owned(),
            items: list("items")?,
            notes: list("notes")?,
            first_seen: v.get("first")?.as_u64()?,
            balance: v.get("bal").and_then(Value::as_str).and_then(|b| b.parse().ok()),
            rise: v
                .get("rise")
                .and_then(Value::as_array)
                .and_then(|r| Some((r.first()?.as_str()?.parse().ok()?, r.get(1)?.as_u64()?))),
            sent_to: v
                .get("to")?
                .as_array()?
                .iter()
                .filter_map(|a| a.as_str().map(str::to_owned))
                .collect(),
            dropped: v.get("drop").and_then(Value::as_bool) == Some(true),
            head: v.get("head").and_then(Value::as_u64),
            src: v.get("src").cloned().unwrap_or(Value::Null),
        })
    }

    /// The state as text, to be stored.
    #[must_use]
    pub fn dump(&self) -> String {
        let mut o = Map::new();
        o.insert("v".into(), json!(VERSION));
        o.insert("who".into(), json!(self.who));
        o.insert("first".into(), json!(self.first_seen));
        if let Some(b) = self.balance {
            o.insert("bal".into(), json!(b.to_string()));
        }
        if let Some((seen, since)) = self.rise {
            o.insert("rise".into(), json!([seen.to_string(), since]));
        }
        o.insert("to".into(), json!(self.sent_to));
        if self.dropped {
            o.insert("drop".into(), json!(true));
        }
        if let Some(h) = self.head {
            o.insert("head".into(), json!(h));
        }
        o.insert("items".into(), Value::Array(self.items.iter().map(Item::to_state).collect()));
        o.insert("notes".into(), Value::Array(self.notes.iter().map(Item::to_state).collect()));
        o.insert("src".into(), self.src.clone());
        Value::Object(o).to_string()
    }

    /// Adds items, replacing any with the same id, keeps the list in order and
    /// within [`MAX_ITEMS`], and lets the chain's transactions replace the
    /// notes of what was sent.
    pub fn merge(&mut self, new: Vec<Item>) {
        for item in new {
            match self.items.iter_mut().find(|held| held.id == item.id) {
                Some(held) => {
                    // The facts that were checked, unchanged: the check stands.
                    let same = held.verified
                        && held.hash == item.hash
                        && held.status == item.status
                        && held.direction == item.direction
                        && held.amount == item.amount
                        && held.asset == item.asset
                        && held.contract == item.contract
                        && held.block == item.block
                        && held.counterparty == item.counterparty;
                    let mut item = item;
                    item.verified = item.verified || same;
                    *held = item;
                }
                None => self.items.push(item),
            }
        }
        self.items.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        if self.items.len() > MAX_ITEMS {
            self.items.truncate(MAX_ITEMS);
            self.dropped = true;
        }
        let known: Vec<&str> = self.items.iter().map(|i| i.hash.as_str()).collect();
        self.notes.retain(|note| !known.contains(&note.hash.as_str()));
    }

    /// Leaves each transaction's fee on its first item only (a transaction of
    /// several operations makes several items, and its fee is paid once).
    pub fn fee_once_per_hash(&mut self) {
        let mut paid: Vec<String> = Vec::new();
        for item in &mut self.items {
            if item.fee.is_none() {
                continue;
            }
            if paid.contains(&item.hash) {
                item.fee = None;
            } else {
                paid.push(item.hash.clone());
            }
        }
    }

    /// The addresses sent to, from the notes and the items, for look-alike checks.
    pub fn remember_sent_to(&mut self, address: &str) {
        self.sent_to.retain(|a| a != address);
        self.sent_to.insert(0, address.to_owned());
        self.sent_to.truncate(MAX_SENT_TO);
    }

    /// What is listed: the notes (pending, newest first) and then the items.
    /// Items at or before `floor` (Unix seconds) are held back: a source that is
    /// still reading backwards is not certain of them yet.
    #[must_use]
    pub fn listing(&self, floor: Option<u64>) -> Vec<&Item> {
        let mut notes: Vec<&Item> = self.notes.iter().collect();
        notes.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        notes
            .into_iter()
            .chain(self.items.iter().filter(|i| floor.is_none_or(|f| i.time > f)))
            .collect()
    }
}

/// A place in a listing: the time, order and id of the last item given.
#[must_use]
pub fn cursor_of(item: &Item) -> String {
    let json = json!([item.time, item.order, item.id]).to_string();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
}

fn cursor_key(cursor: &str) -> Option<(u64, u64, String)> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.trim_end_matches('='))
        .ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    Some((v.get(0)?.as_u64()?, v.get(1)?.as_u64()?, v.get(2)?.as_str()?.to_owned()))
}

/// The page that follows `cursor` (the first page for `None`): up to `limit`
/// items, ended between transactions rather than inside one. `Err(())` for a
/// cursor that is not one this code gave.
#[allow(clippy::result_unit_err)]
pub fn page<'a>(
    listing: &[&'a Item],
    cursor: Option<&str>,
    limit: usize,
) -> Result<Vec<&'a Item>, ()> {
    let start = match cursor {
        None => 0,
        Some(text) => {
            let (time, order, id) = cursor_key(text).ok_or(())?;
            let key = (std::cmp::Reverse(time), std::cmp::Reverse(order), id.as_str());
            listing.iter().position(|i| i.sort_key() > key).unwrap_or(listing.len())
        }
    };
    let rest = &listing[start..];
    let mut end = rest.len().min(limit.clamp(1, MAX_PAGE));
    while end < rest.len() && end > 0 && rest[end].hash == rest[end - 1].hash {
        end += 1;
    }
    Ok(rest[..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn item(id: &str, hash: &str, time: u64, direction: Direction) -> Item {
        let mut i = Item::new(id.into(), hash.into(), time, direction, "USDT");
        i.amount = 1_500_000;
        i.decimals = 6;
        i
    }

    fn state_of(n: u64) -> State {
        let mut state = State::new("t", 1_000);
        state.merge(
            (0..n)
                .map(|k| item(&format!("h{k}"), &format!("h{k}"), 10_000 - k, Direction::In))
                .collect(),
        );
        state
    }

    #[test]
    fn a_state_survives_being_stored_and_a_strange_one_is_refused() {
        let mut state = state_of(3);
        state.items[0].look_alike_of = Some("0xabc".into());
        state.items[1].fee = Some(21_000);
        state.items[2].memo = Some("m".into());
        state.notes.push(item("n1", "pending", 20_000, Direction::Out));
        state.balance = Some(123);
        state.sent_to = vec!["0xdead".into()];
        state.src = json!({ "tail": 5 });
        let back = State::load(&state.dump()).unwrap();
        assert_eq!(back, state);
        assert!(State::load("not json").is_none());
        assert!(
            State::load(r#"{"v":2}"#).is_none(),
            "another version is read again, not guessed at"
        );
        assert!(State::load(&state.dump().replace("\"items\":[", "\"items\":[7,")).is_none());
    }

    #[test]
    fn items_are_newest_first_and_merging_replaces_by_id() {
        let mut state = state_of(3);
        let mut again = item("h1", "h1", 9_999, Direction::In);
        again.amount = 7;
        state.merge(vec![again, item("fresh", "fresh", 20_000, Direction::In)]);
        let ids: Vec<&str> = state.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["fresh", "h0", "h1", "h2"]);
        assert_eq!(state.items[2].amount, 7);
    }

    #[test]
    fn the_cap_drops_the_oldest_and_says_so() {
        let state = state_of(MAX_ITEMS as u64 + 5);
        assert_eq!(state.items.len(), MAX_ITEMS);
        assert!(state.dropped);
        assert_eq!(state.items[0].id, "h0", "the newest stay");
        assert_eq!(state.items.last().unwrap().id, format!("h{}", MAX_ITEMS - 1));
        // And the stored text stays within what an app can keep and pass about.
        assert!(state.dump().len() < 450_000, "{}", state.dump().len());
    }

    #[test]
    fn a_note_goes_when_the_chain_has_the_transaction() {
        let mut state = State::new("t", 0);
        state.notes.push(item("n", "0xsent", 50, Direction::Out));
        state.notes.push(item("m", "0xother", 51, Direction::Out));
        state.merge(vec![item("0xsent:0", "0xsent", 55, Direction::Out)]);
        assert_eq!(state.notes.len(), 1);
        assert_eq!(state.notes[0].hash, "0xother");
    }

    #[test]
    fn pages_follow_the_cursor_and_end_between_transactions() {
        let mut state = state_of(7);
        // Two items of one transaction on the boundary of a page of three.
        state.merge(vec![
            item("a", "same", 20_000, Direction::In),
            item("b", "same", 20_000, Direction::Out),
            item("c", "same", 20_000, Direction::In),
            item("d", "same", 20_000, Direction::Out),
        ]);
        let listing = state.listing(None);
        let first = page(&listing, None, 3).unwrap();
        assert_eq!(first.len(), 4, "the page does not end inside a transaction");
        let next = page(&listing, Some(&cursor_of(first[3])), 3).unwrap();
        assert_eq!(next.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["h0", "h1", "h2"]);
        let last = page(&listing, Some(&cursor_of(next[2])), 50).unwrap();
        assert_eq!(last.len(), 4);
        assert!(page(&listing, Some(&cursor_of(last[3])), 5).unwrap().is_empty());
        assert!(page(&listing, Some("not-a-cursor"), 5).is_err());
    }

    #[test]
    fn items_not_yet_certain_are_held_back_and_notes_come_first() {
        let mut state = state_of(4);
        state.notes.push(item("n", "pend", 5, Direction::Out));
        let all: Vec<&str> = state.listing(None).iter().map(|i| i.id.as_str()).collect();
        assert_eq!(all, ["n", "h0", "h1", "h2", "h3"]);
        let held: Vec<&str> = state.listing(Some(9_998)).iter().map(|i| i.id.as_str()).collect();
        assert_eq!(held, ["n", "h0", "h1"]);
    }

    #[test]
    fn an_item_is_written_as_the_apps_read_it() {
        let mut i = item("x", "0xabc", 1_793_058_193, Direction::Out);
        i.contract = Some("0xdAC1".into());
        i.counterparty = Some("0xfeed".into());
        i.fee = Some(1_000);
        i.block = Some(100);
        i.look_alike_of = Some("0xfeeb".into());
        // Long enough ago that no second opinion is asked for it.
        let v = i.to_api(Network::Ethereum, Some(111), i.time + 30 * 86_400);
        assert_eq!(v["status"], "confirmed");
        assert_eq!(v.get("unverified"), None);
        assert_eq!(v["time"], "2026-10-26T23:43:13Z");
        assert_eq!(v["direction"], "out");
        assert_eq!(v["confirmations"], 12);
        assert_eq!(v["fee"], json!({ "asset": "ETH", "amount": "1000", "decimals": 18 }));
        assert_eq!(v["poisoned"], true);
        assert_eq!(v["look_alike_of"], "0xfeeb");
        let mut pending = item("p", "0xp", 5, Direction::Out);
        pending.status = Status::Pending;
        assert_eq!(pending.to_api(Network::Ethereum, None, 0)["confirmations"], 0);
        // Recent and not agreed by a second operator: pending, unverified, with what was reported.
        let recent = i.to_api(Network::Ethereum, Some(111), i.time + 60);
        assert_eq!(recent["status"], "pending");
        assert_eq!(recent["unverified"], true);
        assert_eq!(recent["reported"], "confirmed");
        // Once two operators agree it is confirmed, and the flag survives a refresh that reads the
        // same facts again, but not one that reads different ones.
        let mut state = State::new("ethereum:0xa", i.time);
        let mut held = i.clone();
        held.verified = true;
        state.merge(vec![held]);
        state.merge(vec![i.clone()]);
        assert!(state.items[0].verified);
        assert_eq!(
            state.items[0].to_api(Network::Ethereum, Some(111), i.time + 60)["status"],
            "confirmed"
        );
        let mut different = i.clone();
        different.amount += 1;
        state.merge(vec![different]);
        assert!(!state.items[0].verified);
        // A state written with the flag reads back with it.
        let mut verified = i;
        verified.verified = true;
        assert!(Item::from_state(&verified.to_state()).unwrap().verified);
    }
}
