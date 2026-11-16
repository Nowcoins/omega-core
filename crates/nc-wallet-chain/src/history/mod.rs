//! History, kept on the device only.
//!
//! Nothing here asks a Nowcoin server, an indexer or an explorer's API. Each
//! network's history is read from what its public, keyless endpoints can say,
//! kept in a [`State`] the app stores, and extended a bounded step at a time.
//!
//! | Network | Where it comes from | How much |
//! |---|---|---|
//! | Bitcoin | Esplora (`/address/{a}/txs`), over every address of the account found by BIP-84 gap-limit discovery from its zpub | all of it |
//! | TRON | TronGrid `/v1/accounts/{a}/transactions` and `…/trc20` | all of it |
//! | Stellar | Horizon `/accounts/{a}/payments` with its transactions | all of it |
//! | Solana | `getSignaturesForAddress`, then `getTransaction` for each | all of it |
//! | Ethereum, BNB Chain, Polygon, Base: tokens | `eth_getLogs` for the listed tokens' `Transfer` with the address as sender and as recipient | as far back as the endpoints serve logs |
//! | Ethereum, BNB Chain, Polygon, Base: the coin; Bittensor | what the app sent (`history_note`) and arrivals seen as a rise of balance | from the day the wallet was first seen |
//!
//! # Operations
//!
//! * `history`: `{ network, address, addresses?, zpub?, state?, cursor?, limit?,
//!   mode?, balance? }`, answered `{ items, next_cursor, state, coverage,
//!   explorer_address, stale? }`.
//! * `history_note`: `{ network, address, state?, sent }`, answered `{ state }`.
//!
//! `docs/history.md` has the contract, the state, the limits measured and
//! the cost.
//!
//! # Bounded and resumable
//!
//! A call makes a handful of requests (its [`Budget`]) in a limited time, then
//! stops where it is. What it read is in the state it returns; `coverage.scanning`
//! says more remains, and the next call goes on. Nothing is lost by stopping.

mod bitcoin;
mod evm;
mod firstsight;
pub mod poison;
mod solana;
mod stellar;
pub mod store;
mod tron;
mod verify;

use serde_json::{Value, json};

use crate::address::{self, Address};
use crate::client::ChainClient;
use crate::error::{ChainError, ChainResult};
use crate::net::Net;
use crate::networks::{Family, Network};
use crate::util::{parse_amount, rfc3339};
use store::{
    DEFAULT_PAGE, Direction, Item, Kind, MAX_NOTES, MAX_PAGE, State, Status, cursor_of, page,
};

/// How long one call may take, in milliseconds.
const WALL_MS: u64 = 15_000;

/// Which end of the history a call is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Read what is newer than the state, then give the first page.
    Newest,
    /// Give the page at the cursor, reading further back if the state does not reach.
    Page,
}

/// What the endpoints that history is read from must serve.
fn source(network: Network) -> crate::pool::Need {
    if network.family() == Family::Tron {
        crate::pool::Need::TRON_V1
    } else {
        crate::pool::Need::ANY
    }
}

/// A history request, read and checked.
#[derive(Debug)]
pub struct Req {
    /// The network.
    pub network: Network,
    /// The account's address on it.
    pub address: Address,
    /// Bitcoin: the account's other known addresses.
    pub others: Vec<Address>,
    /// Bitcoin: the BIP-84 account key, for discovery.
    pub zpub: Option<String>,
    /// The state the app stored, as text.
    pub state: Option<String>,
    /// Where the page begins.
    pub cursor: Option<String>,
    /// How many items a page holds.
    pub limit: usize,
    /// Newest or page.
    pub mode: Mode,
    /// The native balance in base units, for networks whose coin has no source.
    pub balance: Option<u128>,
}

impl Req {
    fn parse(request: &Value) -> ChainResult<Self> {
        let text = |key: &str| request.get(key).and_then(Value::as_str);
        let network = Network::from_id(
            text("network").ok_or_else(|| ChainError::invalid("network is missing"))?,
        )
        .ok_or(ChainError::UnknownNetwork)?;
        let address = address::parse(
            network,
            text("address").ok_or_else(|| ChainError::invalid("address is missing"))?,
        )?;
        let mut others = Vec::new();
        match request.get("addresses") {
            None | Some(Value::Null) => {}
            Some(Value::Array(list)) => {
                if network != Network::Bitcoin && !list.is_empty() {
                    return Err(ChainError::invalid("addresses is for Bitcoin only"));
                }
                let given: Vec<String> =
                    list.iter().filter_map(|a| a.as_str().map(str::to_owned)).collect();
                others = address::list(network, &address, &given)?.into_iter().skip(1).collect();
            }
            Some(_) => return Err(ChainError::invalid("addresses is a list")),
        }
        let zpub = text("zpub").map(str::to_owned);
        if zpub.is_some() && network != Network::Bitcoin {
            return Err(ChainError::invalid("zpub is for Bitcoin only"));
        }
        let mode = match text("mode") {
            None | Some("newest") => Mode::Newest,
            Some("page") => Mode::Page,
            Some(_) => return Err(ChainError::invalid("mode is newest or page")),
        };
        let limit = request
            .get("limit")
            .and_then(Value::as_u64)
            .map_or(DEFAULT_PAGE, |l| usize::try_from(l).unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE));
        let balance = match text("balance") {
            Some(b) => Some(parse_amount(b)?),
            None => None,
        };
        Ok(Self {
            network,
            address,
            others,
            zpub,
            state: text("state").map(str::to_owned),
            cursor: text("cursor").map(str::to_owned),
            limit,
            mode,
            balance,
        })
    }

    fn who(&self) -> String {
        format!("{}:{}", self.network.id(), self.address.text)
    }
}

/// What a call is made of.
#[derive(Debug)]
pub struct Cx<'a> {
    /// The client, for its other networks' endpoints where a family needs them.
    pub client: &'a ChainClient,
    /// The network's endpoints.
    pub net: &'a Net,
    /// The network.
    pub network: Network,
    /// The request.
    pub req: &'a Req,
    /// Now, in Unix seconds.
    pub now: u64,
}

/// How many requests a call may make, and until when.
#[derive(Debug)]
pub struct Budget {
    left: u32,
    deadline_ms: u64,
}

impl Budget {
    /// `requests` requests, within the wall time, from `now_ms`.
    #[must_use]
    pub const fn new(requests: u32, now_ms: u64) -> Self {
        Self { left: requests, deadline_ms: now_ms.saturating_add(WALL_MS) }
    }

    /// Takes one request, if there is one left and time. `false` means stop.
    pub fn take(&mut self, now_ms: u64) -> bool {
        self.take_up_to(1, now_ms) == 1
    }

    /// Whether any request is left.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.left > 0
    }

    /// Takes up to `n` at once (for a batch sent side by side); how many were granted.
    pub fn take_up_to(&mut self, n: u32, now_ms: u64) -> u32 {
        if now_ms >= self.deadline_ms {
            self.left = 0;
        }
        let granted = n.min(self.left);
        self.left -= granted;
        granted
    }
}

/// How much of the history the state covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// `full`, `from_first_sight` or `partial`.
    pub kind: &'static str,
    /// Whether nothing older is missing.
    pub complete: bool,
    /// The earliest moment the history is good from, Unix seconds.
    pub from: Option<u64>,
    /// Each part's own, where a network has parts of different kinds.
    pub parts: Vec<Part>,
    /// Whether reading further back is not possible now: no endpoint reaches
    /// the next block (or the source has nothing more to give).
    pub stuck: bool,
}

/// The coverage of one part of a network's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// `coin` or `tokens`.
    pub scope: &'static str,
    /// `full`, `from_first_sight` or `partial`.
    pub kind: &'static str,
    /// Whether nothing older is missing.
    pub complete: bool,
    /// The earliest moment this part is good from.
    pub from: Option<u64>,
}

impl Coverage {
    /// A coverage of one part.
    #[must_use]
    pub fn single(kind: &'static str, complete: bool, from: Option<u64>) -> Self {
        Self { kind, complete, from, parts: Vec::new(), stuck: false }
    }

    /// A coverage that is the least of its parts'.
    #[must_use]
    pub fn of_parts(parts: Vec<Part>) -> Self {
        let rank = |kind: &str| match kind {
            "full" => 0,
            "partial" => 1,
            _ => 2,
        };
        let kind = parts.iter().map(|p| p.kind).max_by_key(|k| rank(k)).unwrap_or("full");
        // A part that can never be complete (the coin, from first sight) does not
        // keep a scan going: what can still be read is what "complete" is about.
        let complete = parts.iter().all(|p| p.complete || p.kind == "from_first_sight");
        // Anything older than the latest start of a part may be missing from it.
        let from = parts.iter().filter_map(|p| p.from).max();
        Self { kind, complete, from, parts, stuck: false }
    }

    fn to_value(&self, scanning: bool) -> Value {
        let mut o = json!({
            "kind": self.kind,
            "complete": self.complete,
            "scanning": scanning && !self.stuck,
            "from": self.from.map(rfc3339),
        });
        if !self.parts.is_empty() {
            o["parts"] = Value::Array(
                self.parts
                    .iter()
                    .map(|p| {
                        json!({
                            "scope": p.scope,
                            "kind": p.kind,
                            "complete": p.complete,
                            "from": p.from.map(rfc3339),
                        })
                    })
                    .collect(),
            );
        }
        o
    }
}

/// `GET`s `path` from the network's REST endpoints and reads it as JSON, trying
/// another endpoint when the answer is not what the source documents: `ok` says
/// what a good answer looks like. A `404` is `(404, Null)`, an answer in its own
/// right. Each try takes a request of the budget.
pub(crate) async fn get_json(
    cx: &Cx<'_>,
    b: &mut Budget,
    path: &str,
    ok: fn(&Value) -> bool,
) -> ChainResult<(u16, Value)> {
    get_json_from(cx, b, crate::pool::Need::ANY, path, ok).await
}

/// As [`get_json`], from the endpoints that fit `need`.
pub(crate) async fn get_json_from(
    cx: &Cx<'_>,
    b: &mut Budget,
    need: crate::pool::Need,
    path: &str,
    ok: fn(&Value) -> bool,
) -> ChainResult<(u16, Value)> {
    let mut avoid: Vec<usize> = Vec::new();
    for _ in 0..3 {
        if !b.take(cx.net.now()) {
            return Err(ChainError::Busy { retry_after_seconds: 1 });
        }
        let ((status, body), index) = cx.net.get_from(need, &avoid, path).await?;
        if status == 404 {
            return Ok((404, Value::Null));
        }
        if (200..300).contains(&status)
            && let Ok(value) = serde_json::from_slice::<Value>(&body)
            && ok(&value)
        {
            return Ok((status, value));
        }
        avoid.push(index);
    }
    Err(ChainError::Unavailable)
}

/// How many requests a call to this network may make.
const fn requests(network: Network) -> u32 {
    match network.family() {
        Family::Bitcoin => 16,
        Family::Solana => 14,
        Family::Evm | Family::Tron => 10,
        Family::Stellar => 8,
        Family::Substrate => 6,
    }
}

/// Runs a history operation (`history`, `history_note`) on a parsed request.
pub async fn call(client: &ChainClient, op: &str, request: &Value) -> ChainResult<Value> {
    match op {
        "history" => history(client, request).await,
        "history_note" => note(client, request),
        _ => Err(ChainError::invalid("that history operation is not one this wallet has")),
    }
}

fn load(req: &Req, now: u64) -> State {
    req.state
        .as_deref()
        .and_then(State::load)
        .filter(|s| s.who == req.who())
        .unwrap_or_else(|| State::new(&req.who(), now))
}

async fn update(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    match cx.network.family() {
        Family::Evm => evm::update(cx, b, st).await,
        Family::Bitcoin => bitcoin::update(cx, b, st).await,
        Family::Tron => tron::update(cx, b, st).await,
        Family::Stellar => stellar::update(cx, b, st).await,
        Family::Solana => solana::update(cx, b, st).await,
        Family::Substrate => {
            firstsight::update(cx, b, st).await;
            Ok(())
        }
    }
}

async fn extend(cx: &Cx<'_>, b: &mut Budget, st: &mut State) -> ChainResult<()> {
    match cx.network.family() {
        Family::Evm => evm::extend(cx, b, st).await,
        Family::Bitcoin => bitcoin::extend(cx, b, st).await,
        Family::Tron => tron::extend(cx, b, st).await,
        Family::Stellar => stellar::extend(cx, b, st).await,
        Family::Solana => solana::extend(cx, b, st).await,
        Family::Substrate => Ok(()),
    }
}

fn coverage(cx: &Cx<'_>, st: &State) -> Coverage {
    match cx.network.family() {
        Family::Evm => evm::coverage(cx, st),
        Family::Bitcoin => bitcoin::coverage(st),
        Family::Tron => tron::coverage(st),
        Family::Stellar => stellar::coverage(st),
        Family::Solana => solana::coverage(st),
        Family::Substrate => firstsight::coverage(st),
    }
}

/// Items at or before this time (Unix seconds) are not certain yet.
fn floor(cx: &Cx<'_>, st: &State) -> Option<u64> {
    match cx.network.family() {
        Family::Tron => tron::floor(st),
        Family::Bitcoin => bitcoin::floor(st),
        _ => None,
    }
}

async fn history(client: &ChainClient, request: &Value) -> ChainResult<Value> {
    let req = Req::parse(request)?;
    let net = client.net(req.network);
    let now_ms = net.now();
    let cx = Cx { client, net, network: req.network, req: &req, now: now_ms / 1000 };
    let mut st = load(&req, cx.now);
    let mut budget = Budget::new(requests(req.network), now_ms);
    let mut stale: Option<ChainError> = None;
    let bad_cursor = |()| ChainError::invalid("the cursor is not one this wallet gave");

    // What is newer than the state, or the newest, if there is no state yet.
    // A page further back does not need it, unless there is nothing at all.
    if (req.mode == Mode::Newest || st.items.is_empty())
        && let Err(e) = update(&cx, &mut budget, &mut st).await
    {
        // With nothing to show, an error is the answer, unless a challenge is the
        // reason: that is told as a result, so the app can say so.
        if st.items.is_empty() && st.notes.is_empty() && !net.blocked(source(req.network)) {
            return Err(e);
        }
        stale = Some(e);
    }
    if req.network.family() == Family::Evm {
        evm::settle_notes(&cx, &mut budget, &mut st).await;
    }
    if let Some(balance) = req.balance
        && matches!(req.network.family(), Family::Evm | Family::Substrate)
    {
        firstsight::observe(&cx, &mut st, balance);
    }
    poison::flag(req.network, &mut st);

    // Read further back while the page asked for is not full.
    while stale.is_none() && budget.any() && !coverage(&cx, &st).complete {
        let listing = st.listing(floor(&cx, &st));
        let probe = page(&listing, req.cursor.as_deref(), req.limit + 1).map_err(bad_cursor)?;
        if probe.len() > req.limit {
            break;
        }
        let before = (st.items.len(), coverage(&cx, &st));
        if let Err(e) = extend(&cx, &mut budget, &mut st).await {
            stale = Some(e);
            break;
        }
        poison::flag(req.network, &mut st);
        // Nothing gained and nothing learned: stop rather than ask again.
        if before == (st.items.len(), coverage(&cx, &st)) {
            break;
        }
    }
    if stale.is_none() && req.network.family() == Family::Evm {
        evm::finish(&cx, &mut budget, &mut st).await;
    }
    // What a source calls confirmed is checked against a second operator, a few a call.
    verify::run(&cx, &mut st).await;

    let coverage = coverage(&cx, &st);
    let listing = st.listing(floor(&cx, &st));
    let given = page(&listing, req.cursor.as_deref(), req.limit).map_err(bad_cursor)?;
    let position = given
        .last()
        .and_then(|last| listing.iter().position(|i| std::ptr::eq(*i, *last)))
        .map_or(0, |p| p + 1);
    let more = listing.len() > position || !coverage.complete;
    // Nothing given (the endpoints were busy): the same place is offered again.
    let next_cursor =
        given.last().map(|i| cursor_of(i)).or_else(|| req.cursor.clone()).filter(|_| more);
    let scanning = !coverage.complete && stale.is_none();
    let items: Vec<Value> = given.iter().map(|i| i.to_api(req.network, st.head, cx.now)).collect();
    let mut answer = json!({
        "items": items,
        "next_cursor": next_cursor,
        "state": st.dump(),
        "coverage": coverage.to_value(scanning),
        "explorer_address": req.network.explorer_address().replace("{address}", &req.address.text),
    });
    if let Some(e) = stale {
        answer["stale"] = json!(e.code());
        if net.blocked(source(req.network)) {
            answer["unavailable"] = json!("history_source_blocked");
        }
    }
    Ok(answer)
}

/// Records a transfer the app has just sent, as pending until the chain has it.
fn note(client: &ChainClient, request: &Value) -> ChainResult<Value> {
    let req = Req::parse(request)?;
    let now = client.net(req.network).now() / 1000;
    let mut st = load(&req, now);
    let sent = request.get("sent").ok_or_else(|| ChainError::invalid("sent is missing"))?;
    let text = |key: &str| sent.get(key).and_then(Value::as_str);
    let hash = text("hash").ok_or_else(|| ChainError::invalid("sent.hash is missing"))?;
    let asset = text("asset").ok_or_else(|| ChainError::invalid("sent.asset is missing"))?;
    let to = text("to").ok_or_else(|| ChainError::invalid("sent.to is missing"))?;
    let amount =
        parse_amount(text("amount").ok_or_else(|| ChainError::invalid("sent.amount is missing"))?)?;
    let decimals = sent
        .get("decimals")
        .and_then(Value::as_u64)
        .and_then(|d| u8::try_from(d).ok())
        .ok_or_else(|| ChainError::invalid("sent.decimals is missing"))?;
    let time = sent.get("time").and_then(Value::as_u64).unwrap_or(now);
    // Bittensor's nodes keep no index of extrinsics by hash: the account's nonce says whether a send came
    // in, so the note keeps the nonce it used, as the app says or as the broadcast recorded for this hash.
    let nonce = match sent.get("nonce") {
        None | Some(Value::Null) => None,
        Some(given) => Some(
            crate::util::json_u128(given)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| ChainError::invalid("sent.nonce is a number from 0 to 2^32 - 1"))?,
        ),
    };
    let fee = match sent.get("fee") {
        Some(Value::Object(f)) => {
            f.get("amount").and_then(Value::as_str).map(parse_amount).transpose()?
        }
        _ => None,
    };
    let token = req.network.token(asset);
    let known = req.network.is_native(asset)
        || token
            .is_some_and(|t| text("contract").is_none_or(|c| t.contract.eq_ignore_ascii_case(c)));
    if !known || hash.len() > 128 || to.len() > 128 {
        return Err(ChainError::invalid("that is not an asset listed on the network"));
    }
    let mut item = Item::new(format!("note:{hash}"), hash.to_owned(), time, Direction::Out, asset);
    item.kind = Kind::Transfer;
    item.status = Status::Pending;
    item.amount = amount;
    item.decimals = decimals;
    item.counterparty = Some(to.to_owned());
    item.fee = fee;
    item.contract = token.map(|t| t.contract.to_owned());
    if req.network.family() == Family::Substrate {
        item.nonce = nonce.or_else(|| client.sent_nonce(hash).and_then(|n| u32::try_from(n).ok()));
    }
    st.notes.retain(|n| n.hash != hash);
    st.notes.insert(0, item);
    st.notes.truncate(MAX_NOTES);
    st.remember_sent_to(to);
    // The coin that left is spoken for: an arrival is what is more than that.
    if req.network.is_native(asset)
        && let Some(balance) = st.balance
    {
        st.balance = Some(balance.saturating_sub(amount.saturating_add(fee.unwrap_or(0))));
    }
    Ok(json!({ "state": st.dump() }))
}

#[cfg(test)]
mod tests;
