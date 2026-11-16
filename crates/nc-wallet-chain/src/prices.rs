//! Prices, from Chainlink's feeds **on chain**: `latestRoundData()` of each
//! coin's aggregator, read through Multicall3 in one `eth_call`. No price API
//! is asked, no key, nothing about the person leaves the phone.
//!
//! * **Which feed.** Chainlink's reference feeds (from its data directory,
//!   each checked on chain): BNB Chain carries
//!   almost all of them, because its feeds move on 0.1 to 0.2% or every
//!   minute to ten, and TAO has a feed only on Ethereum (2% or daily). **Every
//!   coin the wallet lists has a feed**, so no on-chain pool is used for any.
//! * **Checked.** A feed's `description()` and `decimals()` are read the first
//!   time it is used and compared with what is pinned here beside its address, so a
//!   feed that was replaced or reconfigured is refused rather than misread. The scale
//!   is the pinned one, never the one the same reply carries, and a remembered
//!   check from an earlier launch counts only if it agrees with the pin.
//! * **Stale.** A feed writes a new answer when the price moves past its
//!   deviation threshold or its heartbeat elapses. One that is older than its
//!   heartbeat and five minutes more is marked `stale`; the apps show it as out
//!   of date.
//! * **24-hour change.** The feed's round from a day ago, searched for in the
//!   feed's own rounds: a ladder of rounds going back, then up to five questions
//!   that narrow it to neighbouring rounds ([`day_ago`]; two to six `eth_call`s a
//!   chain, one after the other, once an hour: five on BNB Chain and two on
//!   Ethereum when measured on 2026-11-01). The prices do not wait for it for
//!   longer than [`SEARCH_FOR_MS`]. Where it cannot be found there is no change shown.

use std::sync::Mutex;

use futures::future::Either;
use serde_json::{Value, json};

use crate::abi::{self, SubCall};
use crate::error::{ChainError, ChainResult, clean};
use crate::net::Net;
use crate::networks::Network;
use crate::pool::Need;
use crate::util::{bytes_from_hex, rfc3339, to_hex, word_to_u128};
use nc_wallet_core::evm::abi::selector;

/// How long past its heartbeat a feed's answer is still not stale.
const GRACE_SECONDS: u64 = 300;
/// How long a 24-hour reference is used before it is looked for again.
const REFERENCE_FOR_SECONDS: u64 = 3_600;
/// How far from exactly a day ago the round found may be.
const REFERENCE_SLACK_SECONDS: u64 = 3 * 3_600;
/// A day.
const DAY: u64 = 86_400;
/// How far back, in rounds, the first question looks, each four times the one before: one
/// `getRoundData` for each in the one call puts a round on each side of a day ago for a feed that
/// writes from a few rounds a day to many thousands.
///
/// The longer rungs are insurance, not what makes the search exact: on 500 days of histories at the paces
/// measured on the live feeds, a ladder of one rung finds the day ago to the digit as well, in one question
/// more. What they keep is the pair the narrowing starts from, a few times a day's rounds wide wherever
/// the day falls, however old the feed or however its pace has changed. A rung is a sub-call only for a
/// feed that has that many rounds.
const LADDER: [u64; 7] = [64, 256, 1_024, 4_096, 16_384, 65_536, 262_144];
/// How many more questions are asked, all the feeds' of a chain together in one call each, to narrow
/// the two rounds down to neighbours.
const HOPS: usize = 5;
/// The most the search for the prices of a day ago may take, both chains together, before the prices
/// are answered without it. It asks up to six questions one after the other, so a node that takes
/// seconds over each (`PublicNode`'s BNB Chain endpoint took 4 to 18 s over state reads) would hold the
/// prices back for the best part of a minute; the person is waiting for them, and they do not depend on it.
const SEARCH_FOR_MS: u64 = 4_000;
/// How long a coin whose search ran out of time goes without a change before it is looked for again,
/// instead of the hour a reference that could not be found at all is left.
const SEARCH_AGAIN_SECONDS: u64 = 600;
const _: () = assert!(SEARCH_AGAIN_SECONDS < REFERENCE_FOR_SECONDS);

/// One Chainlink aggregator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feed {
    /// The coin it prices, in dollars.
    pub asset: &'static str,
    /// The chain it is deployed on.
    pub network: Network,
    /// The proxy address, which survives aggregator upgrades.
    pub address: &'static str,
    /// What `description()` returns, checked before the feed is trusted.
    pub description: &'static str,
    /// What `decimals()` returns, pinned here beside the address: the feed's own answer is
    /// checked against it and never taken from the same reply that carries the price. Every
    /// Chainlink USD feed has eight.
    pub decimals: u8,
    /// The longest the feed goes without a new answer, in seconds.
    pub heartbeat: u64,
}

const fn feed(
    asset: &'static str,
    network: Network,
    address: &'static str,
    description: &'static str,
    heartbeat: u64,
) -> Feed {
    Feed { asset, network, address, description, decimals: 8, heartbeat }
}

/// The feeds, one per coin the wallet lists.
pub const FEEDS: &[Feed] = &[
    // BNB Smart Chain's, 0.1% deviation or a minute: Ethereum's own ETH/USD
    // moves on 0.5% or an hour, too loose for a price on a screen.
    feed("ETH", Network::Bsc, "0x9ef1B8c0E4F7dc8bF5719Ea496883DC6401d5b2e", "ETH / USD", 60),
    // 0.1% or 27 s.
    feed("BNB", Network::Bsc, "0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE", "BNB / USD", 27),
    // 0.2% deviation: Ethereum's moves only on 2% or daily.
    feed("SOL", Network::Bsc, "0x0E8a53DD9c13589df6382F13dA6B3Ec8F919B323", "SOL / USD", 600),
    feed("POL", Network::Bsc, "0x081195B56674bb87b2B92F6D58F7c5f449aCE19d", "POL / USD", 600),
    feed("TRX", Network::Bsc, "0xF4C5e535756D11994fCBB12Ba8adD0192D9b88be", "TRX / USD", 600),
    feed("XLM", Network::Bsc, "0x27Cc356A5891A3Fe6f84D0457dE4d108C6078888", "XLM / USD", 600),
    // 0.1% or a minute; Ethereum's moves on 0.5% or an hour.
    feed("BTC", Network::Bsc, "0x264990fbd0A4796A3E3d8E37C4d5F87a3aCa5Ebf", "BTC / USD", 60),
    // The only TAO feed on a network the wallet reads: 2% or daily, priced
    // from exchange data.
    feed(
        "TAO",
        Network::Ethereum,
        "0x1c88503c9A52aE6aaE1f9bb99b3b7e9b8Ab35459",
        "TAO / USD",
        86_400,
    ),
    // The stablecoins, 0.1% or fifteen minutes: what shows a stablecoin that
    // lost its peg as worth less than a dollar.
    feed("USDT", Network::Bsc, "0xB97Ad0E74fa7d920791E90258A6E2085088b4320", "USDT / USD", 900),
    feed("USDC", Network::Bsc, "0x51597f405303C4377E36123cBc172b13269EA163", "USDC / USD", 900),
];

const STABLECOINS: [&str; 2] = ["USDT", "USDC"];

/// A price, as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// Dollars per whole coin times 10^8.
    pub usd_e8: u128,
    /// When the feed wrote it, Unix seconds.
    pub updated_at: u64,
    /// The feed's round.
    pub round: u128,
}

/// What is held of a coin's price a day ago.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// Not looked for yet, or looked for too long ago.
    Missing,
    /// Looked for, and not found.
    NoPrice,
    /// The price a day ago, times 10^8.
    Price(u128),
}

/// What is remembered between calls.
#[derive(Debug, Default)]
pub struct State {
    /// Feeds whose description matched, with their `decimals()`.
    verified: Mutex<Vec<(&'static str, u8)>>,
    /// The price a day ago, by coin: price times 10^8, and when it was looked for.
    reference: Mutex<Vec<(&'static str, Option<u128>, u64)>>,
}

fn target(text: &str) -> ChainResult<[u8; 20]> {
    nc_wallet_core::evm::parse_address_any(text).map_err(|_| ChainError::Internal)
}

/// `answer` scaled to dollars times 10^8.
fn to_e8(answer: u128, decimals: u8) -> Option<u128> {
    if decimals >= 8 {
        Some(answer / 10_u128.checked_pow(u32::from(decimals - 8))?)
    } else {
        answer.checked_mul(10_u128.checked_pow(u32::from(8 - decimals))?)
    }
}

/// `usd_e8` as the apps read it: dollars to eight decimals.
fn usd_text(usd_e8: u128) -> String {
    format!("{}.{:08}", usd_e8 / 100_000_000, usd_e8 % 100_000_000)
}

/// The change from `then` to `now` in percent to two decimals, `1.23` or `-0.40`.
fn change_text(now: u128, then: u128) -> Option<String> {
    if then == 0 {
        return None;
    }
    let (up, difference) = if now >= then { (true, now - then) } else { (false, then - now) };
    // Basis points, rounded to the nearest.
    let bp = difference.checked_mul(10_000)?.checked_add(then / 2)? / then;
    let sign = if up || bp == 0 { "" } else { "-" };
    Some(format!("{sign}{}.{:02}", bp / 100, bp % 100))
}

fn round_data(round: u128) -> Vec<u8> {
    let mut data = selector("getRoundData(uint80)").to_vec();
    data.extend_from_slice(&crate::util::pad_u128(round));
    data
}

impl State {
    /// What is worth keeping between launches: the feeds already checked, and the
    /// prices a day ago.
    pub fn export(&self) -> Value {
        let verified: Vec<Value> = self
            .verified
            .lock()
            .map(|v| v.iter().map(|(asset, decimals)| json!([asset, decimals])).collect())
            .unwrap_or_default();
        let reference: Vec<Value> = self
            .reference
            .lock()
            .map(|v| {
                v.iter()
                    .map(|(asset, price, at)| json!([asset, price.map(|p| p.to_string()), at]))
                    .collect()
            })
            .unwrap_or_default();
        json!({ "verified": verified, "reference": reference })
    }

    /// Takes back what [`Self::export`] wrote; anything that is not a known
    /// feed's or not shaped as written is left out.
    pub fn import(&self, state: &Value) {
        let known = |asset: &str| FEEDS.iter().find(|f| f.asset == asset).map(|f| f.asset);
        if let (Ok(mut held), Some(list)) =
            (self.verified.lock(), state.get("verified").and_then(Value::as_array))
        {
            for entry in list {
                let asset = entry.get(0).and_then(Value::as_str).and_then(known);
                // What was remembered counts only if it is what is pinned now.
                let decimals =
                    entry.get(1).and_then(Value::as_u64).and_then(|d| u8::try_from(d).ok()).filter(
                        |d| FEEDS.iter().any(|f| Some(f.asset) == asset && f.decimals == *d),
                    );
                if let (Some(asset), Some(decimals)) = (asset, decimals)
                    && !held.iter().any(|(a, _)| *a == asset)
                {
                    held.push((asset, decimals));
                }
            }
        }
        if let (Ok(mut held), Some(list)) =
            (self.reference.lock(), state.get("reference").and_then(Value::as_array))
        {
            for entry in list {
                let asset = entry.get(0).and_then(Value::as_str).and_then(known);
                let at = entry.get(2).and_then(Value::as_u64);
                let price = match entry.get(1) {
                    Some(Value::Null) => Some(None),
                    Some(Value::String(text)) => text.parse::<u128>().ok().map(Some),
                    _ => None,
                };
                if let (Some(asset), Some(at), Some(price)) = (asset, at, price)
                    && !held.iter().any(|(a, _, _)| *a == asset)
                {
                    held.push((asset, price, at));
                }
            }
        }
    }

    fn decimals_of(&self, asset: &str) -> Option<u8> {
        self.verified.lock().ok()?.iter().find(|(a, _)| *a == asset).map(|(_, d)| *d)
    }

    fn reference_of(&self, asset: &str, now: u64) -> Held {
        let Ok(held) = self.reference.lock() else { return Held::Missing };
        match held.iter().find(|(a, _, _)| *a == asset) {
            Some((_, price, at)) if now.saturating_sub(*at) < REFERENCE_FOR_SECONDS => {
                price.map_or(Held::NoPrice, Held::Price)
            }
            _ => Held::Missing,
        }
    }

    fn set_reference(&self, asset: &'static str, price: Option<u128>, now: u64) {
        if let Ok(mut held) = self.reference.lock() {
            held.retain(|(a, _, _)| *a != asset);
            held.push((asset, price, now));
        }
    }

    /// A search that ran out of time: no change for the coin for now, and it is looked for again after
    /// [`SEARCH_AGAIN_SECONDS`] (dated back so that the reference lapses then, not after the hour).
    fn postpone_reference(&self, asset: &'static str, now: u64) {
        let lapses_in = REFERENCE_FOR_SECONDS - SEARCH_AGAIN_SECONDS;
        self.set_reference(asset, None, now.saturating_sub(lapses_in));
    }
}

/// Reads `latestRoundData` of `feeds` on one network in one `eth_call`, with
/// `description()` and `decimals()` for any not yet verified.
async fn read(
    net: &Net,
    state: &State,
    feeds: &[&'static Feed],
) -> ChainResult<Vec<(&'static Feed, Option<Reading>)>> {
    let mut calls: Vec<SubCall> = Vec::new();
    // How many sub-calls each feed has, and whether the first two are the checks.
    let mut plan: Vec<(&'static Feed, bool)> = Vec::new();
    for &feed in feeds {
        let target = target(feed.address)?;
        let verify = state.decimals_of(feed.asset).is_none();
        if verify {
            calls.push(SubCall { target, data: abi::description() });
            calls.push(SubCall { target, data: abi::decimals() });
        }
        calls.push(SubCall { target, data: abi::latest_round_data() });
        plan.push((feed, verify));
    }
    let answer = net
        .rpc(
            Need::ANY,
            "eth_call",
            &json!([{ "to": abi::MULTICALL3, "data": to_hex(&abi::aggregate3(&calls)) }, "latest"]),
        )
        .await?
        .map_err(|_| ChainError::Unavailable)?;
    let bytes = answer.as_str().and_then(bytes_from_hex).ok_or(ChainError::Unavailable)?;
    let results = abi::decode_aggregate3(&bytes)
        .filter(|results| results.len() == calls.len())
        .ok_or(ChainError::Unavailable)?;
    let mut results = results.into_iter();
    let mut out = Vec::new();
    for (feed, verify) in plan {
        if verify {
            let description =
                results.next().filter(|r| r.success).and_then(|r| abi::decode_string(&r.data));
            let decimals = results
                .next()
                .filter(|r| r.success)
                .and_then(|r| word_to_u128(&r.data))
                .and_then(|d| u8::try_from(d).ok());
            match (description, decimals) {
                (Some(description), Some(decimals))
                    if description == feed.description && decimals == feed.decimals =>
                {
                    if let Ok(mut verified) = state.verified.lock() {
                        verified.push((feed.asset, feed.decimals));
                    }
                }
                // A feed that is not the one listed is refused, not misread.
                _ => {
                    results.next();
                    out.push((feed, None));
                    continue;
                }
            }
        }
        let decimals = state.decimals_of(feed.asset);
        let reading = results
            .next()
            .filter(|r| r.success)
            .and_then(|r| abi::decode_round(&r.data))
            .zip(decimals)
            .and_then(|(round, decimals)| {
                Some(Reading {
                    usd_e8: to_e8(round.answer, decimals)?,
                    updated_at: round.updated_at,
                    round: round.round,
                })
            });
        out.push((feed, reading));
    }
    Ok(out)
}

/// A round of a feed, the way a search keeps it: its number within the feed's phase, when it was
/// written and what it said (the feed's own scale, as `getRoundData` gives it).
#[derive(Debug, Clone, Copy)]
struct Seen {
    round: u64,
    time: u64,
    answer: u128,
}

/// A feed whose round from a day ago is being narrowed down. The price a day ago is what the last
/// round written at or before `wanted` said: that round is `low` or after it, and before `high`.
#[derive(Debug)]
struct Search {
    feed: &'static Feed,
    /// The feed's phase: the high bits every round id of it begins with.
    phase: u128,
    /// A day before the latest round was written.
    wanted: u64,
    /// A round written at or before `wanted`.
    low: Seen,
    /// A round written after it: the latest, or one found since.
    high: Seen,
}

impl Search {
    /// The rounds to ask next, all in the one call: where `wanted` would fall if the rounds between the
    /// two were evenly spaced, and a few either side of it, widening, in case they are not; and the
    /// middle of what lies between, so that however unevenly the feed has written, what is left
    /// shrinks by half at least. None where the two are neighbours already.
    fn questions(&self) -> Vec<u64> {
        let (low, high) = (self.low.round, self.high.round);
        let width = high.saturating_sub(low);
        if width < 2 {
            return Vec::new();
        }
        let elapsed = u128::from(self.wanted.saturating_sub(self.low.time));
        let total = u128::from(self.high.time.saturating_sub(self.low.time)).max(1);
        let along = elapsed.saturating_mul(u128::from(width)) / total;
        let guess = low.saturating_add(u64::try_from(along).unwrap_or(width));
        let step = (width / 64).max(1);
        let mut rounds: Vec<u64> = [1_u64, 4]
            .into_iter()
            .flat_map(|k| [guess.saturating_sub(k * step), guess.saturating_add(k * step)])
            .chain([guess, low + width / 2])
            .filter(|round| *round > low && *round < high)
            .collect();
        rounds.sort_unstable();
        rounds.dedup();
        rounds
    }

    /// Takes in the rounds that were asked (in order of round), narrowing the pair. A round that does not
    /// fit (times that run backwards, one outside the pair) ends the search: what the node says of this
    /// feed is not to be reasoned from.
    fn take(&mut self, seen: &[Seen]) -> bool {
        let mut before = self.low;
        for round in seen {
            if round.round <= self.low.round
                || round.round >= self.high.round
                || round.time < before.time
                || round.time > self.high.time
            {
                return false;
            }
            before = *round;
        }
        // Times only rise with the rounds, so the rounds at or before the moment come first.
        if let Some(low) = seen.iter().rev().find(|round| round.time <= self.wanted) {
            self.low = *low;
        }
        if let Some(high) = seen.iter().find(|round| round.time > self.wanted) {
            self.high = *high;
        }
        self.low.round < self.high.round
    }

    /// The price a day ago, if the search found it: exactly where the two rounds are neighbours, and
    /// otherwise only if the round at hand was written within the slack of that time.
    fn price(&self, decimals: u8) -> Option<u128> {
        let exact = self.high.round.saturating_sub(self.low.round) == 1;
        (exact || self.wanted.saturating_sub(self.low.time) <= REFERENCE_SLACK_SECONDS)
            .then(|| to_e8(self.low.answer, decimals))
            .flatten()
            .filter(|price| *price > 0)
    }
}

/// A round of the feed as asked for, if the node gave it and it is that round.
fn read_round(result: Option<&abi::SubResult>, asked: u128) -> Option<abi::Round> {
    let round = result.filter(|r| r.success).and_then(|r| abi::decode_round(&r.data))?;
    (round.round == asked).then_some(round)
}

/// The prices a day ago of the feeds on one network, for `latest` readings.
///
/// The price a day ago is what the last round written at or before that moment said, and a feed writes
/// when the price has moved enough or its heartbeat has run out, so how many rounds back that is differs
/// from feed to feed and from day to day. So it is searched for, in the feed's own rounds
/// (`getRoundData`, an ordinary read of the latest state, one sub-call of the one `eth_call` of the
/// chain's feeds for each round asked):
///
/// 1. one question puts a ladder of rounds, four times as far back each, on the chain: the nearest
///    written at or before a day ago, and the nearest after it, are a first pair;
/// 2. up to [`HOPS`] more narrow the pair, each asking for the round where the moment would fall if the
///    rounds between were evenly spaced, a few either side of it, and the middle (so that however unevenly
///    the feed wrote, half of what is left goes at least);
/// 3. where the pair are neighbours the answer is exact, however long before a day ago the earlier was
///    written (a feed that waits for its heartbeat has one in force for a day or more).
///
/// It takes two to six questions a chain, one after the other (the ladder, and as many narrowings as the
/// feeds of the chain need: five on BNB Chain and two on Ethereum when measured on 2026-11-01), once an hour,
/// and [`prices`] gives it [`SEARCH_FOR_MS`] in all. A feed that cannot be pinned down is shown no change.
async fn day_ago(
    net: &Net,
    state: &State,
    latest: &[(&'static Feed, Reading)],
    now: u64,
) -> ChainResult<()> {
    // The ladder: for each feed the rounds a few, a few hundred, a few thousand … back, down to the first
    // round of its phase.
    let mut calls: Vec<SubCall> = Vec::new();
    let mut ladders: Vec<(&'static Feed, Reading, u128, Vec<u64>)> = Vec::new();
    for &(feed, reading) in latest {
        let newest = u64::try_from(reading.round & u128::from(u64::MAX)).unwrap_or(0);
        if newest < 2 || reading.updated_at <= DAY {
            state.set_reference(feed.asset, None, now);
            continue;
        }
        let phase = reading.round - u128::from(newest);
        let mut rounds: Vec<u64> =
            LADDER.iter().filter(|back| **back < newest).map(|back| newest - back).collect();
        rounds.push(1);
        rounds.dedup();
        for round in &rounds {
            calls.push(SubCall {
                target: target(feed.address)?,
                data: round_data(phase | u128::from(*round)),
            });
        }
        ladders.push((feed, reading, phase, rounds));
    }
    if calls.is_empty() {
        return Ok(());
    }
    let mut results = multicall(net, &calls).await?.into_iter();
    let mut searches: Vec<Search> = Vec::new();
    for (feed, reading, phase, rounds) in ladders {
        let wanted = reading.updated_at - DAY;
        let newest = u64::try_from(reading.round & u128::from(u64::MAX)).unwrap_or(0);
        // (The latest is only ever the upper end, whose price nothing reads: its answer is not kept.)
        let latest = Seen { round: newest, time: reading.updated_at, answer: 0 };
        let (mut low, mut high) = (None, latest);
        for round in rounds {
            // (Every round of the ladder is taken from the results, found or not: the next feed's follow.)
            let result = results.next();
            if low.is_some() {
                continue;
            }
            let Some(read) = read_round(result.as_ref(), phase | u128::from(round)) else {
                continue;
            };
            let seen = Seen { round, time: read.updated_at, answer: read.answer };
            if seen.time <= wanted {
                low = Some(seen);
            } else if seen.time <= high.time {
                // Written after the moment, and before the nearer of those so far: the new upper end.
                high = seen;
            }
        }
        match low {
            Some(low) => searches.push(Search { feed, phase, wanted, low, high }),
            None => state.set_reference(feed.asset, None, now),
        }
    }

    // Narrowing the pair down, questions to each feed that still has rounds between its two.
    for _ in 0..HOPS {
        let mut calls: Vec<SubCall> = Vec::new();
        let mut asked: Vec<(usize, Vec<u64>)> = Vec::new();
        for (at, search) in searches.iter().enumerate() {
            let rounds = search.questions();
            if rounds.is_empty() {
                continue;
            }
            for round in &rounds {
                calls.push(SubCall {
                    target: target(search.feed.address)?,
                    data: round_data(search.phase | u128::from(*round)),
                });
            }
            asked.push((at, rounds));
        }
        if calls.is_empty() {
            break;
        }
        let Ok(results) = multicall(net, &calls).await else { break };
        let mut results = results.into_iter();
        let mut dropped: Vec<usize> = Vec::new();
        for (at, rounds) in asked {
            let search = &mut searches[at];
            // Every question of the feed is taken from the results, read or not.
            let read: Vec<Option<Seen>> = rounds
                .iter()
                .map(|round| {
                    let result = results.next();
                    read_round(result.as_ref(), search.phase | u128::from(*round)).map(|read| {
                        Seen { round: *round, time: read.updated_at, answer: read.answer }
                    })
                })
                .collect();
            // A round the node would not give is a gap in what is known, not an answer: the rest are used.
            let seen: Vec<Seen> = read.into_iter().flatten().collect();
            if !search.take(&seen) {
                dropped.push(at);
            }
        }
        for at in dropped.into_iter().rev() {
            let gone = searches.remove(at);
            state.set_reference(gone.feed.asset, None, now);
        }
    }
    for search in searches {
        let decimals = state.decimals_of(search.feed.asset).unwrap_or(8);
        state.set_reference(search.feed.asset, search.price(decimals), now);
    }
    Ok(())
}

/// [`day_ago`] for the feeds of one network that are due, if any are. A reference that cannot be found is
/// no change shown, not a failure.
async fn search_day_ago(net: &Net, state: &State, due: &[(&'static Feed, Reading)], now: u64) {
    if !due.is_empty() && day_ago(net, state, due, now).await.is_err() {
        for (feed, _) in due {
            state.set_reference(feed.asset, None, now);
        }
    }
}

async fn multicall(net: &Net, calls: &[SubCall]) -> ChainResult<Vec<abi::SubResult>> {
    let answer = net
        .rpc(
            Need::ANY,
            "eth_call",
            &json!([{ "to": abi::MULTICALL3, "data": to_hex(&abi::aggregate3(calls)) }, "latest"]),
        )
        .await?
        .map_err(|_| ChainError::Unavailable)?;
    let bytes = answer.as_str().and_then(bytes_from_hex).ok_or(ChainError::Unavailable)?;
    abi::decode_aggregate3(&bytes)
        .filter(|results| results.len() == calls.len())
        .ok_or(ChainError::Unavailable)
}

/// The prices of `assets` (all there are, if empty) as the apps read them. A ticker nothing lists is
/// left out and named in `unknown`: it never fails the prices of the others.
pub async fn prices(
    bsc: &Net,
    ethereum: &Net,
    state: &State,
    assets: &[String],
) -> ChainResult<Value> {
    let mut unknown: Vec<String> = Vec::new();
    let wanted: Vec<&'static Feed> = if assets.is_empty() {
        FEEDS.iter().collect()
    } else {
        let mut found = Vec::new();
        for ticker in assets {
            match FEEDS.iter().find(|f| f.asset.eq_ignore_ascii_case(ticker)) {
                Some(feed) if !found.contains(&feed) => found.push(feed),
                None if !unknown.contains(&clean(ticker)) => unknown.push(clean(ticker)),
                Some(_) | None => {}
            }
        }
        found
    };
    if !assets.is_empty() && wanted.is_empty() {
        return Ok(json!({ "prices": {}, "unknown": unknown }));
    }
    let now = bsc.now() / 1000;
    let on = |network: Network| -> Vec<&'static Feed> {
        wanted.iter().copied().filter(|f| f.network == network).collect()
    };
    let (on_bsc, on_ethereum) = (on(Network::Bsc), on(Network::Ethereum));
    let (from_bsc, from_ethereum) = futures::join!(
        async { if on_bsc.is_empty() { Ok(Vec::new()) } else { read(bsc, state, &on_bsc).await } },
        async {
            if on_ethereum.is_empty() {
                Ok(Vec::new())
            } else {
                read(ethereum, state, &on_ethereum).await
            }
        },
    );
    // One network failing leaves the other's prices; both failing is an error.
    if from_bsc.is_err() && from_ethereum.is_err() {
        return Err(from_bsc.err().unwrap_or(ChainError::Unavailable));
    }
    let readings: Vec<(&'static Feed, Option<Reading>)> =
        from_bsc.into_iter().flatten().chain(from_ethereum.into_iter().flatten()).collect();

    // Yesterday's prices, looked for once an hour for the coins that need it: both chains at once, and for no
    // longer than SEARCH_FOR_MS in all. The prices are in hand and the person is waiting for them; what is not
    // found in time is shown no change, and looked for again in a few minutes.
    let due_on = |network: Network| -> Vec<(&'static Feed, Reading)> {
        readings
            .iter()
            .filter(|(f, _)| f.network == network)
            .filter_map(|(f, r)| Some((*f, (*r)?)))
            .filter(|(f, _)| state.reference_of(f.asset, now) == Held::Missing)
            .collect()
    };
    let (due_bsc, due_ethereum) = (due_on(Network::Bsc), due_on(Network::Ethereum));
    if !due_bsc.is_empty() || !due_ethereum.is_empty() {
        let search = Box::pin(futures::future::join(
            search_day_ago(bsc, state, &due_bsc, now),
            search_day_ago(ethereum, state, &due_ethereum, now),
        ));
        let out_of_time = bsc.platform().sleep(SEARCH_FOR_MS);
        if let Either::Right(_) = futures::future::select(search, out_of_time).await {
            for (feed, _) in due_bsc.iter().chain(&due_ethereum) {
                if state.reference_of(feed.asset, now) == Held::Missing {
                    state.postpone_reference(feed.asset, now);
                }
            }
        }
    }

    let mut out = serde_json::Map::new();
    for (feed, reading) in readings {
        match reading {
            Some(reading) => {
                let stale = now.saturating_sub(reading.updated_at) > feed.heartbeat + GRACE_SECONDS;
                let change = match state.reference_of(feed.asset, now) {
                    Held::Price(then) => change_text(reading.usd_e8, then),
                    Held::Missing | Held::NoPrice => None,
                };
                out.insert(
                    feed.asset.to_owned(),
                    json!({
                        "usd": usd_text(reading.usd_e8),
                        "change_24h": change,
                        "updated_at": rfc3339(reading.updated_at),
                        "stale": stale,
                    }),
                );
            }
            // A stablecoin with no reading is a dollar, and said to be unread.
            None if STABLECOINS.contains(&feed.asset) => {
                out.insert(
                    feed.asset.to_owned(),
                    json!({ "usd": usd_text(100_000_000), "change_24h": null, "updated_at": null, "stale": true }),
                );
            }
            None => {}
        }
    }
    if unknown.is_empty() {
        return Ok(json!({ "prices": out }));
    }
    Ok(json!({ "prices": out, "unknown": unknown }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_change_between_prices_a_node_makes_up_never_overflows() {
        // The multiplication is checked; the addition after it must be too. None of these may panic.
        let edges = [0, 1, 2, u128::MAX / 10_000, u128::MAX / 10_000 + 1, u128::MAX - 1, u128::MAX];
        for now in edges {
            for then in edges {
                let _ = change_text(now, then);
            }
        }
        assert_eq!(change_text(110, 100).as_deref(), Some("10.00"));
        assert_eq!(change_text(90, 100).as_deref(), Some("-10.00"));
    }

    use super::*;

    #[test]
    fn a_feeds_answer_is_scaled_to_eight_decimals_by_its_own_decimals() {
        assert_eq!(to_e8(9_654_312_345_678, 8), Some(9_654_312_345_678));
        assert_eq!(to_e8(96_543_123_456_780_000_000_000, 18), Some(9_654_312_345_678));
        assert_eq!(to_e8(96_543, 3), Some(9_654_300_000));
    }

    #[test]
    fn prices_and_changes_are_written_without_a_float() {
        assert_eq!(usd_text(9_654_312_345_678), "96543.12345678");
        assert_eq!(usd_text(100_000_000), "1.00000000");
        assert_eq!(usd_text(5), "0.00000005");
        assert_eq!(change_text(101_230, 100_000).as_deref(), Some("1.23"));
        assert_eq!(change_text(99_600, 100_000).as_deref(), Some("-0.40"));
        assert_eq!(change_text(100_000, 100_000).as_deref(), Some("0.00"));
        assert_eq!(change_text(300_000, 100_000).as_deref(), Some("200.00"));
        assert_eq!(change_text(1, 0), None);
    }

    /// What Multicall3 answers: `(success, return data)` for each call.
    fn multicall_answer(results: &[(bool, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&crate::util::pad_u128(32));
        out.extend_from_slice(&crate::util::pad_u128(results.len() as u128));
        let mut elements = Vec::new();
        for (success, data) in results {
            let mut element = Vec::new();
            element.extend_from_slice(&crate::util::pad_u128(u128::from(*success)));
            element.extend_from_slice(&crate::util::pad_u128(64));
            element.extend_from_slice(&crate::util::pad_u128(data.len() as u128));
            element.extend_from_slice(data);
            element.extend(std::iter::repeat_n(0_u8, (32 - data.len() % 32) % 32));
            elements.push(element);
        }
        let mut offset = results.len() * 32;
        for element in &elements {
            out.extend_from_slice(&crate::util::pad_u128(offset as u128));
            offset += element.len();
        }
        out.extend(elements.concat());
        out
    }

    /// A node that answers every `eth_call` with what Multicall3 would say for one feed: its description
    /// and decimals (asked the first time), and a round of `answer` at `updated_at`.
    fn client_with_a_feed(
        feed: &Feed,
        answer: u128,
        updated_at: u64,
    ) -> crate::client::ChainClient {
        use crate::util::pad_u128;
        let mut description = pad_u128(32).to_vec();
        description.extend_from_slice(&pad_u128(feed.description.len() as u128));
        description.extend_from_slice(feed.description.as_bytes());
        description.extend(std::iter::repeat_n(0_u8, (32 - feed.description.len() % 32) % 32));
        // Round 3: too young to look a day back, so no second question is asked.
        let round: Vec<u8> = [3, answer, 1, u128::from(updated_at), 3]
            .iter()
            .flat_map(|word| pad_u128(*word))
            .collect();
        let script = std::sync::Arc::new(crate::testing::Script::new());
        let result = to_hex(&multicall_answer(&[
            (true, description),
            (true, pad_u128(8).to_vec()),
            (true, round),
        ]));
        script.rpc("eth_call", &json!(result));
        crate::client::ChainClient::new(script)
    }

    #[tokio::test]
    async fn a_ticker_nothing_lists_is_named_and_never_fails_the_others() {
        let eth = FEEDS.iter().find(|f| f.asset == "ETH").unwrap();
        let client = client_with_a_feed(eth, 2_000 * 100_000_000, 1_793_145_600);
        let body = client
            .dispatch("prices", &json!({ "assets": ["ETH", "DOGE", "eth", "NOPE", "DOGE"] }))
            .await
            .unwrap();
        assert_eq!(body["prices"]["ETH"]["usd"], "2000.00000000", "{body}");
        assert_eq!(body["prices"].as_object().unwrap().len(), 1);
        assert_eq!(body["unknown"], json!(["DOGE", "NOPE"]));
        // Every ticker priced: no `unknown` at all, as before.
        let all_known = client.dispatch("prices", &json!({ "assets": ["ETH"] })).await.unwrap();
        assert!(all_known.get("unknown").is_none(), "{all_known}");
        // Only tickers nothing lists: nothing is priced, and nothing is asked of any node.
        let before = client.traffic().0;
        let none = client.dispatch("prices", &json!({ "assets": ["DOGE", "PEPE"] })).await.unwrap();
        assert!(none["prices"].as_object().unwrap().is_empty(), "{none}");
        assert_eq!(none["unknown"], json!(["DOGE", "PEPE"]));
        assert_eq!(client.traffic().0, before);
    }

    // ---- the price a day ago, found in feeds that write at their own pace ----

    /// A feed's history as a test makes it: round `i` (from 1) was written at `rounds[i - 1].0` and said
    /// `rounds[i - 1].1` (eight decimals).
    type History = Vec<(u64, u128)>;

    /// The chain's Chainlink feeds, answered through Multicall3 as a node would answer
    /// `description()`, `decimals()`, `latestRoundData()` and `getRoundData(id)`, counting the `eth_call`s.
    struct Feeds {
        histories: Vec<(&'static Feed, History)>,
        phase: u128,
        calls: std::sync::atomic::AtomicUsize,
        /// Unix seconds; the test moves it.
        now: std::sync::atomic::AtomicU64,
        /// Answers every `getRoundData` with these instead (a node making things up).
        liar: Option<(u64, u128)>,
        /// From this many requests on, none is ever answered (a node that takes for ever over every question).
        stall_from: std::sync::atomic::AtomicUsize,
    }

    impl Feeds {
        fn answer(&self, target: &[u8; 20], data: &[u8]) -> (bool, Vec<u8>) {
            use crate::util::pad_u128;
            let Some((feed, history)) = self
                .histories
                .iter()
                .find(|(f, _)| super::target(f.address).is_ok_and(|address| &address == target))
            else {
                return (false, Vec::new());
            };
            let round_words = |id: u128, time: u64, answer: u128| -> Vec<u8> {
                [id, answer, u128::from(time), u128::from(time), id]
                    .iter()
                    .flat_map(|w| pad_u128(*w))
                    .collect()
            };
            let (selector, rest) = data.split_at(4.min(data.len()));
            let is = |signature: &str| selector == nc_wallet_core::evm::abi::selector(signature);
            if is("description()") {
                let mut out = pad_u128(32).to_vec();
                out.extend_from_slice(&pad_u128(feed.description.len() as u128));
                out.extend_from_slice(feed.description.as_bytes());
                out.extend(std::iter::repeat_n(0_u8, (32 - feed.description.len() % 32) % 32));
                (true, out)
            } else if is("decimals()") {
                (true, pad_u128(8).to_vec())
            } else if is("latestRoundData()") {
                let (time, answer) = history[history.len() - 1];
                (true, round_words(self.phase << 64 | history.len() as u128, time, answer))
            } else if is("getRoundData(uint80)") {
                let id = word_to_u128(rest).unwrap_or(0);
                let index = usize::try_from(id & u128::from(u64::MAX)).unwrap_or(0);
                if let Some((time, answer)) = self.liar {
                    return (true, round_words(id, time, answer));
                }
                match history.get(index.wrapping_sub(1)) {
                    Some(&(time, answer)) if id >> 64 == self.phase => {
                        (true, round_words(id, time, answer))
                    }
                    _ => (false, Vec::new()),
                }
            } else {
                (false, Vec::new())
            }
        }
    }

    impl crate::platform::Platform for Feeds {
        fn send(
            &self,
            request: crate::platform::HttpRequest,
        ) -> crate::platform::BoxFut<
            '_,
            Result<crate::platform::HttpResponse, crate::platform::HttpError>,
        > {
            Box::pin(async move {
                let asked = self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if asked >= self.stall_from.load(std::sync::atomic::Ordering::Relaxed) {
                    std::future::pending::<()>().await;
                }
                let body: Value =
                    serde_json::from_slice(&request.body.unwrap_or_default()).unwrap();
                let data = bytes_from_hex(body["params"][0]["data"].as_str().unwrap()).unwrap();
                // Multicall3's `aggregate3`: the selector, the array's offset and length, the offsets, and
                // for each call the target, allowFailure, the offset of the bytes, their length and them.
                let args = &data[4..];
                let word =
                    |at: usize| usize::try_from(word_to_u128(&args[at..at + 32]).unwrap()).unwrap();
                let count = word(32);
                let mut results = Vec::new();
                for index in 0..count {
                    let element = 64 + word(64 + index * 32);
                    let target: [u8; 20] = args[element + 12..element + 32].try_into().unwrap();
                    let length = word(element + 96);
                    results
                        .push(self.answer(&target, &args[element + 128..element + 128 + length]));
                }
                let answer = json!({ "jsonrpc": "2.0", "id": 1, "result": to_hex(&multicall_answer(&results)) });
                Ok(crate::platform::HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: answer.to_string().into_bytes(),
                })
            })
        }

        fn sleep(&self, _millis: u64) -> crate::platform::BoxFut<'_, ()> {
            Box::pin(async {})
        }

        fn now_ms(&self) -> u64 {
            self.now.load(std::sync::atomic::Ordering::Relaxed) * 1000
        }
    }

    /// A deterministic stream of numbers.
    struct Dice(u64);

    impl Dice {
        /// A number below `n`.
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % n
        }
    }

    /// `days` of history ending at `now`, `per_day` rounds a day on average: the gaps are anything but
    /// even (a feed writes when the price has moved enough, and at least every heartbeat), so the number of
    /// rounds in a day is not the number of rounds in the next.
    fn history(seed: u64, now: u64, per_day: u64, days: u64, start: u128) -> History {
        let mut dice = Dice(seed);
        let mean = 86_400 / per_day;
        let mut times = Vec::new();
        let mut at = now - 20;
        while now - at < days * 86_400 {
            times.push(at);
            // Between 5% and 4 times the mean, bunched towards short gaps (the cube of a number below one).
            let u = dice.below(1_001);
            let permille = 50 + 4 * (u * u * u / 1_000_000);
            at = at.saturating_sub((mean * permille / 1_000).max(1));
        }
        times.reverse();
        let mut price = start;
        times
            .into_iter()
            .map(|time| {
                // A third of a percent either way.
                price = price * u128::from(997_000 + dice.below(6_001)) / 1_000_000;
                (time, price.max(1))
            })
            .collect()
    }

    /// The price at `then` the way a feed knows it: what the last round at or before it said.
    fn price_at(history: &History, then: u64) -> Option<u128> {
        history.iter().rev().find(|(time, _)| *time <= then).map(|(_, answer)| *answer)
    }

    /// Rounds a day, by coin, as measured on the live feeds: a fast one,
    /// some that write when the price moves and some that wait for their heartbeat.
    fn rate_of(asset: &str) -> u64 {
        match asset {
            "BNB" => 2_600,
            "ETH" | "BTC" => 1_400,
            "XLM" => 300,
            "TRX" => 250,
            "SOL" => 214,
            "POL" => 150,
            "USDT" | "USDC" => 96,
            _ => 3,
        }
    }

    fn feeds_of(now: u64, shape: impl Fn(&Feed) -> (u64, u64)) -> Feeds {
        Feeds {
            histories: FEEDS
                .iter()
                .map(|feed| {
                    let (per_day, days) = shape(feed);
                    let seed = feed.asset.bytes().fold(7, |acc, b| acc * 31 + u64::from(b));
                    (feed, history(seed, now, per_day, days, 100_000_000 * 40))
                })
                .collect(),
            phase: 4,
            calls: std::sync::atomic::AtomicUsize::new(0),
            now: std::sync::atomic::AtomicU64::new(now),
            liar: None,
            stall_from: std::sync::atomic::AtomicUsize::new(usize::MAX),
        }
    }

    /// The prices of every coin, from feeds that have kept the pace of `rate_of` for `days`: each coin's
    /// change is the one the history says, to the digit, in no more questions than the bound.
    async fn every_change_is_found_in_feeds_that_have_kept_their_pace_for(days: u64) {
        let now = 1_793_145_600;
        let feeds = std::sync::Arc::new(feeds_of(now, |feed| (rate_of(feed.asset), days)));
        let client = crate::client::ChainClient::new(feeds.clone());
        let body = client.dispatch("prices", &json!({})).await.unwrap();
        for (feed, history) in &feeds.histories {
            let (latest_time, latest) = history[history.len() - 1];
            let then = price_at(history, latest_time - DAY).unwrap();
            let want = change_text(latest, then);
            assert!(want.is_some(), "{} over {days} days", feed.asset);
            assert_eq!(
                body["prices"][feed.asset]["change_24h"],
                json!(want),
                "{} over {days} days",
                feed.asset
            );
        }
        // Two chains: the reading (and the checks of the feeds), then the ladder and the questions that
        // narrow it down. Not more than the bound, whatever the age of the feeds.
        let asked = feeds.calls.load(std::sync::atomic::Ordering::Relaxed);
        assert!(asked <= 2 + 2 * (1 + HOPS), "{asked} over {days} days");
    }

    #[tokio::test]
    async fn the_price_a_day_ago_is_found_for_every_coin_whatever_pace_its_feed_keeps() {
        every_change_is_found_in_feeds_that_have_kept_their_pace_for(8).await;
    }

    #[tokio::test]
    async fn the_price_a_day_ago_is_found_in_feeds_a_year_and_more_old() {
        // The live feeds have been written for years: 1,400 rounds a day for ETH and BTC is some 700,000
        // rounds in 500 days, BNB's 2,600 more than a million. Every rung of the ladder is asked of them
        // (the short histories above reach the fourth at most), and the answer is as exact as for a week.
        every_change_is_found_in_feeds_that_have_kept_their_pace_for(500).await;
    }

    #[tokio::test]
    async fn a_round_in_force_a_day_ago_may_have_been_written_much_earlier_than_that() {
        // A feed that writes once a day: the price in force a day ago is the one written thirty hours ago,
        // since the next round came only now. Six hours is past the slack an approximate answer would need,
        // and it is not approximate: nothing was written between.
        let now = 1_793_145_600;
        let mut feeds = feeds_of(now, |feed| (rate_of(feed.asset), 8));
        let slow = feeds.histories.iter_mut().find(|(f, _)| f.asset == "TAO").unwrap();
        slow.1 = vec![
            (now - 90 * 3600, 30_000_000_000),
            (now - 30 * 3600, 33_000_000_000),
            (now - 20, 36_000_000_000),
        ];
        let client = crate::client::ChainClient::new(std::sync::Arc::new(feeds));
        let body = client.dispatch("prices", &json!({ "assets": ["TAO"] })).await.unwrap();
        assert_eq!(
            body["prices"]["TAO"]["change_24h"],
            json!(change_text(36_000_000_000, 33_000_000_000))
        );
    }

    #[tokio::test]
    async fn a_feed_younger_than_a_day_has_no_change_and_a_node_making_the_rounds_up_ends_the_search()
     {
        let now = 1_793_145_600;
        // Rounds from the last few hours only: nothing a day ago to compare with.
        let mut feeds = feeds_of(now, |feed| (rate_of(feed.asset), 8));
        let sol = feeds.histories.iter_mut().find(|(f, _)| f.asset == "SOL").unwrap();
        sol.1.drain(..sol.1.len() - 40);
        let client = crate::client::ChainClient::new(std::sync::Arc::new(feeds));
        let body = client.dispatch("prices", &json!({ "assets": ["SOL", "ETH"] })).await.unwrap();
        assert!(body["prices"]["SOL"]["change_24h"].is_null(), "{body}");
        assert!(body["prices"]["ETH"]["change_24h"].is_string(), "{body}");

        // A node that gives every round the same absurd time and answer: the search ends within its bound,
        // without a panic, and what it shows is no change or a change it can account for.
        for (time, answer) in
            [(u64::MAX, u128::MAX >> 1), (0, 1), (now, 7), (1, u128::from(u64::MAX))]
        {
            let mut feeds = feeds_of(now, |feed| (rate_of(feed.asset), 8));
            feeds.liar = Some((time, answer));
            let feeds = std::sync::Arc::new(feeds);
            let client = crate::client::ChainClient::new(feeds.clone());
            let body =
                client.dispatch("prices", &json!({ "assets": ["ETH", "TAO"] })).await.unwrap();
            assert!(body["prices"]["ETH"]["usd"].is_string(), "{body}");
            assert!(feeds.calls.load(std::sync::atomic::Ordering::Relaxed) <= 2 + 2 * (1 + HOPS));
        }
    }

    #[tokio::test]
    async fn prices_do_not_wait_for_a_search_that_a_slow_node_will_not_finish() {
        use std::sync::atomic::Ordering::Relaxed;
        // PublicNode's BNB Chain endpoint took 4 to 18 seconds over every state read, and the search asks up to
        // six questions in a row. Here no question after the two readings is ever answered: the prices must
        // come back all the same, without a change, when the search has had its time.
        let now = 1_793_145_600;
        let feeds = feeds_of(now, |feed| (rate_of(feed.asset), 8));
        feeds.stall_from.store(2, Relaxed);
        let feeds = std::sync::Arc::new(feeds);
        let client = crate::client::ChainClient::new(feeds.clone());
        let request = json!({ "fresh": true });
        let ask = || async {
            let wait = std::time::Duration::from_secs(10);
            let answer = tokio::time::timeout(wait, client.dispatch("prices", &request));
            answer.await.expect("the prices came back without waiting for the search").unwrap()
        };
        let body = ask().await;
        for feed in FEEDS {
            assert!(body["prices"][feed.asset]["usd"].is_string(), "{}", feed.asset);
            assert!(body["prices"][feed.asset]["change_24h"].is_null(), "{}", feed.asset);
        }
        // The node recovers. A coin whose search ran out of time is looked for again in ten minutes, not at once
        // and not in an hour: a minute on, only the prices are read (a request for each chain).
        feeds.stall_from.store(usize::MAX, Relaxed);
        feeds.now.fetch_add(60, Relaxed);
        let before = feeds.calls.load(Relaxed);
        let body = ask().await;
        assert_eq!(feeds.calls.load(Relaxed) - before, 2);
        assert!(body["prices"]["ETH"]["change_24h"].is_null(), "{body}");
        // Eleven minutes on, it is searched for again, and found.
        feeds.now.fetch_add(10 * 60, Relaxed);
        let body = ask().await;
        for (feed, history) in &feeds.histories {
            let (latest_time, latest) = history[history.len() - 1];
            let then = price_at(history, latest_time - DAY).unwrap();
            assert_eq!(
                body["prices"][feed.asset]["change_24h"],
                json!(change_text(latest, then)),
                "{}",
                feed.asset
            );
        }
    }

    #[test]
    fn every_listed_coin_has_a_feed_and_the_feeds_are_where_the_exchange_reads_them() {
        for network in crate::networks::ALL {
            let native = network.native().symbol;
            assert!(FEEDS.iter().any(|f| f.asset == native), "{native}");
            for token in network.tokens() {
                assert!(FEEDS.iter().any(|f| f.asset == token.symbol), "{}", token.symbol);
            }
        }
        for feed in FEEDS {
            assert!(target(feed.address).is_ok(), "{}", feed.asset);
            assert!(feed.description.ends_with(" / USD"));
        }
        let tao = FEEDS.iter().find(|f| f.asset == "TAO").unwrap();
        assert_eq!(tao.network, Network::Ethereum);
    }

    #[test]
    fn a_remembered_check_counts_only_where_it_agrees_with_the_pinned_decimals() {
        // Every Chainlink USD feed has eight decimals, pinned beside its address.
        assert!(FEEDS.iter().all(|f| f.decimals == 8));
        let state = State::default();
        state.import(&json!({ "verified": [["ETH", 8], ["BTC", 18], ["NOPE", 8], ["BNB", "x"]] }));
        // Only the one that matches the pin is believed; a stored 18 for a feed pinned at 8 is not.
        assert_eq!(state.decimals_of("ETH"), Some(8));
        assert_eq!(state.decimals_of("BTC"), None);
        assert_eq!(state.decimals_of("NOPE"), None);
        assert_eq!(state.decimals_of("BNB"), None);
    }
}
