//! Finding where an HD wallet's coins are: the whole BIP-84 account.
//!
//! A wallet restored from a recovery phrase may have used any address of either chain of its
//! account: receive addresses it gave out (`/0/n`) and change addresses it paid itself
//! (`/1/n`). Esplora has no query for a whole account, so the addresses are derived from the
//! account's `zpub` (no private key) and each is asked about, the way every wallet does:
//!
//! * **The gap limit.** An address is *used* if Esplora has any transaction for it, confirmed or
//!   not. A walk of a chain ends when [`GAP`] (20) addresses in a row are unused.
//! * **A first reading** (nothing known of the account) walks both chains from index 0:
//!   a wallet that used receive 7 and change 3 costs about 28 + 24 lookups, a new one 40.
//!   A wallet *created here* is told to the client as already read (a hint with nothing used),
//!   so it skips this.
//! * **A hint** is what a reading leaves, for the app to keep (sealed) and hand back: the highest
//!   used index on each chain, and which addresses are *live* (hold coins, or have a transaction
//!   waiting). The next reading asks about the live ones, about receive 0 (the address the app
//!   shows), and about the few just past the highest used (a window of [`WINDOW_RECEIVE`] and
//!   [`WINDOW_CHANGE`]): about five lookups for a wallet using one address. If one of the
//!   window turns out used, the walk goes on with the full gap.
//! * **A full re-check** (every address up to the highest used, and the gap) is made when the hint
//!   is a day old, to catch a payment to an old address that was thought finished.
//! * **Bounded.** A reading makes at most [`MOST_LOOKUPS`] lookups; a wallet that needs more says it
//!   is still `scanning` and leaves a `resume` point in its hint: ask again.
//!
//! Nothing here is a secret. The addresses asked about are the ones the wallet would have asked
//! about if it had them one by one.

use std::collections::{BTreeMap, VecDeque};

use nc_wallet_core::bitcoin::{Chain, addresses_from_zpub};
use serde_json::{Value, json};

use super::Bitcoin;
use crate::error::{ChainError, ChainResult};
use crate::pool::Need;
use crate::util::parse_json;

/// How many unused addresses in a row end the walk of a chain.
pub(super) const GAP: u32 = 20;
/// Past the highest used receive address, how many a refresh looks at.
pub(super) const WINDOW_RECEIVE: u32 = 3;
/// Past the highest used change address, how many a refresh looks at (the wallet's own next
/// change address is the first).
pub(super) const WINDOW_CHANGE: u32 = 2;
/// Addresses looked up side by side.
const AT_ONCE: usize = 6;
/// The most lookups one reading makes.
pub(super) const MOST_LOOKUPS: usize = 200;
/// The longest a reading goes on before it hands back what it has and says it is still
/// `scanning` (the app asks again at once, and shows what was found so far): a wallet used on
/// many addresses is looked at for tens of seconds, paced under what the services allow.
pub(super) const MOST_MS: u64 = 12_000;
/// No address past this index is looked at.
const MOST_INDEX: u32 = 5_000;
/// A hint older than this is checked in full.
pub(super) const RESCAN_AFTER_S: u64 = 86_400;
/// How many times a lookup that was told to wait is tried again.
const PATIENCE: u32 = 8;

/// An address of the account that held coins, or had coins waiting, when last read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Live {
    /// Its index on the chain.
    pub index: u32,
    /// Satoshis confirmed.
    pub confirmed: i64,
    /// Satoshis waiting in the mempool, net.
    pub waiting: i64,
}

/// What is known of one chain of the account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainHint {
    /// The highest index known used (`None`: nothing is).
    pub last: Option<u32>,
    /// The highest index that more than one service has said is used (on the change chain, where it
    /// decides where the next change goes; on the receive chain it is `last`). `last` may be ahead of it
    /// while a reading is unfinished or a service's word is not yet confirmed.
    pub proven: Option<u32>,
    /// The addresses that held coins, or had coins waiting, when last read, with what they held:
    /// the next reading asks about these again (and a reading that goes on from an unfinished one
    /// does not need to).
    pub live: Vec<Live>,
    /// Where an unfinished walk goes on from.
    pub resume: Option<u32>,
}

/// What a reading leaves for the next one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hint {
    /// When the account was last read in full (Unix seconds).
    pub at: u64,
    /// The receive chain (`/0/n`).
    pub receive: ChainHint,
    /// The change chain (`/1/n`).
    pub change: ChainHint,
}

impl Hint {
    /// A hint for an account known to have no history at all (made here, a moment ago).
    #[must_use]
    pub fn unused(now_s: u64) -> Self {
        Self { at: now_s, ..Self::default() }
    }

    fn of(&self, chain: Chain) -> &ChainHint {
        if chain == Chain::Receive { &self.receive } else { &self.change }
    }

    /// The hint as the apps keep it.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let one = |c: &ChainHint| {
            let live: Vec<Value> =
                c.live.iter().map(|l| json!([l.index, l.confirmed, l.waiting])).collect();
            json!({ "last": c.last, "proven": c.proven, "live": live, "resume": c.resume })
        };
        json!({ "v": 1, "at": self.at, "r": one(&self.receive), "c": one(&self.change) })
    }

    /// Reads a hint an app handed back; anything that is not one is no hint (the account is then
    /// read from the start).
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        if value.get("v")?.as_u64()? != 1 {
            return None;
        }
        let index =
            |v: &Value| v.as_u64().and_then(|n| u32::try_from(n).ok()).filter(|n| *n <= MOST_INDEX);
        let one = |c: &Value| -> Option<ChainHint> {
            let last = match c.get("last")? {
                Value::Null => None,
                other => Some(index(other)?),
            };
            let resume = match c.get("resume") {
                None | Some(Value::Null) => None,
                Some(other) => Some(index(other)?),
            };
            // (A hint without it is one from before it was kept: its last is taken as proven.)
            let proven = match c.get("proven") {
                None => last,
                Some(Value::Null) => None,
                Some(other) => Some(index(other)?),
            };
            let mut live: Vec<Live> = c
                .get("live")?
                .as_array()?
                .iter()
                .map(|entry| {
                    Some(Live {
                        index: index(entry.get(0)?)?,
                        confirmed: entry.get(1)?.as_i64()?,
                        waiting: entry.get(2)?.as_i64()?,
                    })
                })
                .collect::<Option<_>>()?;
            if live.len() > 1_000 {
                return None;
            }
            live.sort_by_key(|l| l.index);
            live.dedup_by_key(|l| l.index);
            Some(ChainHint { last, proven, live, resume })
        };
        Some(Self {
            at: value.get("at")?.as_u64()?,
            receive: one(value.get("r")?)?,
            change: one(value.get("c")?)?,
        })
    }

    /// The first change index nothing has used (past the highest that two services agree is used).
    #[must_use]
    pub fn next_change(&self) -> u32 {
        self.change.last.map_or(0, |l| l + 1)
    }
}

/// One address of the account holding coins (or with a transaction waiting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// Its chain.
    pub chain: Chain,
    /// Its index.
    pub index: u32,
    /// The address.
    pub address: String,
    /// Satoshis confirmed.
    pub confirmed: i128,
    /// Satoshis waiting in the mempool, net (negative while spending).
    pub waiting: i128,
}

/// A reading of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    /// The addresses holding coins or with something waiting.
    pub held: Vec<Held>,
    /// What to keep for the next reading.
    pub hint: Hint,
    /// The lookups made.
    pub lookups: u32,
    /// More remains to be found: ask again.
    pub scanning: bool,
}

/// What Esplora says of one address.
#[derive(Debug, Clone, Copy)]
struct Stats {
    used: bool,
    confirmed: i128,
    waiting: i128,
}

fn stats_of(body: &Value) -> Option<Stats> {
    let sum = |kind: &str| -> Option<i128> {
        let funded = i128::from(body.pointer(&format!("/{kind}/funded_txo_sum"))?.as_u64()?);
        let spent = i128::from(body.pointer(&format!("/{kind}/spent_txo_sum"))?.as_u64()?);
        Some(funded - spent)
    };
    let count = |kind: &str| body.pointer(&format!("/{kind}/tx_count")).and_then(Value::as_u64);
    let (chain_txs, mempool_txs) = (count("chain_stats")?, count("mempool_stats")?);
    Some(Stats {
        // (Counts a service writes can be anything: 2^64-1 and one more must not overflow.)
        used: chain_txs.saturating_add(mempool_txs) > 0,
        confirmed: sum("chain_stats")?,
        waiting: sum("mempool_stats")?,
    })
}

/// The walk of one chain.
struct Walk {
    /// Indexes to ask about.
    queue: VecDeque<u32>,
    /// What was found, by index.
    found: BTreeMap<u32, Stats>,
    /// Which endpoint gave each answer in `found` (a second opinion is asked of another operator).
    from: BTreeMap<u32, usize>,
    /// The addresses the hint knew held coins: one operator's word that they are empty now is not
    /// enough to forget them.
    prior_live: BTreeMap<u32, Live>,
    /// The highest index known used on the word of more than one service (see [`ChainHint::proven`]).
    proven: Option<u32>,
    /// Whether this is the change chain.
    change: bool,
    /// The highest index known used (from the hint or found).
    last: Option<u32>,
    /// How many unused addresses past `last` must have been seen.
    needed: u32,
    /// Whether anything new was found used (then the full gap applies).
    grew: bool,
}

impl Walk {
    fn start(chain: Chain, hint: Option<&ChainHint>, rescan: bool) -> Self {
        let window = if chain == Chain::Receive { WINDOW_RECEIVE } else { WINDOW_CHANGE };
        let known = hint.and_then(|h| h.last);
        let mut queue: VecDeque<u32> = VecDeque::new();
        let mut push = |i: u32| {
            if !queue.contains(&i) {
                queue.push_back(i);
            }
        };
        let needed = match hint {
            // Nothing known: from the start, with the full gap.
            None => {
                push(0);
                GAP
            }
            // Unfinished: go on from where the last reading stopped (what it found is in the hint).
            Some(ChainHint { resume: Some(from), .. }) => {
                push(*from);
                GAP
            }
            // A day old: everything known used again, and the full gap.
            Some(_) if rescan => {
                for i in 0..=known.unwrap_or(0) {
                    push(i);
                }
                GAP
            }
            // Refresh: the live ones, receive 0 (the address the app shows), and the window.
            Some(h) => {
                for l in &h.live {
                    push(l.index);
                }
                if chain == Chain::Receive {
                    push(0);
                }
                window
            }
        };
        // What the gap (or the window) needs past the highest used.
        let first = known.map_or(0, |l| l + 1);
        for i in first..first.saturating_add(needed).min(MOST_INDEX + 1) {
            if !queue.contains(&i) {
                queue.push_back(i);
            }
        }
        let prior_live = hint.map_or_else(BTreeMap::new, |h| {
            h.live.iter().map(|l| (l.index, *l)).collect::<BTreeMap<u32, Live>>()
        });
        Self {
            queue,
            found: BTreeMap::new(),
            from: BTreeMap::new(),
            prior_live,
            proven: hint.and_then(|h| h.proven),
            change: chain == Chain::Change,
            last: known,
            needed,
            grew: false,
        }
    }

    fn next_batch(&mut self) -> Vec<u32> {
        let mut batch = Vec::new();
        while batch.len() < AT_ONCE {
            match self.queue.pop_front() {
                Some(i) if !self.found.contains_key(&i) => batch.push(i),
                Some(_) => {}
                None => break,
            }
        }
        batch
    }

    /// Takes in what a batch found, and asks about whatever the gap still needs.
    #[cfg(test)]
    fn absorb(&mut self, results: &[(u32, Stats)]) {
        let named: Vec<(u32, Stats, usize)> =
            results.iter().map(|&(i, s)| (i, s, usize::MAX)).collect();
        self.absorb_from(&named);
    }

    /// As `absorb`, saying which endpoint answered each.
    fn absorb_from(&mut self, results: &[(u32, Stats, usize)]) {
        for &(index, stats, at) in results {
            self.found.insert(index, stats);
            self.from.insert(index, at);
            if stats.used && self.last.is_none_or(|l| index > l) {
                self.last = Some(index);
                self.grew = true;
            }
        }
        if self.grew {
            self.needed = GAP;
        }
        let first = self.last.map_or(0, |l| l + 1);
        let upto = first.saturating_add(self.needed).min(MOST_INDEX + 1);
        for i in first..upto {
            if !self.found.contains_key(&i) && !self.queue.contains(&i) {
                self.queue.push_back(i);
            }
        }
    }

    fn done(&self) -> bool {
        self.queue.is_empty()
    }

    /// Where an unfinished walk goes on from.
    fn resume(&self) -> Option<u32> {
        self.queue.front().copied()
    }

    fn hint(&self, prior: Option<&ChainHint>) -> ChainHint {
        let mut live: BTreeMap<u32, Live> = BTreeMap::new();
        // What the hint knew live and this walk did not get to stays as it was.
        if let Some(prior) = prior {
            for l in &prior.live {
                if !self.found.contains_key(&l.index) {
                    live.insert(l.index, *l);
                }
            }
        }
        for (&index, stats) in &self.found {
            if stats.confirmed != 0 || stats.waiting != 0 {
                live.insert(
                    index,
                    Live {
                        index,
                        confirmed: i64::try_from(stats.confirmed).unwrap_or(i64::MAX),
                        waiting: i64::try_from(stats.waiting).unwrap_or(i64::MAX),
                    },
                );
            }
        }
        // On the receive chain nothing rests on it; on the change chain it is what two services agreed on.
        let proven = if self.change { self.proven } else { self.last };
        ChainHint {
            last: self.last,
            proven,
            live: live.into_values().collect(),
            resume: self.resume(),
        }
    }
}

impl Bitcoin<'_> {
    /// What an endpoint says of an address, and which endpoint it was. With `other_than`, an operator of
    /// none of those (a rule): a second opinion.
    async fn lookup_from(
        &self,
        address: &str,
        need: Need,
        other_than: &[usize],
    ) -> ChainResult<(Stats, usize)> {
        let ((status, body), at) =
            self.net.get_from(need, other_than, &format!("/address/{address}")).await?;
        if !(200..300).contains(&status) {
            return Err(ChainError::Unavailable);
        }
        let stats = stats_of(&parse_json(&body)?).ok_or(ChainError::Unavailable)?;
        Ok((stats, at))
    }

    /// A second operator's word on an address the first one answered about (`None`: there was no
    /// second operator to ask, or it did not answer).
    async fn second_opinion(
        &self,
        zpub: &str,
        chain: Chain,
        index: u32,
        first: usize,
    ) -> Option<Stats> {
        let address = addresses_from_zpub(zpub, chain, index, 1).and_then(|mut list| list.pop())?;
        let others = if first == usize::MAX { Vec::new() } else { vec![first] };
        self.lookup_from(&address, Need::ANY.independent(), &others).await.ok().map(|(s, _)| s)
    }

    /// Whether an address is used, on the word of more than one operator: a second one where the first
    /// is known, or two of different operators where it is not (an earlier reading's word).
    async fn confirmed_used(
        &self,
        zpub: &str,
        chain: Chain,
        index: u32,
        first: Option<usize>,
    ) -> bool {
        let Some(address) =
            addresses_from_zpub(zpub, chain, index, 1).and_then(|mut list| list.pop())
        else {
            return false;
        };
        if let Some(first) = first {
            return self
                .lookup_from(&address, Need::ANY.independent(), &[first])
                .await
                .is_ok_and(|(s, _)| s.used);
        }
        let path = format!("/address/{address}");
        let Ok(answers) = self.net.get_many(Need::ANY.independent(), 2, &path).await else {
            return false;
        };
        answers.len() >= 2
            && answers.iter().all(|((status, body), _)| {
                (200..300).contains(status)
                    && parse_json(body).ok().as_ref().and_then(stats_of).is_some_and(|s| s.used)
            })
    }

    /// An address the hint knew held coins and a lookup now says is empty is asked of a second operator
    /// before it is forgotten: one lagging or lying service must not hide coins from the balance and
    /// from the next payment. If the second finds coins, they are kept; if it cannot be asked, the
    /// address stays as it was, and is asked again at the next reading.
    async fn keep_what_was_held(
        &self,
        zpub: &str,
        chain: Chain,
        results: Vec<(u32, Stats, usize)>,
        prior_live: &BTreeMap<u32, Live>,
        lookups: &mut u32,
    ) -> Vec<(u32, Stats, usize)> {
        let mut out = Vec::with_capacity(results.len());
        for (index, stats, at) in results {
            let emptied = stats.confirmed == 0 && stats.waiting == 0;
            let Some(held) = prior_live.get(&index).filter(|_| emptied) else {
                out.push((index, stats, at));
                continue;
            };
            *lookups = lookups.saturating_add(1);
            let kept = match self.second_opinion(zpub, chain, index, at).await {
                Some(second) if second.confirmed != 0 || second.waiting != 0 => second,
                Some(_) => stats,
                None => Stats {
                    used: true,
                    confirmed: i128::from(held.confirmed),
                    waiting: i128::from(held.waiting),
                },
            };
            out.push((index, kept, at));
        }
        out
    }

    /// The change address the next payment sends its change to is the one after the highest used, so a
    /// service that says a far address is used would push the change past every other wallet's gap of
    /// twenty (where a restore could not find it). So the highest change address a finished reading
    /// finds used, beyond what was already confirmed, must be confirmed used by a second operator; if it
    /// is not (or none could be asked) it is not counted, and the next one below it is tried. The coins
    /// of such an address are still shown: only where the change goes is held to two opinions.
    async fn confirm_change_top(&self, zpub: &str, walk: &mut Walk, lookups: &mut u32) {
        let known = walk.proven;
        while let Some(top) = walk.last {
            if known.is_some_and(|k| top <= k) {
                break;
            }
            *lookups = lookups.saturating_add(1);
            let first = walk.from.get(&top).copied().filter(|at| *at != usize::MAX);
            if self.confirmed_used(zpub, Chain::Change, top, first).await {
                break;
            }
            walk.last = walk
                .found
                .iter()
                .filter(|(i, s)| s.used && **i < top)
                .map(|(i, _)| *i)
                .max()
                .max(known);
        }
        walk.proven = walk.last;
    }

    /// Asks about a batch, waiting where the endpoints ask for time.
    async fn lookup_batch(
        &self,
        zpub: &str,
        chain: Chain,
        indexes: &[u32],
    ) -> ChainResult<Vec<(u32, Stats, usize)>> {
        let addresses: Vec<(u32, String)> = indexes
            .iter()
            .map(|&i| {
                addresses_from_zpub(zpub, chain, i, 1)
                    .and_then(|mut list| list.pop())
                    .map(|a| (i, a))
                    .ok_or_else(|| ChainError::invalid("the account key is not a zpub"))
            })
            .collect::<ChainResult<_>>()?;
        let mut pending = addresses;
        let mut done: Vec<(u32, Stats, usize)> = Vec::new();
        let mut patience = PATIENCE;
        loop {
            let answers = futures::future::join_all(pending.iter().map(|(i, a)| async move {
                (*i, a.clone(), self.lookup_from(a, Need::ANY, &[]).await)
            }))
            .await;
            let mut again: Vec<(u32, String)> = Vec::new();
            let mut wait: Option<u64> = None;
            let mut failure: Option<ChainError> = None;
            for (i, a, result) in answers {
                match result {
                    Ok((stats, at)) => done.push((i, stats, at)),
                    Err(ChainError::Busy { retry_after_seconds }) => {
                        wait =
                            Some(wait.map_or(retry_after_seconds, |w| w.min(retry_after_seconds)));
                        again.push((i, a));
                    }
                    Err(error) => failure = Some(error),
                }
            }
            if let Some(error) = failure {
                return Err(error);
            }
            if again.is_empty() {
                return Ok(done);
            }
            patience -= 1;
            if patience == 0 {
                return Err(ChainError::Busy { retry_after_seconds: wait.unwrap_or(5) });
            }
            // The endpoints asked for time: give it, and ask the rest again.
            self.net.platform().sleep(wait.unwrap_or(1).clamp(1, 5) * 1000).await;
            pending = again;
        }
    }

    /// Reads the account: where its coins are, and what to keep for the next reading. `start` is
    /// the hint of an earlier reading (`None`: read from the start); `now_s` is the time.
    pub async fn read_account(
        &self,
        zpub: &str,
        start: Option<&Hint>,
        now_s: u64,
    ) -> ChainResult<Reading> {
        // A hint dated in the future (a clock that moved, or a hint made up) is as good as a day old:
        // it would otherwise never come due.
        let rescan =
            start.is_some_and(|h| h.at > now_s || now_s.saturating_sub(h.at) >= RESCAN_AFTER_S);
        let full = start.is_none()
            || rescan
            || start.is_some_and(|h| h.receive.resume.is_some() || h.change.resume.is_some());
        let mut budget = MOST_LOOKUPS;
        let deadline = self.net.now().saturating_add(MOST_MS);
        let mut lookups = 0_u32;
        let mut held: Vec<Held> = Vec::new();
        let mut hint = Hint { at: start.map_or(now_s, |h| h.at), ..Hint::default() };
        let mut scanning = false;
        // Going on from a reading that ran out of lookups or time: a chain it finished is not read
        // again (what it found is in the hint), only the one it did not.
        let continuing =
            start.is_some_and(|h| h.receive.resume.is_some() || h.change.resume.is_some());
        for chain in [Chain::Receive, Chain::Change] {
            let prior = start.map(|h| h.of(chain));
            let carried = continuing && prior.is_some_and(|p| p.resume.is_none());
            let chain_hint = if carried || scanning {
                // Out of lookups or time before this chain: it goes on from where it was (from the
                // start, if nothing was known).
                prior.cloned().unwrap_or(ChainHint {
                    last: None,
                    proven: None,
                    live: Vec::new(),
                    resume: Some(0),
                })
            } else {
                let mut walk = Walk::start(chain, prior, rescan);
                while !walk.done() {
                    if budget == 0 || self.net.now() >= deadline {
                        scanning = true;
                        break;
                    }
                    let mut batch = walk.next_batch();
                    if batch.is_empty() {
                        break;
                    }
                    batch.truncate(budget);
                    budget -= batch.len();
                    lookups += u32::try_from(batch.len()).unwrap_or(u32::MAX);
                    let results = self.lookup_batch(zpub, chain, &batch).await?;
                    let results = self
                        .keep_what_was_held(zpub, chain, results, &walk.prior_live, &mut lookups)
                        .await;
                    walk.absorb_from(&results);
                }
                if chain == Chain::Change && walk.done() {
                    self.confirm_change_top(zpub, &mut walk, &mut lookups).await;
                }
                walk.hint(prior)
            };
            for l in &chain_hint.live {
                let address = addresses_from_zpub(zpub, chain, l.index, 1)
                    .and_then(|mut list| list.pop())
                    .ok_or_else(|| ChainError::invalid("the account key is not a zpub"))?;
                held.push(Held {
                    chain,
                    index: l.index,
                    address,
                    confirmed: i128::from(l.confirmed),
                    waiting: i128::from(l.waiting),
                });
            }
            if chain == Chain::Receive {
                hint.receive = chain_hint;
            } else {
                hint.change = chain_hint;
            }
        }
        // The reading is complete (and dated now) only if the whole walk was made and was a full one.
        if full && !scanning {
            hint.at = now_s;
        }
        Ok(Reading { held, hint, lookups, scanning })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hint_round_trips_and_a_bad_one_is_no_hint() {
        let hint = Hint {
            at: 1_793_000_000,
            receive: ChainHint {
                last: Some(7),
                proven: Some(7),
                live: live(&[0, 7]),
                resume: None,
            },
            change: ChainHint { last: None, proven: None, live: vec![], resume: Some(25) },
        };
        let json = hint.to_json();
        assert_eq!(Hint::from_json(&json), Some(hint.clone()));
        assert_eq!(hint.next_change(), 0);
        let mut used = hint;
        used.change.last = Some(3);
        assert_eq!(used.next_change(), 4);
        for bad in [
            json!({}),
            json!({ "v": 2, "at": 1, "r": { "last": null, "live": [] }, "c": { "last": null, "live": [] } }),
            json!({ "v": 1, "at": 1, "r": { "last": 99999, "live": [] }, "c": { "last": null, "live": [] } }),
            json!({ "v": 1, "at": 1, "r": { "last": null, "live": [["x", 1, 2]] }, "c": { "last": null, "live": [] } }),
            json!({ "v": 1, "at": 1, "r": { "last": null, "live": [[1, 2]] }, "c": { "last": null, "live": [] } }),
            json!({ "v": 1, "at": 1, "r": { "last": null } , "c": { "last": null, "live": [] } }),
            json!("hint"),
        ] {
            assert_eq!(Hint::from_json(&bad), None, "{bad}");
        }
    }

    fn live(indexes: &[u32]) -> Vec<Live> {
        indexes.iter().map(|&index| Live { index, confirmed: 1000, waiting: 0 }).collect()
    }

    fn used(n: u64) -> Stats {
        Stats { used: n > 0, confirmed: i128::from(n) * 1000, waiting: 0 }
    }
    fn unused() -> Stats {
        Stats { used: false, confirmed: 0, waiting: 0 }
    }

    /// Drives a walk over a chain where `usedset` are used.
    fn run(mut walk: Walk, used_at: &[u32]) -> (Walk, usize) {
        let mut asked = 0;
        while !walk.done() {
            let batch = walk.next_batch();
            if batch.is_empty() {
                break;
            }
            asked += batch.len();
            let results: Vec<(u32, Stats)> = batch
                .iter()
                .map(|&i| (i, if used_at.contains(&i) { used(1) } else { unused() }))
                .collect();
            walk.absorb(&results);
        }
        (walk, asked)
    }

    #[test]
    fn a_first_reading_walks_to_twenty_unused_past_the_last_used_address() {
        let (walk, asked) = run(Walk::start(Chain::Receive, None, false), &[0, 3, 7]);
        // 0..=7 used or between, then 8..=27 unused: 28 lookups, no more.
        assert_eq!(asked, 28);
        assert_eq!(walk.last, Some(7));
        let hint = walk.hint(None);
        assert_eq!(hint.last, Some(7));
        assert_eq!(hint.live.iter().map(|l| l.index).collect::<Vec<_>>(), vec![0, 3, 7]);
        assert_eq!(hint.resume, None);
        // An unused account is 20 lookups a chain.
        let (empty, asked) = run(Walk::start(Chain::Change, None, false), &[]);
        assert_eq!(asked, 20);
        assert_eq!(empty.last, None);
    }

    #[test]
    fn a_refresh_asks_only_the_live_the_shown_address_and_a_short_window() {
        let hint = ChainHint { last: Some(7), proven: Some(7), live: live(&[3, 7]), resume: None };
        let (walk, asked) = run(Walk::start(Chain::Receive, Some(&hint), false), &[0, 3, 7]);
        // 3, 7, 0, and the window 8, 9, 10.
        assert_eq!(asked, 6);
        assert_eq!(walk.last, Some(7));
        // A change chain with nothing used: its window of two.
        let none = ChainHint::default();
        let (_, asked) = run(Walk::start(Chain::Change, Some(&none), false), &[]);
        assert_eq!(asked, 2);
        // A new account that has used nothing: three receive lookups (0 is among them) and two change.
        let (_, asked) = run(Walk::start(Chain::Receive, Some(&none), false), &[]);
        assert_eq!(asked, 3);
    }

    #[test]
    fn a_used_address_in_the_window_brings_back_the_full_gap() {
        let hint = ChainHint { last: Some(7), proven: Some(7), live: live(&[7]), resume: None };
        // Receive 9 turned out used: the gap of twenty is walked from there.
        let (walk, asked) = run(Walk::start(Chain::Receive, Some(&hint), false), &[0, 7, 9]);
        assert_eq!(walk.last, Some(9));
        // Five lookups to start (7, 0 and the window 8 to 10), then 11 to 29: twenty unused past 9.
        assert_eq!(asked, 5 + 19);
        assert_eq!(walk.hint(Some(&hint)).last, Some(9));
    }

    #[test]
    fn a_day_old_hint_is_checked_in_full() {
        let hint = ChainHint { last: Some(7), proven: Some(7), live: live(&[7]), resume: None };
        let (_, asked) = run(Walk::start(Chain::Receive, Some(&hint), true), &[0, 3, 7]);
        // 0..=7 again and the gap of twenty after it.
        assert_eq!(asked, 28);
    }

    #[test]
    fn what_a_hint_knew_live_and_a_refresh_did_not_ask_stays_live() {
        let prior = ChainHint { last: Some(7), proven: Some(7), live: live(&[2, 7]), resume: None };
        let (walk, _) = run(Walk::start(Chain::Receive, Some(&prior), false), &[0, 2, 7]);
        assert!(walk.hint(Some(&prior)).live.iter().any(|l| l.index == 2));
    }
}
