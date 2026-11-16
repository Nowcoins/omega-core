//! A network's public endpoints, used the way a shared free service should be.
//!
//! * **Pacing.** Each endpoint has a rate the device keeps under (the
//!   endpoint's published one, or less where none is published), with a small
//!   burst. It is a theoretical-arrival-time limiter on the platform's clock
//!   (GCRA): a request that would exceed the rate is delayed, and a request that
//!   would be delayed too long goes to another endpoint instead.
//! * **Rotation.** The endpoints that may be used right now share the work in
//!   proportion to their weights (smooth weighted round robin), so nobody is
//!   asked more than its share and a refresh spreads over the operators.
//! * **Health.** Three failures in a row open an endpoint's circuit for a
//!   while (30 s, doubling to five minutes); a success closes it. An endpoint
//!   that asked the device to wait (`429`, `Retry-After`) is left alone until
//!   then. One that put a bot challenge in front of the answer is left alone for
//!   five minutes and **never worked around**: nothing here imitates a browser
//!   or retries past a refusal. One that does not serve a method (`eth_getLogs`
//!   on some) is not asked that method again for ten minutes.
//! * **Independence.** A figure that moves money (a nonce, a fee) is asked of
//!   endpoints of different operators and believed only where they agree
//!   ([`Pool::pick`] can be told which operators to avoid).
//!
//! The pool only decides *which* endpoint and *when*; the request itself is
//! [`crate::net::Net`]'s.

use std::sync::{Mutex, PoisonError};

/// What an endpoint is known to refuse (as observed in use, and re-checked by
/// `examples/live_smoke.rs`).
pub mod refuses {
    /// `eth_getLogs` (or answers "limit exceeded" even for one block).
    pub const LOGS: u8 = 1;
    /// Transaction receipts (an access token is wanted).
    pub const RECEIPTS: u8 = 2;
    /// TronGrid's `/v1` account-history API (a plain TRON node does not have it).
    pub const V1: u8 = 4;
    /// TRON constant calls (`triggerconstantcontract`): a node run without them answers
    /// `CONTRACT_VALIDATE_ERROR: this node does not support constant` with a 200.
    pub const CONSTANT: u8 = 8;
}

/// One public endpoint of a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointSpec {
    /// A short name for health reports: never sent anywhere.
    pub name: &'static str,
    /// The base URL, HTTPS, no trailing slash, no key.
    pub url: &'static str,
    /// The organisation that runs it: endpoints of one operator are one
    /// opinion, not two.
    pub operator: &'static str,
    /// Requests per second the device keeps under.
    pub per_second: u32,
    /// Requests that may go back to back before the pace applies.
    pub burst: u32,
    /// Its share of the work among the endpoints that may be used.
    pub weight: u32,
    /// What it refuses ([`refuses`]).
    pub refuses: u8,
    /// The widest `eth_getLogs` span it answers, in blocks (0: no limit known;
    /// results are capped instead).
    pub max_log_span: u32,
    /// How far back from the head it answers `eth_getLogs`, in blocks (0: all
    /// the way, it is an archive).
    pub log_depth: u32,
    /// Used for `eth_getLogs` only: an endpoint that answers logs well but whose
    /// other answers are not to be believed alike (BNB Chain's 48 Club quotes
    /// fees differently) or that is a private relay (MEV Blocker).
    pub logs_only: bool,
}

impl EndpointSpec {
    /// A spec with the usual burst of two.
    #[must_use]
    pub const fn new(
        name: &'static str,
        url: &'static str,
        operator: &'static str,
        per_second: u32,
        weight: u32,
    ) -> Self {
        Self {
            name,
            url,
            operator,
            per_second,
            burst: 2,
            weight,
            refuses: 0,
            max_log_span: 0,
            log_depth: 0,
            logs_only: false,
        }
    }

    /// Marks what this endpoint refuses.
    #[must_use]
    pub const fn refusing(mut self, refuses: u8) -> Self {
        self.refuses = refuses;
        self
    }

    /// Sets the widest `eth_getLogs` span.
    #[must_use]
    pub const fn log_span(mut self, blocks: u32) -> Self {
        self.max_log_span = blocks;
        self
    }

    /// Sets how far back from the head `eth_getLogs` is answered.
    #[must_use]
    pub const fn log_reach(mut self, blocks: u32) -> Self {
        self.log_depth = blocks;
        self
    }

    /// Marks the endpoint as used for `eth_getLogs` only.
    #[must_use]
    pub const fn logs_only(mut self) -> Self {
        self.logs_only = true;
        self
    }
}

/// What a request needs of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Need {
    /// [`refuses`] bits the endpoint must not have.
    pub avoid: u8,
    /// A method name the endpoint must not have been seen to refuse.
    pub method: &'static str,
    /// For `eth_getLogs`: the blocks the query spans (0: not constrained).
    pub span: u64,
    /// For `eth_getLogs`: how far back from the head it starts (0: not
    /// constrained).
    pub depth: u64,
    /// The endpoints named as `other_than` are a rule, not a preference: an endpoint of the
    /// same *operator* is never picked. Opinions that must be independent (a fee, a nonce,
    /// anything that moves money) are asked like this; with no other operator left the
    /// request finds nobody, and the caller says it could not be confirmed.
    pub distinct: bool,
}

impl Need {
    /// Anything goes.
    pub const ANY: Self = Self { avoid: 0, method: "", span: 0, depth: 0, distinct: false };

    /// Needs `eth_getLogs`.
    pub const LOGS: Self =
        Self { avoid: refuses::LOGS, method: "eth_getLogs", span: 0, depth: 0, distinct: false };

    /// Needs TronGrid's `/v1` account-history API.
    pub const TRON_V1: Self =
        Self { avoid: refuses::V1, method: "", span: 0, depth: 0, distinct: false };

    /// Needs a TRON node that runs constant calls (the energy of a token transfer, a token's balance).
    pub const TRON_CONSTANT: Self = Self {
        avoid: refuses::CONSTANT,
        method: "triggerconstantcontract",
        span: 0,
        depth: 0,
        distinct: false,
    };

    /// Needs transaction receipts.
    pub const RECEIPTS: Self =
        Self { avoid: refuses::RECEIPTS, method: "", span: 0, depth: 0, distinct: false };

    /// Needs this method answered.
    #[must_use]
    pub const fn method(method: &'static str) -> Self {
        Self { avoid: 0, method, span: 0, depth: 0, distinct: false }
    }

    /// Needs `eth_getLogs` over `span` blocks starting `depth` blocks back.
    #[must_use]
    pub const fn logs(span: u64, depth: u64) -> Self {
        Self { avoid: refuses::LOGS, method: "eth_getLogs", span, depth, distinct: false }
    }

    /// The same need, with operators already heard from never asked again.
    #[must_use]
    pub const fn independent(mut self) -> Self {
        self.distinct = true;
        self
    }
}

/// The longest a request is held back to keep an endpoint's pace before the
/// pool would rather say "busy": a person is waiting.
const MAX_PACE_WAIT_MS: u64 = 2_500;

/// Failures in a row that open a circuit.
const OPEN_AFTER: u32 = 3;
const OPEN_FIRST_MS: u64 = 30_000;
const OPEN_MAX_MS: u64 = 300_000;
/// How long a challenged endpoint is left alone.
const BLOCKED_MS: u64 = 300_000;
/// How long an endpoint that does not serve a method is not asked it.
const METHOD_OFF_MS: u64 = 600_000;
/// How long a `429` holds an endpoint back when it did not say, and the most it
/// is held however long it asks.
const HELD_DEFAULT_MS: u64 = 10_000;
const HELD_MAX_MS: u64 = 300_000;

#[derive(Debug)]
struct Slot {
    spec: EndpointSpec,
    /// GCRA's theoretical arrival time of the next request, in epoch ms.
    tat: u64,
    fails: u32,
    open_until: u64,
    held_until: u64,
    blocked_until: u64,
    off: Vec<(&'static str, u64)>,
    /// Smooth weighted round robin's running credit.
    credit: i64,
    ok: u64,
    errors: u64,
    /// A moving average of how long an answer takes, in ms (0 before the first).
    latency_ms: u64,
    /// What the endpoint has been seen to answer for `eth_getLogs`, narrower
    /// than what the list says (0: nothing learned).
    span_cap: u64,
    depth_cap: u64,
}

/// The smaller of two limits, 0 standing for none.
fn tighter(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, x) | (x, 0) => x,
        (a, b) => a.min(b),
    }
}

impl Slot {
    fn new(spec: EndpointSpec) -> Self {
        Self {
            spec,
            tat: 0,
            fails: 0,
            open_until: 0,
            held_until: 0,
            blocked_until: 0,
            off: Vec::new(),
            credit: 0,
            ok: 0,
            errors: 0,
            latency_ms: 0,
            span_cap: 0,
            depth_cap: 0,
        }
    }

    /// The widest log query it answers (0: no limit).
    fn span_limit(&self) -> u64 {
        tighter(u64::from(self.spec.max_log_span), self.span_cap)
    }

    /// How far back it answers logs (0: all the way).
    fn depth_limit(&self) -> u64 {
        tighter(u64::from(self.spec.log_depth), self.depth_cap)
    }

    fn interval_ms(&self) -> u64 {
        (1000 / u64::from(self.spec.per_second.max(1))).max(1)
    }

    /// When a request could go without breaking the pace.
    fn allowed_at(&self) -> u64 {
        let tolerance = self.interval_ms() * u64::from(self.spec.burst.saturating_sub(1));
        self.tat.saturating_sub(tolerance)
    }

    /// The moment the endpoint is out of every penalty box, or 0.
    fn usable_from(&self, method: &str) -> u64 {
        let off = self.off.iter().find(|(name, _)| *name == method).map_or(0, |(_, until)| *until);
        self.open_until.max(self.held_until).max(self.blocked_until).max(off)
    }

    fn fits(&self, need: Need) -> bool {
        if self.spec.refuses & need.avoid != 0 {
            return false;
        }
        if self.spec.logs_only && need.method != "eth_getLogs" {
            return false;
        }
        let (span, depth) = (self.span_limit(), self.depth_limit());
        (need.span == 0 || span == 0 || need.span <= span)
            && (need.depth == 0 || depth == 0 || need.depth <= depth)
    }
}

/// Which endpoint to ask, and after how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pick {
    /// The endpoint's index in the pool.
    pub index: usize,
    /// How long to wait before sending, to keep the endpoint's pace.
    pub wait_ms: u64,
}

/// Why no endpoint can be asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoPick {
    /// Every endpoint that could be asked is resting; the soonest is back in
    /// this many ms.
    Resting(u64),
    /// Every endpoint was tried (or none fits the need).
    Exhausted,
}

/// How an attempt on an endpoint went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// An answer, in this many ms.
    Ok(u64),
    /// No answer, a server error, an answer that is not what the endpoint
    /// documents.
    Failed,
    /// The endpoint asked the device to wait this many seconds (or did not say).
    RateLimited(Option<u64>),
    /// A bot challenge stands in front of the answer.
    Challenged,
    /// The endpoint does not serve this method.
    MethodOff(&'static str),
}

/// A network's endpoints and what is known of their health.
#[derive(Debug)]
pub struct Pool {
    slots: Mutex<Vec<Slot>>,
}

impl Pool {
    /// A pool over `specs`.
    #[must_use]
    pub fn new(specs: &[EndpointSpec]) -> Self {
        Self { slots: Mutex::new(specs.iter().copied().map(Slot::new).collect()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Slot>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many endpoints there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The spec of endpoint `index`.
    #[must_use]
    pub fn spec(&self, index: usize) -> Option<EndpointSpec> {
        self.lock().get(index).map(|slot| slot.spec)
    }

    /// Chooses an endpoint at `now` and books a request on its pace.
    ///
    /// `avoid` are endpoints already tried by this request; `other_than` are
    /// endpoints whose *operators* are preferably not used again (a second
    /// opinion). The second is a preference, the first a rule.
    pub fn pick(
        &self,
        now: u64,
        need: Need,
        avoid: &[usize],
        other_than: &[usize],
    ) -> Result<Pick, NoPick> {
        let mut slots = self.lock();
        let used_operators: Vec<&str> =
            other_than.iter().filter_map(|&i| slots.get(i)).map(|s| s.spec.operator).collect();

        // Not tried yet, serving what is needed.
        let eligible: Vec<usize> = (0..slots.len())
            .filter(|i| {
                !avoid.contains(i)
                    && slots[*i].fits(need)
                    // An independent opinion never comes from an operator already heard.
                    && !(need.distinct && used_operators.contains(&slots[*i].spec.operator))
            })
            .collect();
        if eligible.is_empty() {
            return Err(NoPick::Exhausted);
        }
        // Out of every penalty box now.
        let usable: Vec<usize> = eligible
            .iter()
            .copied()
            .filter(|&i| slots[i].usable_from(need.method) <= now)
            .collect();
        if usable.is_empty() {
            let soonest = eligible
                .iter()
                .map(|&i| slots[i].usable_from(need.method).saturating_sub(now))
                .min()
                .unwrap_or(0);
            return Err(NoPick::Resting(soonest.max(1)));
        }
        // A second opinion comes from another operator where there is one.
        let independent: Vec<usize> = usable
            .iter()
            .copied()
            .filter(|&i| !used_operators.contains(&slots[i].spec.operator))
            .collect();
        let pool = if independent.is_empty() { usable } else { independent };

        // Those that can go now share the work by weight; if none can, the one
        // that can go soonest, if that is soon enough.
        let ready: Vec<usize> =
            pool.iter().copied().filter(|&i| slots[i].allowed_at() <= now).collect();
        let chosen = if ready.is_empty() {
            let (index, wait) = pool
                .iter()
                .map(|&i| (i, slots[i].allowed_at().saturating_sub(now)))
                .min_by_key(|&(_, wait)| wait)
                .ok_or(NoPick::Exhausted)?;
            if wait > MAX_PACE_WAIT_MS {
                return Err(NoPick::Resting(wait));
            }
            index
        } else {
            let total: i64 = ready.iter().map(|&i| i64::from(slots[i].spec.weight.max(1))).sum();
            for &i in &ready {
                slots[i].credit += i64::from(slots[i].spec.weight.max(1));
            }
            let best = ready
                .iter()
                .copied()
                .max_by_key(|&i| (slots[i].credit, std::cmp::Reverse(i)))
                .ok_or(NoPick::Exhausted)?;
            slots[best].credit -= total;
            best
        };

        let slot = &mut slots[chosen];
        let wait_ms = slot.allowed_at().saturating_sub(now);
        slot.tat = slot.tat.max(now) + slot.interval_ms();
        Ok(Pick { index: chosen, wait_ms })
    }

    /// The widest `eth_getLogs` any endpoint answers for a query starting `depth`
    /// blocks back, `u64::MAX` for no limit; `None` when no endpoint answers logs
    /// that far back with a span of at least `min_span`. Endpoints resting at
    /// `now` are left out (`None` for `now` counts them: whether it is possible
    /// at all). `avoid` are endpoints not to count.
    pub fn log_reach(
        &self,
        now: Option<u64>,
        depth: u64,
        avoid: &[usize],
        min_span: u64,
    ) -> Option<u64> {
        let slots = self.lock();
        slots
            .iter()
            .enumerate()
            .filter(|(i, s)| !avoid.contains(i) && s.fits(Need::logs(0, depth)))
            .filter(|(_, s)| now.is_none_or(|now| s.usable_from("eth_getLogs") <= now))
            .map(|(_, s)| match s.span_limit() {
                0 => u64::MAX,
                span => span,
            })
            .filter(|span| *span >= min_span)
            .max()
    }

    /// Whether a bot challenge is what stands between the device and the
    /// endpoints that serve `need`: one of them is blocked now and none can be
    /// asked. The device does not go round a challenge; it says so.
    #[must_use]
    pub fn blocked(&self, now: u64, need: Need) -> bool {
        let slots = self.lock();
        let serving: Vec<&Slot> = slots.iter().filter(|s| s.fits(need)).collect();
        serving.iter().any(|s| s.blocked_until > now)
            && serving.iter().all(|s| s.usable_from(need.method) > now)
    }

    /// How far back from the head any endpoint answers logs with a span of at
    /// least `min_span` (`u64::MAX`: all the way), or `None` if none does.
    pub fn log_deepest(&self, now: Option<u64>, min_span: u64) -> Option<u64> {
        let slots = self.lock();
        slots
            .iter()
            .filter(|s| s.fits(Need::logs(0, 0)))
            .filter(|s| now.is_none_or(|now| s.usable_from("eth_getLogs") <= now))
            .filter(|s| match s.span_limit() {
                0 => true,
                span => span >= min_span,
            })
            .map(|s| match s.depth_limit() {
                0 => u64::MAX,
                depth => depth,
            })
            .max()
    }

    /// Notes that an endpoint was seen to refuse log queries wider than `span`.
    pub fn learn_span(&self, index: usize, span: u64) {
        if let Some(slot) = self.lock().get_mut(index) {
            slot.span_cap = tighter(slot.span_cap, span.max(1));
        }
    }

    /// Notes that an endpoint was seen to refuse log queries starting more than
    /// `depth` blocks back.
    pub fn learn_depth(&self, index: usize, depth: u64) {
        if let Some(slot) = self.lock().get_mut(index) {
            slot.depth_cap = tighter(slot.depth_cap, depth.max(1));
        }
    }

    /// Records how an attempt went.
    pub fn report(&self, now: u64, index: usize, outcome: Outcome) {
        let mut slots = self.lock();
        let Some(slot) = slots.get_mut(index) else { return };
        match outcome {
            Outcome::Ok(latency) => {
                slot.ok += 1;
                slot.fails = 0;
                slot.open_until = 0;
                slot.latency_ms = if slot.latency_ms == 0 {
                    latency
                } else {
                    (slot.latency_ms * 3 + latency) / 4
                };
            }
            Outcome::Failed => {
                slot.errors += 1;
                slot.fails += 1;
                if slot.fails >= OPEN_AFTER {
                    let doublings = (slot.fails - OPEN_AFTER).min(4);
                    let rest = (OPEN_FIRST_MS << doublings).min(OPEN_MAX_MS);
                    slot.open_until = now + rest;
                }
            }
            Outcome::RateLimited(seconds) => {
                slot.errors += 1;
                let hold = seconds
                    .map_or(HELD_DEFAULT_MS, |s| s.saturating_mul(1000))
                    .clamp(1_000, HELD_MAX_MS);
                slot.held_until = slot.held_until.max(now + hold);
            }
            Outcome::Challenged => {
                slot.errors += 1;
                slot.blocked_until = now + BLOCKED_MS;
            }
            Outcome::MethodOff(method) => {
                let until = now + METHOD_OFF_MS;
                match slot.off.iter_mut().find(|(name, _)| *name == method) {
                    Some(entry) => entry.1 = until,
                    None => slot.off.push((method, until)),
                }
            }
        }
    }

    /// What is known of each endpoint, for a diagnostics screen: name, answers,
    /// failures, and whether it is resting. Never a URL.
    #[must_use]
    pub fn health(&self, now: u64) -> Vec<serde_json::Value> {
        self.lock()
            .iter()
            .map(|slot| {
                serde_json::json!({
                    "endpoint": slot.spec.name,
                    "operator": slot.spec.operator,
                    "ok": slot.ok,
                    "errors": slot.errors,
                    "latency_ms": slot.latency_ms,
                    "resting_ms": slot.usable_from("").saturating_sub(now),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: EndpointSpec = EndpointSpec::new("a", "https://a.example", "alpha", 10, 100);
    const B: EndpointSpec = EndpointSpec::new("b", "https://b.example", "beta", 10, 50);
    const C: EndpointSpec = EndpointSpec::new("c", "https://c.example", "alpha", 1, 10);

    fn pick(pool: &Pool, now: u64) -> Pick {
        pool.pick(now, Need::ANY, &[], &[]).unwrap()
    }

    #[test]
    fn work_is_shared_in_proportion_to_weight() {
        let pool = Pool::new(&[A, B]);
        let mut counts = [0_u32; 2];
        for step in 0..30_u64 {
            // Far apart: pacing never matters here.
            counts[pick(&pool, 10_000 * step).index] += 1;
        }
        assert_eq!(counts, [20, 10], "weights 100:50");
    }

    #[test]
    fn a_request_is_delayed_to_keep_the_pace_and_then_goes_elsewhere() {
        let slow = EndpointSpec::new("slow", "https://s.example", "s", 1, 1);
        let pool = Pool::new(&[slow]);
        // Burst of two, then one a second.
        assert_eq!(pick(&pool, 1_000).wait_ms, 0);
        assert_eq!(pick(&pool, 1_000).wait_ms, 0);
        assert_eq!(pick(&pool, 1_000).wait_ms, 1_000);
        assert_eq!(pick(&pool, 1_000).wait_ms, 2_000);
        // Too far behind: say so instead of making a person wait.
        assert_eq!(pool.pick(1_000, Need::ANY, &[], &[]), Err(NoPick::Resting(3_000)));
        // Another endpoint that is free takes the work.
        let pool = Pool::new(&[slow, B]);
        for _ in 0..4 {
            pool.pick(1_000, Need::ANY, &[1], &[]).unwrap();
        }
        assert_eq!(pool.pick(1_000, Need::ANY, &[], &[]), Ok(Pick { index: 1, wait_ms: 0 }));
    }

    #[test]
    fn three_failures_in_a_row_rest_an_endpoint_and_a_success_forgives_it() {
        let pool = Pool::new(&[A, B]);
        for _ in 0..2 {
            pool.report(0, 0, Outcome::Failed);
        }
        pool.report(0, 0, Outcome::Ok(30));
        pool.report(0, 0, Outcome::Failed);
        assert_eq!(pool.pick(1, Need::ANY, &[1], &[]).unwrap().index, 0, "not three in a row");
        for _ in 0..2 {
            pool.report(100, 0, Outcome::Failed);
        }
        // Open for 30 s from the third failure.
        assert_eq!(pool.pick(1_000, Need::ANY, &[1], &[]), Err(NoPick::Resting(29_100)));
        assert_eq!(pool.pick(1_000, Need::ANY, &[], &[]).unwrap().index, 1);
        assert_eq!(pool.pick(31_000, Need::ANY, &[1], &[]).unwrap().index, 0, "half-open again");
    }

    #[test]
    fn a_rate_limit_is_waited_out_and_a_challenge_is_left_alone_for_five_minutes() {
        let pool = Pool::new(&[A]);
        pool.report(0, 0, Outcome::RateLimited(Some(7)));
        assert_eq!(pool.pick(1_000, Need::ANY, &[], &[]), Err(NoPick::Resting(6_000)));
        assert!(pool.pick(7_000, Need::ANY, &[], &[]).is_ok());
        pool.report(8_000, 0, Outcome::Challenged);
        assert_eq!(pool.pick(9_000, Need::ANY, &[], &[]), Err(NoPick::Resting(299_000)));
        assert!(pool.pick(308_000, Need::ANY, &[], &[]).is_ok());
    }

    #[test]
    fn an_endpoint_that_refuses_logs_is_never_asked_for_them() {
        let dataseed =
            EndpointSpec::new("d", "https://d.example", "bnb", 5, 10).refusing(refuses::LOGS);
        let pool = Pool::new(&[dataseed, B]);
        for step in 0..5_u64 {
            assert_eq!(pool.pick(step * 10_000, Need::LOGS, &[], &[]).unwrap().index, 1);
        }
        assert_eq!(pool.pick(0, Need::LOGS, &[1], &[]), Err(NoPick::Exhausted));
        // Asked a method it then refuses, it is off that method only.
        let pool = Pool::new(&[A, B]);
        pool.report(0, 0, Outcome::MethodOff("eth_getLogs"));
        assert_eq!(pool.pick(1, Need::LOGS, &[], &[]).unwrap().index, 1);
        assert_eq!(pool.pick(10_000, Need::method("eth_call"), &[1], &[]).unwrap().index, 0);
    }

    #[test]
    fn a_second_opinion_comes_from_another_operator() {
        let pool = Pool::new(&[A, C, B]);
        let first = pick(&pool, 0);
        let second = pool.pick(0, Need::ANY, &[first.index], &[first.index]).unwrap();
        let operators =
            [pool.spec(first.index).unwrap().operator, pool.spec(second.index).unwrap().operator];
        assert_ne!(operators[0], operators[1]);
        // With only one operator left, the same operator is better than none.
        let pool = Pool::new(&[A, C]);
        let third = pool.pick(0, Need::ANY, &[0], &[0]).unwrap();
        assert_eq!(third.index, 1);
    }
}
