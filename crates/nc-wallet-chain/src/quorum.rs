//! No single operator is trusted for a figure that moves money.
//!
//! A fee or a nonce is asked of two endpoints of **different operators** (an operator is an
//! organisation: `PublicNode`'s two hosts are one), never of two of the same, and it is
//! believed where they agree. Where they do not, a third operator is asked and the figure two
//! of the three agree on is taken, so one liar (or one that is behind) is outvoted. With
//! no majority, or only one operator answering, the figure is **unconfirmed**: it
//! carries `sources == 1`, and the caller either uses it within the wallet's own bounds
//! for a lone operator (`nc_wallet_core::limits::Bound::alone`) or refuses with "could not
//! be confirmed, try again". The wallet's own ceilings (`Bound::refuse`) apply to every
//! figure however many agree. A nonce is never taken from the lower of two disagreeing
//! sources: a nonce too low replaces the person's own pending transaction.

use nc_wallet_core::limits::Bound;
use serde_json::Value;

use crate::error::{ChainError, ChainResult};
use crate::net::Net;
use crate::pool::Need;

/// How two readings of a figure are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A fee: within a quarter of each other agrees, and the higher is used (a fee a
    /// little high is paid; one a little low does not get in).
    Fee,
    /// A tip to the block producer: as a fee, or within a gwei of each other: where tips are a
    /// fraction of a gwei, two nodes' figures differ by a large share of nothing.
    Tip,
    /// A rate two services estimate differently (Bitcoin's): within a factor of three, and
    /// two satoshis a byte, agrees, and the higher is used.
    Rate,
    /// A nonce or a sequence number: equal agrees.
    Exact,
}

/// How close two fees must be to agree: a quarter apart at most.
const FEE_TOLERANCE_PERCENT: u128 = 25;
/// Tips agree besides if they are this close, in wei: a gwei.
const TIP_SLACK_WEI: u128 = 1_000_000_000;
/// Two rates agree within this factor, plus [`RATE_SLACK_KVB`] (2 sat/vB).
const RATE_FACTOR: u128 = 3;
const RATE_SLACK_KVB: u128 = 2_000;

/// A figure and how many *operators* vouch for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Figure {
    /// The figure.
    pub value: u128,
    /// How many independent operators' answers it rests on (one is a figure nothing
    /// checked).
    pub sources: usize,
}

impl Figure {
    /// The figure, if it is within `bound` for the operators that vouch for it.
    ///
    /// * Above `bound.refuse` it is refused, whoever agrees (never clamped).
    /// * Above `bound.alone` with one operator, it is not used: it could not be confirmed.
    ///
    /// `what` names it for the person: "network fee", "tip".
    pub fn within(self, bound: Bound, what: &str) -> ChainResult<u128> {
        if !bound.allows(self.value) {
            return Err(ChainError::OverCeiling(format!(
                "the {what} the network quotes is above the most this wallet will pay"
            )));
        }
        if !bound.trusts(self.value, self.sources) {
            return Err(unconfirmed(what));
        }
        Ok(self.value)
    }
}

/// "Could not be confirmed": one operator's figure is too high to rest on alone, or the
/// operators do not agree.
#[must_use]
pub fn unconfirmed(what: &str) -> ChainError {
    ChainError::Unconfirmed(format!(
        "the {what} could not be confirmed by a second source; try again in a moment"
    ))
}

fn agree(kind: Kind, a: u128, b: u128) -> bool {
    let (low, high) = (a.min(b), a.max(b));
    match kind {
        Kind::Exact => a == b,
        Kind::Fee => high.saturating_sub(low) <= low.saturating_mul(FEE_TOLERANCE_PERCENT) / 100,
        Kind::Tip => {
            high.saturating_sub(low) <= low.saturating_mul(FEE_TOLERANCE_PERCENT) / 100
                || high.saturating_sub(low) <= TIP_SLACK_WEI
        }
        Kind::Rate => high <= low.saturating_mul(RATE_FACTOR).saturating_add(RATE_SLACK_KVB),
    }
}

/// What the readings of up to three operators amount to: the figure and how many of them
/// vouch for it, or `None` where they cannot be reconciled (two that disagree, or three
/// with no two in agreement).
#[must_use]
pub fn decide(kind: Kind, values: &[u128]) -> Option<(u128, usize)> {
    match values {
        [] => None,
        [one] => Some((*one, 1)),
        _ => {
            // The largest set of readings that agree with each other (all pairs), and in it
            // the higher figure (an exact figure is the same throughout).
            let mut best: Option<(u128, usize)> = None;
            for (i, &anchor) in values.iter().enumerate() {
                let group: Vec<u128> = values
                    .iter()
                    .enumerate()
                    .filter(|&(j, &v)| i == j || agree(kind, anchor, v))
                    .map(|(_, &v)| v)
                    .collect();
                // Every pair in the group must agree, not only each with the anchor.
                let consistent = group.iter().all(|&a| group.iter().all(|&b| agree(kind, a, b)));
                if consistent
                    && group.len() >= 2
                    && best.is_none_or(|(_, n)| group.len() > n)
                    && let Some(&high) = group.iter().max()
                {
                    best = Some((high, group.len()));
                }
            }
            best
        }
    }
}

/// What to ask over REST.
#[derive(Debug, Clone, Copy)]
pub enum Ask<'a> {
    /// `GET` this path.
    Get(&'a str),
    /// `POST` this body to this path.
    Post(&'a str, &'static str, &'a [u8]),
}

impl Net {
    /// Reads a figure by JSON-RPC from two endpoints of different operators, and from a third
    /// where the two disagree. `parse` reads the result. Fewer than two operators answering
    /// gives `sources == 1`; no agreement is [`ChainError::Unconfirmed`].
    pub async fn rpc_figure(
        &self,
        method: &'static str,
        params: &Value,
        parse: fn(&Value) -> Option<u128>,
        kind: Kind,
    ) -> ChainResult<Figure> {
        let need = Need::ANY.independent();
        let answers = self.rpc_many(need, 2, method, params).await?;
        let mut values: Vec<u128> = Vec::new();
        let mut from: Vec<usize> = Vec::new();
        for (answer, index) in answers {
            if let Ok(result) = answer
                && let Some(value) = parse(&result)
            {
                values.push(value);
                from.push(index);
            }
        }
        if values.is_empty() {
            return Err(ChainError::Unavailable);
        }
        if values.len() >= 2
            && decide(kind, &values).is_none()
            && let Ok((Ok(result), index)) = self.rpc_from(need, &from, method, params).await
            && let Some(value) = parse(&result)
        {
            values.push(value);
            from.push(index);
        }
        let (value, sources) = decide(kind, &values).ok_or_else(|| unconfirmed("figure"))?;
        Ok(Figure { value, sources })
    }

    /// Reads several figures from one REST answer, from two operators and a third where
    /// they disagree on any. `base` is what the endpoints must serve (`Need::ANY` for most), `parse`
    /// turns an answer into one reading per entry of `kinds`.
    pub async fn rest_figures(
        &self,
        base: Need,
        ask: Ask<'_>,
        parse: fn(&[u8]) -> Option<Vec<u128>>,
        kinds: &[Kind],
    ) -> ChainResult<Vec<Figure>> {
        let need = base.independent();
        let answers = match ask {
            Ask::Get(path) => self.get_many(need, 2, path).await?,
            Ask::Post(path, content_type, body) => {
                self.post_many(need, 2, path, content_type, body).await?
            }
        };
        let read = |status: u16, body: &[u8]| -> Option<Vec<u128>> {
            ((200..300).contains(&status))
                .then(|| parse(body))
                .flatten()
                .filter(|readings| readings.len() == kinds.len())
        };
        let mut readings: Vec<Vec<u128>> = Vec::new();
        let mut from: Vec<usize> = Vec::new();
        for ((status, body), index) in answers {
            if let Some(found) = read(status, &body) {
                readings.push(found);
                from.push(index);
            }
        }
        if readings.is_empty() {
            return Err(ChainError::Unavailable);
        }
        if readings.len() >= 2 && !settled(kinds, &readings) {
            let third = match ask {
                Ask::Get(path) => self.get_from(need, &from, path).await,
                Ask::Post(path, content_type, body) => {
                    self.post_from(need, &from, path, content_type, body).await
                }
            };
            if let Ok(((status, body), _)) = third
                && let Some(found) = read(status, &body)
            {
                readings.push(found);
            }
        }
        figures_of(kinds, &readings)
    }

    /// Reads several figures from one JSON-RPC answer, from two operators and a third where they
    /// disagree on any, as [`Self::rest_figures`] does from a REST answer. `parse` turns a result into one
    /// reading per entry of `kinds`.
    pub async fn rpc_figures(
        &self,
        method: &'static str,
        params: &Value,
        parse: fn(&Value) -> Option<Vec<u128>>,
        kinds: &[Kind],
    ) -> ChainResult<Vec<Figure>> {
        let need = Need::ANY.independent();
        let read = |answer: Result<Value, crate::net::NodeError>| {
            answer.ok().and_then(|result| parse(&result)).filter(|found| found.len() == kinds.len())
        };
        let mut readings: Vec<Vec<u128>> = Vec::new();
        let mut from: Vec<usize> = Vec::new();
        for (answer, index) in self.rpc_many(need, 2, method, params).await? {
            if let Some(found) = read(answer) {
                readings.push(found);
                from.push(index);
            }
        }
        if readings.is_empty() {
            return Err(ChainError::Unavailable);
        }
        if readings.len() >= 2
            && !settled(kinds, &readings)
            && let Ok((answer, _)) = self.rpc_from(need, &from, method, params).await
            && let Some(found) = read(answer)
        {
            readings.push(found);
        }
        figures_of(kinds, &readings)
    }
}

/// One reading per figure from each operator that answered: the figure `decide` makes of the column of
/// its readings, or "could not be confirmed".
fn figures_of(kinds: &[Kind], readings: &[Vec<u128>]) -> ChainResult<Vec<Figure>> {
    kinds
        .iter()
        .enumerate()
        .map(|(at, kind)| {
            let (value, sources) =
                decide(*kind, &column(readings, at)).ok_or_else(|| unconfirmed("figure"))?;
            Ok(Figure { value, sources })
        })
        .collect()
}

/// Whether the readings of every figure can be reconciled (so that no further operator is asked).
fn settled(kinds: &[Kind], readings: &[Vec<u128>]) -> bool {
    kinds.iter().enumerate().all(|(at, kind)| decide(*kind, &column(readings, at)).is_some())
}

/// The readings of figure `at`.
fn column(readings: &[Vec<u128>], at: usize) -> Vec<u128> {
    readings.iter().filter_map(|r| r.get(at).copied()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_fees_within_a_quarter_agree_on_the_higher() {
        assert_eq!(decide(Kind::Fee, &[100, 120]), Some((120, 2)));
        assert_eq!(decide(Kind::Fee, &[125, 100]), Some((125, 2)));
        assert_eq!(decide(Kind::Fee, &[100, 126]), None);
        assert_eq!(decide(Kind::Fee, &[100]), Some((100, 1)));
        assert_eq!(decide(Kind::Fee, &[0, 0]), Some((0, 2)));
        assert_eq!(decide(Kind::Fee, &[]), None);
    }

    #[test]
    fn exact_figures_agree_only_when_equal_and_never_fall_to_the_lower() {
        assert_eq!(decide(Kind::Exact, &[5, 5]), Some((5, 2)));
        assert_eq!(decide(Kind::Exact, &[7]), Some((7, 1)));
        // Two that disagree are not reconciled by taking the lower (a nonce too low replaces the
        // person's own pending transaction) or the higher (a gap): the caller asks again.
        assert_eq!(decide(Kind::Exact, &[5, 6]), None);
        assert_eq!(decide(Kind::Exact, &[6, 5]), None);
        // A third settles it, whichever way.
        assert_eq!(decide(Kind::Exact, &[5, 6, 6]), Some((6, 2)));
        assert_eq!(decide(Kind::Exact, &[5, 6, 5]), Some((5, 2)));
        assert_eq!(decide(Kind::Exact, &[5, 6, 9]), None);
    }

    #[test]
    fn tips_below_a_gwei_apart_agree_whatever_their_share() {
        // BNB Chain's nodes say 0.05 and 0.08 gwei: 60% apart, nothing in money.
        assert_eq!(decide(Kind::Tip, &[50_000_000, 80_000_000]), Some((80_000_000, 2)));
        // The same pair as a fee are not close enough.
        assert_eq!(decide(Kind::Fee, &[50_000_000, 80_000_000]), None);
        // A gwei and a half apart, and far apart in share, do not agree.
        assert_eq!(decide(Kind::Tip, &[1_000_000_000, 2_600_000_000]), None);
        assert_eq!(decide(Kind::Tip, &[30_000_000_000, 36_000_000_000]), Some((36_000_000_000, 2)));
    }

    #[test]
    fn a_third_outvotes_one_liar_either_way() {
        // A liar high, a liar low, and the two honest ones in between.
        assert_eq!(decide(Kind::Fee, &[100, 100_000, 110]), Some((110, 2)));
        assert_eq!(decide(Kind::Fee, &[100, 1, 110]), Some((110, 2)));
        // Nobody agrees with anybody.
        assert_eq!(decide(Kind::Fee, &[1, 100, 10_000]), None);
        // Three that are all close agree as a set.
        assert_eq!(decide(Kind::Fee, &[100, 110, 120]), Some((120, 3)));
        // A chain of near readings that is not all mutually close is not a group of three.
        assert_eq!(decide(Kind::Fee, &[100, 124, 154]), Some((124, 2)));
    }

    #[test]
    fn rates_two_services_estimate_differently_agree_within_a_factor_of_three() {
        // 10 and 30 sat/vB (in thousandths): fine. 10 and 50: no.
        assert_eq!(decide(Kind::Rate, &[10_000, 30_000]), Some((30_000, 2)));
        assert_eq!(decide(Kind::Rate, &[10_000, 50_000]), None);
        // A liar's {"1": 50000} sat/vB against an honest 5 sat/vB.
        assert_eq!(decide(Kind::Rate, &[5_000, 50_000_000]), None);
        assert_eq!(decide(Kind::Rate, &[1_000, 3_000]), Some((3_000, 2)));
    }

    #[test]
    fn a_figure_is_used_alone_only_up_to_its_lower_bound_and_never_above_the_upper() {
        let bound = Bound { alone: 10, refuse: 100 };
        assert_eq!(Figure { value: 10, sources: 1 }.within(bound, "network fee").unwrap(), 10);
        let alone = Figure { value: 11, sources: 1 }.within(bound, "network fee").unwrap_err();
        assert!(matches!(alone, ChainError::Unconfirmed(_)), "{alone:?}");
        assert!(alone.retryable());
        assert_eq!(Figure { value: 100, sources: 2 }.within(bound, "network fee").unwrap(), 100);
        let over = Figure { value: 101, sources: 3 }.within(bound, "network fee").unwrap_err();
        assert!(matches!(over, ChainError::OverCeiling(_)), "{over:?}");
        assert!(!over.retryable());
        // Both are told in words, with the code the apps show the words of.
        assert_eq!(over.code(), "estimate_failed");
        assert!(!over.message().contains("gas"));
    }
}
