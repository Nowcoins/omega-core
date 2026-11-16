//! A coin whose past nobody keyless can list: history from the day the wallet
//! was first seen.
//!
//! A plain node cannot list the transactions of an address, and the indexers
//! that can are not used. For the native coin of Ethereum, BNB Chain, Polygon
//! and Base (ETH, BNB, POL) and for Bittensor's TAO the history is therefore
//! what the wallet itself saw:
//!
//! * **What it sent.** The app tells it (`history_note`), the note is shown as
//!   pending, and settled when the chain says so: an EVM receipt, or, for
//!   Bittensor, whose nodes keep no index of extrinsics by hash, the account's
//!   nonce on chain. An extrinsic the account's nonce has passed came in; one
//!   whose era is over with the nonce not past it never will. Nothing is
//!   settled by a timer: a node's pool can drop an extrinsic it accepted.
//! * **What arrived.** The app hands over the balance with each call. A balance
//!   higher than the one the sends explain is an arrival: an item with no hash,
//!   no sender and `observed: true`, dated when it was seen.
//!
//! `coverage` says `from_first_sight` with the date, and the answer carries the
//! address's explorer link for everything older.

use super::store::{Direction, Item, Kind, State, Status};
use super::{Budget, Coverage, Cx};

/// How long after a Bittensor send the extrinsic can still come in: it lives for 64 blocks of twelve
/// seconds from the block it was built on (about thirteen minutes), and the note is made after it was
/// built. Past this, with the account's nonce not past the one it used, it never will.
const DROPPED_AFTER_SECONDS: u64 = 900;

/// A rise of the balance is an arrival only when a reading this long after the first still shows it.
const CONFIRM_RISE_AFTER_SECONDS: u64 = 20;

/// For this long after this wallet's own send, no rise is taken as an arrival: a balance read just after a
/// send can be older than the send (a node that lags, an app that kept the number from before), and would
/// show the money that left as money that came.
const QUIET_AFTER_OWN_SEND_SECONDS: u64 = 600;

/// Bittensor's update: settles the sends the app noted, by the account's nonce on chain, asked of two
/// operators (and only when a send is waiting).
pub(super) async fn update(cx: &Cx<'_>, b: &mut Budget, st: &mut State) {
    let waiting = st.notes.iter().any(|n| n.status == Status::Pending && n.nonce.is_some());
    let mut included = None;
    if waiting && b.take_up_to(2, cx.net.now()) == 2 {
        included = crate::bittensor::included(cx.net, &cx.req.address)
            .await
            .ok()
            .filter(|nonce| nonce.sources >= 2)
            .map(|nonce| nonce.value);
    }
    settle(st, cx.now, included);
}

/// Settles the notes of Bittensor sends. `included` is how many extrinsics two operators agree the account
/// has had included, if they were asked and did.
///
/// * A send whose nonce the account has passed came in: a confirmed item.
/// * One whose era is over with the nonce not past it never came in (the node's pool dropped it, or it
///   was refused): a failed item that cost nothing, and the coin it had spoken for is back in the balance.
/// * Any other waits, however long that is, for there is nothing else that knows. A note without a nonce,
///   or that nothing could settle, is forgotten after three days.
pub(super) fn settle(st: &mut State, now: u64, included: Option<u128>) {
    let mut done: Vec<Item> = Vec::new();
    let mut kept: Vec<Item> = Vec::new();
    for note in std::mem::take(&mut st.notes) {
        let age = now.saturating_sub(note.time);
        let verdict = match (note.nonce, included) {
            (Some(nonce), Some(included)) if included > u128::from(nonce) => {
                Some(Status::Confirmed)
            }
            (Some(_), Some(_)) if age >= DROPPED_AFTER_SECONDS => Some(Status::Failed),
            _ => None,
        };
        let Some(status) = verdict else {
            if age <= super::evm::NOTE_LIFETIME_SECONDS {
                kept.push(note);
            }
            continue;
        };
        let mut item = note.clone();
        item.id = format!("{}:0", note.hash);
        item.status = status;
        item.verified = true;
        if status == Status::Failed {
            // It moved nothing and cost nothing: the way a failed send is told elsewhere, without a fee.
            item.kind = Kind::Call;
            item.amount = 0;
            item.fee = None;
            st.balance = st
                .balance
                .map(|held| held.saturating_add(note.amount).saturating_add(note.fee.unwrap_or(0)));
        }
        done.push(item);
    }
    st.notes = kept;
    st.merge(done);
}

/// What the coin's history covers: from the day it was first seen.
pub(super) fn coverage(st: &State) -> Coverage {
    Coverage::single("from_first_sight", true, Some(st.first_seen))
}

/// The coin that sends spoke for and has not left yet.
fn unmined(cx: &Cx<'_>, st: &State) -> u128 {
    st.notes
        .iter()
        .filter(|n| n.status == Status::Pending && cx.network.is_native(&n.asset))
        .map(|n| n.amount.saturating_add(n.fee.unwrap_or(0)))
        .fold(0, u128::saturating_add)
}

/// Whether this wallet sent something lately (its fee is in the coin, whatever it sent).
fn sent_lately(cx: &Cx<'_>, st: &State) -> bool {
    st.notes.iter().chain(st.items.iter()).any(|i| {
        i.direction == Direction::Out
            && cx.now.saturating_sub(i.time) < QUIET_AFTER_OWN_SEND_SECONDS
    })
}

/// Looks at the balance: a rise that the sends do not explain, seen again a little later and not just
/// after a send of this wallet's own, is an arrival.
///
/// `st.balance` is the balance once every pending send has been mined, as of the
/// last look. The chain's balance now is that plus what the still-unmined sends
/// will take, plus anything that arrived; or, if they have been mined since, that
/// plus anything that arrived. A fall the sends do not explain is never made into
/// an arrival.
pub(super) fn observe(cx: &Cx<'_>, st: &mut State, balance: u128) {
    let pending = unmined(cx, st);
    let Some(explained) = st.balance else {
        // The first look: what is there is the wallet's past, not an arrival.
        st.balance = Some(balance.saturating_sub(pending));
        return;
    };
    let expected = explained.saturating_add(pending);
    if balance > expected {
        // Nothing is made of a rise just after this wallet's own send.
        if sent_lately(cx, st) {
            return;
        }
        match st.rise {
            Some((seen, since)) if cx.now.saturating_sub(since) >= CONFIRM_RISE_AFTER_SECONDS => {
                // Seen twice, apart: the lower of the two readings is what arrived.
                let held = balance.min(seen);
                st.rise = None;
                if held > expected {
                    let native = cx.network.native();
                    let mut item = Item::new(
                        format!("seen:{since}"),
                        String::new(),
                        since,
                        Direction::In,
                        native.symbol,
                    );
                    item.amount = held - expected;
                    item.decimals = native.decimals;
                    item.observed = true;
                    st.merge(vec![item]);
                    st.balance = Some(held - pending.min(held));
                }
            }
            Some((seen, since)) => st.rise = Some((seen.min(balance), since)),
            None => st.rise = Some((balance, cx.now)),
        }
        return;
    }
    st.rise = None;
    // Under what was expected, the sends have been mined already: the balance
    // is what remains once they have left.
    st.balance = Some(if balance >= expected { balance - pending } else { balance });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::Req;
    use crate::history::store::Kind;
    use crate::networks::Network;

    fn native_note(hash: &str, time: u64, amount: u128, fee: u128) -> Item {
        let mut note = Item::new(format!("note:{hash}"), hash.into(), time, Direction::Out, "TAO");
        note.status = Status::Pending;
        note.amount = amount;
        note.fee = Some(fee);
        note.decimals = 9;
        note.counterparty = Some("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty".into());
        // It used the account's nonce 7.
        note.nonce = Some(7);
        note
    }

    fn with_cx<T>(now: u64, f: impl FnOnce(&Cx<'_>) -> T) -> T {
        use crate::testing::Script;
        use std::sync::Arc;
        let client = crate::client::ChainClient::new(Arc::new(Script::new()));
        let req = Req::parse(&serde_json::json!({
            "network": "bittensor",
            "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        }))
        .unwrap();
        let cx = Cx {
            client: &client,
            net: client.net(Network::Bittensor),
            network: Network::Bittensor,
            req: &req,
            now,
        };
        f(&cx)
    }

    #[test]
    fn the_first_look_is_the_past_and_a_rise_after_it_is_an_arrival() {
        let mut st = State::new("t", 1_000);
        with_cx(1_000, |cx| observe(cx, &mut st, 5_000_000_000));
        assert!(st.items.is_empty(), "what was there is not an arrival");
        with_cx(1_060, |cx| observe(cx, &mut st, 5_000_000_000));
        assert!(st.items.is_empty(), "no change, no item");
        with_cx(1_120, |cx| observe(cx, &mut st, 7_500_000_000));
        assert!(st.items.is_empty(), "one reading of a rise is not yet an arrival");
        with_cx(1_130, |cx| observe(cx, &mut st, 7_500_000_000));
        assert!(st.items.is_empty(), "nor is a second a moment later");
        with_cx(1_150, |cx| observe(cx, &mut st, 7_500_000_000));
        assert_eq!(st.items.len(), 1);
        let arrival = &st.items[0];
        assert_eq!((arrival.amount, arrival.observed, arrival.time), (2_500_000_000, true, 1_120));
        assert_eq!(
            (arrival.direction, arrival.kind, arrival.asset.as_str()),
            (Direction::In, Kind::Transfer, "TAO")
        );
        assert!(arrival.hash.is_empty() && arrival.counterparty.is_none());
        // A fall is a spend (maybe from another device), not an arrival.
        with_cx(1_180, |cx| observe(cx, &mut st, 1_000_000_000));
        assert_eq!(st.items.len(), 1);
        with_cx(1_240, |cx| observe(cx, &mut st, 1_000_000_001));
        with_cx(1_270, |cx| observe(cx, &mut st, 1_000_000_001));
        assert_eq!(st.items.len(), 2, "and the baseline moved with it");
    }

    #[test]
    fn a_send_is_not_an_arrival_pending_or_mined() {
        // 10 TAO, then a send of 3 TAO and a fee of 0.001 as the app notes it.
        let mut st = State::new("t", 0);
        with_cx(100, |cx| observe(cx, &mut st, 10_000_000_000));
        st.notes.push(native_note("0xsend", 100, 3_000_000_000, 1_000_000));
        st.balance = Some(st.balance.unwrap() - 3_001_000_000);
        // Not mined: the chain still says 10 TAO.
        with_cx(130, |cx| observe(cx, &mut st, 10_000_000_000));
        assert!(st.items.is_empty());
        assert_eq!(st.balance, Some(6_999_000_000), "as it will be once the send is mined");
        // Mined: the balance fell by the amount and the fee; the note is settled at the same time.
        settle(&mut st, 250, Some(8));
        assert!(st.notes.is_empty());
        assert_eq!(st.items.len(), 1);
        assert_eq!(st.items[0].status, Status::Confirmed);
        assert_eq!(st.items[0].hash, "0xsend");
        with_cx(250, |cx| observe(cx, &mut st, 6_999_000_000));
        assert_eq!(st.items.len(), 1, "no arrival");
        // A rise soon after the wallet's own send is not taken for an arrival: the reading may be older
        // than the send.
        with_cx(310, |cx| observe(cx, &mut st, 8_000_000_000));
        with_cx(340, |cx| observe(cx, &mut st, 8_000_000_000));
        assert_eq!(st.items.len(), 1);
        // Once that time has passed, an arrival seen on two readings is.
        with_cx(800, |cx| observe(cx, &mut st, 8_000_000_000));
        assert_eq!(st.items.len(), 1);
        with_cx(830, |cx| observe(cx, &mut st, 8_000_000_000));
        assert_eq!(st.items.len(), 2);
        assert_eq!(st.items[0].amount, 1_001_000_000);
        assert_eq!(st.items[0].time, 800, "dated when it was first seen");
    }

    #[test]
    fn a_send_that_was_included_and_moved_nothing_is_confirmed_and_what_never_left_is_seen_again() {
        // The account's nonce passing a send's says its extrinsic was included, not that the transfer worked
        // (docs/history.md): one whose call failed once included cost its fee and moved nothing. It is
        // shown confirmed, and the coin that never left is noticed later as a rise: a "Seen" arrival.
        let mut st = State::new("t", 0);
        with_cx(100, |cx| observe(cx, &mut st, 10_000_000_000));
        st.notes.push(native_note("0xsend", 100, 3_000_000_000, 1_000_000));
        st.balance = Some(st.balance.unwrap() - 3_001_000_000);
        settle(&mut st, 250, Some(8));
        assert_eq!(st.items.len(), 1);
        assert_eq!(st.items[0].status, Status::Confirmed);
        // The fee was charged and the 3 TAO did not leave: 9.999, where the send explains 6.999.
        with_cx(250, |cx| observe(cx, &mut st, 9_999_000_000));
        with_cx(900, |cx| observe(cx, &mut st, 9_999_000_000));
        with_cx(930, |cx| observe(cx, &mut st, 9_999_000_000));
        let arrivals: Vec<_> = st.items.iter().filter(|item| item.observed).collect();
        assert_eq!(arrivals.len(), 1);
        assert_eq!((arrivals[0].amount, arrivals[0].direction), (3_000_000_000, Direction::In));
    }

    #[test]
    fn a_node_that_lags_after_a_send_makes_no_arrival() {
        // 10 TAO; 3 TAO and a fee are sent and mined: 6.999. A node that has not caught up (or a number kept
        // from before the send) says 10 again, once, a minute after: that is not 3.001 TAO arriving.
        let mut st = State::new("t", 0);
        with_cx(100, |cx| observe(cx, &mut st, 10_000_000_000));
        st.notes.push(native_note("0xsend", 100, 3_000_000_000, 1_000_000));
        st.balance = Some(st.balance.unwrap() - 3_001_000_000);
        settle(&mut st, 250, Some(8));
        with_cx(250, |cx| observe(cx, &mut st, 6_999_000_000));
        with_cx(300, |cx| observe(cx, &mut st, 10_000_000_000));
        with_cx(330, |cx| observe(cx, &mut st, 10_000_000_000));
        assert_eq!(st.items.len(), 1, "inside the quiet time after the send, even twice");
        with_cx(360, |cx| observe(cx, &mut st, 6_999_000_000));
        assert!(st.rise.is_none(), "and the honest reading clears it");
        // Well after the send, one stale reading and then the true one: nothing.
        with_cx(2_000, |cx| observe(cx, &mut st, 10_000_000_000));
        assert!(st.rise.is_some());
        with_cx(2_060, |cx| observe(cx, &mut st, 6_999_000_000));
        assert_eq!(st.items.len(), 1);
        assert!(st.rise.is_none());
        // The reading in doubt survives a stored state.
        with_cx(3_000, |cx| observe(cx, &mut st, 7_000_000_000));
        let again = State::load(&st.dump()).unwrap();
        assert_eq!(again.rise, st.rise);
    }

    #[test]
    fn a_send_counts_when_the_accounts_nonce_has_passed_it_and_not_before_however_long_it_waits() {
        let mut st = State::new("t", 0);
        st.notes.push(native_note("0xa", 100, 1, 1));
        // Not two minutes, not ten: the nonce has not moved, or nobody could say.
        for (now, included) in [(220, Some(7)), (700, Some(7)), (700, None), (990, Some(0))] {
            settle(&mut st, now, included);
            assert_eq!((st.notes.len(), st.items.len()), (1, 0), "{now} {included:?}");
        }
        settle(&mut st, 220, Some(8));
        assert_eq!((st.notes.len(), st.items.len()), (0, 1));
        let item = &st.items[0];
        assert_eq!(
            (item.status, item.verified, item.hash.as_str()),
            (Status::Confirmed, true, "0xa")
        );
        assert_eq!((item.amount, item.fee, item.nonce), (1, Some(1), Some(7)));
    }

    #[test]
    fn a_send_whose_era_is_over_with_the_nonce_where_it_was_never_came_in() {
        let mut st = State::new("t", 0);
        // 3 TAO and a fee, noted as the app does: the balance is lowered by both at once.
        with_cx(100, |cx| observe(cx, &mut st, 10_000_000_000));
        st.notes.push(native_note("0xa", 100, 3_000_000_000, 1_000_000));
        st.balance = Some(st.balance.unwrap() - 3_001_000_000);
        // Fourteen minutes and fifty-nine seconds: the era may not be over.
        settle(&mut st, 100 + DROPPED_AFTER_SECONDS - 1, Some(7));
        assert_eq!(st.notes.len(), 1);
        // Then it is: a failed send that moved and cost nothing, and the coin is the balance's again.
        settle(&mut st, 100 + DROPPED_AFTER_SECONDS, Some(7));
        assert!(st.notes.is_empty());
        let item = &st.items[0];
        assert_eq!(
            (item.status, item.kind, item.amount, item.fee),
            (Status::Failed, Kind::Call, 0, None)
        );
        assert_eq!(
            item.counterparty.as_deref(),
            Some("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty")
        );
        assert_eq!(st.balance, Some(10_000_000_000));
        // So the chain still saying 10 TAO is neither an arrival nor a surprise.
        with_cx(2_000, |cx| observe(cx, &mut st, 10_000_000_000));
        with_cx(2_030, |cx| observe(cx, &mut st, 10_000_000_000));
        assert_eq!(st.items.len(), 1);
        // The nonce passing it settles it as in, whatever the age.
        let mut late = State::new("t", 0);
        late.notes.push(native_note("0xb", 100, 1, 1));
        settle(&mut late, 100_000, Some(8));
        assert_eq!(late.items[0].status, Status::Confirmed);
    }

    #[test]
    fn a_note_with_no_nonce_waits_for_nothing_and_is_forgotten_after_three_days() {
        let mut st = State::new("t", 0);
        let mut note = native_note("0xa", 100, 1, 1);
        note.nonce = None;
        st.notes.push(note);
        for included in [None, Some(0), Some(u128::MAX)] {
            settle(&mut st, 100 + 3 * 86_400, included);
            assert_eq!(st.notes.len(), 1, "{included:?}");
        }
        settle(&mut st, 101 + 3 * 86_400, Some(u128::MAX));
        assert!(st.notes.is_empty() && st.items.is_empty());
    }

    #[test]
    fn the_nonce_rides_in_the_stored_state() {
        let mut st = State::new("t", 0);
        st.notes.push(native_note("0xa", 100, 1, 1));
        let again = State::load(&st.dump()).unwrap();
        assert_eq!(again.notes[0].nonce, Some(7));
        // A state from before the nonce was kept is read as it was.
        let old = st.dump().replace(",\"nc\":7", "");
        assert_ne!(old, st.dump());
        assert_eq!(State::load(&old).unwrap().notes[0].nonce, None);
    }

    #[test]
    fn the_coverage_is_from_the_day_the_wallet_was_first_seen() {
        let st = State::new("t", 1_793_000_000);
        let c = coverage(&st);
        assert_eq!((c.kind, c.from), ("from_first_sight", Some(1_793_000_000)));
    }
}
