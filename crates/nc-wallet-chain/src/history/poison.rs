//! Address poisoning, spotted on the device.
//!
//! The trick: an attacker makes an address that begins and ends like one the
//! victim has paid, and sends the victim a zero-value or dust transfer from it,
//! so that it shows in the history where a careless copy of "the address I paid
//! before" will find it. The history here marks such a transfer `poisoned`, with
//! the real address it imitates in `look_alike_of`, and the apps warn.
//!
//! A transfer is flagged when all of these hold:
//!
//! * it is **incoming** and has a counterparty (an arrival the wallet merely
//!   observed has none);
//! * it is **zero or dust**: below [`dust_limit`] of its asset;
//! * its sender is **not** an address this account has sent to, but **looks
//!   like** one: the same first four and last four characters of the address
//!   body (EVM: the hex after `0x`, compared without regard to case; elsewhere
//!   the characters after the network's fixed lead: `T`, `G`, `5`, `bc1q`/`bc1p`,
//!   `1`/`3`).
//!
//! Which addresses the account has sent to comes from the history itself (what
//! it sent, the notes of what the app sent, and a memory of the last 200 that
//! outlives the cap on items).

use super::store::{Direction, Item, MAX_SENT_TO, State};
use crate::networks::{Family, Network};

/// How many characters at each end must match.
const ENDS: usize = 4;

/// The least an incoming transfer of this asset must be to be an amount and not
/// dust, in base units: a hundredth of a stablecoin, a ten-thousandth of
/// Bitcoin's... The table, by ticker:
///
/// | Asset | Dust is below |
/// |---|---|
/// | USDT, USDC | 0.01 |
/// | ETH, BNB, POL | 0.000001 |
/// | BTC | 0.00002 (2,000 satoshis) |
/// | TRX, XLM | 0.01 |
/// | SOL | 0.00001 |
/// | TAO | 0.0001 |
/// | anything else | 0.000001 |
#[must_use]
pub fn dust_limit(asset: &str, decimals: u8) -> u128 {
    let scale = |exponent: u32| 10_u128.pow(u32::from(decimals).saturating_sub(exponent));
    match asset {
        "USDT" | "USDC" | "TRX" | "XLM" => scale(2),
        "BTC" => 2_000,
        "SOL" => scale(5),
        "TAO" => scale(4),
        _ => scale(6),
    }
}

/// An address without the fixed lead every address of the network begins with.
fn body(network: Network, address: &str) -> &str {
    let lead = match network.family() {
        Family::Evm => 2,
        Family::Bitcoin => {
            if address.starts_with("bc1") {
                4
            } else {
                1
            }
        }
        Family::Tron | Family::Stellar | Family::Substrate => 1,
        Family::Solana => 0,
    };
    address.get(lead..).unwrap_or("")
}

/// Whether `a` and `b` are different addresses that begin and end alike.
#[must_use]
pub fn looks_like(network: Network, a: &str, b: &str) -> bool {
    let (a, b) = (body(network, a), body(network, b));
    let fold = |s: &str| {
        if network.family() == Family::Evm { s.to_ascii_lowercase() } else { s.to_owned() }
    };
    let (a, b) = (fold(a), fold(b));
    if a == b || a.len() < ENDS * 2 || b.len() < ENDS * 2 {
        return false;
    }
    a.get(..ENDS) == b.get(..ENDS) && a.get(a.len() - ENDS..) == b.get(b.len() - ENDS..)
}

/// Whether two addresses are the same one (EVM: without regard to case).
fn same(network: Network, a: &str, b: &str) -> bool {
    if network.family() == Family::Evm { a.eq_ignore_ascii_case(b) } else { a == b }
}

/// Brings the memory of addresses sent to up to date and marks the look-alikes'
/// dust in `state`. Safe to run again: what is no longer a look-alike is cleared.
pub fn flag(network: Network, state: &mut State) {
    let mut sent: Vec<String> = Vec::new();
    let outgoing =
        state.notes.iter().chain(state.items.iter()).filter(|i| i.direction == Direction::Out);
    for item in outgoing {
        if let Some(to) = &item.counterparty
            && !sent.iter().any(|s| same(network, s, to))
        {
            sent.push(to.clone());
        }
    }
    for old in &state.sent_to {
        if !sent.iter().any(|s| same(network, s, old)) {
            sent.push(old.clone());
        }
    }
    sent.truncate(MAX_SENT_TO);
    state.sent_to = sent;

    let known = state.sent_to.clone();
    for item in &mut state.items {
        item.look_alike_of = look_alike(network, item, &known);
    }
}

fn look_alike(network: Network, item: &Item, sent_to: &[String]) -> Option<String> {
    if item.direction != Direction::In || item.observed {
        return None;
    }
    let from = item.counterparty.as_deref()?;
    if item.amount >= dust_limit(&item.asset, item.decimals) {
        return None;
    }
    if sent_to.iter().any(|s| same(network, s, from)) {
        return None;
    }
    sent_to.iter().find(|s| looks_like(network, s, from)).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = "0x5BC24606e389465DF34068fCC3357465e7A473C2";
    // Same first and last four hex digits, the middle another.
    const FAKE: &str = "0x5bc2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa73c2";

    fn incoming(id: &str, from: &str, amount: u128) -> Item {
        let mut i = Item::new(id.into(), format!("0x{id}"), 100, Direction::In, "USDT");
        i.amount = amount;
        i.decimals = 6;
        i.counterparty = Some(from.into());
        i
    }

    fn outgoing(to: &str) -> Item {
        let mut i = Item::new("o".into(), "0xo".into(), 50, Direction::Out, "USDT");
        i.amount = 5_000_000;
        i.decimals = 6;
        i.counterparty = Some(to.into());
        i
    }

    #[test]
    fn addresses_that_begin_and_end_alike_look_alike() {
        assert!(looks_like(Network::Ethereum, REAL, FAKE));
        assert!(!looks_like(Network::Ethereum, REAL, REAL));
        assert!(
            !looks_like(Network::Ethereum, REAL, &REAL.to_ascii_lowercase()),
            "the same address"
        );
        assert!(!looks_like(Network::Ethereum, REAL, "0x5bc2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa73c3"));
        assert!(!looks_like(Network::Ethereum, REAL, "0x6bc2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa73c2"));
        // The lead every address has is not a likeness.
        assert!(!looks_like(
            Network::Tron,
            "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9",
            "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb"
        ));
        assert!(looks_like(
            Network::Tron,
            "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9",
            "TMuA6AAAAAAAAAAAAAAAAAAAAAAAAAAAreY9"
        ));
        assert!(!looks_like(
            Network::Bitcoin,
            "bc1q9qkjc8x853msxzsykp5qc5hjc0uav8ak4wwj5q",
            "bc1qg3f7exyzcgpw48ysh58rgpuu7vyh9wnu64mae8"
        ));
    }

    #[test]
    fn dust_is_by_asset() {
        assert_eq!(dust_limit("USDT", 6), 10_000);
        assert_eq!(dust_limit("USDC", 18), 10_u128.pow(16), "BNB Chain's 18-decimal pegs");
        assert_eq!(dust_limit("ETH", 18), 10_u128.pow(12));
        assert_eq!(dust_limit("BTC", 8), 2_000);
        assert_eq!(dust_limit("TRX", 6), 10_000);
        assert_eq!(dust_limit("SOL", 9), 10_000);
        assert_eq!(dust_limit("TAO", 9), 100_000);
        assert_eq!(dust_limit("XLM", 7), 100_000);
    }

    #[test]
    fn a_zero_or_dust_transfer_from_a_look_alike_of_an_address_paid_is_flagged() {
        let mut state = State::new("t", 0);
        state.merge(vec![
            outgoing(REAL),
            incoming("zero", FAKE, 0),
            incoming("dust", FAKE, 1),
            incoming("real", FAKE, 25_000_000),
            incoming("stranger", "0x1111111111111111111111111111111111112222", 0),
            incoming("friend", REAL, 0),
        ]);
        flag(Network::Ethereum, &mut state);
        let flagged = |id: &str| {
            state.items.iter().find(|i| i.id == id).and_then(|i| i.look_alike_of.clone())
        };
        assert_eq!(flagged("zero").as_deref(), Some(REAL));
        assert_eq!(flagged("dust").as_deref(), Some(REAL));
        assert_eq!(flagged("real"), None, "a real amount is a payment, not a trick");
        assert_eq!(flagged("stranger"), None, "it resembles nothing paid");
        assert_eq!(flagged("friend"), None, "the address itself is not its own look-alike");
        assert_eq!(state.sent_to, [REAL]);
    }

    #[test]
    fn what_was_sent_to_is_remembered_past_the_items_and_the_flag_clears_when_it_no_longer_holds() {
        let mut state = State::new("t", 0);
        state.sent_to = vec![REAL.into()];
        state.merge(vec![incoming("zero", FAKE, 0)]);
        flag(Network::Ethereum, &mut state);
        assert!(state.items[0].look_alike_of.is_some(), "from the memory alone");
        // The person pays the address that was thought a fake: it is theirs now.
        state.merge(vec![outgoing(FAKE)]);
        flag(Network::Ethereum, &mut state);
        assert_eq!(state.items.iter().find(|i| i.id == "zero").unwrap().look_alike_of, None);
        assert_eq!(state.sent_to[0], FAKE);
    }

    #[test]
    fn an_arrival_the_wallet_only_saw_is_never_flagged_and_pending_sends_count() {
        let mut state = State::new("t", 0);
        let mut seen = incoming("seen", FAKE, 0);
        seen.observed = true;
        state.merge(vec![seen]);
        state.notes.push(outgoing(REAL));
        flag(Network::Ethereum, &mut state);
        assert_eq!(state.items[0].look_alike_of, None);
        assert_eq!(state.sent_to, [REAL], "a note of a send is a send");
    }

    #[test]
    fn the_memory_is_bounded() {
        let mut state = State::new("t", 0);
        state.sent_to = (0..400).map(|n| format!("0x{n:040x}")).collect();
        flag(Network::Ethereum, &mut state);
        assert_eq!(state.sent_to.len(), MAX_SENT_TO);
    }
}
