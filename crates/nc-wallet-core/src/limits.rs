//! The most this wallet will pay in network fees, whatever an endpoint says.
//!
//! A fee is a figure a public endpoint tells us, and a lying or broken endpoint could
//! quote a fee that costs a person a fortune. So the bounds do not come from the endpoints:
//! they are here, in the wallet, fixed per network, and an endpoint only chooses *within*
//! them.
//!
//! Each figure has two bounds:
//!
//! * **`alone`**: the most a figure may be when only **one operator** vouches for it. Above
//!   it, a second, independent operator must agree, or the figure is not used ("the
//!   network fee could not be confirmed, try again"). A lone liar can therefore cost
//!   the person no more than this.
//! * **`refuse`**: the most that is ever used, however many operators agree. Above it the
//!   figure is refused, not clamped: a number the wallet would have to change is a number it
//!   does not trust. The signing code checks `refuse` again, on the transaction it is about
//!   to sign, so a bug or a hostile caller above the chain client cannot get past it.
//!
//! The numbers are far above any fee seen in normal markets, and below what would hurt: they
//! are the last line, not the working range (the apps also show the fee in dollars and ask
//! for an extra confirmation when it is high, see `docs/direct-chain.md`).

use crate::evm::EvmChain;

/// One figure's two bounds (see the module's description).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    /// The most a lone operator's figure may be.
    pub alone: u128,
    /// The most any figure may be.
    pub refuse: u128,
}

impl Bound {
    const fn new(alone: u128, refuse: u128) -> Self {
        Self { alone, refuse }
    }

    /// A bound that is the same alone and with company.
    #[must_use]
    pub const fn alone_and_refuse(limit: u128) -> Self {
        Self::new(limit, limit)
    }

    /// Whether `value` is above what a lone operator may say: high enough that the person is asked
    /// to accept it, and a second operator must agree.
    #[must_use]
    pub const fn above_alone(self, value: u128) -> bool {
        value > self.alone
    }

    /// Whether `value` is within `refuse`.
    #[must_use]
    pub const fn allows(self, value: u128) -> bool {
        value <= self.refuse
    }

    /// Whether `value` may stand on `sources` independent operators.
    #[must_use]
    pub const fn trusts(self, value: u128, sources: usize) -> bool {
        value <= self.refuse && (sources >= 2 || value <= self.alone)
    }
}

/// One gwei, in wei.
pub const GWEI: u128 = 1_000_000_000;
/// One whole coin of an EVM chain, in wei.
pub const ETHER: u128 = 1_000_000_000_000_000_000;

/// The price per unit of gas a transaction may offer to pay, in wei.
#[must_use]
pub const fn evm_max_fee_per_gas(chain: EvmChain) -> Bound {
    match chain {
        EvmChain::Ethereum => Bound::new(150 * GWEI, 1_000 * GWEI),
        EvmChain::BnbChain => Bound::new(20 * GWEI, 200 * GWEI),
        // A real Polygon transaction has paid 5,000 gwei; POL is cheap, so the ceiling is generous.
        EvmChain::Polygon => Bound::new(1_000 * GWEI, 10_000 * GWEI),
        EvmChain::Base => Bound::new(5 * GWEI, 200 * GWEI),
    }
}

/// The tip to the block producer, per unit of gas, in wei.
#[must_use]
pub const fn evm_priority_fee(chain: EvmChain) -> Bound {
    match chain {
        EvmChain::Ethereum => Bound::new(20 * GWEI, 200 * GWEI),
        EvmChain::BnbChain => Bound::new(5 * GWEI, 50 * GWEI),
        EvmChain::Polygon => Bound::new(500 * GWEI, 10_000 * GWEI),
        EvmChain::Base => Bound::new(2 * GWEI, 50 * GWEI),
    }
}

/// The gas a plain coin or listed-token send may reserve. A send to a contract that burns all
/// of it pays for all of it, so the reservation is bounded however high an estimate says.
pub const EVM_GAS_LIMIT: u64 = 600_000;

/// The most a send may reserve for fees in all, in wei: its gas limit at its max fee per gas
/// (plus, on Base, the layer-1 data fee).
#[must_use]
pub const fn evm_total_fee(chain: EvmChain) -> Bound {
    match chain {
        // 0.01 / 0.05 ETH (about $24 / $120), and the same of BNB.
        EvmChain::Ethereum | EvmChain::BnbChain => Bound::new(ETHER / 100, ETHER / 20),
        // 5 / 20 POL.
        EvmChain::Polygon => Bound::new(5 * ETHER, 20 * ETHER),
        // 0.001 / 0.005 ETH.
        EvmChain::Base => Bound::new(ETHER / 1_000, ETHER / 200),
    }
}

/// The gas a *site's* transaction may reserve. A contract call (a swap through an aggregator, a
/// batch mint, a bridge deposit) uses a few hundred thousand units, the heaviest ordinary ones
/// up to about two million; three million covers them. Above it the site is asked to split the call:
/// a transaction that reserves more can burn a block's worth of work at the person's cost.
pub const EVM_DAPP_GAS_LIMIT: u64 = 3_000_000;

/// The most a *site's* transaction may reserve for fees in all, in wei: its gas limit at its max
/// fee per gas. Ten times a plain send's, because contract calls cost more.
#[must_use]
pub const fn evm_dapp_total_fee(chain: EvmChain) -> Bound {
    match chain {
        // 0.05 / 0.5 ETH (about $120 / $1,200), and the same of BNB.
        EvmChain::Ethereum | EvmChain::BnbChain => Bound::new(ETHER / 20, ETHER / 2),
        // 20 / 200 POL.
        EvmChain::Polygon => Bound::new(20 * ETHER, 200 * ETHER),
        // 0.01 / 0.05 ETH.
        EvmChain::Base => Bound::new(ETHER / 100, ETHER / 20),
    }
}

/// Base's layer-1 data fee for one transaction, in wei.
pub const BASE_L1_FEE: Bound = Bound::new(ETHER / 2_000, ETHER / 200);

/// Bitcoin's fee rate, in satoshis per thousand virtual bytes (100 and 1,000 sat/vB).
pub const BITCOIN_RATE_KVB: Bound = Bound::new(100_000, 1_000_000);

/// What a Bitcoin transaction may pay in all, in satoshis: 0.001 BTC alone, 0.01 BTC.
pub const BITCOIN_TOTAL: Bound = Bound::new(100_000, 1_000_000);

/// What a Bitcoin transaction may pay in all, in satoshis (0.01 BTC).
pub const BITCOIN_TOTAL_FEE: u128 = BITCOIN_TOTAL.refuse;

/// What a Solana transaction may pay in all, in lamports: 0.001 SOL alone, 0.01 SOL.
pub const SOLANA_TOTAL_FEE: Bound = Bound::new(1_000_000, 10_000_000);

/// The fee limit of a TRON transaction, in sun: 100 TRX alone, 300 TRX.
pub const TRON_FEE_LIMIT: Bound = Bound::new(100_000_000, 300_000_000);

/// The fee limit of a TRON transaction a *site* built, in sun: 150 TRX alone (`TronWeb`'s own default), 1,000
/// TRX. A site's contract call names the most it may burn for energy; it burns only what it uses, so the
/// limit is a cap and not the fee. Above the first the person is asked to accept it, above the second it is
/// refused.
pub const TRON_DAPP_FEE_LIMIT: Bound = Bound::new(150_000_000, 1_000_000_000);

/// What TRON charges per unit of energy, in sun (the network's own figure): 500 alone, 2,000.
pub const TRON_ENERGY_PRICE: Bound = Bound::new(500, 2_000);

/// What TRON charges per byte of bandwidth burned, in sun: 1,500 alone, 5,000.
pub const TRON_BANDWIDTH_PRICE: Bound = Bound::new(1_500, 5_000);

/// Stellar's fee per operation, in stroops: 0.001 XLM alone, 0.1 XLM.
pub const STELLAR_BASE_FEE: Bound = Bound::new(10_000, 1_000_000);

/// What a Bittensor transfer may cost, in rao: 0.001 TAO alone, 0.01 TAO.
pub const BITTENSOR_FEE: Bound = Bound::new(1_000_000, 10_000_000);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_figure_stands_alone_only_up_to_its_lower_bound_and_never_above_the_upper() {
        let bound = Bound::new(10, 100);
        assert!(bound.trusts(10, 1));
        assert!(!bound.trusts(11, 1));
        assert!(bound.trusts(11, 2));
        assert!(bound.trusts(100, 2));
        assert!(!bound.trusts(101, 2));
        assert!(!bound.trusts(101, 5));
        assert!(bound.allows(100) && !bound.allows(101));
    }

    #[test]
    fn every_bound_is_ordered_and_the_totals_cover_the_reservations() {
        for chain in EvmChain::ALL {
            for bound in [evm_max_fee_per_gas(chain), evm_priority_fee(chain), evm_total_fee(chain)]
            {
                assert!(0 < bound.alone && bound.alone <= bound.refuse, "{chain:?}");
            }
            // A tip never needs to be above the max fee it rides in.
            assert!(evm_priority_fee(chain).refuse <= evm_max_fee_per_gas(chain).refuse);
        }
        for bound in [
            BASE_L1_FEE,
            BITCOIN_RATE_KVB,
            SOLANA_TOTAL_FEE,
            TRON_FEE_LIMIT,
            TRON_DAPP_FEE_LIMIT,
            TRON_ENERGY_PRICE,
            TRON_BANDWIDTH_PRICE,
            STELLAR_BASE_FEE,
            BITTENSOR_FEE,
        ] {
            assert!(0 < bound.alone && bound.alone <= bound.refuse);
        }
    }

    #[test]
    fn what_ordinary_sends_pay_is_far_inside_the_bounds() {
        // A token send on Ethereum at 30 gwei with a 2 gwei tip, 65,000 gas.
        let max_fee = 32 * GWEI;
        assert!(evm_max_fee_per_gas(EvmChain::Ethereum).trusts(max_fee, 1));
        assert!(evm_total_fee(EvmChain::Ethereum).trusts(max_fee * 65_000, 1));
        // 100 gwei and 21,000 gas on Polygon is 0.0021 POL, a hundredth of a cent.
        assert!(evm_total_fee(EvmChain::Polygon).trusts(100 * GWEI * 21_000, 1));
        assert!(evm_total_fee(EvmChain::Base).trusts(GWEI / 10 * 65_000 + ETHER / 50_000, 1));
        // Polygon's usual tip of 30 gwei and a price of 50.
        assert!(evm_priority_fee(EvmChain::Polygon).trusts(30 * GWEI, 1));
        assert!(evm_max_fee_per_gas(EvmChain::Polygon).trusts(50 * GWEI, 1));
        // 140 vB at 20 sat/vB.
        assert!(BITCOIN_RATE_KVB.trusts(20_000, 1) && 140 * 20 < BITCOIN_TOTAL_FEE);
        // TRX: 65,000 energy at 420 sun.
        assert!(TRON_FEE_LIMIT.trusts(65_000 * 420 * 13 / 10, 1));
    }
}
