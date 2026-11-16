//! Ethereum, BNB Chain, Polygon and Base, by plain JSON-RPC to public nodes.
//!
//! * **Balances** in one `eth_call` of Multicall3 (the coin through
//!   `getEthBalance`, each token through `balanceOf`), and one at a time when an
//!   endpoint will not do a multicall.
//! * **Inputs** for a send: the account's pending nonce and the fee market
//!   (the node's gas price, the latest block's base fee, the tip). Each is read
//!   from two endpoints of different operators and believed where they agree.
//! * **Estimate**: the gas of this very transfer from the node
//!   (`eth_estimateGas`, a fifth of headroom), the price it bids, and on Base the
//!   L1 data fee its gas price oracle quotes.
//! * **Broadcast** to up to three endpoints at once.
//! * **Status** from the receipt.

use nc_wallet_core::evm::EvmChain;
use nc_wallet_core::limits;
use serde_json::{Value, json};
use sha3::{Digest as _, Keccak256};

use crate::abi::{self, SubCall};
use crate::address::{self, Address};
use crate::common::{EstimateArgs, balances_body, fee_value, native_entry, token_entry};
use crate::error::{ChainError, ChainResult, REFUSED, clean};
use crate::net::{Net, NodeError};
use crate::networks::Network;
use crate::pool::Need;
use crate::quorum::{Figure, Kind, unconfirmed};
use crate::util::{bytes_from_hex, to_hex, u64_from_hex, u128_from_hex, word_to_u128};

/// Gas of a plain coin transfer to an account with no code.
const TRANSFER_GAS: u128 = 21_000;
/// The headroom put on a node's gas estimate, in percent.
const GAS_BUFFER_PERCENT: u128 = 120;
/// The rollups' gas price oracle, which prices the L1 data fee.
const GAS_PRICE_ORACLE: &str = "0x420000000000000000000000000000000000000F";
/// The unsigned size an L1 data fee is priced for: a coin transfer and a token
/// transfer, each a little over.
const L1_SIZE_COIN: u128 = 130;
const L1_SIZE_TOKEN: u128 = 190;
/// Blocks of fee history a tip is read from where a node has no oracle, and the tiers of a fee are read
/// from.
const FEE_HISTORY_BLOCKS: u64 = 10;
/// The percentiles of the tips paid in a block that the slow and the fast tier are read from.
const SLOW_PERCENTILE: u64 = 10;
const FAST_PERCENTILE: u64 = 90;
/// How many endpoints a signed transaction is sent to at once.
const BROADCAST_TO: usize = 3;

/// The least tip each network takes, in wei: Polygon takes nothing under
/// 25 gwei, BNB Chain asks 0.05 gwei, Ethereum a hundredth of a gwei.
#[must_use]
pub const fn min_priority_fee(network: Network) -> u128 {
    match network {
        Network::Polygon => 25_000_000_000,
        Network::Bsc => 50_000_000,
        Network::Ethereum => 10_000_000,
        _ => 0,
    }
}

/// The fee market now.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fees {
    gas_price: u128,
    /// `None` on a network whose blocks carry no base fee.
    base_fee: Option<u128>,
    tip: u128,
    /// How many independent operators the figures rest on, at the least.
    sources: usize,
}

impl Fees {
    /// Twice the base fee and the tip: room for two blocks of rises.
    fn max_fee(&self) -> Option<u128> {
        self.base_fee.map(|base| base.saturating_mul(2).saturating_add(self.tip))
    }

    /// The price a transaction bids: the cap where there is one.
    fn bid(&self) -> u128 {
        self.max_fee().unwrap_or(self.gas_price)
    }
}

/// What a transaction bids at a speed other than the standard one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bid {
    max_fee: u128,
    tip: u128,
    /// How many independent operators the bid rests on, at the least.
    sources: usize,
}

/// An EVM network.
#[derive(Debug, Clone, Copy)]
pub struct Evm<'a> {
    net: &'a Net,
    network: Network,
}

fn quantity(value: &Value) -> Option<u128> {
    u128_from_hex(value.as_str()?)
}

/// The number in a call's answer that is one 32-byte word.
fn word(value: &Value) -> Option<u128> {
    word_to_u128(&bytes_from_hex(value.as_str()?)?)
}

impl<'a> Evm<'a> {
    /// The network `network` over `net`.
    #[must_use]
    pub const fn new(net: &'a Net, network: Network) -> Self {
        Self { net, network }
    }

    fn chain_id(&self) -> u64 {
        self.network.chain_id().unwrap_or(0)
    }

    /// One call on one endpoint, a node's refusal turned into `Unavailable`
    /// (for a read nothing depends on).
    async fn read(&self, method: &'static str, params: Value) -> ChainResult<Value> {
        match self.net.rpc(Need::ANY, method, &params).await? {
            Ok(value) => Ok(value),
            Err(_) => Err(ChainError::Unavailable),
        }
    }

    async fn eth_call(&self, to: &str, data: &[u8]) -> ChainResult<Result<Vec<u8>, NodeError>> {
        let params = json!([{ "to": to, "data": to_hex(data) }, "latest"]);
        let answer = self.net.rpc(Need::ANY, "eth_call", &params).await?;
        Ok(answer.and_then(|value| {
            value.as_str().and_then(bytes_from_hex).ok_or(NodeError {
                code: 0,
                message: "not hex".to_owned(),
                data: None,
            })
        }))
    }

    /// The coin and every listed token of `address`.
    pub async fn balances(&self, address: &Address, as_of: &str) -> ChainResult<Value> {
        let owner = address.evm()?;
        let tokens = self.network.tokens();
        let mut calls = vec![SubCall {
            target: address_bytes(abi::MULTICALL3)?,
            data: abi::eth_balance(&owner),
        }];
        for token in tokens {
            calls.push(SubCall {
                target: address_bytes(token.contract)?,
                data: abi::balance_of(&owner),
            });
        }
        let data = abi::aggregate3(&calls);
        let from_multicall = match self.eth_call(abi::MULTICALL3, &data).await? {
            Ok(bytes) => {
                abi::decode_aggregate3(&bytes).filter(|results| results.len() == calls.len())
            }
            Err(_) => None,
        };
        let (native, token_amounts) = match from_multicall {
            Some(results) => {
                let native =
                    results.first().filter(|r| r.success).and_then(|r| word_to_u128(&r.data));
                let amounts: Vec<Option<u128>> = results
                    .iter()
                    .skip(1)
                    .map(|r| r.success.then(|| word_to_u128(&r.data)).flatten())
                    .collect();
                match native {
                    Some(native) => (native, amounts),
                    None => self.balances_one_by_one(address).await?,
                }
            }
            None => self.balances_one_by_one(address).await?,
        };
        let mut entries = vec![native_entry(self.network, native)];
        entries.extend(tokens.iter().zip(token_amounts).map(|(t, a)| token_entry(t, a)));
        Ok(balances_body(self.network, &address.text, &entries, as_of))
    }

    async fn balances_one_by_one(
        &self,
        address: &Address,
    ) -> ChainResult<(u128, Vec<Option<u128>>)> {
        let owner = address.evm()?;
        let native = self.read("eth_getBalance", json!([address.text, "latest"])).await?;
        let native = quantity(&native).ok_or(ChainError::Unavailable)?;
        let reads = self.network.tokens().iter().map(|token| async move {
            let answer = self.eth_call(token.contract, &abi::balance_of(&owner)).await.ok()?;
            word_to_u128(&answer.ok()?)
        });
        Ok((native, futures::future::join_all(reads).await))
    }

    /// The wallet's own bounds for this network's fees.
    fn chain(&self) -> ChainResult<EvmChain> {
        EvmChain::from_chain_id(self.chain_id()).ok_or(ChainError::Internal)
    }

    /// The fee market, each figure read from two endpoints of different operators and held to
    /// the wallet's own bounds (`nc_wallet_core::limits`): a figure above them is refused, one
    /// above the lone-operator bound needs a second operator to agree, or is not used.
    ///
    /// The base fee comes from `eth_feeHistory` (the next block's, a few
    /// hundred bytes) and not from the latest block, whose list of transaction
    /// hashes is tens of kilobytes on a busy network.
    async fn fees(&self) -> ChainResult<Fees> {
        let chain = self.chain()?;
        let (base_fee, tip) = futures::join!(self.base_fee(), self.tip());
        let (base_fee, tip) = (base_fee?, tip?);
        let tip_sources = tip.sources;
        let tip = Figure { value: tip.value.max(min_priority_fee(self.network)), ..tip }
            .within(limits::evm_priority_fee(chain), "tip")?;
        if let (Some(base), base_sources) = base_fee {
            // The price a node would quote: what the next block asks and the tip.
            let sources = base_sources.min(tip_sources);
            let fees =
                Fees { gas_price: base.saturating_add(tip), base_fee: Some(base), tip, sources };
            // What a transaction bids is held to the bound, on the weaker of the two readings.
            Figure { value: fees.bid(), sources }
                .within(limits::evm_max_fee_per_gas(chain), "network fee")?;
            Ok(fees)
        } else {
            let none = json!([]);
            let price = self.net.rpc_figure("eth_gasPrice", &none, quantity, Kind::Fee).await?;
            let gas_price = price.within(limits::evm_max_fee_per_gas(chain), "network fee")?;
            Ok(Fees { gas_price, base_fee: None, tip, sources: price.sources.min(tip_sources) })
        }
    }

    /// The next block's base fee, or `None` on a network whose blocks carry none, with how
    /// many operators agree on it.
    async fn base_fee(&self) -> ChainResult<(Option<u128>, usize)> {
        // `u128::MAX` stands for "no base fee" so that two answers can be compared.
        fn next(value: &Value) -> Option<u128> {
            match value.get("baseFeePerGas") {
                None => Some(u128::MAX),
                Some(list) => quantity(list.as_array()?.last()?),
            }
        }
        fn in_block(value: &Value) -> Option<u128> {
            match value.get("baseFeePerGas") {
                None => Some(u128::MAX),
                Some(fee) => quantity(fee),
            }
        }
        let history = json!(["0x1", "latest", []]);
        let figure = match self.net.rpc_figure("eth_feeHistory", &history, next, Kind::Fee).await {
            Ok(figure) => figure,
            // Operators that disagree are not a reason to ask someone else.
            Err(error @ (ChainError::Unconfirmed(_) | ChainError::OverCeiling(_))) => {
                return Err(error);
            }
            Err(_) => {
                // An endpoint list that will not do fee history is asked for the block.
                let latest = json!(["latest", false]);
                self.net.rpc_figure("eth_getBlockByNumber", &latest, in_block, Kind::Fee).await?
            }
        };
        Ok(((figure.value != u128::MAX).then_some(figure.value), figure.sources))
    }

    /// The tip a transaction landing now bids: the nodes' oracle, or the median of what
    /// recent blocks' transactions tipped, each read from two operators.
    async fn tip(&self) -> ChainResult<Figure> {
        fn median_reward(history: &Value) -> Option<u128> {
            let mut tips: Vec<u128> = history
                .get("reward")?
                .as_array()?
                .iter()
                .filter_map(|block| quantity(block.get(0)?))
                .collect();
            tips.sort_unstable();
            tips.get(tips.len() / 2).copied()
        }
        match self.net.rpc_figure("eth_maxPriorityFeePerGas", &json!([]), quantity, Kind::Tip).await
        {
            Ok(figure) => return Ok(figure),
            Err(error @ (ChainError::Unconfirmed(_) | ChainError::OverCeiling(_))) => {
                return Err(error);
            }
            Err(_) => {}
        }
        let history = json!([format!("0x{FEE_HISTORY_BLOCKS:x}"), "latest", [50]]);
        self.net.rpc_figure("eth_feeHistory", &history, median_reward, Kind::Tip).await
    }

    /// The slow and the fast bid next to the standard one `fees` makes, or `None` for a tier that cannot be
    /// vouched for (a network whose blocks carry no base fee, tips the operators do not agree on, a bid past the
    /// wallet's own bounds).
    ///
    /// Slow leaves room for one block's rise of an eighth (a block's base fee can rise by no more) and tips what
    /// the quiet blocks of the last ten paid (the 10th percentile of each block's tips, the middle of the ten);
    /// fast keeps standard's room of two blocks and tips what the busy blocks paid (the 90th). Neither is ever
    /// past the standard on the wrong side of it.
    async fn speeds(&self, fees: &Fees) -> (Option<Bid>, Option<Bid>) {
        // The middle, over the blocks, of the tip each paid at the two percentiles.
        fn tips(history: &Value) -> Option<Vec<u128>> {
            let blocks = history.get("reward")?.as_array()?;
            let at = |place: usize| {
                let mut tips: Vec<u128> =
                    blocks.iter().filter_map(|block| quantity(block.get(place)?)).collect();
                tips.sort_unstable();
                tips.get(tips.len() / 2).copied()
            };
            Some(vec![at(0)?, at(1)?])
        }
        let (Some(base), Ok(chain)) = (fees.base_fee, self.chain()) else { return (None, None) };
        let params = json!([
            format!("0x{FEE_HISTORY_BLOCKS:x}"),
            "latest",
            [SLOW_PERCENTILE, FAST_PERCENTILE]
        ]);
        let Ok(tips) =
            self.net.rpc_figures("eth_feeHistory", &params, tips, &[Kind::Tip, Kind::Tip]).await
        else {
            return (None, None);
        };
        let [quiet, busy] = tips[..] else { return (None, None) };
        let bid = |tip: u128, max_fee: u128, sources: usize| -> Option<Bid> {
            let sources = sources.min(fees.sources);
            Figure { value: tip, sources }.within(limits::evm_priority_fee(chain), "tip").ok()?;
            Figure { value: max_fee, sources }
                .within(limits::evm_max_fee_per_gas(chain), "network fee")
                .ok()?;
            Some(Bid { max_fee, tip, sources })
        };
        let slow_tip = quiet.value.max(min_priority_fee(self.network)).min(fees.tip);
        let fast_tip = busy.value.max(fees.tip);
        (
            bid(
                slow_tip,
                base.saturating_mul(9).div_ceil(8).saturating_add(slow_tip),
                quiet.sources,
            ),
            bid(fast_tip, base.saturating_mul(2).saturating_add(fast_tip), busy.sources),
        )
    }

    /// Whether `address` has code (a contract, or an account that delegates to
    /// one). Two operators are asked, and a contract to either is a contract:
    /// a coin sent to one with the gas of a plain transfer would run out.
    async fn is_contract(&self, address: &Address) -> ChainResult<bool> {
        let params = json!([address.text, "latest"]);
        let answers = self.net.rpc_many(Need::ANY, 2, "eth_getCode", &params).await?;
        let mut any_answer = false;
        for (answer, _) in answers {
            if let Ok(code) = answer
                && let Some(code) = code.as_str()
            {
                any_answer = true;
                if code.trim_start_matches("0x").bytes().any(|b| b != b'0') {
                    return Ok(true);
                }
            }
        }
        if any_answer { Ok(false) } else { Err(ChainError::Unavailable) }
    }

    /// The L1 data fee of an unsigned transaction of `size` bytes on a rollup
    /// (an upper bound at the oracle's current prices), read from two operators and held to
    /// the wallet's own bound; `None` elsewhere. A rollup whose oracle cannot be read is an
    /// error, not a fee of nothing.
    async fn l1_fee(&self, size: u128) -> ChainResult<Option<(u128, usize)>> {
        if self.network != Network::Base {
            return Ok(None);
        }
        let params = json!([{ "to": GAS_PRICE_ORACLE, "data": to_hex(&abi::l1_fee_upper_bound(size)) }, "latest"]);
        let figure = self.net.rpc_figure("eth_call", &params, word, Kind::Fee).await?;
        figure
            .within(limits::BASE_L1_FEE, "layer-1 data fee")
            .map(|fee| Some((fee, figure.sources)))
    }

    /// What a send is built from. `floor` is the least the nonce may be: one past the last this
    /// device sent while that is fresh (see [`crate::sent`]).
    ///
    /// The nonce must be confirmed by two operators: a nonce that is too low would replace the
    /// person's own pending transaction, and one that is too high leaves a gap.
    pub async fn inputs(&self, address: &Address, floor: u128) -> ChainResult<Value> {
        let nonce_params = json!([address.text, "pending"]);
        let (nonce, fees) = futures::join!(
            self.net.rpc_figure("eth_getTransactionCount", &nonce_params, quantity, Kind::Exact),
            self.fees(),
        );
        let (nonce, fees) = (nonce?, fees?);
        if nonce.sources < 2 {
            return Err(unconfirmed("number of the next transaction"));
        }
        let nonce = Figure { value: nonce.value.max(floor), ..nonce };
        Ok(json!({
            "network": self.network.id(),
            "address": address.text,
            "chain_id": self.chain_id(),
            "nonce": u64::try_from(nonce.value).map_err(|_| ChainError::Unavailable)?,
            "gas_price": fees.gas_price.to_string(),
            "eip1559": fees.base_fee.is_some(),
            "base_fee": fees.base_fee.map(|fee| fee.to_string()),
            "max_priority_fee": fees.base_fee.map(|_| fees.tip.to_string()),
            "max_fee": fees.max_fee().map(|fee| fee.to_string()),
        }))
    }

    /// The fee of a transfer and what is known of its recipient.
    pub async fn estimate(&self, args: &EstimateArgs) -> ChainResult<Value> {
        let from = address::parse(self.network, &args.from)
            .map_err(|_| ChainError::InvalidAddress("from is not a valid address".to_owned()))?;
        let to = address::parse(self.network, &args.to)
            .map_err(|_| ChainError::InvalidAddress("to is not a valid address".to_owned()))?;
        let recipient = to.evm()?;
        let (target, value, data) = match args.token {
            Some(token) => (
                token.contract.to_owned(),
                0_u128,
                Some(abi::erc20_transfer(&recipient, args.amount)),
            ),
            None => (to.text.clone(), args.amount, None),
        };
        let (contract, fees) = futures::join!(self.is_contract(&to), self.fees());
        let (contract, fees) = (contract?, fees?);
        let (slow, fast) = if args.tiers { self.speeds(&fees).await } else { (None, None) };

        let (gas, gas_sources) = if args.token.is_none() && !contract {
            // A plain transfer to an account is 21,000 by the protocol, whoever is asked.
            (TRANSFER_GAS, 2)
        } else {
            let mut call =
                json!({ "from": from.text, "to": target, "value": format!("0x{value:x}") });
            if let Some(data) = data {
                call["data"] = json!(to_hex(&data));
            }
            self.gas_of(&call).await?
        };

        let l1 =
            self.l1_fee(if args.token.is_some() { L1_SIZE_TOKEN } else { L1_SIZE_COIN }).await?;
        let total = gas.saturating_mul(fees.bid()).saturating_add(l1.map_or(0, |(fee, _)| fee));
        // Refused above the wallet's own ceiling whoever agrees; above what a lone operator may say,
        // only if every figure it rests on has a second operator's word.
        let sources = fees.sources.min(gas_sources).min(l1.map_or(usize::MAX, |(_, n)| n));
        Figure { value: total, sources }
            .within(limits::evm_total_fee(self.chain()?), "network fee")?;
        // The same work at each speed: what it would cost at the most each bids, held to the same bound.
        let l1_fee = l1.map_or(0, |(fee, _)| fee);
        let tier = |bid: Option<Bid>| -> Value {
            let Some(bid) = bid else { return Value::Null };
            let total = gas.saturating_mul(bid.max_fee).saturating_add(l1_fee);
            let sources = bid.sources.min(gas_sources).min(l1.map_or(usize::MAX, |(_, n)| n));
            let within = self.chain().and_then(|chain| {
                Figure { value: total, sources }.within(limits::evm_total_fee(chain), "network fee")
            });
            if within.is_err() {
                return Value::Null;
            }
            json!({
                "gas_price": fees.base_fee.unwrap_or(0).saturating_add(bid.tip).to_string(),
                "max_fee_per_gas": bid.max_fee.to_string(),
                "max_priority_fee_per_gas": bid.tip.to_string(),
                "fee": fee_value(self.network.native(), total),
            })
        };
        let standard = fees.max_fee().map(|max_fee| Bid { max_fee, tip: fees.tip, sources });
        let mut answer = json!({
            "network": self.network.id(),
            "gas_limit": gas.to_string(),
            "gas_price": fees.gas_price.to_string(),
            "eip1559": fees.base_fee.is_some(),
            "max_fee_per_gas": fees.max_fee().map(|fee| fee.to_string()),
            "max_priority_fee_per_gas": fees.base_fee.map(|_| fees.tip.to_string()),
            "fee": fee_value(self.network.native(), total),
            "recipient": { "is_contract": contract },
        });
        // Slow, standard and fast, when the app asked for them and the network's blocks carry a base fee;
        // standard is the top of the answer. A speed that cannot be vouched for is `null`.
        if args.tiers && standard.is_some() {
            answer["fees"] =
                json!({ "slow": tier(slow), "normal": tier(standard), "fast": tier(fast) });
        }
        if let Some((l1, _)) = l1 {
            answer["l1_fee"] = json!(l1.to_string());
        }
        Ok(answer)
    }

    /// `eth_estimateGas` from two operators: the higher, as they said it (no headroom, no bound), and how
    /// many stand behind it: the answers within a quarter of the highest. One means a lone answer, or two that
    /// do not agree (one node far below the other): the figure is then one node's word and the caller must not
    /// build a bound out of it. A node that says the call would fail is believed (it ran it).
    pub async fn gas_raw(&self, call: &Value) -> ChainResult<(u128, usize)> {
        let answers = self
            .net
            .rpc_many(Need::ANY.independent(), 2, "eth_estimateGas", &json!([call]))
            .await?;
        let mut figures: Vec<u128> = Vec::new();
        let mut refusal: Option<NodeError> = None;
        for (answer, _) in answers {
            match answer {
                Ok(value) => figures.extend(quantity(&value)),
                Err(error) => refusal = refusal.or(Some(error)),
            }
        }
        if let Some(error) = refusal {
            let lower = error.lower();
            return Err(if lower.contains("insufficient funds") {
                ChainError::InsufficientFunds(
                    "the account cannot cover the amount and the fee".to_owned(),
                )
            } else if error.code == 3 || lower.contains("revert") {
                // The contract's verdict, which the person may need: its reason is
                // quoted as what the network reported, never as the wallet's own words.
                ChainError::EstimateFailed(format!(
                    "the call would fail; the network reports: \"{}\"",
                    clean(&error.message)
                ))
            } else {
                ChainError::EstimateFailed("the network could not estimate this call".to_owned())
            });
        }
        let gas = figures.iter().copied().max().ok_or(ChainError::Unavailable)?;
        let sources = figures
            .iter()
            .filter(|figure| figure.saturating_mul(4) >= gas.saturating_mul(3))
            .count();
        Ok((gas, sources))
    }

    /// The work of a plain send, with a fifth of headroom, and bounded by the wallet's own limit: a send to
    /// a contract that burns all it is given pays for all of it.
    async fn gas_of(&self, call: &Value) -> ChainResult<(u128, usize)> {
        let (gas, sources) = self.gas_raw(call).await?;
        let gas = gas.saturating_mul(GAS_BUFFER_PERCENT).div_ceil(100);
        if gas > u128::from(limits::EVM_GAS_LIMIT) {
            return Err(ChainError::OverCeiling(
                "this send needs more work than the most this wallet will pay for".to_owned(),
            ));
        }
        Ok((gas, sources))
    }

    /// The hash a signed transaction will have: Keccak-256 of its bytes.
    #[must_use]
    pub fn hash(raw: &[u8]) -> String {
        to_hex(&Keccak256::digest(raw))
    }

    /// Sends signed bytes to up to three endpoints at once and tells the
    /// verdict. Returns the transaction's hash.
    ///
    /// `sent_before` is whether this device already had this very transaction accepted: if
    /// the nodes now say its nonce is used, it is that transaction that used it.
    pub async fn broadcast(
        &self,
        raw: &[u8],
        hash: &str,
        sent_before: bool,
    ) -> ChainResult<String> {
        let hash = hash.to_owned();
        let answers = self
            .net
            .rpc_many(Need::ANY, BROADCAST_TO, "eth_sendRawTransaction", &json!([to_hex(raw)]))
            .await?;
        let mut accepted = false;
        let mut known = false;
        let mut known_by: Vec<usize> = Vec::new();
        let mut refusal: Option<ChainError> = None;
        let mut nonce_low = false;
        for (answer, index) in answers {
            match answer {
                Ok(_) => accepted = true,
                Err(error) => {
                    let lower = error.lower();
                    if lower.contains("already known")
                        || lower.contains("known transaction")
                        || lower.contains("already imported")
                        || lower.contains("already in the mempool")
                    {
                        known = true;
                        known_by.push(index);
                    } else if lower.contains("nonce too low") {
                        nonce_low = true;
                    } else if refusal.is_none() {
                        refusal = refused(&error);
                    }
                }
            }
        }
        if accepted {
            return Ok(hash);
        }
        if known {
            // "Already known" with nobody having accepted it is one node's word that it has
            // the transaction. This device has it accepted before, or a second operator has
            // it too, or it is not shown as sent: a lone node (or a lie on the path) could
            // otherwise make an unsent payment look sent.
            if sent_before || self.another_operator_has(&hash, &known_by).await {
                return Ok(hash);
            }
            return Err(ChainError::Unconfirmed(
                "one node says it has this transaction, but no second one does yet; it is not \
                 shown as sent. Check your activity, and try again in a moment"
                    .to_owned(),
            ));
        }
        if nonce_low {
            // "Nonce too low" is the verdict of whichever endpoints answered, and endpoints
            // lag: it may be this very transaction that used the nonce. One this device had
            // accepted already did. Otherwise the network is asked, of three operators, for the
            // transaction and for its receipt, and any one that has it settles it.
            if sent_before {
                return Err(ChainError::Duplicate { hash });
            }
            let by_hash = json!([hash]);
            let (found, receipts) = futures::join!(
                self.net.rpc_many(Need::ANY.independent(), 3, "eth_getTransactionByHash", &by_hash),
                self.net.rpc_many(
                    Need::RECEIPTS.independent(),
                    3,
                    "eth_getTransactionReceipt",
                    &by_hash
                ),
            );
            let mut said_no = false;
            for answers in [found, receipts].into_iter().flatten() {
                for (answer, _) in answers {
                    match answer {
                        Ok(found) if !found.is_null() => {
                            return Err(ChainError::Duplicate { hash });
                        }
                        Ok(_) => said_no = true,
                        Err(_) => {}
                    }
                }
            }
            return Err(if said_no {
                ChainError::Nonce(
                    "that number was already used by another transaction; if you have just sent \
                     this one, check your activity before sending it again"
                        .to_owned(),
                )
            } else {
                ChainError::Unavailable
            });
        }
        Err(refusal.unwrap_or(ChainError::Unavailable))
    }

    /// Whether an operator other than those in `others` has the transaction (pending or mined).
    async fn another_operator_has(&self, hash: &str, others: &[usize]) -> bool {
        let by_hash = json!([hash]);
        let found = self
            .net
            .rpc_from(Need::ANY.independent(), others, "eth_getTransactionByHash", &by_hash)
            .await;
        matches!(found, Ok((Ok(value), _)) if !value.is_null())
    }

    /// Where a transaction stands, from its receipt, **as two operators agree**.
    ///
    /// * `pending`: not mined, or mined by one operator's word only (`unverified: true`,
    ///   with `reported` saying what the one said). A second, independent operator is asked
    ///   only when the first has a receipt, so a transaction costs one extra request, once.
    /// * `confirmed` / `failed`: two operators give a receipt with the same outcome and block.
    /// * `not_found`: no operator has the transaction (a second is asked before saying so).
    pub async fn status(&self, hash: &str) -> ChainResult<Value> {
        if !(hash.len() == 66
            && hash.starts_with("0x")
            && hash[2..].bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(ChainError::invalid("that is not a transaction hash"));
        }
        let Ok((Ok(receipt), first)) = self
            .net
            .rpc_from(Need::RECEIPTS, &[], "eth_getTransactionReceipt", &json!([hash]))
            .await
        else {
            return Err(ChainError::Unavailable);
        };
        if receipt.is_null() {
            let seen = self.read("eth_getTransactionByHash", json!([hash])).await?;
            if seen.is_null() && self.another_operator_has(hash, &[first]).await {
                return Ok(json!({ "status": "pending" }));
            }
            return Ok(json!({ "status": if seen.is_null() { "not_found" } else { "pending" } }));
        }
        let ok = receipt.get("status").and_then(Value::as_str) != Some("0x0");
        let block = receipt.get("blockNumber").and_then(Value::as_str).and_then(u64_from_hex);
        // A second operator must give the same receipt: the outcome and the block (and its hash
        // when both give one). One that cannot be asked, or says otherwise, leaves it unverified.
        let second = self
            .net
            .rpc_from(
                Need::RECEIPTS.independent(),
                &[first],
                "eth_getTransactionReceipt",
                &json!([hash]),
            )
            .await;
        let agrees = matches!(&second, Ok((Ok(other), _)) if same_receipt(&receipt, other));
        if !agrees {
            return Ok(json!({
                "status": "pending",
                "unverified": true,
                "reported": if ok { "confirmed" } else { "failed" },
            }));
        }
        let head = self.read("eth_blockNumber", json!([])).await.ok().as_ref().and_then(quantity);
        let confirmations = match (block, head) {
            (Some(block), Some(head)) => {
                u64::try_from(head).ok().map(|h| h.saturating_sub(block).saturating_add(1))
            }
            _ => None,
        };
        Ok(json!({
            "status": if ok { "confirmed" } else { "failed" },
            "block": block,
            "confirmations": confirmations,
        }))
    }
}

/// Whether two receipts say the same: the same outcome in the same block (same hash too, when both
/// name it).
fn same_receipt(a: &Value, b: &Value) -> bool {
    let field = |v: &'_ Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_lowercase);
    if b.is_null() || field(a, "blockNumber").is_none() {
        return false;
    }
    let both = |key: &str| match (field(a, key), field(b, key)) {
        (Some(x), Some(y)) => x == y,
        (None, None) => key != "blockNumber",
        _ => key == "blockHash",
    };
    both("blockNumber") && both("status") && both("blockHash")
}

fn address_bytes(text: &str) -> ChainResult<[u8; 20]> {
    nc_wallet_core::evm::parse_address_any(text).map_err(|_| ChainError::Internal)
}

/// A node's refusal of a transaction, as the code that fits it. `None` for
/// what a node says that is no verdict on the transaction itself.
fn refused(error: &NodeError) -> Option<ChainError> {
    let lower = error.lower();
    let says = |phrases: &[&str]| phrases.iter().any(|phrase| lower.contains(phrase));
    if says(&[
        "underpriced",
        "base fee",
        "fee cap",
        "gas price below",
        "max fee per gas less",
        "tip too low",
    ]) {
        Some(ChainError::InsufficientFee("the fee is below what the network takes now".to_owned()))
    } else if says(&["insufficient funds", "insufficient balance"]) {
        Some(ChainError::InsufficientFunds(
            "the account cannot cover the amount and the network fee".to_owned(),
        ))
    } else if says(&["nonce too high"]) {
        Some(ChainError::Nonce(
            "the transaction's number is ahead of the account's next one".to_owned(),
        ))
    } else if says(&[
        "invalid sender",
        "invalid chain id",
        "invalid signature",
        "invalid transaction",
        "gas limit",
        "gas too",
        "intrinsic gas",
        "oversized",
        "initcode",
        "tx fee",
        "exceeds",
        "not supported",
        "rejected",
        "max fee per gas",
    ]) {
        Some(ChainError::Rejected(REFUSED.to_owned()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(message: &str) -> NodeError {
        NodeError { code: -32000, message: message.to_owned(), data: None }
    }

    #[test]
    fn a_nodes_refusal_is_told_by_its_words() {
        assert_eq!(
            refused(&node("replacement transaction underpriced")).map(|e| e.code()),
            Some("insufficient_fee")
        );
        assert_eq!(
            refused(&node("insufficient funds for gas * price + value")).map(|e| e.code()),
            Some("insufficient_funds")
        );
        assert_eq!(refused(&node("nonce too high")).map(|e| e.code()), Some("nonce"));
        assert_eq!(refused(&node("intrinsic gas too low")).map(|e| e.code()), Some("rejected"));
        assert_eq!(refused(&node("something odd happened")), None);
    }

    #[test]
    fn a_transactions_hash_is_keccak_of_its_bytes() {
        // The hash of the empty string.
        assert_eq!(
            Evm::hash(&[]),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn each_network_has_the_least_tip_it_takes() {
        assert_eq!(min_priority_fee(Network::Polygon), 25_000_000_000);
        assert_eq!(min_priority_fee(Network::Base), 0);
    }
}
