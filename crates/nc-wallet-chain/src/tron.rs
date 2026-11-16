//! TRON, through a full node's HTTP API (`/wallet/*`) on public endpoints
//! (`PublicNode`'s, TronGrid's keyless one, Pocket's): the balance (`getaccount`,
//! a token's `balanceOf` as a constant call), the reference block and the
//! prices (`getblock` without its transactions, `getchainparameters`), the account's resources, the
//! energy a token transfer burns (a constant call of the transfer itself), and
//! `broadcasthex`.

use nc_wallet_core::tron::{
    Contract, RawDataError, ReferenceBlock, TronTransaction, format_address,
};
use serde_json::{Value, json};

use crate::address::{self, Address};
use crate::common::{EstimateArgs, balances_body, fee_value, native_entry, token_entry};
use crate::error::{ChainError, ChainResult, REFUSED};
use crate::net::Net;
use crate::networks::Network;
use crate::pool::Need;
use crate::quorum::{Ask, Figure, Kind, unconfirmed};
use crate::util::{
    bytes_from_hex, pad_address, pad_u128, parse_json, to_hex, u128_from_hex, word_to_u128,
};
use nc_wallet_core::limits;

/// A transaction expires a minute past the moment it is made.
const EXPIRES_AFTER_MS: u64 = 60_000;
/// How far apart in time two operators' latest blocks may be and still agree on the time (a node a minute or
/// two behind is ordinary; one further out is not telling the time), and how far ahead of this device's clock
/// one operator alone may put it.
const TIME_SLACK_MS: u64 = 300_000;
/// The last moment a block can be dated (the end of the year 9999): a time past it is a node making things up.
const MOST_TIME_MS: u64 = 253_402_300_799_000;
/// Bandwidth, in bytes, of a TRX transfer and of a TRC-20 transfer, as the
/// network has charged them.
const TRX_TRANSFER_BANDWIDTH: u64 = 270;
const TOKEN_TRANSFER_BANDWIDTH: u64 = 345;
/// The headroom put on a token transfer's energy for the fee limit, percent.
const FEE_LIMIT_BUFFER_PERCENT: u128 = 130;
/// What java-tron adds to a transaction's size when it counts its bandwidth (`MAX_RESULT_SIZE_IN_TX`).
const RESULT_SIZE: u64 = 64;

/// The bandwidth a transaction whose `raw_data` is `raw_len` bytes uses once signed: the signed message
/// (`raw_data` with its tag and length, and one 65-byte signature with its own) and the result's allowance.
/// For the real mainnet transactions in the core's vectors this is the figure the network charged.
fn bandwidth_of(raw_len: usize) -> u64 {
    let length = u64::try_from(raw_len).unwrap_or(u64::MAX);
    let prefix = if length < 128 {
        1
    } else if length < 16_384 {
        2
    } else {
        3
    };
    1 + prefix + length + 67 + RESULT_SIZE
}

/// TRON.
#[derive(Debug, Clone, Copy)]
pub struct Tron<'a> {
    net: &'a Net,
}

/// What the chain charges now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Prices {
    /// Sun per unit of energy.
    energy: u128,
    /// Sun per byte of bandwidth.
    bandwidth: u128,
    /// Sun to activate an account.
    activation: u128,
}

/// The latest block, as the transaction names it; its time is the one the transaction's life is counted from.
#[derive(Debug, Clone)]
struct Latest {
    number: u64,
    /// As the node wrote it.
    id: String,
    bytes: [u8; 32],
    /// The block's own time, in ms.
    block_time: u64,
}

impl Latest {
    /// A node's `getblock` (header only), if it is one: a time past the end of the year 9999 is not a block's.
    fn read(body: &[u8]) -> Option<Self> {
        let block = parse_json(body).ok()?;
        let header = block.pointer("/block_header/raw_data")?;
        let number = header.get("number")?.as_u64()?;
        let block_time = header.get("timestamp")?.as_u64().filter(|t| *t <= MOST_TIME_MS)?;
        let id = block.get("blockID")?.as_str()?;
        let bytes: [u8; 32] = hex::decode(id).ok()?.try_into().ok()?;
        Some(Self { number, id: id.to_owned(), bytes, block_time })
    }
}

/// What an account may spend without paying.
#[derive(Debug, Clone, Copy, Default)]
struct Resource {
    free_bandwidth: u64,
    staked_bandwidth: u64,
    energy: u64,
}

fn number(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn hex_of(address: &Address) -> ChainResult<String> {
    Ok(hex::encode(address.tron()?))
}

/// The reference a transaction names: the low two bytes of the block's number
/// and bytes 8 to 16 of its id.
#[must_use]
pub fn reference(number: u64, id: &[u8; 32]) -> ([u8; 2], [u8; 8]) {
    let block = ReferenceBlock::from_block(number, id);
    (block.bytes, block.hash)
}

impl<'a> Tron<'a> {
    /// TRON over `net`.
    #[must_use]
    pub const fn new(net: &'a Net) -> Self {
        Self { net }
    }

    async fn post(&self, path: &str, body: &Value) -> ChainResult<Value> {
        self.post_needing(Need::ANY, path, body).await
    }

    async fn post_needing(&self, need: Need, path: &str, body: &Value) -> ChainResult<Value> {
        let (status, text) =
            self.net.post(need, path, "application/json", body.to_string().as_bytes()).await?;
        if !(200..300).contains(&status) {
            return Err(ChainError::Unavailable);
        }
        parse_json(&text)
    }

    /// Whether the account exists (has ever been paid) and its TRX in sun.
    async fn account(&self, address: &Address) -> ChainResult<(bool, u128)> {
        let account =
            self.post("/wallet/getaccount", &json!({ "address": hex_of(address)? })).await?;
        // An address never paid answers an empty object.
        let exists = account.get("balance").is_some() || account.get("create_time").is_some();
        Ok((exists, u128::from(number(&account, "balance"))))
    }

    async fn resource(&self, address: &Address) -> ChainResult<Resource> {
        let r = self
            .post("/wallet/getaccountresource", &json!({ "address": hex_of(address)? }))
            .await?;
        Ok(Resource {
            free_bandwidth: number(&r, "freeNetLimit").saturating_sub(number(&r, "freeNetUsed")),
            staked_bandwidth: number(&r, "NetLimit").saturating_sub(number(&r, "NetUsed")),
            energy: number(&r, "EnergyLimit").saturating_sub(number(&r, "EnergyUsed")),
        })
    }

    /// The prices, read from two operators and believed where they agree, each held to the
    /// wallet's own bounds (`nc_wallet_core::limits`). Also says how many operators agree
    /// on the energy price, which the fee limit rests on.
    async fn prices(&self) -> ChainResult<(Prices, usize)> {
        fn parse(body: &[u8]) -> Option<Vec<u128>> {
            let body = parse_json(body).ok()?;
            let get = |key: &str| -> Option<u128> {
                body.get("chainParameter")?
                    .as_array()?
                    .iter()
                    .find(|p| p.get("key").and_then(Value::as_str) == Some(key))?
                    .get("value")?
                    .as_u64()
                    .map(u128::from)
            };
            Some(vec![
                get("getEnergyFee")?,
                get("getTransactionFee")?,
                get("getCreateNewAccountFeeInSystemContract").unwrap_or(1_000_000)
                    + get("getCreateAccountFee").unwrap_or(100_000),
            ])
        }
        let figures = self
            .net
            .rest_figures(
                Need::ANY,
                Ask::Post("/wallet/getchainparameters", "application/json", b"{}"),
                parse,
                &[Kind::Fee, Kind::Fee, Kind::Fee],
            )
            .await?;
        let [energy, bandwidth, activation] = figures[..] else {
            return Err(ChainError::Internal);
        };
        // What it costs to make an account is a handful of TRX: the bound is 5 TRX.
        let activation_bound = limits::Bound::alone_and_refuse(5_000_000);
        Ok((
            Prices {
                energy: energy.within(limits::TRON_ENERGY_PRICE, "energy price")?,
                bandwidth: bandwidth.within(limits::TRON_BANDWIDTH_PRICE, "bandwidth price")?,
                activation: activation.within(activation_bound, "account activation fee")?,
            },
            energy.sources,
        ))
    }

    /// A constant call of `selector` with `parameter` (hex words) on `contract`, as `owner`.
    async fn constant(
        &self,
        owner: &Address,
        contract: &str,
        selector: &str,
        parameter: &str,
    ) -> ChainResult<Value> {
        let contract = address::parse(Network::Tron, contract)?;
        self.post_needing(
            Need::TRON_CONSTANT,
            "/wallet/triggerconstantcontract",
            &json!({
                "owner_address": hex_of(owner)?,
                "contract_address": hex_of(&contract)?,
                "function_selector": selector,
                "parameter": parameter,
            }),
        )
        .await
    }

    fn reverted(answer: &Value) -> bool {
        answer.get("result").is_some_and(|r| {
            r.get("result").and_then(Value::as_bool) == Some(false) || r.get("message").is_some()
        })
    }

    async fn token_balance(&self, contract: &str, owner: &Address) -> Option<u128> {
        let bytes = owner.tron().ok()?;
        let hash: [u8; 20] = bytes[1..].try_into().ok()?;
        let parameter = hex::encode(pad_address(&hash));
        let answer = self.constant(owner, contract, "balanceOf(address)", &parameter).await.ok()?;
        if Self::reverted(&answer) {
            return None;
        }
        let word = answer.get("constant_result")?.as_array()?.first()?.as_str()?;
        word_to_u128(&hex::decode(word).ok()?)
    }

    /// The coin and every listed token of `address`, through the nodes'
    /// Ethereum-compatible JSON-RPC: a few hundred bytes, where the account
    /// record (`getaccount`) is some 18 KB even for an ordinary account, mostly
    /// its permission tables.
    pub async fn balances(&self, address: &Address, as_of: &str) -> ChainResult<Value> {
        match self.balances_by_json_rpc(address, as_of).await {
            Ok(body) => Ok(body),
            Err(_) => self.balances_by_http(address, as_of).await,
        }
    }

    async fn balances_by_json_rpc(&self, address: &Address, as_of: &str) -> ChainResult<Value> {
        let bytes = address.tron()?;
        let hash: [u8; 20] = bytes[1..].try_into().map_err(|_| ChainError::Internal)?;
        let owner = to_hex(&hash);
        let balance_params = json!([owner, "latest"]);
        let native = self.net.rpc(Need::ANY, "eth_getBalance", &balance_params);
        let tokens = Network::Tron.tokens();
        let reads = futures::future::join_all(tokens.iter().map(|token| async move {
            let contract = address::parse(Network::Tron, token.contract).ok()?.tron().ok()?;
            let call = json!([{
                "to": to_hex(&contract[1..]),
                "data": to_hex(&crate::abi::balance_of(&hash)),
            }, "latest"]);
            let answer =
                self.net.rpc(Need::method("eth_call"), "eth_call", &call).await.ok()?.ok()?;
            word_to_u128(&bytes_from_hex(answer.as_str()?)?)
        }));
        let (native, amounts) = futures::join!(native, reads);
        let native = native?.map_err(|_| ChainError::Unavailable)?;
        let native = u128_from_hex(native.as_str().ok_or(ChainError::Unavailable)?)
            .ok_or(ChainError::Unavailable)?;
        let mut entries = vec![native_entry(Network::Tron, native)];
        entries.extend(tokens.iter().zip(amounts).map(|(t, a)| token_entry(t, a)));
        Ok(balances_body(Network::Tron, &address.text, &entries, as_of))
    }

    async fn balances_by_http(&self, address: &Address, as_of: &str) -> ChainResult<Value> {
        let tokens = Network::Tron.tokens();
        let reads = futures::future::join_all(
            tokens.iter().map(|token| self.token_balance(token.contract, address)),
        );
        let (account, amounts) = futures::join!(self.account(address), reads);
        let mut entries = vec![native_entry(Network::Tron, account?.1)];
        entries.extend(tokens.iter().zip(amounts).map(|(t, a)| token_entry(t, a)));
        Ok(balances_body(Network::Tron, &address.text, &entries, as_of))
    }

    /// The latest block's header, from two operators, and the time to count a transaction's life from.
    ///
    /// The block's time rides into the transaction (its timestamp and its expiry), so a node that says it is a day
    /// ahead would make a transaction that lives a day. Two operators' times must be within [`TIME_SLACK_MS`] of
    /// each other (a third is asked where they are not), and the block named, and so the time, is the oldest of
    /// those that agree: two that are close cannot tell which of them is right, and counting from the later would
    /// let one that is five minutes ahead stretch a transaction signed to live for a minute to nearly six. (A node
    /// that is behind is covered by the device's clock, which the time is never earlier than: see [`Self::inputs`].)
    /// One operator alone is believed only if its time is not ahead of this device's clock by more than the slack.
    /// Where two agree the device's clock is not the judge: a phone days behind still builds.
    async fn latest(&self) -> ChainResult<Latest> {
        // The header only: `getnowblock` is the whole block, some 300 KB.
        const ASK: &[u8] = br#"{"detail":false}"#;
        let need = Need::ANY.independent();
        let read = |status: u16, body: &[u8]| {
            (200..300).contains(&status).then(|| Latest::read(body)).flatten()
        };
        let answers =
            self.net.post_many(need, 2, "/wallet/getblock", "application/json", ASK).await?;
        let mut heard: Vec<Latest> = Vec::new();
        let mut from: Vec<usize> = Vec::new();
        for ((status, body), at) in answers {
            if let Some(latest) = read(status, &body) {
                heard.push(latest);
                from.push(at);
            }
        }
        if heard.is_empty() {
            return Err(ChainError::Unavailable);
        }
        if heard.len() >= 2 && agreeing(&heard).len() < 2 {
            let third =
                self.net.post_from(need, &from, "/wallet/getblock", "application/json", ASK);
            if let Ok(((status, body), _)) = third.await
                && let Some(latest) = read(status, &body)
            {
                heard.push(latest);
            }
        }
        let group = agreeing(&heard);
        let believed = group.len() >= 2
            || (heard.len() == 1
                && group
                    .first()
                    .is_some_and(|l| l.block_time <= self.net.now().saturating_add(TIME_SLACK_MS)));
        group
            .iter()
            .min_by_key(|l| l.block_time)
            .filter(|_| believed)
            .map(|oldest| (*oldest).clone())
            .ok_or_else(|| unconfirmed("block time"))
    }

    /// What a send is built from.
    pub async fn inputs(&self, address: &Address) -> ChainResult<Value> {
        let (latest, prices, account, resource) = futures::join!(
            self.latest(),
            self.prices(),
            self.account(address),
            self.resource(address),
        );
        let (latest, (prices, _), (activated, _), resource) =
            (latest?, prices?, account?, resource?);
        let (bytes, hash) = reference(latest.number, &latest.bytes);
        // Not before the block it refers to: a transaction expires after the
        // later of the nodes' clock and ours.
        let now = self.net.now().max(latest.block_time);
        Ok(json!({
            "network": "tron",
            "address": address.text,
            "reference_block": {
                "number": latest.number,
                "block_id": latest.id,
                "ref_block_bytes": hex::encode(bytes),
                "ref_block_hash": hex::encode(hash),
                "timestamp_ms": latest.block_time,
            },
            "timestamp_ms": now,
            "expiration_ms": now.saturating_add(EXPIRES_AFTER_MS),
            "energy_price_sun": prices.energy.to_string(),
            "bandwidth_price_sun": prices.bandwidth.to_string(),
            "account": {
                "activated": activated,
                "free_bandwidth": resource.free_bandwidth,
                "staked_bandwidth": resource.staked_bandwidth,
                "energy": resource.energy,
            },
        }))
    }

    /// The fee of a transfer and what is known of its recipient.
    pub async fn estimate(&self, args: &EstimateArgs) -> ChainResult<Value> {
        let from = address::parse(Network::Tron, &args.from)
            .map_err(|_| ChainError::InvalidAddress("from is not a valid address".to_owned()))?;
        let to = address::parse(Network::Tron, &args.to)
            .map_err(|_| ChainError::InvalidAddress("to is not a valid address".to_owned()))?;
        let (prices, resource, recipient) =
            futures::join!(self.prices(), self.resource(&from), self.account(&to));
        let ((prices, price_sources), resource, (activated, _)) = (prices?, resource?, recipient?);

        let (energy, bandwidth, activation) = match args.token {
            Some(token) => {
                let bytes = to.tron()?;
                let hash: [u8; 20] = bytes[1..].try_into().map_err(|_| ChainError::Internal)?;
                let parameter = format!(
                    "{}{}",
                    hex::encode(pad_address(&hash)),
                    hex::encode(pad_u128(args.amount))
                );
                let answer = self
                    .constant(&from, token.contract, "transfer(address,uint256)", &parameter)
                    .await?;
                if Self::reverted(&answer) {
                    return Err(ChainError::EstimateFailed(
                        "the token transfer would fail: check the balance and the amount"
                            .to_owned(),
                    ));
                }
                (number(&answer, "energy_used"), TOKEN_TRANSFER_BANDWIDTH, 0)
            }
            None => (0, TRX_TRANSFER_BANDWIDTH, if activated { 0 } else { prices.activation }),
        };

        // What burning would cost: the energy the account's stake does not
        // cover, and the bandwidth its free allowance and stake do not.
        let energy_burned = u128::from(energy.saturating_sub(resource.energy));
        let bandwidth_available = resource.free_bandwidth.max(resource.staked_bandwidth);
        let bandwidth_burned =
            if bandwidth <= bandwidth_available { 0 } else { u128::from(bandwidth) };
        let fee = energy_burned * prices.energy + bandwidth_burned * prices.bandwidth + activation;
        // What the transaction may burn at most: the energy the node says it takes, at the price
        // the operators agree on, with headroom. Above the wallet's own bound it is refused.
        let fee_limit = Figure {
            value: u128::from(energy) * prices.energy * FEE_LIMIT_BUFFER_PERCENT / 100,
            sources: price_sources,
        }
        .within(limits::TRON_FEE_LIMIT, "fee limit")?;
        Ok(json!({
            "network": "tron",
            "energy": energy.to_string(),
            "bandwidth": bandwidth.to_string(),
            "energy_price_sun": prices.energy.to_string(),
            "bandwidth_price_sun": prices.bandwidth.to_string(),
            "fee_limit": fee_limit.to_string(),
            "fee": fee_value(Network::Tron.native(), fee),
            "activation_fee": activation.to_string(),
            "recipient": { "activated": activated },
        }))
    }

    /// The energy a call would use, as two operators say it (a constant call of the very bytes the site built, as the
    /// account), and whether it would fail. A call that would fail is refused here, with the words to say so.
    async fn energy_of(
        &self,
        owner: &[u8; 21],
        contract: &[u8; 21],
        call_value: u64,
        data: &[u8],
    ) -> ChainResult<Figure> {
        fn read(body: &[u8]) -> Option<Vec<u128>> {
            let answer = parse_json(body).ok()?;
            let failed = Tron::reverted(&answer);
            Some(vec![u128::from(number(&answer, "energy_used")), u128::from(failed)])
        }
        let body = json!({
            "owner_address": hex::encode(owner),
            "contract_address": hex::encode(contract),
            "call_value": call_value,
            "data": hex::encode(data),
        })
        .to_string();
        let figures = self
            .net
            .rest_figures(
                Need::TRON_CONSTANT,
                Ask::Post("/wallet/triggerconstantcontract", "application/json", body.as_bytes()),
                read,
                &[Kind::Fee, Kind::Exact],
            )
            .await?;
        let [energy, failed] = figures[..] else { return Err(ChainError::Internal) };
        if failed.value != 0 {
            return Err(ChainError::EstimateFailed(
                "the call would fail: the contract refuses it with the account's balance and allowances as they are"
                    .to_owned(),
            ));
        }
        Ok(energy)
    }

    /// The network fee of a transaction a *site* built, from its own bytes (`raw_data`): the energy a call would
    /// use, the bandwidth the bytes take, and what the account would burn for them given its stake. `from` must
    /// be the transaction's owner. The fee is bounded by the wallet's own ceiling for a site's call, and stands on
    /// the operators that agree on the energy and on the prices.
    pub async fn dapp_estimate(&self, from: &Address, raw: &[u8]) -> ChainResult<Value> {
        let tx = TronTransaction::from_raw_data(raw).map_err(|error| {
            ChainError::invalid(match error {
                // The same words the signing engine uses, so a person is told one thing.
                RawDataError::Unsupported(what) => format!("Nowcoin Omega does not sign {what}"),
                RawDataError::Malformed(what) => {
                    format!("the transaction is not well formed: {what}")
                }
            })
        })?;
        if format_address(tx.owner()) != from.text {
            return Err(ChainError::invalid("the transaction is not from this account"));
        }
        let (prices, resource) = futures::join!(self.prices(), self.resource(from));
        let ((prices, price_sources), resource) = (prices?, resource?);
        let (energy, activation, energy_sources) = match &tx.contract {
            Contract::Transfer { to, .. } => {
                let to = address::parse(Network::Tron, &format_address(to))?;
                let (activated, _) = self.account(&to).await?;
                (0, if activated { 0 } else { prices.activation }, usize::MAX)
            }
            Contract::TriggerSmartContract { owner, contract, call_value, data } => {
                let energy = self.energy_of(owner, contract, *call_value, data).await?;
                (u64::try_from(energy.value).unwrap_or(u64::MAX), 0, energy.sources)
            }
        };
        let bandwidth = bandwidth_of(raw.len());
        let energy_burned = u128::from(energy.saturating_sub(resource.energy));
        let bandwidth_available = resource.free_bandwidth.max(resource.staked_bandwidth);
        let bandwidth_burned =
            if bandwidth <= bandwidth_available { 0 } else { u128::from(bandwidth) };
        let energy_fee = energy_burned * prices.energy;
        let fee = Figure {
            value: energy_fee + bandwidth_burned * prices.bandwidth + activation,
            sources: price_sources.min(energy_sources),
        }
        .within(limits::TRON_DAPP_FEE_LIMIT, "network fee")?;
        Ok(json!({
            "network": "tron",
            "energy": energy.to_string(),
            "bandwidth": bandwidth.to_string(),
            "energy_price_sun": prices.energy.to_string(),
            "bandwidth_price_sun": prices.bandwidth.to_string(),
            "energy_fee": energy_fee.to_string(),
            "fee": fee_value(Network::Tron.native(), fee),
            "activation_fee": activation.to_string(),
        }))
    }

    /// Sends a signed transaction to two endpoints at once.
    pub async fn broadcast(&self, raw: &[u8], txid: &str) -> ChainResult<String> {
        let body = json!({ "transaction": hex::encode(raw) }).to_string();
        let answers = self
            .net
            .post_many(Need::ANY, 2, "/wallet/broadcasthex", "application/json", body.as_bytes())
            .await?;
        let mut accepted = false;
        let mut refusal: Option<ChainError> = None;
        for ((status, text), _) in answers {
            if !(200..300).contains(&status) {
                continue;
            }
            let Ok(answer) = parse_json(&text) else { continue };
            if answer.get("result").and_then(Value::as_bool) == Some(true) {
                accepted = true;
                continue;
            }
            let error = refused(&answer, txid);
            // A transaction one endpoint took and the other has heard of
            // already is sent.
            if matches!(error, ChainError::Duplicate { .. })
                || !matches!(refusal, Some(ChainError::Duplicate { .. }))
            {
                refusal = Some(error);
            }
        }
        if accepted || matches!(refusal, Some(ChainError::Duplicate { .. })) {
            return Ok(txid.to_owned());
        }
        Err(refusal.unwrap_or(ChainError::Unavailable))
    }

    /// Where a transaction stands.
    pub async fn status(&self, txid: &str) -> ChainResult<Value> {
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ChainError::invalid("that is not a transaction id"));
        }
        let info = self.post("/wallet/gettransactioninfobyid", &json!({ "value": txid })).await?;
        let Some(block) = info.get("blockNumber").and_then(Value::as_u64) else {
            let seen = self.post("/wallet/gettransactionbyid", &json!({ "value": txid })).await?;
            let known = seen.get("txID").is_some();
            return Ok(json!({ "status": if known { "pending" } else { "not_found" } }));
        };
        let head = self
            .post("/wallet/getblock", &json!({ "detail": false }))
            .await
            .ok()
            .and_then(|b| b.pointer("/block_header/raw_data/number")?.as_u64());
        let failed = info
            .pointer("/receipt/result")
            .and_then(Value::as_str)
            .is_some_and(|result| result != "SUCCESS");
        Ok(json!({
            "status": if failed { "failed" } else { "confirmed" },
            "block": block,
            "confirmations": head.map(|h| h.saturating_sub(block).saturating_add(1)),
        }))
    }
}

/// The largest set of blocks whose times are all within [`TIME_SLACK_MS`] of the earliest of them (the first found,
/// where several are as large).
fn agreeing(heard: &[Latest]) -> Vec<&Latest> {
    let mut best: Vec<&Latest> = Vec::new();
    for anchor in heard {
        let group: Vec<&Latest> = heard
            .iter()
            .filter(|l| {
                l.block_time >= anchor.block_time
                    && l.block_time - anchor.block_time <= TIME_SLACK_MS
            })
            .collect();
        if group.len() > best.len() {
            best = group;
        }
    }
    best
}

/// A node's refusal of a broadcast, as the code that fits it.
fn refused(answer: &Value, txid: &str) -> ChainError {
    let code = answer.get("code").and_then(Value::as_str).unwrap_or_default();
    let message = answer
        .get("message")
        .and_then(Value::as_str)
        .map(|m| {
            hex::decode(m)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| m.to_owned())
        })
        .unwrap_or_default();
    let lower = message.to_ascii_lowercase();
    match code {
        "DUP_TRANSACTION_ERROR" => ChainError::Duplicate { hash: txid.to_owned() },
        "TRANSACTION_EXPIRATION_ERROR" | "TAPOS_ERROR" => ChainError::Expired(
            "the transaction's reference block or expiry has passed; build it again from fresh inputs"
                .to_owned(),
        ),
        "BANDWITH_ERROR" | "BANDWIDTH_ERROR" => ChainError::InsufficientFunds(
            "the account cannot pay the bandwidth the transaction needs".to_owned(),
        ),
        "SERVER_BUSY" | "NO_CONNECTION" | "NOT_ENOUGH_EFFECTIVE_CONNECTION" => ChainError::Unavailable,
        _ if lower.contains("balance is not sufficient")
            || lower.contains("balance insufficient")
            || lower.contains("not enough energy") =>
        {
            ChainError::InsufficientFunds(
                "the account cannot pay the energy or balance the transaction needs".to_owned(),
            )
        }
        _ => ChainError::Rejected(REFUSED.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_is_the_low_bytes_of_the_number_and_the_middle_of_the_id() {
        // The vectors' block 87461647 (0x05368f0f) with the id the API gave.
        let id_hex = "0000000005368f0fa1555acb3c6f9bc45b368bc2b683314e933f51fa5f1bc229";
        let id: [u8; 32] = hex::decode(id_hex).unwrap().try_into().unwrap();
        let (bytes, hash) = reference(87_461_647, &id);
        assert_eq!(hex::encode(bytes), "8f0f");
        assert_eq!(hex::encode(hash), "a1555acb3c6f9bc4");
    }

    #[test]
    fn the_bandwidth_of_a_transaction_is_what_the_network_charged_for_real_ones() {
        // The sizes of the raw_data of the core's mainnet vectors (a token call, a transfer, a transfer with a
        // long memo), and what they were charged.
        assert_eq!(bandwidth_of(211), 345);
        assert_eq!(bandwidth_of(131), 265);
        assert_eq!(bandwidth_of(203), 337);
        // A longer one needs a longer length.
        assert_eq!(bandwidth_of(127), 1 + 1 + 127 + 67 + 64);
        assert_eq!(bandwidth_of(128), 1 + 2 + 128 + 67 + 64);
    }

    #[test]
    fn a_nodes_refusal_is_told_by_its_code_and_its_decoded_words() {
        let hash = "ab".repeat(32);
        let case = |code: &str, message: &str| {
            refused(&json!({ "code": code, "message": hex::encode(message) }), &hash).code()
        };
        assert_eq!(case("DUP_TRANSACTION_ERROR", "dup"), "duplicate");
        assert_eq!(case("TRANSACTION_EXPIRATION_ERROR", "expired"), "expired");
        assert_eq!(case("BANDWITH_ERROR", "no bandwidth"), "insufficient_funds");
        assert_eq!(case("SERVER_BUSY", "busy"), "upstream_unavailable");
        assert_eq!(
            case(
                "CONTRACT_VALIDATE_ERROR",
                "Validate TransferContract error, balance is not sufficient."
            ),
            "insufficient_funds"
        );
        assert_eq!(case("OTHER_ERROR", "something"), "rejected");
    }

    mod a_sites_transaction {
        use std::sync::Arc;

        use nc_wallet_core::evm::U256;
        use nc_wallet_core::tron::{TronTransaction, parse_address};

        use super::super::*;
        use crate::client::ChainClient;
        use crate::testing::{Reply, Script};

        const OWNER: &str = "TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp";
        const OTHER: &str = "TBUCzgc29vykkvFaEG2mgRtxKvaKe6skwX";
        const USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
        const NOW: i64 = 1_793_058_193_685;

        fn block() -> ReferenceBlock {
            ReferenceBlock { bytes: [0x8f, 0x0f], hash: [1, 2, 3, 4, 5, 6, 7, 8] }
        }

        fn approve() -> Vec<u8> {
            TronTransaction::trc20_approve(
                parse_address(OWNER).unwrap(),
                parse_address(USDT).unwrap(),
                &parse_address(OTHER).unwrap(),
                &U256::MAX,
                150_000_000,
                block(),
                NOW,
                NOW + 60_000,
            )
            .unwrap()
            .raw_data()
        }

        fn transfer() -> Vec<u8> {
            TronTransaction::trx_transfer(
                parse_address(OWNER).unwrap(),
                parse_address(OTHER).unwrap(),
                1_000_000,
                block(),
                NOW,
                NOW + 60_000,
            )
            .unwrap()
            .raw_data()
        }

        /// Three operators that agree on the prices and the account's resources (600 free bandwidth, no energy).
        fn script() -> Arc<Script> {
            let script = Arc::new(Script::new());
            script
                .on(
                    "/wallet/getchainparameters",
                    None,
                    vec![Reply::json(&json!({ "chainParameter": [
                        { "key": "getEnergyFee", "value": 420 },
                        { "key": "getTransactionFee", "value": 1000 },
                        { "key": "getCreateNewAccountFeeInSystemContract", "value": 1_000_000 },
                        { "key": "getCreateAccountFee", "value": 100_000 },
                    ] }))],
                )
                .on(
                    "/wallet/getaccountresource",
                    None,
                    vec![Reply::json(&json!({ "freeNetLimit": 600, "freeNetUsed": 0 }))],
                );
            script
        }

        fn constant(energy: u64, ok: bool) -> Reply {
            Reply::json(
                &json!({ "result": { "result": ok }, "energy_used": energy, "constant_result": ["00"] }),
            )
        }

        async fn ask(script: Arc<Script>, owner: &str, raw: &[u8]) -> Result<Value, ChainError> {
            let client = ChainClient::new(script);
            let request = json!({ "address": owner, "raw_data_hex": hex::encode(raw) });
            client.dispatch("tron_estimate", &request).await
        }

        #[tokio::test]
        async fn a_call_is_sized_by_two_operators_and_the_bytes_set_the_bandwidth() {
            let script = script();
            script.on("/wallet/triggerconstantcontract", None, vec![constant(64_285, true)]);
            let raw = approve();
            let answer = ask(script.clone(), OWNER, &raw).await.unwrap();
            assert_eq!(answer["energy"], "64285");
            assert_eq!(answer["bandwidth"], bandwidth_of(raw.len()).to_string());
            assert_eq!(answer["energy_price_sun"], "420");
            // No stake: the whole energy is burned, and the bandwidth is free.
            assert_eq!(answer["energy_fee"], (64_285_u128 * 420).to_string());
            assert_eq!(answer["fee"]["asset"], "TRX");
            assert_eq!(answer["fee"]["amount"], (64_285_u128 * 420).to_string());
            // What was asked of the nodes is the very data the site built, from the account.
            let seen = script.seen();
            let calls: Vec<_> = seen
                .iter()
                .filter(|s| s.url.ends_with("/wallet/triggerconstantcontract"))
                .collect();
            assert!(calls.len() >= 2, "two operators were asked");
            let body: Value = serde_json::from_str(&calls[0].body).unwrap();
            assert_eq!(body["owner_address"], hex::encode(parse_address(OWNER).unwrap()));
            assert_eq!(body["contract_address"], hex::encode(parse_address(USDT).unwrap()));
            assert!(body["data"].as_str().unwrap().starts_with("095ea7b3"));
        }

        #[tokio::test]
        async fn pockets_gateway_is_never_asked_to_size_a_sites_call() {
            // It answers every constant call "this node does not support constant" with a 200 (checked on
            // 2026-11-01). Asked, it would be read as the site's call failing, or as an energy of nothing.
            const POCKET: &str = "tron.api.pocket.network/wallet/triggerconstantcontract";
            let script = script();
            script.on(
                POCKET,
                None,
                vec![Reply::json(&json!({ "result": { "code": "CONTRACT_VALIDATE_ERROR",
                    "message": hex::encode("this node does not support constant") } }))],
            );
            script.on("/wallet/triggerconstantcontract", None, vec![constant(64_285, true)]);
            let client = ChainClient::new(script.clone());
            let request = json!({ "address": OWNER, "raw_data_hex": hex::encode(approve()) });
            for round in 0..25 {
                let answer = client.dispatch("tron_estimate", &request).await;
                assert_eq!(
                    answer.map(|a| a["energy"].clone()).ok(),
                    Some(json!("64285")),
                    "{round}"
                );
            }
            assert_eq!(script.count(POCKET), 0);
        }

        #[tokio::test]
        async fn a_transfer_to_an_account_that_does_not_exist_pays_to_make_it() {
            let script = script();
            // Never paid: the node answers an empty object.
            script.on("/wallet/getaccount", None, vec![Reply::json(&json!({}))]);
            let answer = ask(script, OWNER, &transfer()).await.unwrap();
            assert_eq!(answer["energy"], "0");
            assert_eq!(answer["activation_fee"], "1100000");
            assert_eq!(answer["fee"]["amount"], "1100000");

            let script = self::script();
            script.on("/wallet/getaccount", None, vec![Reply::json(&json!({ "balance": 5 }))]);
            let answer = ask(script, OWNER, &transfer()).await.unwrap();
            assert_eq!(answer["fee"]["amount"], "0");
        }

        #[tokio::test]
        async fn a_call_that_would_fail_is_refused_with_the_reason() {
            let script = script();
            script.on("/wallet/triggerconstantcontract", None, vec![constant(100, false)]);
            let error = ask(script, OWNER, &approve()).await.unwrap_err();
            assert_eq!(error.code(), "estimate_failed");
            assert!(error.message().contains("would fail"), "{}", error.message());
        }

        #[tokio::test]
        async fn bytes_that_are_not_the_accounts_or_not_a_transaction_are_refused_before_any_node_is_asked()
         {
            let script = script();
            let error = ask(script.clone(), OTHER, &approve()).await.unwrap_err();
            assert_eq!(error.code(), "invalid_request");
            let error = ask(script.clone(), OWNER, &approve()[..40]).await.unwrap_err();
            assert_eq!(error.code(), "invalid_request");
            assert!(script.seen().is_empty());
        }

        #[tokio::test]
        async fn an_energy_one_operator_alone_names_cannot_set_a_large_fee() {
            // One operator's reading of 600,000 energy (252 TRX) is past what a lone operator may stand for.
            let script = script();
            script.on(
                "api.trongrid.io/wallet/triggerconstantcontract",
                None,
                vec![constant(600_000, true)],
            );
            script.on("/wallet/triggerconstantcontract", None, vec![Reply::text(503, "busy")]);
            let error = ask(script, OWNER, &approve()).await.unwrap_err();
            assert!(matches!(error, ChainError::Unconfirmed(_)), "{error:?}");
        }
    }

    mod a_node_that_runs_no_constant_calls {
        use std::sync::Arc;

        use super::super::*;
        use crate::client::ChainClient;
        use crate::testing::{Reply, Script};

        const OWNER: &str = "TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp";
        const OTHER: &str = "TBUCzgc29vykkvFaEG2mgRtxKvaKe6skwX";
        const POCKET: &str = "tron.api.pocket.network/wallet/triggerconstantcontract";
        const TRONGRID: &str = "api.trongrid.io/wallet/triggerconstantcontract";

        /// What a node run without constant calls answers: a 200 (checked on Pocket's gateway on 2026-11-01).
        fn unsupported() -> Reply {
            Reply::json(&json!({ "result": { "code": "CONTRACT_VALIDATE_ERROR",
                "message": hex::encode("this node does not support constant") } }))
        }

        fn sized() -> Reply {
            Reply::json(
                &json!({ "result": { "result": true }, "energy_used": 64285, "constant_result": ["00"] }),
            )
        }

        /// The rest of what a token estimate asks, answered by every operator.
        fn world(script: &Script) {
            script
                .on(
                    "/wallet/getchainparameters",
                    None,
                    vec![Reply::json(&json!({ "chainParameter": [
                        { "key": "getEnergyFee", "value": 420 },
                        { "key": "getTransactionFee", "value": 1000 },
                        { "key": "getCreateNewAccountFeeInSystemContract", "value": 1_000_000 },
                        { "key": "getCreateAccountFee", "value": 100_000 } ] }))],
                )
                .on(
                    "/wallet/getaccountresource",
                    None,
                    vec![Reply::json(&json!({ "freeNetLimit": 600 }))],
                )
                .on(
                    "/wallet/getaccount",
                    None,
                    vec![Reply::json(&json!({ "balance": 1_000_000 }))],
                );
        }

        async fn estimate(client: &ChainClient) -> Result<Value, ChainError> {
            let ask = json!({ "network": "tron", "from": OWNER, "to": OTHER, "asset": "USDT",
                              "amount": "1000" });
            client.dispatch("estimate", &ask).await
        }

        #[tokio::test]
        async fn pockets_gateway_is_never_asked_to_size_a_token_transfer() {
            // It answers every constant call "this node does not support constant" with a 200, which was read as the
            // contract refusing ("the token transfer would fail"). Twenty-five estimates must all succeed.
            let script = Arc::new(Script::new());
            script.on(POCKET, None, vec![unsupported()]);
            script.on("/wallet/triggerconstantcontract", None, vec![sized()]);
            world(&script);
            let client = ChainClient::new(script.clone());
            for round in 0..25 {
                let estimate = estimate(&client).await;
                assert!(estimate.is_ok(), "estimate {round}: {estimate:?}");
            }
            assert_eq!(script.count(POCKET), 0);
        }

        #[tokio::test]
        async fn a_node_that_says_so_is_passed_over_and_not_asked_again_for_a_while() {
            // Not a node the wallet knows to refuse: the answer itself says it, and the next operator is asked.
            let script = Arc::new(Script::new());
            script.on(TRONGRID, None, vec![unsupported()]);
            script.on(
                "tron-rpc.publicnode.com/wallet/triggerconstantcontract",
                None,
                vec![sized()],
            );
            script.on(POCKET, None, vec![unsupported()]);
            world(&script);
            let client = ChainClient::new(script.clone());
            for round in 0..25 {
                let estimate = estimate(&client).await;
                assert!(estimate.is_ok(), "estimate {round}: {estimate:?}");
            }
            assert!(script.count(TRONGRID) <= 1, "{}", script.count(TRONGRID));
        }

        #[tokio::test]
        async fn a_contract_that_is_not_there_is_the_contracts_verdict_and_not_the_nodes() {
            // A CONTRACT_VALIDATE_ERROR that is not the node's own limit is for the caller to read, once.
            let script = Arc::new(Script::new());
            script.on(
                "/wallet/triggerconstantcontract",
                None,
                vec![Reply::json(&json!({ "result": { "code": "CONTRACT_VALIDATE_ERROR",
                    "message": hex::encode("Smart contract is not exist.") } }))],
            );
            world(&script);
            let client = ChainClient::new(script.clone());
            let error = estimate(&client).await.unwrap_err();
            assert!(error.message().contains("would fail"), "{error:?}");
            assert_eq!(script.count("/wallet/triggerconstantcontract"), 1);
        }
    }

    mod the_time_of_the_reference_block {
        use std::sync::Arc;

        use super::super::*;
        use crate::client::ChainClient;
        use crate::testing::{Reply, Script};

        const ME: &str = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9";
        const BLOCK_ID: &str = "0000000005368f0fa1555acb3c6f9bc45b368bc2b683314e933f51fa5f1bc229";
        /// The test clock's start: 2026-10-28 00:00:00 UTC.
        const NOW: u64 = 1_793_145_600_000;
        const MINUTE: u64 = 60_000;
        const DAY: u64 = 24 * 60 * MINUTE;
        const HOSTS: [&str; 3] = [
            "tron-rpc.publicnode.com/wallet/getblock",
            "api.trongrid.io/wallet/getblock",
            "tron.api.pocket.network/wallet/getblock",
        ];

        fn block(time: u64) -> Reply {
            Reply::json(&json!({
                "blockID": BLOCK_ID,
                "block_header": { "raw_data": { "number": 87_461_647_u64, "timestamp": time } }
            }))
        }

        /// What the operators say the latest block's time is (`None`: that operator does not answer).
        async fn inputs(says: [Option<u64>; 3]) -> Result<Value, ChainError> {
            let script = Arc::new(Script::new());
            for (host, time) in HOSTS.iter().zip(says) {
                match time {
                    Some(time) => script.on(host, None, vec![block(time)]),
                    None => script.on(host, None, vec![Reply::text(503, "down")]),
                };
            }
            script
                .on(
                    "/wallet/getchainparameters",
                    None,
                    vec![Reply::json(&json!({ "chainParameter": [
                        { "key": "getEnergyFee", "value": 420 },
                        { "key": "getTransactionFee", "value": 1000 },
                        { "key": "getCreateNewAccountFeeInSystemContract", "value": 1_000_000 },
                        { "key": "getCreateAccountFee", "value": 100_000 } ] }))],
                )
                .on(
                    "/wallet/getaccountresource",
                    None,
                    vec![Reply::json(&json!({ "freeNetLimit": 600 }))],
                )
                .on(
                    "/wallet/getaccount",
                    None,
                    vec![Reply::json(&json!({ "balance": 1_000_000 }))],
                );
            ChainClient::new(script)
                .dispatch("inputs", &json!({ "network": "tron", "address": ME }))
                .await
        }

        #[tokio::test]
        async fn a_block_time_of_the_largest_number_is_not_added_to_and_not_believed() {
            // One operator writes 2^64-1 (the sum with the expiry overflowed); the others are down.
            let error = inputs([Some(u64::MAX), None, None]).await.unwrap_err();
            assert_eq!(error.code(), "upstream_unavailable", "{error:?}");
            // Every operator does: no block is that old a chain's.
            assert!(inputs([Some(u64::MAX); 3]).await.is_err());
        }

        #[tokio::test]
        async fn two_operators_that_agree_set_the_time_the_transaction_expires_from() {
            let inputs = inputs([Some(NOW + 3_000), Some(NOW + 6_000), None]).await.unwrap();
            // The earlier of what they say (the device's clock is behind both), and a minute on.
            assert_eq!(inputs["timestamp_ms"], NOW + 3_000);
            assert_eq!(inputs["expiration_ms"], NOW + 3_000 + MINUTE);
            assert_eq!(inputs["reference_block"]["number"], 87_461_647_u64);
        }

        #[tokio::test]
        async fn an_operator_that_is_close_cannot_stretch_the_life_of_the_transaction() {
            // Two operators agree if their times are within five minutes, and neither can tell the other is
            // wrong. Counted from the later, "four minutes fifty-nine ahead" would make a transaction signed to
            // live for a minute live for nearly six.
            let inputs = inputs([Some(NOW), Some(NOW + 5 * MINUTE - 1_000), None]).await.unwrap();
            assert_eq!(inputs["timestamp_ms"], NOW);
            assert_eq!(inputs["expiration_ms"], NOW + MINUTE);
            // The same where a third was needed to settle two that differ, and sides with the later of the pair
            // (the pool paces the third request, so the device's clock has moved a little).
            let inputs =
                self::inputs([Some(NOW), Some(NOW + DAY), Some(NOW + 5 * MINUTE)]).await.unwrap();
            assert!(made_in_the_first_second(&inputs), "{inputs}");
            assert_eq!(life(&inputs), MINUTE);
        }

        #[tokio::test]
        async fn one_operator_a_day_ahead_is_not_believed_over_the_other() {
            // The block time rides into the transaction's expiry: a node a day ahead would make a signed
            // transaction that lives a day. Two that differ and nobody to settle it: try again.
            let error = inputs([Some(NOW), Some(NOW + DAY), None]).await.unwrap_err();
            assert!(matches!(error, ChainError::Unconfirmed(_)), "{error:?}");
            // A third that sides with the honest one outvotes it.
            let inputs = inputs([Some(NOW), Some(NOW + DAY), Some(NOW + 2_000)]).await.unwrap();
            assert!(made_in_the_first_second(&inputs), "{inputs}");
            assert_eq!(life(&inputs), MINUTE);
        }

        #[tokio::test]
        async fn a_device_clock_days_behind_still_builds_when_two_operators_agree() {
            let inputs =
                inputs([Some(NOW + 3 * DAY), Some(NOW + 3 * DAY + 3_000), None]).await.unwrap();
            assert_eq!(inputs["timestamp_ms"], NOW + 3 * DAY);
            assert_eq!(inputs["expiration_ms"], NOW + 3 * DAY + MINUTE);
        }

        #[tokio::test]
        async fn one_operator_alone_is_believed_only_near_the_devices_clock() {
            let inputs = inputs([None, Some(NOW + 3_000), None]).await.unwrap();
            assert_eq!(inputs["expiration_ms"], NOW + 3_000 + MINUTE);
            // A day ahead of the device, and nobody to say otherwise.
            let error = inputs_alone(NOW + DAY).await;
            assert!(matches!(error, ChainError::Unconfirmed(_)), "{error:?}");
        }

        async fn inputs_alone(time: u64) -> ChainError {
            inputs([None, Some(time), None]).await.unwrap_err()
        }

        /// How long the transaction in `inputs` lives, from the moment it is made.
        fn life(inputs: &Value) -> u64 {
            inputs["expiration_ms"].as_u64().unwrap() - inputs["timestamp_ms"].as_u64().unwrap()
        }

        /// Whether the transaction was made at the test clock's start, give or take the pool's pacing.
        fn made_in_the_first_second(inputs: &Value) -> bool {
            (NOW..NOW + 1_000).contains(&inputs["timestamp_ms"].as_u64().unwrap())
        }
    }

    mod prices_from_operators {
        use std::sync::Arc;

        use super::super::*;
        use crate::client::ChainClient;
        use crate::testing::{Reply, Script};

        fn parameters(energy: u64) -> Value {
            json!({ "chainParameter": [
                { "key": "getEnergyFee", "value": energy },
                { "key": "getTransactionFee", "value": 1000 },
                { "key": "getCreateNewAccountFeeInSystemContract", "value": 1_000_000 },
                { "key": "getCreateAccountFee", "value": 100_000 },
            ] })
        }

        const HOSTS: [&str; 3] = [
            "tron-rpc.publicnode.com/wallet/getchainparameters",
            "api.trongrid.io/wallet/getchainparameters",
            "tron.api.pocket.network/wallet/getchainparameters",
        ];

        async fn prices(energy: &[(usize, u64)]) -> Result<(u128, usize), ChainError> {
            let script = Arc::new(Script::new());
            for &(host, price) in energy {
                script.on(HOSTS[host], None, vec![Reply::json(&parameters(price))]);
            }
            let client = ChainClient::new(script);
            Tron::new(client.net(Network::Tron)).prices().await.map(|(p, n)| (p.energy, n))
        }

        #[tokio::test]
        async fn two_operators_that_agree_set_the_price_and_a_liar_is_outvoted() {
            assert_eq!(prices(&[(0, 420), (1, 420)]).await.unwrap(), (420, 2));
            assert_eq!(prices(&[(0, 420), (1, 100_000), (2, 440)]).await.unwrap().0, 440);
        }

        #[tokio::test]
        async fn a_price_past_the_ceiling_is_refused_and_one_alone_is_bounded() {
            // Two agree on 5,000 sun an energy: past the 2,000 ceiling, refused.
            assert!(matches!(
                prices(&[(0, 5_000), (1, 5_000)]).await,
                Err(ChainError::OverCeiling(_))
            ));
            // One alone at 600: past the 500 a lone operator may quote.
            assert!(matches!(prices(&[(1, 600)]).await, Err(ChainError::Unconfirmed(_))));
            assert_eq!(prices(&[(1, 420)]).await.unwrap(), (420, 1));
        }
    }
}
