//! The wallet's own transfers (`kind: "send"`): a transaction built from the
//! wallet API's `inputs` and `estimate` bodies for any of the nine networks.
//!
//! The wallet API never builds a transaction; this code does, with the core's
//! encoders, so the bytes are the wallet's. What the approval screen shows is
//! read back from what was built (EVM: `describe()` of the transaction; TRON:
//! the same of its `raw_data`; Solana: `summarize_transaction` of the built
//! bytes; Bitcoin: the plan; Stellar and Bittensor: the operation), never from
//! the request's own words.

use nc_wallet_core::Network;
use nc_wallet_core::bitcoin::{self, Amount, Chain, FeeRate, Plan, Utxo};
use nc_wallet_core::bittensor::{self, CallIndex, Transfer, TransferError};
use nc_wallet_core::evm::{self, EvmChain, EvmTransaction, Fees, U256, abi};
use nc_wallet_core::limits;
use nc_wallet_core::solana::{self, InstructionSummary, Priority, SolTransfer, SplTransfer};
use nc_wallet_core::stellar::{
    self, Asset, Memo, Operation, PUBLIC_NETWORK_PASSPHRASE, StellarError, TimeBounds, XdrError,
};
use nc_wallet_core::tron::{self, ReferenceBlock, TronTransaction};
use serde_json::{Value, json};

use super::json::{self, Obj, bad};
use super::warning::{self, Code};
use super::{
    Action, Prepared, Secrets, SigningError, Summary, derive_key, fee_json, hexs, send_output,
    signer_address, signer_public_key,
};
use crate::types::NetworkId;

/// A fee above what this wallet will ever pay (`nc_wallet_core::limits`), whoever quoted it.
fn too_high(what: &'static str) -> SigningError {
    SigningError::new("FeeTooHigh", what)
}

/// The price per unit of work a transaction offers, against the wallet's own ceilings: for any
/// EVM transaction, a site's included. (A site's transaction may use more work than a plain
/// send, so the amount of work and the total are checked for the wallet's own sends only.)
pub(super) fn check_evm_rates(chain: EvmChain, tx: &EvmTransaction) -> Result<(), SigningError> {
    let (max_fee, tip) = match tx.fees {
        Fees::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas } => {
            (max_fee_per_gas, max_priority_fee_per_gas)
        }
        Fees::Legacy { gas_price } => (gas_price, 0),
    };
    if !limits::evm_max_fee_per_gas(chain).allows(max_fee)
        || !limits::evm_priority_fee(chain).allows(tip)
    {
        return Err(too_high("the network fee rate is above the most this wallet will pay"));
    }
    Ok(())
}

/// The network fee of an EVM send, against the wallet's own ceilings.
fn check_evm_fee(chain: EvmChain, tx: &EvmTransaction) -> Result<(), SigningError> {
    if tx.gas_limit > limits::EVM_GAS_LIMIT {
        return Err(too_high(
            "the amount of work reserved for this send is above the most allowed",
        ));
    }
    check_evm_rates(chain, tx)?;
    let max_fee = match tx.fees {
        Fees::Eip1559 { max_fee_per_gas, .. } => max_fee_per_gas,
        Fees::Legacy { gas_price } => gas_price,
    };
    let reserved = u128::from(tx.gas_limit).saturating_mul(max_fee);
    if !limits::evm_total_fee(chain).allows(reserved) {
        return Err(too_high(
            "the network fee for this send is above the most this wallet will pay",
        ));
    }
    Ok(())
}

const SEND_FIELDS: &[&str] =
    &["kind", "network", "asset", "to", "amount", "send_max", "inputs", "estimate", "options"];

/// A `send` request, read and checked as far as every network agrees.
struct SendRequest<'a> {
    network: NetworkId,
    asset: &'a Obj,
    symbol: &'a str,
    token: bool,
    decimals: u8,
    to: &'a str,
    amount: u128,
    send_max: bool,
    inputs: &'a Obj,
    estimate: &'a Obj,
    options: Option<&'a Obj>,
}

impl SendRequest<'_> {
    fn amount_u64(&self) -> Result<u64, SigningError> {
        u64::try_from(self.amount).map_err(|_| bad("amount is more than this network holds"))
    }

    fn amount_i64(&self) -> Result<i64, SigningError> {
        i64::try_from(self.amount).map_err(|_| bad("amount is more than this network holds"))
    }

    /// The fee the estimate quotes, in the network's native coin.
    fn estimate_fee(&self) -> Result<Value, SigningError> {
        let fee = json::object(self.estimate, "fee")?;
        Ok(fee_json(self.network, json::api_u128(fee, "amount")?))
    }

    /// `inputs.address`, when the API echoes it, must be the signer's.
    fn check_inputs_address(&self, signer: &str) -> Result<(), SigningError> {
        let Some(echoed) = json::opt_string(self.inputs, "address")? else { return Ok(()) };
        let same = match self.network {
            NetworkId::Ethereum | NetworkId::BnbChain | NetworkId::Polygon | NetworkId::Base => {
                evm::parse_address_any(echoed).ok() == evm::parse_address_any(signer).ok()
            }
            _ => echoed == signer,
        };
        if same {
            Ok(())
        } else {
            Err(SigningError::new(
                "NotASigner",
                "inputs are for another address than the account's",
            ))
        }
    }

    fn speed(&self) -> Result<&str, SigningError> {
        let chosen = match self.options {
            Some(options) => json::opt_string(options, "fee_speed")?,
            None => None,
        };
        match chosen {
            None => Ok("normal"),
            Some(speed @ ("slow" | "normal" | "fast")) => Ok(speed),
            Some(_) => Err(bad("fee_speed is not slow, normal or fast")),
        }
    }

    fn memo(&self) -> Result<Option<&str>, SigningError> {
        match self.options {
            Some(options) => json::opt_string(options, "memo"),
            None => Ok(None),
        }
    }

    fn prepared(
        &self,
        signer: String,
        summary: Summary,
        payload: Vec<u8>,
        action: Action,
    ) -> Prepared {
        Prepared {
            kind: "send",
            network: self.network.api_id().to_owned(),
            signer,
            summary: summary.into_value(),
            payload,
            action,
            send: true,
            fee_high: false,
            fee_ok: false,
            chain_mismatch_ok: false,
        }
    }

    fn summary(
        &self,
        signer: &str,
        action: &'static str,
        details: Value,
        fee: Value,
        warnings: Vec<Code>,
    ) -> Summary {
        Summary {
            request: "send",
            network: self.network.api_id().to_owned(),
            signer: signer.to_owned(),
            action,
            details,
            tx: None,
            fee: Some(fee),
            warnings,
        }
    }
}

fn parse(map: &Obj) -> Result<SendRequest<'_>, SigningError> {
    json::only(map, SEND_FIELDS, "the request")?;
    let network = NetworkId::from_api_id(json::string(map, "network")?)
        .ok_or_else(|| bad("network is not one this wallet serves"))?;
    let asset = json::object(map, "asset")?;
    let symbol = json::string(asset, "symbol")?;
    let decimals = u8::try_from(json::api_u128(asset, "decimals")?)
        .ok()
        .filter(|d| *d <= 36)
        .ok_or_else(|| bad("asset.decimals is out of range"))?;
    let has_kind = asset.get("kind").is_some_and(|v| !v.is_null());
    let has_contract = asset.get("contract").is_some_and(|v| !v.is_null());
    if has_kind != has_contract {
        return Err(bad("asset names a token by both kind and contract, or neither"));
    }
    let token = has_kind;
    if token {
        let wanted = match network {
            NetworkId::Ethereum | NetworkId::BnbChain | NetworkId::Polygon | NetworkId::Base => {
                "erc20"
            }
            NetworkId::Tron => "trc20",
            NetworkId::Solana => "spl",
            NetworkId::Stellar => "stellar_asset",
            NetworkId::Bitcoin | NetworkId::Bittensor => {
                return Err(bad("this network has no tokens"));
            }
        };
        if json::string(asset, "kind")? != wanted {
            return Err(bad("asset.kind is not this network's token kind"));
        }
        json::string(asset, "contract")?;
    } else if (symbol, decimals) != super::native(network) {
        return Err(bad("asset is not this network's coin"));
    }
    let send_max = json::flag(map, "send_max")?;
    if send_max && network != NetworkId::Bitcoin {
        return Err(bad(
            "send_max is for Bitcoin only: work the maximum out and send it as amount",
        ));
    }
    let amount = if send_max && !map.contains_key("amount") {
        0
    } else {
        json::decimal_u128(map, "amount")?
    };
    if amount == 0 && !send_max {
        return Err(bad("amount must be more than zero"));
    }
    let options = json::opt_object(map, "options")?;
    if let Some(options) = options {
        json::only(options, &["fee_speed", "memo"], "options")?;
    }
    let inputs = json::object(map, "inputs")?;
    let estimate = json::object(map, "estimate")?;
    for body in [inputs, estimate] {
        if let Some(echoed) = json::opt_string(body, "network")?
            && echoed != network.api_id()
        {
            return Err(bad("inputs or estimate are for another network"));
        }
    }
    Ok(SendRequest {
        network,
        asset,
        symbol,
        token,
        decimals,
        to: json::string(map, "to")?,
        amount,
        send_max,
        inputs,
        estimate,
        options,
    })
}

pub(super) fn prepare(secrets: &Secrets, index: u32, map: &Obj) -> Result<Prepared, SigningError> {
    let send = parse(map)?;
    match send.network {
        NetworkId::Ethereum | NetworkId::BnbChain | NetworkId::Polygon | NetworkId::Base => {
            evm_send(secrets, index, &send)
        }
        NetworkId::Tron => tron_send(secrets, index, &send),
        NetworkId::Bitcoin => bitcoin_send(secrets, index, &send),
        NetworkId::Solana => solana_send(secrets, index, &send),
        NetworkId::Stellar => stellar_send(secrets, index, &send),
        NetworkId::Bittensor => bittensor_send(secrets, index, &send),
    }
}

// ---- EVM ----

fn evm_send(
    secrets: &Secrets,
    index: u32,
    send: &SendRequest<'_>,
) -> Result<Prepared, SigningError> {
    let chain = match send.network {
        NetworkId::Ethereum => EvmChain::Ethereum,
        NetworkId::BnbChain => EvmChain::BnbChain,
        NetworkId::Polygon => EvmChain::Polygon,
        _ => EvmChain::Base,
    };
    let signer = signer_address(secrets, Network::Evm, index)?;
    send.check_inputs_address(&signer)?;
    if json::api_u64(send.inputs, "chain_id")? != chain.chain_id() {
        return Err(bad("inputs are for another chain"));
    }
    let eip1559 = match send.estimate.get("eip1559") {
        Some(Value::Bool(flag)) => *flag,
        _ => return Err(bad("eip1559 is missing from the estimate")),
    };
    // The bid of the speed the person chose. An estimate that offers speeds (`fees`: the app asked the chain
    // client for them, and it offers the ones it can vouch for) is priced at the tier of that name, and a
    // tier it left out is not guessed at. An estimate without `fees` has the one price and `fee_speed`
    // changes nothing, as it never did here: an app's form may still hold the speed it was given for
    // Bitcoin. Whichever bid is used is held to the wallet's own ceilings below.
    let priced = match send.estimate.get("fees").filter(|fees| !fees.is_null()) {
        None => send.estimate,
        Some(_) => match send.speed()? {
            "normal" => send.estimate,
            speed => json::object(json::object(send.estimate, "fees")?, speed)?,
        },
    };
    let fees = if eip1559 {
        Fees::Eip1559 {
            max_fee_per_gas: json::api_u128(priced, "max_fee_per_gas")?,
            max_priority_fee_per_gas: json::api_u128(priced, "max_priority_fee_per_gas")?,
        }
    } else {
        Fees::Legacy { gas_price: json::api_u128(priced, "gas_price")? }
    };
    let recipient = evm::parse_address(send.to).map_err(|error| match error {
        evm::AddressError::Checksum => bad("to fails its address checksum"),
        evm::AddressError::Zero => bad("to is the all-zero address"),
        evm::AddressError::Format => bad("to is not an address"),
    })?;
    let (to, value, data) = if send.token {
        let contract = evm::parse_address_any(json::string(send.asset, "contract")?)
            .map_err(|_| bad("asset.contract is not an address"))?;
        (contract, 0, abi::erc20_transfer(&recipient, &U256::from_u128(send.amount)))
    } else {
        (recipient, send.amount, Vec::new())
    };
    let tx = EvmTransaction {
        chain_id: chain.chain_id(),
        nonce: json::api_u64(send.inputs, "nonce")?,
        to,
        value,
        data,
        gas_limit: json::api_u64(send.estimate, "gas_limit")?,
        fees,
    };
    tx.validate()?;
    check_evm_fee(chain, &tx)?;
    let summary = super::evm::transaction_summary("send", send.network, &signer, &tx)?;
    Ok(super::evm::prepared_transaction("send", send.network, signer, summary, tx, true))
}

// ---- TRON ----

fn tron_send(
    secrets: &Secrets,
    index: u32,
    send: &SendRequest<'_>,
) -> Result<Prepared, SigningError> {
    let signer = signer_address(secrets, Network::Tron, index)?;
    send.check_inputs_address(&signer)?;
    let owner = tron::parse_address(&signer)?;
    let to = tron::parse_address(send.to)?;

    let block = json::object(send.inputs, "reference_block")?;
    let block_id: [u8; 32] = hexs::decode_array(json::string(block, "block_id")?)
        .ok_or_else(|| bad("block_id is not 32 bytes of hex"))?;
    let reference = ReferenceBlock::from_block(json::api_u64(block, "number")?, &block_id);
    let bytes: [u8; 2] = hexs::decode_array(json::string(block, "ref_block_bytes")?)
        .ok_or_else(|| bad("ref_block_bytes is not 2 bytes of hex"))?;
    let hash: [u8; 8] = hexs::decode_array(json::string(block, "ref_block_hash")?)
        .ok_or_else(|| bad("ref_block_hash is not 8 bytes of hex"))?;
    if reference.bytes != bytes || reference.hash != hash {
        return Err(bad("the reference block's fields do not belong to its block"));
    }
    let timestamp = i64::try_from(json::api_u64(send.inputs, "timestamp_ms")?)
        .map_err(|_| bad("timestamp_ms is out of range"))?;
    let expiration = i64::try_from(json::api_u64(send.inputs, "expiration_ms")?)
        .map_err(|_| bad("expiration_ms is out of range"))?;

    let tx = if send.token {
        let token = tron::parse_address(json::string(send.asset, "contract")?)?;
        let fee_limit = json::api_u64(send.estimate, "fee_limit")?;
        if !limits::TRON_FEE_LIMIT.allows(u128::from(fee_limit)) {
            return Err(too_high("the fee limit is above the most this wallet will pay"));
        }
        TronTransaction::trc20_transfer(
            owner,
            token,
            &to,
            &U256::from_u128(send.amount),
            fee_limit,
            reference,
            timestamp,
            expiration,
        )?
    } else {
        TronTransaction::trx_transfer(
            owner,
            to,
            send.amount_u64()?,
            reference,
            timestamp,
            expiration,
        )?
    };
    let activation_fee =
        json::opt_api_u128(send.estimate, "activation_fee")?.unwrap_or(0).to_string();
    let (action, details) = match tx.describe() {
        tron::Call::TrxTransfer { to, amount } => (
            "trx_transfer",
            json!({
                "recipient": tron::format_address(&to),
                "amount": amount.to_string(),
                "activation_fee": activation_fee,
            }),
        ),
        tron::Call::Trc20Transfer { token, to, amount } => (
            "trc20_transfer",
            json!({
                "token": tron::format_address(&token),
                "recipient": tron::format_address(&to),
                "amount": amount.to_string(),
                "fee_limit": tx.fee_limit.unwrap_or(0).to_string(),
                "activation_fee": activation_fee,
            }),
        ),
        _ => return Err(SigningError::new("Unavailable", "the transfer could not be read back")),
    };
    let summary = send.summary(&signer, action, details, send.estimate_fee()?, Vec::new());
    let payload = tx.raw_data();
    Ok(send.prepared(signer, summary, payload, Action::Tron(tx)))
}

pub(super) fn sign_tron(
    secrets: &Secrets,
    index: u32,
    prepared: &Prepared,
    tx: &TronTransaction,
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Tron, index)?;
    let signed = tx.sign(&key)?;
    Ok(send_output(&prepared.network, &signed.transaction_hex(), "hex", &signed.txid_hex()))
}

// ---- Bitcoin ----

/// The most change addresses ahead of the first that a request may name: the wallet moves to a
/// new change address with each payment, and nobody has paid from thousands.
const MAX_CHANGE_INDEX: u32 = 10_000;
/// The highest address index of either chain a request's output may name.
const MAX_ADDRESS_INDEX: u32 = 1_000_000;

/// Where one of the account's addresses is, from a request: a chain (0 receive, 1 change) and an index.
fn bitcoin_place(entry: &Obj) -> Result<(Chain, u32), SigningError> {
    let chain = match json::api_u32(entry, "chain")? {
        0 => Chain::Receive,
        1 => Chain::Change,
        _ => return Err(bad("chain is not 0 (receive) or 1 (change)")),
    };
    let index = json::api_u32(entry, "index")?;
    if index > MAX_ADDRESS_INDEX {
        return Err(bad("an address index is beyond what the wallet looks for"));
    }
    Ok((chain, index))
}

fn bitcoin_send(
    secrets: &Secrets,
    index: u32,
    send: &SendRequest<'_>,
) -> Result<Prepared, SigningError> {
    // The wallet's account number is the BIP-84 account: the request names, for each output
    // and for the change, which of its addresses they are, and the keys are derived here; the
    // addresses the request writes are only checked against them.
    let account = index;
    let seed = secrets.seed()?;
    let receive = bitcoin::account(&seed, account, Chain::Receive, 0)?;
    send.check_inputs_address(&receive.address)?;

    // The change goes to the next address of the change chain nothing has used yet.
    let change_at = json::object(send.inputs, "change")?;
    let (change_chain, change_index) = bitcoin_place(change_at)?;
    if change_chain != Chain::Change || change_index > MAX_CHANGE_INDEX {
        return Err(bad("change is not an address of the change chain"));
    }
    let change = bitcoin::account(&seed, account, Chain::Change, change_index)?;
    if let Some(named) = json::opt_string(change_at, "address")?
        && named != change.address
    {
        return Err(bad("the change address is not the one at that place in this account"));
    }

    let speed = send.speed()?;
    let rates = json::object(send.inputs, "fee_rates")?;
    let rate = json::api_u64(json::object(rates, speed)?, "sat_per_kvb")?;
    if !limits::BITCOIN_RATE_KVB.allows(u128::from(rate)) {
        return Err(too_high("the fee rate is above the most this wallet will pay"));
    }

    let mut utxos = Vec::new();
    for entry in json::array(send.inputs, "utxos")? {
        let entry = json::as_object(entry, "an output")?;
        let address = json::string(entry, "address")?;
        let (chain, at) = bitcoin_place(entry)?;
        let confirmed = matches!(entry.get("confirmed"), Some(Value::Bool(true)));
        // Unconfirmed money is spent only if it is this wallet's own change that this device sent
        // (`own`): money from outside, or change of a transaction this device did not make, can be
        // replaced before it is mined, and the payment would then fail.
        let own = matches!(entry.get("own"), Some(Value::Bool(true)));
        if !confirmed && (chain == Chain::Receive || !own) {
            continue;
        }
        utxos.push(Utxo::new(
            json::string(entry, "txid")?,
            json::api_u32(entry, "vout")?,
            json::api_u64(entry, "value")?,
            address,
            chain,
            at,
        )?);
    }
    if utxos.is_empty() {
        return Err(SigningError::new("InsufficientFunds", "there is nothing confirmed to spend"));
    }
    let amount = if send.send_max { Amount::All } else { Amount::Exact(send.amount_u64()?) };
    let plan = bitcoin::plan(&bitcoin::Request {
        to: send.to,
        amount,
        utxos: &utxos,
        change_address: &change.address,
        fee_rate: FeeRate::from_sat_per_kvb(rate),
    })?;

    // Each output spent is at the place the request says: the key there owns its address.
    for input in &plan.inputs {
        let key = bitcoin::signing_key(&seed, account, input.chain(), input.index())?;
        if !input.is_paid_to(key.public_key()) {
            return Err(SigningError::new(
                "NotASigner",
                "an output is not paid to the address at its place in this account",
            ));
        }
    }
    if u128::from(plan.fee) > limits::BITCOIN_TOTAL_FEE {
        return Err(too_high("the fee is above the most this wallet will pay"));
    }
    let paid = plan.transaction.outputs.first().map_or(0, |o| o.value);
    let change_json = plan.change.and_then(|i| plan.transaction.outputs.get(i)).map_or(
        Value::Null,
        |output| json!({ "address": change.address, "amount": output.value.to_string() }),
    );
    let mut warnings = Vec::new();
    if u128::from(plan.fee) * 5 > u128::from(paid) {
        warnings.push(warning::HIGH_FEE);
    }
    let details = json!({
        "recipient": send.to,
        "amount": paid.to_string(),
        "change": change_json,
        "inputs": plan.inputs.len(),
        "vsize": plan.estimated_vsize(),
        "rate_sat_per_kvb": rate,
    });
    let summary = send.summary(
        &receive.address,
        "bitcoin_payment",
        details,
        fee_json(NetworkId::Bitcoin, u128::from(plan.fee)),
        warnings,
    );

    // The transaction and, for each input, what BIP-143 commits to besides it.
    let mut payload = plan.transaction.encode_without_witness();
    for input in &plan.inputs {
        payload.extend_from_slice(&input.value().to_le_bytes());
        payload.push(u8::from(input.chain() == Chain::Change));
        payload.extend_from_slice(&input.index().to_le_bytes());
    }
    Ok(send.prepared(receive.address, summary, payload, Action::Bitcoin(plan)))
}

pub(super) fn sign_bitcoin(
    secrets: &Secrets,
    index: u32,
    prepared: &Prepared,
    plan: &Plan,
) -> Result<Value, SigningError> {
    let seed = secrets.seed()?;
    let signed = plan.sign(&seed, index)?;
    Ok(send_output(&prepared.network, &signed.raw_hex(), "hex", &signed.txid_hex()))
}

// ---- Solana ----

fn solana_send(
    secrets: &Secrets,
    index: u32,
    send: &SendRequest<'_>,
) -> Result<Prepared, SigningError> {
    let signer = signer_address(secrets, Network::Solana, index)?;
    send.check_inputs_address(&signer)?;
    let key_of = |text: &str, field: &str| {
        solana::parse_address(text).ok_or_else(|| bad(format!("{field} is not a Solana address")))
    };
    let owner = key_of(&signer, "the signer")?;
    let to = key_of(send.to, "to")?;
    let recent_blockhash = key_of(json::string(send.inputs, "blockhash")?, "blockhash")?;
    let priority = Some(Priority {
        compute_unit_limit: json::api_u32(send.estimate, "compute_unit_limit")?,
        compute_unit_price_micro_lamports: json::api_u64(
            send.estimate,
            "compute_unit_price_micro_lamports",
        )?,
    });
    if let Some(priority) = &priority {
        // The base fee of one signature, and the compute units at their price, rounded up.
        let total = 5_000_u128.saturating_add(
            (u128::from(priority.compute_unit_limit)
                * u128::from(priority.compute_unit_price_micro_lamports))
            .div_ceil(1_000_000),
        );
        if !limits::SOLANA_TOTAL_FEE.allows(total) {
            return Err(too_high("the fee is above the most this wallet will pay"));
        }
    }
    let recipient = json::object(send.estimate, "recipient")?;

    let bytes = if send.token {
        if matches!(recipient.get("is_token_account"), Some(Value::Bool(true))) {
            return Err(SigningError::new(
                "RecipientIsTokenAccount",
                "to is a token account: ask for the wallet address instead",
            ));
        }
        let mint = key_of(json::string(send.asset, "contract")?, "asset.contract")?;
        let amount = send.amount_u64()?;
        let associated = solana::message::associated_token_account(&owner, &mint)
            .ok_or_else(|| bad("no token account address could be derived"))?;
        let source = token_source(send, &mint, &associated, u128::from(amount))?;
        let exists = matches!(recipient.get("token_account_exists"), Some(Value::Bool(true)));
        solana::build_spl_transfer(&SplTransfer {
            owner,
            mint,
            decimals: send.decimals,
            amount,
            recipient: to,
            source,
            recipient_token_account_exists: exists,
            recent_blockhash,
            priority,
        })
        .map_err(|e| super::solana::solana_error(&e))?
    } else {
        solana::build_sol_transfer(&SolTransfer {
            from: owner,
            to,
            lamports: send.amount_u64()?,
            recent_blockhash,
            priority,
        })
        .map_err(|e| super::solana::solana_error(&e))?
    };

    // What is shown is read back from what was built.
    let read = super::solana::summarize(&bytes, &[], &owner)?;
    let created = read
        .instructions
        .iter()
        .any(|i| matches!(i, InstructionSummary::CreateAssociatedTokenAccount { .. }));
    let unread = || SigningError::new("Unavailable", "the transfer could not be read back");
    let (action, details) = if send.token {
        let mint = key_of(json::string(send.asset, "contract")?, "asset.contract")?;
        let destination = solana::message::associated_token_account(&to, &mint)
            .ok_or_else(|| bad("no token account address could be derived"))?;
        let moved =
            read.instructions.iter().find_map(|i| match i {
                InstructionSummary::SplTransfer {
                    destination: d, amount, mint: Some(m), ..
                } if *d == destination && *m == mint => Some(*amount),
                _ => None,
            });
        let amount = moved.ok_or_else(unread)?;
        let creation = if created {
            json::opt_api_u128(send.estimate, "account_creation")?.unwrap_or(0)
        } else {
            0
        };
        (
            "spl_transfer",
            json!({
                "token": solana::address(&mint),
                "recipient": send.to,
                "amount": amount.to_string(),
                "creates_token_account": created,
                "account_creation": creation.to_string(),
            }),
        )
    } else {
        let moved = read.instructions.iter().find_map(|i| match i {
            InstructionSummary::SystemTransfer { to: t, lamports, .. } if *t == to => {
                Some(*lamports)
            }
            _ => None,
        });
        let lamports = moved.ok_or_else(unread)?;
        ("sol_transfer", json!({ "recipient": send.to, "amount": lamports.to_string() }))
    };
    // Lamports sent to an account a program owns (a mint, a token account, a program, a sysvar) can
    // never be taken out again: the person is told, whatever else is shown.
    let mut warnings = Vec::new();
    if !send.token && matches!(recipient.get("program_owned"), Some(Value::Bool(true))) {
        warnings.push(warning::RECIPIENT_IS_PROGRAM_ACCOUNT);
    }
    let summary = send.summary(&signer, action, details, send.estimate_fee()?, warnings);
    Ok(send.prepared(signer, summary, bytes.clone(), Action::SolanaTransaction(bytes)))
}

/// The token account the tokens leave: the associated one if it holds enough,
/// otherwise the fullest other account of the owner for that mint that does
/// (`None` stands for the associated account, which the builder derives).
fn token_source(
    send: &SendRequest<'_>,
    mint: &solana::Pubkey,
    associated: &solana::Pubkey,
    amount: u128,
) -> Result<Option<solana::Pubkey>, SigningError> {
    let mut best: Option<(u128, solana::Pubkey)> = None;
    for entry in json::array(send.inputs, "token_accounts")? {
        let entry = json::as_object(entry, "a token account")?;
        if solana::parse_address(json::string(entry, "mint")?).as_ref() != Some(mint) {
            continue;
        }
        let address = solana::parse_address(json::string(entry, "address")?)
            .ok_or_else(|| bad("a token account's address is not an address"))?;
        if let Some(decimals) = json::opt_api_u128(entry, "decimals")?
            && decimals != u128::from(send.decimals)
        {
            return Err(bad("a token account's decimals are not the token's"));
        }
        let held = json::api_u128(entry, "amount")?;
        if held < amount {
            continue;
        }
        if address == *associated {
            return Ok(None);
        }
        if best.as_ref().is_none_or(|(most, _)| held > *most) {
            best = Some((held, address));
        }
    }
    best.map(|(_, address)| Some(address))
        .ok_or_else(|| SigningError::new("InsufficientFunds", "no token account holds that much"))
}

// ---- Stellar ----

pub(super) fn xdr_error(error: &XdrError) -> SigningError {
    match error {
        XdrError::AssetCode(_) => bad("the asset code is not valid"),
        other => bad(other.to_string()),
    }
}

fn stellar_send(
    secrets: &Secrets,
    index: u32,
    send: &SendRequest<'_>,
) -> Result<Prepared, SigningError> {
    let signer = signer_address(secrets, Network::Stellar, index)?;
    send.check_inputs_address(&signer)?;
    let source: [u8; 32] = signer_public_key(secrets, Network::Stellar, index)?
        .try_into()
        .map_err(|_| SigningError::new("Unavailable", "the account's key could not be made"))?;
    if matches!(send.inputs.get("account_exists"), Some(Value::Bool(false))) {
        return Err(bad("this account does not exist on the network yet"));
    }
    // `G…`, or a muxed `M…` (SEP-23): an account and the id its owner gave this address.
    let destination =
        stellar::parse_destination(send.to).ok_or_else(|| bad("to is not a Stellar address"))?;
    let recipient = json::object(send.estimate, "recipient")?;
    let memo_text = send.memo()?.filter(|m| !m.is_empty());
    if destination.id.is_some() {
        // The id is the address's own and the payment is made to it: a memo beside it would be a
        // second id for one payment, and the person is not asked to choose between them.
        if memo_text.is_some() {
            return Err(bad("to is a muxed address that carries its own id: leave the memo empty"));
        }
    } else if matches!(recipient.get("memo_required"), Some(Value::Bool(true)))
        && memo_text.is_none()
    {
        return Err(SigningError::new("MemoRequired", "the recipient asks for a memo"));
    }
    let memo = match memo_text {
        Some(text) => Memo::parse(text).map_err(|e| xdr_error(&e))?,
        None => Memo::None,
    };
    let amount = send.amount_i64()?;

    let (action, operation, details) = if send.token {
        match recipient.get("trustline") {
            Some(Value::Bool(true)) => {}
            Some(Value::Bool(false)) => {
                return Err(SigningError::new(
                    "NoTrustline",
                    "the recipient cannot hold this asset yet",
                ));
            }
            _ => {
                return Err(bad("the estimate does not say whether the recipient has a trustline"));
            }
        }
        let code = json::opt_string(send.asset, "code")?.unwrap_or(send.symbol);
        let issuer = match json::opt_string(send.asset, "issuer")? {
            Some(issuer) => issuer,
            None => json::string(send.asset, "contract")?,
        };
        let asset = Asset::credit(code, issuer).map_err(|e| xdr_error(&e))?;
        (
            "stellar_payment",
            Operation::Payment {
                destination: destination.key,
                destination_id: destination.id,
                asset,
                amount,
            },
            json!({
                "recipient": send.to,
                "asset": send.symbol,
                "amount": send.amount.to_string(),
                "memo": memo_text,
            }),
        )
    } else if matches!(recipient.get("exists"), Some(Value::Bool(false))) {
        // An account is made by a payment of XLM to its plain address, which cannot carry an id: the
        // id of a muxed address would be lost, so the person is asked for the plain one.
        if destination.id.is_some() {
            return Err(bad(
                "the account behind this muxed address does not exist yet: it is created by a payment to its G address",
            ));
        }
        let minimum = json::api_u128(recipient, "minimum_new_account")?;
        if send.amount < minimum {
            return Err(SigningError::new(
                "Dust",
                "the first payment to a new account must be larger",
            ));
        }
        (
            "stellar_create_account",
            Operation::CreateAccount { destination: destination.key, starting_balance: amount },
            json!({
                "recipient": send.to,
                "starting_balance": send.amount.to_string(),
                "memo": memo_text,
            }),
        )
    } else {
        (
            "stellar_payment",
            Operation::Payment {
                destination: destination.key,
                destination_id: destination.id,
                asset: Asset::Native,
                amount,
            },
            json!({
                "recipient": send.to,
                "asset": "XLM",
                "amount": send.amount.to_string(),
                "memo": memo_text,
            }),
        )
    };
    // A muxed address is shown as what it is made of: the account that is paid and the id that is its own.
    let mut details = details;
    if let Some(id) = destination.id {
        details["account"] =
            json!(stellar::address_from_public_key(&destination.key).ok_or_else(|| {
                SigningError::new("Unavailable", "the account could not be read")
            })?);
        details["muxed_id"] = json!(id.to_string());
    }
    let base_fee = json::api_u32(send.inputs, "base_fee")?;
    if !limits::STELLAR_BASE_FEE.allows(u128::from(base_fee)) {
        return Err(too_high("the fee is above the most this wallet will pay"));
    }
    let sequence = i64::try_from(json::api_u64(send.inputs, "sequence")?)
        .map_err(|_| bad("sequence is out of range"))?;
    let tx = stellar::Transaction {
        source,
        fee: base_fee,
        account_sequence: sequence,
        time_bounds: TimeBounds {
            min_time: 0,
            max_time: json::api_u64(send.inputs, "server_time")?.saturating_add(300),
        },
        memo,
        operation,
    };
    let payload = tx.encode().map_err(|e| xdr_error(&e))?;
    let summary = send.summary(
        &signer,
        action,
        details,
        fee_json(NetworkId::Stellar, u128::from(base_fee)),
        Vec::new(),
    );
    Ok(send.prepared(signer, summary, payload, Action::Stellar(tx)))
}

pub(super) fn sign_stellar(
    secrets: &Secrets,
    index: u32,
    prepared: &Prepared,
    tx: &stellar::Transaction,
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Stellar, index)?;
    let signed =
        stellar::sign_transaction(&key, PUBLIC_NETWORK_PASSPHRASE, tx).map_err(|e| match e {
            StellarError::Transaction(inner) => xdr_error(&inner),
            StellarError::NotTheSource => {
                SigningError::new("NotASigner", "the account is not the transaction's source")
            }
            StellarError::WrongKeyScheme => {
                SigningError::new("Unavailable", "the signature could not be made")
            }
        })?;
    Ok(send_output(&prepared.network, &signed.envelope_base64(), "base64", &signed.hash_hex()))
}

// ---- Bittensor ----

fn transfer_error(error: TransferError) -> SigningError {
    match error {
        TransferError::NotTheSender => {
            SigningError::new("NotASigner", "the account is not the sender")
        }
        TransferError::WrongKeyScheme | TransferError::Randomness => {
            SigningError::new("Unavailable", "the signature could not be made")
        }
        TransferError::ZeroValue => bad("the amount must be more than zero"),
        TransferError::EraPeriod => bad("era_period is not a power of two from 4 to 4096"),
    }
}

fn bittensor_send(
    secrets: &Secrets,
    index: u32,
    send: &SendRequest<'_>,
) -> Result<Prepared, SigningError> {
    let signer = signer_address(secrets, Network::Bittensor, index)?;
    send.check_inputs_address(&signer)?;
    let sender: [u8; 32] = signer_public_key(secrets, Network::Bittensor, index)?
        .try_into()
        .map_err(|_| SigningError::new("Unavailable", "the account's key could not be made"))?;
    let dest =
        bittensor::parse_address(send.to).ok_or_else(|| bad("to is not a Bittensor address"))?;
    let recipient = json::object(send.estimate, "recipient")?;
    if matches!(recipient.get("exists"), Some(Value::Bool(false)))
        && send.amount < json::api_u128(send.estimate, "existential_deposit")?
    {
        return Err(SigningError::new(
            "Dust",
            "the first transfer to a new account must be larger",
        ));
    }
    // What the signature covers about the chain is pinned here, not read from the inputs:
    // the inputs come from the chain client, which learns the metadata from a public
    // node. A wrong genesis hash makes a transaction no node accepts, but a wrong call
    // index would make the same bytes mean another call. The runtime is checked against
    // its metadata by the chain client as well; this is the engine's own refusal. A Finney
    // runtime upgrade that renumbers the Balances pallet will need a new wallet release, and
    // until then sending TAO fails closed.
    let call = json::object(send.inputs, "call_index")?;
    let pinned = CallIndex::BALANCES_TRANSFER_KEEP_ALIVE;
    if u32::from(pinned.pallet) != json::api_u32(call, "pallet")?
        || u32::from(pinned.call) != json::api_u32(call, "call")?
    {
        return Err(SigningError::new(
            "Unsupported",
            "the Bittensor runtime's transfer call is not the one this wallet knows",
        ));
    }
    let hash32 = |field: &str| -> Result<[u8; 32], SigningError> {
        hexs::decode_array(json::string(send.inputs, field)?)
            .ok_or_else(|| bad(format!("{field} is not 32 bytes of hex")))
    };
    if hash32("genesis_hash")? != bittensor::FINNEY_GENESIS {
        return Err(SigningError::new("Unsupported", "the genesis hash is not Bittensor Finney's"));
    }
    let transfer = Transfer {
        sender,
        dest,
        value: send.amount_u64()?,
        call_index: pinned,
        nonce: json::api_u32(send.inputs, "nonce")?,
        tip: 0,
        period: json::api_u64(send.inputs, "era_period")?,
        birth: json::api_u64(send.inputs, "block_number")?,
        birth_hash: hash32("block_hash")?,
        spec_version: json::api_u32(send.inputs, "spec_version")?,
        transaction_version: json::api_u32(send.inputs, "transaction_version")?,
        genesis_hash: bittensor::FINNEY_GENESIS,
    };
    let quoted = json::api_u128(json::object(send.estimate, "fee")?, "amount")?;
    if !limits::BITTENSOR_FEE.allows(quoted) {
        return Err(too_high("the fee is above the most this wallet will pay"));
    }
    let payload = transfer.signing_payload().map_err(transfer_error)?;
    let details = json!({ "recipient": send.to, "amount": send.amount.to_string() });
    let summary = send.summary(&signer, "tao_transfer", details, send.estimate_fee()?, Vec::new());
    Ok(send.prepared(signer, summary, payload, Action::Bittensor(transfer)))
}

pub(super) fn sign_bittensor(
    secrets: &Secrets,
    index: u32,
    prepared: &Prepared,
    transfer: &Transfer,
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Bittensor, index)?;
    let signed = bittensor::sign_transfer(&key, transfer).map_err(transfer_error)?;
    Ok(send_output(
        &prepared.network,
        &hexs::encode_0x(&signed.extrinsic),
        "hex",
        &hexs::encode_0x(&signed.hash),
    ))
}
