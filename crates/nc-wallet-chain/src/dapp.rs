//! What a website's wallet provider may read, straight from the networks.
//!
//! A page calls `eth_call`, `eth_estimateGas`, `eth_getTransactionReceipt` or
//! Solana's `simulateTransaction` through the wallet's injected provider. This
//! is a **strict, read-only passthrough** to the network's own public nodes: one
//! JSON-RPC 2.0 request on a short list of reads, answered as the node answered
//! (its `result` or its `error`, whole, so a reverted `eth_call` keeps the
//! revert reason the page decodes), with the caller's `id` put back. Nothing a
//! person could sign or send passes: transactions go through `broadcast`, which
//! checks them first.
//!
//! The list is the one the wallet API kept, and it is kept strictly:
//!
//! * **EVM** (`ethereum`, `bsc`, `polygon`, `base`): `eth_chainId`,
//!   `net_version`, `eth_blockNumber`, `eth_call`, `eth_estimateGas`,
//!   `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`,
//!   `eth_getBalance`, `eth_getCode`, `eth_getStorageAt`,
//!   `eth_getTransactionCount`, `eth_getTransactionByHash`,
//!   `eth_getTransactionReceipt`, `eth_getBlockByNumber`, `eth_getBlockByHash`,
//!   `eth_getLogs`.
//! * **Solana**: `getLatestBlockhash`, `getBalance`, `getAccountInfo`,
//!   `getMultipleAccounts`, `getTokenAccountsByOwner`, `getSignatureStatuses`,
//!   `getTransaction`, `simulateTransaction`, `getMinimumBalanceForRentExemption`,
//!   `getFeeForMessage`, `getSlot`, `getBlockHeight`, `getRecentPrioritizationFees`,
//!   `isBlockhashValid`, `getEpochInfo`, `getGenesisHash`, `getVersion`.
//!
//! The name is matched whole and exactly, case included. Everything else is
//! answered `-32601` without asking a node: every way of sending
//! (`eth_sendRawTransaction`, `sendTransaction`), every `debug_`, `trace_`,
//! `admin_`, `personal_`, `txpool_` and `engine_` method, subscriptions, and
//! every method that creates a filter on a node.
//!
//! Four calls are limited further, and past a limit the answer is a `-32602`
//! error that says why and no node is asked: `eth_getBlockByNumber` and
//! `eth_getBlockByHash` take `false` as their second parameter (no full
//! transactions); `eth_getLogs` takes one filter with an `address` or at least
//! one topic and spans at most 1,000 blocks; `getMultipleAccounts` takes at most
//! 100 accounts. One request, never a batch. Nothing is kept except that
//! `eth_chainId` and `net_version` are the same for ever and are answered
//! without asking.

use serde_json::{Value, json};

use crate::error::{ChainError, ChainResult};
use crate::net::Net;
use crate::networks::{Family, Network};
use crate::pool::Need;
use crate::util::u64_from_hex;

/// The most blocks an `eth_getLogs` may span.
pub const MAX_LOG_BLOCKS: u64 = 1_000;
/// The most accounts a `getMultipleAccounts` may ask for.
pub const MAX_ACCOUNTS: usize = 100;
/// The longest an `id` may be, as written.
const MAX_ID_BYTES: usize = 128;
/// The most bytes of a request.
pub const MAX_REQUEST: usize = 64 * 1024;

/// JSON-RPC's own codes.
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const EVM_METHODS: &[&str] = &[
    "eth_chainId",
    "net_version",
    "eth_blockNumber",
    "eth_call",
    "eth_estimateGas",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_feeHistory",
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_getTransactionCount",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getLogs",
];

const SOLANA_METHODS: &[&str] = &[
    "getLatestBlockhash",
    "getBalance",
    "getAccountInfo",
    "getMultipleAccounts",
    "getTokenAccountsByOwner",
    "getSignatureStatuses",
    "getTransaction",
    "simulateTransaction",
    "getMinimumBalanceForRentExemption",
    "getFeeForMessage",
    "getSlot",
    "getBlockHeight",
    "getRecentPrioritizationFees",
    "isBlockhashValid",
    "getEpochInfo",
    "getGenesisHash",
    "getVersion",
];

/// A request answered with an error of its own, not asked of any node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// JSON-RPC's code.
    pub code: i64,
    /// What is wrong.
    pub message: &'static str,
}

const NOT_AVAILABLE: Refusal =
    Refusal { code: METHOD_NOT_FOUND, message: "method not available through the wallet" };

const fn invalid(message: &'static str) -> Refusal {
    Refusal { code: INVALID_PARAMS, message }
}

/// What a request that may pass needs.
#[derive(Debug, PartialEq, Eq)]
pub enum Screened {
    /// Ask a node.
    Forward,
    /// Answered here: it is the same for ever.
    Constant(Constant),
    /// An `eth_getLogs` whose span is known only against the chain's head.
    Logs(Span),
}

/// A constant of an EVM network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constant {
    /// `eth_chainId`: `0x`-hex.
    ChainId,
    /// `net_version`: decimal, as a string.
    NetVersion,
}

/// An end of a log query's span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// A block number.
    Number(u64),
    /// `latest` or `pending`, which is the head as it stands.
    Head,
}

/// The blocks an `eth_getLogs` spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    from: Bound,
    to: Bound,
}

impl Span {
    const TOO_WIDE: Refusal =
        invalid("eth_getLogs spans at most 1000 blocks; ask for a narrower range");

    const fn needs_head(self) -> bool {
        matches!(self.from, Bound::Head) || matches!(self.to, Bound::Head)
    }

    /// Whether the span is within the cap, the head being `head`.
    fn check(self, head: u64) -> Result<(), Refusal> {
        let at = |bound| match bound {
            Bound::Number(number) => number,
            Bound::Head => head,
        };
        // A span running backwards is empty: the node says so.
        if at(self.to).saturating_sub(at(self.from)) >= MAX_LOG_BLOCKS {
            return Err(Self::TOO_WIDE);
        }
        Ok(())
    }
}

/// A block quantity: `0x` and 1 to 16 hex digits.
fn quantity(text: &str) -> Option<u64> {
    let digits = text.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// One end of a span: a number, `earliest`, `latest` or `pending`; `latest`
/// where it is left out. `safe` and `finalized` are behind the head by an amount
/// only a node knows, so they are not taken here.
fn bound(value: Option<&Value>) -> Result<Bound, Refusal> {
    const BAD: Refusal =
        invalid("fromBlock and toBlock are a block number, earliest, latest or pending");
    match value {
        None | Some(Value::Null) => Ok(Bound::Head),
        Some(Value::String(text)) => match text.as_str() {
            "latest" | "pending" => Ok(Bound::Head),
            "earliest" => Ok(Bound::Number(0)),
            number => quantity(number).map(Bound::Number).ok_or(BAD),
        },
        Some(_) => Err(BAD),
    }
}

fn filters_by_address(filter: &serde_json::Map<String, Value>) -> bool {
    match filter.get("address") {
        Some(Value::String(address)) => !address.is_empty(),
        Some(Value::Array(addresses)) => !addresses.is_empty(),
        _ => false,
    }
}

fn filters_by_topic(filter: &serde_json::Map<String, Value>) -> bool {
    match filter.get("topics") {
        Some(Value::Array(topics)) => topics.iter().any(|topic| match topic {
            Value::String(_) => true,
            Value::Array(any_of) => !any_of.is_empty(),
            _ => false,
        }),
        _ => false,
    }
}

fn logs(params: &[Value]) -> Result<Screened, Refusal> {
    let [Value::Object(filter)] = params else {
        return Err(invalid("eth_getLogs takes one filter object"));
    };
    if !filters_by_address(filter) && !filters_by_topic(filter) {
        return Err(invalid("eth_getLogs needs an address or topics to filter by"));
    }
    match filter.get("blockHash") {
        // One block: no span to cap.
        Some(Value::String(_)) => return Ok(Screened::Forward),
        None | Some(Value::Null) => {}
        Some(_) => return Err(invalid("blockHash is a block hash")),
    }
    let span = Span { from: bound(filter.get("fromBlock"))?, to: bound(filter.get("toBlock"))? };
    if span.needs_head() {
        return Ok(Screened::Logs(span));
    }
    // Both are numbers: the head is not needed to count them.
    span.check(0).map(|()| Screened::Forward)
}

/// Blocks come without their transactions' bodies only.
fn block(params: &[Value]) -> Result<Screened, Refusal> {
    match params {
        [_, Value::Bool(false)] => Ok(Screened::Forward),
        _ => Err(invalid("full transactions are not available through the wallet; ask with false")),
    }
}

fn accounts(params: &[Value]) -> Result<Screened, Refusal> {
    match params.first() {
        Some(Value::Array(keys)) if keys.len() <= MAX_ACCOUNTS => Ok(Screened::Forward),
        Some(Value::Array(_)) => Err(invalid("getMultipleAccounts takes at most 100 accounts")),
        _ => Err(invalid("getMultipleAccounts takes a list of accounts")),
    }
}

/// The list a network answers from, or `None` for one with no JSON-RPC route.
fn methods(network: Network) -> Option<&'static [&'static str]> {
    match network.family() {
        Family::Evm => Some(EVM_METHODS),
        Family::Solana => Some(SOLANA_METHODS),
        _ => None,
    }
}

/// Whether, and how, `method` with `params` may be answered on `network`.
/// Returns the method as the list spells it (`'static`) with the verdict.
pub fn screen(
    network: Network,
    method: &str,
    params: &[Value],
) -> Result<(&'static str, Screened), Refusal> {
    let Some(list) = methods(network) else { return Err(NOT_AVAILABLE) };
    let Some(&listed) = list.iter().find(|m| **m == method) else { return Err(NOT_AVAILABLE) };
    let screened = match (network.family(), listed) {
        (Family::Evm, "eth_chainId") => Screened::Constant(Constant::ChainId),
        (Family::Evm, "net_version") => Screened::Constant(Constant::NetVersion),
        (Family::Evm, "eth_getBlockByNumber" | "eth_getBlockByHash") => block(params)?,
        (Family::Evm, "eth_getLogs") => logs(params)?,
        (Family::Solana, "getMultipleAccounts") => accounts(params)?,
        _ => Screened::Forward,
    };
    Ok((listed, screened))
}

// ---- the request ----------------------------------------------------------------

const SHAPE: &str =
    "the body is one JSON-RPC 2.0 request: {\"jsonrpc\": \"2.0\", \"id\", \"method\", \"params\"}";

/// One request, checked for its form.
#[derive(Debug)]
pub struct Call {
    /// The caller's, as written: a number, a string or `null`.
    pub id: Value,
    /// The method.
    pub method: String,
    /// The parameters.
    pub params: Vec<Value>,
}

/// Reads a request: one, with an `id`, in JSON-RPC 2.0's form. A batch is refused.
pub fn parse(request: &Value) -> ChainResult<Call> {
    if request.is_array() {
        return Err(ChainError::invalid("batches are not accepted; send one request at a time"));
    }
    let bad = || ChainError::invalid(SHAPE);
    let object = request.as_object().ok_or_else(bad)?;
    if object.keys().any(|k| !matches!(k.as_str(), "jsonrpc" | "id" | "method" | "params")) {
        return Err(bad());
    }
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(bad());
    }
    let id = object.get("id").ok_or_else(|| {
        ChainError::invalid("the request has no id; a notification gets no answer")
    })?;
    let fine = match id {
        Value::Null | Value::Number(_) => true,
        Value::String(text) => text.len() <= MAX_ID_BYTES,
        _ => false,
    };
    if !fine {
        return Err(ChainError::invalid(
            "id is a number, a string of at most 128 characters, or null",
        ));
    }
    let method = object.get("method").and_then(Value::as_str).ok_or_else(bad)?.to_owned();
    let params = match object.get("params") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(params)) => params.clone(),
        Some(_) => return Err(ChainError::invalid("params is an array")),
    };
    Ok(Call { id: id.clone(), method, params })
}

fn reply(id: &Value, outcome: Result<Value, Value>) -> Value {
    match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
    }
}

/// Answers one request: refused here, answered here, or asked of the network
/// and answered as the node answered. The answer is the whole JSON-RPC response.
pub async fn answer(net: &Net, network: Network, request: &Value) -> ChainResult<Value> {
    if methods(network).is_none() {
        return Err(ChainError::RpcNotAvailable);
    }
    if request.to_string().len() > MAX_REQUEST {
        return Err(ChainError::invalid("the request is larger than 64 KiB"));
    }
    let call = parse(request)?;
    let (method, screened) = match screen(network, &call.method, &call.params) {
        Ok(screened) => screened,
        Err(refusal) => {
            return Ok(reply(
                &call.id,
                Err(json!({ "code": refusal.code, "message": refusal.message })),
            ));
        }
    };
    match screened {
        Screened::Constant(constant) => {
            let id = network.chain_id().ok_or(ChainError::Internal)?;
            let value = match constant {
                Constant::ChainId => format!("0x{id:x}"),
                Constant::NetVersion => id.to_string(),
            };
            Ok(reply(&call.id, Ok(Value::String(value))))
        }
        Screened::Forward => forward(net, &call, method).await,
        Screened::Logs(span) => {
            let head = net.rpc(Need::ANY, "eth_blockNumber", &json!([])).await?;
            let head = head
                .ok()
                .as_ref()
                .and_then(Value::as_str)
                .and_then(u64_from_hex)
                .ok_or(ChainError::Unavailable)?;
            if let Err(refusal) = span.check(head) {
                return Ok(reply(
                    &call.id,
                    Err(json!({ "code": refusal.code, "message": refusal.message })),
                ));
            }
            forward(net, &call, method).await
        }
    }
}

async fn forward(net: &Net, call: &Call, method: &'static str) -> ChainResult<Value> {
    let need = match method {
        "eth_getLogs" => Need::LOGS,
        "eth_getTransactionReceipt" => Need::RECEIPTS,
        _ => Need::method(method),
    };
    let params = Value::Array(call.params.clone());
    let outcome = net.rpc_site(need, method, &params).await?.map_err(|error| error.to_value());
    Ok(reply(&call.id, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "0xdac17f958d2ee523a2206206994597c13d831ec7";

    fn params(value: &Value) -> Vec<Value> {
        value.as_array().cloned().unwrap_or_default()
    }

    #[test]
    fn the_lists_are_exactly_the_reads() {
        for sending in [
            "eth_sendRawTransaction",
            "eth_sendTransaction",
            "eth_sign",
            "personal_sign",
            "eth_signTransaction",
            "eth_subscribe",
            "eth_newFilter",
            "eth_getFilterChanges",
            "debug_traceTransaction",
            "trace_call",
            "admin_peers",
            "txpool_content",
            "engine_newPayloadV1",
            "eth_accounts",
            "eth_getProof",
            "ETH_CALL",
            "eth_call ",
        ] {
            assert_eq!(screen(Network::Ethereum, sending, &[]), Err(NOT_AVAILABLE), "{sending}");
        }
        for sending in
            ["sendTransaction", "requestAirdrop", "accountSubscribe", "getProgramAccounts"]
        {
            assert_eq!(screen(Network::Solana, sending, &[]), Err(NOT_AVAILABLE), "{sending}");
        }
        // A method of one family is not the other's.
        assert!(screen(Network::Solana, "eth_call", &[]).is_err());
        assert!(screen(Network::Base, "getBalance", &[]).is_err());
        // The other networks have no route at all.
        assert!(screen(Network::Tron, "eth_call", &[]).is_err());
        assert!(screen(Network::Bitcoin, "eth_call", &[]).is_err());
    }

    #[test]
    fn every_listed_read_passes_with_fitting_parameters() {
        for method in EVM_METHODS {
            let fitting = match *method {
                "eth_getBlockByNumber" | "eth_getBlockByHash" => params(&json!(["latest", false])),
                "eth_getLogs" => {
                    params(&json!([{ "address": ADDRESS, "fromBlock": "0x10", "toBlock": "0x20" }]))
                }
                _ => Vec::new(),
            };
            assert!(screen(Network::Ethereum, method, &fitting).is_ok(), "{method}");
        }
        for method in SOLANA_METHODS {
            let fitting = if *method == "getMultipleAccounts" {
                params(&json!([["11111111111111111111111111111111"]]))
            } else {
                Vec::new()
            };
            assert!(screen(Network::Solana, method, &fitting).is_ok(), "{method}");
        }
    }

    #[test]
    fn the_chain_id_and_the_network_version_are_answered_without_asking() {
        assert_eq!(
            screen(Network::Base, "eth_chainId", &[]).map(|(_, s)| s),
            Ok(Screened::Constant(Constant::ChainId))
        );
        assert_eq!(
            screen(Network::Base, "net_version", &[]).map(|(_, s)| s),
            Ok(Screened::Constant(Constant::NetVersion))
        );
    }

    #[test]
    fn a_block_comes_without_its_transactions_only() {
        for method in ["eth_getBlockByNumber", "eth_getBlockByHash"] {
            assert!(screen(Network::Ethereum, method, &params(&json!(["latest", false]))).is_ok());
            for bad in
                [json!(["latest", true]), json!(["latest"]), json!(["latest", "false"]), json!([])]
            {
                assert_eq!(
                    screen(Network::Ethereum, method, &params(&bad))
                        .map(|(_, s)| s)
                        .map_err(|r| r.code),
                    Err(INVALID_PARAMS),
                    "{bad}"
                );
            }
        }
    }

    #[test]
    fn a_log_query_names_an_address_or_a_topic_and_spans_a_thousand_blocks_at_most() {
        let logs =
            |filter: Value| screen(Network::Ethereum, "eth_getLogs", &[filter]).map(|(_, s)| s);
        assert_eq!(
            logs(json!({ "address": ADDRESS, "fromBlock": "0x10", "toBlock": "0x3e7" })),
            Ok(Screened::Forward)
        );
        // 1,000 blocks is 0x10 to 0x3f7 inclusive; one more is too many.
        assert_eq!(
            logs(json!({ "address": ADDRESS, "fromBlock": "0x0", "toBlock": "0x3e8" }))
                .map_err(|r| r.code),
            Err(INVALID_PARAMS)
        );
        assert_eq!(
            logs(json!({ "topics": ["0xaa"], "fromBlock": "0x1", "toBlock": "0x2" })),
            Ok(Screened::Forward)
        );
        assert!(
            logs(json!({ "fromBlock": "0x1", "toBlock": "0x2" })).is_err(),
            "nothing to filter by"
        );
        assert!(logs(json!({ "topics": [null], "fromBlock": "0x1", "toBlock": "0x2" })).is_err());
        assert!(logs(json!({ "address": "", "fromBlock": "0x1", "toBlock": "0x2" })).is_err());
        assert!(
            logs(json!({ "address": ADDRESS, "fromBlock": "safe", "toBlock": "0x2" })).is_err()
        );
        assert!(
            logs(json!({ "address": ADDRESS, "fromBlock": "finalized", "toBlock": "0x2" }))
                .is_err()
        );
        // A block hash is one block.
        assert_eq!(logs(json!({ "address": ADDRESS, "blockHash": "0xaa" })), Ok(Screened::Forward));
        // `latest` is counted against the head.
        assert!(matches!(
            logs(json!({ "address": ADDRESS, "fromBlock": "0x10" })),
            Ok(Screened::Logs(_))
        ));
        let head_span = Span { from: Bound::Number(100), to: Bound::Head };
        assert!(head_span.check(1_099).is_ok());
        assert!(head_span.check(1_100).is_err());
        // Two filters, or none, are not a query.
        assert!(screen(Network::Ethereum, "eth_getLogs", &[]).is_err());
    }

    #[test]
    fn at_most_a_hundred_accounts_at_once() {
        let keys = |n: usize| params(&json!([vec!["11111111111111111111111111111111"; n]]));
        assert!(screen(Network::Solana, "getMultipleAccounts", &keys(100)).is_ok());
        assert!(screen(Network::Solana, "getMultipleAccounts", &keys(101)).is_err());
        assert!(screen(Network::Solana, "getMultipleAccounts", &[]).is_err());
    }

    #[test]
    fn a_request_is_one_json_rpc_two_call_with_an_id() {
        let call = |v: Value| parse(&v).map(|c| (c.id, c.method, c.params.len()));
        assert_eq!(
            call(json!({ "jsonrpc": "2.0", "id": 7, "method": "eth_call", "params": [1, 2] }))
                .unwrap(),
            (json!(7), "eth_call".to_owned(), 2)
        );
        assert!(call(json!({ "jsonrpc": "2.0", "id": null, "method": "eth_blockNumber" })).is_ok());
        assert!(
            call(json!({ "jsonrpc": "2.0", "id": "s1", "method": "getSlot", "params": [] }))
                .is_ok()
        );
        for bad in [
            json!([{ "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber" }]),
            json!({ "jsonrpc": "1.0", "id": 1, "method": "eth_blockNumber" }),
            json!({ "jsonrpc": "2.0", "method": "eth_blockNumber" }),
            json!({ "jsonrpc": "2.0", "id": 1 }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": {} }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "extra": 1 }),
            json!({ "jsonrpc": "2.0", "id": [1], "method": "eth_blockNumber" }),
            json!({ "jsonrpc": "2.0", "id": "x".repeat(129), "method": "eth_blockNumber" }),
            json!("eth_blockNumber"),
        ] {
            assert!(call(bad.clone()).is_err(), "{bad}");
        }
    }
}
