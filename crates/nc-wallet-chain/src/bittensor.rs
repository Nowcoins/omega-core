//! Bittensor, through a Finney node's JSON-RPC on public endpoints (the
//! Opentensor Foundation's and `OnFinality`'s): the account (`System.Account`
//! storage, the nonce counting the pool), what a signature covers (the
//! runtime's versions, the genesis hash, a recent finalized block), the call
//! index of `Balances.transfer_keep_alive`, a fee quote
//! (`TransactionPaymentApi_query_info`), and `author_submitExtrinsic`.
//!
//! The runtime is checked against its metadata before anything built for it is
//! described ([`metadata`]). A runtime the checks do not pass answers
//! `upstream_unavailable`: nothing is guessed.

pub mod metadata;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U16;
use nc_wallet_core::bittensor::extrinsic::{CallIndex, Transfer};
use serde_json::{Value, json};

use crate::address::{self, Address};
use crate::common::{EstimateArgs, balances_body, fee_value, native_entry};
use crate::error::{ChainError, ChainResult, REFUSED};
use crate::net::{Net, NodeError};
use crate::networks::Network;
use crate::pool::Need;
use crate::quorum::{Figure, Kind, unconfirmed};
use crate::util::{bytes_from_hex, to_hex};
use metadata::{Runtime, compact_u64};
use nc_wallet_core::limits;

/// Finney's genesis hash: every signature covers it.
pub const FINNEY_GENESIS: [u8; 32] = [
    0x2f, 0x05, 0x55, 0xcc, 0x76, 0xfc, 0x28, 0x40, 0xa2, 0x5a, 0x6e, 0xa3, 0xb9, 0x63, 0x71, 0x46,
    0x80, 0x6f, 0x1f, 0x44, 0xb0, 0x90, 0xc1, 0x75, 0xff, 0xde, 0x2a, 0x7e, 0x5a, 0xb3, 0x6c, 0x03,
];

/// How many blocks a transaction lives for.
const ERA_PERIOD: u64 = 64;
/// `twox128("System") ‖ twox128("Account")`: the prefix of every account's
/// entry in `System.Account`.
const SYSTEM_ACCOUNT: [u8; 32] = [
    0x26, 0xaa, 0x39, 0x4e, 0xea, 0x56, 0x30, 0xe0, 0x7c, 0x48, 0xae, 0x0c, 0x95, 0x58, 0xce, 0xf7,
    0xb9, 0x9d, 0x88, 0x0e, 0xc6, 0x81, 0x79, 0x9c, 0x0c, 0xf3, 0x0e, 0x88, 0x86, 0x37, 0x1d, 0xa9,
];
/// An account entry's length: four `u32`s, three `u64`s and a `u128`.
const ACCOUNT_INFO_LEN: usize = 4 * 4 + 3 * 8 + 16;
/// `TransactionSource::External`: a transaction that came from outside the
/// node, which is what a submission is.
const SOURCE_EXTERNAL: u8 = 2;
/// How many endpoints a signed extrinsic is sent to at once.
const BROADCAST_TO: usize = 3;

/// What the client remembers between calls.
#[derive(Debug, Default)]
pub struct State {
    /// Runtimes read and checked, by spec and transaction version.
    runtimes: Mutex<Vec<((u32, u32), Runtime)>>,
    /// Whether the endpoints have been seen to serve Finney.
    genesis_checked: AtomicBool,
}

impl State {
    /// The runtimes already checked, so that a new launch does not read the
    /// metadata (some 700 KB) again for a runtime it has passed before.
    pub fn export(&self) -> Value {
        let runtimes: Vec<Value> = self
            .runtimes
            .lock()
            .map(|r| {
                r.iter()
                    .map(|((spec, transaction), runtime)| {
                        json!([spec, transaction, runtime.existential_deposit.to_string()])
                    })
                    .collect()
            })
            .unwrap_or_default();
        json!({ "runtimes": runtimes })
    }

    /// Takes back what [`Self::export`] wrote.
    pub fn import(&self, state: &Value) {
        let (Ok(mut held), Some(list)) =
            (self.runtimes.lock(), state.get("runtimes").and_then(Value::as_array))
        else {
            return;
        };
        for entry in list.iter().take(8) {
            let number = |at: usize| {
                entry.get(at).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok())
            };
            let deposit = entry.get(2).and_then(Value::as_str).and_then(|d| d.parse::<u64>().ok());
            if let (Some(spec), Some(transaction), Some(deposit)) = (number(0), number(1), deposit)
                && !held.iter().any(|(key, _)| *key == (spec, transaction))
            {
                held.push((
                    (spec, transaction),
                    Runtime {
                        spec_version: spec,
                        transaction_version: transaction,
                        existential_deposit: deposit,
                    },
                ));
            }
        }
    }
}

/// Bittensor.
#[derive(Debug, Clone, Copy)]
pub struct Bittensor<'a> {
    net: &'a Net,
    state: &'a State,
}

/// An account's entry in `System.Account`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AccountInfo {
    /// How many extrinsics the account has had included.
    nonce: u32,
    providers: u32,
    free: u64,
}

impl AccountInfo {
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ACCOUNT_INFO_LEN {
            return None;
        }
        Some(Self {
            nonce: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            providers: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            free: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
        })
    }
}

/// An account's key in `System.Account`, a `Blake2_128Concat` map: the prefix,
/// the BLAKE2-128 of the account, and the account itself.
fn account_key(account: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(80);
    key.extend_from_slice(&SYSTEM_ACCOUNT);
    key.extend_from_slice(&Blake2b::<U16>::digest(account));
    key.extend_from_slice(account);
    key
}

/// How many extrinsics `address` has had included, as `System.Account` says at the best block, from
/// two operators that must agree (one alone is a figure nothing checked: `sources` says). It is
/// the account's nonce on chain, not the next one the pool would take: a send whose nonce is below it
/// came in, and one whose nonce is not, and whose era is over, never will.
pub(crate) async fn included(net: &Net, address: &Address) -> ChainResult<Figure> {
    fn read(stored: &Value) -> Option<u128> {
        match stored {
            // An account nothing was ever sent to.
            Value::Null => Some(0),
            Value::String(text) => {
                AccountInfo::decode(&bytes_from_hex(text)?).map(|info| u128::from(info.nonce))
            }
            _ => None,
        }
    }
    let key = to_hex(&account_key(&address.key()?));
    net.rpc_figure("state_getStorage", &json!([key]), read, Kind::Exact).await
}

fn hash_from_hex(text: &str) -> Option<[u8; 32]> {
    bytes_from_hex(text)?.try_into().ok()
}

fn number(value: &Value) -> Option<u128> {
    match value {
        Value::Number(n) => n.as_u64().map(u128::from),
        Value::String(s) => s
            .strip_prefix("0x")
            .map_or_else(|| s.parse().ok(), |digits| u128::from_str_radix(digits, 16).ok()),
        _ => None,
    }
}

/// The finalized head: its hash and height.
struct Head {
    hash: [u8; 32],
    number: u64,
}

impl<'a> Bittensor<'a> {
    /// Bittensor over `net`, remembering runtimes in `state`.
    #[must_use]
    pub const fn new(net: &'a Net, state: &'a State) -> Self {
        Self { net, state }
    }

    async fn read(&self, method: &'static str, params: Value) -> ChainResult<Value> {
        match self.net.rpc(Need::ANY, method, &params).await? {
            Ok(value) => Ok(value),
            Err(_) => Err(ChainError::Unavailable),
        }
    }

    /// The endpoints serve Finney and not another chain: its block 0 is the
    /// genesis every signature covers. Two operators are asked and both must
    /// say so.
    async fn check_genesis(&self) -> ChainResult<()> {
        if self.state.genesis_checked.load(Ordering::Relaxed) {
            return Ok(());
        }
        let answers = self.net.rpc_many(Need::ANY, 2, "chain_getBlockHash", &json!([0])).await?;
        let mut seen = 0;
        for (answer, _) in answers {
            let hash = answer.ok().and_then(|v| v.as_str().and_then(hash_from_hex));
            if hash != Some(FINNEY_GENESIS) {
                return Err(ChainError::Unavailable);
            }
            seen += 1;
        }
        if seen == 0 {
            return Err(ChainError::Unavailable);
        }
        self.state.genesis_checked.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn head(&self) -> ChainResult<Head> {
        let hash = self.read("chain_getFinalizedHead", json!([])).await?;
        let hash = hash.as_str().ok_or(ChainError::Unavailable)?.to_owned();
        let header = self.read("chain_getHeader", json!([hash])).await?;
        Ok(Head {
            hash: hash_from_hex(&hash).ok_or(ChainError::Unavailable)?,
            number: header
                .get("number")
                .and_then(number)
                .and_then(|n| u64::try_from(n).ok())
                .ok_or(ChainError::Unavailable)?,
        })
    }

    /// The runtime in force, read from its metadata and checked once per
    /// version; `Unavailable` where the checks do not pass.
    async fn runtime(&self) -> ChainResult<Runtime> {
        self.check_genesis().await?;
        let versions = self.read("state_getRuntimeVersion", json!([])).await?;
        let spec = versions.get("specVersion").and_then(number).and_then(|n| u32::try_from(n).ok());
        let transaction =
            versions.get("transactionVersion").and_then(number).and_then(|n| u32::try_from(n).ok());
        let (Some(spec), Some(transaction)) = (spec, transaction) else {
            return Err(ChainError::Unavailable);
        };
        let key = (spec, transaction);
        if let Some(runtime) =
            self.state.runtimes.lock().ok().and_then(|runtimes| {
                runtimes.iter().find(|(k, _)| *k == key).map(|(_, r)| r.clone())
            })
        {
            return Ok(runtime);
        }
        let metadata = self.read("state_getMetadata", json!([])).await?;
        let bytes = metadata.as_str().and_then(bytes_from_hex).ok_or(ChainError::Unavailable)?;
        let runtime = metadata::check(&bytes).map_err(|_| ChainError::Unavailable)?;
        // The node's metadata is of another runtime than it says: asked again later.
        if (runtime.spec_version, runtime.transaction_version) != key {
            return Err(ChainError::Unavailable);
        }
        if let Ok(mut runtimes) = self.state.runtimes.lock() {
            runtimes.push((key, runtime.clone()));
        }
        Ok(runtime)
    }

    async fn account(&self, account: &[u8; 32]) -> ChainResult<AccountInfo> {
        let stored = self.read("state_getStorage", json!([to_hex(&account_key(account))])).await?;
        match stored.as_str() {
            None if stored.is_null() => Ok(AccountInfo::default()),
            Some(text) => bytes_from_hex(text)
                .and_then(|bytes| AccountInfo::decode(&bytes))
                .ok_or(ChainError::Unavailable),
            None => Err(ChainError::Unavailable),
        }
    }

    /// The account's next nonce, counting what is waiting in the pool, confirmed by two
    /// operators (a nonce too low replaces the person's own pending transaction, one too
    /// high leaves a gap) and never below `floor`, one past the last this device sent.
    async fn nonce(&self, address: &Address, floor: u128) -> ChainResult<u32> {
        let figure = self
            .net
            .rpc_figure("system_accountNextIndex", &json!([address.text]), number, Kind::Exact)
            .await?;
        if figure.sources < 2 {
            return Err(unconfirmed("number of the next transaction"));
        }
        u32::try_from(figure.value.max(floor)).map_err(|_| ChainError::Unavailable)
    }

    /// The runtime's verdict on `raw` at the best block, for a refusal to be told by.
    async fn validity(&self, raw: &[u8]) -> ChainResult<ChainError> {
        let best = self.read("chain_getBlockHash", json!([])).await?;
        let best = best.as_str().ok_or(ChainError::Unavailable)?.to_owned();
        let at = hash_from_hex(&best).ok_or(ChainError::Unavailable)?;
        let mut data = Vec::with_capacity(raw.len() + 33);
        data.push(SOURCE_EXTERNAL);
        data.extend_from_slice(raw);
        data.extend_from_slice(&at);
        let answer = self
            .read(
                "state_call",
                json!(["TaggedTransactionQueue_validate_transaction", to_hex(&data), best]),
            )
            .await?;
        let bytes = answer.as_str().and_then(bytes_from_hex).ok_or(ChainError::Unavailable)?;
        Ok(told_by(&bytes))
    }

    /// The coin of `address`: its free balance.
    pub async fn balances(&self, address: &Address, as_of: &str) -> ChainResult<Value> {
        let info = self.account(&address.key()?).await?;
        Ok(balances_body(
            Network::Bittensor,
            &address.text,
            &[native_entry(Network::Bittensor, u128::from(info.free))],
            as_of,
        ))
    }

    /// What a send is built from.
    pub async fn inputs(&self, address: &Address, floor: u128) -> ChainResult<Value> {
        let (runtime, head, nonce) =
            futures::join!(self.runtime(), self.head(), self.nonce(address, floor));
        let (runtime, head, nonce) = (runtime?, head?, nonce?);
        Ok(json!({
            "network": "bittensor",
            "address": address.text,
            "nonce": nonce,
            "spec_version": runtime.spec_version,
            "transaction_version": runtime.transaction_version,
            "genesis_hash": to_hex(&FINNEY_GENESIS),
            "block_hash": to_hex(&head.hash),
            "block_number": head.number,
            "era_period": ERA_PERIOD,
            // Verified against the metadata by `runtime()`.
            "call_index": { "pallet": 5, "call": 3 },
            "existential_deposit": runtime.existential_deposit.to_string(),
        }))
    }

    /// The fee of a transfer and whether its recipient exists.
    pub async fn estimate(&self, args: &EstimateArgs, floor: u128) -> ChainResult<Value> {
        let from = address::parse(Network::Bittensor, &args.from)
            .map_err(|_| ChainError::InvalidAddress("from is not a valid address".to_owned()))?;
        let to = address::parse(Network::Bittensor, &args.to)
            .map_err(|_| ChainError::InvalidAddress("to is not a valid address".to_owned()))?;
        let value = u64::try_from(args.amount)
            .map_err(|_| ChainError::invalid("amount is more than an account can hold"))?;
        let (sender, dest) = (from.key()?, to.key()?);
        let (runtime, head, nonce, recipient) = futures::join!(
            self.runtime(),
            self.head(),
            self.nonce(&from, floor),
            self.account(&dest)
        );
        let (runtime, head, nonce, recipient) = (runtime?, head?, nonce?, recipient?);
        let exists = recipient.providers > 0 || recipient.free > 0;
        if !exists && value < runtime.existential_deposit {
            return Err(ChainError::EstimateFailed(format!(
                "a new account must receive at least {} rao",
                runtime.existential_deposit
            )));
        }
        // The runtime prices an extrinsic by its length and its call's weight,
        // so a copy with a blank signature of the same length is asked about.
        let extrinsic = Transfer {
            sender,
            dest,
            value,
            call_index: CallIndex::BALANCES_TRANSFER_KEEP_ALIVE,
            nonce,
            tip: 0,
            period: ERA_PERIOD,
            birth: head.number,
            birth_hash: head.hash,
            spec_version: runtime.spec_version,
            transaction_version: runtime.transaction_version,
            genesis_hash: FINNEY_GENESIS,
        }
        .encode_signed(&[0; 64])
        .map_err(|_| ChainError::invalid("that transfer cannot be built"))?;
        let length = u32::try_from(extrinsic.len()).map_err(|_| ChainError::Internal)?;
        let mut data = extrinsic;
        data.extend_from_slice(&length.to_le_bytes());
        // What the runtime says a transfer costs, from two operators and within the wallet's own
        // bound (the fee itself is the chain's to charge; this is what the person is shown).
        let params = json!(["TransactionPaymentApi_query_info", to_hex(&data), to_hex(&head.hash)]);
        let figure = self.net.rpc_figure("state_call", &params, quoted, Kind::Fee).await?;
        let fee = figure.within(limits::BITTENSOR_FEE, "network fee")?;
        Ok(json!({
            "network": "bittensor",
            "fee": fee_value(Network::Bittensor.native(), fee),
            "existential_deposit": runtime.existential_deposit.to_string(),
            "recipient": { "exists": exists },
        }))
    }

    /// Sends a signed extrinsic to three endpoints at once.
    ///
    /// `sent_before` is whether this device already had this very extrinsic accepted: a node
    /// that now says its nonce is used is saying that it came in.
    pub async fn broadcast(
        &self,
        raw: &[u8],
        hash: &str,
        sent_before: bool,
    ) -> ChainResult<String> {
        let answers = self
            .net
            .rpc_many(Need::ANY, BROADCAST_TO, "author_submitExtrinsic", &json!([to_hex(raw)]))
            .await?;
        let mut accepted = false;
        let mut duplicate = false;
        let mut low_priority = false;
        let mut invalid = false;
        let mut other: Option<NodeError> = None;
        for (answer, _) in answers {
            match answer {
                Ok(_) => accepted = true,
                // "Transaction Already Imported".
                Err(NodeError { code: 1013, .. }) => duplicate = true,
                // "Priority is too low": the pool holds one on this nonce already.
                Err(NodeError { code: 1014, .. }) => low_priority = true,
                // Invalid, or temporarily banned: the runtime says why when asked again.
                Err(NodeError { code: 1010 | 1012, .. }) => invalid = true,
                Err(error) => other = other.or(Some(error)),
            }
        }
        if accepted || duplicate {
            return Ok(hash.to_owned());
        }
        if low_priority {
            return Err(ChainError::InsufficientFee(
                "a transaction with this nonce is waiting; a higher tip replaces it".to_owned(),
            ));
        }
        if invalid {
            let verdict = self.validity(raw).await.unwrap_or(ChainError::Unavailable);
            // Nodes keep no index of extrinsics, so "that nonce is used" cannot be checked by hash.
            // But an extrinsic this device had accepted a moment ago is the one that used it.
            if sent_before && matches!(verdict, ChainError::Nonce(_)) {
                return Err(ChainError::Duplicate { hash: hash.to_owned() });
            }
            return Err(verdict);
        }
        Err(match other {
            Some(_) => ChainError::Rejected(REFUSED.to_owned()),
            None => ChainError::Unavailable,
        })
    }

    /// Nodes keep no index of extrinsics by hash: a transaction's place cannot
    /// be asked for. The account's nonce and its history say whether it came in.
    pub fn status(&self, _hash: &str) -> Value {
        json!({ "status": "unknown" })
    }
}

/// What the runtime's verdict means for a transaction a node refused.
fn told_by(verdict: &[u8]) -> ChainError {
    match verdict {
        [1, 0, tag, ..] => match tag {
            3 => ChainError::Nonce(
                "that nonce is already used, perhaps by this very transaction: nodes keep no index of extrinsics, \
                 so check the account's nonce and history"
                    .to_owned(),
            ),
            2 => ChainError::Nonce("the nonce is ahead of the account's: an earlier one is missing".to_owned()),
            1 => ChainError::InsufficientFunds("the account cannot pay the fee".to_owned()),
            5 => ChainError::Expired("the transaction's era has passed; build it again from fresh inputs".to_owned()),
            // A full block is no verdict on the transaction.
            6 => ChainError::Unavailable,
            4 => ChainError::Rejected("the signature does not verify".to_owned()),
            7 => ChainError::Rejected("the runtime refused it with its own code".to_owned()),
            _ => ChainError::Rejected("the runtime refused the transaction".to_owned()),
        },
        // Refused a moment ago and acceptable now (send it again), or the
        // runtime could not say.
        _ => ChainError::Unavailable,
    }
}

/// The fee in a `state_call` answer (hex of `RuntimeDispatchInfo`).
fn quoted(answer: &Value) -> Option<u128> {
    partial_fee(&bytes_from_hex(answer.as_str()?)?)
}

/// `RuntimeDispatchInfo<Balance, Weight>`: a weight of two compact `u64`s, the
/// class byte, then the fee as a little-endian integer (a `u64` on Bittensor,
/// though a `u128` is read as well, so that widening the balance type could
/// not be misread as a smaller fee).
fn partial_fee(bytes: &[u8]) -> Option<u128> {
    let mut input = bytes;
    compact_u64(&mut input)?;
    compact_u64(&mut input)?;
    let (_class, fee) = input.split_first()?;
    match fee.len() {
        8 => Some(u128::from(u64::from_le_bytes(fee.try_into().ok()?))),
        16 => Some(u128::from_le_bytes(fee.try_into().ok()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_key_is_the_prefix_the_hash_and_the_account() {
        let key = account_key(&[5; 32]);
        assert_eq!(key.len(), 80);
        assert_eq!(&key[..32], &SYSTEM_ACCOUNT);
        assert_eq!(&key[48..], &[5; 32]);
    }

    #[test]
    fn the_genesis_is_finneys() {
        assert_eq!(
            to_hex(&FINNEY_GENESIS),
            "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
        );
    }

    #[test]
    fn an_entry_of_the_wrong_length_is_refused_and_a_balance_is_the_free_part() {
        assert_eq!(AccountInfo::decode(&[0; 40]), None);
        let mut bytes = Vec::new();
        for word in [3_u32, 0, 1, 0] {
            bytes.extend(word.to_le_bytes());
        }
        for word in [1_500_000_000_u64, 0, 0] {
            bytes.extend(word.to_le_bytes());
        }
        bytes.extend(0_u128.to_le_bytes());
        assert_eq!(
            AccountInfo::decode(&bytes),
            Some(AccountInfo { nonce: 3, providers: 1, free: 1_500_000_000 })
        );
    }

    #[test]
    fn a_transfers_fee_reads_from_what_finney_answered() {
        // `query_info` for a 1-rao `transfer_keep_alive`, 2026-09-25.
        let bytes = hex::decode("e2fc6a35bd7900b344010000000000").unwrap();
        assert_eq!(partial_fee(&bytes), Some(83_123));
        assert_eq!(partial_fee(&bytes[..11]), None);
    }

    #[test]
    fn the_runtimes_verdict_is_told_as_the_code_that_fits() {
        // What Finney answered for a correctly signed transfer from an empty account.
        assert_eq!(told_by(&[1, 0, 1]).code(), "insufficient_funds");
        assert_eq!(told_by(&[1, 0, 3]).code(), "nonce");
        assert_eq!(told_by(&[1, 0, 2]).code(), "nonce");
        assert_eq!(told_by(&[1, 0, 5]).code(), "expired");
        assert_eq!(told_by(&[1, 0, 6]).code(), "upstream_unavailable");
        assert_eq!(told_by(&[1, 1, 0]).code(), "upstream_unavailable");
        assert_eq!(told_by(&[1, 0, 4]).code(), "rejected");
    }
}
