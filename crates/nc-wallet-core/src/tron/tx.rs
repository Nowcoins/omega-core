//! TRON transactions: the protobuf `raw_data` of a TRX transfer and of a
//! smart-contract call (TRC-20 `transfer` and `approve`), the transaction id,
//! and the signature.
//!
//! TRON's nodes build transactions for a caller. This wallet must not trust a
//! node with what it signs, so it writes the bytes itself, from
//! `core/Tron.proto` and `core/contract/*.proto`
//! (github.com/tronprotocol/protocol), in the order and the omissions
//! java-tron's serializer uses (a field holding its default is left out; the
//! fields come in field-number order). The result is pinned by real mainnet
//! transactions and by Trust Wallet Core's vectors (`tests/tron_encoding.rs`).
//!
//! Everything the node knows is an input: the reference block, the time, the
//! fee limit.

use sha2::{Digest as _, Sha256};

use crate::ecdsa::{RecoverableSignature, sign_digest};
use crate::evm::U256;
use crate::evm::abi;
use crate::hexutil;
use crate::key::SigningKey;
use crate::tx_error::TxError;

/// How long java-tron gives a transaction it builds, in milliseconds: its
/// expiration is the head block's time plus this (`Constant.
/// TRANSACTION_DEFAULT_EXPIRATION_TIME`).
pub const DEFAULT_EXPIRATION_MS: i64 = 60_000;

/// `TransferContract`'s number in `Transaction.Contract.ContractType`.
pub(super) const TRANSFER_CONTRACT: u64 = 1;
/// `TriggerSmartContract`'s.
pub(super) const TRIGGER_SMART_CONTRACT: u64 = 31;

pub(super) const TRANSFER_TYPE_URL: &str = "type.googleapis.com/protocol.TransferContract";
pub(super) const TRIGGER_TYPE_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// The version byte of a mainnet address.
pub(crate) const ADDRESS_PREFIX: u8 = 0x41;

/// A TRON address in the 21 bytes the protocol uses: `0x41` and the 20-byte
/// account hash.
pub type AddressBytes = [u8; 21];

/// The 21 bytes of a `T…` address.
pub fn parse_address(text: &str) -> Result<AddressBytes, TxError> {
    let bad = || TxError::Address(text.to_owned());
    let payload = bs58::decode(text).with_check(None).into_vec().map_err(|_| bad())?;
    let bytes = <AddressBytes>::try_from(payload).map_err(|_| bad())?;
    if bytes[0] != ADDRESS_PREFIX {
        return Err(bad());
    }
    Ok(bytes)
}

/// The `T…` text of an address's 21 bytes.
#[must_use]
pub fn format_address(address: &AddressBytes) -> String {
    bs58::encode(address).with_check().into_string()
}

/// The TRON form of a 20-byte account hash.
#[must_use]
pub fn address_from_hash(hash: &[u8; 20]) -> AddressBytes {
    let mut out = [ADDRESS_PREFIX; 21];
    out[1..].copy_from_slice(hash);
    out
}

/// The block a transaction names as its reference: the network accepts the
/// transaction only on a chain that has this block, so it cannot be replayed
/// on a fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceBlock {
    /// `ref_block_bytes`: the low two bytes of the block's number.
    pub bytes: [u8; 2],
    /// `ref_block_hash`: bytes 8 to 16 of the block's id.
    pub hash: [u8; 8],
}

impl ReferenceBlock {
    /// The reference for a block of `number` whose id (the 32 bytes the node
    /// calls `blockID`) is `block_id`, as java-tron's `setReference` writes
    /// it.
    #[must_use]
    pub fn from_block(number: u64, block_id: &[u8; 32]) -> Self {
        let low = (number & 0xffff).to_be_bytes();
        let mut hash = [0u8; 8];
        hash.copy_from_slice(&block_id[8..16]);
        Self { bytes: [low[6], low[7]], hash }
    }
}

/// The contract a transaction carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Contract {
    /// `TransferContract`: TRX.
    Transfer {
        /// The sender.
        owner: AddressBytes,
        /// The recipient.
        to: AddressBytes,
        /// The amount, in sun (1 TRX = 1,000,000 sun).
        amount: u64,
    },
    /// `TriggerSmartContract`: a call to a contract (a TRC-20 token's
    /// `transfer` or `approve`).
    TriggerSmartContract {
        /// The sender.
        owner: AddressBytes,
        /// The contract.
        contract: AddressBytes,
        /// TRX sent with the call, in sun; zero for a token call.
        call_value: u64,
        /// The ABI-encoded call.
        data: Vec<u8>,
    },
}

/// A TRON transaction, with everything its `raw_data` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronTransaction {
    /// The block the transaction is anchored to.
    pub reference_block: ReferenceBlock,
    /// When the transaction was made, in milliseconds since the Unix epoch.
    pub timestamp_ms: i64,
    /// When it stops being valid, in milliseconds since the Unix epoch;
    /// [`DEFAULT_EXPIRATION_MS`] after the head block's time is what a node
    /// gives.
    pub expiration_ms: i64,
    /// The memo (`raw_data.data`), if any.
    pub memo: Option<Vec<u8>>,
    /// What the transaction does.
    pub contract: Contract,
    /// The most TRX, in sun, a contract call may burn for energy; required for
    /// a call and for nothing else.
    pub fee_limit: Option<u64>,
}

/// A signed TRON transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The `raw_data` that was signed.
    pub raw_data: Vec<u8>,
    /// The transaction id: the SHA-256 of `raw_data`.
    pub txid: [u8; 32],
    /// The signature as TRON carries it: `r ‖ s ‖ recovery id` (0 or 1).
    pub signature: [u8; 65],
    /// The `Transaction` message (`raw_data`, then the signature) that
    /// `/wallet/broadcasthex` takes.
    pub transaction: Vec<u8>,
}

impl SignedTransaction {
    /// The transaction id as hex.
    #[must_use]
    pub fn txid_hex(&self) -> String {
        hexutil::encode(&self.txid)
    }

    /// The `Transaction` message as hex, the body of a `broadcasthex` call.
    #[must_use]
    pub fn transaction_hex(&self) -> String {
        hexutil::encode(&self.transaction)
    }
}

impl TronTransaction {
    /// A TRX transfer.
    pub fn trx_transfer(
        owner: AddressBytes,
        to: AddressBytes,
        amount: u64,
        reference_block: ReferenceBlock,
        timestamp_ms: i64,
        expiration_ms: i64,
    ) -> Result<Self, TxError> {
        let tx = Self {
            reference_block,
            timestamp_ms,
            expiration_ms,
            memo: None,
            contract: Contract::Transfer { owner, to, amount },
            fee_limit: None,
        };
        tx.validate()?;
        Ok(tx)
    }

    /// A TRC-20 `transfer(to, amount)` on `token`.
    #[allow(clippy::too_many_arguments)]
    pub fn trc20_transfer(
        owner: AddressBytes,
        token: AddressBytes,
        to: &AddressBytes,
        amount: &U256,
        fee_limit: u64,
        reference_block: ReferenceBlock,
        timestamp_ms: i64,
        expiration_ms: i64,
    ) -> Result<Self, TxError> {
        let data = abi::erc20_transfer(&hash_of(to), amount);
        Self::call(owner, token, data, fee_limit, reference_block, timestamp_ms, expiration_ms)
    }

    /// A TRC-20 `approve(spender, amount)` on `token`.
    #[allow(clippy::too_many_arguments)]
    pub fn trc20_approve(
        owner: AddressBytes,
        token: AddressBytes,
        spender: &AddressBytes,
        amount: &U256,
        fee_limit: u64,
        reference_block: ReferenceBlock,
        timestamp_ms: i64,
        expiration_ms: i64,
    ) -> Result<Self, TxError> {
        let data = abi::erc20_approve(&hash_of(spender), amount);
        Self::call(owner, token, data, fee_limit, reference_block, timestamp_ms, expiration_ms)
    }

    /// A call to a contract with no TRX sent along.
    pub fn call(
        owner: AddressBytes,
        contract: AddressBytes,
        data: Vec<u8>,
        fee_limit: u64,
        reference_block: ReferenceBlock,
        timestamp_ms: i64,
        expiration_ms: i64,
    ) -> Result<Self, TxError> {
        let tx = Self {
            reference_block,
            timestamp_ms,
            expiration_ms,
            memo: None,
            contract: Contract::TriggerSmartContract { owner, contract, call_value: 0, data },
            fee_limit: Some(fee_limit),
        };
        tx.validate()?;
        Ok(tx)
    }

    /// Reads the `raw_data` of a transaction somebody else built (a web page's), strictly and
    /// canonically: see [`super::raw`]. The result is not yet [`Self::validate`]d.
    pub fn from_raw_data(raw: &[u8]) -> Result<Self, super::raw::RawDataError> {
        super::raw::parse(raw)
    }

    /// The same transaction with a memo.
    #[must_use]
    pub fn with_memo(mut self, memo: &[u8]) -> Self {
        self.memo = Some(memo.to_vec());
        self
    }

    /// The account that signs.
    #[must_use]
    pub fn owner(&self) -> &AddressBytes {
        match &self.contract {
            Contract::Transfer { owner, .. } | Contract::TriggerSmartContract { owner, .. } => {
                owner
            }
        }
    }

    /// Refuses a transaction the network would not take, before it is signed.
    pub fn validate(&self) -> Result<(), TxError> {
        if self.timestamp_ms <= 0 {
            return Err(TxError::invalid("timestamp", "must be after the epoch"));
        }
        if self.expiration_ms <= self.timestamp_ms {
            return Err(TxError::invalid("expiration", "must be after the timestamp"));
        }
        match &self.contract {
            Contract::Transfer { owner, to, amount } => {
                if *amount == 0 || i64::try_from(*amount).is_err() {
                    return Err(TxError::invalid("amount", "must be from 1 to 2^63 - 1 sun"));
                }
                if owner == to {
                    return Err(TxError::invalid("recipient", "is the sender"));
                }
                if self.fee_limit.is_some() {
                    return Err(TxError::invalid("fee limit", "a TRX transfer has none"));
                }
            }
            Contract::TriggerSmartContract { call_value, .. } => {
                if i64::try_from(*call_value).is_err() {
                    return Err(TxError::invalid("call value", "is above 2^63 - 1 sun"));
                }
                match self.fee_limit {
                    Some(limit) if limit > 0 && i64::try_from(limit).is_ok() => {}
                    _ => {
                        return Err(TxError::invalid(
                            "fee limit",
                            "a contract call needs one from 1 to 2^63 - 1 sun",
                        ));
                    }
                }
            }
        }
        let (owner, others): (&AddressBytes, Vec<&AddressBytes>) = match &self.contract {
            Contract::Transfer { owner, to, .. } => (owner, vec![to]),
            Contract::TriggerSmartContract { owner, contract, .. } => (owner, vec![contract]),
        };
        if owner[0] != ADDRESS_PREFIX || others.iter().any(|a| a[0] != ADDRESS_PREFIX) {
            return Err(TxError::invalid("address", "is not a TRON mainnet address"));
        }
        Ok(())
    }

    /// The `Transaction.raw` message, protobuf-encoded as java-tron writes
    /// it: `ref_block_bytes` (1), `ref_block_hash` (4), `expiration` (8),
    /// `data` (10), `contract` (11), `timestamp` (14), `fee_limit` (18), a
    /// field left out when it holds its default.
    #[must_use]
    pub fn raw_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        put_bytes(&mut out, 1, &self.reference_block.bytes);
        put_bytes(&mut out, 4, &self.reference_block.hash);
        put_varint_field(&mut out, 8, self.expiration_ms.cast_unsigned());
        if let Some(memo) = self.memo.as_deref().filter(|m| !m.is_empty()) {
            put_bytes(&mut out, 10, memo);
        }
        put_bytes(&mut out, 11, &self.contract_message());
        put_varint_field(&mut out, 14, self.timestamp_ms.cast_unsigned());
        if let Some(limit) = self.fee_limit {
            put_varint_field(&mut out, 18, limit);
        }
        out
    }

    /// `Transaction.Contract`: the type (1) and the parameter (2), an `Any` of
    /// the type's URL (1) and its message (2).
    fn contract_message(&self) -> Vec<u8> {
        let (type_number, url, value) = match &self.contract {
            Contract::Transfer { owner, to, amount } => {
                let mut value = Vec::with_capacity(48);
                put_bytes(&mut value, 1, owner);
                put_bytes(&mut value, 2, to);
                put_varint_field(&mut value, 3, *amount);
                (TRANSFER_CONTRACT, TRANSFER_TYPE_URL, value)
            }
            Contract::TriggerSmartContract { owner, contract, call_value, data } => {
                let mut value = Vec::with_capacity(64 + data.len());
                put_bytes(&mut value, 1, owner);
                put_bytes(&mut value, 2, contract);
                put_varint_field(&mut value, 3, *call_value);
                put_bytes(&mut value, 4, data);
                (TRIGGER_SMART_CONTRACT, TRIGGER_TYPE_URL, value)
            }
        };
        let mut any = Vec::with_capacity(url.len() + value.len() + 8);
        put_bytes(&mut any, 1, url.as_bytes());
        put_bytes(&mut any, 2, &value);
        let mut contract = Vec::with_capacity(any.len() + 8);
        put_varint_field(&mut contract, 1, type_number);
        put_bytes(&mut contract, 2, &any);
        contract
    }

    /// The transaction id: the SHA-256 of [`Self::raw_data`]. This is also the
    /// digest that is signed.
    #[must_use]
    pub fn txid(&self) -> [u8; 32] {
        sha256(&self.raw_data())
    }

    /// Signs the transaction with `key`, which must be the key of the
    /// transaction's owner.
    pub fn sign(&self, key: &SigningKey) -> Result<SignedTransaction, TxError> {
        self.validate()?;
        let owner_hash = crate::tron::address_hash_of_public_key(key.public_key())
            .ok_or(TxError::WrongKeyScheme)?;
        if address_from_hash(&owner_hash) != *self.owner() {
            return Err(TxError::invalid("owner", "is not the address of the signing key"));
        }
        let raw_data = self.raw_data();
        let txid = sha256(&raw_data);
        let signature: RecoverableSignature = sign_digest(key, &txid)?;
        let signature = signature.to_rsv(0);
        let transaction = signed_message(&raw_data, &signature);
        Ok(SignedTransaction { raw_data, txid, signature, transaction })
    }
}

/// The 20-byte account hash inside a 21-byte address.
fn hash_of(address: &AddressBytes) -> [u8; 20] {
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&address[1..]);
    hash
}

/// SHA-256.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// A `Transaction` message as `/wallet/broadcasthex` takes it: the body as
/// `raw_data` (field 1), then the one signature (field 2, 65 bytes).
fn signed_message(raw_data: &[u8], signature: &[u8; 65]) -> Vec<u8> {
    let mut message = Vec::with_capacity(raw_data.len() + 80);
    put_bytes(&mut message, 1, raw_data);
    put_bytes(&mut message, 2, signature);
    message
}

/// A varint in its shortest form.
fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A length-delimited field (wire type 2), left out when empty.
fn put_bytes(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    put_varint(out, u64::from(field) << 3 | 2);
    put_varint(out, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(bytes);
}

/// A varint field (wire type 0), left out when zero.
fn put_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    if value == 0 {
        return;
    }
    put_varint(out, u64::from(field) << 3);
    put_varint(out, value);
}
