//! Reading a TRON transaction's `raw_data` back, for a transaction a web page built.
//!
//! A dApp (`TronWeb`) builds a transaction through a node and hands the wallet its
//! `raw_data_hex`. The wallet must show the person what those bytes do and sign exactly
//! those bytes, so it reads them itself, field by field, and trusts nothing that the page's
//! JSON says about them.
//!
//! The reader is strict in two ways:
//!
//! * **It reads only what [`TronTransaction`] holds**: a TRX transfer and a smart-contract
//!   call, with a reference block, two times, an optional memo and a fee limit. Any other field,
//!   and any other kind of contract, is [`RawDataError::Unsupported`]: the contracts that
//!   change who controls an account (`AccountPermissionUpdateContract`) or that spend resources
//!   on someone else's behalf are named in the refusal, never summarised and never signed.
//! * **It is canonical**: what it read, written out again by [`TronTransaction::raw_data`], must be
//!   the very bytes it was given. A field in a different order, a default value written out, a
//!   varint longer than it needs to be, a second copy of a field: all are refused, so that
//!   two different byte strings can never read as one transaction, and what is signed (the
//!   bytes) is what was shown (the reading).

use super::tx::{
    ADDRESS_PREFIX, AddressBytes, Contract, ReferenceBlock, TRANSFER_CONTRACT, TRANSFER_TYPE_URL,
    TRIGGER_SMART_CONTRACT, TRIGGER_TYPE_URL, TronTransaction,
};

/// Why `raw_data` is not a transaction this wallet reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RawDataError {
    /// The bytes are not a transaction in the form the network writes.
    #[error("the transaction is not well formed: {0}")]
    Malformed(&'static str),
    /// A well-formed transaction of a kind this wallet does not sign.
    #[error("this wallet does not sign {0}")]
    Unsupported(&'static str),
}

/// A field's value: a varint, or a length-delimited run of bytes. The network's transactions use
/// no other wire type here.
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn varint(rest: &mut &[u8]) -> Result<u64, RawDataError> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let (&byte, tail) =
            rest.split_first().ok_or(RawDataError::Malformed("a number is cut short"))?;
        *rest = tail;
        let bits = u64::from(byte & 0x7f);
        if shift == 63 && bits > 1 {
            return Err(RawDataError::Malformed("a number is too large"));
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(RawDataError::Malformed("a number is too long"))
}

/// Every field of a message, in the order written.
fn fields(mut rest: &[u8]) -> Result<Vec<(u32, Value<'_>)>, RawDataError> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        let tag = varint(&mut rest)?;
        let number = u32::try_from(tag >> 3)
            .map_err(|_| RawDataError::Malformed("a field number is too large"))?;
        let value = match tag & 7 {
            0 => Value::Varint(varint(&mut rest)?),
            2 => {
                let length = usize::try_from(varint(&mut rest)?)
                    .map_err(|_| RawDataError::Malformed("a field is too long"))?;
                if length > rest.len() {
                    return Err(RawDataError::Malformed("a field is cut short"));
                }
                let (bytes, tail) = rest.split_at(length);
                rest = tail;
                Value::Bytes(bytes)
            }
            _ => return Err(RawDataError::Malformed("a field of a kind the network does not use")),
        };
        out.push((number, value));
    }
    Ok(out)
}

fn address(bytes: &[u8]) -> Result<AddressBytes, RawDataError> {
    let address = <AddressBytes>::try_from(bytes)
        .map_err(|_| RawDataError::Malformed("an address is not 21 bytes"))?;
    if address[0] != ADDRESS_PREFIX {
        return Err(RawDataError::Malformed("an address is not a mainnet address"));
    }
    Ok(address)
}

fn put<T>(slot: &mut Option<T>, value: T) -> Result<(), RawDataError> {
    if slot.replace(value).is_some() {
        return Err(RawDataError::Malformed("a field is written twice"));
    }
    Ok(())
}

fn time(value: u64) -> Result<i64, RawDataError> {
    i64::try_from(value).map_err(|_| RawDataError::Malformed("a time is out of range"))
}

/// What a contract type this wallet does not sign is called in the refusal.
const fn unsupported(type_number: u64) -> RawDataError {
    RawDataError::Unsupported(match type_number {
        // The classic theft: it hands the account's keys to someone else.
        46 => "an account permission update, which can hand control of the account to someone else",
        54..=59 => "staking, unstaking or delegating resources",
        2 => "a TRC-10 token transfer",
        4 => "a vote",
        30 => "the creation of a contract",
        _ => "this kind of TRON transaction",
    })
}

fn transfer(value: &[u8]) -> Result<Contract, RawDataError> {
    let (mut owner, mut to, mut amount) = (None, None, None);
    for (number, field) in fields(value)? {
        match (number, field) {
            (1, Value::Bytes(bytes)) => put(&mut owner, address(bytes)?)?,
            (2, Value::Bytes(bytes)) => put(&mut to, address(bytes)?)?,
            (3, Value::Varint(sun)) => put(&mut amount, sun)?,
            _ => return Err(RawDataError::Malformed("a transfer has a field it should not")),
        }
    }
    match (owner, to, amount) {
        (Some(owner), Some(to), Some(amount)) => Ok(Contract::Transfer { owner, to, amount }),
        _ => Err(RawDataError::Malformed("a transfer lacks a sender, a recipient or an amount")),
    }
}

fn trigger(value: &[u8]) -> Result<Contract, RawDataError> {
    let (mut owner, mut contract, mut call_value, mut data) = (None, None, None, None);
    for (number, field) in fields(value)? {
        match (number, field) {
            (1, Value::Bytes(bytes)) => put(&mut owner, address(bytes)?)?,
            (2, Value::Bytes(bytes)) => put(&mut contract, address(bytes)?)?,
            (3, Value::Varint(sun)) => put(&mut call_value, sun)?,
            (4, Value::Bytes(bytes)) => put(&mut data, bytes.to_vec())?,
            (5 | 6, _) => {
                return Err(RawDataError::Unsupported("a TRC-10 token sent along with a call"));
            }
            _ => return Err(RawDataError::Malformed("a call has a field it should not")),
        }
    }
    match (owner, contract) {
        (Some(owner), Some(contract)) => Ok(Contract::TriggerSmartContract {
            owner,
            contract,
            call_value: call_value.unwrap_or(0),
            data: data.unwrap_or_default(),
        }),
        _ => Err(RawDataError::Malformed("a call lacks a sender or a contract")),
    }
}

/// `Transaction.Contract`: the type (1) and the parameter (2), an `Any`.
fn contract(message: &[u8]) -> Result<Contract, RawDataError> {
    let (mut type_number, mut parameter) = (None, None);
    for (number, field) in fields(message)? {
        match (number, field) {
            (1, Value::Varint(kind)) => put(&mut type_number, kind)?,
            (2, Value::Bytes(any)) => put(&mut parameter, any)?,
            (5, _) => {
                return Err(RawDataError::Unsupported(
                    "a transaction signed under a permission other than the owner's",
                ));
            }
            _ => return Err(RawDataError::Malformed("a contract has a field it should not")),
        }
    }
    let (Some(kind), Some(any)) = (type_number, parameter) else {
        return Err(RawDataError::Malformed("a contract lacks its type or its parameter"));
    };
    if !matches!(kind, TRANSFER_CONTRACT | TRIGGER_SMART_CONTRACT) {
        return Err(unsupported(kind));
    }
    let (mut url, mut value) = (None, None);
    for (number, field) in fields(any)? {
        match (number, field) {
            (1, Value::Bytes(bytes)) => put(&mut url, bytes)?,
            (2, Value::Bytes(bytes)) => put(&mut value, bytes)?,
            _ => return Err(RawDataError::Malformed("a parameter has a field it should not")),
        }
    }
    let (Some(url), Some(value)) = (url, value) else {
        return Err(RawDataError::Malformed("a parameter lacks its type or its value"));
    };
    let expected = if kind == TRANSFER_CONTRACT { TRANSFER_TYPE_URL } else { TRIGGER_TYPE_URL };
    if url != expected.as_bytes() {
        return Err(RawDataError::Malformed("a contract's type and its parameter disagree"));
    }
    if kind == TRANSFER_CONTRACT { transfer(value) } else { trigger(value) }
}

/// Reads `raw` (the bytes a transaction id is the SHA-256 of) as a transaction.
pub(super) fn parse(raw: &[u8]) -> Result<TronTransaction, RawDataError> {
    let (mut ref_bytes, mut ref_hash, mut expiration, mut memo) = (None, None, None, None);
    let (mut contract_message, mut timestamp, mut fee_limit) = (None, None, None);
    for (number, field) in fields(raw)? {
        match (number, field) {
            (1, Value::Bytes(bytes)) => put(
                &mut ref_bytes,
                <[u8; 2]>::try_from(bytes)
                    .map_err(|_| RawDataError::Malformed("ref_block_bytes is not 2 bytes"))?,
            )?,
            (4, Value::Bytes(bytes)) => put(
                &mut ref_hash,
                <[u8; 8]>::try_from(bytes)
                    .map_err(|_| RawDataError::Malformed("ref_block_hash is not 8 bytes"))?,
            )?,
            (8, Value::Varint(at)) => put(&mut expiration, time(at)?)?,
            (10, Value::Bytes(bytes)) => put(&mut memo, bytes.to_vec())?,
            (11, Value::Bytes(bytes)) => {
                if contract_message.is_some() {
                    return Err(RawDataError::Unsupported("a transaction with several contracts"));
                }
                contract_message = Some(bytes);
            }
            (14, Value::Varint(at)) => put(&mut timestamp, time(at)?)?,
            (18, Value::Varint(limit)) => put(&mut fee_limit, limit)?,
            (3 | 9 | 12, _) => {
                return Err(RawDataError::Unsupported(
                    "a transaction with authorities, scripts or an old-style block number",
                ));
            }
            _ => return Err(RawDataError::Malformed("a transaction has a field it should not")),
        }
    }
    let (Some(bytes), Some(hash), Some(expiration), Some(message), Some(timestamp)) =
        (ref_bytes, ref_hash, expiration, contract_message, timestamp)
    else {
        return Err(RawDataError::Malformed("a transaction lacks a block, a time or a contract"));
    };
    let tx = TronTransaction {
        reference_block: ReferenceBlock { bytes, hash },
        timestamp_ms: timestamp,
        expiration_ms: expiration,
        memo,
        contract: contract(message)?,
        fee_limit,
    };
    // What was read, written out again, is what was given: one reading per byte string.
    if tx.raw_data() != raw {
        return Err(RawDataError::Malformed("it is not written the way the network writes it"));
    }
    Ok(tx)
}
