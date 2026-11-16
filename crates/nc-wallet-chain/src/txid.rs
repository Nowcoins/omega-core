//! A signed transaction's id, worked out from its bytes.
//!
//! The wallet's own signer already returns the id of what it made, but a
//! broadcast is asked about by bytes (and a retry, a duplicate and a status
//! all need the id), so the id is worked out again here from the bytes that are
//! actually sent. Doing so reads just enough of each format to find what the
//! id is the hash of, and refuses what is not a signed transaction of that
//! network: an unsigned one, a truncated one, one with bytes left over.
//!
//! | Network | The id |
//! |---|---|
//! | EVM | Keccak-256 of the signed bytes |
//! | TRON | SHA-256 of the `raw_data` protobuf |
//! | Bitcoin | double SHA-256 of the serialization without the witnesses |
//! | Solana | the first signature, in base58 |
//! | Stellar | SHA-256 of the network id, the envelope type and the transaction |
//! | Bittensor | BLAKE2b-256 of the extrinsic |

use nc_wallet_core::bittensor::extrinsic::blake2_256;
use nc_wallet_core::stellar::PUBLIC_NETWORK_PASSPHRASE;
use nc_wallet_core::stellar::xdr::{network_id, transaction_hash};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use crate::error::{ChainError, ChainResult};
use crate::networks::{Family, Network};
use crate::util::to_hex;

/// The most bytes of a transaction taken.
const MAX_RAW: usize = 125_000;

fn bad(network: Network, why: &str) -> ChainError {
    ChainError::InvalidTransaction(format!("not a {} transaction: {why}", network.name()))
}

/// The id of the signed transaction `raw` on `network`.
pub fn of(network: Network, raw: &[u8]) -> ChainResult<String> {
    if raw.is_empty() || raw.len() > MAX_RAW {
        return Err(bad(network, "its size"));
    }
    match network.family() {
        Family::Evm => evm(network, raw),
        Family::Tron => tron(network, raw),
        Family::Bitcoin => bitcoin(network, raw),
        Family::Solana => solana(network, raw),
        Family::Stellar => stellar(network, raw),
        Family::Substrate => substrate(network, raw),
    }
}

fn evm(network: Network, raw: &[u8]) -> ChainResult<String> {
    // A legacy transaction is an RLP list (0xc0..); a typed one starts with its
    // type: EIP-2930 (1) or EIP-1559 (2). Blobs and authorisations are not sent.
    match raw.first() {
        Some(0x01 | 0x02 | 0xc0..=0xff) => Ok(to_hex(&Keccak256::digest(raw))),
        _ => Err(bad(network, "unknown transaction type")),
    }
}

fn varint(input: &mut &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = input.split_first()?;
        *input = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn tron(network: Network, raw: &[u8]) -> ChainResult<String> {
    let mut input = raw;
    let mut body: Option<&[u8]> = None;
    let mut signatures = 0;
    while !input.is_empty() {
        let key = varint(&mut input).ok_or_else(|| bad(network, "not protobuf"))?;
        let (number, wire) = (key >> 3, key & 7);
        if wire != 2 {
            return Err(bad(network, "an unexpected field"));
        }
        let length =
            usize::try_from(varint(&mut input).ok_or_else(|| bad(network, "not protobuf"))?)
                .map_err(|_| bad(network, "not protobuf"))?;
        let (value, rest) =
            input.split_at_checked(length).ok_or_else(|| bad(network, "cut short"))?;
        input = rest;
        match number {
            1 if body.is_none() => body = Some(value),
            2 if value.len() == 65 => signatures += 1,
            _ => return Err(bad(network, "an unexpected field")),
        }
    }
    let body = body.ok_or_else(|| bad(network, "no body"))?;
    if signatures == 0 {
        return Err(bad(network, "not signed"));
    }
    Ok(hex::encode(Sha256::digest(body)))
}

fn compact(input: &mut &[u8]) -> Option<u64> {
    let (&first, rest) = input.split_first()?;
    *input = rest;
    let width = match first {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        small => return Some(u64::from(small)),
    };
    let (bytes, rest) = input.split_at_checked(width)?;
    *input = rest;
    let mut value = 0_u64;
    for (shift, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (8 * shift);
    }
    Some(value)
}

fn bitcoin(network: Network, raw: &[u8]) -> ChainResult<String> {
    let cut = || bad(network, "cut short");
    let mut input = raw;
    let version = input.get(..4).ok_or_else(cut)?;
    input = &input[4..];
    // Marker and flag mark a segwit serialization.
    let segwit = input.starts_with(&[0x00, 0x01]);
    if segwit {
        input = &input[2..];
    }
    let body_start = input;
    let inputs = compact(&mut input).ok_or_else(cut)?;
    if inputs == 0 || inputs > 10_000 {
        return Err(bad(network, "its inputs"));
    }
    let mut unsigned_inputs = 0_u64;
    for _ in 0..inputs {
        input = input.get(36..).ok_or_else(cut)?;
        let script = usize::try_from(compact(&mut input).ok_or_else(cut)?).map_err(|_| cut())?;
        if script != 0 {
            unsigned_inputs += 1;
        }
        input = input.get(script + 4..).ok_or_else(cut)?;
    }
    let outputs = compact(&mut input).ok_or_else(cut)?;
    if outputs == 0 || outputs > 10_000 {
        return Err(bad(network, "its outputs"));
    }
    for _ in 0..outputs {
        input = input.get(8..).ok_or_else(cut)?;
        let script = usize::try_from(compact(&mut input).ok_or_else(cut)?).map_err(|_| cut())?;
        input = input.get(script..).ok_or_else(cut)?;
    }
    // Everything from the input count to here is what the id covers.
    let covered = body_start.len() - input.len();
    let body = &body_start[..covered];
    if segwit {
        let mut witnesses = 0_u64;
        for _ in 0..inputs {
            let items = compact(&mut input).ok_or_else(cut)?;
            if items > 0 {
                witnesses += 1;
            }
            for _ in 0..items {
                let length =
                    usize::try_from(compact(&mut input).ok_or_else(cut)?).map_err(|_| cut())?;
                input = input.get(length..).ok_or_else(cut)?;
            }
        }
        // Every input is signed by a witness or a script.
        if witnesses + unsigned_inputs < inputs {
            return Err(bad(network, "an input is not signed"));
        }
    } else if unsigned_inputs < inputs {
        return Err(bad(network, "an input is not signed"));
    }
    let lock_time = input.get(..4).ok_or_else(cut)?;
    if input.len() != 4 {
        return Err(bad(network, "bytes after the end"));
    }
    let mut legacy = Vec::with_capacity(8 + body.len());
    legacy.extend_from_slice(version);
    legacy.extend_from_slice(body);
    legacy.extend_from_slice(lock_time);
    let mut id: [u8; 32] = Sha256::digest(Sha256::digest(&legacy)).into();
    id.reverse();
    Ok(hex::encode(id))
}

fn solana(network: Network, raw: &[u8]) -> ChainResult<String> {
    let cut = || bad(network, "cut short");
    let mut input = raw;
    // The signature count is a compact-u16.
    let mut count = 0_usize;
    for shift in [0, 7, 14] {
        let (&byte, rest) = input.split_first().ok_or_else(cut)?;
        input = rest;
        count |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if count == 0 || count > 16 {
        return Err(bad(network, "its signatures"));
    }
    let signatures = input.get(..count * 64).ok_or_else(cut)?;
    if signatures.chunks(64).any(|s| s.iter().all(|b| *b == 0)) {
        return Err(bad(network, "a signature is missing"));
    }
    if input.len() == count * 64 {
        return Err(bad(network, "no message"));
    }
    Ok(bs58::encode(&signatures[..64]).into_string())
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// A signature in an envelope: its hint (4 bytes), a length word (4) and 64 bytes.
const SIGNATURE: usize = 72;

fn stellar(network: Network, raw: &[u8]) -> ChainResult<String> {
    if !raw.len().is_multiple_of(4) {
        return Err(bad(network, "XDR is a whole number of words"));
    }
    // ENVELOPE_TYPE_TX: a version-1 transaction envelope.
    if u32_at(raw, 0) != Some(2) {
        return Err(bad(network, "only a version-1 transaction envelope is taken"));
    }
    // The signatures are last: a count, then a hint and a 64-byte signature each.
    let (count_at, count) = (1..=20_usize)
        .find_map(|count| {
            let at = raw.len().checked_sub(4 + count * SIGNATURE)?;
            (at >= 4 && u32_at(raw, at) == Some(u32::try_from(count).ok()?)).then_some((at, count))
        })
        .ok_or_else(|| bad(network, "no signatures at its end"))?;
    for index in 0..count {
        let at = count_at + 4 + index * SIGNATURE + 4;
        if u32_at(raw, at) != Some(64) || raw[at + 4..at + 68].iter().all(|b| *b == 0) {
            return Err(bad(network, "a signature is missing"));
        }
    }
    let body = &raw[4..count_at];
    Ok(hex::encode(transaction_hash(&network_id(PUBLIC_NETWORK_PASSPHRASE), body)))
}

fn substrate(network: Network, raw: &[u8]) -> ChainResult<String> {
    // A signed extrinsic is a compact length, then a version byte whose top bit
    // marks "signed" (0x84 is version 4, signed).
    let mut input = raw;
    let length =
        usize::try_from(compact_scale(&mut input).ok_or_else(|| bad(network, "its length"))?)
            .map_err(|_| bad(network, "its length"))?;
    if input.len() != length || input.first() != Some(&0x84) {
        return Err(bad(network, "not a signed extrinsic of version 4"));
    }
    Ok(to_hex(&blake2_256(raw)))
}

/// SCALE's compact integer, as far as a length needs.
fn compact_scale(input: &mut &[u8]) -> Option<u64> {
    let (&first, rest) = input.split_first()?;
    match first & 0b11 {
        0 => {
            *input = rest;
            Some(u64::from(first >> 2))
        }
        1 => {
            let (&second, rest) = rest.split_first()?;
            *input = rest;
            Some(u64::from(u16::from_le_bytes([first, second]) >> 2))
        }
        2 => {
            let bytes: [u8; 4] = rest.get(..3).map(|r| [first, r[0], r[1], r[2]])?;
            *input = &rest[3..];
            Some(u64::from(u32::from_le_bytes(bytes) >> 2))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use serde_json::Value;

    use super::*;

    fn vectors(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn bitcoin_ids_match_real_mainnet_transactions() {
        let all = vectors(include_str!(
            "../../nc-wallet-core/tests/vectors/real-bitcoin-transactions.json"
        ));
        let transactions = all["transactions"].as_array().unwrap();
        assert!(!transactions.is_empty());
        for transaction in transactions {
            let raw = hex::decode(transaction["raw"].as_str().unwrap()).unwrap();
            assert_eq!(of(Network::Bitcoin, &raw).unwrap(), transaction["txid"].as_str().unwrap());
            // Cut short, or with a byte too many: not a transaction.
            assert!(of(Network::Bitcoin, &raw[..raw.len() - 1]).is_err());
            let mut long = raw.clone();
            long.push(0);
            assert!(of(Network::Bitcoin, &long).is_err());
        }
    }

    #[test]
    fn tron_ids_match_real_transactions() {
        let all =
            vectors(include_str!("../../nc-wallet-core/tests/vectors/real-tron-transactions.json"));
        for transaction in all["transactions"].as_array().unwrap() {
            // A signed transaction: field 1 is raw_data, field 2 the signature.
            let body = hex::decode(transaction["raw_data_hex"].as_str().unwrap()).unwrap();
            let signature = hex::decode(transaction["signature"].as_str().unwrap()).unwrap();
            let mut raw = vec![0x0a];
            push_varint(&mut raw, body.len());
            raw.extend_from_slice(&body);
            raw.push(0x12);
            push_varint(&mut raw, signature.len());
            raw.extend_from_slice(&signature);
            assert_eq!(of(Network::Tron, &raw).unwrap(), transaction["txID"].as_str().unwrap());
        }
        // Without its signature it is not sent.
        let unsigned = [0x0a, 0x01, 0x00];
        assert!(of(Network::Tron, &unsigned).is_err());
    }

    fn push_varint(out: &mut Vec<u8>, mut value: usize) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).unwrap());
    }

    #[test]
    fn solana_ids_match_real_transactions() {
        let all = vectors(include_str!(
            "../../nc-wallet-core/tests/vectors/solana-mainnet-transactions.json"
        ));
        for (name, transaction) in all["transactions"].as_object().unwrap() {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(transaction["transaction_base64"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                of(Network::Solana, &raw).unwrap(),
                transaction["signature"].as_str().unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn stellar_ids_match_real_transactions() {
        let all = vectors(include_str!(
            "../../nc-wallet-core/tests/vectors/stellar-public-network-transactions.json"
        ));
        for (name, entry) in all["transactions"].as_object().unwrap() {
            let envelope = base64::engine::general_purpose::STANDARD
                .decode(entry["transaction"]["envelope_xdr"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                of(Network::Stellar, &envelope).unwrap(),
                entry["transaction"]["hash"].as_str().unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn evm_ids_match_real_transactions_and_unknown_types_are_refused() {
        // A transfer's raw bytes are hashed whole; the type byte is looked at.
        assert!(of(Network::Ethereum, &[0x02, 0xc0]).is_ok());
        assert!(of(Network::Ethereum, &[0xf8, 0x00]).is_ok());
        assert!(of(Network::Ethereum, &[0x03, 0xc0]).is_err(), "blob transactions are not sent");
        assert!(of(Network::Ethereum, &[0x04, 0xc0]).is_err());
        assert!(of(Network::Ethereum, &[]).is_err());
    }

    #[test]
    fn bittensor_ids_are_blake2_of_a_signed_extrinsic() {
        let all = vectors(include_str!(
            "../../nc-wallet-core/tests/vectors/finney-transfer-keep-alive-extrinsics.json"
        ));
        for entry in all["extrinsics"].as_array().unwrap() {
            let raw =
                hex::decode(entry["extrinsic"].as_str().unwrap().trim_start_matches("0x")).unwrap();
            let id = of(Network::Bittensor, &raw).unwrap();
            assert_eq!(id, to_hex(&blake2_256(&raw)));
            assert!(of(Network::Bittensor, &raw[..raw.len() - 1]).is_err());
        }
    }
}
