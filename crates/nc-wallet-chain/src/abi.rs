//! The little ABI this crate speaks: a token's `balanceOf`, a Chainlink feed's
//! `latestRoundData`, and Multicall3's `aggregate3`, which reads many things in
//! one `eth_call`.
//!
//! Multicall3 is deployed at the same address on Ethereum, BNB Chain, Polygon
//! and Base. One call for a wallet's coin and every token it lists, and one for
//! every price, keeps an app opening to a handful of requests.

use nc_wallet_core::evm::abi::selector;

use crate::util::{pad_address, pad_u128, word_to_u128};

/// Multicall3, the same on every EVM network the wallet lists.
pub const MULTICALL3: &str = "0xcA11bde05977b3631167028862bE2a173976CA11";

/// One call inside a multicall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubCall {
    /// The contract.
    pub target: [u8; 20],
    /// Its calldata.
    pub data: Vec<u8>,
}

/// What a sub-call returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubResult {
    /// Whether it succeeded.
    pub success: bool,
    /// What it returned.
    pub data: Vec<u8>,
}

/// `balanceOf(address)`.
#[must_use]
pub fn balance_of(owner: &[u8; 20]) -> Vec<u8> {
    let mut data = selector("balanceOf(address)").to_vec();
    data.extend_from_slice(&pad_address(owner));
    data
}

/// Multicall3's `getEthBalance(address)`: the native balance, as a sub-call.
#[must_use]
pub fn eth_balance(owner: &[u8; 20]) -> Vec<u8> {
    let mut data = selector("getEthBalance(address)").to_vec();
    data.extend_from_slice(&pad_address(owner));
    data
}

/// `latestRoundData()` of a Chainlink aggregator.
#[must_use]
pub fn latest_round_data() -> Vec<u8> {
    selector("latestRoundData()").to_vec()
}

/// `decimals()`.
#[must_use]
pub fn decimals() -> Vec<u8> {
    selector("decimals()").to_vec()
}

/// `description()`.
#[must_use]
pub fn description() -> Vec<u8> {
    selector("description()").to_vec()
}

/// An `ERC-20` `transfer(address,uint256)` call.
#[must_use]
pub fn erc20_transfer(to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = selector("transfer(address,uint256)").to_vec();
    data.extend_from_slice(&pad_address(to));
    data.extend_from_slice(&pad_u128(amount));
    data
}

/// `getL1FeeUpperBound(uint256)` of an OP-stack rollup's gas price oracle: the
/// most the L1 data fee of an unsigned transaction of `size` bytes can be at
/// the current L1 prices.
#[must_use]
pub fn l1_fee_upper_bound(size: u128) -> Vec<u8> {
    let mut data = selector("getL1FeeUpperBound(uint256)").to_vec();
    data.extend_from_slice(&pad_u128(size));
    data
}

/// Encodes `aggregate3((address,bool,bytes)[])` with every call allowed to fail
/// on its own.
#[must_use]
pub fn aggregate3(calls: &[SubCall]) -> Vec<u8> {
    let mut data = selector("aggregate3((address,bool,bytes)[])").to_vec();
    // The one argument is dynamic: its offset (one word), then the array.
    data.extend_from_slice(&pad_u128(32));
    data.extend_from_slice(&pad_u128(calls.len() as u128));
    // Each element is a dynamic tuple, so the array holds offsets (from the
    // start of the offsets) to the elements.
    let mut elements: Vec<Vec<u8>> = Vec::with_capacity(calls.len());
    for call in calls {
        let mut element = Vec::new();
        element.extend_from_slice(&pad_address(&call.target));
        element.extend_from_slice(&pad_u128(1)); // allowFailure
        element.extend_from_slice(&pad_u128(96)); // offset of the bytes: after 3 words
        element.extend_from_slice(&pad_u128(call.data.len() as u128));
        element.extend_from_slice(&call.data);
        let padding = (32 - call.data.len() % 32) % 32;
        element.extend(std::iter::repeat_n(0_u8, padding));
        elements.push(element);
    }
    let mut offset = calls.len() * 32;
    for element in &elements {
        data.extend_from_slice(&pad_u128(offset as u128));
        offset += element.len();
    }
    for element in elements {
        data.extend_from_slice(&element);
    }
    data
}

fn word_at(bytes: &[u8], at: usize) -> Option<usize> {
    let word = bytes.get(at..at.checked_add(32)?)?;
    usize::try_from(word_to_u128(word)?).ok()
}

/// Decodes what `aggregate3` returns: `(bool success, bytes returnData)[]`.
/// `None` for anything that is not that, or that claims more than the bytes
/// hold.
#[must_use]
pub fn decode_aggregate3(bytes: &[u8]) -> Option<Vec<SubResult>> {
    let array = word_at(bytes, 0)?;
    let count = word_at(bytes, array)?;
    if count > 1024 {
        return None;
    }
    let offsets_at = array.checked_add(32)?;
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let element =
            offsets_at.checked_add(word_at(bytes, offsets_at.checked_add(index * 32)?)?)?;
        let success = word_at(bytes, element)? == 1;
        let data_at = element.checked_add(word_at(bytes, element.checked_add(32)?)?)?;
        let length = word_at(bytes, data_at)?;
        let start = data_at.checked_add(32)?;
        let data = bytes.get(start..start.checked_add(length)?)?.to_vec();
        out.push(SubResult { success, data });
    }
    Some(out)
}

/// A Solidity `string` return value (`description()`): offset, length, bytes.
#[must_use]
pub fn decode_string(bytes: &[u8]) -> Option<String> {
    let at = word_at(bytes, 0)?;
    let length = word_at(bytes, at)?;
    let start = at.checked_add(32)?;
    let raw = bytes.get(start..start.checked_add(length)?)?;
    String::from_utf8(raw.to_vec()).ok()
}

/// The five words `latestRoundData` returns: round id, answer, started at,
/// updated at, answered in round. Only the answer (a signed integer) and the
/// time it was written are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Round {
    /// The round's id: the aggregator's phase in the high bits, its own round below.
    pub round: u128,
    /// The answer, scaled by the feed's `decimals()`.
    pub answer: u128,
    /// When the feed wrote it, Unix seconds.
    pub updated_at: u64,
}

/// Reads `latestRoundData()`'s return. A negative answer, a zero answer or a
/// zero time is no price.
#[must_use]
pub fn decode_round(bytes: &[u8]) -> Option<Round> {
    if bytes.len() < 160 {
        return None;
    }
    // `int256 answer`: the sign is the top bit of its first byte.
    let answer_word = bytes.get(32..64)?;
    if answer_word.first().is_some_and(|b| b & 0x80 != 0) {
        return None;
    }
    let answer = word_to_u128(answer_word)?;
    let updated_at = u64::try_from(word_to_u128(bytes.get(96..128)?)?).ok()?;
    let round = word_to_u128(bytes.get(..32)?)?;
    (answer > 0 && updated_at > 0).then_some(Round { round, answer, updated_at })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: [u8; 20] = [0xaa; 20];
    const ME: [u8; 20] = [0x11; 20];

    #[test]
    fn selectors_are_the_standard_ones() {
        assert_eq!(hex::encode(&balance_of(&ME)[..4]), "70a08231");
        assert_eq!(hex::encode(latest_round_data()), "feaf968c");
        assert_eq!(hex::encode(decimals()), "313ce567");
        assert_eq!(hex::encode(description()), "7284e416");
        assert_eq!(hex::encode(&eth_balance(&ME)[..4]), "4d2301cc");
        assert_eq!(hex::encode(&l1_fee_upper_bound(130)[..4]), "f1c7a58b");
        assert_eq!(hex::encode(&erc20_transfer(&ME, 1)[..4]), "a9059cbb");
        assert_eq!(hex::encode(&aggregate3(&[])[..4]), "82ad56cb");
    }

    #[test]
    fn aggregate3_is_laid_out_as_the_abi_says() {
        let calls = [
            SubCall { target: TOKEN, data: balance_of(&ME) },
            SubCall { target: ME, data: vec![0x01, 0x02, 0x03] },
        ];
        let data = aggregate3(&calls);
        let body = &data[4..];
        // offset of the array, its length, two element offsets.
        assert_eq!(word_at(body, 0), Some(32));
        assert_eq!(word_at(body, 32), Some(2));
        let first = word_at(body, 64).unwrap();
        let second = word_at(body, 96).unwrap();
        assert_eq!(first, 64, "after the two offsets");
        // The first element: target, allowFailure, offset 96, length 36, 36 bytes padded to 64.
        let element = 64 + first;
        assert_eq!(&body[element + 12..element + 32], &TOKEN);
        assert_eq!(word_at(body, element + 32), Some(1));
        assert_eq!(word_at(body, element + 64), Some(96));
        assert_eq!(word_at(body, element + 96), Some(36));
        assert_eq!(second - first, 3 * 32 + 32 + 64);
        // Everything is a whole number of words.
        assert_eq!(body.len() % 32, 0);
    }

    /// What Multicall3 returns for two calls: one success with a word, one failure.
    fn answer(results: &[(bool, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&pad_u128(32));
        out.extend_from_slice(&pad_u128(results.len() as u128));
        let mut elements = Vec::new();
        for (success, data) in results {
            let mut element = Vec::new();
            element.extend_from_slice(&pad_u128(u128::from(*success)));
            element.extend_from_slice(&pad_u128(64));
            element.extend_from_slice(&pad_u128(data.len() as u128));
            element.extend_from_slice(data);
            element.extend(std::iter::repeat_n(0_u8, (32 - data.len() % 32) % 32));
            elements.push(element);
        }
        let mut offset = results.len() * 32;
        for element in &elements {
            out.extend_from_slice(&pad_u128(offset as u128));
            offset += element.len();
        }
        for element in elements {
            out.extend_from_slice(&element);
        }
        out
    }

    #[test]
    fn a_multicall_answer_is_read_and_a_lying_length_is_refused() {
        let bytes = answer(&[(true, pad_u128(291_368_219).to_vec()), (false, Vec::new())]);
        let results = decode_aggregate3(&bytes).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert_eq!(word_to_u128(&results[0].data), Some(291_368_219));
        assert!(!results[1].success && results[1].data.is_empty());
        // Cut short, or claiming more than there is.
        assert_eq!(decode_aggregate3(&bytes[..bytes.len() - 40]), None);
        let mut lie = bytes.clone();
        lie[64..96].copy_from_slice(&pad_u128(u128::MAX >> 8));
        assert_eq!(decode_aggregate3(&lie), None);
        assert_eq!(decode_aggregate3(&[]), None);
    }

    #[test]
    fn a_round_is_an_answer_and_the_time_it_was_written() {
        let mut bytes = Vec::new();
        for word in [1_u128, 9_654_312_345_678, 5, 1_793_058_000, 1] {
            bytes.extend_from_slice(&pad_u128(word));
        }
        assert_eq!(
            decode_round(&bytes),
            Some(Round { round: 1, answer: 9_654_312_345_678, updated_at: 1_793_058_000 })
        );
        // A negative answer is no price.
        bytes[32] = 0xff;
        assert_eq!(decode_round(&bytes), None);
        assert_eq!(decode_round(&bytes[..100]), None);
    }

    #[test]
    fn a_string_return_is_offset_length_bytes() {
        let mut bytes = pad_u128(32).to_vec();
        bytes.extend_from_slice(&pad_u128(9));
        bytes.extend_from_slice(b"ETH / USD");
        bytes.extend_from_slice(&[0; 23]);
        assert_eq!(decode_string(&bytes).as_deref(), Some("ETH / USD"));
    }
}
