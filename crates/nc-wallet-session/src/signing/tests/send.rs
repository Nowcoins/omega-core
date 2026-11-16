//! Kind 6: the wallet's own transfers on the nine networks, built from the
//! wallet API's example `inputs` and `estimate` bodies (the shapes in
//! `crates/nc-wallet-chain/tests/fixtures/wallet-api/`) with the example address replaced by this
//! account's, since the request is checked against the signer.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey};
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use nc_wallet_core::bittensor::{CallIndex, Transfer};
use nc_wallet_core::evm::{self, EvmChain, EvmTransaction, Fees, U256, abi};
use nc_wallet_core::stellar::{self, Asset, Memo, Operation, TimeBounds};
use nc_wallet_core::tron::{self, ReferenceBlock, TronTransaction};
use nc_wallet_core::{Mnemonic, Network, bitcoin, derive, signing_key};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::super::hexs;
use super::evm::{pad32, recover, rlp_list};
use super::*;

fn account(network: Network, index: u32) -> nc_wallet_core::Account {
    derive(&Mnemonic::parse(ABANDON).unwrap(), "", network, index).unwrap()
}

fn address(network: Network, index: u32) -> String {
    account(network, index).address
}

fn request(
    network: &str,
    asset: Value,
    to: &str,
    amount: &str,
    inputs: Value,
    estimate: Value,
) -> Value {
    json!({
        "kind": "send", "network": network, "asset": asset, "to": to, "amount": amount,
        "inputs": inputs, "estimate": estimate,
    })
}

fn with(mut value: Value, key: &str, new: Value) -> Value {
    value[key] = new;
    value
}

// ---- EVM ----

fn evm_inputs(chain_id: u64) -> Value {
    // The wallet API's example, "inputs", EVM.
    json!({
        "network": "ethereum", "address": EVM_0, "chain_id": chain_id, "nonce": 5969,
        "gas_price": "50709286", "eip1559": true, "base_fee": "50708939",
        "max_priority_fee": "10000000", "max_fee": "111417878", "block": 26280228
    })
}

fn evm_estimate_1559() -> Value {
    // The wallet API's example, "estimate", EVM (the Base example, gas for a token transfer).
    json!({
        "network": "ethereum", "gas_limit": "65000", "gas_price": "6000000", "eip1559": true,
        "max_fee_per_gas": "111417878", "max_priority_fee_per_gas": "10000000",
        "fee": { "asset": "ETH", "amount": "7242162070000", "decimals": 18 },
        "recipient": { "is_contract": false }
    })
}

const USDT_ETH: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
const BOB: &str = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB";

fn usdt_eth() -> Value {
    json!({ "symbol": "USDT", "name": "Tether USD", "decimals": 6, "kind": "erc20", "contract": USDT_ETH })
}

fn native(symbol: &str, decimals: u8) -> Value {
    json!({ "symbol": symbol, "name": symbol, "decimals": decimals })
}

#[test]
fn an_erc20_transfer_is_built_from_the_api_and_signed() {
    let engine = engine();
    let req = request("ethereum", usdt_eth(), BOB, "5000000", evm_inputs(1), evm_estimate_1559());
    let decoded = decode(&engine, 0, &req).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["request"], "send");
    assert_eq!(s["action"], "token_transfer");
    assert_eq!(s["details"], json!({ "token": USDT_ETH, "recipient": BOB, "amount": "5000000" }));
    assert_eq!(s["tx"]["to"], USDT_ETH);
    assert_eq!(s["tx"]["nonce"], "5969");
    assert_eq!(s["tx"]["gas_limit"], "65000");
    assert_eq!(s["tx"]["type"], "eip1559");
    assert_eq!(s["fee"], json!({ "asset": "ETH", "amount": "7242162070000", "decimals": 18 }));
    assert_eq!(s["warnings"], json!([]));

    let signed = sign(&engine, 0, &req);
    assert_eq!(signed["network"], "ethereum");
    assert_eq!(signed["encoding"], "hex");
    let raw = hex(signed["raw"].as_str().unwrap());
    assert_eq!(signed["hash"], hexs::encode_0x(&evm::tx::keccak(&raw)));

    let tx = EvmTransaction {
        chain_id: 1,
        nonce: 5969,
        to: evm::parse_address(USDT_ETH).unwrap(),
        value: 0,
        data: abi::erc20_transfer(&evm::parse_address(BOB).unwrap(), &U256::from(5_000_000_u64)),
        gas_limit: 65_000,
        fees: Fees::Eip1559 { max_fee_per_gas: 111_417_878, max_priority_fee_per_gas: 10_000_000 },
    };
    let key = signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Evm, 0).unwrap();
    assert_eq!(signed["raw"], tx.sign(&key).unwrap().raw_hex());
    let items = rlp_list(&raw[1..]);
    let parity = items[9].first().copied().unwrap_or(0);
    assert_eq!(recover(&tx.signing_hash(), &pad32(&items[10]), &pad32(&items[11]), parity), EVM_0);
}

/// An Ethereum estimate that offers the three speeds (the shape of the chain client's: standard is
/// also the top of the answer).
fn evm_estimate_speeds() -> Value {
    let tier = |max_fee: u64, tip: u64, fee: &str| {
        json!({ "gas_price": max_fee.to_string(), "max_fee_per_gas": max_fee.to_string(),
                "max_priority_fee_per_gas": tip.to_string(),
                "fee": { "asset": "ETH", "amount": fee, "decimals": 18 } })
    };
    let mut estimate = evm_estimate_1559();
    estimate["fees"] = json!({
        "slow": tier(60_000_000, 1_000_000, "3900000000000"),
        "normal": tier(111_417_878, 10_000_000, "7242162070000"),
        "fast": tier(160_000_000, 30_000_000, "10400000000000"),
    });
    estimate
}

#[test]
fn an_evm_send_is_priced_at_the_speed_the_person_chose() {
    let engine = engine();
    let ask = |speed: Option<&str>| {
        let mut req =
            request("ethereum", usdt_eth(), BOB, "5000000", evm_inputs(1), evm_estimate_speeds());
        if let Some(speed) = speed {
            req["options"] = json!({ "fee_speed": speed });
        }
        req
    };
    let fees_of = |req: &Value| -> (String, String) {
        let signed = sign(&engine, 0, req);
        let raw = hex(signed["raw"].as_str().unwrap());
        // EIP-1559: [chain, nonce, tip, max fee, ...]
        let items = rlp_list(&raw[1..]);
        let number = |bytes: &[u8]| bytes.iter().fold(0_u128, |acc, b| acc * 256 + u128::from(*b));
        (number(&items[2]).to_string(), number(&items[3]).to_string())
    };
    // Standard is what it was: with no speed, and when it is named.
    let plain = ask(None);
    assert_eq!(fees_of(&plain), ("10000000".to_owned(), "111417878".to_owned()));
    assert_eq!(fees_of(&ask(Some("normal"))), fees_of(&plain));
    assert_eq!(
        decode(&engine, 0, &ask(Some("normal"))).unwrap().approval,
        decode(&engine, 0, &plain).unwrap().approval
    );
    // Slow and fast bid what their own tier says, and the summary's fee is the tier's.
    assert_eq!(fees_of(&ask(Some("slow"))), ("1000000".to_owned(), "60000000".to_owned()));
    assert_eq!(fees_of(&ask(Some("fast"))), ("30000000".to_owned(), "160000000".to_owned()));
    let slow = decode(&engine, 0, &ask(Some("slow"))).unwrap().summary;
    let fast = decode(&engine, 0, &ask(Some("fast"))).unwrap().summary;
    assert_eq!(slow["fee"]["amount"], "3900000000000");
    assert_eq!(fast["fee"]["amount"], "10400000000000");
    // Each speed is another request to approve.
    let approvals = [
        decode(&engine, 0, &ask(None)).unwrap().approval,
        decode(&engine, 0, &ask(Some("slow"))).unwrap().approval,
        decode(&engine, 0, &ask(Some("fast"))).unwrap().approval,
    ];
    assert!(
        approvals[0] != approvals[1]
            && approvals[1] != approvals[2]
            && approvals[0] != approvals[2]
    );

    // Where the estimate offers speeds, one it left out (null) is not guessed at.
    let mut without = ask(Some("fast"));
    without["estimate"]["fees"]["fast"] = Value::Null;
    assert_eq!(code(decode(&engine, 0, &without)), "BadRequest");
    // And a word that is no speed.
    assert_eq!(code(decode(&engine, 0, &ask(Some("instant")))), "BadRequest");
    // A tier is held to the wallet's own ceilings like any bid: 5,000 gwei is past Ethereum's 1,000.
    let mut over = ask(Some("fast"));
    over["estimate"]["fees"]["fast"]["max_fee_per_gas"] = json!("5000000000000");
    assert_eq!(code(decode(&engine, 0, &over)), "FeeTooHigh");
}

#[test]
fn an_estimate_that_offers_no_speeds_is_priced_as_it_always_was_whatever_speed_is_in_the_request() {
    // The apps keep the speed chosen for Bitcoin in the send form and send it with a send on any network;
    // an estimate asked for without speeds has one price, and a stale "fast" must not change it.
    let engine = engine();
    let mut plain =
        request("ethereum", usdt_eth(), BOB, "5000000", evm_inputs(1), evm_estimate_1559());
    let standard = decode(&engine, 0, &plain).unwrap();
    for speed in ["slow", "normal", "fast"] {
        plain["options"] = json!({ "fee_speed": speed });
        assert_eq!(decode(&engine, 0, &plain).unwrap().approval, standard.approval, "{speed}");
    }
    // `fees: null` is no offer either.
    let mut nulled = plain.clone();
    nulled["estimate"]["fees"] = Value::Null;
    assert_eq!(decode(&engine, 0, &nulled).unwrap().approval, standard.approval);
    // Offered, the same words are a choice.
    let mut offered =
        request("ethereum", usdt_eth(), BOB, "5000000", evm_inputs(1), evm_estimate_speeds());
    offered["options"] = json!({ "fee_speed": "fast" });
    assert_ne!(decode(&engine, 0, &offered).unwrap().approval, standard.approval);
}

#[test]
fn a_network_with_one_fee_is_priced_as_it_always_was_whatever_speed_is_in_the_request() {
    let engine = engine();
    let owner = address(Network::Solana, 0);
    let to = address(Network::Solana, 1);
    let estimate = json!({
        "network": "solana", "fee": { "asset": "SOL", "amount": "5200", "decimals": 9 },
        "base_fee": "5000", "priority_fee": "200", "compute_unit_limit": 1000,
        "compute_unit_price_micro_lamports": "200000", "account_creation": "0",
        "recipient": { "exists": true }
    });
    let mut req = request(
        "solana",
        native("SOL", 9),
        &to,
        "1500000000",
        solana_inputs(&owner, vec![]),
        estimate,
    );
    // Standard is the only speed there: with no mention, or with any, it is the same request. (The apps
    // keep the speed chosen for Bitcoin in the send form and send it with a send on any network, so
    // refusing it would stop every Solana, TRON, Stellar and Bittensor send after the person had looked
    // at Bitcoin's.) The estimate of such a network offers no speeds, so nothing is hidden by it.
    let plain = decode(&engine, 0, &req).unwrap();
    for speed in ["slow", "normal", "fast"] {
        req["options"] = json!({ "fee_speed": speed });
        assert_eq!(decode(&engine, 0, &req).unwrap().approval, plain.approval, "{speed}");
    }
}

#[test]
fn a_native_transfer_on_a_chain_without_a_base_fee_is_a_legacy_transaction() {
    let engine = engine();
    let estimate = json!({
        "network": "bsc", "gas_limit": "21000", "gas_price": "3000000000", "eip1559": false,
        "max_fee_per_gas": null, "max_priority_fee_per_gas": null,
        "fee": { "asset": "BNB", "amount": "63000000000000", "decimals": 18 },
        "recipient": { "is_contract": false }
    });
    let inputs = with(evm_inputs(56), "network", json!("bsc"));
    let req = request("bsc", native("BNB", 18), BOB, "2000000000000000000", inputs, estimate);
    let decoded = decode(&engine, 0, &req).unwrap();
    assert_eq!(decoded.summary["action"], "native_transfer");
    assert_eq!(decoded.summary["tx"]["type"], "legacy");
    assert_eq!(decoded.summary["tx"]["chain_id"], 56);
    assert_eq!(decoded.summary["fee"]["amount"], "63000000000000");
    let signed = sign(&engine, 0, &req);
    let items = rlp_list(&hex(signed["raw"].as_str().unwrap()));
    assert_eq!(items.len(), 9);
    let tx = EvmTransaction {
        chain_id: EvmChain::BnbChain.chain_id(),
        nonce: 5969,
        to: evm::parse_address(BOB).unwrap(),
        value: 2_000_000_000_000_000_000,
        data: Vec::new(),
        gas_limit: 21_000,
        fees: Fees::Legacy { gas_price: 3_000_000_000 },
    };
    let v = *items[6].last().unwrap();
    assert_eq!(recover(&tx.signing_hash(), &pad32(&items[7]), &pad32(&items[8]), v - 147), EVM_0);
}

#[test]
fn an_evm_send_is_checked_against_the_account_and_the_chain() {
    let engine = engine();
    let good = request("ethereum", usdt_eth(), BOB, "5000000", evm_inputs(1), evm_estimate_1559());
    // Inputs read for another address.
    let other = with(evm_inputs(1), "address", json!(BOB));
    let req = with(good.clone(), "inputs", other);
    assert_eq!(code(decode(&engine, 0, &req)), "NotASigner");
    // Inputs for another chain.
    assert_eq!(
        code(decode(&engine, 0, &with(good.clone(), "inputs", evm_inputs(137)))),
        "BadRequest"
    );
    // A recipient with a bad checksum, and the all-zero address.
    let wrong = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBBb";
    assert_eq!(code(decode(&engine, 0, &with(good.clone(), "to", json!(wrong)))), "BadRequest");
    let zero = format!("0x{}", "0".repeat(40));
    assert_eq!(code(decode(&engine, 0, &with(good.clone(), "to", json!(zero)))), "BadRequest");
    // Nothing to send.
    assert_eq!(code(decode(&engine, 0, &with(good.clone(), "amount", json!("0")))), "BadRequest");
    // The coin named as a token of the wrong kind, a token on a coin-only network.
    let mut wrong_kind = usdt_eth();
    wrong_kind["kind"] = json!("trc20");
    assert_eq!(code(decode(&engine, 0, &with(good.clone(), "asset", wrong_kind))), "BadRequest");
    let mut tokenless = good.clone();
    tokenless["network"] = json!("bitcoin");
    assert_eq!(code(decode(&engine, 0, &tokenless)), "BadRequest");
    // The estimate of another network.
    let mut foreign = good.clone();
    foreign["estimate"]["network"] = json!("tron");
    assert_eq!(code(decode(&engine, 0, &foreign)), "BadRequest");
    // send_max is Bitcoin's.
    assert_eq!(
        code(decode(&engine, 0, &with(good.clone(), "send_max", json!(true)))),
        "BadRequest"
    );
    // An asset that is not the network's coin.
    let wrong_coin = with(good.clone(), "asset", native("BNB", 18));
    assert_eq!(code(decode(&engine, 0, &wrong_coin)), "BadRequest");
    // A field the request does not define.
    assert_eq!(code(decode(&engine, 0, &with(good, "memo", json!("x")))), "BadRequest");
}

// ---- TRON ----

fn tron_inputs(owner: &str) -> Value {
    // The wallet API's example, "inputs", TRON.
    json!({
        "network": "tron", "address": owner,
        "reference_block": {
            "number": 87461647,
            "block_id": "0000000005368f0fa1555acb3c6f9bc45b368bc2b683314e933f51fa5f1bc229",
            "ref_block_bytes": "8f0f", "ref_block_hash": "a1555acb3c6f9bc4", "timestamp_ms": 1793058189000_u64
        },
        "timestamp_ms": 1793058193685_u64, "expiration_ms": 1793058253685_u64,
        "energy_price_sun": "100", "bandwidth_price_sun": "1000",
        "account": { "activated": true, "free_bandwidth": 600, "staked_bandwidth": 0, "energy": 0 }
    })
}

fn tron_estimate(energy: &str, fee_limit: Option<&str>) -> Value {
    // The wallet API's example, "estimate", TRON.
    let mut body = json!({
        "network": "tron", "energy": energy, "bandwidth": "345",
        "energy_price_sun": "100", "bandwidth_price_sun": "1000",
        "fee": { "asset": "TRX", "amount": "5528500", "decimals": 6 },
        "activation_fee": "0", "recipient": { "activated": true }
    });
    if let Some(limit) = fee_limit {
        body["fee_limit"] = json!(limit);
    }
    body
}

const TRON_USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

fn trc20() -> Value {
    json!({ "symbol": "USDT", "name": "Tether USD", "decimals": 6, "kind": "trc20", "contract": TRON_USDT })
}

fn tron_signature_and_raw(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Transaction { raw_data (1), signature (2) }.
    assert_eq!(raw[0], 0x0a);
    let (mut length, mut at) = (0usize, 1usize);
    let mut shift = 0;
    loop {
        let byte = raw[at];
        length |= usize::from(byte & 0x7f) << shift;
        at += 1;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let raw_data = raw[at..at + length].to_vec();
    assert_eq!(&raw[at + length..at + length + 2], [0x12, 0x41]);
    (raw_data, raw[at + length + 2..].to_vec())
}

#[test]
fn trc20_and_trx_transfers_are_built_from_the_api_and_signed() {
    let engine = engine();
    let owner = address(Network::Tron, 0);
    let to = address(Network::Tron, 1);
    let reference = ReferenceBlock::from_block(
        87_461_647,
        &hexs::decode_array::<32>(
            "0000000005368f0fa1555acb3c6f9bc45b368bc2b683314e933f51fa5f1bc229",
        )
        .unwrap(),
    );

    // A token transfer, with the fee limit the estimate gives.
    let req = request(
        "tron",
        trc20(),
        &to,
        "250000000",
        tron_inputs(&owner),
        tron_estimate("64285", Some("8357050")),
    );
    let decoded = decode(&engine, 0, &req).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["action"], "trc20_transfer");
    assert_eq!(s["signer"], owner);
    assert_eq!(s["details"]["token"], TRON_USDT);
    assert_eq!(s["details"]["recipient"], to);
    assert_eq!(s["details"]["amount"], "250000000");
    assert_eq!(s["details"]["fee_limit"], "8357050");
    assert_eq!(s["details"]["activation_fee"], "0");
    assert_eq!(s["fee"], json!({ "asset": "TRX", "amount": "5528500", "decimals": 6 }));

    let signed = sign(&engine, 0, &req);
    assert_eq!(signed["encoding"], "hex");
    let (raw_data, signature) = tron_signature_and_raw(&hex(signed["raw"].as_str().unwrap()));
    let txid: [u8; 32] = Sha256::digest(&raw_data).into();
    assert_eq!(signed["hash"], hexs::encode(&txid));
    let direct = TronTransaction::trc20_transfer(
        tron::parse_address(&owner).unwrap(),
        tron::parse_address(TRON_USDT).unwrap(),
        &tron::parse_address(&to).unwrap(),
        &U256::from(250_000_000_u64),
        8_357_050,
        reference,
        1_793_058_193_685,
        1_793_058_253_685,
    )
    .unwrap();
    assert_eq!(raw_data, direct.raw_data());
    let public = recover_compressed(&txid, &signature[..32], &signature[32..64], signature[64]);
    assert_eq!(tron::address_from_public_key(&public).unwrap(), owner);

    // TRX itself: no fee limit needed.
    let req = request(
        "tron",
        native("TRX", 6),
        &to,
        "1500000",
        tron_inputs(&owner),
        tron_estimate("0", None),
    );
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["action"], "trx_transfer");
    assert_eq!(s["details"]["amount"], "1500000");
    let signed = sign(&engine, 0, &req);
    let (raw_data, signature) = tron_signature_and_raw(&hex(signed["raw"].as_str().unwrap()));
    let txid: [u8; 32] = Sha256::digest(&raw_data).into();
    assert_eq!(signed["hash"], hexs::encode(&txid));
    let public = recover_compressed(&txid, &signature[..32], &signature[32..64], signature[64]);
    assert_eq!(tron::address_from_public_key(&public).unwrap(), owner);
}

fn recover_compressed(digest: &[u8; 32], r: &[u8], s: &[u8], parity: u8) -> Vec<u8> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(r);
    rs[32..].copy_from_slice(s);
    let key = VerifyingKey::recover_from_prehash(
        digest,
        &Signature::from_slice(&rs).unwrap(),
        RecoveryId::from_byte(parity).unwrap(),
    )
    .unwrap();
    key.to_encoded_point(true).as_bytes().to_vec()
}

#[test]
fn tron_refuses_what_the_api_did_not_say_consistently() {
    let engine = engine();
    let owner = address(Network::Tron, 0);
    let to = address(Network::Tron, 1);
    let good = request(
        "tron",
        trc20(),
        &to,
        "1000000",
        tron_inputs(&owner),
        tron_estimate("64285", Some("8357050")),
    );
    assert!(decode(&engine, 0, &good).is_ok());
    // A token call needs the fee limit.
    let mut no_limit = good.clone();
    no_limit["estimate"].as_object_mut().unwrap().remove("fee_limit");
    assert_eq!(code(decode(&engine, 0, &no_limit)), "BadRequest");
    // A reference block whose bytes are not its block's.
    let mut forged = good.clone();
    forged["inputs"]["reference_block"]["ref_block_hash"] = json!("0000000000000000");
    assert_eq!(code(decode(&engine, 0, &forged)), "BadRequest");
    // An address that is not TRON's, and the sender itself.
    assert_eq!(code(decode(&engine, 0, &with(good.clone(), "to", json!(EVM_0)))), "BadRequest");
    let to_self = request(
        "tron",
        native("TRX", 6),
        &owner,
        "1",
        tron_inputs(&owner),
        tron_estimate("0", None),
    );
    assert_eq!(code(decode(&engine, 0, &to_self)), "BadRequest");
    // Inputs of another address.
    let other = with(tron_inputs(&owner), "address", json!(to));
    assert_eq!(code(decode(&engine, 0, &with(good, "inputs", other))), "NotASigner");
}

// ---- Bitcoin ----

/// The address at `chain`/`index` of BIP-84 account `account` of the test wallet.
fn btc_at(account: u32, chain: bitcoin::Chain, index: u32) -> String {
    let seed = Mnemonic::parse(ABANDON).unwrap().to_seed("");
    bitcoin::account(&seed, account, chain, index).unwrap().address
}

/// One of the wallet's unspent outputs as the chain client lists it: where it is and what it pays.
fn btc_utxo(txid: &str, value: u64, chain: bitcoin::Chain, index: u32, confirmed: bool) -> Value {
    json!({
        "txid": txid, "vout": 0, "value": value.to_string(),
        "address": btc_at(0, chain, index),
        "chain": u32::from(chain == bitcoin::Chain::Change), "index": index,
        "confirmed": confirmed, "confirmations": if confirmed { 96 } else { 0 },
    })
}

fn bitcoin_inputs(receive: &str, extra: Vec<Value>) -> Value {
    bitcoin_inputs_with(receive, extra, 0)
}

/// The inputs of account 0 with the funded output at receive 0, `extra` outputs, and the next
/// unused change address being change `next_change`.
fn bitcoin_inputs_with(receive: &str, extra: Vec<Value>, next_change: u32) -> Value {
    // The wallet API's example, "inputs", Bitcoin.
    let mut utxos = vec![json!({
        "txid": "f341510e483fe97dd22e4bf28ed485f5e349519d84e5fb206e2331d657942118", "vout": 1,
        "value": "56389", "address": receive, "chain": 0, "index": 0,
        "confirmed": true, "confirmations": 96, "block": 973215
    })];
    utxos.extend(extra);
    json!({
        "network": "bitcoin", "address": receive, "utxos": utxos, "truncated": false,
        "change": {
            "chain": 1, "index": next_change,
            "address": btc_at(0, bitcoin::Chain::Change, next_change),
        },
        "fee_rates": {
            "slow": { "sat_per_vb": "1", "sat_per_kvb": "1000" },
            "normal": { "sat_per_vb": "1", "sat_per_kvb": "1000" },
            "fast": { "sat_per_vb": "2", "sat_per_kvb": "2000" }
        },
        "block": 973310
    })
}

fn bitcoin_estimate() -> Value {
    // The wallet API's example, "estimate", Bitcoin.
    json!({
        "network": "bitcoin",
        "fees": {
            "slow": { "sat_per_vb": "1", "vsize": "141", "inputs": 1, "fee": "141" },
            "normal": { "sat_per_vb": "1", "vsize": "141", "inputs": 1, "fee": "141" },
            "fast": { "sat_per_vb": "1", "vsize": "141", "inputs": 1, "fee": "141" }
        },
        "fee": { "asset": "BTC", "amount": "141", "decimals": 8 },
        "recipient": { "valid": true }
    })
}

/// The signature (DER and the sighash byte) and the public key in the
/// witness of a segwit transaction with one input.
fn witness_of_single_input(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(&raw[4..6], [0, 1], "marker and flag");
    let mut at = 6;
    assert_eq!(raw[at], 1, "one input");
    at += 1 + 32 + 4;
    assert_eq!(raw[at], 0, "no script_sig");
    at += 1 + 4;
    let outputs = raw[at];
    at += 1;
    for _ in 0..outputs {
        at += 8;
        at += 1 + usize::from(raw[at]);
    }
    assert_eq!(raw[at], 2, "a signature and a key");
    let length = usize::from(raw[at + 1]);
    let der = raw[at + 2..at + 2 + length].to_vec();
    at += 2 + length;
    assert_eq!(raw[at], 0x21);
    (der, raw[at + 1..at + 34].to_vec())
}

#[test]
fn a_bitcoin_payment_spends_the_utxos_pays_change_and_the_signature_verifies() {
    let engine = engine();
    let receive = address(Network::Bitcoin, 0);
    let change = btc_at(0, bitcoin::Chain::Change, 0);
    assert_ne!(receive, change);
    assert_eq!(receive, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    let to = address(Network::Bitcoin, 1);

    let req = request(
        "bitcoin",
        native("BTC", 8),
        &to,
        "10000",
        bitcoin_inputs(&receive, vec![]),
        bitcoin_estimate(),
    );
    let decoded = decode(&engine, 0, &req).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["action"], "bitcoin_payment");
    assert_eq!(s["signer"], receive);
    assert_eq!(s["details"]["recipient"], to);
    assert_eq!(s["details"]["amount"], "10000");
    assert_eq!(s["details"]["inputs"], 1);
    assert_eq!(s["details"]["change"], json!({ "address": change, "amount": "46248" }));
    // One input, a payment and change: 141 virtual bytes at 1 sat/vB, as the estimate says.
    assert_eq!(s["fee"], json!({ "asset": "BTC", "amount": "141", "decimals": 8 }));
    assert_eq!(s["details"]["vsize"], 141);
    assert_eq!(s["warnings"], json!([]));

    let signed = sign(&engine, 0, &req);
    assert_eq!(signed["network"], "bitcoin");
    let raw = hex(signed["raw"].as_str().unwrap());
    // The signature verifies under BIP-143's digest for the output spent.
    let utxo = bitcoin::Utxo::new(
        "f341510e483fe97dd22e4bf28ed485f5e349519d84e5fb206e2331d657942118",
        1,
        56_389,
        &receive,
        bitcoin::Chain::Receive,
        0,
    )
    .unwrap();
    let plan = bitcoin::plan(&bitcoin::Request {
        to: &to,
        amount: bitcoin::Amount::Exact(10_000),
        utxos: &[utxo],
        change_address: &change,
        fee_rate: bitcoin::FeeRate::from_sat_per_kvb(1000),
    })
    .unwrap();
    let cache = bitcoin::tx::SighashCache::new(&plan.transaction);
    let hash160 = bitcoin::script::p2wpkh_hash_of_address(&receive).unwrap();
    let digest = cache.p2wpkh_digest(&plan.transaction, 0, &hash160, 56_389).unwrap();
    let (der, key) = witness_of_single_input(&raw);
    assert_eq!(*der.last().unwrap(), 1, "SIGHASH_ALL");
    let signature = k256::ecdsa::Signature::from_der(&der[..der.len() - 1]).unwrap();
    let verifier = k256::ecdsa::VerifyingKey::from_sec1_bytes(&key).unwrap();
    verifier.verify_prehash(&digest, &signature).unwrap();
    assert_eq!(key, account(Network::Bitcoin, 0).public_key);
    // The id is the transaction id, in display order.
    assert_eq!(signed["hash"], plan.transaction.txid_hex());

    // Faster costs more.
    let mut fast = req.clone();
    fast["options"] = json!({ "fee_speed": "fast" });
    let s = decode(&engine, 0, &fast).unwrap().summary;
    assert_eq!(s["fee"]["amount"], "282");
}

#[test]
fn bitcoin_send_max_spends_everything_and_unconfirmed_money_is_not_spent() {
    let engine = engine();
    let receive = address(Network::Bitcoin, 0);
    let change = btc_at(0, bitcoin::Chain::Change, 0);
    let to = address(Network::Bitcoin, 1);
    // An unconfirmed output on the receive chain (someone else's money) is left alone;
    // the wallet's own unconfirmed change (one this device sent) is spent.
    let extra = vec![
        json!({ "txid": "aa".repeat(32), "vout": 0, "value": "1000000", "address": receive, "chain": 0, "index": 0, "confirmed": false }),
        json!({ "txid": "bb".repeat(32), "vout": 2, "value": "20000", "address": change, "chain": 1, "index": 0, "confirmed": false, "own": true }),
        // Unconfirmed change of a transaction this device did not send (`own` absent or false) is left alone
        // too: it can be replaced before it is mined, and the payment would fail.
        json!({ "txid": "dd".repeat(32), "vout": 0, "value": "70000", "address": change, "chain": 1, "index": 0, "confirmed": false }),
        json!({ "txid": "ee".repeat(32), "vout": 0, "value": "80000", "address": change, "chain": 1, "index": 0, "confirmed": false, "own": false }),
    ];
    let mut req = request(
        "bitcoin",
        native("BTC", 8),
        &to,
        "1",
        bitcoin_inputs(&receive, extra),
        bitcoin_estimate(),
    );
    req["send_max"] = json!(true);
    req.as_object_mut().unwrap().remove("amount");
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["details"]["inputs"], 2);
    assert_eq!(s["details"]["change"], Value::Null);
    let amount: u64 = s["details"]["amount"].as_str().unwrap().parse().unwrap();
    let fee: u64 = s["fee"]["amount"].as_str().unwrap().parse().unwrap();
    assert_eq!(amount + fee, 56_389 + 20_000);
    // Both inputs were signed with their own keys.
    let signed = sign(&engine, 0, &req);
    assert!(signed["raw"].as_str().unwrap().starts_with("02000000000102"));

    // Money that is not this account's is refused.
    let foreign = vec![json!({
        "txid": "cc".repeat(32), "vout": 0, "value": "90000", "address": address(Network::Bitcoin, 1),
        "chain": 0, "index": 0, "confirmed": true
    })];
    let bad = request(
        "bitcoin",
        native("BTC", 8),
        &to,
        "1000",
        bitcoin_inputs(&receive, foreign),
        bitcoin_estimate(),
    );
    // Money that is not at the place in this account it says it is (the largest is spent first, and
    // the key at that place does not own it) is refused.
    assert_eq!(code(decode(&engine, 0, &bad)), "NotASigner");
    // Not enough, and below dust.
    let big = request(
        "bitcoin",
        native("BTC", 8),
        &to,
        "56389",
        bitcoin_inputs(&receive, vec![]),
        bitcoin_estimate(),
    );
    assert_eq!(code(decode(&engine, 0, &big)), "InsufficientFunds");
    let tiny = request(
        "bitcoin",
        native("BTC", 8),
        &to,
        "100",
        bitcoin_inputs(&receive, vec![]),
        bitcoin_estimate(),
    );
    assert_eq!(code(decode(&engine, 0, &tiny)), "Dust");
    // Nothing confirmed.
    let mut none = request(
        "bitcoin",
        native("BTC", 8),
        &to,
        "1000",
        bitcoin_inputs(&receive, vec![]),
        bitcoin_estimate(),
    );
    none["inputs"]["utxos"][0]["confirmed"] = json!(false);
    assert_eq!(code(decode(&engine, 0, &none)), "InsufficientFunds");
    // A fee that eats the payment is flagged.
    let mut dear = request(
        "bitcoin",
        native("BTC", 8),
        &to,
        "1000",
        bitcoin_inputs(&receive, vec![]),
        bitcoin_estimate(),
    );
    dear["inputs"]["fee_rates"]["normal"]["sat_per_kvb"] = json!("20000");
    assert_eq!(decode(&engine, 0, &dear).unwrap().summary["warnings"], json!(["high_fee"]));
    // An address that is not Bitcoin's.
    let evm_to = request(
        "bitcoin",
        native("BTC", 8),
        EVM_0,
        "1000",
        bitcoin_inputs(&receive, vec![]),
        bitcoin_estimate(),
    );
    assert_eq!(code(decode(&engine, 0, &evm_to)), "BadRequest");
}

// ---- Solana ----

const MINT_USDT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

fn solana_inputs(owner: &str, token_accounts: Vec<Value>) -> Value {
    // The wallet API's example, "inputs", Solana.
    json!({
        "network": "solana", "address": owner,
        "blockhash": "F9YDb7X2fNnvX4x7U8RXLF3eLJfBwMVgcbnfVdZ4Sn9G", "last_valid_block_height": 439880804_u64,
        "token_accounts": token_accounts,
        "priority_fee": { "micro_lamports_per_unit": "200000",
            "compute_unit_limit": { "sol_transfer": 1000, "token_transfer": 60000, "token_transfer_new_account": 100000 } },
        "token_account_rent": "1488440"
    })
}

fn spl() -> Value {
    json!({ "symbol": "USDT", "name": "Tether USD", "decimals": 6, "kind": "spl", "contract": MINT_USDT, "mint": MINT_USDT })
}

fn ata(owner: &str, mint: &str) -> String {
    let owner = nc_wallet_core::solana::parse_address(owner).unwrap();
    let mint = nc_wallet_core::solana::parse_address(mint).unwrap();
    nc_wallet_core::solana::address(
        &nc_wallet_core::solana::message::associated_token_account(&owner, &mint).unwrap(),
    )
}

fn ed_verifies(index: u32, network: Network, message: &[u8], signature: &[u8]) -> bool {
    let key: [u8; 32] = account(network, index).public_key.try_into().unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify(message, &EdSignature::from_slice(signature).unwrap())
        .is_ok()
}

#[test]
fn a_sol_transfer_to_an_account_a_program_owns_carries_a_warning_and_nothing_else_changes() {
    let engine = engine();
    let owner = address(Network::Solana, 0);
    let to = address(Network::Solana, 1);
    let estimate = |recipient: Value| {
        json!({
            "network": "solana", "fee": { "asset": "SOL", "amount": "5200", "decimals": 9 },
            "base_fee": "5000", "priority_fee": "200", "compute_unit_limit": 1000,
            "compute_unit_price_micro_lamports": "200000", "account_creation": "0",
            "recipient": recipient
        })
    };
    let ask = |recipient: Value| {
        request(
            "solana",
            native("SOL", 9),
            &to,
            "1500000000",
            solana_inputs(&owner, vec![]),
            estimate(recipient),
        )
    };
    let plain =
        decode(&engine, 0, &ask(json!({ "exists": true, "program_owned": false }))).unwrap();
    assert_eq!(plain.summary["warnings"], json!([]));
    // An estimate from before the fact existed says nothing, and nothing is warned.
    let old = decode(&engine, 0, &ask(json!({ "exists": true }))).unwrap();
    assert_eq!(old.summary["warnings"], json!([]));
    // A program's account: lamports sent to it cannot be taken out again.
    let program = ask(json!({ "exists": true, "program_owned": true,
                              "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" }));
    let warned = decode(&engine, 0, &program).unwrap();
    assert_eq!(warned.summary["warnings"], json!(["recipient_is_program_account"]));
    // The same transfer in every other way: the details, the fee and what is signed.
    assert_eq!(warned.summary["details"], plain.summary["details"]);
    assert_eq!(warned.summary["fee"], plain.summary["fee"]);
    // The warning is part of what was approved: the approval does not carry over to the plain one.
    assert_ne!(warned.approval, plain.approval);
    assert!(sign(&engine, 0, &program)["raw"].is_string());
}

#[test]
fn sol_and_spl_transfers_are_built_read_back_and_signed() {
    let engine = engine();
    let owner = address(Network::Solana, 0);
    let to = address(Network::Solana, 1);

    // SOL: the wallet API's example, "estimate", Solana.
    let estimate = json!({
        "network": "solana", "fee": { "asset": "SOL", "amount": "5200", "decimals": 9 },
        "base_fee": "5000", "priority_fee": "200", "compute_unit_limit": 1000,
        "compute_unit_price_micro_lamports": "200000", "account_creation": "0",
        "recipient": { "exists": true }
    });
    let req = request(
        "solana",
        native("SOL", 9),
        &to,
        "1500000000",
        solana_inputs(&owner, vec![]),
        estimate,
    );
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["action"], "sol_transfer");
    assert_eq!(s["details"], json!({ "recipient": to, "amount": "1500000000" }));
    assert_eq!(s["fee"], json!({ "asset": "SOL", "amount": "5200", "decimals": 9 }));
    let signed = sign(&engine, 0, &req);
    assert_eq!(signed["encoding"], "base64");
    let wire = STANDARD.decode(signed["raw"].as_str().unwrap()).unwrap();
    let parsed = nc_wallet_core::solana::ParsedTransaction::parse(&wire).unwrap();
    assert!(ed_verifies(0, Network::Solana, &parsed.message_bytes, &parsed.signatures[0]));
    assert_eq!(signed["hash"], bs58::encode(parsed.signatures[0]).into_string());
    // The built message is what the API's numbers say.
    let read = nc_wallet_core::solana::summarize_transaction(&wire, &[]).unwrap();
    assert_eq!(
        bs58::encode(read.recent_blockhash).into_string(),
        "F9YDb7X2fNnvX4x7U8RXLF3eLJfBwMVgcbnfVdZ4Sn9G"
    );

    // SPL into a token account that has to be made.
    let accounts = vec![json!({
        "address": ata(&owner, MINT_USDT), "mint": MINT_USDT, "symbol": "USDT",
        "amount": "714135444", "decimals": 6, "associated": true
    })];
    let estimate = json!({
        "network": "solana", "fee": { "asset": "SOL", "amount": "20000", "decimals": 9 },
        "base_fee": "5000", "priority_fee": "15000", "compute_unit_limit": 100000,
        "compute_unit_price_micro_lamports": "150000", "account_creation": "2039280",
        "recipient": { "token_account_exists": false, "token_account": ata(&to, MINT_USDT), "is_token_account": false }
    });
    let req = request(
        "solana",
        spl(),
        &to,
        "250000000",
        solana_inputs(&owner, accounts.clone()),
        estimate.clone(),
    );
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["action"], "spl_transfer");
    assert_eq!(
        s["details"],
        json!({ "token": MINT_USDT, "recipient": to, "amount": "250000000",
                "creates_token_account": true, "account_creation": "2039280" })
    );
    let signed = sign(&engine, 0, &req);
    let wire = STANDARD.decode(signed["raw"].as_str().unwrap()).unwrap();
    let parsed = nc_wallet_core::solana::ParsedTransaction::parse(&wire).unwrap();
    assert!(ed_verifies(0, Network::Solana, &parsed.message_bytes, &parsed.signatures[0]));
    let read = nc_wallet_core::solana::summarize_transaction(&wire, &[]).unwrap();
    assert_eq!(read.instructions.len(), 4, "limit, price, create account, transfer");

    // The recipient already has an account: nothing to create.
    let mut exists = estimate.clone();
    exists["recipient"]["token_account_exists"] = json!(true);
    let req = with(req, "estimate", exists);
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["details"]["creates_token_account"], false);
    assert_eq!(s["details"]["account_creation"], "0");

    // A recipient that is itself a token account is refused.
    let mut is_account = estimate.clone();
    is_account["recipient"]["is_token_account"] = json!(true);
    let req2 = with(req.clone(), "estimate", is_account);
    assert_eq!(code(decode(&engine, 0, &req2)), "RecipientIsTokenAccount");
    // Not enough tokens.
    let too_much = with(req.clone(), "amount", json!("714135445"));
    assert_eq!(code(decode(&engine, 0, &too_much)), "InsufficientFunds");
    // Tokens that sit in a second account: used when the associated one cannot pay.
    let other = address(Network::Solana, 2);
    let split = vec![
        json!({ "address": ata(&owner, MINT_USDT), "mint": MINT_USDT, "amount": "10", "decimals": 6, "associated": true }),
        json!({ "address": other, "mint": MINT_USDT, "amount": "999999999", "decimals": 6, "associated": false }),
    ];
    let req3 = with(req.clone(), "inputs", solana_inputs(&owner, split));
    let signed = sign(&engine, 0, &req3);
    let wire = STANDARD.decode(signed["raw"].as_str().unwrap()).unwrap();
    let read = nc_wallet_core::solana::summarize_transaction(&wire, &[]).unwrap();
    let source = read.instructions.iter().find_map(|i| match i {
        nc_wallet_core::solana::InstructionSummary::SplTransfer { source, .. } => Some(*source),
        _ => None,
    });
    assert_eq!(bs58::encode(source.unwrap()).into_string(), other);
    // A token account of the wrong decimals.
    let odd = vec![
        json!({ "address": ata(&owner, MINT_USDT), "mint": MINT_USDT, "amount": "999999999", "decimals": 9 }),
    ];
    assert_eq!(
        code(decode(&engine, 0, &with(req, "inputs", solana_inputs(&owner, odd)))),
        "BadRequest"
    );
}

// ---- Stellar ----

fn stellar_inputs(address: &str, exists: bool) -> Value {
    // The wallet API's example, "inputs", Stellar.
    if !exists {
        return json!({ "network": "stellar", "address": address, "account_exists": false, "base_fee": "100", "server_time": 1793058206_u64 });
    }
    json!({
        "network": "stellar", "address": address, "account_exists": true,
        "sequence": "144373126631784461", "base_fee": "100", "balance": "320999354850", "min_balance": "40000000",
        "trustlines": [], "server_time": 1793058206_u64
    })
}

fn stellar_estimate(recipient: Value) -> Value {
    // The wallet API's example, "estimate", Stellar.
    json!({ "network": "stellar", "fee": { "asset": "XLM", "amount": "100", "decimals": 7 }, "recipient": recipient })
}

const USDC_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

fn usdc_stellar() -> Value {
    json!({ "symbol": "USDC", "name": "USD Coin", "decimals": 7, "kind": "stellar_asset",
            "contract": USDC_ISSUER, "issuer": USDC_ISSUER, "code": "USDC" })
}

fn stellar_signature(envelope_base64: &str) -> (Vec<u8>, [u8; 32]) {
    let envelope = STANDARD.decode(envelope_base64).unwrap();
    let signature = envelope[envelope.len() - 64..].to_vec();
    // The signature covers the transaction hash: rebuilt by the caller.
    (signature, [0; 32])
}

#[test]
fn stellar_payments_creations_memos_and_trustlines() {
    let engine = engine();
    let owner = address(Network::Stellar, 0);
    let to = address(Network::Stellar, 1);
    let source: [u8; 32] = account(Network::Stellar, 0).public_key.try_into().unwrap();
    let destination = stellar::parse_address(&to).unwrap();
    let bounds = TimeBounds { min_time: 0, max_time: 1_793_058_206 + 300 };

    // XLM to an account that exists.
    let est =
        stellar_estimate(json!({ "exists": true, "trustline": null, "memo_required": false }));
    let mut req = request(
        "stellar",
        native("XLM", 7),
        &to,
        "25000000",
        stellar_inputs(&owner, true),
        est.clone(),
    );
    req["options"] = json!({ "memo": "12345" });
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["action"], "stellar_payment");
    assert_eq!(
        s["details"],
        json!({ "recipient": to, "asset": "XLM", "amount": "25000000", "memo": "12345" })
    );
    assert_eq!(s["fee"], json!({ "asset": "XLM", "amount": "100", "decimals": 7 }));
    let signed = sign(&engine, 0, &req);
    assert_eq!(signed["encoding"], "base64");
    let direct_tx = stellar::Transaction {
        source,
        fee: 100,
        account_sequence: 144_373_126_631_784_461,
        time_bounds: bounds,
        memo: Memo::Id(12345),
        operation: Operation::Payment {
            destination,
            destination_id: None,
            asset: Asset::Native,
            amount: 25_000_000,
        },
    };
    let key = signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Stellar, 0).unwrap();
    let direct =
        stellar::sign_transaction(&key, stellar::PUBLIC_NETWORK_PASSPHRASE, &direct_tx).unwrap();
    assert_eq!(signed["raw"], direct.envelope_base64());
    assert_eq!(signed["hash"], direct.hash_hex());
    let (signature, _) = stellar_signature(signed["raw"].as_str().unwrap());
    assert!(ed_verifies(0, Network::Stellar, &direct.hash, &signature));

    // XLM to an account that does not exist yet: a creation, at least the minimum.
    let est = stellar_estimate(
        json!({ "exists": false, "trustline": null, "memo_required": false, "minimum_new_account": "10000000" }),
    );
    let req = request(
        "stellar",
        native("XLM", 7),
        &to,
        "10000000",
        stellar_inputs(&owner, true),
        est.clone(),
    );
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["action"], "stellar_create_account");
    assert_eq!(s["details"]["starting_balance"], "10000000");
    let small = with(req, "amount", json!("9999999"));
    assert_eq!(code(decode(&engine, 0, &small)), "Dust");

    // USDC needs the recipient's trustline.
    let with_line =
        stellar_estimate(json!({ "exists": true, "trustline": true, "memo_required": false }));
    let req =
        request("stellar", usdc_stellar(), &to, "5000000", stellar_inputs(&owner, true), with_line);
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["details"]["asset"], "USDC");
    let signed = sign(&engine, 0, &req);
    let direct_tx = stellar::Transaction {
        memo: Memo::None,
        operation: Operation::Payment {
            destination,
            destination_id: None,
            asset: Asset::credit("USDC", USDC_ISSUER).unwrap(),
            amount: 5_000_000,
        },
        ..direct_tx
    };
    let direct =
        stellar::sign_transaction(&key, stellar::PUBLIC_NETWORK_PASSPHRASE, &direct_tx).unwrap();
    assert_eq!(signed["raw"], direct.envelope_base64());
    let without =
        stellar_estimate(json!({ "exists": true, "trustline": false, "memo_required": false }));
    assert_eq!(code(decode(&engine, 0, &with(req.clone(), "estimate", without))), "NoTrustline");
    let unknown =
        stellar_estimate(json!({ "exists": true, "trustline": null, "memo_required": false }));
    assert_eq!(code(decode(&engine, 0, &with(req, "estimate", unknown))), "BadRequest");

    // A recipient that asks for a memo.
    let needs =
        stellar_estimate(json!({ "exists": true, "trustline": null, "memo_required": true }));
    let req = request("stellar", native("XLM", 7), &to, "1", stellar_inputs(&owner, true), needs);
    assert_eq!(code(decode(&engine, 0, &req)), "MemoRequired");
    let mut with_memo = req.clone();
    with_memo["options"] = json!({ "memo": "for invoice 7" });
    assert!(decode(&engine, 0, &with_memo).is_ok());
    let mut long = req.clone();
    long["options"] = json!({ "memo": "x".repeat(29) });
    assert_eq!(code(decode(&engine, 0, &long)), "BadRequest");
    // An account that does not exist cannot send.
    let ghost = request("stellar", native("XLM", 7), &to, "1", stellar_inputs(&owner, false), est);
    assert_eq!(code(decode(&engine, 0, &ghost)), "BadRequest");
    // A secret seed, or anything else that is not an address, is not a destination.
    for not_an_address in [
        "SAV76USXIJOBMEQXPANUOQM6F5LIOTLPDIDVRJBFFE2MDJXG24TAPUU7",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4",
    ] {
        let req = request(
            "stellar",
            native("XLM", 7),
            not_an_address,
            "1",
            stellar_inputs(&owner, true),
            stellar_estimate(json!({ "exists": true })),
        );
        assert_eq!(code(decode(&engine, 0, &req)), "BadRequest");
    }
}

const MUXED_BASE: &str = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
/// SEP-23's address of that account with the id 2^63 (an id past the largest signed number).
const MUXED: &str = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";

#[test]
fn a_payment_to_a_muxed_address_is_paid_to_it_as_the_address_says() {
    let engine = engine();
    let owner = address(Network::Stellar, 0);
    let source: [u8; 32] = account(Network::Stellar, 0).public_key.try_into().unwrap();
    let key = signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Stellar, 0).unwrap();
    let base = stellar::parse_address(MUXED_BASE).unwrap();
    let estimate = stellar_estimate(
        json!({ "exists": true, "trustline": null, "memo_required": false, "muxed_id": "9223372036854775808" }),
    );
    let req = request(
        "stellar",
        native("XLM", 7),
        MUXED,
        "25000000",
        stellar_inputs(&owner, true),
        estimate.clone(),
    );
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["action"], "stellar_payment");
    // Both parts are shown: the account that is paid and the id that is its own.
    assert_eq!(
        s["details"],
        json!({ "recipient": MUXED, "account": MUXED_BASE, "muxed_id": "9223372036854775808",
                "asset": "XLM", "amount": "25000000", "memo": null })
    );
    // What is signed is a payment to the muxed account, with no memo.
    let signed = sign(&engine, 0, &req);
    let direct_tx = stellar::Transaction {
        source,
        fee: 100,
        account_sequence: 144_373_126_631_784_461,
        time_bounds: TimeBounds { min_time: 0, max_time: 1_793_058_206 + 300 },
        memo: Memo::None,
        operation: Operation::Payment {
            destination: base,
            destination_id: Some(9_223_372_036_854_775_808),
            asset: Asset::Native,
            amount: 25_000_000,
        },
    };
    let direct =
        stellar::sign_transaction(&key, stellar::PUBLIC_NETWORK_PASSPHRASE, &direct_tx).unwrap();
    assert_eq!(signed["raw"], direct.envelope_base64());
    assert_eq!(signed["hash"], direct.hash_hex());
    // The same payment to the plain account is another transaction.
    let plain = request(
        "stellar",
        native("XLM", 7),
        MUXED_BASE,
        "25000000",
        stellar_inputs(&owner, true),
        stellar_estimate(json!({ "exists": true, "trustline": null, "memo_required": false })),
    );
    assert_ne!(sign(&engine, 0, &plain)["raw"], signed["raw"]);
    assert_eq!(decode(&engine, 0, &plain).unwrap().summary["details"]["recipient"], MUXED_BASE);

    // The id is the address's own: a memo typed beside it is refused, not guessed at.
    let mut with_memo = req.clone();
    with_memo["options"] = json!({ "memo": "12345" });
    assert_eq!(code(decode(&engine, 0, &with_memo)), "BadRequest");
    // A recipient that asks for a memo is not owed one when the address carries an id.
    let needs =
        stellar_estimate(json!({ "exists": true, "trustline": null, "memo_required": true }));
    assert!(decode(&engine, 0, &with(req.clone(), "estimate", needs)).is_ok());
    // An account that does not exist is made by a payment to its plain address, which cannot carry an
    // id: the person is told to ask for that, not paid into an id that is lost.
    let ghost = stellar_estimate(
        json!({ "exists": false, "trustline": null, "memo_required": false, "minimum_new_account": "10000000" }),
    );
    let creation = request(
        "stellar",
        native("XLM", 7),
        MUXED,
        "10000000",
        stellar_inputs(&owner, true),
        ghost,
    );
    assert_eq!(code(decode(&engine, 0, &creation)), "BadRequest");
    // An issued asset goes the same way, to a recipient with the trustline.
    let usdc = request(
        "stellar",
        usdc_stellar(),
        MUXED,
        "5000000",
        stellar_inputs(&owner, true),
        stellar_estimate(json!({ "exists": true, "trustline": true, "memo_required": false })),
    );
    let signed = sign(&engine, 0, &usdc);
    let direct_tx = stellar::Transaction {
        operation: Operation::Payment {
            destination: base,
            destination_id: Some(9_223_372_036_854_775_808),
            asset: Asset::credit("USDC", USDC_ISSUER).unwrap(),
            amount: 5_000_000,
        },
        ..direct_tx
    };
    let direct =
        stellar::sign_transaction(&key, stellar::PUBLIC_NETWORK_PASSPHRASE, &direct_tx).unwrap();
    assert_eq!(signed["raw"], direct.envelope_base64());
}

// ---- Bittensor ----

fn compact_len(extrinsic: &[u8]) -> usize {
    match extrinsic[0] & 3 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 1 + usize::from(extrinsic[0] >> 2) + 4,
    }
}

#[test]
fn a_bittensor_transfer_is_built_from_the_api_and_the_signature_verifies() {
    let engine = engine();
    let owner = address(Network::Bittensor, 0);
    let to = address(Network::Bittensor, 1);
    // The wallet API's example, "inputs" and "estimate", Bittensor.
    let inputs = json!({
        "network": "bittensor", "address": owner, "nonce": 77, "spec_version": 486, "transaction_version": 1,
        "genesis_hash": "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03",
        "block_hash": "0x05282fae70442737bb48e0ecc0bca971c2e63dc8b9698857810174804f2a68a9",
        "block_number": 9371216, "era_period": 64, "call_index": { "pallet": 5, "call": 3 },
        "existential_deposit": "500"
    });
    let estimate = json!({
        "network": "bittensor", "fee": { "asset": "TAO", "amount": "83125", "decimals": 9 },
        "existential_deposit": "500", "recipient": { "exists": true }
    });
    let req = request("bittensor", native("TAO", 9), &to, "1500000000", inputs, estimate.clone());
    let s = decode(&engine, 0, &req).unwrap().summary;
    assert_eq!(s["action"], "tao_transfer");
    assert_eq!(s["details"], json!({ "recipient": to, "amount": "1500000000" }));
    assert_eq!(s["fee"], json!({ "asset": "TAO", "amount": "83125", "decimals": 9 }));

    let signed = sign(&engine, 0, &req);
    assert_eq!(signed["encoding"], "hex");
    let extrinsic = hex(signed["raw"].as_str().unwrap());
    let body = &extrinsic[compact_len(&extrinsic)..];
    assert_eq!(body[0], 0x84);
    assert_eq!(body[1], 0x00);
    let sender: [u8; 32] = body[2..34].try_into().unwrap();
    assert_eq!(body[34], 0x01, "sr25519");
    assert_eq!(sender.as_slice(), account(Network::Bittensor, 0).public_key.as_slice());
    let signature = schnorrkel::Signature::from_bytes(&body[35..99]).unwrap();
    let transfer = Transfer {
        sender,
        dest: nc_wallet_core::bittensor::parse_address(&to).unwrap(),
        value: 1_500_000_000,
        call_index: CallIndex { pallet: 5, call: 3 },
        nonce: 77,
        tip: 0,
        period: 64,
        birth: 9_371_216,
        birth_hash: hexs::decode_array(
            "05282fae70442737bb48e0ecc0bca971c2e63dc8b9698857810174804f2a68a9",
        )
        .unwrap(),
        spec_version: 486,
        transaction_version: 1,
        genesis_hash: hexs::decode_array(
            "2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03",
        )
        .unwrap(),
    };
    let payload = transfer.signing_payload().unwrap();
    let public = schnorrkel::PublicKey::from_bytes(&sender).unwrap();
    assert!(public.verify_simple(b"substrate", &payload, &signature).is_ok());
    // The same extrinsic around the signature, and its hash (blake2-256 of all of it).
    assert_eq!(transfer.encode_signed(&signature.to_bytes()).unwrap(), extrinsic);
    assert_eq!(
        signed["hash"],
        hexs::encode_0x(&nc_wallet_core::bittensor::extrinsic::blake2_256(&extrinsic))
    );

    // The chain and the call are pinned in the engine: inputs that name another genesis hash
    // or another call index are refused, whoever supplied them.
    for (field, value) in [
        (
            "genesis_hash",
            json!("0x1111111111111111111111111111111111111111111111111111111111111111"),
        ),
        ("call_index", json!({ "pallet": 5, "call": 0 })),
        ("call_index", json!({ "pallet": 6, "call": 3 })),
    ] {
        let mut inputs = req["inputs"].clone();
        inputs[field] = value;
        assert_eq!(
            code(decode(&engine, 0, &with(req.clone(), "inputs", inputs))),
            "Unsupported",
            "{field}"
        );
    }

    // A new account must receive at least the existential deposit.
    let mut fresh = estimate;
    fresh["recipient"]["exists"] = json!(false);
    let tiny = with(with(req.clone(), "estimate", fresh), "amount", json!("499"));
    assert_eq!(code(decode(&engine, 0, &tiny)), "Dust");
    // An SS58 address of another prefix is another network's.
    let polkadot = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5";
    assert_eq!(code(decode(&engine, 0, &with(req, "to", json!(polkadot)))), "BadRequest");
}

// ---- the wallet's own fee ceilings (nc_wallet_core::limits) ----

#[test]
fn an_evm_send_above_the_wallets_fee_ceilings_is_refused_whatever_the_estimate_says() {
    let engine = engine();
    let ok = request("ethereum", usdt_eth(), BOB, "5000000", evm_inputs(1), evm_estimate_1559());
    assert!(decode(&engine, 0, &ok).is_ok());
    let gwei = |n: u128| (n * 1_000_000_000).to_string();
    let with_estimate = |changes: &[(&str, Value)]| {
        let mut estimate = evm_estimate_1559();
        for (key, value) in changes {
            estimate[*key] = value.clone();
        }
        request("ethereum", usdt_eth(), BOB, "5000000", evm_inputs(1), estimate)
    };
    // A price of a thousand and one gwei, a tip of two hundred and one, a gas limit of 600,001.
    for (name, req) in [
        ("max fee", with_estimate(&[("max_fee_per_gas", json!(gwei(1_001)))])),
        (
            "tip",
            with_estimate(&[
                ("max_fee_per_gas", json!(gwei(900))),
                ("max_priority_fee_per_gas", json!(gwei(201))),
            ]),
        ),
        ("gas limit", with_estimate(&[("gas_limit", json!("600001"))])),
        // Each inside its own ceiling, but 600,000 units at 100 gwei reserves 0.06 ETH.
        (
            "total",
            with_estimate(&[
                ("gas_limit", json!("600000")),
                ("max_fee_per_gas", json!(gwei(100))),
                ("max_priority_fee_per_gas", json!(gwei(2))),
            ]),
        ),
    ] {
        let error = decode(&engine, 0, &req).unwrap_err();
        assert_eq!(error.code(), "FeeTooHigh", "{name}: {}", error.detail());
    }
    // A fee a person might actually meet in a busy hour passes.
    let busy = with_estimate(&[
        ("max_fee_per_gas", json!(gwei(300))),
        ("max_priority_fee_per_gas", json!(gwei(5))),
    ]);
    assert!(decode(&engine, 0, &busy).is_ok());
    // ...but it is a fee the person has to accept: the engine does not sign it on its own.
    let text = busy.to_string();
    let decoded = engine.decode_request(0, &text).unwrap();
    assert!(decoded.summary["warnings"].as_array().unwrap().iter().any(|w| w == "fee_high"));
    assert_eq!(
        engine.sign_request(0, &text, &decoded.approval).unwrap_err().code(),
        "FeeNotAccepted"
    );
    let mut accepted = busy.clone();
    accepted["fee_ok"] = json!(true);
    assert!(engine.sign_request(0, &accepted.to_string(), &decoded.approval).is_ok());
}

#[test]
fn a_bitcoin_rate_of_fifty_thousand_satoshis_a_byte_is_refused() {
    // `{"1": 50000}` from one Esplora answer was a 0.07 BTC fee on a 0.5 BTC payment.
    let engine = engine();
    let receive = address(Network::Bitcoin, 0);
    let to = address(Network::Bitcoin, 1);
    let mut inputs = bitcoin_inputs(&receive, vec![]);
    inputs["fee_rates"]["normal"] = json!({ "sat_per_vb": "50000", "sat_per_kvb": "50000000" });
    let req = request("bitcoin", native("BTC", 8), &to, "10000", inputs, bitcoin_estimate());
    assert_eq!(decode(&engine, 0, &req).unwrap_err().code(), "FeeTooHigh");
    // A thousand satoshis a byte is the most; a thousand and one is not.
    let mut inputs = bitcoin_inputs(&receive, vec![]);
    inputs["fee_rates"]["normal"] = json!({ "sat_per_vb": "1001", "sat_per_kvb": "1001000" });
    let req = request("bitcoin", native("BTC", 8), &to, "10000", inputs, bitcoin_estimate());
    assert_eq!(decode(&engine, 0, &req).unwrap_err().code(), "FeeTooHigh");
}

#[test]
fn the_other_networks_refuse_their_own_absurd_fees() {
    let engine = engine();
    // Solana: 60,000 units at 5 billion micro-lamports is 300,000 lamports... and ten times that is not allowed.
    let owner = address(Network::Solana, 0);
    let to = address(Network::Solana, 1);
    let estimate = |price: &str| {
        json!({
            "network": "solana", "fee": { "asset": "SOL", "amount": "5200", "decimals": 9 },
            "base_fee": "5000", "priority_fee": "200", "compute_unit_limit": 1000,
            "compute_unit_price_micro_lamports": price, "account_creation": "0",
            "recipient": { "exists": true }
        })
    };
    // 1,000 units at 20 trillion micro-lamports: 20,000,000 lamports (0.02 SOL).
    let req = request(
        "solana",
        native("SOL", 9),
        &to,
        "1500000000",
        solana_inputs(&owner, vec![]),
        estimate("20000000000000"),
    );
    assert_eq!(decode(&engine, 0, &req).unwrap_err().code(), "FeeTooHigh");

    // Stellar: a base fee of 1,000,001 stroops an operation.
    let from = address(Network::Stellar, 0);
    let dest = address(Network::Stellar, 1);
    let mut inputs = stellar_inputs(&from, true);
    inputs["base_fee"] = json!("1000001");
    let req = request(
        "stellar",
        native("XLM", 7),
        &dest,
        "10000000",
        inputs,
        stellar_estimate(json!({ "exists": true })),
    );
    assert_eq!(decode(&engine, 0, &req).unwrap_err().code(), "FeeTooHigh");

    // TRON: a fee limit of 301 TRX on a token transfer.
    let owner = address(Network::Tron, 0);
    let dest = address(Network::Tron, 1);
    let req = request(
        "tron",
        json!({ "symbol": "USDT", "name": "Tether USD", "decimals": 6, "kind": "trc20", "contract": TRON_USDT }),
        &dest,
        "5000000",
        tron_inputs(&owner),
        tron_estimate("65000", Some("301000000")),
    );
    assert_eq!(decode(&engine, 0, &req).unwrap_err().code(), "FeeTooHigh");

    // Bittensor: a quote of 0.011 TAO for a transfer.
    let owner = address(Network::Bittensor, 0);
    let to = address(Network::Bittensor, 1);
    let inputs = json!({
        "network": "bittensor", "address": owner, "nonce": 77, "spec_version": 486, "transaction_version": 1,
        "genesis_hash": "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03",
        "block_hash": "0x05282fae70442737bb48e0ecc0bca971c2e63dc8b9698857810174804f2a68a9",
        "block_number": 9371216, "era_period": 64, "call_index": { "pallet": 5, "call": 3 },
        "existential_deposit": "500"
    });
    let estimate = json!({
        "network": "bittensor", "fee": { "asset": "TAO", "amount": "11000000", "decimals": 9 },
        "existential_deposit": "500", "recipient": { "exists": true }
    });
    let req = request("bittensor", native("TAO", 9), &to, "1500000000", inputs, estimate);
    assert_eq!(decode(&engine, 0, &req).unwrap_err().code(), "FeeTooHigh");
}

// ---- Bitcoin: the whole BIP-84 account, found by looking ----

fn seed_of_test_wallet() -> nc_wallet_core::Seed {
    Mnemonic::parse(ABANDON).unwrap().to_seed("")
}

#[test]
fn an_imported_wallet_with_money_at_receive_7_and_change_3_spends_from_both_and_signs_each_input() {
    let engine = engine();
    let to = address(Network::Bitcoin, 3);
    let receive0 = btc_at(0, bitcoin::Chain::Receive, 0);
    // The account was used elsewhere: money paid to receive address 7 and left as change at change 3.
    // The next unused change address is change 4.
    let extra = vec![
        btc_utxo(&"d1".repeat(32), 30_000, bitcoin::Chain::Receive, 7, true),
        btc_utxo(&"d2".repeat(32), 40_000, bitcoin::Chain::Change, 3, true),
    ];
    let mut inputs = bitcoin_inputs_with(&receive0, extra, 4);
    // Nothing at receive 0 in this wallet.
    inputs["utxos"].as_array_mut().unwrap().remove(0);
    let req = request("bitcoin", native("BTC", 8), &to, "60000", inputs, bitcoin_estimate());
    let decoded = decode(&engine, 0, &req).unwrap();
    let s = &decoded.summary;
    // Both outputs are spent (70,000 in all), the signer is the account's one shown address, and
    // the change goes to the next unused change address, not to a fixed one.
    assert_eq!(s["details"]["inputs"], 2);
    assert_eq!(s["signer"], receive0);
    let change_address = btc_at(0, bitcoin::Chain::Change, 4);
    assert_eq!(s["details"]["change"]["address"], change_address);
    let fee: u64 = s["fee"]["amount"].as_str().unwrap().parse().unwrap();
    let change: u64 = s["details"]["change"]["amount"].as_str().unwrap().parse().unwrap();
    assert_eq!(60_000 + change + fee, 70_000);

    // Each input is signed with the key of its own place: the same transaction built and signed with
    // the core (keys derived at receive 7 and change 3) is byte for byte what the engine signs.
    let signed = sign(&engine, 0, &req);
    let raw = hex(signed["raw"].as_str().unwrap());
    let utxos = [
        bitcoin::Utxo::new(
            &"d1".repeat(32),
            0,
            30_000,
            &btc_at(0, bitcoin::Chain::Receive, 7),
            bitcoin::Chain::Receive,
            7,
        )
        .unwrap(),
        bitcoin::Utxo::new(
            &"d2".repeat(32),
            0,
            40_000,
            &btc_at(0, bitcoin::Chain::Change, 3),
            bitcoin::Chain::Change,
            3,
        )
        .unwrap(),
    ];
    let plan = bitcoin::plan(&bitcoin::Request {
        to: &to,
        amount: bitcoin::Amount::Exact(60_000),
        utxos: &utxos,
        change_address: &change_address,
        fee_rate: bitcoin::FeeRate::from_sat_per_kvb(1000),
    })
    .unwrap();
    let by_core = plan.sign(&seed_of_test_wallet(), 0).unwrap();
    assert_eq!(raw, by_core.raw);
    assert_eq!(signed["hash"], by_core.txid_hex());
    // And no input was signed with the key of receive 0: the witnesses carry the keys at 7 and at change 3.
    let seed = seed_of_test_wallet();
    for (chain, at) in [(bitcoin::Chain::Receive, 7), (bitcoin::Chain::Change, 3)] {
        let key = bitcoin::account(&seed, 0, chain, at).unwrap().public_key;
        assert!(raw.windows(key.len()).any(|w| w == key.as_slice()), "{chain:?} {at}");
    }
    let wrong = bitcoin::account(&seed, 0, bitcoin::Chain::Receive, 0).unwrap().public_key;
    assert!(!raw.windows(wrong.len()).any(|w| w == wrong.as_slice()));
}

#[test]
fn a_bitcoin_account_signs_with_its_own_keys_and_no_other_accounts() {
    let engine = engine();
    // Account 2 of the same phrase: its shown address is its own, and money at its receive 5 is spent with its key.
    let receive0 = btc_at(2, bitcoin::Chain::Receive, 0);
    assert_eq!(receive0, address(Network::Bitcoin, 2));
    let at = |chain, index| {
        let seed = seed_of_test_wallet();
        bitcoin::account(&seed, 2, chain, index).unwrap().address
    };
    let utxo = json!({
        "txid": "e1".repeat(32), "vout": 0, "value": "50000", "address": at(bitcoin::Chain::Receive, 5),
        "chain": 0, "index": 5, "confirmed": true,
    });
    let inputs = json!({
        "network": "bitcoin", "address": receive0, "utxos": [utxo],
        "change": { "chain": 1, "index": 0, "address": at(bitcoin::Chain::Change, 0) },
        "fee_rates": {
            "slow": { "sat_per_vb": "1", "sat_per_kvb": "1000" },
            "normal": { "sat_per_vb": "1", "sat_per_kvb": "1000" },
            "fast": { "sat_per_vb": "2", "sat_per_kvb": "2000" }
        },
        "block": 1,
    });
    let to = address(Network::Bitcoin, 3);
    let req =
        request("bitcoin", native("BTC", 8), &to, "10000", inputs.clone(), bitcoin_estimate());
    let s = decode(&engine, 2, &req).unwrap().summary;
    assert_eq!(s["signer"], receive0);
    sign(&engine, 2, &req);
    // The same request for account 0: nothing there is its, so nothing is signed.
    assert_eq!(code(decode(&engine, 0, &req)), "NotASigner");
}

#[test]
fn a_request_cannot_make_the_signer_pay_change_somewhere_else_or_far_ahead() {
    let engine = engine();
    let receive0 = btc_at(0, bitcoin::Chain::Receive, 0);
    let to = address(Network::Bitcoin, 3);
    let ask = |inputs: Value| {
        request("bitcoin", native("BTC", 8), &to, "10000", inputs, bitcoin_estimate())
    };

    // A change address that is not the one at the place named.
    let mut other = bitcoin_inputs_with(&receive0, vec![], 2);
    other["change"]["address"] = json!(address(Network::Bitcoin, 1));
    assert_eq!(code(decode(&engine, 0, &ask(other))), "BadRequest");
    // The change on the receive chain, or ten thousand and one ahead.
    let mut on_receive = bitcoin_inputs_with(&receive0, vec![], 2);
    on_receive["change"] = json!({ "chain": 0, "index": 2 });
    assert_eq!(code(decode(&engine, 0, &ask(on_receive))), "BadRequest");
    let mut far = bitcoin_inputs_with(&receive0, vec![], 2);
    far["change"] = json!({ "chain": 1, "index": 10_001 });
    assert_eq!(code(decode(&engine, 0, &ask(far))), "BadRequest");
    // No change place at all.
    let mut none = bitcoin_inputs_with(&receive0, vec![], 2);
    none.as_object_mut().unwrap().remove("change");
    assert_eq!(code(decode(&engine, 0, &ask(none))), "BadRequest");
    // The address alone, with no place, is enough when it is the right one: the signer derives it.
    let mut named = bitcoin_inputs_with(&receive0, vec![], 2);
    named["change"].as_object_mut().unwrap().remove("address");
    let s = decode(&engine, 0, &ask(named)).unwrap().summary;
    assert_eq!(s["details"]["change"]["address"], btc_at(0, bitcoin::Chain::Change, 2));
    // An output claimed at a place that is not its address.
    let mut moved = bitcoin_inputs_with(&receive0, vec![], 0);
    moved["utxos"][0]["index"] = json!(1);
    assert_eq!(code(decode(&engine, 0, &ask(moved))), "NotASigner");
    // A chain that is neither.
    let mut odd = bitcoin_inputs_with(&receive0, vec![], 0);
    odd["utxos"][0]["chain"] = json!(2);
    assert_eq!(code(decode(&engine, 0, &ask(odd))), "BadRequest");
}
