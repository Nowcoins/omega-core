//! Signing through the entry points Dart calls (`api::signing`), on the
//! process-wide engine, for each of the six signing families: EVM, TRON,
//! Bitcoin (secp256k1), Solana and Stellar (ed25519), Bittensor (sr25519).
//!
//! The rule: ask for the summary, sign with its approval hash, then prove the
//! signature belongs to the account with the primitive crates and none of the
//! session's own code: recover the secp256k1 signer and compare it with the
//! address, or verify the ed25519 / sr25519 signature against the derived
//! public key. The wallet is the BIP-39 reference phrase (entropy all zero),
//! and the request bodies are the wallet API's documented examples
//! (`crates/nc-wallet-chain/tests/fixtures/wallet-api/`) with the example address replaced by the account's,
//! since a request is checked against the signer.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::unreadable_literal,
    clippy::needless_pass_by_value
)]

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey};
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey as SecpKey};
use nc_wallet_core::bittensor::{self, CallIndex, Transfer};
use nc_wallet_core::evm::{self, EvmTransaction, Fees, U256, abi};
use nc_wallet_core::tron;
use nc_wallet_core::{bitcoin, solana};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::tests::{ABANDON, serial};
use super::*;
use crate::api::accounts::derive_accounts;
use crate::api::signing::{
    AddressProblem, SigningError, bitcoin_zpub, decode_request, sign_request, validate_address,
};
use crate::api::{phrase, vault};

const PASSWORD: &str = "a good password";

/// The reference wallet's vault and its key, sealed once (Argon2id is slow in a
/// debug build) and reopened by key for every other test.
fn sealed() -> &'static (Vec<u8>, Vec<u8>) {
    static SEALED: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    SEALED.get_or_init(|| {
        engine().lock();
        engine().discard_pending();
        phrase::start_import(ABANDON.to_owned(), String::new()).unwrap();
        let blob = vault::seal_pending(PASSWORD.to_owned()).unwrap();
        vault::commit_pending().unwrap();
        let key = vault::take_new_unlock_key().unwrap();
        vault::lock();
        (blob, key)
    })
}

/// The reference wallet, unlocked. Hold the guard for the length of the test.
fn unlocked() -> MutexGuard<'static, ()> {
    let guard = serial();
    let (blob, key) = sealed();
    vault::lock();
    vault::unlock_with_key(blob.clone(), key.clone()).unwrap();
    guard
}

fn address(network: NetworkId) -> String {
    derive_accounts(0).unwrap().into_iter().find(|a| a.network == network).unwrap().address
}

fn public_key(network: NetworkId) -> Vec<u8> {
    let found = derive_accounts(0).unwrap().into_iter().find(|a| a.network == network).unwrap();
    hex::decode(found.public_key_hex).unwrap()
}

/// Decodes and signs a request as the app does: the summary first, then the
/// signature with its approval hash. Returns the summary and the answer.
fn decode_and_sign(request: &Value) -> (Value, Value) {
    let text = request.to_string();
    let decoded = decode_request(0, text.clone()).unwrap();
    assert_eq!(decoded.approval.len(), 64);
    assert!(decoded.approval.bytes().all(|b| b.is_ascii_hexdigit()));
    let summary: Value = serde_json::from_str(&decoded.summary_json).unwrap();
    let signed: Value =
        serde_json::from_str(&sign_request(0, text, decoded.approval).unwrap()).unwrap();
    (summary, signed)
}

fn code(result: Result<impl std::fmt::Debug, SigningError>) -> SigningError {
    result.unwrap_err()
}

fn send(
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

fn native(symbol: &str, decimals: u8) -> Value {
    json!({ "symbol": symbol, "name": symbol, "decimals": decimals })
}

fn hex_bytes(text: &str) -> Vec<u8> {
    hex::decode(text.trim_start_matches("0x")).unwrap()
}

fn recover(digest: &[u8; 32], r: &[u8], s: &[u8], parity: u8) -> Vec<u8> {
    let mut rs = [0u8; 64];
    rs[32 - r.len()..32].copy_from_slice(r);
    rs[64 - s.len()..].copy_from_slice(s);
    let key = SecpKey::recover_from_prehash(
        digest,
        &Signature::from_slice(&rs).unwrap(),
        RecoveryId::from_byte(parity).unwrap(),
    )
    .unwrap();
    key.to_encoded_point(true).as_bytes().to_vec()
}

/// The items of an RLP list: strings without their length prefix.
fn rlp_list(data: &[u8]) -> Vec<Vec<u8>> {
    fn length(data: &[u8], at: usize, short: u8, long: u8) -> (usize, usize) {
        let first = data[at];
        if first <= short + 55 {
            (usize::from(first - short), 1)
        } else {
            let n = usize::from(first - long);
            let len = data[at + 1..at + 1 + n].iter().fold(0usize, |l, b| l << 8 | usize::from(*b));
            (len, 1 + n)
        }
    }
    let (len, skip) = length(data, 0, 0xc0, 0xf7);
    let body = &data[skip..skip + len];
    let mut items = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let first = body[at];
        let (start, end) = if first < 0x80 {
            (at, at + 1)
        } else if first < 0xc0 {
            let (len, skip) = length(body, at, 0x80, 0xb7);
            (at + skip, at + skip + len)
        } else {
            let (len, skip) = length(body, at, 0xc0, 0xf7);
            (at, at + skip + len)
        };
        items.push(body[start..end].to_vec());
        at = end;
    }
    items
}

fn ed_verifies(network: NetworkId, message: &[u8], signature: &[u8]) -> bool {
    let key: [u8; 32] = public_key(network).try_into().unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify(message, &EdSignature::from_slice(signature).unwrap())
        .is_ok()
}

// ---- EVM ----

const USDT_ETH: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
const BOB: &str = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB";

fn evm_inputs(owner: &str, chain_id: u64) -> Value {
    // The wallet API's example, "inputs", EVM.
    json!({
        "network": "ethereum", "address": owner, "chain_id": chain_id, "nonce": 5969,
        "gas_price": "50709286", "eip1559": true, "base_fee": "50708939",
        "max_priority_fee": "10000000", "max_fee": "111417878", "block": 26280228
    })
}

#[test]
fn an_evm_token_transfer_is_signed_and_its_signer_recovered() {
    let _wallet = unlocked();
    let owner = address(NetworkId::Ethereum);
    assert_eq!(owner, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    // The wallet API's example, "estimate", EVM (a token transfer's gas).
    let estimate = json!({
        "network": "ethereum", "gas_limit": "65000", "gas_price": "6000000", "eip1559": true,
        "max_fee_per_gas": "111417878", "max_priority_fee_per_gas": "10000000",
        "fee": { "asset": "ETH", "amount": "7242162070000", "decimals": 18 },
        "recipient": { "is_contract": false }
    });
    let token = json!({ "symbol": "USDT", "name": "Tether USD", "decimals": 6, "kind": "erc20", "contract": USDT_ETH });
    let request = send("ethereum", token, BOB, "5000000", evm_inputs(&owner, 1), estimate);
    let (summary, signed) = decode_and_sign(&request);

    assert_eq!(summary["request"], "send");
    assert_eq!(summary["action"], "token_transfer");
    assert_eq!(summary["signer"], owner);
    assert_eq!(summary["details"]["recipient"], BOB);
    assert_eq!(summary["details"]["amount"], "5000000");
    assert_eq!(
        summary["fee"],
        json!({ "asset": "ETH", "amount": "7242162070000", "decimals": 18 })
    );
    assert_eq!(signed["encoding"], "hex");

    let raw = hex_bytes(signed["raw"].as_str().unwrap());
    assert_eq!(raw[0], 0x02, "an EIP-1559 transaction");
    let tx = EvmTransaction {
        chain_id: 1,
        nonce: 5969,
        to: evm::parse_address(USDT_ETH).unwrap(),
        value: 0,
        data: abi::erc20_transfer(&evm::parse_address(BOB).unwrap(), &U256::from(5_000_000_u64)),
        gas_limit: 65_000,
        fees: Fees::Eip1559 { max_fee_per_gas: 111_417_878, max_priority_fee_per_gas: 10_000_000 },
    };
    let items = rlp_list(&raw[1..]);
    let parity = items[9].first().copied().unwrap_or(0);
    let signer = recover(&tx.signing_hash(), &items[10], &items[11], parity);
    assert_eq!(evm::address_from_public_key(&signer).unwrap(), owner);
    assert_eq!(signer, public_key(NetworkId::Ethereum));
    // The id is the transaction hash.
    assert_eq!(signed["hash"], format!("0x{}", hex::encode(evm::tx::keccak(&raw))));
}

#[test]
fn a_native_transfer_on_a_chain_without_a_base_fee_is_legacy_and_recovers() {
    let _wallet = unlocked();
    let owner = address(NetworkId::BnbChain);
    let estimate = json!({
        "network": "bsc", "gas_limit": "21000", "gas_price": "3000000000", "eip1559": false,
        "max_fee_per_gas": null, "max_priority_fee_per_gas": null,
        "fee": { "asset": "BNB", "amount": "63000000000000", "decimals": 18 },
        "recipient": { "is_contract": false }
    });
    let mut inputs = evm_inputs(&owner, 56);
    inputs["network"] = json!("bsc");
    let request = send("bsc", native("BNB", 18), BOB, "2000000000000000000", inputs, estimate);
    let (summary, signed) = decode_and_sign(&request);
    assert_eq!(summary["action"], "native_transfer");
    assert_eq!(summary["tx"]["type"], "legacy");
    assert_eq!(summary["tx"]["chain_id"], 56);

    let raw = hex_bytes(signed["raw"].as_str().unwrap());
    let items = rlp_list(&raw);
    assert_eq!(items.len(), 9);
    let tx = EvmTransaction {
        chain_id: 56,
        nonce: 5969,
        to: evm::parse_address(BOB).unwrap(),
        value: 2_000_000_000_000_000_000,
        data: Vec::new(),
        gas_limit: 21_000,
        fees: Fees::Legacy { gas_price: 3_000_000_000 },
    };
    // EIP-155: v = 35 + 2 * chain id + parity.
    let v = *items[6].last().unwrap();
    let signer = recover(&tx.signing_hash(), &items[7], &items[8], v - (35 + 2 * 56));
    assert_eq!(evm::address_from_public_key(&signer).unwrap(), owner);
}

// ---- TRON ----

const TRON_USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

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

/// `Transaction { raw_data (1), signature (2) }`: the two parts.
fn tron_parts(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(raw[0], 0x0a);
    let (mut length, mut at, mut shift) = (0usize, 1usize, 0);
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
fn a_trc20_and_a_trx_transfer_are_signed_and_the_signer_recovered() {
    let _wallet = unlocked();
    let owner = address(NetworkId::Tron);
    // Any valid TRON address is a recipient; this one is the reference wallet's account 1.
    let to = {
        let me = nc_wallet_core::Mnemonic::parse(ABANDON).unwrap();
        nc_wallet_core::derive(&me, "", nc_wallet_core::Network::Tron, 1).unwrap().address
    };
    let estimate = |energy: &str, fee_limit: Option<&str>| {
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
    };

    let token = json!({ "symbol": "USDT", "name": "Tether USD", "decimals": 6, "kind": "trc20", "contract": TRON_USDT });
    let request = send(
        "tron",
        token,
        &to,
        "250000000",
        tron_inputs(&owner),
        estimate("64285", Some("8357050")),
    );
    let (summary, signed) = decode_and_sign(&request);
    assert_eq!(summary["action"], "trc20_transfer");
    assert_eq!(summary["signer"], owner);
    assert_eq!(summary["details"]["recipient"], to);
    assert_eq!(summary["details"]["amount"], "250000000");
    let (raw_data, signature) = tron_parts(&hex_bytes(signed["raw"].as_str().unwrap()));
    let txid: [u8; 32] = Sha256::digest(&raw_data).into();
    assert_eq!(signed["hash"], hex::encode(txid));
    let signer = recover(&txid, &signature[..32], &signature[32..64], signature[64]);
    assert_eq!(tron::address_from_public_key(&signer).unwrap(), owner);

    let request =
        send("tron", native("TRX", 6), &to, "1500000", tron_inputs(&owner), estimate("0", None));
    let (summary, signed) = decode_and_sign(&request);
    assert_eq!(summary["action"], "trx_transfer");
    let (raw_data, signature) = tron_parts(&hex_bytes(signed["raw"].as_str().unwrap()));
    let txid: [u8; 32] = Sha256::digest(&raw_data).into();
    let signer = recover(&txid, &signature[..32], &signature[32..64], signature[64]);
    assert_eq!(tron::address_from_public_key(&signer).unwrap(), owner);
}

// ---- Bitcoin ----

fn bitcoin_inputs(receive: &str) -> Value {
    // The wallet API's example, "inputs", Bitcoin.
    json!({
        "network": "bitcoin", "address": receive,
        "utxos": [{
            "txid": "f341510e483fe97dd22e4bf28ed485f5e349519d84e5fb206e2331d657942118", "vout": 1,
            "value": "56389", "address": receive, "chain": 0, "index": 0,
            "confirmed": true, "confirmations": 96, "block": 973215
        }],
        "change": { "chain": 1, "index": 0 },
        "truncated": false,
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

/// The signature (DER and the sighash byte) and the public key in the witness
/// of a segwit transaction with one input.
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
fn a_bitcoin_payment_pays_change_to_the_change_chain_and_its_signature_verifies() {
    let _wallet = unlocked();
    let receive = address(NetworkId::Bitcoin);
    assert_eq!(receive, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    // BIP-84's documented first change address for the reference wallet.
    let change = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el".to_owned();
    assert_ne!(change, receive);
    // The account's zpub is BIP-84's, and it finds that first change address without a key.
    let zpub = bitcoin_zpub(0).unwrap();
    assert_eq!(
        zpub,
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    );
    assert_eq!(
        bitcoin::addresses_from_zpub(&zpub, bitcoin::Chain::Change, 0, 1).unwrap(),
        std::slice::from_ref(&change)
    );
    assert_eq!(bitcoin_zpub(u32::MAX).unwrap_err(), SigningError::AccountIndexOutOfRange);
    // Recipient: the account's own second address is as good as any.
    let to = {
        let me = nc_wallet_core::Mnemonic::parse(ABANDON).unwrap();
        nc_wallet_core::derive(&me, "", nc_wallet_core::Network::Bitcoin, 1).unwrap().address
    };

    let request = send(
        "bitcoin",
        native("BTC", 8),
        &to,
        "10000",
        bitcoin_inputs(&receive),
        bitcoin_estimate(),
    );
    let (summary, signed) = decode_and_sign(&request);
    assert_eq!(summary["action"], "bitcoin_payment");
    assert_eq!(summary["signer"], receive);
    assert_eq!(summary["details"]["recipient"], to);
    assert_eq!(summary["details"]["amount"], "10000");
    assert_eq!(summary["details"]["change"], json!({ "address": change, "amount": "46248" }));
    assert_eq!(summary["fee"], json!({ "asset": "BTC", "amount": "141", "decimals": 8 }));

    let raw = hex_bytes(signed["raw"].as_str().unwrap());
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
    let signature = Signature::from_der(&der[..der.len() - 1]).unwrap();
    SecpKey::from_sec1_bytes(&key).unwrap().verify_prehash(&digest, &signature).unwrap();
    assert_eq!(key, public_key(NetworkId::Bitcoin));
    assert_eq!(signed["hash"], plan.transaction.txid_hex());
}

// ---- Solana ----

#[test]
fn a_solana_transaction_names_the_lookup_tables_it_needs() {
    use crate::api::signing::{SigningError, solana_lookup_tables};
    let _wallet = unlocked();
    let owner = address(NetworkId::Solana);
    let inputs = json!({
        "network": "solana", "address": owner,
        "blockhash": "F9YDb7X2fNnvX4x7U8RXLF3eLJfBwMVgcbnfVdZ4Sn9G", "last_valid_block_height": 439880804_u64,
        "token_accounts": [],
        "priority_fee": { "micro_lamports_per_unit": "200000",
            "compute_unit_limit": { "sol_transfer": 1000, "token_transfer": 60000, "token_transfer_new_account": 100000 } },
        "token_account_rent": "1488440"
    });
    let estimate = json!({
        "network": "solana", "fee": { "asset": "SOL", "amount": "5200", "decimals": 9 },
        "base_fee": "5000", "priority_fee": "200", "compute_unit_limit": 1000,
        "compute_unit_price_micro_lamports": "200000", "account_creation": "0",
        "recipient": { "exists": true }
    });
    let request = send("solana", native("SOL", 9), &owner, "1", inputs, estimate);
    let (_, signed) = decode_and_sign(&request);
    // A plain transfer loads no accounts through a table; the bridge says so without a wallet's help.
    let none = solana_lookup_tables(signed["raw"].as_str().unwrap().to_owned()).unwrap();
    assert!(none.is_empty());
    // Text that is not a transaction is refused, with its code.
    assert_eq!(solana_lookup_tables("!".to_owned()).unwrap_err(), SigningError::BadRequest);
    assert_eq!(solana_lookup_tables("AAAA".to_owned()).unwrap_err(), SigningError::BadRequest);
}

#[test]
fn a_sol_transfer_is_signed_and_the_signature_verifies() {
    let _wallet = unlocked();
    let owner = address(NetworkId::Solana);
    let to = {
        let me = nc_wallet_core::Mnemonic::parse(ABANDON).unwrap();
        nc_wallet_core::derive(&me, "", nc_wallet_core::Network::Solana, 1).unwrap().address
    };
    // The wallet API's example, "inputs" and "estimate", Solana.
    let inputs = json!({
        "network": "solana", "address": owner,
        "blockhash": "F9YDb7X2fNnvX4x7U8RXLF3eLJfBwMVgcbnfVdZ4Sn9G", "last_valid_block_height": 439880804_u64,
        "token_accounts": [],
        "priority_fee": { "micro_lamports_per_unit": "200000",
            "compute_unit_limit": { "sol_transfer": 1000, "token_transfer": 60000, "token_transfer_new_account": 100000 } },
        "token_account_rent": "1488440"
    });
    let estimate = json!({
        "network": "solana", "fee": { "asset": "SOL", "amount": "5200", "decimals": 9 },
        "base_fee": "5000", "priority_fee": "200", "compute_unit_limit": 1000,
        "compute_unit_price_micro_lamports": "200000", "account_creation": "0",
        "recipient": { "exists": true }
    });
    let request = send("solana", native("SOL", 9), &to, "1500000000", inputs, estimate);
    let (summary, signed) = decode_and_sign(&request);
    assert_eq!(summary["action"], "sol_transfer");
    assert_eq!(summary["details"], json!({ "recipient": to, "amount": "1500000000" }));
    assert_eq!(signed["encoding"], "base64");

    let wire = STANDARD.decode(signed["raw"].as_str().unwrap()).unwrap();
    let parsed = solana::ParsedTransaction::parse(&wire).unwrap();
    assert!(ed_verifies(NetworkId::Solana, &parsed.message_bytes, &parsed.signatures[0]));
    assert_eq!(signed["hash"], bs58::encode(parsed.signatures[0]).into_string());
}

// ---- Stellar ----

#[test]
fn a_stellar_payment_is_signed_and_the_signature_verifies() {
    let _wallet = unlocked();
    let owner = address(NetworkId::Stellar);
    let to = {
        let me = nc_wallet_core::Mnemonic::parse(ABANDON).unwrap();
        nc_wallet_core::derive(&me, "", nc_wallet_core::Network::Stellar, 1).unwrap().address
    };
    // The wallet API's example, "inputs" and "estimate", Stellar.
    let inputs = json!({
        "network": "stellar", "address": owner, "account_exists": true,
        "sequence": "144373126631784461", "base_fee": "100", "balance": "320999354850", "min_balance": "40000000",
        "trustlines": [], "server_time": 1793058206_u64
    });
    let estimate = json!({
        "network": "stellar", "fee": { "asset": "XLM", "amount": "100", "decimals": 7 },
        "recipient": { "exists": true, "trustline": null, "memo_required": false }
    });
    let mut request = send("stellar", native("XLM", 7), &to, "25000000", inputs, estimate);
    request["options"] = json!({ "memo": "12345" });
    let (summary, signed) = decode_and_sign(&request);
    assert_eq!(summary["action"], "stellar_payment");
    assert_eq!(summary["details"]["memo"], "12345");
    assert_eq!(signed["encoding"], "base64");

    // The signature (the envelope's last 64 bytes) covers the transaction hash.
    let envelope = STANDARD.decode(signed["raw"].as_str().unwrap()).unwrap();
    let hash = hex_bytes(signed["hash"].as_str().unwrap());
    assert!(ed_verifies(NetworkId::Stellar, &hash, &envelope[envelope.len() - 64..]));
}

// ---- Bittensor ----

#[test]
fn a_bittensor_transfer_is_signed_and_the_signature_verifies() {
    let _wallet = unlocked();
    let owner = address(NetworkId::Bittensor);
    let to = {
        let me = nc_wallet_core::Mnemonic::parse(ABANDON).unwrap();
        nc_wallet_core::derive(&me, "", nc_wallet_core::Network::Bittensor, 1).unwrap().address
    };
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
    let request = send("bittensor", native("TAO", 9), &to, "1500000000", inputs, estimate);
    let (summary, signed) = decode_and_sign(&request);
    assert_eq!(summary["action"], "tao_transfer");
    assert_eq!(summary["details"], json!({ "recipient": to, "amount": "1500000000" }));
    assert_eq!(signed["encoding"], "hex");

    let extrinsic = hex_bytes(signed["raw"].as_str().unwrap());
    let prefix = match extrinsic[0] & 3 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 1 + usize::from(extrinsic[0] >> 2) + 4,
    };
    let body = &extrinsic[prefix..];
    assert_eq!(body[0], 0x84, "a signed extrinsic, format 4");
    let sender: [u8; 32] = body[2..34].try_into().unwrap();
    assert_eq!(body[34], 0x01, "sr25519");
    assert_eq!(sender.as_slice(), public_key(NetworkId::Bittensor).as_slice());
    let signature = schnorrkel::Signature::from_bytes(&body[35..99]).unwrap();
    let transfer = Transfer {
        sender,
        dest: bittensor::parse_address(&to).unwrap(),
        value: 1_500_000_000,
        call_index: CallIndex { pallet: 5, call: 3 },
        nonce: 77,
        tip: 0,
        period: 64,
        birth: 9_371_216,
        birth_hash: hex_bytes("05282fae70442737bb48e0ecc0bca971c2e63dc8b9698857810174804f2a68a9")
            .try_into()
            .unwrap(),
        spec_version: 486,
        transaction_version: 1,
        genesis_hash: hex_bytes("2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03")
            .try_into()
            .unwrap(),
    };
    let payload = transfer.signing_payload().unwrap();
    let public = schnorrkel::PublicKey::from_bytes(&sender).unwrap();
    assert!(public.verify_simple(b"substrate", &payload, &signature).is_ok());
    assert_eq!(
        signed["hash"],
        format!("0x{}", hex::encode(bittensor::extrinsic::blake2_256(&extrinsic)))
    );
}

// ---- what the app depends on around signing ----

#[test]
fn a_request_that_changed_after_the_review_is_not_signed() {
    let _wallet = unlocked();
    let owner = address(NetworkId::Ethereum);
    let estimate = json!({
        "network": "ethereum", "gas_limit": "21000", "gas_price": "6000000", "eip1559": true,
        "max_fee_per_gas": "111417878", "max_priority_fee_per_gas": "10000000",
        "fee": { "asset": "ETH", "amount": "2339755638000", "decimals": 18 },
        "recipient": { "is_contract": false }
    });
    let request = send(
        "ethereum",
        native("ETH", 18),
        BOB,
        "1000000000000000",
        evm_inputs(&owner, 1),
        estimate,
    );
    let text = request.to_string();
    let decoded = decode_request(0, text.clone()).unwrap();

    // Another amount, another recipient, another account, another fee: none signs.
    for changed in [
        {
            let mut r = request.clone();
            r["amount"] = json!("1000000000000001");
            r
        },
        {
            let mut r = request.clone();
            r["to"] = json!("0xdAC17F958D2ee523a2206206994597C13D831ec7");
            r
        },
        {
            let mut r = request.clone();
            r["inputs"]["nonce"] = json!(5970);
            r
        },
    ] {
        assert_eq!(
            sign_request(0, changed.to_string(), decoded.approval.clone()).unwrap_err(),
            SigningError::ApprovalMismatch
        );
    }
    assert_eq!(
        sign_request(1, text.clone(), decoded.approval.clone()).unwrap_err(),
        // Account 1's address is not the one the inputs name.
        SigningError::NotASigner
    );
    // An approval that is not 64 hex digits is refused before anything is read.
    for bad in ["", "abc", &"g".repeat(64), &"a".repeat(63)] {
        assert_eq!(
            sign_request(0, text.clone(), (*bad).to_owned()).unwrap_err(),
            SigningError::BadRequest
        );
    }
    // The right one signs, and signs the same bytes every time (RFC 6979).
    let first = sign_request(0, text.clone(), decoded.approval.clone()).unwrap();
    let second = sign_request(0, text, decoded.approval).unwrap();
    assert_eq!(first, second);
}

#[test]
fn a_locked_wallet_decodes_and_signs_nothing() {
    let _wallet = unlocked();
    let request = json!({ "kind": "send" }).to_string();
    vault::lock();
    assert_eq!(decode_request(0, request.clone()).unwrap_err(), SigningError::NotUnlocked);
    assert_eq!(sign_request(0, request, "0".repeat(64)).unwrap_err(), SigningError::NotUnlocked);
    assert_eq!(bitcoin_zpub(0).unwrap_err(), SigningError::NotUnlocked);
}

#[test]
fn what_the_engine_refuses_arrives_as_a_typed_error() {
    let _wallet = unlocked();
    let owner = address(NetworkId::Bitcoin);
    let to = {
        let me = nc_wallet_core::Mnemonic::parse(ABANDON).unwrap();
        nc_wallet_core::derive(&me, "", nc_wallet_core::Network::Bitcoin, 1).unwrap().address
    };
    let btc = |amount: &str| {
        send("bitcoin", native("BTC", 8), &to, amount, bitcoin_inputs(&owner), bitcoin_estimate())
            .to_string()
    };
    // More than the outputs hold; less than the network relays.
    assert_eq!(code(decode_request(0, btc("56389"))), SigningError::InsufficientFunds);
    assert_eq!(code(decode_request(0, btc("100"))), SigningError::Dust);
    // Garbage in every form.
    assert_eq!(code(decode_request(0, "not json".to_owned())), SigningError::BadRequest);
    assert_eq!(code(decode_request(0, "[]".to_owned())), SigningError::BadRequest);
    assert_eq!(
        code(decode_request(0, json!({ "kind": "mint_a_coin" }).to_string())),
        SigningError::BadRequest
    );
    assert_eq!(code(decode_request(u32::MAX, btc("1000"))), SigningError::AccountIndexOutOfRange);
    // An output that is not at its place in this account (the key there does not own it).
    let mut foreign: Value = serde_json::from_str(&btc("1000")).unwrap();
    foreign["inputs"]["utxos"][0]["address"] = json!(to);
    assert_eq!(code(decode_request(0, foreign.to_string())), SigningError::NotASigner);
    let mut other: Value = serde_json::from_str(&btc("1000")).unwrap();
    other["inputs"]["address"] = json!(to);
    assert_eq!(code(decode_request(0, other.to_string())), SigningError::NotASigner);
    // A request of 256 KiB and a byte is too much to read.
    assert_eq!(code(decode_request(0, " ".repeat(262_145))), SigningError::BadRequest);
}

#[test]
fn addresses_are_checked_by_the_core_per_network() {
    // No wallet needed.
    let _one_at_a_time = serial();
    let ok = |network: NetworkId, text: &str| {
        let check = validate_address(network, text.to_owned());
        assert!(check.valid, "{text} on {network:?}: {:?}", check.problem);
        assert_eq!(check.problem, None);
        check.normalized.unwrap()
    };
    let no = |network: NetworkId, text: &str| {
        let check = validate_address(network, text.to_owned());
        assert!(!check.valid, "{text} on {network:?}");
        assert_eq!(check.normalized, None);
        check.problem.unwrap()
    };

    // EVM: lower case is taken and given its checksum form; a wrong mixed case is not.
    for network in [NetworkId::Ethereum, NetworkId::BnbChain, NetworkId::Polygon, NetworkId::Base] {
        assert_eq!(
            ok(network, "0x9858effd232b4033e47d90003d41ec34ecaeda94"),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(ok(network, BOB), BOB);
        assert_eq!(
            no(network, "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBBb"),
            AddressProblem::Checksum
        );
        assert_eq!(no(network, &format!("0x{}", "0".repeat(40))), AddressProblem::ZeroAddress);
        assert_eq!(no(network, "0x1234"), AddressProblem::Format);
        assert_eq!(no(network, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"), AddressProblem::Format);
    }
    assert_eq!(no(NetworkId::Ethereum, ""), AddressProblem::Empty);
    assert_eq!(no(NetworkId::Ethereum, "   "), AddressProblem::Empty);

    ok(NetworkId::Tron, TRON_USDT);
    assert_eq!(no(NetworkId::Tron, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u"), AddressProblem::Format);
    assert_eq!(no(NetworkId::Tron, BOB), AddressProblem::Format);

    for bitcoin in [
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    ] {
        ok(NetworkId::Bitcoin, bitcoin);
    }
    // A testnet address, and one with a bad checksum.
    assert_eq!(
        no(NetworkId::Bitcoin, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
        AddressProblem::Format
    );
    assert_eq!(
        no(NetworkId::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyx"),
        AddressProblem::Format
    );

    ok(NetworkId::Solana, "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB");
    assert_eq!(
        no(NetworkId::Solana, "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNY0"),
        AddressProblem::Format
    );
    assert_eq!(
        no(NetworkId::Solana, "11111111111111111111111111111111"),
        AddressProblem::ZeroAddress
    );

    ok(NetworkId::Stellar, "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN");
    // A muxed address (M...), an account and an id, is one to pay; a secret seed (S...) is not.
    ok(NetworkId::Stellar, "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK");
    assert_eq!(
        no(NetworkId::Stellar, "SAV76USXIJOBMEQXPANUOQM6F5LIOTLPDIDVRJBFFE2MDJXG24TAPUU7"),
        AddressProblem::Format
    );
    assert_eq!(
        no(
            NetworkId::Solana,
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"
        ),
        AddressProblem::Format
    );

    ok(NetworkId::Bittensor, "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
    // Polkadot's prefix is another network's.
    assert_eq!(
        no(NetworkId::Bittensor, "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"),
        AddressProblem::Format
    );
}
