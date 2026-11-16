//! Bitcoin encoding, signing and planning against vectors from outside this
//! crate: BIP-143, real mainnet transactions, Bitcoin Core's address and
//! policy data, BIP-84's wallet, Trust Wallet Core's.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use k256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;

use super::plan::{Amount, FeeRate, Request, Utxo, plan, quote};
use super::script::{dust_limit, hash160, p2wpkh_program, script_for_address};
use super::tx::{SighashCache, Transaction, TxIn, TxOut, hash_to_hex};
use super::{Chain, account};
use crate::hexutil;
use crate::key::SigningKey;
use crate::mnemonic::Mnemonic;
use crate::tx_error::TxError;

const BIP143: &str = include_str!("../../tests/vectors/bip-0143-native-p2wpkh.txt");
const REAL: &str = include_str!("../../tests/vectors/real-bitcoin-transactions.json");
const KEY_IO_VALID: &str = include_str!("../../tests/vectors/key_io_valid.json");
const KEY_IO_INVALID: &str = include_str!("../../tests/vectors/key_io_invalid.json");
const CORE_DUST: &str = include_str!("../../tests/vectors/bitcoin-core-getdustthreshold.txt");

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn h(text: &str) -> Vec<u8> {
    hexutil::decode(text).unwrap()
}

fn key(hex: &str) -> SigningKey {
    SigningKey::secp256k1(&h(hex).try_into().unwrap()).unwrap()
}

// ---- a reader of the wire format, written for the tests -----------------------

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> &[u8] {
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        head
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }
    fn count(&mut self) -> usize {
        match self.take(1)[0] {
            0xfd => usize::from(u16::from_le_bytes(self.take(2).try_into().unwrap())),
            0xfe => usize::try_from(self.u32()).unwrap(),
            0xff => usize::try_from(self.u64()).unwrap(),
            n => usize::from(n),
        }
    }
    fn bytes(&mut self) -> Vec<u8> {
        let n = self.count();
        self.take(n).to_vec()
    }
}

/// Reads a serialised transaction, with or without witnesses.
fn decode(raw: &[u8]) -> Transaction {
    let mut r = Reader(raw);
    let version = r.u32();
    let segwit = r.0[0] == 0;
    if segwit {
        assert_eq!(r.take(2), [0, 1]);
    }
    let mut inputs: Vec<TxIn> = (0..r.count())
        .map(|_| TxIn {
            prev_txid: r.take(32).try_into().unwrap(),
            prev_vout: r.u32(),
            script_sig: r.bytes(),
            sequence: r.u32(),
            witness: Vec::new(),
        })
        .collect();
    let outputs =
        (0..r.count()).map(|_| TxOut { value: r.u64(), script_pubkey: r.bytes() }).collect();
    if segwit {
        for input in &mut inputs {
            input.witness = (0..r.count()).map(|_| r.bytes()).collect();
        }
    }
    let lock_time = r.u32();
    assert!(r.0.is_empty());
    Transaction { version, inputs, outputs, lock_time }
}

/// The value a line `name:` of the BIP's vector states, after the colon.
fn bip143(name: &str) -> String {
    let line = BIP143.lines().find(|l| l.trim_start().starts_with(name)).unwrap();
    line.split_once(':').unwrap().1.trim().to_owned()
}

/// The hex on the line after one that starts with `marker`.
fn bip143_after(marker: &str) -> String {
    let mut lines = BIP143.lines();
    lines.find(|l| l.trim_start().starts_with(marker)).unwrap();
    lines.next().unwrap().trim().to_owned()
}

// ---- BIP-143 ----------------------------------------------------------------

#[test]
fn bip143_native_p2wpkh_is_reproduced_exactly() {
    let unsigned_hex = bip143_after("The following is an unsigned transaction");
    let signed_hex = bip143("The serialized signed transaction is");
    let unsigned = decode(&h(&unsigned_hex));
    // The second input's output: a P2WPKH program of 6 BTC, and its private
    // key (the BIP lists the key of the first input, a P2PK output, before).
    let secret = BIP143
        .lines()
        .filter(|l| l.contains("private key  :"))
        .nth(1)
        .unwrap()
        .split(':')
        .nth(1)
        .unwrap()
        .trim()
        .to_owned();
    let public = bip143("public key");
    let program = "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
    assert_eq!(
        hexutil::encode(&unsigned.encode()),
        unsigned_hex,
        "the encoder reads back what the BIP printed"
    );
    assert_eq!(unsigned.version, 1);
    assert_eq!(unsigned.lock_time, 17);

    // The sighash of the second input, 6 BTC.
    let digest = SighashCache::new(&unsigned)
        .p2wpkh_digest(&unsigned, 1, &h(program).try_into().unwrap(), 600_000_000)
        .unwrap();
    assert_eq!(hexutil::encode(&digest), bip143("sigHash"));

    // The key is the BIP's and hashes to the output's program.
    let signer = key(&secret);
    assert_eq!(hexutil::encode(signer.public_key()), public);
    assert_eq!(hexutil::encode(&hash160(signer.public_key())), program);

    // Signing reproduces the BIP's signature byte for byte (RFC 6979), and the
    // whole signed transaction once the first input's own signature, made by
    // other means in the BIP, is put in.
    let mut ours = unsigned.clone();
    ours.sign_p2wpkh_input(1, 600_000_000, &signer).unwrap();
    assert_eq!(
        hexutil::encode(&ours.inputs[1].witness[0]),
        format!("{}01", bip143("signature").trim_end_matches("01")),
    );
    assert_eq!(hexutil::encode(&ours.inputs[1].witness[1]), public);
    let published = decode(&h(&signed_hex));
    ours.inputs[0].script_sig = published.inputs[0].script_sig.clone();
    assert_eq!(hexutil::encode(&ours.encode()), signed_hex);
    assert_eq!(ours, published);
    assert_eq!(ours.txid(), published.txid());
}

// ---- real mainnet transactions ------------------------------------------------

#[test]
fn real_mainnet_transactions_verify_under_our_digests() {
    let file: Value = serde_json::from_str(REAL).unwrap();
    let txs = file["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 3);
    for t in txs {
        let name = t["txid"].as_str().unwrap();
        let raw = h(t["raw"].as_str().unwrap());
        let tx = decode(&raw);
        // Encoding, id, weight, size and fee are the chain's.
        assert_eq!(tx.encode(), raw, "{name}");
        assert_eq!(tx.txid_hex(), name);
        assert_eq!(tx.weight(), t["weight"].as_u64().unwrap(), "{name}: weight");
        assert_eq!(tx.encode().len() as u64, t["size"].as_u64().unwrap(), "{name}: size");
        // The fee is priced on an estimate that is never below the size as
        // signed, and is within a quarter of a virtual byte per signature of it.
        let scripts: Vec<&[u8]> = tx.outputs.iter().map(|o| o.script_pubkey.as_slice()).collect();
        let estimate = super::tx::estimate_vsize(tx.inputs.len(), &scripts);
        assert!(
            estimate >= tx.vsize() && estimate - tx.vsize() <= tx.inputs.len() as u64,
            "{name}"
        );
        let prevouts = t["prevouts"].as_array().unwrap();
        let spent: u64 = prevouts.iter().map(|p| p["value"].as_u64().unwrap()).sum();
        let created: u64 = tx.outputs.iter().map(|o| o.value).sum();
        assert_eq!(spent - created, t["fee"].as_u64().unwrap(), "{name}: fee");
        // The chain accepted each signature over our digest.
        let cache = SighashCache::new(&tx);
        for (i, (input, prevout)) in tx.inputs.iter().zip(prevouts).enumerate() {
            assert_eq!(hash_to_hex(&input.prev_txid), prevout["txid"].as_str().unwrap());
            let program = p2wpkh_program(&h(prevout["scriptpubkey"].as_str().unwrap())).unwrap();
            let (signature, public) = (&input.witness[0], &input.witness[1]);
            assert_eq!(hash160(public), program, "{name}:{i}: the key is the output's");
            assert_eq!(signature.last(), Some(&1), "SIGHASH_ALL");
            let digest =
                cache.p2wpkh_digest(&tx, i, &program, prevout["value"].as_u64().unwrap()).unwrap();
            let verifying = VerifyingKey::from_sec1_bytes(public).unwrap();
            let der = Signature::from_der(&signature[..signature.len() - 1]).unwrap();
            verifying.verify_prehash(&digest, &der).unwrap_or_else(|e| panic!("{name}:{i}: {e}"));
            // And a digest that differs in any way does not verify: change
            // an output, the sequence, the value, the lock time.
            let mut other = tx.clone();
            other.outputs[0].value += 1;
            let wrong = SighashCache::new(&other)
                .p2wpkh_digest(&other, i, &program, prevout["value"].as_u64().unwrap())
                .unwrap();
            assert!(verifying.verify_prehash(&wrong, &der).is_err());
            let wrong = cache
                .p2wpkh_digest(&tx, i, &program, prevout["value"].as_u64().unwrap() + 1)
                .unwrap();
            assert!(verifying.verify_prehash(&wrong, &der).is_err());
            let mut other = tx.clone();
            other.lock_time += 1;
            let wrong = SighashCache::new(&other)
                .p2wpkh_digest(&other, i, &program, prevout["value"].as_u64().unwrap())
                .unwrap();
            assert!(verifying.verify_prehash(&wrong, &der).is_err());
        }
    }
}

// ---- addresses and policy -------------------------------------------------------

#[test]
fn addresses_pay_the_scripts_bitcoin_core_lists() {
    let valid: Vec<Value> = serde_json::from_str(KEY_IO_VALID).unwrap();
    let (mut accepted, mut refused) = (0, 0);
    for entry in &valid {
        let (address, script, meta) =
            (entry[0].as_str().unwrap(), entry[1].as_str().unwrap(), &entry[2]);
        if meta["isPrivkey"] == true || meta["chain"] != "main" {
            continue;
        }
        let script = h(script);
        // A witness program of a later version has no rules yet: the wallet
        // does not send there.
        let sendable = matches!(
            script.as_slice(),
            [0x76, 0xa9, 0x14, .., 0x88, 0xac]
                | [0xa9, 0x14, .., 0x87]
                | [0x00, 0x14 | 0x20, ..]
                | [0x51, 0x20, ..]
        );
        if sendable {
            assert_eq!(script_for_address(address).unwrap(), script, "{address}");
            accepted += 1;
        } else {
            assert!(script_for_address(address).is_err(), "{address}");
            refused += 1;
        }
        // Case: all upper case is the same address in Bech32.
        if meta["tryCaseFlip"] == true && sendable {
            assert_eq!(script_for_address(&address.to_uppercase()).unwrap(), script);
        }
    }
    assert_eq!((accepted, refused), (12, 2));
    let invalid: Vec<Value> = serde_json::from_str(KEY_IO_INVALID).unwrap();
    for entry in &invalid {
        assert!(script_for_address(entry[0].as_str().unwrap()).is_err(), "{entry}");
    }
}

#[test]
fn testnet_and_hashless_addresses_are_refused() {
    for bad in [
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "mzK2FFDEhxqHcmrJw1ysqFkVyhUULo45hZ",
        "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        "1111111111111111111114oLvT2",
    ] {
        assert!(script_for_address(bad).is_err(), "{bad}");
    }
}

#[test]
fn dust_limits_follow_bitcoin_cores_rule() {
    // GetDustThreshold: the txout's size, plus the size of an input that
    // spends it (148 bytes, or 67 for a witness program), at 3000 sat/kvB.
    assert!(CORE_DUST.contains("546 satoshis at the default rate of 3000 sat/kvB."));
    assert!(CORE_DUST.contains("294 satoshis at the default rate of 3000 sat/kvB."));
    assert!(CORE_DUST.contains("nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);"));
    assert!(CORE_DUST.contains("nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above"));
    let threshold = |script_len: u64, witness: bool| {
        let txout = 8 + 1 + script_len;
        let input = if witness { 32 + 4 + 1 + 107 / 4 + 4 } else { 32 + 4 + 1 + 107 + 4 };
        (txout + input) * 3000 / 1000
    };
    let p2pkh = script_for_address("1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo").unwrap();
    let p2sh = script_for_address("36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm").unwrap();
    let p2wpkh = script_for_address("bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv").unwrap();
    let p2wsh =
        script_for_address("bc1qyucykdlhp62tezs0hagqury402qwhk589q80tqs5myh3rxq34nwqhkdhv7")
            .unwrap();
    let p2tr = script_for_address("bc1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36s6jjnnu")
        .unwrap();
    assert_eq!(dust_limit(&p2pkh), 546);
    assert_eq!(dust_limit(&p2wpkh), 294);
    for (script, witness) in
        [(&p2pkh, false), (&p2sh, false), (&p2wpkh, true), (&p2wsh, true), (&p2tr, true)]
    {
        assert_eq!(dust_limit(script), threshold(script.len() as u64, witness));
    }
    assert_eq!((dust_limit(&p2sh), dust_limit(&p2wsh), dust_limit(&p2tr)), (540, 330, 330));
    assert_eq!(dust_limit(&[0x6a, 0x01, 0x00]), 0, "an OP_RETURN holds nothing");
}

// ---- the wallet: BIP-84's account ------------------------------------------------

fn seed() -> crate::mnemonic::Seed {
    Mnemonic::parse(ABANDON).unwrap().to_seed("")
}

const RECEIVE_0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const RECEIVE_1: &str = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";
const CHANGE_0: &str = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";

fn txid(n: u8) -> String {
    hexutil::encode(&[n; 32])
}

fn utxo(n: u8, value: u64, chain: Chain, index: u32) -> Utxo {
    let address = account(&seed(), 0, chain, index).unwrap().address;
    Utxo::new(&txid(n), u32::from(n), value, &address, chain, index).unwrap()
}

#[test]
fn bip84_addresses_are_the_ones_the_account_derives() {
    // BIP-84's test vectors, again, through the planner's inputs.
    assert_eq!(account(&seed(), 0, Chain::Receive, 0).unwrap().address, RECEIVE_0);
    assert_eq!(account(&seed(), 0, Chain::Receive, 1).unwrap().address, RECEIVE_1);
    assert_eq!(account(&seed(), 0, Chain::Change, 0).unwrap().address, CHANGE_0);
}

/// Checks a signed payment against its plan: every input verifies under its
/// own digest, the fee is inputs less outputs, the size is at most estimated.
fn check_signed(plan_: &super::Plan, signed: &super::SignedTransaction, rate: FeeRate) {
    let tx = decode(&signed.raw);
    assert_eq!(tx.encode(), signed.raw);
    assert_eq!(tx.txid(), signed.txid);
    assert_eq!(tx.vsize(), signed.vsize);
    assert!(signed.vsize <= plan_.estimated_vsize());
    assert_eq!(tx.version, 2);
    assert_eq!(tx.lock_time, 0);
    assert!(tx.inputs.iter().all(|i| i.sequence == 0xffff_fffd), "replace-by-fee is signalled");
    let spent: u64 = plan_.inputs.iter().map(Utxo::value).sum();
    let created: u64 = tx.outputs.iter().map(|o| o.value).sum();
    assert_eq!(spent - created, signed.fee);
    assert_eq!(signed.fee, plan_.fee);
    // The fee pays at least the rate on the size as signed.
    assert!(
        signed.fee >= rate.fee_for(signed.vsize),
        "{} < {}",
        signed.fee,
        rate.fee_for(signed.vsize)
    );
    let cache = SighashCache::new(&tx);
    for (i, (input, spend)) in tx.inputs.iter().zip(&plan_.inputs).enumerate() {
        let public = &input.witness[1];
        let digest = cache.p2wpkh_digest(&tx, i, &hash160(public), spend.value()).unwrap();
        let der = Signature::from_der(&input.witness[0][..input.witness[0].len() - 1]).unwrap();
        VerifyingKey::from_sec1_bytes(public).unwrap().verify_prehash(&digest, &der).unwrap();
        assert_eq!(der.normalize_s(), der, "low S");
    }
}

#[test]
fn a_payment_with_change_is_laid_out_and_signed() {
    let utxos = vec![
        utxo(1, 50_000, Chain::Receive, 0),
        utxo(2, 120_000, Chain::Receive, 1),
        utxo(3, 30_000, Chain::Change, 0),
    ];
    let rate = FeeRate::from_sat_per_vb(5);
    let request = Request {
        to: "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv",
        amount: Amount::Exact(100_000),
        utxos: &utxos,
        change_address: CHANGE_0,
        fee_rate: rate,
    };
    let planned = plan(&request).unwrap();
    // The largest output covers it alone: 100,000 plus the fee of a
    // one-input, two-output transaction (110 vB estimated at 5 sat/vB... 141).
    assert_eq!(planned.inputs.len(), 1);
    assert_eq!(planned.inputs[0].value(), 120_000);
    assert_eq!(planned.transaction.outputs.len(), 2);
    assert_eq!(planned.transaction.outputs[0].value, 100_000);
    assert_eq!(
        planned.transaction.outputs[0].script_pubkey,
        script_for_address(request.to).unwrap()
    );
    assert_eq!(planned.change, Some(1));
    assert_eq!(planned.transaction.outputs[1].script_pubkey, script_for_address(CHANGE_0).unwrap());
    // 1 input, 2 P2WPKH outputs, signature at its largest: (4 + 1 + 41 + 1 +
    // 2 * 31 + 4) bytes at 4 weight units, and 2 + 108 witness bytes at 1:
    // 562 weight units, which is 140.5, so 141 virtual bytes.
    assert_eq!(planned.estimated_vsize(), 141);
    assert_eq!(planned.fee, 141 * 5);
    assert_eq!(planned.transaction.outputs[1].value, 120_000 - 100_000 - 141 * 5);
    let signed = planned.sign(&seed(), 0).unwrap();
    check_signed(&planned, &signed, rate);
    // Deterministic: the same request, the same bytes.
    assert_eq!(plan(&request).unwrap().sign(&seed(), 0).unwrap(), signed);
}

#[test]
fn several_outputs_are_spent_when_one_is_not_enough() {
    let utxos = vec![
        utxo(1, 50_000, Chain::Receive, 0),
        utxo(2, 60_000, Chain::Receive, 1),
        utxo(3, 30_000, Chain::Change, 0),
    ];
    let rate = FeeRate::from_sat_per_kvb(1_640);
    let planned = plan(&Request {
        to: "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv",
        amount: Amount::Exact(100_000),
        utxos: &utxos,
        change_address: CHANGE_0,
        fee_rate: rate,
    })
    .unwrap();
    // The two largest, in that order.
    let values: Vec<u64> = planned.inputs.iter().map(Utxo::value).collect();
    assert_eq!(values, [60_000, 50_000]);
    assert_eq!(planned.fee, rate.fee_for(planned.estimated_vsize()));
    check_signed(&planned, &planned.sign(&seed(), 0).unwrap(), rate);
}

#[test]
fn send_max_spends_everything_into_one_output() {
    let utxos = vec![utxo(1, 50_000, Chain::Receive, 0), utxo(2, 60_000, Chain::Change, 0)];
    let rate = FeeRate::from_sat_per_vb(2);
    let planned = plan(&Request {
        to: RECEIVE_1,
        amount: Amount::All,
        utxos: &utxos,
        change_address: CHANGE_0,
        fee_rate: rate,
    })
    .unwrap();
    assert_eq!(planned.change, None);
    assert_eq!(planned.transaction.outputs.len(), 1);
    assert_eq!(planned.inputs.len(), 2);
    // 2 inputs, 1 output: (4 + 1 + 2 * 41 + 1 + 31 + 4) = 123 bytes at 4, and
    // 2 + 2 * 108 = 218 witness bytes at 1: 710 weight units, 177.5, so 178.
    assert_eq!(planned.estimated_vsize(), 178);
    assert_eq!(planned.fee, 356);
    assert_eq!(planned.transaction.outputs[0].value, 110_000 - 356);
    check_signed(&planned, &planned.sign(&seed(), 0).unwrap(), rate);
}

#[test]
fn trust_wallet_core_send_max_vector() {
    // tests/chains/Bitcoin/TWBitcoinSigningTests.cpp @ adf80f8b, SignMaxAmount:
    // one output of 10,189,534 satoshis at bc1qhkfq…, 1 sat/vB, to
    // bc1q2dsdlq…: the amount sent is 10,189,424 and the fee 110.
    let own = "bc1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z00ppggv";
    let spend = Utxo::new(
        "07c42b969286be06fae38528c85f0a1ce508d4df837eb5ac4cf5f2a7a9d65fa8",
        0,
        10_189_534,
        own,
        Chain::Receive,
        0,
    )
    .unwrap();
    let planned = plan(&Request {
        to: "bc1q2dsdlq3343vk29runkgv4yc292hmq53jedfjmp",
        amount: Amount::All,
        utxos: &[spend],
        change_address: own,
        fee_rate: FeeRate::from_sat_per_vb(1),
    })
    .unwrap();
    assert_eq!(planned.fee, 110);
    assert_eq!(planned.transaction.outputs[0].value, 10_189_534 - 110);
    assert_eq!(
        planned.transaction.outputs[0].script_pubkey,
        script_for_address("bc1q2dsdlq3343vk29runkgv4yc292hmq53jedfjmp").unwrap()
    );
}

fn send(utxos: &[Utxo], amount: Amount, rate: FeeRate) -> Result<super::Plan, TxError> {
    plan(&Request {
        to: "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv",
        amount,
        utxos,
        change_address: CHANGE_0,
        fee_rate: rate,
    })
}

#[test]
fn change_too_small_to_be_worth_an_output_goes_to_the_fee() {
    let utxos = [utxo(1, 100_000, Chain::Receive, 0)];
    let rate = FeeRate::from_sat_per_vb(5);
    // With change the fee is 705 and the change 295, under the 1,000 kept as
    // an output; without it the fee is 550 (110 vB) and 450 more goes to the
    // miners, less than the change would have been worth.
    assert_eq!(rate.min_change(), 1_000);
    let planned = send(&utxos, Amount::Exact(99_000), rate).unwrap();
    assert_eq!(planned.change, None);
    assert_eq!(planned.transaction.outputs.len(), 1);
    assert_eq!(planned.fee, 1_000);
    check_signed(&planned, &planned.sign(&seed(), 0).unwrap(), rate);
    // A little less, and the change is kept.
    let planned = send(&utxos, Amount::Exact(98_000), rate).unwrap();
    assert_eq!(planned.change, Some(1));
    assert_eq!(planned.transaction.outputs[1].value, 100_000 - 98_000 - 705);
}

#[test]
fn what_cannot_be_paid_is_refused() {
    let utxos = [utxo(1, 10_000, Chain::Receive, 0)];
    let rate = FeeRate::from_sat_per_vb(1);
    // Dust to the recipient: 294 is the least a P2WPKH output may hold.
    assert_eq!(
        send(&utxos, Amount::Exact(293), rate).unwrap_err(),
        TxError::Dust { amount: 293, limit: 294 }
    );
    assert!(send(&utxos, Amount::Exact(294), rate).is_ok());
    // More than the outputs hold, or than they hold with the fee.
    assert!(matches!(
        send(&utxos, Amount::Exact(10_001), rate).unwrap_err(),
        TxError::InsufficientFunds { available: 10_000, .. }
    ));
    assert!(matches!(
        send(&utxos, Amount::Exact(10_000), rate).unwrap_err(),
        TxError::InsufficientFunds { available: 10_000, .. }
    ));
    // Send max that leaves nothing after the fee.
    let tiny = [utxo(2, 300, Chain::Receive, 0)];
    assert!(send(&tiny, Amount::All, FeeRate::from_sat_per_vb(1)).is_err());
    // No outputs, a zero rate, an output listed twice.
    assert!(send(&[], Amount::Exact(1_000), rate).is_err());
    assert!(send(&utxos, Amount::Exact(1_000), FeeRate::from_sat_per_kvb(0)).is_err());
    let twice = [utxo(1, 10_000, Chain::Receive, 0), utxo(1, 10_000, Chain::Receive, 0)];
    assert!(send(&twice, Amount::Exact(1_000), rate).is_err());
}

#[test]
fn addresses_and_outputs_that_cannot_be_used_are_refused() {
    let utxos = [utxo(1, 100_000, Chain::Receive, 0)];
    let rate = FeeRate::from_sat_per_vb(1);
    let request = |to: &'static str, change: &'static str| {
        plan(&Request {
            to,
            amount: Amount::Exact(1_000),
            utxos: &utxos,
            change_address: change,
            fee_rate: rate,
        })
    };
    assert!(request("bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv", CHANGE_0).is_ok());
    // Every form a payment can go to.
    for to in [
        "1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo",
        "36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm",
        "bc1qyucykdlhp62tezs0hagqury402qwhk589q80tqs5myh3rxq34nwqhkdhv7",
        "bc1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36s6jjnnu",
    ] {
        assert!(request(to, CHANGE_0).is_ok(), "{to}");
    }
    // A testnet recipient; change to a script the wallet cannot spend from.
    assert!(request("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", CHANGE_0).is_err());
    assert!(
        request("bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv", "1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo")
            .is_err()
    );
    assert!(
        request(
            "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv",
            "bc1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36s6jjnnu"
        )
        .is_err()
    );
    // An output that is not P2WPKH, a txid that is not one, no value.
    assert!(
        Utxo::new(&txid(1), 0, 1_000, "1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo", Chain::Receive, 0)
            .is_err()
    );
    assert!(Utxo::new("abcd", 0, 1_000, RECEIVE_0, Chain::Receive, 0).is_err());
    assert!(Utxo::new(&txid(1), 0, 0, RECEIVE_0, Chain::Receive, 0).is_err());
    assert!(Utxo::new(&txid(1), 0, 2_100_000_000_000_001, RECEIVE_0, Chain::Receive, 0).is_err());
}

#[test]
fn an_output_the_named_key_does_not_own_is_not_signed() {
    // The address of receive 0, said to be receive 1.
    let wrong = Utxo::new(&txid(1), 0, 100_000, RECEIVE_0, Chain::Receive, 1).unwrap();
    let planned = send(&[wrong], Amount::Exact(1_000), FeeRate::from_sat_per_vb(1)).unwrap();
    assert_eq!(planned.sign(&seed(), 0).unwrap_err(), TxError::KeyMismatch { input: 0 });
    // The right one signs; a key of another curve does not.
    let right = Utxo::new(&txid(1), 0, 100_000, RECEIVE_0, Chain::Receive, 0).unwrap();
    let planned = send(&[right], Amount::Exact(1_000), FeeRate::from_sat_per_vb(1)).unwrap();
    assert!(planned.sign(&seed(), 0).is_ok());
    assert!(planned.sign_with(|_| Ok(SigningKey::ed25519(&[1; 32]))).is_err());
}

#[test]
fn equal_outputs_are_chosen_in_a_fixed_order() {
    let a = utxo(1, 50_000, Chain::Receive, 0);
    let b = utxo(2, 50_000, Chain::Receive, 1);
    for order in [[a.clone(), b.clone()], [b.clone(), a.clone()]] {
        let planned = send(&order, Amount::Exact(40_000), FeeRate::from_sat_per_vb(1)).unwrap();
        // Largest first, and by id as written between equals: 0101… before 0202….
        assert_eq!(planned.inputs.len(), 1);
        assert_eq!(planned.inputs[0].txid_hex(), txid(1));
    }
}

#[test]
fn a_transaction_nodes_would_not_relay_is_refused() {
    let utxos: Vec<Utxo> = (0..1_500u32)
        .map(|n| {
            let address = account(&seed(), 0, Chain::Receive, 0).unwrap().address;
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            Utxo::new(&hexutil::encode(&id), 0, 10_000, &address, Chain::Receive, 0).unwrap()
        })
        .collect();
    assert!(send(&utxos, Amount::All, FeeRate::from_sat_per_vb(1)).is_err());
    assert!(send(&utxos[..1_000], Amount::All, FeeRate::from_sat_per_vb(1)).is_ok());
}

#[test]
fn a_quote_is_the_payment_the_planner_lays_out() {
    // The chain client shows a fee from `quote` when a payment is composed and the engine signs what
    // `plan` lays out: for every set of coins, rate and amount they are one thing.
    let to = script_for_address("bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv").unwrap();
    let change = script_for_address(CHANGE_0).unwrap();
    let mut compared = 0;
    for rate in [1_000, 1_640, 5_000, 12_300, 50_000, 120_000].map(FeeRate::from_sat_per_kvb) {
        for values in [
            vec![100_000],
            vec![60_000, 50_000],
            vec![100_000, 100_000],
            vec![40_000, 30_000, 20_000, 10_000],
            vec![5_000, 4_000, 3_000, 2_000, 1_000],
        ] {
            let utxos: Vec<Utxo> = values
                .iter()
                .enumerate()
                .map(|(n, v)| utxo(u8::try_from(n + 1).unwrap(), *v, Chain::Receive, 0))
                .collect();
            let total: u64 = values.iter().sum();
            for amount in (294..=total + 2_000).step_by(397) {
                let planned = send(&utxos, Amount::Exact(amount), rate);
                let quoted = quote(&values, amount, rate, &to, &change);
                match (planned, quoted) {
                    (Ok(planned), Ok(quoted)) => {
                        assert_eq!(quoted.fee, planned.fee, "{values:?} {amount}");
                        assert_eq!(quoted.inputs, planned.inputs.len(), "{values:?} {amount}");
                        assert_eq!(quoted.vsize, planned.estimated_vsize(), "{values:?} {amount}");
                        let kept = planned.change.map(|at| planned.transaction.outputs[at].value);
                        assert_eq!(quoted.change, kept, "{values:?} {amount}");
                    }
                    (Err(planned), Err(quoted)) => assert_eq!(planned, quoted),
                    (planned, quoted) => panic!("{values:?} {amount}: {planned:?} {quoted:?}"),
                }
                compared += 1;
            }
        }
    }
    assert!(compared > 2_000, "{compared}");
}

#[test]
fn a_quote_keeps_change_only_when_it_is_worth_an_output_and_says_what_the_fee_is() {
    let to = script_for_address("bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv").unwrap();
    let change = script_for_address(CHANGE_0).unwrap();
    let at = |sat_per_vb: u64, values: &[u64], amount: u64| {
        quote(values, amount, FeeRate::from_sat_per_vb(sat_per_vb), &to, &change).unwrap()
    };
    // 10 sat/vB on one 100,000-satoshi output paying 98,000: 590 would be left after a fee of 1,410,
    // which is not worth an output (1,000), so it all goes to the fee: 2,000, as signed.
    let q = at(10, &[100_000], 98_000);
    assert_eq!((q.inputs, q.change, q.fee), (1, None, 2_000));
    // 1 sat/vB on two 100,000 outputs paying 99,700: one output leaves 300 (not worth keeping), two
    // leave worthwhile change, and any number that does is preferred.
    let q = at(1, &[100_000, 100_000], 99_700);
    assert_eq!((q.inputs, q.fee), (2, 209));
    assert_eq!(q.change, Some(200_000 - 99_700 - 209));
    // Changing the order of the values changes nothing.
    assert_eq!(at(1, &[100_000, 100_000], 99_700), q);
    assert_eq!(at(5, &[10_000, 90_000, 50_000], 70_000), at(5, &[90_000, 50_000, 10_000], 70_000));
}

#[test]
fn a_quote_refuses_what_the_planner_would_and_values_no_one_can_hold() {
    let to = script_for_address("bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv").unwrap();
    let change = script_for_address(CHANGE_0).unwrap();
    let rate = FeeRate::from_sat_per_vb(5);
    assert!(matches!(quote(&[100_000], 100, rate, &to, &change), Err(TxError::Dust { .. })));
    assert!(matches!(
        quote(&[10_000], 100_000, rate, &to, &change),
        Err(TxError::InsufficientFunds { .. })
    ));
    assert!(matches!(
        quote(&[], 1_000, rate, &to, &change),
        Err(TxError::InsufficientFunds { .. })
    ));
    // Values a node made up: more than there is bitcoin, and a sum past it. Nothing overflows.
    for values in [vec![u64::MAX], vec![u64::MAX, u64::MAX], vec![super::tx::MAX_MONEY, 1]] {
        for amount in [1_000, u64::MAX - 10, u64::MAX] {
            assert!(
                matches!(quote(&values, amount, rate, &to, &change), Err(TxError::Invalid { .. })),
                "{values:?} {amount}"
            );
        }
    }
    // Spending more outputs than nodes relay: spend fewer at once.
    let many = vec![100_000; 1_500];
    assert!(matches!(quote(&many, 149_000_000, rate, &to, &change), Err(TxError::Invalid { .. })));
    assert!(quote(&many, 100_000_000, rate, &to, &change).is_ok());
}

#[test]
fn fee_rates_round_up_to_the_satoshi() {
    // 1.64 sat/vB on 144 vB is 236.16, so 237.
    assert_eq!(FeeRate::from_sat_per_kvb(1_640).fee_for(144), 237);
    assert_eq!(FeeRate::from_sat_per_vb(2).fee_for(144), 288);
    assert_eq!(FeeRate::from_sat_per_vb(2).sat_per_kvb(), 2_000);
    // Change is kept at 1,000 satoshis, or what making and spending it costs
    // at the rate if that is more: 99 vB.
    assert_eq!(FeeRate::from_sat_per_kvb(1_640).min_change(), 1_000);
    assert_eq!(FeeRate::from_sat_per_kvb(50_000).min_change(), 4_950);
}

// ---- public derivation from a zpub ----------------------------------------------

#[test]
fn addresses_come_from_the_zpub_alone_as_bip84_lists_them() {
    // BIP-84's wallet "abandon … about": its account zpub, and the addresses the BIP lists.
    let zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    let receive = super::addresses_from_zpub(zpub, Chain::Receive, 0, 2).unwrap();
    assert_eq!(
        receive,
        [
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        ]
    );
    let change = super::addresses_from_zpub(zpub, Chain::Change, 0, 1).unwrap();
    assert_eq!(change, ["bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"]);
    // Windows are windows: asking for the second address alone gives the second.
    assert_eq!(
        super::addresses_from_zpub(zpub, Chain::Receive, 1, 1).unwrap(),
        ["bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"]
    );
    // And the same as the seed derives, through the secret path.
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    let seed = phrase.to_seed("");
    assert_eq!(super::account_zpub(&seed, 0).unwrap(), zpub);
    assert_eq!(account(&seed, 0, Chain::Receive, 1).unwrap().address, receive[1]);
    // Not a key.
    assert!(super::addresses_from_zpub("zpub-not-a-key", Chain::Receive, 0, 1).is_none());
    assert!(super::addresses_from_zpub(zpub, Chain::Receive, u32::MAX, 5).is_none());
}
