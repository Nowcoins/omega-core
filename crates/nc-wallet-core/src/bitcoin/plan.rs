//! Choosing what a payment spends, laying the transaction out, and signing it.
//!
//! The coin selection is deterministic: the largest outputs first, equal values in outpoint order, so one request always builds
//! one transaction; change kept only when it is worth an output; and a last
//! resort without change when the inputs cover the payment and the fee but
//! cannot leave worthwhile change.
//!
//! All of it is pure. The caller supplies the outputs it holds and the fee
//! rate it reads from the network.

use super::script::{
    dust_limit, hash160, p2wpkh_hash_of_address, p2wpkh_script, script_for_address,
};
use super::tx::{
    MAX_MONEY, RBF_SEQUENCE, SighashCache, TX_VERSION, Transaction, TxIn, TxOut, estimate_vsize,
    hash_from_hex,
};
use super::{Chain, signing_key};
use crate::mnemonic::Seed;
use crate::tx_error::TxError;
use crate::{hexutil, key::SigningKey};

/// The least change worth an output of its own, in satoshis, however low fees
/// are. Less is added to the fee.
pub const MIN_CHANGE: u64 = 1_000;

/// The largest transaction nodes relay, in virtual bytes: 400,000 weight
/// units. About 1,470 P2WPKH inputs.
pub const MAX_STANDARD_VSIZE: u64 = 100_000;

/// Virtual bytes a P2WPKH change output adds to a transaction.
const CHANGE_OUTPUT_VBYTES: u64 = 31;

/// Virtual bytes spending a P2WPKH output later costs.
const P2WPKH_INPUT_VBYTES: u64 = 68;

/// A fee rate, held in satoshis per thousand virtual bytes so that a rate
/// between two whole satoshis a byte (1.64 sat/vB is common) is exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeRate(u64);

impl FeeRate {
    /// A rate in whole satoshis per virtual byte.
    #[must_use]
    pub const fn from_sat_per_vb(rate: u64) -> Self {
        Self(rate.saturating_mul(1_000))
    }

    /// A rate in satoshis per thousand virtual bytes (1,640 is 1.64 sat/vB).
    #[must_use]
    pub const fn from_sat_per_kvb(rate: u64) -> Self {
        Self(rate)
    }

    /// The rate in satoshis per thousand virtual bytes.
    #[must_use]
    pub const fn sat_per_kvb(self) -> u64 {
        self.0
    }

    /// What `vsize` virtual bytes cost at this rate, rounded up to the
    /// satoshi.
    #[must_use]
    pub fn fee_for(self, vsize: u64) -> u64 {
        self.0.saturating_mul(vsize).div_ceil(1_000)
    }

    /// The least change kept as an output at this rate: [`MIN_CHANGE`], or
    /// what the output costs to create now and to spend later at the same
    /// rate if that is more.
    #[must_use]
    pub fn min_change(self) -> u64 {
        MIN_CHANGE.max(self.fee_for(CHANGE_OUTPUT_VBYTES + P2WPKH_INPUT_VBYTES))
    }
}

/// An output the wallet holds and may spend: an unspent P2WPKH output paid to
/// one of its own addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// The transaction that created it, in internal byte order.
    txid: [u8; 32],
    /// Which of that transaction's outputs.
    vout: u32,
    /// Its value, in satoshis.
    value: u64,
    /// Which address chain of the wallet's account it was paid on.
    chain: Chain,
    /// The address index on that chain.
    index: u32,
    /// The key hash its address pays.
    pubkey_hash: [u8; 20],
}

impl Utxo {
    /// An unspent output, as a block explorer or the wallet's API lists it:
    /// the transaction id as written (64 hex digits), the output number, its
    /// value, the `bc1q…` address it was paid to, and which of the wallet's
    /// addresses that is (`chain` and `index`, as [`super::account`] derives
    /// them). Signing checks that the key at that place really owns the
    /// address.
    pub fn new(
        txid: &str,
        vout: u32,
        value: u64,
        address: &str,
        chain: Chain,
        index: u32,
    ) -> Result<Self, TxError> {
        let txid = hash_from_hex(txid).ok_or(TxError::invalid("txid", "is not 64 hex digits"))?;
        if value == 0 || value > MAX_MONEY {
            return Err(TxError::invalid("value", "must be from 1 satoshi to 21 million bitcoin"));
        }
        Ok(Self { txid, vout, value, chain, index, pubkey_hash: p2wpkh_hash_of_address(address)? })
    }

    /// The value, in satoshis.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    /// The id of the transaction that created it, as written.
    #[must_use]
    pub fn txid_hex(&self) -> String {
        super::tx::hash_to_hex(&self.txid)
    }

    /// The output number.
    #[must_use]
    pub fn vout(&self) -> u32 {
        self.vout
    }

    /// Which address chain it was paid on.
    #[must_use]
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// The address index on that chain.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Whether this output is paid to the address of the compressed public key `public_key`
    /// (33 bytes): that the key at its place in the account owns it.
    #[must_use]
    pub fn is_paid_to(&self, public_key: &[u8]) -> bool {
        hash160(public_key) == self.pubkey_hash
    }

    /// Outpoint order, how equal values are sorted: by the
    /// transaction id as written, then the output number.
    fn outpoint_key(&self) -> ([u8; 32], u32) {
        let mut written = self.txid;
        written.reverse();
        (written, self.vout)
    }
}

/// How much a payment sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amount {
    /// This many satoshis; the fee is paid on top, and change comes back.
    Exact(u64),
    /// Everything the outputs offered hold, less the fee: "send max". One
    /// output, no change.
    All,
}

/// What a payment is asked to do.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// Who is paid: any mainnet address (P2PKH, P2SH, P2WPKH, P2WSH, P2TR).
    pub to: &'a str,
    /// How much.
    pub amount: Amount,
    /// The outputs the wallet may spend from.
    pub utxos: &'a [Utxo],
    /// Where the change goes: a `bc1q…` address of the wallet's own, normally
    /// the next unused one on the change chain.
    pub change_address: &'a str,
    /// What the fee costs per virtual byte.
    pub fee_rate: FeeRate,
}

/// A payment chosen and laid out, not yet signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The transaction, without witnesses: version 2, no lock time, every
    /// input signalling replace-by-fee.
    pub transaction: Transaction,
    /// The outputs it spends, in the transaction's order.
    pub inputs: Vec<Utxo>,
    /// What it pays the miners: the inputs' value less the outputs'.
    pub fee: u64,
    /// The index of the change output, if there is one.
    pub change: Option<usize>,
}

/// A signed payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The transaction to broadcast, in the segwit serialisation.
    pub raw: Vec<u8>,
    /// Its id, in internal byte order; [`Self::txid_hex`] writes it as it is
    /// shown.
    pub txid: [u8; 32],
    /// Its virtual size as signed.
    pub vsize: u64,
    /// What it pays the miners, in satoshis.
    pub fee: u64,
}

impl SignedTransaction {
    /// The transaction id as it is written: hex, in reversed byte order.
    #[must_use]
    pub fn txid_hex(&self) -> String {
        super::tx::hash_to_hex(&self.txid)
    }

    /// The raw transaction as hex.
    #[must_use]
    pub fn raw_hex(&self) -> String {
        hexutil::encode(&self.raw)
    }
}

/// Chooses the outputs a payment spends and lays it out.
///
/// An exact amount spends the largest outputs first until the amount, the fee
/// and change worth an output ([`FeeRate::min_change`]) are covered, and pays
/// the recipient first, then the change. Where no choice of the outputs
/// leaves worthwhile change but the fewest of the largest still cover the
/// amount and the fee, the payment goes without change and the remainder
/// goes to the fee, which is less than the change would have been worth.
/// [`Amount::All`] spends every output into one.
pub fn plan(request: &Request<'_>) -> Result<Plan, TxError> {
    let to_script = script_for_address(request.to)?;
    let change_hash = p2wpkh_hash_of_address(request.change_address)?;
    let change_script = p2wpkh_script(&change_hash);
    if request.fee_rate.sat_per_kvb() == 0 {
        return Err(TxError::invalid("fee rate", "must not be zero"));
    }
    let available = checked_inputs(request.utxos)?;
    let rate = request.fee_rate;
    let dust = dust_limit(&to_script);

    // Largest first; equal values in outpoint order, so one request always
    // builds one transaction.
    let mut candidates: Vec<&Utxo> = request.utxos.iter().collect();
    candidates.sort_by(|a, b| {
        b.value.cmp(&a.value).then_with(|| a.outpoint_key().cmp(&b.outpoint_key()))
    });

    let mut outputs = vec![TxOut { value: 0, script_pubkey: to_script.clone() }];
    let values: Vec<u64> = candidates.iter().map(|u| u.value).collect();
    let (count, change) = match request.amount {
        Amount::All => {
            let fee = rate.fee_for(estimate_vsize(candidates.len(), &[&to_script]));
            let paid = available.checked_sub(fee).filter(|paid| *paid >= dust).ok_or(
                TxError::InsufficientFunds { needed: fee.saturating_add(dust), available },
            )?;
            outputs[0].value = paid;
            (candidates.len(), None)
        }
        Amount::Exact(amount) => {
            let quoted = quote(&values, amount, rate, &to_script, &change_script)?;
            outputs[0].value = amount;
            (quoted.inputs, quoted.change)
        }
    };

    let mut change_index = None;
    if let Some(change) = change {
        outputs.push(TxOut { value: change, script_pubkey: change_script });
        change_index = Some(outputs.len() - 1);
    }

    let chosen: Vec<Utxo> = candidates[..count].iter().map(|u| (*u).clone()).collect();
    let inputs = chosen
        .iter()
        .map(|utxo| TxIn {
            prev_txid: utxo.txid,
            prev_vout: utxo.vout,
            script_sig: Vec::new(),
            sequence: RBF_SEQUENCE,
            witness: Vec::new(),
        })
        .collect();
    let transaction = Transaction { version: TX_VERSION, inputs, outputs, lock_time: 0 };
    let spent: u64 = chosen.iter().map(|u| u.value).sum();
    let created: u64 = transaction.outputs.iter().map(|o| o.value).sum();
    let plan = Plan {
        fee: spent.saturating_sub(created),
        transaction,
        inputs: chosen,
        change: change_index,
    };
    let vsize = plan.estimated_vsize();
    relayable(vsize)?;
    Ok(plan)
}

/// What an exact payment spends and pays: how many of the largest outputs, what it costs, what comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    /// How many of the largest outputs it spends.
    pub inputs: usize,
    /// Its virtual size once signed, at most.
    pub vsize: u64,
    /// What it pays the miners: what the outputs hold less the payment and the change. Where what
    /// is left is too little for a change output it is part of the fee.
    pub fee: u64,
    /// The change output's value, if there is one.
    pub change: Option<u64>,
}

/// Chooses what an exact payment of `amount` to `to_script` spends, given the `values` of the
/// outputs the wallet may spend (in any order: the largest go first): the one rule [`plan`] lays a
/// transaction out by, and the one an estimate of its fee must be read from, so that the fee shown
/// when composing is the fee signed. `change_script` is the script the change would be paid to.
///
/// Change is kept only when it is worth an output ([`FeeRate::min_change`]), and then any number of
/// outputs that leaves that much is preferred; where none does but the fewest of the largest still
/// cover the amount and the fee, the payment goes without change.
pub fn quote(
    values: &[u64],
    amount: u64,
    rate: FeeRate,
    to_script: &[u8],
    change_script: &[u8],
) -> Result<Quote, TxError> {
    let dust = dust_limit(to_script);
    if amount < dust {
        return Err(TxError::Dust { amount, limit: dust });
    }
    let mut largest_first = values.to_vec();
    largest_first.sort_unstable_by(|a, b| b.cmp(a));
    largest_first
        .iter()
        .try_fold(0_u64, |total, value| total.checked_add(*value).filter(|t| *t <= MAX_MONEY))
        .ok_or(TxError::invalid("inputs", "hold more than there is"))?;
    let (inputs, change) =
        match select_with_change(&largest_first, amount, rate, to_script, change_script) {
            Some((count, change)) => (count, Some(change)),
            None => (cover_without_change(&largest_first, amount, rate, to_script)?, None),
        };
    let vsize = match change {
        Some(_) => estimate_vsize(inputs, &[to_script, change_script]),
        None => estimate_vsize(inputs, &[to_script]),
    };
    relayable(vsize)?;
    let spent = largest_first.iter().take(inputs).fold(0_u64, |total, v| total.saturating_add(*v));
    let fee = spent.saturating_sub(amount).saturating_sub(change.unwrap_or(0));
    Ok(Quote { inputs, vsize, fee, change })
}

/// Refuses a transaction larger than nodes relay.
fn relayable(vsize: u64) -> Result<(), TxError> {
    if vsize > MAX_STANDARD_VSIZE {
        return Err(TxError::invalid(
            "inputs",
            "make a transaction larger than nodes relay: spend fewer at once",
        ));
    }
    Ok(())
}

impl Plan {
    /// Its virtual size once signed, at most.
    #[must_use]
    pub fn estimated_vsize(&self) -> u64 {
        let scripts: Vec<&[u8]> =
            self.transaction.outputs.iter().map(|o| o.script_pubkey.as_slice()).collect();
        estimate_vsize(self.inputs.len(), &scripts)
    }

    /// Signs every input with the keys of BIP-84 account `account`, derived from
    /// `seed` at each output's own chain and index, and returns the transaction ready to
    /// broadcast. A key that does not own the address its output was paid to is refused.
    pub fn sign(&self, seed: &Seed, account: u32) -> Result<SignedTransaction, TxError> {
        self.sign_with(|utxo| Ok(signing_key(seed, account, utxo.chain, utxo.index)?))
    }

    /// [`Self::sign`] with the keys supplied by `key_for`, which is asked for
    /// each input's key in turn (for a caller that holds keys another way).
    /// Each key is checked against the address its output was paid to.
    pub fn sign_with(
        &self,
        mut key_for: impl FnMut(&Utxo) -> Result<SigningKey, TxError>,
    ) -> Result<SignedTransaction, TxError> {
        let mut transaction = self.transaction.clone();
        let cache = SighashCache::new(&transaction);
        for (index, utxo) in self.inputs.iter().enumerate() {
            let key = key_for(utxo)?;
            if hash160(key.public_key()) != utxo.pubkey_hash {
                return Err(TxError::KeyMismatch { input: index });
            }
            transaction.sign_p2wpkh_input_cached(&cache, index, utxo.value, &key)?;
        }
        Ok(SignedTransaction {
            raw: transaction.encode(),
            txid: transaction.txid(),
            vsize: transaction.vsize(),
            fee: self.fee,
        })
    }
}

/// How many of the largest `values` an exact payment spends, and its
/// change, worth an output. `None` where no number of them leaves that much.
fn select_with_change(
    values: &[u64],
    amount: u64,
    rate: FeeRate,
    to_script: &[u8],
    change_script: &[u8],
) -> Option<(usize, u64)> {
    let scripts: [&[u8]; 2] = [to_script, change_script];
    let keep = rate.min_change();
    let mut total: u64 = 0;
    for (count, value) in (1..).zip(values) {
        total = total.saturating_add(*value);
        let paid = amount.saturating_add(rate.fee_for(estimate_vsize(count, &scripts)));
        if let Some(change) = total.checked_sub(paid).filter(|change| *change >= keep) {
            return Some((count, change));
        }
    }
    None
}

/// How many of the largest `values` an exact payment without change
/// spends: the fewest that cover the amount and the fee, the rest of them
/// given to the fee.
fn cover_without_change(
    values: &[u64],
    amount: u64,
    rate: FeeRate,
    to_script: &[u8],
) -> Result<usize, TxError> {
    let scripts: [&[u8]; 1] = [to_script];
    let mut total: u64 = 0;
    let mut needed = amount;
    for (count, value) in (1..).zip(values) {
        total = total.saturating_add(*value);
        needed = amount.saturating_add(rate.fee_for(estimate_vsize(count, &scripts)));
        if total >= needed {
            return Ok(count);
        }
    }
    Err(TxError::InsufficientFunds { needed, available: total })
}

/// Refuses outputs a transaction cannot hold, and returns what they hold
/// together.
fn checked_inputs(utxos: &[Utxo]) -> Result<u64, TxError> {
    if utxos.is_empty() {
        return Err(TxError::invalid("inputs", "a transaction must spend at least one output"));
    }
    let mut seen = std::collections::HashSet::with_capacity(utxos.len());
    let mut total: u64 = 0;
    for utxo in utxos {
        if !seen.insert((utxo.txid, utxo.vout)) {
            return Err(TxError::invalid("inputs", "an output is listed twice"));
        }
        total = total
            .checked_add(utxo.value)
            .filter(|total| *total <= MAX_MONEY)
            .ok_or(TxError::invalid("inputs", "hold more than there is"))?;
    }
    Ok(total)
}
