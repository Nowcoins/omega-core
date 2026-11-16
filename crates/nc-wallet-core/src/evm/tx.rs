//! Building and signing EVM transactions: legacy (EIP-155) and EIP-1559
//! (type 2), on Ethereum, BNB Chain, Polygon, Base and any other chain id.
//!
//! The encoding is pinned by the worked example in EIP-155, by Trust Wallet
//! Core's signed-transaction vectors and by real transactions of all four
//! chains (`tests/evm_encoding.rs`).
//!
//! Everything the transaction needs from the network (the nonce, the gas
//! limit, the fees) is an input: nothing here reads a chain.

use sha3::{Digest as _, Keccak256};

use super::rlp;
use crate::ecdsa::{RecoverableSignature, sign_digest};
use crate::hexutil;
use crate::key::SigningKey;
use crate::tx_error::TxError;

/// The EVM chains of version 1, by their EIP-155 chain id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvmChain {
    /// Ethereum mainnet, chain id 1.
    Ethereum,
    /// BNB Chain, chain id 56.
    BnbChain,
    /// Polygon PoS, chain id 137.
    Polygon,
    /// Base, chain id 8453.
    Base,
}

impl EvmChain {
    /// Every chain, in the order the wallet lists them.
    pub const ALL: [Self; 4] = [Self::Ethereum, Self::BnbChain, Self::Polygon, Self::Base];

    /// The EIP-155 chain id.
    #[must_use]
    pub const fn chain_id(self) -> u64 {
        match self {
            Self::Ethereum => 1,
            Self::BnbChain => 56,
            Self::Polygon => 137,
            Self::Base => 8453,
        }
    }

    /// The chain with this id, if it is one of the four.
    #[must_use]
    pub const fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(Self::Ethereum),
            56 => Some(Self::BnbChain),
            137 => Some(Self::Polygon),
            8453 => Some(Self::Base),
            _ => None,
        }
    }
}

/// What the sender pays per unit of gas, in wei, and which transaction form
/// that makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fees {
    /// A legacy transaction with EIP-155 replay protection: one gas price.
    /// BNB Chain and many L2 endpoints take these happily, and a chain with no
    /// base fee has no use for the other form.
    Legacy {
        /// Wei per gas.
        gas_price: u128,
    },
    /// An EIP-1559 (type 2) transaction.
    Eip1559 {
        /// The most wei per gas the sender will pay in all (base fee plus
        /// tip).
        max_fee_per_gas: u128,
        /// The most wei per gas the sender will tip the proposer.
        max_priority_fee_per_gas: u128,
    },
}

/// A native transfer or a contract call, with every field the network needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmTransaction {
    /// The EIP-155 chain id; it is signed over, so the transaction is valid on
    /// that chain only.
    pub chain_id: u64,
    /// The sender's nonce (the number of transactions it has sent).
    pub nonce: u64,
    /// The recipient: an account, or the contract called. This wallet never
    /// creates contracts.
    pub to: [u8; 20],
    /// The native coin sent, in wei.
    pub value: u128,
    /// The call data; empty for a plain transfer.
    pub data: Vec<u8>,
    /// The most gas the transaction may use.
    pub gas_limit: u64,
    /// What each unit of gas costs.
    pub fees: Fees,
}

/// A signed transaction, ready for `eth_sendRawTransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The bytes to broadcast: RLP for a legacy transaction, the type byte and
    /// RLP for a type 2 one.
    pub raw: Vec<u8>,
    /// The transaction hash: `keccak256(raw)`.
    pub hash: [u8; 32],
    /// The signature the transaction carries.
    pub signature: RecoverableSignature,
}

impl SignedTransaction {
    /// The raw transaction as `0x` and hex, for `eth_sendRawTransaction`.
    #[must_use]
    pub fn raw_hex(&self) -> String {
        hexutil::encode_prefixed(&self.raw)
    }

    /// The transaction hash as `0x` and hex.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        hexutil::encode_prefixed(&self.hash)
    }
}

/// Which wire form a transaction takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxType {
    /// Legacy, with EIP-155 replay protection.
    Legacy,
    /// EIP-1559, type 2.
    Eip1559,
}

impl EvmTransaction {
    /// Which form the fees make.
    #[must_use]
    pub const fn tx_type(&self) -> TxType {
        match self.fees {
            Fees::Legacy { .. } => TxType::Legacy,
            Fees::Eip1559 { .. } => TxType::Eip1559,
        }
    }

    /// The most the transaction can cost, gas and value, in wei; `None` if
    /// that does not fit 128 bits.
    #[must_use]
    pub fn max_cost(&self) -> Option<u128> {
        let price = match self.fees {
            Fees::Legacy { gas_price } => gas_price,
            Fees::Eip1559 { max_fee_per_gas, .. } => max_fee_per_gas,
        };
        u128::from(self.gas_limit).checked_mul(price)?.checked_add(self.value)
    }

    /// Refuses a transaction no node would take, before anything is signed.
    pub fn validate(&self) -> Result<(), TxError> {
        if self.chain_id == 0 {
            return Err(TxError::invalid("chain id", "must not be zero"));
        }
        if self.gas_limit == 0 {
            return Err(TxError::invalid("gas limit", "must not be zero"));
        }
        if let Fees::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas } = self.fees
            && max_priority_fee_per_gas > max_fee_per_gas
        {
            return Err(TxError::invalid("priority fee", "is above the max fee"));
        }
        Ok(())
    }

    /// The bytes that are hashed to give [`Self::signing_hash`]: for a legacy
    /// transaction the nine RLP fields of EIP-155 (the chain id and two empty
    /// values where the signature goes), for type 2 the type byte and the RLP
    /// of its nine fields.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        match self.fees {
            Fees::Eip1559 { .. } => {
                let mut out = vec![0x02];
                out.extend_from_slice(&rlp::list(&self.eip1559_fields()));
                out
            }
            Fees::Legacy { .. } => {
                let mut fields = self.legacy_fields();
                fields.push(rlp::uint(u128::from(self.chain_id)));
                fields.push(rlp::uint(0));
                fields.push(rlp::uint(0));
                rlp::list(&fields)
            }
        }
    }

    /// The digest the sender signs.
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        keccak(&self.signing_payload())
    }

    /// The transaction with `signature`: the bytes to broadcast and their
    /// hash.
    #[must_use]
    pub fn encode_signed(&self, signature: &RecoverableSignature) -> (Vec<u8>, [u8; 32]) {
        let parity = u128::from(signature.recovery_id);
        let raw = match self.fees {
            Fees::Eip1559 { .. } => {
                let mut fields = self.eip1559_fields();
                fields.push(rlp::uint(parity));
                fields.push(rlp::uint256(&signature.r));
                fields.push(rlp::uint256(&signature.s));
                let mut out = vec![0x02];
                out.extend_from_slice(&rlp::list(&fields));
                out
            }
            Fees::Legacy { .. } => {
                // EIP-155: v = parity + chain_id * 2 + 35.
                let v = parity + u128::from(self.chain_id) * 2 + 35;
                let mut fields = self.legacy_fields();
                fields.push(rlp::uint(v));
                fields.push(rlp::uint256(&signature.r));
                fields.push(rlp::uint256(&signature.s));
                rlp::list(&fields)
            }
        };
        let hash = keccak(&raw);
        (raw, hash)
    }

    /// Signs the transaction with `key` (a secp256k1 key).
    pub fn sign(&self, key: &SigningKey) -> Result<SignedTransaction, TxError> {
        self.validate()?;
        let signature = sign_digest(key, &self.signing_hash())?;
        let (raw, hash) = self.encode_signed(&signature);
        Ok(SignedTransaction { raw, hash, signature })
    }

    fn eip1559_fields(&self) -> Vec<Vec<u8>> {
        let (max_fee, priority) = match self.fees {
            Fees::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas } => {
                (max_fee_per_gas, max_priority_fee_per_gas)
            }
            Fees::Legacy { gas_price } => (gas_price, gas_price),
        };
        vec![
            rlp::uint(u128::from(self.chain_id)),
            rlp::uint(u128::from(self.nonce)),
            rlp::uint(priority),
            rlp::uint(max_fee),
            rlp::uint(u128::from(self.gas_limit)),
            rlp::bytes(&self.to),
            rlp::uint(self.value),
            rlp::bytes(&self.data),
            // An empty access list.
            rlp::list(&[]),
        ]
    }

    fn legacy_fields(&self) -> Vec<Vec<u8>> {
        let gas_price = match self.fees {
            Fees::Legacy { gas_price } => gas_price,
            Fees::Eip1559 { max_fee_per_gas, .. } => max_fee_per_gas,
        };
        vec![
            rlp::uint(u128::from(self.nonce)),
            rlp::uint(gas_price),
            rlp::uint(u128::from(self.gas_limit)),
            rlp::bytes(&self.to),
            rlp::uint(self.value),
            rlp::bytes(&self.data),
        ]
    }
}

/// Keccak-256, the hash EVM chains use everywhere.
#[must_use]
pub fn keccak(input: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
