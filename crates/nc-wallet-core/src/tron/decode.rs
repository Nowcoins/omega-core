//! Reading a TRON transaction for an approval screen: a TRX transfer, or a
//! call to a contract classified like an EVM call (TRC-20 `transfer`,
//! `approve` and `transferFrom`, `setApprovalForAll`). It only reads bytes;
//! anything not recognised exactly is [`Call::UnknownContractCall`].

use super::tx::{AddressBytes, Contract, TronTransaction, address_from_hash};
use crate::evm::abi::{self, TokenCall};
use crate::evm::u256::U256;

/// What a TRON transaction does, as far as the wallet can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// A transfer of TRX.
    TrxTransfer {
        /// The recipient.
        to: AddressBytes,
        /// The amount, in sun.
        amount: u64,
    },
    /// A TRC-20 `transfer`.
    Trc20Transfer {
        /// The token contract.
        token: AddressBytes,
        /// The recipient.
        to: AddressBytes,
        /// The amount, in the token's base units.
        amount: U256,
    },
    /// A TRC-20 `approve`: `spender` may take up to `amount`.
    Trc20Approve {
        /// The token contract.
        token: AddressBytes,
        /// Who may spend.
        spender: AddressBytes,
        /// How much, in base units.
        amount: U256,
        /// True when `amount` is at least 2^255: "everything, always".
        unlimited: bool,
    },
    /// A TRC-20 `transferFrom`.
    Trc20TransferFrom {
        /// The token contract.
        token: AddressBytes,
        /// The account debited.
        from: AddressBytes,
        /// The recipient.
        to: AddressBytes,
        /// The amount, in base units.
        amount: U256,
    },
    /// `setApprovalForAll` on a TRC-721 or TRC-1155 collection.
    SetApprovalForAll {
        /// The collection's contract.
        contract: AddressBytes,
        /// Who is granted or denied the right.
        operator: AddressBytes,
        /// Granted (true) or revoked (false).
        approved: bool,
    },
    /// Anything else.
    UnknownContractCall {
        /// The contract called.
        contract: AddressBytes,
        /// TRX sent with the call, in sun.
        call_value: u64,
        /// The first four bytes of the call data.
        selector: Option<[u8; 4]>,
        /// The length of the call data.
        data_len: usize,
    },
}

/// Classifies a call to `contract` that sends `call_value` sun with `data`.
/// Token calls are recognised only in their canonical form and with no TRX
/// sent along.
#[must_use]
pub fn classify_contract_call(contract: &AddressBytes, call_value: u64, data: &[u8]) -> Call {
    if call_value == 0
        && let Some(call) = abi::decode_token_call_tron(data)
    {
        return match call {
            TokenCall::Transfer { to, amount } => {
                Call::Trc20Transfer { token: *contract, to: address_from_hash(&to), amount }
            }
            TokenCall::Approve { spender, amount } => Call::Trc20Approve {
                token: *contract,
                spender: address_from_hash(&spender),
                unlimited: amount.is_unlimited(),
                amount,
            },
            TokenCall::TransferFrom { from, to, amount } => Call::Trc20TransferFrom {
                token: *contract,
                from: address_from_hash(&from),
                to: address_from_hash(&to),
                amount,
            },
            TokenCall::SetApprovalForAll { operator, approved } => Call::SetApprovalForAll {
                contract: *contract,
                operator: address_from_hash(&operator),
                approved,
            },
        };
    }
    Call::UnknownContractCall {
        contract: *contract,
        call_value,
        selector: data.first_chunk::<4>().copied(),
        data_len: data.len(),
    }
}

impl TronTransaction {
    /// What this transaction does, for the approval screen.
    #[must_use]
    pub fn describe(&self) -> Call {
        match &self.contract {
            Contract::Transfer { to, amount, .. } => Call::TrxTransfer { to: *to, amount: *amount },
            Contract::TriggerSmartContract { contract, call_value, data, .. } => {
                classify_contract_call(contract, *call_value, data)
            }
        }
    }
}
