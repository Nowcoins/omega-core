//! Reading a transaction's call data for an approval screen: what the user is
//! about to authorise, in a form a screen can show. **Nothing here executes
//! anything**; it only reads bytes, and anything it does not recognise
//! exactly is [`Call::UnknownContractCall`].

use super::abi::{self, TokenCall};
use super::u256::U256;

/// What a transaction does, as far as the wallet can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// A plain transfer of the native coin: no call data.
    NativeTransfer {
        /// The recipient.
        to: [u8; 20],
        /// The amount, in wei.
        value: u128,
    },
    /// An ERC-20 `transfer`.
    Erc20Transfer {
        /// The token contract.
        token: [u8; 20],
        /// The recipient.
        to: [u8; 20],
        /// The amount, in the token's base units.
        amount: U256,
    },
    /// An ERC-20 `approve`: `spender` may take up to `amount` of the sender's
    /// tokens, with no further say from the sender.
    Erc20Approve {
        /// The token contract.
        token: [u8; 20],
        /// Who may spend.
        spender: [u8; 20],
        /// How much, in base units.
        amount: U256,
        /// True when `amount` is a maximum nobody means as a number
        /// ([`U256::is_unlimited`]): "everything, always". Show it as such.
        unlimited: bool,
    },
    /// An ERC-20 `transferFrom`: tokens moved from `from` by whoever is
    /// allowed to.
    Erc20TransferFrom {
        /// The token contract.
        token: [u8; 20],
        /// The account debited.
        from: [u8; 20],
        /// The recipient.
        to: [u8; 20],
        /// The amount, in base units.
        amount: U256,
    },
    /// `setApprovalForAll`: an operator's right over every token of the
    /// sender in an NFT collection (ERC-721 or ERC-1155).
    SetApprovalForAll {
        /// The collection's contract.
        contract: [u8; 20],
        /// Who is granted or denied the right.
        operator: [u8; 20],
        /// Granted (true) or revoked (false).
        approved: bool,
    },
    /// Anything else: a call whose effect the wallet cannot state. Show the
    /// contract, the selector and the amount of native coin sent along, and
    /// warn.
    UnknownContractCall {
        /// The contract called.
        to: [u8; 20],
        /// The native coin sent with the call, in wei.
        value: u128,
        /// The first four bytes of the call data (`None` if there are fewer).
        selector: Option<[u8; 4]>,
        /// The length of the call data, selector included.
        data_len: usize,
    },
}

/// Classifies a call to `to` that sends `value` wei with `data`.
///
/// The token calls are recognised only in their one canonical form, and only
/// when no native coin travels with them; any other shape is an unknown call,
/// which a screen shows with a warning.
#[must_use]
pub fn classify_call(to: &[u8; 20], value: u128, data: &[u8]) -> Call {
    if data.is_empty() {
        return Call::NativeTransfer { to: *to, value };
    }
    if value == 0
        && let Some(call) = abi::decode_token_call(data)
    {
        return match call {
            TokenCall::Transfer { to: recipient, amount } => {
                Call::Erc20Transfer { token: *to, to: recipient, amount }
            }
            TokenCall::Approve { spender, amount } => {
                Call::Erc20Approve { token: *to, spender, unlimited: amount.is_unlimited(), amount }
            }
            TokenCall::TransferFrom { from, to: recipient, amount } => {
                Call::Erc20TransferFrom { token: *to, from, to: recipient, amount }
            }
            TokenCall::SetApprovalForAll { operator, approved } => {
                Call::SetApprovalForAll { contract: *to, operator, approved }
            }
        };
    }
    Call::UnknownContractCall {
        to: *to,
        value,
        selector: data.first_chunk::<4>().copied(),
        data_len: data.len(),
    }
}

impl super::tx::EvmTransaction {
    /// What this transaction does, for the approval screen.
    #[must_use]
    pub fn describe(&self) -> Call {
        classify_call(&self.to, self.value, &self.data)
    }
}
