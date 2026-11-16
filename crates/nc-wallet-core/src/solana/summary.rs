//! What a Solana transaction does, in words a person can be asked to approve.
//!
//! A site hands the wallet a serialized transaction; before the wallet signs
//! it, it reads the instructions back and classifies each one: a SOL transfer,
//! an SPL token transfer or approval, creating a token account, a compute
//! budget setting, or anything else. Nothing is executed or simulated: this is
//! a reading of the bytes, and an instruction it does not recognise is
//! reported as [`InstructionSummary::Unknown`] with the program, the accounts
//! and the data, never skipped.
//!
//! # What the reading promises
//!
//! Two questions are answered for the whole transaction, and a screen must
//! ask both before it says anything reassuring:
//!
//! * [`TransactionSummary::fully_understood`]: every instruction was decoded.
//!   One that was not (a swap, any program the wallet does not read) makes the
//!   transaction's effect unknown, and "no coins of yours are sent" cannot be
//!   said of it.
//! * [`TransactionSummary::may_move_user_funds`]: some instruction may spend
//!   the user's coins or tokens, or hand control of them away (an approval, a
//!   change of authority or owner, closing an account, a durable nonce).
//!
//! For each instruction, known or not, an [`InstructionReview`] says whether
//! the user's own accounts (the signer, and the user's token accounts as far as
//! they can be known) are a signer or writable in it.

use super::message::{
    ASSOCIATED_TOKEN_PROGRAM, AccountMeta, COMPUTE_BUDGET_PROGRAM, Instruction, LookupTable,
    MEMO_PROGRAM, MEMO_V1_PROGRAM, MessageError, ParsedTransaction, Pubkey, SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM, TOKEN_PROGRAM, find_program_address,
};
use crate::text;

/// One instruction, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionSummary {
    /// The system program's `Transfer`: SOL from `from` to `to`.
    SystemTransfer {
        /// Pays, and signs.
        from: Pubkey,
        /// Receives.
        to: Pubkey,
        /// Lamports (1 SOL is 10^9).
        lamports: u64,
    },
    /// A token program `Transfer` or `TransferChecked` (Token or Token-2022).
    SplTransfer {
        /// The token program called.
        program: Pubkey,
        /// The token account the tokens leave.
        source: Pubkey,
        /// The token account they go to.
        destination: Pubkey,
        /// Who signs for the source account: its owner or its delegate.
        authority: Pubkey,
        /// The mint, named by `TransferChecked` only.
        mint: Option<Pubkey>,
        /// The amount, in the token's smallest unit.
        amount: u64,
        /// The decimals the instruction asserts, by `TransferChecked` only.
        decimals: Option<u8>,
    },
    /// A token program `Approve` or `ApproveChecked`: lets `delegate` spend
    /// up to `amount` from `source` until the approval is revoked.
    SplApprove {
        /// The token program called.
        program: Pubkey,
        /// The token account the delegate may spend from.
        source: Pubkey,
        /// Who may spend.
        delegate: Pubkey,
        /// The account's owner, who signs.
        owner: Pubkey,
        /// The mint, named by `ApproveChecked` only.
        mint: Option<Pubkey>,
        /// The most the delegate may spend, in the token's smallest unit.
        amount: u64,
        /// The decimals the instruction asserts, by `ApproveChecked` only.
        decimals: Option<u8>,
        /// Whether the amount is the largest one there is (`u64::MAX`): an
        /// allowance with no practical limit.
        unlimited: bool,
    },
    /// Creates (or, if `idempotent`, creates if missing) `owner`'s associated
    /// token account for `mint`. `payer` funds its rent.
    CreateAssociatedTokenAccount {
        /// Pays the rent, and signs.
        payer: Pubkey,
        /// The account created.
        account: Pubkey,
        /// The wallet that will own it.
        owner: Pubkey,
        /// The token it holds.
        mint: Pubkey,
        /// Whether it does nothing when the account already exists.
        idempotent: bool,
    },
    /// Caps the compute the transaction may use.
    SetComputeUnitLimit {
        /// Compute units.
        units: u32,
    },
    /// Sets the priority fee.
    SetComputeUnitPrice {
        /// Micro-lamports per compute unit.
        micro_lamports: u64,
    },
    /// The system program's `CreateAccount` or `CreateAccountWithSeed`: `from`
    /// pays `lamports` into a new account and sets its owner program.
    SystemCreateAccount {
        /// Pays, and signs.
        from: Pubkey,
        /// The account made.
        new_account: Pubkey,
        /// Lamports moved into it.
        lamports: u64,
        /// Bytes of data it gets.
        space: u64,
        /// The program that will own it.
        owner: Pubkey,
        /// The seed, for `CreateAccountWithSeed` (escaped for display).
        seed: Option<String>,
        /// The base key, for `CreateAccountWithSeed`.
        base: Option<Pubkey>,
    },
    /// The system program's `Assign` or `AssignWithSeed`: gives `account` to
    /// the program `owner`. Whoever owns an account can take its coins.
    SystemAssign {
        /// The account handed over.
        account: Pubkey,
        /// The program that will own it.
        owner: Pubkey,
        /// The base key, for `AssignWithSeed`.
        base: Option<Pubkey>,
    },
    /// The system program's `Allocate`: sets the size of `account`'s data.
    SystemAllocate {
        /// The account.
        account: Pubkey,
        /// Bytes of data.
        space: u64,
    },
    /// The system program's `TransferWithSeed`: SOL from a derived account.
    SystemTransferWithSeed {
        /// The account the SOL leaves.
        from: Pubkey,
        /// The base key that signs for it.
        base: Pubkey,
        /// Receives.
        to: Pubkey,
        /// Lamports.
        lamports: u64,
        /// The seed (escaped for display).
        from_seed: String,
        /// The program that owns `from`.
        from_owner: Pubkey,
    },
    /// The system program's `AdvanceNonceAccount`. As the first instruction it
    /// makes the transaction a **durable-nonce** one: it stays valid until the
    /// nonce is used, not for about a minute, so it can be broadcast days later.
    SystemAdvanceNonce {
        /// The nonce account.
        nonce_account: Pubkey,
        /// Its authority, who signs.
        authority: Pubkey,
    },
    /// The system program's `WithdrawNonceAccount`: SOL out of a nonce account.
    SystemWithdrawNonce {
        /// The nonce account.
        nonce_account: Pubkey,
        /// Receives.
        to: Pubkey,
        /// The nonce account's authority, who signs.
        authority: Pubkey,
        /// Lamports.
        lamports: u64,
    },
    /// The system program's `InitializeNonceAccount`.
    SystemInitializeNonce {
        /// The nonce account.
        nonce_account: Pubkey,
        /// The authority it is given.
        authority: Pubkey,
    },
    /// The system program's `AuthorizeNonceAccount`: a new authority.
    SystemAuthorizeNonce {
        /// The nonce account.
        nonce_account: Pubkey,
        /// The current authority, who signs.
        authority: Pubkey,
        /// The authority it is handed to.
        new_authority: Pubkey,
    },
    /// A token program `SetAuthority`: hands control of a token account or
    /// a mint to `new_authority` (or gives it up, if `None`).
    SplSetAuthority {
        /// The token program called.
        program: Pubkey,
        /// The token account or mint.
        account: Pubkey,
        /// Who signs now.
        current_authority: Pubkey,
        /// What is handed over: 0 mint tokens, 1 freeze, 2 account owner, 3 close, and for
        /// Token-2022 further kinds.
        authority_type: u8,
        /// Who gets it.
        new_authority: Option<Pubkey>,
    },
    /// A token program `CloseAccount`: the account is closed and its lamports
    /// go to `destination`.
    SplCloseAccount {
        /// The token program called.
        program: Pubkey,
        /// The token account closed.
        account: Pubkey,
        /// Receives its lamports.
        destination: Pubkey,
        /// The account's owner, who signs.
        owner: Pubkey,
    },
    /// A token program `Burn` or `BurnChecked`: destroys tokens.
    SplBurn {
        /// The token program called.
        program: Pubkey,
        /// The token account the tokens leave.
        account: Pubkey,
        /// The mint (`Burn` has it as an account too).
        mint: Pubkey,
        /// Who signs for the account.
        authority: Pubkey,
        /// The amount, in the token's smallest unit.
        amount: u64,
        /// The decimals the instruction asserts, by `BurnChecked` only.
        decimals: Option<u8>,
    },
    /// A token program `Revoke`: takes a delegate's right away.
    SplRevoke {
        /// The token program called.
        program: Pubkey,
        /// The token account.
        source: Pubkey,
        /// The account's owner, who signs.
        owner: Pubkey,
    },
    /// A Memo program instruction: text recorded with the transaction.
    Memo {
        /// The memo program called.
        program: Pubkey,
        /// The text, only if it is UTF-8 with nothing hidden in it.
        text: Option<String>,
        /// The text with hidden characters written out, if it is UTF-8.
        escaped: Option<String>,
        /// Its length in bytes.
        len: usize,
        /// Accounts that must sign it.
        signers: Vec<Pubkey>,
    },
    /// Anything else: a program the wallet does not read, or an instruction of
    /// a known program it does not recognise.
    Unknown {
        /// The program called.
        program: Pubkey,
        /// The accounts it is given, with their privileges.
        accounts: Vec<AccountMeta>,
        /// Its data.
        data: Vec<u8>,
    },
}

/// The kinds of instruction that put the user's coins or control of them at
/// risk, named so a screen can say so in its own words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Danger {
    /// Hands an account to a program (`Assign`): the new owner can take its coins.
    AssignOwner,
    /// Sets the size of a user's account's data, the other half of taking it over.
    Allocate,
    /// Hands control of a token account or mint to someone else.
    SetAuthority,
    /// Closes a token account.
    CloseAccount,
    /// A durable nonce: the transaction can be broadcast long after it is signed.
    DurableNonce,
    /// Changes who controls a nonce account.
    NonceAuthority,
    /// Lets another address spend tokens.
    Approve,
}

impl Danger {
    /// A stable code for the JSON.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AssignOwner => "assign_owner",
            Self::Allocate => "allocate",
            Self::SetAuthority => "set_authority",
            Self::CloseAccount => "close_account",
            Self::DurableNonce => "durable_nonce",
            Self::NonceAuthority => "nonce_authority",
            Self::Approve => "approve",
        }
    }
}

/// What an instruction means for the user, whether or not it was decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionReview {
    /// The program called.
    pub program: Pubkey,
    /// Its name, for the programs the wallet knows.
    pub program_name: Option<&'static str>,
    /// Why the instruction is dangerous, if it is of a dangerous kind.
    pub danger: Option<Danger>,
    /// The user's wallet account is a signer in this instruction.
    pub user_signer: bool,
    /// One of the user's accounts (the wallet, or a token account of theirs) is
    /// writable in it.
    pub user_writable: bool,
    /// Which of the user's accounts it names, in any role.
    pub user_accounts: Vec<Pubkey>,
    /// The instruction may spend the user's coins or tokens, or hand control of
    /// them away. For an instruction that was not decoded this is conservative:
    /// whenever the user's accounts are a signer or writable in it.
    pub moves_user_funds: bool,
}

/// A transaction read for an approval screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSummary {
    /// Who pays the fee.
    pub fee_payer: Pubkey,
    /// Every account that must sign, in order.
    pub required_signers: Vec<Pubkey>,
    /// The recent blockhash it was built on.
    pub recent_blockhash: [u8; 32],
    /// What each instruction does, in order.
    pub instructions: Vec<InstructionSummary>,
    /// What each instruction means for the user: the same length and order as
    /// `instructions`.
    pub reviews: Vec<InstructionReview>,
    /// The user's wallet account, if the reading was made for one.
    pub user: Option<Pubkey>,
    /// The user's token accounts that could be known: associated accounts of
    /// the mints the transaction names, and accounts the user signs for.
    pub user_token_accounts: Vec<Pubkey>,
    /// Every instruction was decoded.
    pub fully_understood: bool,
    /// Some instruction may spend the user's coins or tokens, or hand control of
    /// them away. A screen says "no coins of yours are sent" only if this is
    /// false **and** `fully_understood` is true.
    pub may_move_user_funds: bool,
    /// The first instruction advances a nonce: a durable-nonce transaction.
    pub durable_nonce: bool,
}

/// Reads a serialized transaction and classifies its instructions, without
/// knowing whose wallet it is (every `user` field is empty or false).
///
/// `tables` are the address lookup tables a version-0 message loads accounts
/// through; [`lookup_tables_needed`] names them. Legacy messages need none.
///
/// # Errors
/// [`MessageError`] for bytes that are not a transaction, a version this
/// wallet does not read, or a lookup table missing from `tables`.
pub fn summarize_transaction(
    transaction: &[u8],
    tables: &[LookupTable],
) -> Result<TransactionSummary, MessageError> {
    summarize_inner(transaction, tables, None)
}

/// As [`summarize_transaction`], for the wallet account `user`.
///
/// # Errors
/// As [`summarize_transaction`].
pub fn summarize_transaction_for(
    transaction: &[u8],
    tables: &[LookupTable],
    user: &Pubkey,
) -> Result<TransactionSummary, MessageError> {
    summarize_inner(transaction, tables, Some(*user))
}

fn summarize_inner(
    transaction: &[u8],
    tables: &[LookupTable],
    user: Option<Pubkey>,
) -> Result<TransactionSummary, MessageError> {
    let parsed = ParsedTransaction::parse(transaction)?;
    let resolved = parsed.message.resolved_instructions(tables)?;
    let instructions: Vec<InstructionSummary> = resolved.iter().map(classify).collect();
    let user_token_accounts = user.map_or_else(Vec::new, |u| token_accounts_of(&u, &instructions));
    let reviews: Vec<InstructionReview> = resolved
        .iter()
        .zip(&instructions)
        .map(|(instruction, summary)| {
            review(instruction, summary, user.as_ref(), &user_token_accounts)
        })
        .collect();
    let fully_understood =
        !instructions.iter().any(|i| matches!(i, InstructionSummary::Unknown { .. }));
    let may_move_user_funds = reviews.iter().any(|r| r.moves_user_funds || r.danger.is_some());
    let durable_nonce =
        matches!(instructions.first(), Some(InstructionSummary::SystemAdvanceNonce { .. }));
    Ok(TransactionSummary {
        fee_payer: *parsed.message.fee_payer(),
        required_signers: parsed.message.signers().to_vec(),
        recent_blockhash: parsed.message.recent_blockhash,
        instructions,
        reviews,
        user,
        user_token_accounts,
        fully_understood,
        may_move_user_funds,
        durable_nonce,
    })
}

/// The lookup tables a serialized transaction loads accounts through: empty
/// for a legacy message. Fetch these, parse them with [`LookupTable::parse`]
/// and pass them to [`summarize_transaction`].
///
/// # Errors
/// [`MessageError`] unless the bytes are a transaction.
pub fn lookup_tables_needed(transaction: &[u8]) -> Result<Vec<Pubkey>, MessageError> {
    Ok(ParsedTransaction::parse(transaction)?.message.lookup_table_keys())
}

/// The name of a program the wallet knows.
#[must_use]
pub fn program_name(program: &Pubkey) -> Option<&'static str> {
    Some(match *program {
        SYSTEM_PROGRAM => "System",
        TOKEN_PROGRAM => "Token",
        TOKEN_2022_PROGRAM => "Token-2022",
        ASSOCIATED_TOKEN_PROGRAM => "Associated Token",
        MEMO_PROGRAM | MEMO_V1_PROGRAM => "Memo",
        COMPUTE_BUDGET_PROGRAM => "Compute Budget",
        _ => return None,
    })
}

/// The token accounts of `user` that the transaction lets us know: the
/// associated account (under both token programs) of every mint it names, and
/// every token account the user signs for or owns in a token instruction.
fn token_accounts_of(user: &Pubkey, instructions: &[InstructionSummary]) -> Vec<Pubkey> {
    use InstructionSummary as I;
    let mut found: Vec<Pubkey> = Vec::new();
    let mut add = |key: Pubkey| {
        if !found.contains(&key) {
            found.push(key);
        }
    };
    let mut mints: Vec<Pubkey> = Vec::new();
    for instruction in instructions {
        match instruction {
            I::SplTransfer { source, authority, mint, .. } => {
                if authority == user {
                    add(*source);
                }
                mints.extend(*mint);
            }
            I::SplApprove { source, owner, mint, .. } => {
                if owner == user {
                    add(*source);
                }
                mints.extend(*mint);
            }
            I::SplRevoke { source, owner, .. } => {
                if owner == user {
                    add(*source);
                }
            }
            I::SplSetAuthority { account, current_authority, .. } => {
                if current_authority == user {
                    add(*account);
                }
            }
            I::SplCloseAccount { account, owner, .. } => {
                if owner == user {
                    add(*account);
                }
            }
            I::SplBurn { account, mint, authority, .. } => {
                if authority == user {
                    add(*account);
                }
                mints.push(*mint);
            }
            I::CreateAssociatedTokenAccount { account, owner, mint, .. } => {
                if owner == user {
                    add(*account);
                }
                mints.push(*mint);
            }
            _ => {}
        }
    }
    for mint in mints {
        for program in [TOKEN_PROGRAM, TOKEN_2022_PROGRAM] {
            if let Some((key, _)) =
                find_program_address(&[user, &program, &mint], &ASSOCIATED_TOKEN_PROGRAM)
            {
                add(key);
            }
        }
    }
    found
}

fn review(
    instruction: &Instruction,
    summary: &InstructionSummary,
    user: Option<&Pubkey>,
    user_tokens: &[Pubkey],
) -> InstructionReview {
    use InstructionSummary as I;
    let mine = |key: &Pubkey| user == Some(key) || user_tokens.contains(key);
    let me = |key: &Pubkey| user == Some(key);
    let user_signer = instruction.accounts.iter().any(|m| m.signer && me(&m.key));
    let user_writable = instruction.accounts.iter().any(|m| m.writable && mine(&m.key));
    let mut user_accounts: Vec<Pubkey> = Vec::new();
    for meta in &instruction.accounts {
        if mine(&meta.key) && !user_accounts.contains(&meta.key) {
            user_accounts.push(meta.key);
        }
    }
    let (danger, moves) = match summary {
        I::SystemTransfer { from, .. } | I::SystemCreateAccount { from, .. } => (None, me(from)),
        I::SystemTransferWithSeed { from, base, .. } => (None, me(from) || me(base)),
        I::SystemWithdrawNonce { authority, nonce_account, .. } => {
            (None, me(authority) || mine(nonce_account))
        }
        I::SystemAssign { account, base, .. } => {
            ((mine(account) || base.as_ref().is_some_and(me)).then_some(Danger::AssignOwner), false)
        }
        I::SystemAllocate { account, .. } => ((mine(account)).then_some(Danger::Allocate), false),
        I::SystemAdvanceNonce { .. } => (Some(Danger::DurableNonce), false),
        I::SystemAuthorizeNonce { .. } => (Some(Danger::NonceAuthority), false),
        I::SplTransfer { source, authority, .. } => (None, me(authority) || mine(source)),
        I::SplApprove { source, owner, .. } => (Some(Danger::Approve), me(owner) || mine(source)),
        I::SplSetAuthority { account, current_authority, .. } => {
            (Some(Danger::SetAuthority), me(current_authority) || mine(account))
        }
        I::SplCloseAccount { account, owner, .. } => {
            (Some(Danger::CloseAccount), me(owner) || mine(account))
        }
        I::SplBurn { account, authority, .. } => (None, me(authority) || mine(account)),
        // Nothing of the user's moves, and nothing is handed over.
        I::SplRevoke { .. }
        | I::Memo { .. }
        | I::SystemInitializeNonce { .. }
        | I::SetComputeUnitLimit { .. }
        | I::SetComputeUnitPrice { .. } => (None, false),
        I::CreateAssociatedTokenAccount { payer, .. } => (None, me(payer)),
        I::Unknown { .. } => (None, user_signer || user_writable),
    };
    InstructionReview {
        program: instruction.program,
        program_name: program_name(&instruction.program),
        danger,
        user_signer,
        user_writable,
        user_accounts,
        moves_user_funds: moves,
    }
}

/// Classifies one instruction.
#[must_use]
pub fn classify(instruction: &Instruction) -> InstructionSummary {
    known(instruction).unwrap_or_else(|| InstructionSummary::Unknown {
        program: instruction.program,
        accounts: instruction.accounts.clone(),
        data: instruction.data.clone(),
    })
}

/// Reads bincode-encoded fields in order, failing at the first one that is
/// short; `done` says nothing is left over (a trailing byte is not a match).
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn key(&mut self) -> Option<Pubkey> {
        self.take(32)?.try_into().ok()
    }
    /// A bincode `String`: a u64 length, then the bytes (a seed is at most 32).
    fn seed(&mut self) -> Option<String> {
        let len = usize::try_from(self.u64()?).ok().filter(|l| *l <= 32)?;
        Some(text::one_line(&String::from_utf8_lossy(self.take(len)?)))
    }
    const fn done(&self) -> bool {
        self.0.is_empty()
    }
}

fn system(instruction: &Instruction) -> Option<InstructionSummary> {
    use InstructionSummary as I;
    let (tag, body) = instruction.data.split_first_chunk::<4>()?;
    let mut r = Reader(body);
    let key = |index: usize| instruction.accounts.get(index).map(|meta| meta.key);
    let summary = match u32::from_le_bytes(*tag) {
        0 => {
            let (lamports, space, owner) = (r.u64()?, r.u64()?, r.key()?);
            I::SystemCreateAccount {
                from: key(0)?,
                new_account: key(1)?,
                lamports,
                space,
                owner,
                seed: None,
                base: None,
            }
        }
        1 => I::SystemAssign { account: key(0)?, owner: r.key()?, base: None },
        2 => I::SystemTransfer { from: key(0)?, to: key(1)?, lamports: r.u64()? },
        3 => {
            let base = r.key()?;
            let seed = r.seed()?;
            let (lamports, space, owner) = (r.u64()?, r.u64()?, r.key()?);
            I::SystemCreateAccount {
                from: key(0)?,
                new_account: key(1)?,
                lamports,
                space,
                owner,
                seed: Some(seed),
                base: Some(base),
            }
        }
        4 => I::SystemAdvanceNonce { nonce_account: key(0)?, authority: key(2)? },
        5 => I::SystemWithdrawNonce {
            nonce_account: key(0)?,
            to: key(1)?,
            authority: key(4)?,
            lamports: r.u64()?,
        },
        6 => I::SystemInitializeNonce { nonce_account: key(0)?, authority: r.key()? },
        7 => I::SystemAuthorizeNonce {
            nonce_account: key(0)?,
            authority: key(1)?,
            new_authority: r.key()?,
        },
        8 => I::SystemAllocate { account: key(0)?, space: r.u64()? },
        10 => {
            let base = r.key()?;
            let _seed = r.seed()?;
            I::SystemAssign { account: key(0)?, owner: r.key()?, base: Some(base) }
        }
        11 => {
            let lamports = r.u64()?;
            let from_seed = r.seed()?;
            I::SystemTransferWithSeed {
                from: key(0)?,
                base: key(1)?,
                to: key(2)?,
                lamports,
                from_seed,
                from_owner: r.key()?,
            }
        }
        _ => return None,
    };
    r.done().then_some(summary)
}

fn known(instruction: &Instruction) -> Option<InstructionSummary> {
    let data = instruction.data.as_slice();
    let key = |index: usize| instruction.accounts.get(index).map(|meta| meta.key);
    let program = instruction.program;

    if program == SYSTEM_PROGRAM {
        return system(instruction);
    }

    if program == MEMO_PROGRAM || program == MEMO_V1_PROGRAM {
        let found = text::inspect(data);
        return Some(InstructionSummary::Memo {
            program,
            text: found.text,
            escaped: found.escaped,
            len: data.len(),
            signers: instruction
                .accounts
                .iter()
                .filter(|meta| meta.signer)
                .map(|meta| meta.key)
                .collect(),
        });
    }

    if program == TOKEN_PROGRAM || program == TOKEN_2022_PROGRAM {
        let (&tag, rest) = data.split_first()?;
        return match (tag, rest.len()) {
            // Transfer { amount }: source, destination, authority.
            (3, 8) => Some(InstructionSummary::SplTransfer {
                program,
                source: key(0)?,
                destination: key(1)?,
                authority: key(2)?,
                mint: None,
                amount: amount_of(rest)?,
                decimals: None,
            }),
            // TransferChecked { amount, decimals }: source, mint, destination, authority.
            (12, 9) => Some(InstructionSummary::SplTransfer {
                program,
                source: key(0)?,
                destination: key(2)?,
                authority: key(3)?,
                mint: Some(key(1)?),
                amount: amount_of(rest)?,
                decimals: rest.get(8).copied(),
            }),
            // Approve { amount }: source, delegate, owner.
            (4, 8) => {
                let amount = amount_of(rest)?;
                Some(InstructionSummary::SplApprove {
                    program,
                    source: key(0)?,
                    delegate: key(1)?,
                    owner: key(2)?,
                    mint: None,
                    amount,
                    decimals: None,
                    unlimited: is_unlimited(amount),
                })
            }
            // ApproveChecked { amount, decimals }: source, mint, delegate, owner.
            (13, 9) => {
                let amount = amount_of(rest)?;
                Some(InstructionSummary::SplApprove {
                    program,
                    source: key(0)?,
                    delegate: key(2)?,
                    owner: key(3)?,
                    mint: Some(key(1)?),
                    amount,
                    decimals: rest.get(8).copied(),
                    unlimited: is_unlimited(amount),
                })
            }
            // Revoke: source, owner.
            (5, 0) => {
                Some(InstructionSummary::SplRevoke { program, source: key(0)?, owner: key(1)? })
            }
            // SetAuthority { authority_type, new_authority: COption<Pubkey> }:
            // the account, the current authority.
            (6, 2 | 34) => {
                let authority_type = rest[0];
                let new_authority = match (rest[1], rest.len()) {
                    (0, 2) => None,
                    (1, 34) => Some(<Pubkey>::try_from(&rest[2..]).ok()?),
                    _ => return None,
                };
                Some(InstructionSummary::SplSetAuthority {
                    program,
                    account: key(0)?,
                    current_authority: key(1)?,
                    authority_type,
                    new_authority,
                })
            }
            // Burn { amount }: account, mint, authority.
            (8, 8) => Some(InstructionSummary::SplBurn {
                program,
                account: key(0)?,
                mint: key(1)?,
                authority: key(2)?,
                amount: amount_of(rest)?,
                decimals: None,
            }),
            // BurnChecked { amount, decimals }: account, mint, authority.
            (15, 9) => Some(InstructionSummary::SplBurn {
                program,
                account: key(0)?,
                mint: key(1)?,
                authority: key(2)?,
                amount: amount_of(rest)?,
                decimals: rest.get(8).copied(),
            }),
            // CloseAccount: account, destination, owner.
            (9, 0) => Some(InstructionSummary::SplCloseAccount {
                program,
                account: key(0)?,
                destination: key(1)?,
                owner: key(2)?,
            }),
            _ => None,
        };
    }

    if program == ASSOCIATED_TOKEN_PROGRAM {
        // `Create` (no data, or 0) and `CreateIdempotent` (1): payer, account,
        // owner, mint, system program, token program.
        let idempotent = match data {
            [] | [0] => false,
            [1] => true,
            _ => return None,
        };
        return Some(InstructionSummary::CreateAssociatedTokenAccount {
            payer: key(0)?,
            account: key(1)?,
            owner: key(2)?,
            mint: key(3)?,
            idempotent,
        });
    }

    if program == COMPUTE_BUDGET_PROGRAM {
        let (&tag, rest) = data.split_first()?;
        return match (tag, rest.len()) {
            (2, 4) => Some(InstructionSummary::SetComputeUnitLimit {
                units: u32::from_le_bytes(rest.try_into().ok()?),
            }),
            (3, 8) => {
                Some(InstructionSummary::SetComputeUnitPrice { micro_lamports: amount_of(rest)? })
            }
            _ => None,
        };
    }
    None
}

/// The little-endian `u64` at the start of `bytes`.
fn amount_of(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
}

/// Whether a token allowance is, for any purpose, unlimited: the most there is
/// (`u64::MAX`), or more than half of the 64-bit range, which no token's
/// supply approaches.
const fn is_unlimited(amount: u64) -> bool {
    amount >= 1 << 63
}
