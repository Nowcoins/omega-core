//! Solana messages and transactions, encoded and read by hand.
//!
//! Only what a wallet signs: legacy messages
//! it builds itself, and legacy or version-0 messages a site hands it, which
//! it must read before it signs. Nothing here does I/O: the recent blockhash,
//! and the lookup tables a version-0 message loads, are inputs.
//!
//! A transaction on the wire is a compact-u16 count of signatures, the
//! signatures (64 bytes each), then the message they sign. A legacy message
//! is its header (three bytes), the account keys, the recent blockhash and the
//! instructions; a version-0 message starts with the byte `0x80` and ends with
//! its address table lookups.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest as _, Sha256};

/// A Solana account key: 32 bytes, shown in base58.
pub type Pubkey = [u8; 32];

/// The system program: creates accounts and moves SOL
/// (`11111111111111111111111111111111`).
pub const SYSTEM_PROGRAM: Pubkey = [0; 32];

/// The SPL Token program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`). USDT
/// and USDC are both minted under it.
pub const TOKEN_PROGRAM: Pubkey = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// The Token-2022 program (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`). The
/// wallet builds nothing for it, but a site's transaction may use it, and the
/// instructions it shares with the Token program are read the same way.
pub const TOKEN_2022_PROGRAM: Pubkey = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
];

/// The Associated Token Account program
/// (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`).
pub const ASSOCIATED_TOKEN_PROGRAM: Pubkey = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
];

/// The Compute Budget program (`ComputeBudget111111111111111111111111111111`).
pub const COMPUTE_BUDGET_PROGRAM: Pubkey = [
    3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229, 187,
    197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0,
];

/// The Memo program, version 1 (`Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo`).
pub const MEMO_V1_PROGRAM: Pubkey = [
    5, 74, 83, 80, 248, 93, 200, 130, 214, 20, 165, 86, 114, 120, 138, 41, 109, 223, 30, 171, 171,
    208, 166, 6, 120, 136, 73, 50, 244, 238, 246, 160,
];

/// The Memo program, version 2 (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`).
pub const MEMO_PROGRAM: Pubkey = [
    5, 74, 83, 90, 153, 41, 33, 6, 77, 36, 232, 113, 96, 218, 56, 124, 124, 53, 181, 221, 188, 146,
    187, 129, 228, 31, 168, 64, 65, 5, 68, 141,
];

/// The first byte of a version-0 message: the high bit marks a versioned
/// message, the rest is its version. A legacy message starts with its header,
/// whose first byte (the signer count) never has the high bit set.
pub const VERSION_0: u8 = 0x80;

/// The most bytes a serialized transaction may have (the IPv6 minimum MTU,
/// less headers).
pub const MAX_TRANSACTION_SIZE: usize = 1232;

/// Why a message could not be built or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// A legacy message addresses at most 256 accounts.
    #[error("a legacy message addresses at most 256 accounts")]
    TooManyAccounts,
    /// An instruction's data does not fit a transaction.
    #[error("an instruction carries more data than a transaction can")]
    TooMuchData,
    /// Bytes that are not what they were read as. The reason is a fixed
    /// phrase, never the bytes.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// A message version this wallet does not read (the high bit set, and
    /// the version after it not 0).
    #[error("message version {0} is not supported")]
    UnsupportedVersion(u8),
    /// A version-0 message loads accounts through a lookup table that was
    /// not supplied.
    #[error("the lookup table {} was not supplied", crate::solana::address(.0))]
    MissingLookupTable(Pubkey),
}

/// An account an instruction reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountMeta {
    /// The account.
    pub key: Pubkey,
    /// Whether the transaction must be signed by its key.
    pub signer: bool,
    /// Whether the instruction may change it.
    pub writable: bool,
}

impl AccountMeta {
    /// An account the instruction writes.
    #[must_use]
    pub const fn writable(key: Pubkey, signer: bool) -> Self {
        Self { key, signer, writable: true }
    }

    /// An account the instruction only reads.
    #[must_use]
    pub const fn readonly(key: Pubkey, signer: bool) -> Self {
        Self { key, signer, writable: false }
    }
}

/// One call to a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// The program called.
    pub program: Pubkey,
    /// The accounts it is given, in the order it expects them.
    pub accounts: Vec<AccountMeta>,
    /// Its arguments.
    pub data: Vec<u8>,
}

// ---- instruction builders -------------------------------------------------

/// Moves SOL: the system program's `Transfer` (instruction 2, then the
/// lamports; bincode's layout of `SystemInstruction::Transfer`).
#[must_use]
pub fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
    let mut data = 2_u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program: SYSTEM_PROGRAM,
        accounts: vec![AccountMeta::writable(from, true), AccountMeta::writable(to, false)],
        data,
    }
}

/// Caps the compute a transaction may use, which is what its priority fee is
/// charged against (`ComputeBudgetInstruction::SetComputeUnitLimit`).
#[must_use]
pub fn set_compute_unit_limit(units: u32) -> Instruction {
    let mut data = vec![2];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program: COMPUTE_BUDGET_PROGRAM, accounts: Vec::new(), data }
}

/// The priority fee, in micro-lamports per compute unit
/// (`ComputeBudgetInstruction::SetComputeUnitPrice`).
#[must_use]
pub fn set_compute_unit_price(micro_lamports: u64) -> Instruction {
    let mut data = vec![3];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction { program: COMPUTE_BUDGET_PROGRAM, accounts: Vec::new(), data }
}

/// Creates `owner`'s associated token account for `mint` if it does not
/// exist, and does nothing if it does (`CreateIdempotent`, instruction 1).
/// `payer` funds the rent.
#[must_use]
pub fn create_associated_token_account_idempotent(
    payer: Pubkey,
    account: Pubkey,
    owner: Pubkey,
    mint: Pubkey,
) -> Instruction {
    Instruction {
        program: ASSOCIATED_TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::writable(payer, true),
            AccountMeta::writable(account, false),
            AccountMeta::readonly(owner, false),
            AccountMeta::readonly(mint, false),
            AccountMeta::readonly(SYSTEM_PROGRAM, false),
            AccountMeta::readonly(TOKEN_PROGRAM, false),
        ],
        data: vec![1],
    }
}

/// Moves tokens: the token program's `TransferChecked` (instruction 12, the
/// amount, the decimals), which also asserts the mint and its decimals, so an
/// amount can never be read at the wrong scale.
#[must_use]
pub fn transfer_checked(
    source: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    owner: Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = vec![12];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program: TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::writable(source, false),
            AccountMeta::readonly(mint, false),
            AccountMeta::writable(destination, false),
            AccountMeta::readonly(owner, true),
        ],
        data,
    }
}

// ---- addresses --------------------------------------------------------------

/// Reads a base58 key: exactly 32 bytes.
#[must_use]
pub fn decode(text: &str) -> Option<Pubkey> {
    let bytes = bs58::decode(text).into_vec().ok()?;
    Pubkey::try_from(bytes.as_slice()).ok()
}

/// Writes a key in base58.
#[must_use]
pub fn encode(key: &Pubkey) -> String {
    bs58::encode(key).into_string()
}

/// Whether a key is a point on the ed25519 curve, i.e. could have a private
/// key. One off it is a program-derived address, which only its program can
/// sign for.
#[must_use]
pub fn on_curve(key: &Pubkey) -> bool {
    CompressedEdwardsY(*key).decompress().is_some()
}

/// The most seeds a program-derived address takes, and the most bytes in one.
const MAX_SEEDS: usize = 16;
const MAX_SEED_LEN: usize = 32;

/// The program-derived address of `seeds` under `program`: the SHA-256 of the
/// seeds, the program and `"ProgramDerivedAddress"`, which must land *off* the
/// curve. `None` if it lands on it, or for more seeds or longer ones than the
/// runtime takes.
#[must_use]
pub fn create_program_address(seeds: &[&[u8]], program: &Pubkey) -> Option<Pubkey> {
    if seeds.len() > MAX_SEEDS || seeds.iter().any(|seed| seed.len() > MAX_SEED_LEN) {
        return None;
    }
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(program);
    hasher.update(b"ProgramDerivedAddress");
    let key: Pubkey = hasher.finalize().into();
    (!on_curve(&key)).then_some(key)
}

/// A program-derived address with its bump: the first bump, counting down
/// from 255, that gives an address off the curve.
#[must_use]
pub fn find_program_address(seeds: &[&[u8]], program: &Pubkey) -> Option<(Pubkey, u8)> {
    (0..=u8::MAX).rev().find_map(|bump| {
        let bump = [bump];
        let mut with_bump: Vec<&[u8]> = seeds.to_vec();
        with_bump.push(&bump);
        create_program_address(&with_bump, program).map(|key| (key, bump[0]))
    })
}

/// The associated token account that `owner` holds `mint` in (under the Token
/// program): where every wallet sends a token to by default. `None` only if no
/// bump gives an off-curve address, which is a 2^-256 event.
#[must_use]
pub fn associated_token_account(owner: &Pubkey, mint: &Pubkey) -> Option<Pubkey> {
    find_program_address(&[owner, &TOKEN_PROGRAM, mint], &ASSOCIATED_TOKEN_PROGRAM)
        .map(|(key, _)| key)
}

// ---- compact-u16 ------------------------------------------------------------

/// Solana's compact-u16: seven bits a byte, low bits first, high bit set while
/// more follow.
pub fn shortvec(mut len: usize, out: &mut Vec<u8>) {
    loop {
        let byte = u8::try_from(len & 0x7f).unwrap_or(0);
        len >>= 7;
        if len == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Reads a compact-u16 at `*offset`, moving past it. `None` if the bytes end
/// first, the value needs more than the format's three bytes or does not fit
/// 16 bits, or it is written longer than it needs to be.
pub(crate) fn read_shortvec(bytes: &[u8], offset: &mut usize) -> Option<usize> {
    let mut value = 0_usize;
    for (position, shift) in [0, 7, 14].into_iter().enumerate() {
        let byte = *bytes.get(*offset)?;
        *offset += 1;
        value |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            // A last byte of zero after another is the same number written
            // longer; the runtime refuses it, so this does too.
            if position > 0 && byte == 0 {
                return None;
            }
            return u16::try_from(value).is_ok().then_some(value);
        }
    }
    None
}

// ---- compiling ----------------------------------------------------------------

/// Compiles instructions into a legacy message paid for by `payer`.
///
/// Accounts are ordered deterministically: the payer first, then
/// every key in the order instructions first mention it, each instruction's
/// program before its accounts, grouped into writable signers, read-only
/// signers, writable others and read-only others.
///
/// The order of accounts within a group is not part of the protocol, and
/// libraries differ: this one (and web3.js) keeps first mention, Solana's Rust
/// SDK sorts a group by key, and `@solana/kit` sorts by the address's text. The
/// runtime accepts them all and they give the same transaction: the same
/// accounts with the same privileges, the same header, the same instructions.
///
/// # Errors
/// [`MessageError`] if the message would exceed a legacy message's limits.
pub fn compile(
    payer: &Pubkey,
    instructions: &[Instruction],
    blockhash: &[u8; 32],
) -> Result<Vec<u8>, MessageError> {
    let mut metas = vec![AccountMeta::writable(*payer, true)];
    let mut upsert = |key: Pubkey, signer: bool, writable: bool| {
        if let Some(meta) = metas.iter_mut().find(|meta| meta.key == key) {
            meta.signer |= signer;
            meta.writable |= writable;
        } else {
            metas.push(AccountMeta { key, signer, writable });
        }
    };
    for instruction in instructions {
        upsert(instruction.program, false, false);
        for account in &instruction.accounts {
            upsert(account.key, account.signer, account.writable);
        }
    }

    let group = |signer: bool, writable: bool| {
        metas.iter().filter(move |meta| meta.signer == signer && meta.writable == writable)
    };
    let keys: Vec<Pubkey> = group(true, true)
        .chain(group(true, false))
        .chain(group(false, true))
        .chain(group(false, false))
        .map(|meta| meta.key)
        .collect();
    if keys.len() > 256 {
        return Err(MessageError::TooManyAccounts);
    }
    let count = |signer: bool, writable: bool| {
        u8::try_from(group(signer, writable).count()).unwrap_or(u8::MAX)
    };
    let signers = count(true, true).saturating_add(count(true, false));
    let index = |key: &Pubkey| {
        keys.iter().position(|candidate| candidate == key).and_then(|i| u8::try_from(i).ok())
    };

    let mut out = vec![signers, count(true, false), count(false, false)];
    shortvec(keys.len(), &mut out);
    for key in &keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(blockhash);
    shortvec(instructions.len(), &mut out);
    for instruction in instructions {
        out.push(index(&instruction.program).ok_or(MessageError::TooManyAccounts)?);
        shortvec(instruction.accounts.len(), &mut out);
        for account in &instruction.accounts {
            out.push(index(&account.key).ok_or(MessageError::TooManyAccounts)?);
        }
        if instruction.data.len() > usize::from(u16::MAX) {
            return Err(MessageError::TooMuchData);
        }
        shortvec(instruction.data.len(), &mut out);
        out.extend_from_slice(&instruction.data);
    }
    Ok(out)
}

/// A transaction on the wire: the signatures, then the message they sign. The
/// first signature is the transaction's id.
#[must_use]
pub fn transaction(signatures: &[[u8; 64]], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + signatures.len() * 64 + message.len());
    shortvec(signatures.len(), &mut out);
    for signature in signatures {
        out.extend_from_slice(signature);
    }
    out.extend_from_slice(message);
    out
}

// ---- reading ------------------------------------------------------------------

/// A message's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// The original format: all account keys are in the message.
    Legacy,
    /// Version 0: accounts may also be loaded through address lookup tables.
    V0,
}

/// How many signatures a message needs and which accounts are read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The first this-many account keys must sign.
    pub required_signatures: u8,
    /// Of those, the last this-many only read.
    pub readonly_signed: u8,
    /// Of the keys that do not sign, the last this-many only read.
    pub readonly_unsigned: u8,
}

/// An instruction as a message holds it: indexes into the account keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    /// The program's index into the keys.
    pub program_index: u8,
    /// The accounts' indexes into the keys.
    pub accounts: Vec<u8>,
    /// Its arguments.
    pub data: Vec<u8>,
}

/// The accounts a version-0 message loads from one lookup table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableLookup {
    /// The table's own address.
    pub table: Pubkey,
    /// Indexes of the accounts loaded writable.
    pub writable: Vec<u8>,
    /// Indexes of the accounts loaded read-only.
    pub readonly: Vec<u8>,
}

/// An address lookup table as the chain holds it: its key and the addresses it
/// lists, by index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupTable {
    /// The table's own address.
    pub key: Pubkey,
    /// The addresses it lists.
    pub addresses: Vec<Pubkey>,
}

/// The size of a lookup table's metadata, before its addresses.
const LOOKUP_TABLE_META: usize = 56;
/// The most addresses a lookup table holds.
const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

impl LookupTable {
    /// Reads a lookup table account's data, as the address lookup table
    /// program writes it: a 4-byte type (1, an initialised table), the
    /// deactivation slot, the last extension's slot and start index, the
    /// authority as an option, two bytes of padding, then the addresses.
    ///
    /// # Errors
    /// [`MessageError::Malformed`] unless it is an active, initialised table
    /// whose addresses fill the rest of the account exactly.
    pub fn parse(key: Pubkey, data: &[u8]) -> Result<Self, MessageError> {
        let meta = data
            .get(..LOOKUP_TABLE_META)
            .ok_or(MessageError::Malformed("a lookup table shorter than its header"))?;
        if meta[..4] != 1_u32.to_le_bytes() {
            return Err(MessageError::Malformed("not an initialised lookup table"));
        }
        if meta[4..12] != u64::MAX.to_le_bytes() {
            return Err(MessageError::Malformed("a lookup table being deactivated"));
        }
        let rest = &data[LOOKUP_TABLE_META..];
        let (addresses, ragged) = rest.as_chunks::<32>();
        if !ragged.is_empty() || addresses.len() > LOOKUP_TABLE_MAX_ADDRESSES {
            return Err(MessageError::Malformed("a lookup table's addresses do not fill it"));
        }
        Ok(Self { key, addresses: addresses.to_vec() })
    }
}

/// A message read back from its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMessage {
    /// Legacy or version 0.
    pub version: Version,
    /// Its header.
    pub header: Header,
    /// The account keys written in the message. The first is the fee payer,
    /// and the first `header.required_signatures` must sign.
    pub account_keys: Vec<Pubkey>,
    /// The recent blockhash it was built on.
    pub recent_blockhash: [u8; 32],
    /// Its instructions, by index.
    pub instructions: Vec<CompiledInstruction>,
    /// The lookup tables a version-0 message loads accounts through (always
    /// empty for a legacy message).
    pub lookups: Vec<TableLookup>,
}

impl ParsedMessage {
    /// Reads a message, legacy or version 0.
    ///
    /// The whole input must be the message: a short read, bytes left over, a
    /// header that does not fit the keys or an index past them are refused,
    /// since what is read here is what a person is asked to approve.
    ///
    /// # Errors
    /// [`MessageError::Malformed`], or [`MessageError::UnsupportedVersion`]
    /// for a versioned message other than version 0.
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
        let malformed = MessageError::Malformed;
        let first = *bytes.first().ok_or(malformed("an empty message"))?;
        let (version, mut offset) = if first & 0x80 == 0 {
            (Version::Legacy, 0)
        } else if first == VERSION_0 {
            (Version::V0, 1)
        } else {
            return Err(MessageError::UnsupportedVersion(first & 0x7f));
        };
        let header_bytes = bytes.get(offset..offset + 3).ok_or(malformed("no header"))?;
        let header = Header {
            required_signatures: header_bytes[0],
            readonly_signed: header_bytes[1],
            readonly_unsigned: header_bytes[2],
        };
        offset += 3;

        let key_count = read_shortvec(bytes, &mut offset).ok_or(malformed("no key count"))?;
        let mut account_keys = Vec::with_capacity(key_count.min(256));
        for _ in 0..key_count {
            account_keys.push(
                read_array::<32>(bytes, &mut offset).ok_or(malformed("a key runs past the end"))?,
            );
        }
        let signers = usize::from(header.required_signatures);
        if signers == 0
            || signers > key_count
            || usize::from(header.readonly_signed) >= signers
            || usize::from(header.readonly_unsigned) > key_count - signers
        {
            return Err(malformed("a header that does not fit its keys"));
        }
        if (1..key_count).any(|i| account_keys[..i].contains(&account_keys[i])) {
            // The runtime refuses a message that names an account twice.
            return Err(malformed("an account key named twice"));
        }
        let recent_blockhash =
            read_array::<32>(bytes, &mut offset).ok_or(malformed("no blockhash"))?;

        let instruction_count =
            read_shortvec(bytes, &mut offset).ok_or(malformed("no instruction count"))?;
        let mut instructions = Vec::with_capacity(instruction_count.min(64));
        for _ in 0..instruction_count {
            let program_index = *bytes.get(offset).ok_or(malformed("no program index"))?;
            offset += 1;
            let accounts =
                read_vec(bytes, &mut offset, "no account count", "accounts run past the end")?;
            let data = read_vec(bytes, &mut offset, "no data length", "data runs past the end")?;
            instructions.push(CompiledInstruction { program_index, accounts, data });
        }

        let mut lookups = Vec::new();
        if version == Version::V0 {
            let count = read_shortvec(bytes, &mut offset).ok_or(malformed("no lookup count"))?;
            for _ in 0..count {
                let table = read_array::<32>(bytes, &mut offset)
                    .ok_or(malformed("a lookup table runs past the end"))?;
                let writable = read_vec(
                    bytes,
                    &mut offset,
                    "no index count",
                    "lookup indexes run past the end",
                )?;
                let readonly = read_vec(
                    bytes,
                    &mut offset,
                    "no index count",
                    "lookup indexes run past the end",
                )?;
                lookups.push(TableLookup { table, writable, readonly });
            }
        }
        if offset != bytes.len() {
            return Err(malformed("bytes follow the message"));
        }

        let loaded: usize = lookups.iter().map(|l| l.writable.len() + l.readonly.len()).sum();
        let total = key_count + loaded;
        if total > 256 {
            return Err(MessageError::TooManyAccounts);
        }
        for instruction in &instructions {
            if usize::from(instruction.program_index) >= key_count {
                // A program is always a static key: the runtime does not run
                // one loaded through a table.
                return Err(malformed("a program index past the static keys"));
            }
            if instruction.program_index == 0 {
                // The fee payer cannot be a program.
                return Err(malformed("the fee payer named as a program"));
            }
            if instruction.accounts.iter().any(|index| usize::from(*index) >= total) {
                return Err(malformed("an account index past the keys"));
            }
        }
        Ok(Self { version, header, account_keys, recent_blockhash, instructions, lookups })
    }

    /// The account that pays the fee.
    #[must_use]
    pub fn fee_payer(&self) -> &Pubkey {
        // `parse` guarantees at least one key; a message built by hand
        // without one has no payer, and `[0; 32]` is the system program.
        self.account_keys.first().unwrap_or(&SYSTEM_PROGRAM)
    }

    /// The keys that must sign, in the order their signatures go.
    #[must_use]
    pub fn signers(&self) -> &[Pubkey] {
        let count = usize::from(self.header.required_signatures).min(self.account_keys.len());
        &self.account_keys[..count]
    }

    /// The keys of the lookup tables the message loads accounts through.
    #[must_use]
    pub fn lookup_table_keys(&self) -> Vec<Pubkey> {
        self.lookups.iter().map(|lookup| lookup.table).collect()
    }

    /// Every account the message names with the privileges it gives them:
    /// the static keys, then the loaded writable ones (every table's, in
    /// order), then the loaded read-only ones.
    ///
    /// # Errors
    /// [`MessageError::MissingLookupTable`] for a table not in `tables`;
    /// [`MessageError::Malformed`] for an index past a table.
    pub fn resolve(&self, tables: &[LookupTable]) -> Result<Vec<AccountMeta>, MessageError> {
        let statics = self.account_keys.len();
        let signers = usize::from(self.header.required_signatures);
        let mut metas: Vec<AccountMeta> = self
            .account_keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let writable = if index < signers {
                    index < signers - usize::from(self.header.readonly_signed)
                } else {
                    index < statics - usize::from(self.header.readonly_unsigned)
                };
                AccountMeta { key: *key, signer: index < signers, writable }
            })
            .collect();
        let mut loaded_readonly = Vec::new();
        for lookup in &self.lookups {
            let table = tables
                .iter()
                .find(|table| table.key == lookup.table)
                .ok_or(MessageError::MissingLookupTable(lookup.table))?;
            let address = |index: &u8| {
                table
                    .addresses
                    .get(usize::from(*index))
                    .copied()
                    .ok_or(MessageError::Malformed("a lookup index past its table"))
            };
            for index in &lookup.writable {
                metas.push(AccountMeta::writable(address(index)?, false));
            }
            for index in &lookup.readonly {
                loaded_readonly.push(AccountMeta::readonly(address(index)?, false));
            }
        }
        metas.extend(loaded_readonly);
        Ok(metas)
    }

    /// The instructions with their accounts resolved.
    ///
    /// # Errors
    /// As [`ParsedMessage::resolve`].
    pub fn resolved_instructions(
        &self,
        tables: &[LookupTable],
    ) -> Result<Vec<Instruction>, MessageError> {
        let metas = self.resolve(tables)?;
        let at = |index: u8| {
            metas
                .get(usize::from(index))
                .copied()
                .ok_or(MessageError::Malformed("an account index past the keys"))
        };
        self.instructions
            .iter()
            .map(|instruction| {
                Ok(Instruction {
                    program: at(instruction.program_index)?.key,
                    accounts: instruction
                        .accounts
                        .iter()
                        .map(|index| at(*index))
                        .collect::<Result<_, _>>()?,
                    data: instruction.data.clone(),
                })
            })
            .collect()
    }
}

/// A transaction read back from its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTransaction {
    /// The signatures, one slot per required signer (all zeros where unsigned).
    pub signatures: Vec<[u8; 64]>,
    /// The message, exactly as it appears in the bytes: what is signed.
    pub message_bytes: Vec<u8>,
    /// The message, read.
    pub message: ParsedMessage,
}

impl ParsedTransaction {
    /// Reads a serialized transaction.
    ///
    /// # Errors
    /// [`MessageError`] unless the bytes are exactly a transaction whose
    /// signature slots number the message's required signatures.
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
        let mut offset = 0;
        let count = read_shortvec(bytes, &mut offset)
            .ok_or(MessageError::Malformed("no signature count"))?;
        let mut signatures = Vec::with_capacity(count.min(16));
        for _ in 0..count {
            signatures.push(
                read_array::<64>(bytes, &mut offset)
                    .ok_or(MessageError::Malformed("a signature runs past the end"))?,
            );
        }
        let message_bytes = bytes[offset..].to_vec();
        let message = ParsedMessage::parse(&message_bytes)?;
        if usize::from(message.header.required_signatures) != signatures.len() {
            return Err(MessageError::Malformed("signature slots that do not match the header"));
        }
        Ok(Self { signatures, message_bytes, message })
    }
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let array = <[u8; N]>::try_from(bytes.get(*offset..end)?).ok()?;
    *offset = end;
    Some(array)
}

fn read_vec(
    bytes: &[u8],
    offset: &mut usize,
    no_length: &'static str,
    short: &'static str,
) -> Result<Vec<u8>, MessageError> {
    let length = read_shortvec(bytes, offset).ok_or(MessageError::Malformed(no_length))?;
    let end = offset.checked_add(length).ok_or(MessageError::Malformed(short))?;
    let slice = bytes.get(*offset..end).ok_or(MessageError::Malformed(short))?;
    *offset = end;
    Ok(slice.to_vec())
}
