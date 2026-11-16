//! The plain data the session hands out. Public data only: addresses, counts,
//! the quiz's choices. Nothing here is a key.

/// How many words a new recovery phrase has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseLength {
    /// 12 words (128 bits).
    Twelve,
    /// 24 words (256 bits).
    TwentyFour,
}

/// What `check_phrase` found in the text a person typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseProblem {
    /// Nothing typed yet.
    Empty,
    /// A valid recovery phrase (12, 15, 18, 21 or 24 words).
    Valid,
    /// The first word that is not in the BIP-39 English list.
    UnknownWord,
    /// Every word is in the list but there are not 12, 15, 18, 21 or 24.
    WrongWordCount,
    /// The right number of words, all in the list, but the checksum fails:
    /// a word is wrong, missing or out of order.
    BadChecksum,
}

impl PhraseProblem {
    /// A stable name, for apps that cannot share the enum.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Valid => "valid",
            Self::UnknownWord => "unknownWord",
            Self::WrongWordCount => "wrongWordCount",
            Self::BadChecksum => "badChecksum",
        }
    }
}

/// The result of reading typed text as a recovery phrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhraseCheck {
    /// What was found.
    pub problem: PhraseProblem,
    /// How many words were typed.
    pub word_count: u32,
    /// For `UnknownWord`: where the word stands, counting from 1. Otherwise 0.
    pub position: u32,
    /// For `UnknownWord`: up to three words from the list that it starts like
    /// or differs from by a letter. Otherwise empty.
    pub suggestions: Vec<String>,
}

/// One question of the backup check: which word stands at `position`?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupQuestion {
    /// The word's place in the phrase, from 1.
    pub position: u32,
    /// Six words, one of them the answer, in random order.
    pub choices: Vec<String>,
}

/// The nine networks the wallet shows. Ethereum, BNB Chain, Polygon and Base
/// share one key and one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkId {
    /// Ethereum.
    Ethereum,
    /// BNB Chain.
    BnbChain,
    /// Polygon.
    Polygon,
    /// Base.
    Base,
    /// TRON.
    Tron,
    /// Bitcoin (native segwit).
    Bitcoin,
    /// Solana.
    Solana,
    /// Stellar.
    Stellar,
    /// Bittensor (SS58 prefix 42).
    Bittensor,
}

impl NetworkId {
    /// The network with this wallet-API id, if there is one.
    pub fn from_api_id(id: &str) -> Option<Self> {
        Some(match id {
            "ethereum" => Self::Ethereum,
            "bsc" => Self::BnbChain,
            "polygon" => Self::Polygon,
            "base" => Self::Base,
            "tron" => Self::Tron,
            "bitcoin" => Self::Bitcoin,
            "solana" => Self::Solana,
            "stellar" => Self::Stellar,
            "bittensor" => Self::Bittensor,
            _ => return None,
        })
    }

    /// The id the wallet API uses in its paths.
    pub const fn api_id(self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum",
            Self::BnbChain => "bsc",
            Self::Polygon => "polygon",
            Self::Base => "base",
            Self::Tron => "tron",
            Self::Bitcoin => "bitcoin",
            Self::Solana => "solana",
            Self::Stellar => "stellar",
            Self::Bittensor => "bittensor",
        }
    }
}

/// One account on one network: where to receive, and what the chain sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAccount {
    /// Which network.
    pub network: NetworkId,
    /// The address in the network's own format.
    pub address: String,
    /// The public key, hex: 33 bytes for secp256k1, 32 for ed25519 and sr25519.
    pub public_key_hex: String,
    /// The derivation path, as other wallets write it (`""` for Bittensor
    /// account 0, `//i` after).
    pub path: String,
}

/// The public facts in a vault's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultFacts {
    /// The blob format version.
    pub version: u8,
    /// Argon2id memory cost, KiB.
    pub memory_kib: u32,
    /// Argon2id passes.
    pub iterations: u32,
    /// Argon2id lanes.
    pub lanes: u32,
}
