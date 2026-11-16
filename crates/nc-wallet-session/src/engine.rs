//! The wallet being made, and the unlocked wallet.
//!
//! Both are held here, in Rust, and wiped when dropped. The engine is a plain
//! value: a caller that needs one per process (the Android bridge) keeps it in
//! a static of its own; the extension keeps one in its service worker.

use nc_wallet_core::cache::CacheMaster;
use nc_wallet_core::vault::{self, VaultKey, VaultLimits, VaultParams};
use nc_wallet_core::{Mnemonic, WordCount};
use zeroize::Zeroizing;

use crate::accounts::accounts_of;
use crate::error::SessionError;
use crate::quiz::{Quiz, make_quiz};
use crate::types::{BackupQuestion, NetworkAccount, PhraseLength};

/// A phrase and its BIP-39 passphrase. Both wipe themselves when dropped.
pub(crate) struct Secrets {
    pub(crate) mnemonic: Mnemonic,
    pub(crate) passphrase: Zeroizing<String>,
}

/// An unlocked wallet, made by [`crate::open_with_password`] or
/// [`crate::open_with_key`] and handed to [`Engine::install`]. It holds the
/// phrase, so it wipes itself when dropped, and prints nothing of it.
pub struct Unlocked(pub(crate) Secrets);

impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Unlocked(<redacted>)")
    }
}

/// Where a wallet being made came from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Made here: its backup must be checked before it is sealed.
    Created,
    /// Typed in by the user, who has it already.
    Imported,
}

pub(crate) struct Pending {
    pub(crate) secrets: Secrets,
    pub(crate) origin: Origin,
    pub(crate) quiz: Option<Quiz>,
}

/// A wallet taken out of the engine to be sealed, so that the caller can run
/// Argon2id (about a second) without holding whatever lock guards the engine.
/// Made by [`Engine::begin_seal`]; run with [`SealJob::seal`]; the result goes
/// back with [`Engine::finish_seal`]. It seals with the engine's parameters.
pub struct SealJob(Pending, VaultParams);

impl std::fmt::Debug for SealJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealJob(<redacted>)")
    }
}

/// What came of a [`SealJob`]: the wallet back, and the vault or the error.
pub struct SealDone {
    pending: Pending,
    result: Result<(Vec<u8>, VaultKey), SessionError>,
}

impl std::fmt::Debug for SealDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealDone(<redacted>)")
    }
}

impl SealJob {
    /// Seals the wallet under `password`. Takes about a second: Argon2id.
    pub fn seal(self, password: &str) -> SealDone {
        let secrets = &self.0.secrets;
        let result = vault::seal_keeping_key_with_params(
            &secrets.mnemonic,
            &secrets.passphrase,
            password,
            self.1,
        )
        .map_err(SessionError::from);
        SealDone { pending: self.0, result }
    }
}

/// The wallet being made, and the unlocked wallet.
#[derive(Default)]
pub struct Engine {
    pending: Option<Pending>,
    session: Option<Secrets>,
    /// The key the last new vault was sealed with, kept until the app takes it
    /// (to keep it behind a lock of its own) or drops it, or the wallet is
    /// locked.
    new_key: Option<VaultKey>,
    /// The key the wallet being made was just sealed with, until the app has
    /// stored the vault and commits it.
    sealed_key: Option<VaultKey>,
    /// What the sealed caches (the history) are keyed from: made from the phrase the first time
    /// one is wanted after an unlock (one PBKDF2 run), wiped on lock.
    cache_master: Option<CacheMaster>,
    /// The Argon2id parameters a new wallet is sealed with.
    vault_params: VaultParams,
    /// The most a stored vault's header may ask for when this engine opens it.
    open_limits: VaultLimits,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("pending", &self.pending.is_some())
            .field("unlocked", &self.session.is_some())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// An engine with nothing pending and the wallet locked, that seals new
    /// wallets with [`VaultParams::PHONE`] (the Android app's).
    pub const fn new() -> Self {
        Self::with_vault_params(VaultParams::PHONE)
    }

    /// [`Engine::new`] that seals new wallets with `params` (the extension's are
    /// [`VaultParams::EXTENSION`]). Opening reads the parameters from the vault,
    /// within the crate's own ceiling ([`VaultLimits::PHONE`]).
    pub const fn with_vault_params(params: VaultParams) -> Self {
        Self::with_vault_params_and_limits(params, VaultLimits::PHONE)
    }

    /// [`Engine::with_vault_params`] that opens only vaults whose header asks
    /// for no more than `limits` (the extension's are [`VaultLimits::EXTENSION`]):
    /// one that asks for more is [`SessionError::NotAVault`], before any
    /// Argon2id work. `params` should be within `limits`, or the engine seals
    /// vaults it will not open.
    pub const fn with_vault_params_and_limits(params: VaultParams, limits: VaultLimits) -> Self {
        Self {
            pending: None,
            session: None,
            new_key: None,
            sealed_key: None,
            cache_master: None,
            vault_params: params,
            open_limits: limits,
        }
    }

    /// The most a vault's header may ask for when this engine opens it: what the
    /// app passes to the `_within` vault operations ([`crate::vault_facts_within`]
    /// and the rest) for the vaults it opens without the engine.
    pub const fn open_limits(&self) -> VaultLimits {
        self.open_limits
    }

    /// Makes a phrase from the system's secure randomness and holds it until
    /// it is sealed or discarded. Replaces any wallet being made.
    pub fn start_new(&mut self, length: PhraseLength) -> Result<(), SessionError> {
        let count = match length {
            PhraseLength::Twelve => WordCount::Twelve,
            PhraseLength::TwentyFour => WordCount::TwentyFour,
        };
        let mnemonic = Mnemonic::generate(count)?;
        self.sealed_key = None;
        self.pending = Some(Pending {
            secrets: Secrets { mnemonic, passphrase: Zeroizing::new(String::new()) },
            origin: Origin::Created,
            quiz: None,
        });
        Ok(())
    }

    /// Starts an imported wallet from the typed phrase and the optional BIP-39
    /// passphrase (`""` for none). Replaces any wallet being made.
    pub fn start_import(&mut self, text: &str, passphrase: &str) -> Result<(), SessionError> {
        let mnemonic = Mnemonic::parse(text)?;
        self.sealed_key = None;
        self.pending = Some(Pending {
            secrets: Secrets { mnemonic, passphrase: Zeroizing::new(passphrase.to_owned()) },
            origin: Origin::Imported,
            quiz: None,
        });
        Ok(())
    }

    /// Forgets the wallet being made or imported, wiping its phrase.
    pub fn discard_pending(&mut self) {
        self.pending = None;
        self.sealed_key = None;
    }

    /// The vault the wallet being made was sealed into is stored: unlock it.
    /// Until this, the phrase stays pending, so a vault that could not be
    /// written can be sealed again without making a new wallet.
    pub fn commit_pending(&mut self) -> Result<(), SessionError> {
        let key = self.sealed_key.take().ok_or(SessionError::NoPendingWallet)?;
        let pending = self.pending.take().ok_or(SessionError::NoPendingWallet)?;
        self.session = Some(pending.secrets);
        self.new_key = Some(key);
        Ok(())
    }

    fn pending(&self) -> Result<&Pending, SessionError> {
        self.pending.as_ref().ok_or(SessionError::NoPendingWallet)
    }

    /// The words of the phrase being made, for the backup screen. This is the
    /// one place a new phrase leaves the engine.
    pub fn pending_words(&self) -> Result<Vec<String>, SessionError> {
        Ok(words_of(&self.pending()?.secrets.mnemonic))
    }

    /// How many words the phrase being made has (12 or 24), for laying out the
    /// backup screen while the words are hidden.
    pub fn pending_word_count(&self) -> Result<u32, SessionError> {
        Ok(to_u32(self.pending()?.secrets.mnemonic.word_count()))
    }

    /// Whether a wallet is being made or imported.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// The backup quiz, made on the first call and the same after.
    pub fn quiz(&mut self) -> Result<Vec<BackupQuestion>, SessionError> {
        let pending = self.pending.as_mut().ok_or(SessionError::NoPendingWallet)?;
        if pending.quiz.is_none() {
            pending.quiz = Some(make_quiz(&words_of(&pending.secrets.mnemonic))?);
        }
        let quiz = pending.quiz.as_ref().ok_or(SessionError::NoQuiz)?;
        Ok(quiz
            .positions
            .iter()
            .zip(&quiz.choices)
            .map(|(position, choices)| BackupQuestion {
                position: u32::try_from(*position).unwrap_or(u32::MAX),
                choices: choices.clone(),
            })
            .collect())
    }

    /// Whether `word` is the word at `position` in the phrase being made. The
    /// position must be one of the quiz's. A wrong answer replaces that question
    /// (another position, new decoys), so the app must read the questions again;
    /// the old position is then not one of the quiz's.
    pub fn check_answer(&mut self, position: u32, word: &str) -> Result<bool, SessionError> {
        let pending = self.pending.as_mut().ok_or(SessionError::NoPendingWallet)?;
        let quiz = pending.quiz.as_mut().ok_or(SessionError::NoQuiz)?;
        let position = usize::try_from(position).map_err(|_| SessionError::NoQuiz)?;
        let slot =
            quiz.positions.iter().position(|p| *p == position).ok_or(SessionError::NoQuiz)?;
        let words = words_of(&pending.secrets.mnemonic);
        let right = words.get(position - 1).is_some_and(|w| w == word);
        if right {
            quiz.answered[slot] = true;
        } else {
            // The question is drawn again (another position, new decoys): the app
            // asks `backup_questions` again after a wrong answer.
            quiz.redraw(&words, position)?;
        }
        Ok(right)
    }

    /// Takes the wallet being made out, to seal it without holding the lock.
    /// A new wallet whose backup check was not passed is refused (and stays
    /// pending).
    pub fn begin_seal(&mut self) -> Result<SealJob, SessionError> {
        let pending = self.pending.take().ok_or(SessionError::NoPendingWallet)?;
        if pending.origin == Origin::Created {
            let confirmed = pending.quiz.as_ref().is_some_and(|q| q.answered.iter().all(|a| *a));
            if !confirmed {
                self.pending = Some(pending);
                return Err(SessionError::BackupNotConfirmed);
            }
        }
        Ok(SealJob(pending, self.vault_params))
    }

    /// Puts a sealed (or failed) wallet back and returns the vault blob. On
    /// success the phrase stays pending and the key is kept for
    /// [`Engine::commit_pending`]; on failure the wallet is simply pending
    /// again.
    pub fn finish_seal(&mut self, done: SealDone) -> Result<Vec<u8>, SessionError> {
        let SealDone { pending, result } = done;
        self.pending = Some(pending);
        match result {
            Ok((blob, key)) => {
                self.sealed_key = Some(key);
                Ok(blob)
            }
            Err(error) => Err(error),
        }
    }

    /// Seals the wallet being made under `password`: [`Engine::begin_seal`],
    /// [`SealJob::seal`] and [`Engine::finish_seal`] in one call. The wallet is
    /// unlocked by [`Engine::commit_pending`]. About a second.
    pub fn seal_pending(&mut self, password: &str) -> Result<Vec<u8>, SessionError> {
        let job = self.begin_seal()?;
        let done = job.seal(password);
        self.finish_seal(done)
    }

    /// Keeps `unlocked` as the open wallet.
    pub fn install(&mut self, unlocked: Unlocked) {
        self.session = Some(unlocked.0);
        self.cache_master = None;
    }

    /// Opens `blob` with the password and keeps the wallet unlocked.
    pub fn unlock_with_password(
        &mut self,
        blob: &[u8],
        password: &Zeroizing<String>,
    ) -> Result<(), SessionError> {
        self.install(crate::open_with_password_within(blob, password, self.open_limits)?);
        Ok(())
    }

    /// Opens `blob` with the vault key and keeps the wallet unlocked. Quick:
    /// no Argon2id.
    pub fn unlock_with_key(
        &mut self,
        blob: &[u8],
        key: &Zeroizing<Vec<u8>>,
    ) -> Result<(), SessionError> {
        self.install(crate::open_with_key_within(blob, key, self.open_limits)?);
        Ok(())
    }

    /// Locks the wallet: the phrase held here is wiped, and so are the keys
    /// kept for the app. A wallet still being made is left alone
    /// ([`Engine::discard_pending`] forgets it).
    pub fn lock(&mut self) {
        self.session = None;
        self.new_key = None;
        self.sealed_key = None;
        self.cache_master = None;
    }

    /// The key the new vault was sealed with, once.
    pub fn take_new_key(&mut self) -> Result<Vec<u8>, SessionError> {
        let key = self.new_key.take().ok_or(SessionError::NoNewKey)?;
        Ok(key.expose_secret().to_vec())
    }

    /// Forgets the key [`Engine::take_new_key`] would give.
    pub fn drop_new_key(&mut self) {
        self.new_key = None;
    }

    /// Whether the wallet is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// The unlocked wallet's secrets, for the signing code in this crate.
    pub(crate) fn unlocked_secrets(&self) -> Option<&Secrets> {
        self.session.as_ref()
    }

    /// The accounts of all nine networks at account number `index`, derived
    /// from the unlocked wallet. Addresses and public keys only.
    pub fn accounts(&self, index: u32) -> Result<Vec<NetworkAccount>, SessionError> {
        let secrets = self.session.as_ref().ok_or(SessionError::NotUnlocked)?;
        accounts_of(&secrets.mnemonic, &secrets.passphrase, index)
    }

    /// The Solana account Trust Wallet shows for this phrase (`m/44'/501'/0'`), for the wallet being
    /// imported or the unlocked one. This wallet's own Solana account 0 is at Phantom's path
    /// (`m/44'/501'/0'/0'`), so a phrase that came from Trust Wallet has its Solana funds here and not
    /// there. An import reads this address's balance and history like any other address, and tells the
    /// person where their funds are. Addresses and public keys only: no key for this account is reachable,
    /// so nothing can be signed for it.
    pub fn solana_trust_wallet_account(&self) -> Result<NetworkAccount, SessionError> {
        let secrets = self
            .session
            .as_ref()
            .or_else(|| self.pending.as_ref().map(|pending| &pending.secrets))
            .ok_or(SessionError::NotUnlocked)?;
        crate::accounts::trust_wallet_solana_account(&secrets.mnemonic, &secrets.passphrase)
    }

    fn cache_master(&mut self) -> Result<&CacheMaster, SessionError> {
        if self.cache_master.is_none() {
            let secrets = self.session.as_ref().ok_or(SessionError::NotUnlocked)?;
            let seed = secrets.mnemonic.to_seed(&secrets.passphrase);
            self.cache_master = Some(CacheMaster::from_seed(&seed));
        }
        self.cache_master.as_ref().ok_or(SessionError::NotUnlocked)
    }

    /// Seals `plaintext` (the history of one account on one network) at rest, under a key only
    /// this wallet's phrase makes, bound to `label`. Needs the unlocked wallet. The label is
    /// not stored in the blob: the caller must give it again to open it.
    pub fn seal_cache(&mut self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.cache_master()?.seal(label, plaintext).ok_or(SessionError::Unavailable)
    }

    /// What [`Engine::seal_cache`] sealed for `label`, or `None` where the blob is not one of this
    /// wallet's for that label (another wallet's, another label's, or damaged): the caller then
    /// starts afresh. Needs the unlocked wallet.
    pub fn open_cache(
        &mut self,
        label: &str,
        blob: &[u8],
    ) -> Result<Option<Vec<u8>>, SessionError> {
        Ok(self.cache_master()?.open(label, blob).map(|plain| plain.to_vec()))
    }

    /// The name to store the blob for `label` under: 24 hex characters that reveal neither the
    /// address nor the network in the label. Needs the unlocked wallet.
    pub fn cache_id(&mut self, label: &str) -> Result<String, SessionError> {
        Ok(self.cache_master()?.id(label))
    }

    /// Test access: the unlocked secrets.
    #[cfg(test)]
    pub(crate) fn set_session_for_tests(&mut self, secrets: Secrets) {
        self.session = Some(secrets);
    }
}

pub(crate) fn words_of(mnemonic: &Mnemonic) -> Vec<String> {
    mnemonic.expose_phrase().split(' ').map(str::to_owned).collect()
}

pub(crate) fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}
