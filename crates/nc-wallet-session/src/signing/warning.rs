//! The warning codes a summary can carry (`warnings` in [`super::Decoded::summary`]).
//!
//! A summary says what a request does; its warnings say what the person should look at twice. Each is a short
//! code, and each app has plain words for it: the extension in `src/ui/approval/warnings.ts`, the Android app in
//! `lib/data/send_form.dart` (the review of the wallet's own transfer) and `lib/walletconnect/wc_describe.dart`
//! (a site's request). A code the engine raises and an app has no words for is shown as "the wallet reports a
//! warning it cannot put into words", which tells the person nothing.
//!
//! So the codes are listed once, here, and nothing else in the engine can make one:
//!
//! * a [`Code`] can only be made in this file, from the list below, so a warning is raised by naming a constant
//!   (`warning::UNLIMITED_APPROVAL`) and never by writing a string;
//! * `crates/nc-wallet-session/warning-codes.json` is the same list for the apps, with where each code is shown
//!   (`send`: the review of the wallet's own transfer; `signing`: the approval of a site's request). A test here
//!   keeps the file equal to this list, and a parity test in each app fails when it has no words for a code on a
//!   screen that can show it;
//! * a test reads the engine's source and fails on a code written as a string, on a listed code nothing raises,
//!   and on a code listed for a screen that cannot show it; and in the tests every decoded summary is checked
//!   against the list as it is made (`assert_listed`).
//!
//! To add a warning: add a line to the list, use the constant where the warning is raised, add the code to
//! `warning-codes.json`, and give it words in both apps in six languages.

use serde_json::Value;

/// Where an app shows a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Shown {
    /// In the review of the wallet's own transfer (`kind: "send"`).
    Send,
    /// In the approval of a site's request (every other `kind`).
    Signing,
    /// In both: the code is raised for any kind of request.
    Both,
}

/// A warning code. It cannot be made outside this file: the codes are the constants below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Code(&'static str);

impl Code {
    /// The code as the summary and the apps write it.
    pub(crate) const fn as_str(self) -> &'static str {
        self.0
    }
}

impl From<Code> for Value {
    fn from(code: Code) -> Self {
        Self::from(code.0)
    }
}

/// One line of the list: the constant's name (for the source check), its code and where it is shown.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Listed {
    pub(crate) name: &'static str,
    pub(crate) code: Code,
    pub(crate) shown: Shown,
}

macro_rules! codes {
    ($($(#[$doc:meta])* $name:ident = $code:literal, $shown:ident;)+) => {
        $($(#[$doc])* pub(crate) const $name: Code = Code($code);)+

        /// Every code the engine can raise. A constant is declared together with its entry, so there is no
        /// code that is not on this list.
        #[cfg_attr(not(test), allow(dead_code))]
        pub(crate) const ALL: &[Listed] = &[
            $(Listed { name: stringify!($name), code: $name, shown: Shown::$shown }),+
        ];
    };
}

codes! {
    // ---- a message (`personal_sign`, `signMessage`, TRON's `signMessageV2`) ----
    /// The message is not text the wallet can read.
    UNREADABLE_MESSAGE = "unreadable_message", Signing;
    /// The text, or a TRON memo, has hidden or control characters in it.
    HIDDEN_CHARACTERS = "hidden_characters", Signing;
    /// It looks like a sign-in message but is not written correctly.
    SIWE_MALFORMED = "siwe_malformed", Signing;
    /// A sign-in message names another site than the one asking.
    SIWE_DOMAIN_MISMATCH = "siwe_domain_mismatch", Signing;
    /// A sign-in message names another account than the one that would sign.
    SIWE_ADDRESS_MISMATCH = "siwe_address_mismatch", Signing;
    /// A message of 32 bytes, the size of a hash, which can approve something nobody can read.
    HASH_LIKE_MESSAGE = "hash_like_message", Signing;

    // ---- EVM and TRON calls, typed data ----
    /// An approval of more than anyone spends: the spender can take it all.
    UNLIMITED_APPROVAL = "unlimited_approval", Signing;
    /// `setApprovalForAll` granted.
    APPROVAL_FOR_ALL = "approval_for_all", Signing;
    /// A contract call the wallet cannot read.
    UNKNOWN_CONTRACT_CALL = "unknown_contract_call", Signing;
    /// A permit: spending rights given by a signature, with no transaction.
    PERMIT_SIGNATURE = "permit_signature", Signing;
    /// Typed data the wallet does not recognise.
    UNRECOGNISED_TYPED_DATA = "unrecognised_typed_data", Signing;
    /// Typed data written for another chain than the one asked.
    CHAIN_MISMATCH = "chain_mismatch", Signing;

    // ---- Solana ----
    /// The transaction calls programs the wallet does not know.
    UNKNOWN_PROGRAMS = "unknown_programs", Signing;
    /// An instruction that changes who controls an account or a token, or closes one.
    DANGEROUS_INSTRUCTION = "dangerous_instruction", Signing;
    /// A durable nonce: the transaction does not expire.
    DURABLE_NONCE = "durable_nonce", Signing;
    /// A token approval: another address may spend the tokens.
    DELEGATE_APPROVAL = "delegate_approval", Signing;

    // ---- TRON ----
    /// The most a call may burn for energy is less than the energy costs now.
    FEE_LIMIT_LOW = "fee_limit_low", Signing;

    // ---- fees and the recipient of the wallet's own transfers ----
    /// The network fee is a large part of the amount sent (Bitcoin).
    HIGH_FEE = "high_fee", Send;
    /// The SOL sent goes to an account a program owns, from which it can never be taken out.
    RECIPIENT_IS_PROGRAM_ACCOUNT = "recipient_is_program_account", Send;
    /// The network fee is above the wallet's own "high" line: added to any request whose fee is.
    FEE_HIGH = "fee_high", Both;
}

/// Whether `code` is on the list.
#[cfg(test)]
pub(crate) fn is_listed(code: &str) -> bool {
    ALL.iter().any(|listed| listed.code.as_str() == code)
}

/// Whether the summary (as JSON) carries `code`.
pub(crate) fn has(summary: &Value, code: Code) -> bool {
    summary
        .get("warnings")
        .and_then(Value::as_array)
        .is_some_and(|list| list.iter().any(|w| w == code.as_str()))
}

/// In a test build, every summary the engine makes is held to the list as it is made: a code that is not on it
/// fails whichever test decoded the request.
#[cfg(test)]
pub(crate) fn assert_listed(summary: &Value) {
    let list = summary.get("warnings").and_then(Value::as_array);
    assert!(list.is_some(), "a summary has a list of warnings");
    for w in list.into_iter().flatten() {
        assert!(
            w.as_str().is_some_and(is_listed),
            "the engine raised the warning {w}, which is not on the list in signing/warning.rs"
        );
    }
}
