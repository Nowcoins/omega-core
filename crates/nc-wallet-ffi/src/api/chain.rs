//! Reading the networks from the phone: balances, the inputs a send needs, fee
//! estimates, prices and broadcast, by calling each network's **public
//! endpoints directly**. There is no Nowcoin server in between.
//!
//! One door, [`chain_call`]: an operation name and a JSON request go in, JSON
//! comes out, in the shapes the app's data layer reads (see `nc-wallet-chain`'s
//! `client` module for the operations). A failure is a [`ChainFailure`] whose
//! `json` is `{ code, message, retryable, details? }`.
//!
//! Nothing here touches a key or the unlocked wallet: the chain client has no
//! secrets, and what it asks the endpoints is a public address.

// The bridge hands each argument over by value; there is no borrowing across it.
#![allow(clippy::needless_pass_by_value)]

use std::sync::{Arc, OnceLock};

use flutter_rust_bridge::frb;
use nc_wallet_chain::ChainClient;
use nc_wallet_chain::native::ReqwestPlatform;

/// Why a chain operation failed: the error as the data layer reads it,
/// `{ "code", "message", "retryable", "details"? }` as JSON text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFailure {
    /// The error's JSON.
    pub json: String,
}

static CLIENT: OnceLock<ChainClient> = OnceLock::new();

/// The process-wide client: one pool of endpoints, one pace, one set of
/// health records, so that every screen shares what the endpoints allow.
pub(crate) fn client() -> &'static ChainClient {
    CLIENT.get_or_init(|| ChainClient::new(Arc::new(ReqwestPlatform::new())))
}

/// Runs one chain operation (`networks`, `balances`, `inputs`, `estimate`,
/// `broadcast`, `status`, `prices`, `health`) on a JSON request.
pub async fn chain_call(op: String, request: String) -> Result<String, ChainFailure> {
    client().call(&op, &request).await.map_err(|json| ChainFailure { json })
}

/// What is worth keeping between launches (the price feeds already checked, the
/// prices a day ago, the Bittensor runtimes already read), as JSON text to store.
/// Nothing in it is about a person or an address.
#[frb(sync)]
pub fn chain_export_state() -> String {
    client().export_state()
}

/// Takes back what [`chain_export_state`] wrote. Anything else is ignored.
#[frb(sync)]
pub fn chain_import_state(state: String) {
    client().import_state(&state);
}

/// Forgets what the client holds of the wallet's reading: the balances and prices it
/// answers from memory. The wallet was removed, or another one opened.
#[frb(sync)]
pub fn chain_forget() {
    client().forget_everything();
}

/// What this phone sent lately (nonces and hashes), as JSON text for the app to keep sealed for a few
/// minutes: a nonce must not be put on one a send a moment ago already holds, and the app may have
/// restarted since. It names the wallet's addresses; remove it with the wallet.
#[frb(sync)]
pub fn chain_export_sent() -> String {
    client().export_sent()
}

/// Takes back what [`chain_export_sent`] wrote. Anything else, or anything stale, is ignored.
#[frb(sync)]
pub fn chain_import_sent(state: String) {
    client().import_sent(&state);
}
