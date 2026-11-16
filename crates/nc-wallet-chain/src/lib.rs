//! Nowcoin Omega's chain access: the apps read balances, the inputs a send
//! needs, fee estimates, prices and history, and broadcast transactions, by
//! calling **public blockchain endpoints directly from the device**. There is
//! no Nowcoin server in between, and nothing about a person reaches one.
//!
//! One implementation serves both apps: the Android app reaches it through
//! `nc-wallet-ffi` (with [`native::ReqwestPlatform`]) and the Chrome extension
//! through `nc-wallet-wasm` (with the browser's `fetch`). The crate has no
//! secrets and holds no keys: it reads, and hands the signing engine the
//! numbers a transaction is built from.
//!
//! # Hard rules
//!
//! * No API key of any kind.
//! * No indexer or explorer API (no Blockscout, Etherscan, Taostats, Covalent,
//!   Moralis, Alchemy, Infura or the like) and no price API: prices come from
//!   Chainlink feeds on chain.
//! * A bot challenge (Cloudflare and the like) is never gone round.
//! * Nothing about a person is sent anywhere but to the public endpoints of the
//!   network they use: their public address, as that network's own protocol
//!   needs it.
//!
//! # Shape
//!
//! [`ChainClient::call`] takes an operation and a JSON request and answers JSON,
//! in the shapes the apps already read (the former wallet API's): `networks`,
//! `balances`, `inputs`, `estimate`, `broadcast`, `status` and `prices`, and
//! errors as `{ code, message, retryable, details? }`.
//!
//! | Module | What it is |
//! |---|---|
//! | [`platform`] | the device: HTTPS, a clock, sleeping |
//! | [`endpoints`] | the bundled list of public endpoints per network |
//! | [`pool`] | pacing, rotation, health |
//! | [`net`] | asking endpoints: failover, second opinions, JSON-RPC and REST |
//! | [`quorum`] | no single endpoint trusted for a nonce or a fee |
//! | [`evm`], [`tron`], [`bitcoin`], [`solana`], [`stellar`], [`bittensor`] | the six families |
//! | [`prices`] | Chainlink feeds on chain |
//! | [`networks`] | the nine networks, their tokens and explorer links |

// Tests unwrap what they have just built; the code they test never does.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

pub mod abi;
pub mod address;
pub mod bitcoin;
pub mod bittensor;
pub mod client;
pub mod common;
pub mod dapp;
pub mod endpoints;
pub mod error;
pub mod evm;
pub mod freshness;
pub mod history;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
pub mod net;
pub mod networks;
pub mod platform;
pub mod pool;
pub mod prices;
pub mod quorum;
pub mod sent;
pub mod solana;
pub mod stellar;
pub mod tron;
pub mod txid;
pub mod util;

pub use client::ChainClient;
pub use error::{ChainError, ChainResult};
pub use networks::Network;
pub use platform::{HttpError, HttpRequest, HttpResponse, Method, Platform};

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod safety_tests;
