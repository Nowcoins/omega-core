//! Solana, through the network's JSON-RPC on public nodes: balances
//! (`getBalance`, and the owner's token accounts for each listed mint), what a
//! transaction is built from (a recent blockhash, the token accounts, a
//! priority fee read from what others recently paid), what a transfer costs and
//! whether its recipient can take it, and `sendTransaction`.

use base64::Engine as _;
use nc_wallet_core::solana::message::{
    TOKEN_2022_PROGRAM, TOKEN_PROGRAM, associated_token_account,
};
use nc_wallet_core::solana::{address as encode_key, parse_address};
use serde_json::{Value, json};

use crate::address::{self, Address};
use crate::common::{EstimateArgs, balances_body, fee_value, native_entry, token_entry};
use crate::error::{ChainError, ChainResult, REFUSED};
use crate::net::{Net, NodeError};
use crate::networks::{Network, Token};
use crate::pool::Need;
use crate::quorum::{Figure, Kind};
use nc_wallet_core::limits;

/// The compute a transaction reserves: a coin transfer, a token transfer, a
/// token transfer that also opens the recipient's token account.
const COMPUTE_SOL: u32 = 1_000;
const COMPUTE_TOKEN: u32 = 60_000;
const COMPUTE_TOKEN_NEW: u32 = 100_000;
/// The fee for each signature a transaction carries, in lamports.
const FEE_PER_SIGNATURE: u128 = 5_000;
/// The least and the most priority fee bid, in micro-lamports per compute unit,
/// and what is bid when the cluster will not say what others paid.
const MIN_PRIORITY: u64 = 1_000;
const MAX_PRIORITY: u64 = 1_000_000;
const FALLBACK_PRIORITY: u64 = 10_000;
/// The size of a token account's data.
const TOKEN_ACCOUNT_LEN: u64 = 165;
/// How many endpoints a signed transaction is sent to at once.
const BROADCAST_TO: usize = 2;

/// Solana.
#[derive(Debug, Clone, Copy)]
pub struct Solana<'a> {
    net: &'a Net,
}

/// What one operator said of some lookup tables (each one's owner and data), and which endpoint.
type TableReading = (Vec<(String, String)>, usize);

/// The reading two operators gave alike.
fn agreed(readings: &[TableReading]) -> Option<&TableReading> {
    readings.iter().find(|(a, _)| readings.iter().filter(|(b, _)| a == b).count() >= 2)
}

/// One of the owner's token accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenAccount {
    address: String,
    mint: String,
    amount: u128,
}

/// What a token's accounts hold in all, whatever the node says each holds (it never wraps).
fn sum_of(accounts: &[TokenAccount]) -> u128 {
    accounts.iter().map(|a| a.amount).fold(0, u128::saturating_add)
}

/// Whether `owner` is a token program: an account it owns is a token account (or a mint).
fn is_token_program(owner: &str) -> bool {
    [TOKEN_PROGRAM, TOKEN_2022_PROGRAM].iter().any(|program| owner == encode_key(program))
}

/// The System Program, which owns every ordinary wallet.
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// Whether `owner` is a program other than the System Program: an account it owns is that
/// program's (a mint, a token account, a program, a sysvar), not a person's wallet.
fn is_program_owner(owner: &str) -> bool {
    owner != SYSTEM_PROGRAM
}

impl<'a> Solana<'a> {
    /// Solana over `net`.
    #[must_use]
    pub const fn new(net: &'a Net) -> Self {
        Self { net }
    }

    async fn read(&self, method: &'static str, params: Value) -> ChainResult<Value> {
        match self.net.rpc(Need::ANY, method, &params).await? {
            Ok(value) => Ok(value),
            Err(_) => Err(ChainError::Unavailable),
        }
    }

    async fn lamports(&self, address: &Address) -> ChainResult<u128> {
        let answer =
            self.read("getBalance", json!([address.text, { "commitment": "confirmed" }])).await?;
        answer.get("value").and_then(Value::as_u64).map(u128::from).ok_or(ChainError::Unavailable)
    }

    /// The owner's token accounts for `mint`.
    async fn token_accounts(&self, owner: &Address, mint: &str) -> ChainResult<Vec<TokenAccount>> {
        let answer = self
            .read(
                "getTokenAccountsByOwner",
                json!([owner.text, { "mint": mint }, { "encoding": "jsonParsed", "commitment": "confirmed" }]),
            )
            .await?;
        let list = answer.get("value").and_then(Value::as_array).cloned().unwrap_or_default();
        Ok(list
            .iter()
            .filter_map(|entry| {
                let info = entry.pointer("/account/data/parsed/info")?;
                let account = TokenAccount {
                    address: entry.get("pubkey")?.as_str()?.to_owned(),
                    mint: info.get("mint")?.as_str()?.to_owned(),
                    amount: info.pointer("/tokenAmount/amount")?.as_str()?.parse().ok()?,
                };
                // As for the associated account below: only an account of this mint, held by
                // this owner, is the owner's balance of it.
                let holder = info.get("owner")?.as_str()?;
                (account.mint == mint && holder == owner.text).then_some(account)
            })
            .collect())
    }

    /// The owner's token accounts for every listed mint.
    ///
    /// `getTokenAccountsByOwner` is what finds every account an owner holds, but it is an
    /// *indexed* request: `PublicNode` asks for a personal token for it, and the Foundation's
    /// endpoint refuses any request that carries a browser's `Origin` header (so it
    /// answers the app and not the extension). Where it cannot be had, the owner's
    /// **associated** token accounts (where wallets keep tokens, and derivable) are read
    /// with `getMultipleAccounts`, which any endpoint serves. A token kept in some other
    /// account of the owner is found only by the first.
    async fn token_accounts_all(&self, owner: &Address) -> Vec<ChainResult<Vec<TokenAccount>>> {
        let tokens = Network::Solana.tokens();
        let mut found = futures::future::join_all(
            tokens.iter().map(|token| self.token_accounts(owner, token.contract)),
        )
        .await;
        let failed: Vec<usize> =
            found.iter().enumerate().filter(|(_, r)| r.is_err()).map(|(i, _)| i).collect();
        if failed.is_empty() {
            return found;
        }
        let wanted: Vec<&Token> = failed.iter().filter_map(|&i| tokens.get(i)).collect();
        if let Ok(by_ata) = self.token_accounts_by_ata(owner, &wanted).await {
            for (&slot, accounts) in failed.iter().zip(by_ata) {
                found[slot] = Ok(accounts);
            }
        }
        found
    }

    /// The owner's associated token accounts for `tokens`, in one `getMultipleAccounts`.
    async fn token_accounts_by_ata(
        &self,
        owner: &Address,
        tokens: &[&Token],
    ) -> ChainResult<Vec<Vec<TokenAccount>>> {
        let keys: Vec<String> = tokens
            .iter()
            .map(|token| Self::associated(owner, token))
            .collect::<ChainResult<_>>()?;
        let answer = self
            .read(
                "getMultipleAccounts",
                json!([keys, { "encoding": "jsonParsed", "commitment": "confirmed" }]),
            )
            .await?;
        let list = answer.get("value").and_then(Value::as_array).ok_or(ChainError::Unavailable)?;
        if list.len() != keys.len() {
            return Err(ChainError::Unavailable);
        }
        Ok(keys
            .iter()
            .zip(tokens)
            .zip(list)
            .map(|((key, token), entry)| {
                // No account is a balance of nothing.
                let info = entry.pointer("/data/parsed/info");
                let mint = info.and_then(|i| i.get("mint")).and_then(Value::as_str);
                let holder = info.and_then(|i| i.get("owner")).and_then(Value::as_str);
                let amount = info
                    .and_then(|i| i.pointer("/tokenAmount/amount"))
                    .and_then(Value::as_str)
                    .and_then(|a| a.parse().ok());
                match (mint, holder, amount) {
                    (Some(mint), Some(holder), Some(amount))
                        if mint == token.contract && holder == owner.text =>
                    {
                        vec![TokenAccount { address: key.clone(), mint: mint.to_owned(), amount }]
                    }
                    _ => Vec::new(),
                }
            })
            .collect())
    }

    /// An account's owner program and lamports, or `None` where there is no
    /// such account.
    async fn account(&self, address: &str) -> ChainResult<Option<(String, u64)>> {
        let answer = self
            .read(
                "getAccountInfo",
                json!([address, { "encoding": "base64", "dataSlice": { "offset": 0, "length": 0 }, "commitment": "confirmed" }]),
            )
            .await?;
        let value = answer.get("value").ok_or(ChainError::Unavailable)?;
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some((
            value.get("owner").and_then(Value::as_str).ok_or(ChainError::Unavailable)?.to_owned(),
            value.get("lamports").and_then(Value::as_u64).unwrap_or(0),
        )))
    }

    /// Whether an operator other than the usual one says `address` is a token account (owned
    /// by a token program). A second operator that cannot be asked says nothing.
    async fn second_says_token_account(&self, address: &str) -> bool {
        self.second_says_owner(address, is_token_program).await
    }

    /// Whether either of two independent operators says `address` is owned by a program other
    /// than the System Program. One that cannot be asked says nothing.
    async fn second_says_program_account(&self, address: &str) -> bool {
        self.second_says_owner(address, is_program_owner).await
    }

    /// Whether either of two independent operators gives `address` an owner `says` yes to.
    async fn second_says_owner(&self, address: &str, says: fn(&str) -> bool) -> bool {
        let params = json!([address, { "encoding": "base64", "dataSlice": { "offset": 0, "length": 0 }, "commitment": "confirmed" }]);
        let Ok(answers) =
            self.net.rpc_many(Need::ANY.independent(), 2, "getAccountInfo", &params).await
        else {
            return false;
        };
        answers.iter().any(|(answer, _)| {
            answer
                .as_ref()
                .ok()
                .and_then(|value| value.pointer("/value/owner"))
                .and_then(Value::as_str)
                .is_some_and(says)
        })
    }

    async fn rent(&self, data_len: u64) -> ChainResult<u128> {
        let rent = self.read("getMinimumBalanceForRentExemption", json!([data_len])).await?;
        rent.as_u64().map(u128::from).ok_or(ChainError::Unavailable)
    }

    /// The 75th percentile of the non-zero fees recently paid to write the
    /// account, within bounds: it lands in the next few slots without paying
    /// for the busiest moment in the window.
    async fn priority_fee(&self, writable: &Address) -> (u64, usize) {
        fn upper_quartile(value: &Value) -> Option<u128> {
            let mut fees: Vec<u64> = value
                .as_array()?
                .iter()
                .filter_map(|entry| entry.get("prioritizationFee")?.as_u64())
                .filter(|fee| *fee > 0)
                .collect();
            fees.sort_unstable();
            fees.get(fees.len() * 3 / 4).copied().map(u128::from)
        }
        // Two operators, and the wallet's own constants around what they say: a priority fee is
        // at most `MAX_PRIORITY` (a tenth of a thousandth of a SOL on a token transfer), however
        // high a node quotes it, so a liar costs at most that. Where the operators cannot agree,
        // or only one answers a figure that high, a conservative fixed fee is bid.
        let params = json!([[writable.text]]);
        let Ok(figure) = self
            .net
            .rpc_figure("getRecentPrioritizationFees", &params, upper_quartile, Kind::Fee)
            .await
        else {
            return (FALLBACK_PRIORITY, 2);
        };
        let alone_cap = u128::from(MAX_PRIORITY / 10);
        if figure.sources < 2 && figure.value > alone_cap {
            return (FALLBACK_PRIORITY, 2);
        }
        (
            u64::try_from(figure.value).unwrap_or(MAX_PRIORITY).clamp(MIN_PRIORITY, MAX_PRIORITY),
            figure.sources,
        )
    }

    /// What a transaction pays: `signatures` at the base fee, and `compute`
    /// units at `priority` micro-lamports each, rounded up.
    fn total_fee(signatures: u128, compute: u32, priority: u64) -> u128 {
        FEE_PER_SIGNATURE
            .saturating_mul(signatures)
            .saturating_add((u128::from(compute) * u128::from(priority)).div_ceil(1_000_000))
    }

    /// The associated token account of `owner` for `token`.
    fn associated(owner: &Address, token: &Token) -> ChainResult<String> {
        let owner = owner.key()?;
        let mint = parse_address(token.contract).ok_or(ChainError::Internal)?;
        let ata = associated_token_account(&owner, &mint).ok_or(ChainError::Internal)?;
        Ok(encode_key(&ata))
    }

    /// The address lookup tables a site's transaction loads accounts through, read from **two
    /// operators** that must agree, byte for byte. A transaction names a table and an index, not
    /// the address: the approval summary shows what the table says, so a node that lies about a
    /// table would make the summary show a destination other than the one the chain resolves.
    /// Where two operators do not agree (and a third does not settle it) the tables are not
    /// given: the destination could not be verified.
    pub async fn lookup_tables(&self, tables: &[String]) -> ChainResult<Value> {
        const MOST: usize = 32;
        const PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";
        if tables.is_empty() || tables.len() > MOST {
            return Err(ChainError::invalid("between 1 and 32 tables"));
        }
        for table in tables {
            parse_address(table).ok_or_else(|| ChainError::invalid("a table is not an address"))?;
        }
        let params = json!([tables, { "encoding": "base64", "commitment": "confirmed" }]);
        // What one operator says of all the tables: each one's owner and data, or nothing.
        let read = |answer: &Value| -> Option<Vec<(String, String)>> {
            let list = answer.get("value")?.as_array()?;
            if list.len() != tables.len() {
                return None;
            }
            list.iter()
                .map(|entry| {
                    let owner = entry.get("owner")?.as_str()?.to_owned();
                    let data = entry.get("data")?.get(0)?.as_str()?.to_owned();
                    (owner == PROGRAM).then_some((owner, data))
                })
                .collect()
        };
        let need = Need::ANY.independent();
        let mut readings: Vec<TableReading> = Vec::new();
        for (answer, index) in self.net.rpc_many(need, 2, "getMultipleAccounts", &params).await? {
            if let Some(found) = answer.ok().as_ref().and_then(read) {
                readings.push((found, index));
            }
        }
        if readings.len() >= 2 && agreed(&readings).is_none() {
            let from: Vec<usize> = readings.iter().map(|(_, index)| *index).collect();
            if let Ok((Ok(answer), index)) =
                self.net.rpc_from(need, &from, "getMultipleAccounts", &params).await
                && let Some(found) = read(&answer)
            {
                readings.push((found, index));
            }
        }
        let Some((found, _)) = agreed(&readings) else {
            return Err(crate::quorum::unconfirmed("destination of this transaction"));
        };
        let tables: Vec<Value> = tables
            .iter()
            .zip(found)
            .map(|(address, (_, data))| json!({ "address": address, "data_base64": data }))
            .collect();
        Ok(json!({ "tables": tables }))
    }

    /// The coin and every listed token of `address`.
    pub async fn balances(&self, address: &Address, as_of: &str) -> ChainResult<Value> {
        let tokens = Network::Solana.tokens();
        let (native, accounts) =
            futures::join!(self.lamports(address), self.token_accounts_all(address));
        let mut entries = vec![native_entry(Network::Solana, native?)];
        entries.extend(
            tokens
                .iter()
                .zip(accounts)
                .map(|(token, accounts)| token_entry(token, accounts.ok().map(|a| sum_of(&a)))),
        );
        Ok(balances_body(Network::Solana, &address.text, &entries, as_of))
    }

    /// What a send is built from.
    pub async fn inputs(&self, address: &Address) -> ChainResult<Value> {
        let tokens = Network::Solana.tokens();
        let (hash, accounts, (priority, _), rent) = futures::join!(
            self.read("getLatestBlockhash", json!([{ "commitment": "confirmed" }])),
            self.token_accounts_all(address),
            self.priority_fee(address),
            self.rent(TOKEN_ACCOUNT_LEN),
        );
        let hash = hash?;
        let blockhash = hash
            .pointer("/value/blockhash")
            .and_then(Value::as_str)
            .ok_or(ChainError::Unavailable)?;
        let last_valid = hash
            .pointer("/value/lastValidBlockHeight")
            .and_then(Value::as_u64)
            .ok_or(ChainError::Unavailable)?;
        let mut listed = Vec::new();
        // A token whose accounts could not be read is left out, and named: a coin send does not
        // depend on any token, and a token send will find no source for it.
        let mut unread: Vec<&str> = Vec::new();
        for (token, accounts) in tokens.iter().zip(accounts) {
            let Ok(accounts) = accounts else {
                unread.push(token.symbol);
                continue;
            };
            let associated = Self::associated(address, token)?;
            listed.extend(accounts.into_iter().map(|account| {
                json!({
                    "address": account.address,
                    "mint": account.mint,
                    "symbol": token.symbol,
                    "amount": account.amount.to_string(),
                    "decimals": token.decimals,
                    "associated": account.address == associated,
                })
            }));
        }
        Ok(json!({
            "network": "solana",
            "address": address.text,
            "blockhash": blockhash,
            "last_valid_block_height": last_valid,
            "token_accounts": listed,
            "token_accounts_unread": unread,
            "priority_fee": {
                "micro_lamports_per_unit": priority.to_string(),
                "compute_unit_limit": {
                    "sol_transfer": COMPUTE_SOL,
                    "token_transfer": COMPUTE_TOKEN,
                    "token_transfer_new_account": COMPUTE_TOKEN_NEW,
                },
            },
            "token_account_rent": rent?.to_string(),
        }))
    }

    /// The fee of a transfer and whether its recipient can take it.
    pub async fn estimate(&self, args: &EstimateArgs) -> ChainResult<Value> {
        let from = address::parse(Network::Solana, &args.from)
            .map_err(|_| ChainError::InvalidAddress("from is not a valid address".to_owned()))?;
        let to = address::parse(Network::Solana, &args.to)
            .map_err(|_| ChainError::InvalidAddress("to is not a valid address".to_owned()))?;
        let native = Network::Solana.native();
        let ((priority, priority_sources), recipient) =
            futures::join!(self.priority_fee(&from), self.account(&to.text));
        let recipient = recipient?;

        let Some(token) = args.token else {
            // A coin transfer: a new account must be given enough to stay.
            let exists = recipient.as_ref().is_some_and(|(_, lamports)| *lamports > 0);
            if !exists {
                let minimum = self.rent(0).await?;
                if args.amount < minimum {
                    return Err(ChainError::EstimateFailed(format!(
                        "a new account must receive at least {minimum} lamports to stay open"
                    )));
                }
            }
            let total = Self::total_fee(1, COMPUTE_SOL, priority);
            Figure { value: total, sources: priority_sources }
                .within(limits::SOLANA_TOTAL_FEE, "network fee")?;
            // Lamports sent to an account a program owns (a mint, a token account, a program, a
            // sysvar) are the program's: nobody can take them out again. Either of two operators'
            // "yes" counts, as for a token account; an account nothing has been sent to has no owner.
            let owner = recipient.as_ref().map(|(owner, _)| owner.as_str());
            let program_owned = owner.is_some_and(is_program_owner)
                || (recipient.is_some() && self.second_says_program_account(&to.text).await);
            return Ok(json!({
                "network": "solana",
                "fee": fee_value(native, total),
                "base_fee": FEE_PER_SIGNATURE.to_string(),
                "priority_fee": (total - FEE_PER_SIGNATURE).to_string(),
                "compute_unit_limit": COMPUTE_SOL,
                "compute_unit_price_micro_lamports": priority.to_string(),
                "account_creation": "0",
                "recipient": { "exists": exists, "owner": owner, "program_owned": program_owned },
            }));
        };

        // A token transfer goes to the recipient's associated token account.
        // Sending a token to the address of a token account (and not to a wallet) strands it
        // there, so this is asked of a second operator too, and either one's "yes" counts.
        let is_token_account = recipient.as_ref().is_some_and(|(owner, _)| is_token_program(owner))
            || self.second_says_token_account(&to.text).await;
        let associated = Self::associated(&to, token)?;
        let exists = self.account(&associated).await?.is_some();
        let compute = if exists { COMPUTE_TOKEN } else { COMPUTE_TOKEN_NEW };
        let rent = if exists { 0 } else { self.rent(TOKEN_ACCOUNT_LEN).await? };
        let total = Self::total_fee(1, compute, priority);
        Figure { value: total, sources: priority_sources }
            .within(limits::SOLANA_TOTAL_FEE, "network fee")?;
        Ok(json!({
            "network": "solana",
            "fee": fee_value(native, total),
            "base_fee": FEE_PER_SIGNATURE.to_string(),
            "priority_fee": (total - FEE_PER_SIGNATURE).to_string(),
            "compute_unit_limit": compute,
            "compute_unit_price_micro_lamports": priority.to_string(),
            "account_creation": rent.to_string(),
            "recipient": {
                "token_account_exists": exists,
                "token_account": associated,
                "is_token_account": is_token_account,
            },
        }))
    }

    /// Sends a signed transaction to two endpoints at once.
    pub async fn broadcast(&self, raw: &[u8], signature: &str) -> ChainResult<String> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let params = json!([encoded, { "encoding": "base64", "preflightCommitment": "confirmed", "maxRetries": 5 }]);
        let answers =
            self.net.rpc_many(Need::ANY, BROADCAST_TO, "sendTransaction", &params).await?;
        let mut accepted = false;
        let mut verdict: Option<ChainError> = None;
        for (answer, _) in answers {
            match answer {
                Ok(_) => accepted = true,
                Err(error) => {
                    let refusal = refused(&error, signature);
                    // "Already processed" beside an acceptance is the first
                    // endpoint's work reaching the second.
                    if matches!(refusal, ChainError::Duplicate { .. }) || verdict.is_none() {
                        verdict = Some(refusal);
                    }
                }
            }
        }
        if accepted || matches!(verdict, Some(ChainError::Duplicate { .. })) {
            return Ok(signature.to_owned());
        }
        Err(verdict.unwrap_or(ChainError::Unavailable))
    }

    /// Where a transaction stands.
    pub async fn status(&self, signature: &str) -> ChainResult<Value> {
        if !(80..=90).contains(&signature.len())
            || bs58::decode(signature).into_vec().map(|b| b.len()) != Ok(64)
        {
            return Err(ChainError::invalid("that is not a transaction signature"));
        }
        let answer = self
            .read(
                "getSignatureStatuses",
                json!([[signature], { "searchTransactionHistory": true }]),
            )
            .await?;
        let status = answer.pointer("/value/0").filter(|v| !v.is_null());
        let Some(status) = status else {
            return Ok(json!({ "status": "not_found" }));
        };
        let failed = status.get("err").is_some_and(|e| !e.is_null());
        let level = status.get("confirmationStatus").and_then(Value::as_str).unwrap_or("processed");
        Ok(json!({
            "status": if failed { "failed" } else if level == "finalized" || level == "confirmed" { "confirmed" } else { "pending" },
            "block": status.get("slot").and_then(Value::as_u64),
            "confirmations": status.get("confirmations").and_then(Value::as_u64),
        }))
    }
}

/// A node's refusal of a transaction, as the code that fits it.
fn refused(error: &NodeError, signature: &str) -> ChainError {
    let lower = error.lower();
    let has = |phrases: &[&str]| phrases.iter().any(|p| lower.contains(p));
    if has(&["already been processed", "already processed"]) {
        ChainError::Duplicate { hash: signature.to_owned() }
    } else if has(&["blockhash not found", "block height exceeded", "blockhash has expired"]) {
        ChainError::Expired(
            "the transaction's recent blockhash has expired; build it again from fresh inputs"
                .to_owned(),
        )
    } else if has(&[
        "insufficient funds",
        "insufficientfundsforfee",
        "no record of a prior credit",
        // The token program's "insufficient funds" (custom error 1).
        "custom program error: 0x1",
        "\"custom\":1}",
    ]) {
        ChainError::InsufficientFunds("the account cannot cover the amount and the fee".to_owned())
    } else {
        ChainError::Rejected(REFUSED.to_owned())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_tokens_accounts_add_without_wrapping_whatever_the_node_says() {
        let account =
            |amount: u128| TokenAccount { address: String::new(), mint: String::new(), amount };
        let accounts = [account(u128::MAX), account(u128::MAX), account(5)];
        assert_eq!(sum_of(&accounts), u128::MAX);
        assert_eq!(sum_of(&[]), 0);
    }

    use std::sync::Arc;

    use super::*;
    use crate::client::ChainClient;
    use crate::testing::Script;

    fn node(message: &str) -> NodeError {
        NodeError { code: -32002, message: message.to_owned(), data: None }
    }

    #[test]
    fn a_fee_is_its_signatures_and_its_compute_at_its_priority() {
        // 58,021 units at 493,868 micro-lamports: 28,654.7, rounded up.
        assert_eq!(Solana::total_fee(1, 58_021, 493_868), 5_000 + 28_655);
        assert_eq!(Solana::total_fee(2, 0, 0), 10_000);
    }

    #[test]
    fn a_nodes_refusal_is_told_by_its_words() {
        let case = |m: &str| refused(&node(m), "sig").code();
        assert_eq!(
            case("Transaction simulation failed: This transaction has already been processed"),
            "duplicate"
        );
        assert_eq!(case("Transaction simulation failed: Blockhash not found"), "expired");
        assert_eq!(
            case("Attempt to debit an account but found no record of a prior credit."),
            "insufficient_funds"
        );
        assert_eq!(case("custom program error: 0x1"), "insufficient_funds");
        assert_eq!(case("Transaction signature verification failure"), "rejected");
    }

    const OWNER: &str = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";

    fn parsed_token_account(mint: &str, owner: &str, amount: &str) -> Value {
        json!({ "data": { "parsed": { "info": {
            "mint": mint, "owner": owner, "tokenAmount": { "amount": amount }
        } } } })
    }

    /// Reads the balances of `OWNER` over a script, and says what it was asked.
    async fn balances_over(script: &Arc<Script>) -> Value {
        let client = ChainClient::new(script.clone());
        client
            .dispatch("balances", &json!({ "network": "solana", "address": OWNER }))
            .await
            .unwrap()
    }

    fn amount_of(body: &Value, symbol: &str) -> Option<String> {
        body["balances"]
            .as_array()?
            .iter()
            .find(|e| e["asset"] == symbol)?
            .get("amount")?
            .as_str()
            .map(str::to_owned)
    }

    #[tokio::test]
    async fn tokens_are_read_by_their_associated_accounts_where_the_index_is_refused() {
        // PublicNode asks for a personal token for the indexed call; the Foundation's refuses a
        // browser's Origin. Neither is a reason to show a token as unreadable.
        let script = Arc::new(Script::new());
        script.rpc("getBalance", &json!({ "value": 2_000_000_000_u64 })).rpc_error(
            "getTokenAccountsByOwner",
            -32602,
            "Indexed requests require a personal token",
        );
        let tokens = Network::Solana.tokens();
        let entries: Vec<Value> = tokens
            .iter()
            .enumerate()
            .map(|(i, t)| {
                // The first listed token is held, the others are not (no account).
                if i == 0 {
                    parsed_token_account(t.contract, OWNER, "2500000")
                } else {
                    Value::Null
                }
            })
            .collect();
        script.rpc("getMultipleAccounts", &json!({ "value": entries }));
        let body = balances_over(&script).await;

        assert_eq!(amount_of(&body, "SOL").as_deref(), Some("2000000000"));
        let first = tokens.first().unwrap();
        assert_eq!(amount_of(&body, first.symbol).as_deref(), Some("2500000"));
        for token in tokens.iter().skip(1) {
            assert_eq!(amount_of(&body, token.symbol).as_deref(), Some("0"), "{}", token.symbol);
        }
        // One batched read, of the derived accounts, and no indexed call went unanswered twice.
        assert_eq!(script.count("getMultipleAccounts"), 1);
        let asked = script
            .seen()
            .into_iter()
            .find(|s| s.body.contains("getMultipleAccounts"))
            .unwrap()
            .body;
        let owner = address::parse(Network::Solana, OWNER).unwrap();
        for token in tokens {
            assert!(
                asked.contains(&Solana::associated(&owner, token).unwrap()),
                "{}",
                token.symbol
            );
        }
    }

    #[tokio::test]
    async fn an_account_that_is_not_the_owners_or_the_mint_is_not_counted() {
        let script = Arc::new(Script::new());
        script.rpc("getBalance", &json!({ "value": 1_u64 })).rpc_error(
            "getTokenAccountsByOwner",
            -32602,
            "Indexed requests require a personal token",
        );
        let tokens = Network::Solana.tokens();
        // Every derived account answers with someone else's holding of the wrong mint.
        let entries: Vec<Value> = tokens
            .iter()
            .map(|_| {
                parsed_token_account("So11111111111111111111111111111111111111112", OWNER, "9")
            })
            .collect();
        script.rpc("getMultipleAccounts", &json!({ "value": entries }));
        let body = balances_over(&script).await;
        for token in tokens {
            assert_eq!(amount_of(&body, token.symbol).as_deref(), Some("0"), "{}", token.symbol);
        }
    }

    #[test]
    fn the_associated_account_is_the_standard_derivation() {
        // Owner and mint from the vectors; the answer is the account the network knows.
        let owner = address::parse(Network::Solana, "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9")
            .unwrap();
        let usdt = Network::Solana.token("USDT").unwrap();
        let ata = Solana::associated(&owner, usdt).unwrap();
        // Dy691B3uxmiHDvscgmtNUyAngTpSYi2YUuUCg453M5C is the API doc's example; its address is
        // shortened there, so only the shape is pinned.
        assert!((32..=44).contains(&ata.len()));
        assert_ne!(ata, owner.text);
    }
}
