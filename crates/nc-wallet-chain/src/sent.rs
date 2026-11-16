//! What this device itself has just sent, kept in memory for a few minutes.
//!
//! Endpoints learn of a new transaction at different moments, so right after a send some
//! of them still count the old number of transactions. A nonce read from them could be the
//! one the person's own pending transaction already holds, and a second send at that nonce
//! would replace the first (silently, if it pays at least a tenth more) or fail as
//! underpriced. So the next nonce is never below *the last one sent, plus one* while the
//! record is fresh. The record is the device's own: it holds an address and a number, lives
//! only in memory, and is forgotten after [`FOR_MS`] (by then the endpoints have caught up,
//! or the transaction was dropped and its number is free again).

use std::collections::HashMap;
use std::sync::Mutex;

/// How long a record is kept: ten minutes.
pub const FOR_MS: u64 = 600_000;
/// Records kept at most.
const MOST: usize = 64;

#[derive(Debug, Default)]
struct Inner {
    /// `network|address` to the last nonce sent and when.
    nonces: HashMap<String, (u128, u64)>,
    /// Hashes the endpoints accepted, when, and the nonce each used where the app said.
    hashes: HashMap<String, (u64, Option<u128>)>,
}

/// The device's own record of its sends.
#[derive(Debug, Default)]
pub struct Sent {
    inner: Mutex<Inner>,
}

fn key(network: &str, from: &str) -> String {
    format!("{network}|{}", from.to_ascii_lowercase())
}

impl Sent {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Notes that `hash` was accepted by the network, and (where the sender and the nonce are
    /// known) that `from` has used `nonce` on `network`.
    pub fn record(
        &self,
        network: &str,
        from: Option<&str>,
        nonce: Option<u128>,
        hash: &str,
        now: u64,
    ) {
        let mut inner = self.lock();
        inner.nonces.retain(|_, (_, at)| now.saturating_sub(*at) < FOR_MS);
        inner.hashes.retain(|_, (at, _)| now.saturating_sub(*at) < FOR_MS);
        if inner.hashes.len() >= MOST {
            inner.hashes.clear();
        }
        if inner.nonces.len() >= MOST {
            inner.nonces.clear();
        }
        inner.hashes.insert(hash.to_ascii_lowercase(), (now, nonce));
        if let (Some(from), Some(nonce)) = (from, nonce) {
            let slot = inner.nonces.entry(key(network, from)).or_insert((nonce, now));
            if nonce >= slot.0 {
                *slot = (nonce, now);
            }
        }
    }

    /// The nonce the next send uses: what the endpoints agree on, but never below one past
    /// the last this device sent, while that record is fresh.
    #[must_use]
    pub fn next_nonce(&self, network: &str, from: &str, agreed: u128, now: u64) -> u128 {
        let inner = self.lock();
        match inner.nonces.get(&key(network, from)) {
            Some(&(sent, at)) if now.saturating_sub(at) < FOR_MS => {
                agreed.max(sent.saturating_add(1))
            }
            _ => agreed,
        }
    }

    /// Whether this device sent `hash` and the network accepted it, lately.
    #[must_use]
    pub fn knows(&self, hash: &str, now: u64) -> bool {
        self.lock()
            .hashes
            .get(&hash.to_ascii_lowercase())
            .is_some_and(|(at, _)| now.saturating_sub(*at) < FOR_MS)
    }

    /// The nonce the send of `hash` used, if this device sent it lately and the app said which.
    #[must_use]
    pub fn nonce_of(&self, hash: &str, now: u64) -> Option<u128> {
        self.lock()
            .hashes
            .get(&hash.to_ascii_lowercase())
            .filter(|(at, _)| now.saturating_sub(*at) < FOR_MS)
            .and_then(|(_, nonce)| *nonce)
    }

    /// The hashes this device sent and the network accepted, lately (lowercase): what an unconfirmed output
    /// is compared with to tell whether it is this wallet's own.
    #[must_use]
    pub fn recent_hashes(&self, now: u64) -> std::collections::HashSet<String> {
        self.lock()
            .hashes
            .iter()
            .filter(|(_, (at, _))| now.saturating_sub(*at) < FOR_MS)
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    /// What is kept, for the app to hold across a restart of the worker or the app (a few minutes
    /// matter): the addresses and nonces sent from lately, and the hashes accepted. It names
    /// addresses of the wallet, so an app keeps it where the history is kept (sealed) or in memory
    /// that goes with the session, and removes it with the wallet.
    #[must_use]
    pub fn export(&self, now: u64) -> serde_json::Value {
        let inner = self.lock();
        let fresh = |at: u64| now.saturating_sub(at) < FOR_MS;
        let nonces: Vec<serde_json::Value> = inner
            .nonces
            .iter()
            .filter(|(_, (_, at))| fresh(*at))
            .map(|(key, (nonce, at))| serde_json::json!([key, nonce.to_string(), at]))
            .collect();
        // (A nonce rides as a third part, where the app said which the send used.)
        let hashes: Vec<serde_json::Value> = inner
            .hashes
            .iter()
            .filter(|(_, (at, _))| fresh(*at))
            .map(|(hash, (at, nonce))| match nonce {
                Some(nonce) => serde_json::json!([hash, at, nonce.to_string()]),
                None => serde_json::json!([hash, at]),
            })
            .collect();
        serde_json::json!({ "v": 1, "n": nonces, "h": hashes })
    }

    /// Takes back what [`Self::export`] wrote; anything that is not that, or is stale, is left out.
    pub fn import(&self, value: &serde_json::Value, now: u64) {
        if value.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return;
        }
        let mut inner = self.lock();
        let fresh = |at: u64| now.saturating_sub(at) < FOR_MS;
        for entry in
            value.get("n").and_then(serde_json::Value::as_array).into_iter().flatten().take(MOST)
        {
            let parsed = (|| {
                let key = entry.get(0)?.as_str()?.to_owned();
                let nonce: u128 = entry.get(1)?.as_str()?.parse().ok()?;
                let at = entry.get(2)?.as_u64()?;
                Some((key, nonce, at))
            })();
            if let Some((key, nonce, at)) = parsed
                && fresh(at)
            {
                let slot = inner.nonces.entry(key).or_insert((nonce, at));
                if nonce >= slot.0 {
                    *slot = (nonce, at);
                }
            }
        }
        for entry in
            value.get("h").and_then(serde_json::Value::as_array).into_iter().flatten().take(MOST)
        {
            if let (Some(hash), Some(at)) = (
                entry.get(0).and_then(serde_json::Value::as_str),
                entry.get(1).and_then(serde_json::Value::as_u64),
            ) && fresh(at)
            {
                let nonce = entry
                    .get(2)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|nonce| nonce.parse().ok());
                inner.hashes.insert(hash.to_ascii_lowercase(), (at, nonce));
            }
        }
    }

    /// Forgets everything (the wallet was removed).
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.nonces.clear();
        inner.hashes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "0xAbC0000000000000000000000000000000000001";

    #[test]
    fn the_next_nonce_is_never_below_one_past_the_last_sent_while_the_record_is_fresh() {
        let sent = Sent::default();
        assert_eq!(sent.next_nonce("ethereum", ME, 7, 1_000), 7);
        sent.record("ethereum", Some(ME), Some(7), "0xaa", 1_000);
        // Endpoints that still say 7 (or less) cannot put the next send on the same number.
        assert_eq!(sent.next_nonce("ethereum", ME, 7, 21_000), 8);
        assert_eq!(sent.next_nonce("ethereum", &ME.to_ascii_lowercase(), 5, 21_000), 8);
        // Endpoints that have caught up, or run ahead (another device), are believed.
        assert_eq!(sent.next_nonce("ethereum", ME, 8, 21_000), 8);
        assert_eq!(sent.next_nonce("ethereum", ME, 12, 21_000), 12);
        // Another network or account is not affected.
        assert_eq!(sent.next_nonce("polygon", ME, 7, 21_000), 7);
        assert_eq!(sent.next_nonce("ethereum", "0xdef", 7, 21_000), 7);
        // After ten minutes the record is forgotten: a dropped transaction frees its number.
        assert_eq!(sent.next_nonce("ethereum", ME, 7, 1_000 + FOR_MS), 7);
    }

    #[test]
    fn two_sends_in_a_row_count_up_and_an_older_one_does_not_lower_the_record() {
        let sent = Sent::default();
        sent.record("ethereum", Some(ME), Some(7), "0xaa", 1_000);
        sent.record("ethereum", Some(ME), Some(8), "0xbb", 2_000);
        assert_eq!(sent.next_nonce("ethereum", ME, 7, 3_000), 9);
        sent.record("ethereum", Some(ME), Some(5), "0xcc", 3_000);
        assert_eq!(sent.next_nonce("ethereum", ME, 7, 3_000), 9);
    }

    #[test]
    fn the_record_survives_a_restart_through_export_and_import_while_it_is_fresh() {
        let sent = Sent::default();
        sent.record("ethereum", Some(ME), Some(7), "0xaa", 1_000);
        let kept = sent.export(5_000);
        // A new client, handed it a little later: the same floor, the same hash.
        let again = Sent::default();
        again.import(&kept, 60_000);
        assert_eq!(again.next_nonce("ethereum", ME, 7, 60_000), 8);
        assert!(again.knows("0xaa", 60_000));
        // Handed it after ten minutes it is nothing; nor is anything that is not a record.
        let late = Sent::default();
        late.import(&kept, 1_000 + FOR_MS);
        assert_eq!(late.next_nonce("ethereum", ME, 7, 1_000 + FOR_MS), 7);
        for bad in [
            serde_json::json!({}),
            serde_json::json!("x"),
            serde_json::json!({ "v": 2, "n": [], "h": [] }),
        ] {
            Sent::default().import(&bad, 0);
        }
        // Export drops what is stale.
        assert_eq!(sent.export(1_000 + FOR_MS)["n"], serde_json::json!([]));
    }

    #[test]
    fn the_nonce_a_send_used_is_found_by_its_hash_and_survives_a_restart() {
        let sent = Sent::default();
        sent.record("bittensor", Some("5Gr"), Some(7), "0xAA", 1_000);
        sent.record("bittensor", None, None, "0xbb", 1_000);
        assert_eq!(sent.nonce_of("0xaa", 2_000), Some(7));
        assert_eq!(sent.nonce_of("0xbb", 2_000), None, "the app did not say");
        assert_eq!(sent.nonce_of("0xcc", 2_000), None);
        assert_eq!(sent.nonce_of("0xaa", 1_000 + FOR_MS), None, "and not for ever");
        let again = Sent::default();
        again.import(&sent.export(5_000), 60_000);
        assert_eq!(again.nonce_of("0xaa", 60_000), Some(7));
        assert!(again.knows("0xbb", 60_000));
        // A record written before nonces rode along is read as it was, and a nonce that is not one is none.
        let old = Sent::default();
        old.import(
            &serde_json::json!({ "v": 1, "n": [], "h": [["0xaa", 1_000], ["0xbb", 1_000, "x"], ["0xcc", 1_000, 7]] }),
            2_000,
        );
        assert!(old.knows("0xaa", 2_000) && old.knows("0xbb", 2_000) && old.knows("0xcc", 2_000));
        assert_eq!(
            (old.nonce_of("0xaa", 2_000), old.nonce_of("0xbb", 2_000), old.nonce_of("0xcc", 2_000)),
            (None, None, None)
        );
    }

    #[test]
    fn a_hash_is_known_for_a_while_and_not_forever() {
        let sent = Sent::default();
        assert!(!sent.knows("0xAA", 0));
        sent.record("ethereum", None, None, "0xaa", 100);
        assert!(sent.knows("0xAA", 200));
        assert!(!sent.knows("0xaa", 100 + FOR_MS));
        sent.clear();
        assert!(!sent.knows("0xaa", 200));
    }
}
