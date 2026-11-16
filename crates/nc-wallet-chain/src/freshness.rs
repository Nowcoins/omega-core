//! How often the endpoints are really asked, whatever the screens do.
//!
//! Public endpoints are free and shared, and an open panel or app asks again
//! and again. So the client keeps the last answer of a read for a while and
//! answers from it, and **backs off while nothing changes**:
//!
//! * a read is answered from the last answer for 45 seconds;
//! * each time the answer comes back the same, the time doubles (90 s, 3 min),
//!   up to five minutes;
//! * a change resets it, and so does `fresh: true` in the request, which the
//!   app sends when the person comes back to the window, pulls to refresh, or
//!   has just sent something;
//! * a broadcast on a network forgets what was kept for that network.
//!
//! A quiet wallet in a panel that stays open therefore falls from a read a
//! minute to a read every five. Nothing here decides *when* a screen asks: a
//! hidden panel must not ask at all, and that is the screen's job. This only
//! bounds what asking costs the endpoints.

use std::sync::{Mutex, PoisonError};

use serde_json::Value;

/// How long a read is answered from the last answer to begin with.
pub const BASE_MS: u64 = 45_000;
/// The longest, once the answers keep coming back the same.
pub const MAX_MS: u64 = 300_000;
/// The most reads kept.
const MAX_ENTRIES: usize = 64;

#[derive(Debug)]
struct Entry {
    key: String,
    network: String,
    at: u64,
    ttl: u64,
    unchanged: u32,
    body: Value,
}

/// The last answers, and how long each is good for.
#[derive(Debug)]
pub struct Freshness {
    base: u64,
    max: u64,
    entries: Mutex<Vec<Entry>>,
}

impl Default for Freshness {
    /// The policy of a balance read: 45 seconds, backing off to five minutes.
    fn default() -> Self {
        Self::new(BASE_MS, MAX_MS)
    }
}

/// An answer without the moment it was read, to tell whether it changed.
fn same(a: &Value, b: &Value) -> bool {
    let strip = |v: &Value| {
        let mut v = v.clone();
        if let Some(object) = v.as_object_mut() {
            object.remove("as_of");
        }
        v
    };
    strip(a) == strip(b)
}

impl Freshness {
    /// A cache whose answers are good for `base` milliseconds, and for up to
    /// `max` once they keep coming back the same.
    #[must_use]
    pub const fn new(base: u64, max: u64) -> Self {
        Self { base, max, entries: Mutex::new(Vec::new()) }
    }

    /// The last answer to `key`, if it is still good at `now`.
    pub fn get(&self, key: &str, now: u64) -> Option<Value> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.iter().find(|e| e.key == key)?;
        (now.saturating_sub(entry.at) < entry.ttl).then(|| entry.body.clone())
    }

    /// Keeps `body` as the answer to `key` (of `network`), and works out for how
    /// long: longer each time it is the same as the last.
    pub fn put(&self, key: &str, network: &str, now: u64, body: &Value) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let previous = entries.iter().position(|e| e.key == key).map(|i| entries.remove(i));
        let unchanged = match &previous {
            Some(p) if same(&p.body, body) => p.unchanged + 1,
            _ => 0,
        };
        let ttl = (self.base << unchanged.min(6)).min(self.max);
        if entries.len() >= MAX_ENTRIES {
            entries.remove(0);
        }
        entries.push(Entry {
            key: key.to_owned(),
            network: network.to_owned(),
            at: now,
            ttl,
            unchanged,
            body: body.clone(),
        });
    }

    /// Forgets everything kept for `network` (after a transaction was sent on it).
    pub fn forget(&self, network: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|e| e.network != network);
    }

    /// Forgets everything (the wallet was removed or replaced).
    pub fn clear(&self) {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn an_answer_is_good_for_a_while_and_longer_each_time_it_is_the_same() {
        let kept = Freshness::default();
        let body =
            |amount: &str, at: &str| json!({ "balances": [{ "amount": amount }], "as_of": at });
        assert_eq!(kept.get("k", 0), None);
        kept.put("k", "ethereum", 0, &body("5", "t0"));
        assert!(kept.get("k", 44_999).is_some());
        assert!(kept.get("k", 45_000).is_none(), "45 s to begin with");
        // The same again (the time it was read differs): 90 s, then 180 s, then 300 s.
        kept.put("k", "ethereum", 45_000, &body("5", "t1"));
        assert!(kept.get("k", 45_000 + 89_999).is_some());
        assert!(kept.get("k", 45_000 + 90_000).is_none());
        kept.put("k", "ethereum", 135_000, &body("5", "t2"));
        kept.put("k", "ethereum", 315_000, &body("5", "t3"));
        kept.put("k", "ethereum", 615_000, &body("5", "t4"));
        assert!(kept.get("k", 615_000 + 299_999).is_some());
        assert!(kept.get("k", 615_000 + 300_000).is_none(), "five minutes at most");
        // A change starts over.
        kept.put("k", "ethereum", 915_000, &body("6", "t5"));
        assert!(kept.get("k", 915_000 + 45_000).is_none());
    }

    #[test]
    fn a_send_forgets_its_network_only() {
        let kept = Freshness::default();
        kept.put("a", "ethereum", 0, &json!(1));
        kept.put("b", "base", 0, &json!(2));
        kept.forget("ethereum");
        assert_eq!(kept.get("a", 1), None);
        assert_eq!(kept.get("b", 1), Some(json!(2)));
        kept.clear();
        assert_eq!(kept.get("b", 1), None);
    }

    #[test]
    fn the_cache_does_not_grow_without_end() {
        let kept = Freshness::default();
        for i in 0..200 {
            kept.put(&format!("k{i}"), "n", 0, &json!(i));
        }
        assert_eq!(kept.get("k0", 1), None);
        assert!(kept.get("k199", 1).is_some());
    }
}
