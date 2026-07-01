//! [`ProviderStore`] — the local key→providers map a node serves on `find_providers` / `add_provider`.
//!
//! Every DHT node keeps a small store of provider records it has been told about (via
//! `add_provider`, because it is one of the `k` closest to those content keys) plus the records for
//! content **it itself holds and announces**. The store is:
//!
//! - **keyed by content key** (the 64-hex [`Key`](crate::Key)) → a set of [`ProviderRecord`]s (one
//!   per distinct provider `peer_id`);
//! - **TTL'd** — [`get`](ProviderStore::get) never returns expired records, and
//!   [`gc`](ProviderStore::gc) drops them so the store does not grow without bound;
//! - **dedup-on-provider** — re-announcing from the same provider replaces that provider's record
//!   (refreshing its `expires_at` + addresses), it does not accumulate duplicates.
//!
//! It also tracks the set of content keys **this node announces** (content it holds) so the
//! maintenance loop can republish them before their TTL elapses ([`local_announcements`]).
//!
//! [`local_announcements`]: ProviderStore::local_announcements

use std::collections::{HashMap, HashSet};

use crate::record::ProviderRecord;

/// A node's local provider records + the set of content keys it announces itself.
#[derive(Debug, Default)]
pub struct ProviderStore {
    /// content_key (64-hex) → provider_peer_id (64-hex) → record.
    by_key: HashMap<String, HashMap<String, ProviderRecord>>,
    /// content keys (64-hex) this node holds + announces (for republish).
    announced: HashSet<String>,
}

impl ProviderStore {
    /// A new empty store.
    pub fn new() -> Self {
        ProviderStore::default()
    }

    /// Store (or refresh) a provider record. Keyed by (content_key, provider_peer_id): a second
    /// record from the same provider for the same key REPLACES the first (refreshes expiry +
    /// addresses) rather than duplicating.
    pub fn put(&mut self, record: ProviderRecord) {
        self.by_key
            .entry(record.content_key.clone())
            .or_default()
            .insert(record.provider_peer_id.clone(), record);
    }

    /// The live (non-expired at `now`) provider records for `content_key`. Expired records are
    /// skipped (and cleaned up by [`gc`](Self::gc)); returns an empty vec if none are known/live.
    pub fn get(&self, content_key: &str, now: u64) -> Vec<ProviderRecord> {
        self.by_key
            .get(content_key)
            .map(|providers| {
                providers
                    .values()
                    .filter(|r| !r.is_expired(now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Drop every expired record (and any content key left with no live providers) as of `now`.
    /// Returns the number of records removed. Call periodically from the maintenance loop.
    pub fn gc(&mut self, now: u64) -> usize {
        let mut removed = 0;
        self.by_key.retain(|_key, providers| {
            let before = providers.len();
            providers.retain(|_pid, r| !r.is_expired(now));
            removed += before - providers.len();
            !providers.is_empty()
        });
        removed
    }

    /// Record that this node holds + announces `content_key` (so the maintenance loop republishes
    /// it). Idempotent.
    pub fn mark_announced(&mut self, content_key: String) {
        self.announced.insert(content_key);
    }

    /// Stop announcing `content_key` (this node no longer holds the content). Returns whether it was
    /// being announced.
    pub fn unmark_announced(&mut self, content_key: &str) -> bool {
        self.announced.remove(content_key)
    }

    /// The content keys this node announces (holds) — the republish work list.
    pub fn local_announcements(&self) -> Vec<String> {
        self.announced.iter().cloned().collect()
    }

    /// Total live+stale records across all keys (diagnostics / tests).
    pub fn len(&self) -> usize {
        self.by_key.values().map(|p| p.len()).sum()
    }

    /// Whether the store holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;
    use crate::record::CandidateAddr;
    use dig_nat::PeerId;

    fn rec(content: &Key, provider: u8, expires_at: u64) -> ProviderRecord {
        ProviderRecord::new(
            content,
            &PeerId::from_bytes([provider; 32]),
            vec![CandidateAddr::direct("h", 9444)],
            expires_at,
        )
    }

    #[test]
    fn put_then_get_returns_live_record() {
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        s.put(rec(&key, 1, 100));
        let got = s.get(&key.to_hex(), 50);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].provider_peer_id,
            PeerId::from_bytes([1u8; 32]).to_hex()
        );
    }

    #[test]
    fn get_hides_expired_records() {
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        s.put(rec(&key, 1, 100));
        assert!(
            s.get(&key.to_hex(), 100).is_empty(),
            "expired at exactly TTL"
        );
        assert!(s.get(&key.to_hex(), 200).is_empty());
    }

    #[test]
    fn same_provider_dedups_and_refreshes() {
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        s.put(rec(&key, 1, 100));
        s.put(rec(&key, 1, 500)); // same provider, later expiry
        assert_eq!(s.len(), 1, "same provider must not duplicate");
        // The refreshed expiry wins.
        assert_eq!(s.get(&key.to_hex(), 300).len(), 1);
    }

    #[test]
    fn distinct_providers_for_same_key_coexist() {
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        s.put(rec(&key, 1, 100));
        s.put(rec(&key, 2, 100));
        assert_eq!(s.get(&key.to_hex(), 50).len(), 2);
    }

    #[test]
    fn gc_removes_expired_and_empty_keys() {
        let mut s = ProviderStore::new();
        let k1 = Key::from_bytes([0x01; 32]);
        let k2 = Key::from_bytes([0x02; 32]);
        s.put(rec(&k1, 1, 100)); // expires at 100
        s.put(rec(&k2, 1, 500)); // expires at 500
        let removed = s.gc(200);
        assert_eq!(removed, 1);
        assert!(s.get(&k1.to_hex(), 200).is_empty());
        assert_eq!(s.get(&k2.to_hex(), 200).len(), 1);
    }

    #[test]
    fn announcements_track_and_untrack() {
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0x07; 32]).to_hex();
        s.mark_announced(key.clone());
        s.mark_announced(key.clone()); // idempotent
        assert_eq!(s.local_announcements(), vec![key.clone()]);
        assert!(s.unmark_announced(&key));
        assert!(!s.unmark_announced(&key));
        assert!(s.local_announcements().is_empty());
    }
}
