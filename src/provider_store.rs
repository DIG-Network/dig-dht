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
//!   (refreshing its `expires_at` + addresses), it does not accumulate duplicates;
//! - **bounded** — [`put`](ProviderStore::put) enforces a per-content-key cap
//!   ([`ProviderStoreLimits::max_providers_per_key`]) and a global record ceiling
//!   ([`ProviderStoreLimits::max_total_records`]); an inbound record from an untrusted peer can
//!   never grow the store without bound (SPEC §6.3, §14).
//!
//! It also tracks the set of content keys **this node announces** (content it holds) so the
//! maintenance loop can republish them before their TTL elapses ([`local_announcements`]).
//!
//! [`local_announcements`]: ProviderStore::local_announcements

use std::collections::{HashMap, HashSet};

use crate::record::ProviderRecord;

/// Bounds enforced by [`ProviderStore::put`] — the admission control that keeps the store from
/// growing without bound under inbound `add_provider` traffic from untrusted peers.
///
/// Both caps are enforced **on every `put`**, not just at GC time: a single misbehaving peer that
/// floods `add_provider` for many distinct content keys (or many distinct providers per key) is
/// rejected once a cap is hit, rather than accepted and relying on TTL expiry to eventually free
/// memory (SPEC §6.3, §14 "Unbounded provider store").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderStoreLimits {
    /// Maximum distinct provider records kept **per content key**. When a `put` for a new provider
    /// would exceed this, the soonest-to-expire existing record for that key is evicted to make
    /// room (a fresher/longer-lived record is preferred over a stale one).
    pub max_providers_per_key: usize,
    /// Maximum total records across **all** content keys. When a `put` for a genuinely new
    /// (content_key, provider) pair would exceed this, the request is rejected outright (no
    /// eviction across keys — that would let one attacker evict another key's legitimate holders).
    pub max_total_records: usize,
}

impl Default for ProviderStoreLimits {
    /// Conservative defaults: `k` (20, the Kademlia replication parameter) providers per key is
    /// already generous replication, and a global ceiling that comfortably covers a node
    /// participating in many lookups while still bounding worst-case memory from a single
    /// misbehaving peer.
    fn default() -> Self {
        ProviderStoreLimits {
            max_providers_per_key: 20,
            max_total_records: 100_000,
        }
    }
}

/// The outcome of a [`ProviderStore::put`] — whether the record was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// The record was stored (fresh insert or refresh of an existing provider's record).
    Accepted,
    /// The record was rejected: the store is at capacity and the record did not qualify for
    /// eviction-based admission (a new provider would exceed
    /// [`ProviderStoreLimits::max_total_records`], or the per-key cap is full of records that all
    /// expire no sooner than the incoming one).
    RejectedOverCapacity,
}

/// A node's local provider records + the set of content keys it announces itself.
#[derive(Debug)]
pub struct ProviderStore {
    /// content_key (64-hex) → provider_peer_id (64-hex) → record.
    by_key: HashMap<String, HashMap<String, ProviderRecord>>,
    /// content keys (64-hex) this node holds + announces (for republish).
    announced: HashSet<String>,
    /// Admission-control bounds enforced by [`put`](Self::put).
    limits: ProviderStoreLimits,
}

impl Default for ProviderStore {
    fn default() -> Self {
        ProviderStore::new()
    }
}

impl ProviderStore {
    /// A new empty store with the default [`ProviderStoreLimits`].
    pub fn new() -> Self {
        ProviderStore::with_limits(ProviderStoreLimits::default())
    }

    /// A new empty store enforcing `limits` on every [`put`](Self::put).
    pub fn with_limits(limits: ProviderStoreLimits) -> Self {
        ProviderStore {
            by_key: HashMap::new(),
            announced: HashSet::new(),
            limits,
        }
    }

    /// Store (or refresh) a provider record, subject to [`ProviderStoreLimits`].
    ///
    /// Keyed by (content_key, provider_peer_id): a second record from the same provider for the
    /// same key REPLACES the first (refreshes expiry + addresses) rather than duplicating — this
    /// always succeeds regardless of capacity, since it does not grow the store.
    ///
    /// A genuinely new (content_key, provider) pair is admission-controlled:
    /// - if the key already holds [`ProviderStoreLimits::max_providers_per_key`] *other* providers,
    ///   the soonest-to-expire one is evicted to make room (soonest-to-expire is the least valuable
    ///   record to keep);
    /// - if the store is at [`ProviderStoreLimits::max_total_records`] globally, the new record is
    ///   rejected — [`PutOutcome::RejectedOverCapacity`] — rather than evicting another key's
    ///   records (which would let one attacker's flood evict another key's legitimate holders).
    pub fn put(&mut self, record: ProviderRecord) -> PutOutcome {
        let is_new_provider = !self
            .by_key
            .get(&record.content_key)
            .is_some_and(|providers| providers.contains_key(&record.provider_peer_id));

        if is_new_provider {
            // Global ceiling check FIRST, before touching this key's entry, so a rejected record
            // never leaves a stray empty entry behind and so the check reads the true pre-insert
            // total (not skewed by an entry we are about to create).
            if self.len() >= self.limits.max_total_records {
                return PutOutcome::RejectedOverCapacity;
            }
            if let Some(providers) = self.by_key.get_mut(&record.content_key) {
                if providers.len() >= self.limits.max_providers_per_key {
                    // Evict the soonest-to-expire record in this key's set to make room.
                    if let Some(evict_id) = providers
                        .iter()
                        .min_by_key(|(_, r)| r.expires_at)
                        .map(|(pid, _)| pid.clone())
                    {
                        providers.remove(&evict_id);
                    }
                }
            }
        }

        self.by_key
            .entry(record.content_key.clone())
            .or_default()
            .insert(record.provider_peer_id.clone(), record);
        PutOutcome::Accepted
    }

    /// Remove exactly the record for `(content_key, provider_peer_id)`, if present. Returns whether
    /// a record was removed.
    ///
    /// This is the store half of an **authenticated retract** (SPEC §6.6): a caller that has
    /// verified a signed retract from `provider_peer_id` removes only that provider's record for
    /// that key. It MUST NOT touch any OTHER provider of the same key — a retract signed by one
    /// holder can never evict another holder's record (censorship-resistance). A content key left
    /// with no remaining providers is dropped so the store does not accumulate empty entries.
    pub fn remove(&mut self, content_key: &str, provider_peer_id: &str) -> bool {
        let Some(providers) = self.by_key.get_mut(content_key) else {
            return false;
        };
        let removed = providers.remove(provider_peer_id).is_some();
        if providers.is_empty() {
            self.by_key.remove(content_key);
        }
        removed
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

    // ---- Admission control (HIGH #1: unbounded provider store, SECURITY_AUDIT_P2P.md #179) ----

    #[test]
    fn put_returns_accepted_under_capacity() {
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        assert_eq!(s.put(rec(&key, 1, 100)), PutOutcome::Accepted);
    }

    #[test]
    fn refreshing_same_provider_always_succeeds_even_at_per_key_cap() {
        // A refresh (same provider, same key) never counts as "new" so it must never be blocked by
        // the per-key cap even when the key is already full.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 1,
            max_total_records: 1000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        assert_eq!(s.put(rec(&key, 1, 100)), PutOutcome::Accepted);
        assert_eq!(s.put(rec(&key, 1, 999)), PutOutcome::Accepted, "refresh");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn per_key_cap_evicts_soonest_to_expire_to_make_room() {
        // One malicious/heavy peer announcing many DISTINCT providers for the SAME content key must
        // not grow that key's provider set past `max_providers_per_key` — the audit's "no cap on
        // providers-per-key" finding.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 2,
            max_total_records: 1000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        assert_eq!(s.put(rec(&key, 1, 100)), PutOutcome::Accepted); // expires soonest
        assert_eq!(s.put(rec(&key, 2, 500)), PutOutcome::Accepted);
        // A third distinct provider must evict the soonest-to-expire (provider 1), not grow past 2.
        assert_eq!(s.put(rec(&key, 3, 900)), PutOutcome::Accepted);
        assert_eq!(
            s.get(&key.to_hex(), 0).len(),
            2,
            "per-key cap must not be exceeded"
        );
        let ids: std::collections::HashSet<String> = s
            .get(&key.to_hex(), 0)
            .into_iter()
            .map(|r| r.provider_peer_id)
            .collect();
        assert!(
            !ids.contains(&PeerId::from_bytes([1u8; 32]).to_hex()),
            "soonest-to-expire provider must be the one evicted"
        );
    }

    #[test]
    fn global_cap_rejects_new_content_keys_over_ceiling() {
        // Many DISTINCT content keys (not just many providers per key) must also be bounded — the
        // audit's "no cap on distinct content keys ... no global record ceiling" finding.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 20,
            max_total_records: 2,
        });
        let k1 = Key::from_bytes([0x01; 32]);
        let k2 = Key::from_bytes([0x02; 32]);
        let k3 = Key::from_bytes([0x03; 32]);
        assert_eq!(s.put(rec(&k1, 1, 100)), PutOutcome::Accepted);
        assert_eq!(s.put(rec(&k2, 1, 100)), PutOutcome::Accepted);
        assert_eq!(
            s.put(rec(&k3, 1, 100)),
            PutOutcome::RejectedOverCapacity,
            "third distinct record must be rejected once the global ceiling is hit"
        );
        assert_eq!(s.len(), 2, "rejected record must not be stored");
        assert!(
            s.get(&k3.to_hex(), 0).is_empty(),
            "rejected key must not appear in the store at all"
        );
    }

    #[test]
    fn global_cap_does_not_evict_a_different_key_to_make_room() {
        // A single attacker flooding new keys must not be able to evict a DIFFERENT (legitimate)
        // key's providers just by hitting the global ceiling.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 20,
            max_total_records: 1,
        });
        let legit = Key::from_bytes([0xAA; 32]);
        s.put(rec(&legit, 1, 100));
        let attacker_key = Key::from_bytes([0xBB; 32]);
        assert_eq!(
            s.put(rec(&attacker_key, 2, 100)),
            PutOutcome::RejectedOverCapacity
        );
        assert_eq!(
            s.get(&legit.to_hex(), 0).len(),
            1,
            "the legitimate key's record must survive"
        );
    }

    #[test]
    fn remove_deletes_only_the_named_provider_record() {
        // Authenticated retract (SPEC §6.6): removing (key, provider-1) must leave provider-2 of the
        // SAME key untouched — a retract signed by one holder cannot censor another holder.
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        s.put(rec(&key, 1, 100));
        s.put(rec(&key, 2, 100));
        let pid1 = PeerId::from_bytes([1u8; 32]).to_hex();
        let pid2 = PeerId::from_bytes([2u8; 32]).to_hex();
        assert!(
            s.remove(&key.to_hex(), &pid1),
            "the named record was removed"
        );
        let survivors: std::collections::HashSet<String> = s
            .get(&key.to_hex(), 0)
            .into_iter()
            .map(|r| r.provider_peer_id)
            .collect();
        assert_eq!(survivors.len(), 1, "the other provider must survive");
        assert!(survivors.contains(&pid2));
        assert!(!survivors.contains(&pid1));
    }

    #[test]
    fn remove_of_absent_record_returns_false() {
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        s.put(rec(&key, 1, 100));
        let absent = PeerId::from_bytes([9u8; 32]).to_hex();
        assert!(!s.remove(&key.to_hex(), &absent), "no such provider");
        assert!(!s.remove(&"00".repeat(32), &absent), "no such content key");
        assert_eq!(s.len(), 1, "nothing removed");
    }

    #[test]
    fn remove_drops_content_key_when_last_provider_leaves() {
        let mut s = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        s.put(rec(&key, 1, 100));
        let pid1 = PeerId::from_bytes([1u8; 32]).to_hex();
        assert!(s.remove(&key.to_hex(), &pid1));
        assert!(
            s.is_empty(),
            "the now-empty content key must be dropped entirely"
        );
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
