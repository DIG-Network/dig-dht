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
    /// would exceed this, an existing record is evicted to make room: an EXPIRED record if the key
    /// holds one, otherwise the soonest-to-expire among the key's NEWEST slots, leaving its
    /// longest-established LIVE providers reserved (see [`ProviderStore::eviction_victim`]).
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

/// Share of a content key's slots reserved for its longest-established providers — the divisor is
/// applied to [`ProviderStoreLimits::max_providers_per_key`], so half the slots are protected from
/// eviction and the newest half form the "churn zone" where eviction happens (#1434).
///
/// Half is chosen so the floor is always strictly smaller than the cap: a newcomer can therefore
/// ALWAYS be admitted by evicting inside the churn zone, and the protection never turns into a
/// refusal to learn about new honest holders.
const ESTABLISHED_FLOOR_DIVISOR: usize = 2;

/// One stored provider record plus **when this node first admitted it** — its establishment.
///
/// Establishment is an admission SEQUENCE number, not a timestamp: the store needs only the relative
/// order in which providers were first learned, and an ordinal cannot be manipulated by an attacker
/// choosing when to announce, nor does it need a clock threaded through [`ProviderStore::put`].
#[derive(Debug)]
struct ProviderEntry {
    record: ProviderRecord,
    /// Admission order — assigned once, on first admission, and PRESERVED across refreshes so
    /// republishing (how an honest holder stays findable) never costs a holder its establishment.
    admitted_seq: u64,
}

/// One content key in a [`ProviderSnapshot`]: the key, and how many live providers this node knows
/// for it. Deliberately carries NO provider identity — see [`ProviderStore::snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSnapshotEntry {
    /// The 64-hex content key.
    pub content_key: String,
    /// How many non-expired providers this node holds a record for.
    pub providers: usize,
}

/// A bounded, aggregated view of a node's provider store — see [`ProviderStore::snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSnapshot {
    /// Content keys with at least one live provider, sorted by key, capped at the requested maximum.
    pub entries: Vec<ProviderSnapshotEntry>,
    /// How many keys had a live provider BEFORE the cap was applied, so a consumer can report
    /// "showing N of M" rather than presenting a truncated view as complete.
    pub total_keys: usize,
    /// Whether the cap dropped entries.
    pub truncated: bool,
}

/// A node's local provider records + the set of content keys it announces itself.
#[derive(Debug)]
pub struct ProviderStore {
    /// content_key (64-hex) → provider_peer_id (64-hex) → entry.
    by_key: HashMap<String, HashMap<String, ProviderEntry>>,
    /// content keys (64-hex) this node holds + announces (for republish).
    announced: HashSet<String>,
    /// Admission-control bounds enforced by [`put`](Self::put).
    limits: ProviderStoreLimits,
    /// Monotonic source of [`ProviderEntry::admitted_seq`] — the next admission's ordinal.
    next_admitted_seq: u64,
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
            next_admitted_seq: 0,
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
    ///   one is evicted to make room — chosen by [`eviction_victim`], which reserves the key's
    ///   longest-established slots so a Sybil flood cannot displace an incumbent holder (#1434);
    /// - if the store is at [`ProviderStoreLimits::max_total_records`] globally, the new record is
    ///   rejected — [`PutOutcome::RejectedOverCapacity`] — rather than evicting another key's
    ///   records (which would let one attacker's flood evict another key's legitimate holders).
    ///
    /// [`eviction_victim`]: Self::eviction_victim
    pub fn put(&mut self, record: ProviderRecord) -> PutOutcome {
        self.put_at(record, crate::clock::now_secs())
    }

    /// [`put`](Self::put) with an explicit `now` (absolute Unix seconds) — the same admission
    /// decision, taking the caller's clock instead of reading the system one.
    ///
    /// `now` is what lets eviction tell a LIVE provider from an expired one, which is the difference
    /// between reclaiming a dead slot and evicting a real holder (see [`eviction_victim`]). A caller
    /// that already has a timestamp — the serving side computes one for the TTL clamp — SHOULD pass
    /// it, so the clamp and the admission decision are made against a single instant.
    ///
    /// [`eviction_victim`]: Self::eviction_victim
    pub fn put_at(&mut self, record: ProviderRecord, now: u64) -> PutOutcome {
        if let Some(existing) = self
            .by_key
            .get_mut(&record.content_key)
            .and_then(|providers| providers.get_mut(&record.provider_peer_id))
        {
            // Refresh: same provider, same key. It does not grow the store, so no capacity check —
            // and `admitted_seq` is deliberately left untouched (see [`ProviderEntry`]).
            existing.record = record;
            return PutOutcome::Accepted;
        }

        // Global ceiling check FIRST, before touching this key's entry, so a rejected record never
        // leaves a stray empty entry behind and so the check reads the true pre-insert total (not
        // skewed by an entry we are about to create).
        if self.len() >= self.limits.max_total_records {
            return PutOutcome::RejectedOverCapacity;
        }
        if let Some(providers) = self.by_key.get_mut(&record.content_key) {
            if providers.len() >= self.limits.max_providers_per_key {
                let Some(evict_id) =
                    Self::eviction_victim(providers, self.limits.max_providers_per_key, now)
                else {
                    // Every slot is established — admitting would breach the per-key cap, so the
                    // cap wins. Unreachable while the floor stays a strict fraction of the cap; kept
                    // as the explicit guard that the per-key invariant is never violated.
                    return PutOutcome::RejectedOverCapacity;
                };
                providers.remove(&evict_id);
            }
        }

        let admitted_seq = self.next_admitted_seq;
        self.next_admitted_seq += 1;
        self.by_key
            .entry(record.content_key.clone())
            .or_default()
            .insert(
                record.provider_peer_id.clone(),
                ProviderEntry {
                    record,
                    admitted_seq,
                },
            );
        PutOutcome::Accepted
    }

    /// Pick which of a full key's providers to evict, or `None` if none may be.
    ///
    /// **Why not simply soonest-to-expire (#1434).** Every inbound record has its `expires_at`
    /// clamped to `now + provider_ttl` at admission, so a provider that announces LATER necessarily
    /// carries a strictly LATER expiry. Pure soonest-to-expire eviction therefore made the honest
    /// incumbent the deterministic victim of anyone announcing after it: `max_providers_per_key`
    /// Sybil identities — free, since a `ProviderRecord` is unsigned self-assertion — could evict
    /// the ONLY real holder of a capsule and replace it with peers that fail the fetch, making that
    /// content undiscoverable through this node. Repeated across the k-closest nodes that is
    /// network-wide censorship of a key.
    ///
    /// **The policy, in two steps.**
    ///
    /// 1. **An EXPIRED record is the victim, wherever it sits — the floor included.** A record past
    ///    its `expires_at` is already invisible to [`get`](Self::get) and merely awaits the next
    ///    [`gc`](Self::gc), so reclaiming its slot costs nothing. Liveness therefore OUTRANKS
    ///    establishment. Were the floor allowed to protect a dead record, a live holder in the churn
    ///    zone would be evicted to keep a corpse — and that needs no attacker, because a node's GC
    ///    tick is coarser than the provider TTL: a key whose earliest providers have gone offline
    ///    (ordinary churn — shutdown, cache eviction) carries expired records inside its floor for a
    ///    whole GC period, and during that window every new announcement would evict a LIVE
    ///    provider, making a capsule LESS discoverable the more holders announce it. That is the
    ///    replication flywheel running backwards.
    /// 2. **Otherwise every record is live, and the establishment floor governs.** The
    ///    `max_providers_per_key / ESTABLISHED_FLOOR_DIVISOR` longest-established providers are
    ///    RESERVED; the victim is the soonest-to-expire among the newest slots (the churn zone),
    ///    that being the least valuable LIVE record to keep. This mirrors the k-bucket policy this
    ///    crate already applies to contacts — long-lived entries resist eviction attacks — and
    ///    bounds what a flood can achieve: an attacker may churn the unreserved slots at will but
    ///    cannot displace an ALREADY-ESTABLISHED holder, however many identities it spends or
    ///    however it times its expiries.
    ///
    /// Ties break on `admitted_seq` in both steps, so the choice is deterministic rather than
    /// hash-order dependent.
    ///
    /// **Residual, NOT closed here.** The floor protects an incumbent, not a latecomer: an attacker
    /// that establishes BEFORE the honest holder retains the full pre-#1434 eviction primitive, and
    /// because this store is in-memory only, every restart resets the floor to first-come. See the
    /// caveat in `SPEC.md` §6.3/§14 — closing it needs signed provider records (#1573).
    fn eviction_victim(
        providers: &HashMap<String, ProviderEntry>,
        max_providers_per_key: usize,
        now: u64,
    ) -> Option<String> {
        let mut by_establishment: Vec<&ProviderEntry> = providers.values().collect();
        by_establishment.sort_by_key(|e| e.admitted_seq);

        // Step 1 — reclaim a dead slot in preference to ANY live record, the floor included.
        let expired = by_establishment
            .iter()
            .filter(|e| e.record.is_expired(now))
            .min_by_key(|e| (e.record.expires_at, e.admitted_seq));
        if let Some(dead) = expired {
            return Some(dead.record.provider_peer_id.clone());
        }

        // Step 2 — every record is live: reserve the established floor, evict inside the churn zone.
        let established_floor = max_providers_per_key / ESTABLISHED_FLOOR_DIVISOR;
        by_establishment
            .into_iter()
            .skip(established_floor)
            .min_by_key(|e| (e.record.expires_at, e.admitted_seq))
            .map(|e| e.record.provider_peer_id.clone())
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
                    .map(|e| &e.record)
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
            providers.retain(|_pid, e| !e.record.is_expired(now));
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

    /// A bounded, AGGREGATED view of what this node holds in its DHT provider store — content keys
    /// and how many live providers each has, with no provider identities (dig_ecosystem #1935).
    ///
    /// This is what lets the relay show the network's content layer without joining the DHT: a
    /// Kademlia node stores records for keys near its OWN `peer_id`, so these are records about
    /// MANY OTHER peers' content, not a self-report of what this node caches. The union across
    /// several nodes is a broad slice of the real DHT.
    ///
    /// # Why counts and not identities
    ///
    /// A provider record IS a `(peer_id, content_key)` pair — exactly the linkage the relay's `/map`
    /// refuses to publish (its tests assert no `peer_id` and no raw IP ever appear). Returning
    /// counts keeps that contract intact rather than carving an exception into it. A caller that
    /// genuinely needs identities can still use [`get`](Self::get) per key.
    ///
    /// Expired records are excluded as of `now`, so the counts match what [`get`](Self::get) would
    /// return rather than including records the store has not GC'd yet.
    ///
    /// `max_keys` bounds the result: the store is attacker-influenced (any peer can announce), so an
    /// unbounded snapshot would let a Sybil dictate the response size. When the cap truncates,
    /// [`ProviderSnapshot::truncated`] is set and `total_keys` still reports the true total, so a
    /// consumer can say "showing N of M" instead of silently presenting a partial view as complete.
    /// `max_keys == 0` yields no entries but still reports `total_keys`.
    pub fn snapshot(&self, now: u64, max_keys: usize) -> ProviderSnapshot {
        let mut entries: Vec<ProviderSnapshotEntry> = self
            .by_key
            .iter()
            .filter_map(|(content_key, providers)| {
                let live = providers
                    .values()
                    .filter(|e| !e.record.is_expired(now))
                    .count();
                // A key whose every record has expired is not part of the view.
                (live > 0).then(|| ProviderSnapshotEntry {
                    content_key: content_key.clone(),
                    providers: live,
                })
            })
            .collect();

        // Deterministic order so the same store yields the same snapshot, and so truncation takes a
        // stable subset rather than an arbitrary one from HashMap iteration order.
        entries.sort_by(|a, b| a.content_key.cmp(&b.content_key));

        let total_keys = entries.len();
        let truncated = total_keys > max_keys;
        entries.truncate(max_keys);

        ProviderSnapshot {
            entries,
            total_keys,
            truncated,
        }
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

    /// The instant the eviction tests reason at. Every `expires_at` they use is in the FUTURE
    /// relative to this, so their records are LIVE and the assertions are about establishment —
    /// not about a record that had silently already expired.
    const NOW: u64 = 0;

    fn rec(content: &Key, provider: u8, expires_at: u64) -> ProviderRecord {
        ProviderRecord::new(
            content,
            &PeerId::from_bytes([provider; 32]),
            vec![CandidateAddr::direct("h", 9444)],
            expires_at,
        )
    }

    // -- #1935: the aggregated snapshot the relay's /dht endpoint is built on -----------------

    #[test]
    fn snapshot_counts_live_providers_per_key_and_never_leaks_an_identity() {
        // The privacy property is the point: a provider record IS (peer_id, content_key), which is
        // exactly the linkage the relay's /map refuses to publish. The snapshot must carry counts.
        let mut s = ProviderStore::new();
        let k1 = Key::from_bytes([1u8; 32]);
        let k2 = Key::from_bytes([2u8; 32]);
        s.put(rec(&k1, 10, NOW + 100));
        s.put(rec(&k1, 11, NOW + 100));
        s.put(rec(&k2, 12, NOW + 100));

        let snap = s.snapshot(NOW, 100);

        assert_eq!(snap.total_keys, 2);
        assert!(!snap.truncated);
        let counts: Vec<usize> = snap.entries.iter().map(|e| e.providers).collect();
        assert_eq!(counts, vec![2, 1], "two providers for k1, one for k2");

        // Nothing in the snapshot may be a provider peer_id. Assert structurally rather than by
        // string-matching, so the property cannot rot when a field is added.
        let rendered = format!("{snap:?}");
        for provider in [10u8, 11, 12] {
            let pid = PeerId::from_bytes([provider; 32]).to_hex();
            assert!(
                !rendered.contains(&pid),
                "provider identity {pid} must never appear in a snapshot"
            );
        }
    }

    #[test]
    fn snapshot_excludes_expired_records_and_keys_left_with_none() {
        // Must agree with `get`, which also filters on expiry — otherwise the relay would advertise
        // providers the node would not actually return.
        let mut s = ProviderStore::new();
        let live = Key::from_bytes([1u8; 32]);
        let dead = Key::from_bytes([2u8; 32]);
        s.put(rec(&live, 10, NOW + 100));
        s.put(rec(&dead, 11, NOW + 1));

        let snap = s.snapshot(NOW + 50, 100);

        assert_eq!(
            snap.total_keys, 1,
            "the fully-expired key drops out entirely"
        );
        assert_eq!(snap.entries[0].providers, 1);
        assert_eq!(
            snap.entries[0].content_key,
            live.to_hex(),
            "the surviving key is the live one"
        );
    }

    #[test]
    fn snapshot_is_bounded_and_reports_the_true_total_when_truncated() {
        // The store is attacker-influenced — any peer can announce — so an unbounded snapshot would
        // let a Sybil dictate the response size. Truncation must be VISIBLE, not silent.
        let mut s = ProviderStore::new();
        for i in 0..10u8 {
            s.put(rec(&Key::from_bytes([i; 32]), 100 + i, NOW + 100));
        }

        let snap = s.snapshot(NOW, 3);

        assert_eq!(snap.entries.len(), 3);
        assert!(snap.truncated);
        assert_eq!(snap.total_keys, 10, "the true total survives truncation");
    }

    #[test]
    fn snapshot_is_deterministic_so_truncation_takes_a_stable_subset() {
        // HashMap iteration order is arbitrary; without sorting, two calls could return different
        // subsets and a consumer polling the relay would see content flicker in and out.
        let mut s = ProviderStore::new();
        for i in 0..8u8 {
            s.put(rec(&Key::from_bytes([i; 32]), 100 + i, NOW + 100));
        }
        assert_eq!(s.snapshot(NOW, 4), s.snapshot(NOW, 4));
    }

    #[test]
    fn a_zero_cap_yields_no_entries_but_still_reports_the_total() {
        let mut s = ProviderStore::new();
        s.put(rec(&Key::from_bytes([1u8; 32]), 10, NOW + 100));
        let snap = s.snapshot(NOW, 0);
        assert!(snap.entries.is_empty());
        assert!(snap.truncated);
        assert_eq!(snap.total_keys, 1);
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
    fn per_key_cap_evicts_soonest_to_expire_within_the_churn_zone() {
        // One malicious/heavy peer announcing many DISTINCT providers for the SAME content key must
        // not grow that key's provider set past `max_providers_per_key` — the audit's "no cap on
        // providers-per-key" finding.
        // Cap 4 → the two longest-established slots are reserved (#1434), so the eviction choice
        // is made among the two newest — the churn zone. Within that zone the soonest-to-expire
        // record is still the least valuable one to keep.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 4,
            max_total_records: 1000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        assert_eq!(s.put_at(rec(&key, 1, 100), NOW), PutOutcome::Accepted); // established
        assert_eq!(s.put_at(rec(&key, 2, 200), NOW), PutOutcome::Accepted); // established
        assert_eq!(s.put_at(rec(&key, 3, 900), NOW), PutOutcome::Accepted); // churn zone
        assert_eq!(s.put_at(rec(&key, 4, 800), NOW), PutOutcome::Accepted); // churn zone, expires sooner
        assert_eq!(s.put_at(rec(&key, 5, 999), NOW), PutOutcome::Accepted);
        assert_eq!(
            s.get(&key.to_hex(), 0).len(),
            4,
            "per-key cap must not be exceeded"
        );
        assert!(
            !live_provider_ids(&s, &key).contains(&PeerId::from_bytes([4u8; 32]).to_hex()),
            "the soonest-to-expire record in the churn zone must be the one evicted"
        );
    }

    /// The live provider peer_ids for `key` (order-independent membership assertions).
    fn live_provider_ids(s: &ProviderStore, key: &Key) -> std::collections::HashSet<String> {
        s.get(&key.to_hex(), 0)
            .into_iter()
            .map(|r| r.provider_peer_id)
            .collect()
    }

    // ---- Sybil-resistant eviction (#1434) ----

    #[test]
    fn sustained_sybil_flood_cannot_evict_the_lone_established_holder() {
        // #1434: every record clamps its expiry to `now + provider_ttl` at put time, so an attacker
        // who announces LATER always holds a strictly-later `expires_at` than an honest incumbent.
        // Under pure soonest-to-expire eviction that made the honest holder the deterministic
        // victim, and 20 Sybil identities could make the only real holder of a capsule
        // undiscoverable at this node — content-discovery censorship. Stated over the CLASS: no
        // volume of later-expiring newcomers may evict a provider inside the established floor.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 20,
            max_total_records: 100_000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        let honest = PeerId::from_bytes([1u8; 32]).to_hex();
        assert_eq!(s.put_at(rec(&key, 1, 100), NOW), PutOutcome::Accepted);

        // A sustained flood of distinct Sybil providers, each expiring strictly later than the last
        // — the worst case for expiry-ordered eviction.
        for i in 0..500u64 {
            let sybil = ProviderRecord::new(
                &key,
                &PeerId::from_bytes(sybil_id(i)),
                vec![CandidateAddr::direct("h", 9444)],
                1_000 + i,
            );
            s.put_at(sybil, NOW);
        }

        assert!(
            live_provider_ids(&s, &key).contains(&honest),
            "the lone honest holder must survive a sustained Sybil flood"
        );
        assert_eq!(
            s.get(&key.to_hex(), 0).len(),
            20,
            "the per-key cap still bounds the set"
        );
    }

    #[test]
    fn established_floor_protects_the_earliest_admitted_providers() {
        // The one-off variant: exactly one provider beyond the cap. Eviction must fall inside the
        // churn zone and never touch the reserved, longest-established slots.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 4,
            max_total_records: 1000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        // Established slots deliberately hold the SOONEST expiries — under the old policy they
        // would have been evicted first.
        s.put_at(rec(&key, 1, 10), NOW);
        s.put_at(rec(&key, 2, 20), NOW);
        s.put_at(rec(&key, 3, 900), NOW);
        s.put_at(rec(&key, 4, 800), NOW);
        s.put_at(rec(&key, 5, 999), NOW);

        let live = live_provider_ids(&s, &key);
        assert!(
            live.contains(&PeerId::from_bytes([1u8; 32]).to_hex()),
            "the first-admitted provider is inside the established floor"
        );
        assert!(
            live.contains(&PeerId::from_bytes([2u8; 32]).to_hex()),
            "the second-admitted provider is inside the established floor"
        );
    }

    #[test]
    fn republish_does_not_reset_a_holders_establishment() {
        // A holder stays findable by republishing before its TTL elapses. If a refresh reset the
        // record's establishment, republishing — the very act that keeps an honest holder alive —
        // would drop it into the churn zone and hand the attacker the eviction it wanted.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 4,
            max_total_records: 1000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        let honest = PeerId::from_bytes([1u8; 32]).to_hex();
        s.put_at(rec(&key, 1, 100), NOW);
        for i in 0..3u64 {
            s.put_at(rec(&key, 10 + i as u8, 500 + i), NOW);
        }
        s.put_at(rec(&key, 1, 5_000), NOW); // the honest holder republishes
        for i in 0..50u64 {
            s.put_at(
                ProviderRecord::new(
                    &key,
                    &PeerId::from_bytes(sybil_id(i)),
                    vec![CandidateAddr::direct("h", 9444)],
                    9_000 + i,
                ),
                NOW,
            );
        }
        assert!(
            live_provider_ids(&s, &key).contains(&honest),
            "a republished record keeps its establishment"
        );
    }

    // ---- Liveness outranks establishment (#1434 follow-up) ----

    #[test]
    fn an_expired_record_in_the_floor_is_evicted_before_a_live_one() {
        // The pre-#1434 policy evicted the soonest-to-expire record, so an EXPIRED record was always
        // the first victim. The establishment floor must not invert that: a dead record inside the
        // reserved floor cannot outrank a live provider in the churn zone. Without a liveness check
        // this needs NO attacker — a node's GC tick is coarser than the provider TTL, so whenever the
        // earliest-admitted half of a key goes offline, every new announcement for that key evicts a
        // LIVE holder and announcing more holders makes the capsule LESS discoverable.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 4,
            max_total_records: 1000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        let now = 10_000;
        // The reserved floor (seq 0, 1) is long expired...
        s.put_at(rec(&key, 1, 100), now);
        s.put_at(rec(&key, 2, 200), now);
        // ...while the churn zone (seq 2, 3) holds two LIVE honest providers.
        s.put_at(rec(&key, 3, now + 5_000), now);
        s.put_at(rec(&key, 4, now + 6_000), now);

        s.put_at(rec(&key, 5, now + 7_000), now);

        let live = live_provider_ids_at(&s, &key, now);
        assert!(
            live.contains(&PeerId::from_bytes([3u8; 32]).to_hex())
                && live.contains(&PeerId::from_bytes([4u8; 32]).to_hex()),
            "both LIVE providers must survive; an expired record in the floor is the victim"
        );
    }

    #[test]
    fn one_expired_record_anywhere_is_the_victim_before_any_live_record() {
        // The one-off variant: exactly ONE expired record, sitting inside the reserved floor, with
        // every other slot live. It must still be the one evicted.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 4,
            max_total_records: 1000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        let now = 10_000;
        s.put_at(rec(&key, 1, 100), now); // expired, seq 0 → inside the floor
        s.put_at(rec(&key, 2, now + 1_000), now);
        s.put_at(rec(&key, 3, now + 2_000), now);
        s.put_at(rec(&key, 4, now + 3_000), now);

        s.put_at(rec(&key, 5, now + 4_000), now);

        assert_eq!(
            live_provider_ids_at(&s, &key, now).len(),
            4,
            "reclaiming the dead slot leaves every live provider intact"
        );
    }

    #[test]
    fn the_floor_still_protects_an_established_holder_when_every_record_is_live() {
        // Liveness must take precedence WITHOUT weakening #1434: with no dead slot to reclaim, the
        // establishment floor governs again and a sustained flood cannot displace the incumbent.
        let mut s = ProviderStore::with_limits(ProviderStoreLimits {
            max_providers_per_key: 20,
            max_total_records: 100_000,
        });
        let key = Key::from_bytes([0xAA; 32]);
        let now = 10_000;
        let honest = PeerId::from_bytes([1u8; 32]).to_hex();
        s.put_at(rec(&key, 1, now + 1_000), now);
        for i in 0..500u64 {
            s.put_at(
                ProviderRecord::new(
                    &key,
                    &PeerId::from_bytes(sybil_id(i)),
                    vec![CandidateAddr::direct("h", 9444)],
                    now + 2_000 + i,
                ),
                now,
            );
        }
        assert!(
            live_provider_ids_at(&s, &key, now).contains(&honest),
            "an all-live key keeps the #1434 protection"
        );
    }

    #[test]
    fn put_delegates_to_put_at_with_the_wall_clock() {
        // `put` is the compatibility wrapper (its signature is public API): same admission decision,
        // with `now` read from the system clock.
        let mut wall = ProviderStore::new();
        let key = Key::from_bytes([0xAA; 32]);
        assert_eq!(wall.put(rec(&key, 1, u64::MAX)), PutOutcome::Accepted);
        assert_eq!(wall.len(), 1);
    }

    /// The live provider peer_ids for `key` as of `now`.
    fn live_provider_ids_at(
        s: &ProviderStore,
        key: &Key,
        now: u64,
    ) -> std::collections::HashSet<String> {
        s.get(&key.to_hex(), now)
            .into_iter()
            .map(|r| r.provider_peer_id)
            .collect()
    }

    /// A distinct Sybil peer_id per index (varying the high bytes so ids stay distinct past 255).
    fn sybil_id(i: u64) -> [u8; 32] {
        let mut b = [0xEE; 32];
        b[0..8].copy_from_slice(&i.to_be_bytes());
        b
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
