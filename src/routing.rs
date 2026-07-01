//! The Kademlia routing table: 256 k-buckets of [`Contact`]s, keyed by XOR-distance
//! [`bucket_index`](crate::key::Distance::bucket_index) from this node.
//!
//! A node keeps, for each possible shared-prefix length with its own id, a bucket of up to `k`
//! contacts it knows at that distance. Buckets are **least-recently-seen ordered**: a fresh contact
//! goes to the back (most-recently-seen); when a full bucket gets a new contact, Kademlia keeps the
//! **existing** least-recently-seen node if it is still alive (long-lived nodes are the most
//! valuable — they resist eviction attacks) and drops the newcomer, only replacing the LRS node once
//! it is confirmed dead. This module implements that policy with an explicit
//! [`InsertOutcome`] so the service can ping-and-replace.
//!
//! [`closest`](RoutingTable::closest) returns the `k` contacts nearest a target across all buckets —
//! the seed set for an iterative lookup.

use serde::{Deserialize, Serialize};

use dig_nat::PeerId;

use crate::key::Key;
use crate::record::CandidateAddr;

/// A known peer in the routing table / on the wire: its `peer_id` (64-hex) and candidate addresses.
///
/// This is the DHT's contact record and the `find_node` / `find_providers.closer` wire shape. The
/// `addresses` are the same `{ host, port, kind }` candidates as an L7 `dig.getPeers` peer, so a
/// contact converts directly to a `dig_nat::PeerTarget`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// The peer's identity — 64-hex `peer_id = SHA-256(SPKI DER)`.
    pub peer_id: String,
    /// Candidate addresses to reach the peer (most-direct-first is not guaranteed — consumer sorts).
    pub addresses: Vec<CandidateAddr>,
}

impl Contact {
    /// Build a contact from a decoded [`PeerId`] and its candidate addresses.
    pub fn new(peer_id: &PeerId, addresses: Vec<CandidateAddr>) -> Self {
        Contact {
            peer_id: peer_id.to_hex(),
            addresses,
        }
    }

    /// The peer's [`PeerId`] decoded from the 64-hex field, or `None` if malformed.
    pub fn peer_id(&self) -> Option<PeerId> {
        PeerId::from_hex(&self.peer_id)
    }

    /// This contact's key in the DHT keyspace (its `peer_id`), or `None` if the hex is malformed.
    pub fn key(&self) -> Option<Key> {
        self.peer_id().as_ref().map(Key::from_peer_id)
    }

    /// The most-direct dialable candidate address, if any.
    pub fn best_address(&self) -> Option<&CandidateAddr> {
        self.addresses
            .iter()
            .filter(|a| a.kind.is_dialable())
            .min_by_key(|a| a.kind.rank())
    }
}

/// What happened when a contact was offered to a full bucket — drives the service's
/// ping-and-replace maintenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The contact was inserted (bucket had room, or it was already present and got refreshed).
    Inserted,
    /// The bucket is full. The `candidate` was NOT inserted; the caller should ping `lru` (the
    /// least-recently-seen contact) and, if it fails to respond, call
    /// [`RoutingTable::replace`] to evict it for the candidate.
    Full {
        /// The least-recently-seen contact currently holding the contested slot.
        lru: Contact,
    },
}

/// One k-bucket: up to `capacity` (= `k`) contacts, least-recently-seen at the FRONT, most-recently
/// seen at the BACK.
#[derive(Debug, Clone)]
struct KBucket {
    contacts: Vec<Contact>,
    capacity: usize,
}

impl KBucket {
    fn new(capacity: usize) -> Self {
        KBucket {
            contacts: Vec::new(),
            capacity,
        }
    }

    /// Offer `contact` to the bucket (LRS-ordered):
    /// - already present → move to the back (mark most-recently-seen) → [`InsertOutcome::Inserted`].
    /// - room available → push to the back → [`InsertOutcome::Inserted`].
    /// - full → [`InsertOutcome::Full`] naming the LRS contact for the caller to ping-and-replace.
    fn offer(&mut self, contact: Contact) -> InsertOutcome {
        if let Some(pos) = self
            .contacts
            .iter()
            .position(|c| c.peer_id == contact.peer_id)
        {
            // Seen again: refresh recency by moving to the back, updating addresses.
            self.contacts.remove(pos);
            self.contacts.push(contact);
            return InsertOutcome::Inserted;
        }
        if self.contacts.len() < self.capacity {
            self.contacts.push(contact);
            return InsertOutcome::Inserted;
        }
        // Full — the least-recently-seen contact is at the front.
        InsertOutcome::Full {
            lru: self.contacts[0].clone(),
        }
    }

    /// Evict `lru_peer_id` (if it is still the front contact) and insert `candidate` at the back.
    /// No-op returning `false` if the front contact changed since the [`InsertOutcome::Full`] (the
    /// LRU responded to a ping and got refreshed, or the bucket changed) — the candidate is dropped.
    fn replace(&mut self, lru_peer_id: &str, candidate: Contact) -> bool {
        match self.contacts.first() {
            Some(front) if front.peer_id == lru_peer_id => {
                self.contacts.remove(0);
                self.contacts.push(candidate);
                true
            }
            _ => false,
        }
    }

    fn remove(&mut self, peer_id: &str) -> bool {
        if let Some(pos) = self.contacts.iter().position(|c| c.peer_id == peer_id) {
            self.contacts.remove(pos);
            true
        } else {
            false
        }
    }
}

/// The routing table: 256 buckets keyed by shared-prefix length with `local_key`.
///
/// Bucket `i` holds contacts whose XOR distance from this node has
/// [`bucket_index`](crate::key::Distance::bucket_index) `i` — i.e. contacts that share exactly
/// `255 - i` leading bits with this node. Contacts closer in the tree land in low-index buckets.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_key: Key,
    buckets: Vec<KBucket>,
    k: usize,
}

impl RoutingTable {
    /// A new empty table for the node whose id is `local_id`, with bucket size `k`.
    pub fn new(local_id: &PeerId, k: usize) -> Self {
        RoutingTable {
            local_key: Key::from_peer_id(local_id),
            buckets: (0..256).map(|_| KBucket::new(k)).collect(),
            k,
        }
    }

    /// This node's own key.
    pub fn local_key(&self) -> Key {
        self.local_key
    }

    /// The bucket index a contact with key `key` falls in (`None` for our own key).
    fn bucket_for(&self, key: &Key) -> Option<usize> {
        self.local_key.distance(key).bucket_index()
    }

    /// Offer a contact to the table. A contact whose key equals ours is ignored
    /// ([`InsertOutcome::Inserted`], a no-op). Otherwise routes to the right bucket and applies the
    /// LRS policy — see [`InsertOutcome`].
    pub fn insert(&mut self, contact: Contact) -> InsertOutcome {
        let Some(key) = contact.key() else {
            // Malformed peer_id — reject silently as "inserted" (nothing to do; never a Full).
            return InsertOutcome::Inserted;
        };
        match self.bucket_for(&key) {
            None => InsertOutcome::Inserted, // our own id; never stored
            Some(idx) => self.buckets[idx].offer(contact),
        }
    }

    /// Complete a ping-and-replace: after an [`InsertOutcome::Full`] whose `lru` did not respond,
    /// evict `lru` and insert `candidate`. Returns whether the eviction happened (false if the LRU
    /// slot changed in the meantime — then `candidate` is dropped, per Kademlia).
    pub fn replace(&mut self, lru: &Contact, candidate: Contact) -> bool {
        let Some(key) = candidate.key() else {
            return false;
        };
        match self.bucket_for(&key) {
            None => false,
            Some(idx) => self.buckets[idx].replace(&lru.peer_id, candidate),
        }
    }

    /// Remove a contact (e.g. a peer that failed a liveness ping). Returns whether it was present.
    pub fn remove(&mut self, peer_id: &str) -> bool {
        let Some(pid) = PeerId::from_hex(peer_id) else {
            return false;
        };
        match self.bucket_for(&Key::from_peer_id(&pid)) {
            None => false,
            Some(idx) => self.buckets[idx].remove(peer_id),
        }
    }

    /// The `k` contacts closest (XOR distance) to `target` across all buckets, closest-first.
    ///
    /// This is the seed set for an iterative lookup and the answer to a `find_node`. It scans all
    /// buckets (256 × ≤ k contacts) and returns the `k` with the smallest distance to `target`.
    pub fn closest(&self, target: &Key) -> Vec<Contact> {
        let mut all: Vec<(Contact, crate::key::Distance)> = self
            .buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .filter_map(|c| c.key().map(|k| (c.clone(), target.distance(&k))))
            .collect();
        all.sort_by_key(|(_, dist)| *dist);
        all.into_iter().take(self.k).map(|(c, _)| c).collect()
    }

    /// Total contacts stored across all buckets (diagnostics / tests).
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.contacts.len()).sum()
    }

    /// Whether the table holds no contacts.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Indices of buckets that currently hold at least one contact (used by bucket-refresh to focus
    /// on populated regions; empty buckets far from the node are never realistically filled).
    pub fn non_empty_bucket_indices(&self) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| !b.contacts.is_empty())
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::CandidateAddr;

    fn pid(bytes: [u8; 32]) -> PeerId {
        PeerId::from_bytes(bytes)
    }

    fn contact(bytes: [u8; 32]) -> Contact {
        Contact::new(&pid(bytes), vec![CandidateAddr::direct("h", 1)])
    }

    fn local() -> PeerId {
        pid([0u8; 32])
    }

    #[test]
    fn insert_and_len() {
        let mut t = RoutingTable::new(&local(), 20);
        assert!(t.is_empty());
        let mut b = [0u8; 32];
        b[0] = 0x80;
        assert_eq!(t.insert(contact(b)), InsertOutcome::Inserted);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn own_id_is_never_stored() {
        let mut t = RoutingTable::new(&local(), 20);
        assert_eq!(t.insert(contact([0u8; 32])), InsertOutcome::Inserted);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn reinsert_refreshes_recency_not_count() {
        let mut t = RoutingTable::new(&local(), 20);
        let mut b = [0u8; 32];
        b[0] = 0x01;
        t.insert(contact(b));
        t.insert(contact(b));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn full_bucket_reports_lru_and_does_not_grow() {
        // Force all contacts into the SAME bucket (index 255 = MSB of distance set) with k = 2.
        // Keys with the top bit set share bucket 255 relative to local id 0.
        let mut t = RoutingTable::new(&local(), 2);
        let mut a = [0u8; 32];
        a[0] = 0x80;
        a[31] = 0x01;
        let mut b = [0u8; 32];
        b[0] = 0x80;
        b[31] = 0x02;
        let mut c = [0u8; 32];
        c[0] = 0x80;
        c[31] = 0x03;
        assert_eq!(t.insert(contact(a)), InsertOutcome::Inserted);
        assert_eq!(t.insert(contact(b)), InsertOutcome::Inserted);
        // Third into the full k=2 bucket → Full, naming the LRS (first inserted = `a`).
        match t.insert(contact(c)) {
            InsertOutcome::Full { lru } => assert_eq!(lru, contact(a)),
            other => panic!("expected Full, got {other:?}"),
        }
        assert_eq!(t.len(), 2, "full bucket must not grow past k");
    }

    #[test]
    fn replace_evicts_lru_for_candidate() {
        let mut t = RoutingTable::new(&local(), 2);
        let mut a = [0u8; 32];
        a[0] = 0x80;
        a[31] = 0x01;
        let mut b = [0u8; 32];
        b[0] = 0x80;
        b[31] = 0x02;
        let mut c = [0u8; 32];
        c[0] = 0x80;
        c[31] = 0x03;
        t.insert(contact(a));
        t.insert(contact(b));
        let lru = match t.insert(contact(c)) {
            InsertOutcome::Full { lru } => lru,
            other => panic!("expected Full, got {other:?}"),
        };
        // LRU `a` "did not respond" → replace with candidate `c`.
        assert!(t.replace(&lru, contact(c)));
        assert_eq!(t.len(), 2);
        // `a` gone, `c` present.
        let keys: Vec<String> = t
            .buckets
            .iter()
            .flat_map(|bk| bk.contacts.iter())
            .map(|x| x.peer_id.clone())
            .collect();
        assert!(!keys.contains(&contact(a).peer_id));
        assert!(keys.contains(&contact(c).peer_id));
    }

    #[test]
    fn replace_is_noop_if_lru_slot_changed() {
        let mut t = RoutingTable::new(&local(), 2);
        let mut a = [0u8; 32];
        a[0] = 0x80;
        a[31] = 0x01;
        let mut b = [0u8; 32];
        b[0] = 0x80;
        b[31] = 0x02;
        let mut c = [0u8; 32];
        c[0] = 0x80;
        c[31] = 0x03;
        t.insert(contact(a));
        t.insert(contact(b));
        let lru = match t.insert(contact(c)) {
            InsertOutcome::Full { lru } => lru,
            _ => unreachable!(),
        };
        // Simulate the LRU (`a`) responding to a ping → it is refreshed to the back.
        t.insert(contact(a));
        // Now the front is `b`, not `a`; replace(a, c) must be a no-op and drop `c`.
        assert!(!t.replace(&lru, contact(c)));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn remove_contact() {
        let mut t = RoutingTable::new(&local(), 20);
        let mut b = [0u8; 32];
        b[0] = 0x40;
        let c = contact(b);
        t.insert(c.clone());
        assert!(t.remove(&c.peer_id));
        assert!(!t.remove(&c.peer_id));
        assert!(t.is_empty());
    }

    #[test]
    fn closest_returns_k_sorted_by_distance() {
        let mut t = RoutingTable::new(&local(), 20);
        // Insert contacts at varied distances.
        for i in 1u8..=10 {
            let mut b = [0u8; 32];
            b[0] = i; // distinct top byte → distinct distance from local 0
            t.insert(contact(b));
        }
        let target = Key::from_bytes([0u8; 32]);
        let closest = t.closest(&target);
        assert_eq!(closest.len(), 10);
        // Verify ascending distance order.
        let dists: Vec<_> = closest
            .iter()
            .map(|c| target.distance(&c.key().unwrap()))
            .collect();
        for w in dists.windows(2) {
            assert!(w[0] <= w[1], "closest must be distance-sorted");
        }
    }

    #[test]
    fn closest_caps_at_k() {
        let mut t = RoutingTable::new(&local(), 3);
        for i in 1u8..=10 {
            let mut b = [0u8; 32];
            b[0] = i;
            t.insert(contact(b));
        }
        assert_eq!(t.closest(&Key::from_bytes([0u8; 32])).len(), 3);
    }

    #[test]
    fn non_empty_bucket_indices_tracks_population() {
        let mut t = RoutingTable::new(&local(), 20);
        assert!(t.non_empty_bucket_indices().is_empty());
        let mut b = [0u8; 32];
        b[0] = 0x80; // bucket 255
        t.insert(contact(b));
        assert_eq!(t.non_empty_bucket_indices(), vec![255]);
    }

    #[test]
    fn contact_key_and_best_address() {
        let c = contact({
            let mut b = [0u8; 32];
            b[0] = 0x22;
            b
        });
        assert!(c.key().is_some());
        assert_eq!(c.best_address().unwrap().kind, AddressKindDirect());
    }

    // Small helper to avoid importing AddressKind into every assert.
    #[allow(non_snake_case)]
    fn AddressKindDirect() -> crate::record::AddressKind {
        crate::record::AddressKind::Direct
    }
}
