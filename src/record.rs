//! [`ProviderRecord`] — the value the DHT stores: "peer P holds content C, reachable at these
//! addresses, until this expiry" — plus the [`CandidateAddr`] address shape it carries.
//!
//! A provider record is what `announce_provider` PUTs and `find_providers` returns. It binds a
//! **content key** (the [`ContentId`](crate::ContentId) hashed into the keyspace) to the
//! **`peer_id`** of a node that holds it, together with candidate addresses so the finder can then
//! open a dig-nat connection and fetch over the L7 peer RPC. Records are **TTL'd** (`expires_at`)
//! and **republished** by the holder before expiry, so stale providers age out of the DHT
//! automatically — a Kademlia provider record is soft state, not a permanent entry.
//!
//! The [`CandidateAddr`] `{ host, port, kind }` and the `kind` tokens are byte-compatible with the
//! L7 peer-network `dig.getPeers` `addresses[]` shape (§7), so a record's addresses drop straight
//! into a `PeerTarget` for [`dig_nat::connect`].

use serde::{Deserialize, Serialize};

use dig_nat::PeerId;

/// How a candidate address was learned — the L7 `dig.getPeers` `addresses[].kind` tokens (§7). The
/// lowercase serde spelling is the frozen wire form; the ordering is most-direct-first (a dialer
/// picks the lowest-rank dialable candidate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressKind {
    /// Advertised/observed directly reachable address (publicly routable or port-forwarded).
    Direct,
    /// A UPnP / NAT-PMP / PCP-mapped external address.
    Mapped,
    /// A STUN-discovered public reflexive address.
    Reflexive,
    /// Reachable through the relay (no direct candidate yet).
    Relay,
}

impl AddressKind {
    /// Most-direct-first rank (lower is more direct) — mirrors the dialer's candidate preference.
    pub fn rank(self) -> u8 {
        match self {
            AddressKind::Direct => 0,
            AddressKind::Mapped => 1,
            AddressKind::Reflexive => 2,
            AddressKind::Relay => 3,
        }
    }

    /// Whether an address of this kind can be dialed directly (everything but a bare relay marker).
    pub fn is_dialable(self) -> bool {
        !matches!(self, AddressKind::Relay)
    }
}

/// One candidate address for a provider: `{ host, port, kind }` (L7 `dig.getPeers` §7). The finder
/// dials these (most-direct-first) via [`dig_nat::connect`] to reach the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateAddr {
    /// IPv4/IPv6 literal or hostname.
    pub host: String,
    /// P2P port.
    pub port: u16,
    /// How this address was learned.
    pub kind: AddressKind,
}

impl CandidateAddr {
    /// A directly-dialable candidate (public / port-forwarded / discovered).
    pub fn direct(host: impl Into<String>, port: u16) -> Self {
        CandidateAddr {
            host: host.into(),
            port,
            kind: AddressKind::Direct,
        }
    }

    /// A relay-only marker (no direct address; reach via the relay / a brokered hole punch).
    pub fn relay_marker() -> Self {
        CandidateAddr {
            host: String::new(),
            port: 0,
            kind: AddressKind::Relay,
        }
    }
}

/// The DHT's stored value: peer `provider_peer_id` holds the content whose key is `content_key`,
/// reachable at `addresses`, until `expires_at`.
///
/// - `content_key` is the 64-hex [`Key`](crate::Key) the content id hashed to — the DHT stores by
///   key, not by the (larger, granularity-tagged) content id, so a record is compact and the store
///   is a pure key→providers map.
/// - `provider_peer_id` is the 64-hex `peer_id` of the holder; a finder builds a `PeerTarget` from
///   it plus `addresses` and connects via dig-nat.
/// - `expires_at` is absolute Unix seconds; a record past its expiry is treated as absent and GC'd.
///   The holder republishes (a fresh record with a new `expires_at`) before expiry to stay findable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRecord {
    /// The content key (64-hex) this record provides for — the [`Key`](crate::Key) a content id
    /// hashed to.
    pub content_key: String,
    /// The holder's `peer_id` (64-hex).
    pub provider_peer_id: String,
    /// Candidate addresses to reach the holder (most-direct-first is not guaranteed on the wire —
    /// the consumer sorts by [`AddressKind::rank`]).
    pub addresses: Vec<CandidateAddr>,
    /// Absolute expiry (Unix seconds). A record at/after this time is stale.
    pub expires_at: u64,
}

impl ProviderRecord {
    /// Build a record: peer `provider` holds `content_key`, reachable at `addresses`, until
    /// `expires_at` (absolute Unix seconds).
    pub fn new(
        content_key: &crate::key::Key,
        provider: &PeerId,
        addresses: Vec<CandidateAddr>,
        expires_at: u64,
    ) -> Self {
        ProviderRecord {
            content_key: content_key.to_hex(),
            provider_peer_id: provider.to_hex(),
            addresses,
            expires_at,
        }
    }

    /// The provider's `peer_id` decoded from the 64-hex field, or `None` if malformed.
    pub fn provider_peer_id(&self) -> Option<PeerId> {
        PeerId::from_hex(&self.provider_peer_id)
    }

    /// Whether this record is expired at `now` (Unix seconds) — stale records are dropped on read.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// The most-direct dialable candidate address, if any (the address a finder dials first).
    pub fn best_address(&self) -> Option<&CandidateAddr> {
        self.addresses
            .iter()
            .filter(|a| a.kind.is_dialable())
            .min_by_key(|a| a.kind.rank())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;

    fn pid(b: u8) -> PeerId {
        PeerId::from_bytes([b; 32])
    }

    #[test]
    fn record_round_trips_through_json() {
        let key = Key::from_bytes([0xAB; 32]);
        let rec = ProviderRecord::new(
            &key,
            &pid(0x07),
            vec![CandidateAddr::direct("203.0.113.7", 9444)],
            1_000,
        );
        let json = serde_json::to_string(&rec).unwrap();
        let back: ProviderRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
        assert_eq!(back.provider_peer_id().unwrap(), pid(0x07));
        assert_eq!(back.content_key, key.to_hex());
    }

    #[test]
    fn ttl_expiry() {
        let rec = ProviderRecord::new(&Key::from_bytes([0u8; 32]), &pid(1), vec![], 100);
        assert!(!rec.is_expired(99));
        assert!(rec.is_expired(100));
        assert!(rec.is_expired(101));
    }

    #[test]
    fn address_kind_wire_tokens_are_lowercase() {
        assert_eq!(
            serde_json::to_string(&AddressKind::Direct).unwrap(),
            "\"direct\""
        );
        assert_eq!(
            serde_json::to_string(&AddressKind::Reflexive).unwrap(),
            "\"reflexive\""
        );
        assert_eq!(
            serde_json::to_string(&AddressKind::Mapped).unwrap(),
            "\"mapped\""
        );
        assert_eq!(
            serde_json::to_string(&AddressKind::Relay).unwrap(),
            "\"relay\""
        );
    }

    #[test]
    fn best_address_prefers_most_direct() {
        let key = Key::from_bytes([0u8; 32]);
        let rec = ProviderRecord::new(
            &key,
            &pid(1),
            vec![
                CandidateAddr {
                    host: "r".into(),
                    port: 1,
                    kind: AddressKind::Reflexive,
                },
                CandidateAddr::direct("d", 2),
                CandidateAddr::relay_marker(),
            ],
            10,
        );
        assert_eq!(rec.best_address().unwrap().kind, AddressKind::Direct);
    }

    #[test]
    fn best_address_none_when_only_relay() {
        let key = Key::from_bytes([0u8; 32]);
        let rec = ProviderRecord::new(&key, &pid(1), vec![CandidateAddr::relay_marker()], 10);
        assert!(rec.best_address().is_none());
    }

    #[test]
    fn address_rank_ordering() {
        assert!(AddressKind::Direct.rank() < AddressKind::Mapped.rank());
        assert!(AddressKind::Mapped.rank() < AddressKind::Reflexive.rank());
        assert!(AddressKind::Reflexive.rank() < AddressKind::Relay.rank());
        assert!(!AddressKind::Relay.is_dialable());
        assert!(AddressKind::Direct.is_dialable());
    }
}
