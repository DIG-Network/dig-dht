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

use std::net::{IpAddr, SocketAddr};

use dig_ip::Family;
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

    /// The address-family half of the sort key, derived from [`dig_ip::Family`] — the ecosystem's
    /// single source of truth for the IPv6-first / IPv4-fallback rule (CLAUDE.md §5.2):
    ///
    /// - `0` — a genuine IPv6 literal (tried first);
    /// - `1` — an IPv4 literal, INCLUDING an IPv4-mapped IPv6 address, which [`Family::of`]
    ///   correctly classifies as V4 because it is IPv4 reachability (the fallback);
    /// - `2` — a host that is not an IP literal at all. A DHT candidate is an *observed* socket
    ///   address, so a non-literal is a malformed or hostname-bearing record whose reachability this
    ///   crate cannot classify and does not resolve; it must never outrank a usable IPv4 literal.
    ///
    /// Deriving the family here, rather than hand-rolling an `is_ipv6` check, keeps dig-dht from
    /// drifting off the canonical contract.
    fn family_rank(&self) -> u8 {
        let family = self
            .host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| Family::of(&SocketAddr::new(ip, self.port)));
        match family {
            Some(Family::V6) => 0,
            Some(Family::V4) => 1,
            None => 2,
        }
    }

    /// The identity of the ENDPOINT this candidate names, for deduplication: the parsed address in
    /// canonical form plus the port, falling back to the raw host text when it is not an IP literal.
    ///
    /// Deduplicating on the raw `host` string would treat one address spelled several ways as several
    /// dial targets — `2001:db8::1`, `2001:0db8::1`, `2001:db8:0:0:0:0:0:1` and `2001:DB8::1` are the
    /// same host — which lets a padded record consume every slot of the dial set with a single
    /// address. Parsing first collapses those spellings, and an IPv4-mapped IPv6 literal is reduced to
    /// its IPv4 form so `::ffff:a.b.c.d` and `a.b.c.d` are recognised as one endpoint (consistent with
    /// [`Family::of`] classifying both as IPv4 reachability).
    fn dial_identity(&self) -> (String, u16) {
        let host = match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V6(v6)) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6))
                .to_string(),
            Ok(ip) => ip.to_string(),
            Err(_) => self.host.clone(),
        };
        (host, self.port)
    }

    /// Whether this candidate is a genuine IPv6 literal — the tier that is tried FIRST and, being
    /// the preferred tier, the one that can crowd every other out of a capped dial set.
    fn is_ipv6_literal(&self) -> bool {
        self.family_rank() == 0
    }

    /// Sort key for IPv6-first, then most-direct-first ordering: `(family_rank, kind_rank)`. The
    /// family half comes from [`dig_ip::Family`] (see [`family_rank`](Self::family_rank)); the
    /// dht-specific directness tiebreak stays [`AddressKind::rank`], so within one family the most
    /// direct candidate sorts first.
    fn family_then_kind_rank(&self) -> (u8, u8) {
        (self.family_rank(), self.kind.rank())
    }
}

/// Sort `addresses` **IPv6-first, then by [`AddressKind::rank`]** — the ecosystem-wide IPv6-first,
/// IPv4-fallback rule for peer communication. Used by both [`ProviderRecord::new`] and
/// [`crate::routing::Contact::new`] so provider and routing-table address lists share one ordering
/// policy. This only reorders the list; the wire shape of each [`CandidateAddr`] is unchanged.
pub(crate) fn sort_addresses_ipv6_first(addresses: &mut [CandidateAddr]) {
    addresses.sort_by_key(CandidateAddr::family_then_kind_rank);
}

/// Maximum [`CandidateAddr`] entries kept per [`ProviderRecord`] / [`crate::routing::Contact`].
///
/// A record/contact carries candidate addresses so a finder can dial the holder; nothing on the
/// wire or decode path previously bounded how many a single record could carry (only the overall
/// 256 KiB frame did — [`crate::wire::MAX_FRAMED_BODY`]), so one frame could smuggle thousands of
/// addresses that the victim would store, fold into its routing table, AND re-serve (cloned) to
/// every querying peer — memory inflation plus bandwidth amplification (SPEC §5.5, §14). Eight is
/// generous headroom over the four [`AddressKind`] variants (a conforming producer emits at most
/// one address per kind per family) while remaining a small, cheap-to-clone constant.
pub const MAX_ADDRESSES_PER_RECORD: usize = 8;

/// Sort `addresses` **IPv6-first-then-rank** (see [`sort_addresses_ipv6_first`]) and then truncate
/// to [`MAX_ADDRESSES_PER_RECORD`], so the most-preferred candidates are the ones kept when a list
/// exceeds the cap. This is the one admission point both the constructors ([`ProviderRecord::new`],
/// [`crate::routing::Contact::new`]) and the wire-decode boundary (`handle_request_from`'s
/// `AddProvider` arm, and contacts folded in from lookup responses) MUST call before accepting an
/// address list from any source that did not already go through it — a `ProviderRecord` /
/// `Contact` deserialized directly from the wire bypasses the constructors entirely (their fields
/// are public), so capping only in `new` would not close the untrusted-input path.
pub(crate) fn sort_and_cap_addresses(addresses: &mut Vec<CandidateAddr>) {
    sort_addresses_ipv6_first(addresses);
    addresses.truncate(MAX_ADDRESSES_PER_RECORD);
}

/// Upper bound on how many candidates [`dial_candidates`] hands a dialer for ONE peer, so a record
/// padded with addresses cannot turn a single holder into a connect storm. Byte-for-byte the same
/// bound dig-download applies on its own dial path, so a consumer that adopts this iterator sees no
/// change in attempt count.
pub const MAX_DIAL_CANDIDATES: usize = 4;

/// The dialable candidates of `addresses`, in **dial order**: IPv6 first, then IPv4, then anything
/// unresolvable — deduped by `host:port` and capped at [`MAX_DIAL_CANDIDATES`].
///
/// This is the §5.2-compliant order (IPv6-first, IPv4-**fallback**) and the ONE place the DHT
/// expresses it, so every consumer inherits it instead of re-deriving a ranking of its own. A dialer
/// walks the WHOLE list and only reports failure once every candidate has been tried: in #836 a
/// reader instead took a single address, tried one IPv6 literal, and gave up while a working IPv4
/// candidate sat unused — v4 is the fallback, so a failed v6 attempt MUST fall through to it.
///
/// Relay markers are excluded (they are not directly dialable — reach those peers via the relay /
/// a brokered punch). Unresolvable candidates are KEPT, last, on purpose: a dialer that walks them
/// can report a concrete per-candidate reason instead of pretending the provider had no address.
pub fn dial_candidates(addresses: &[CandidateAddr]) -> Vec<&CandidateAddr> {
    let mut candidates: Vec<&CandidateAddr> =
        addresses.iter().filter(|a| a.kind.is_dialable()).collect();
    // Sorted defensively rather than trusting the stored order: the same ranking is applied when a
    // list is constructed or deserialized, but `addresses` is a public field any caller may rewrite.
    candidates.sort_by_key(|a| a.family_then_kind_rank());
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|a| seen.insert(a.dial_identity()));
    reserve_fallback_slot_and_cap(&mut candidates);
    candidates
}

/// Truncate `candidates` to [`MAX_DIAL_CANDIDATES`] while KEEPING the fallback tier represented.
///
/// Truncating the family-sorted list outright would let the preferred tier fill the cap on its own: a
/// holder advertising four or more IPv6 candidates would yield a dial set containing no IPv4 at all,
/// so a dialer that faithfully walked every candidate it was given would STILL never reach the working
/// address — precisely the #836 read-leg failure this iterator exists to prevent, and a violation of
/// the rule that a failed IPv6 attempt must never mask a working IPv4 one. It needs no attacker: a
/// dual-stack holder legitimately emits direct + mapped + reflexive IPv6 candidates, and an IPv6
/// address with no working route is ordinary.
///
/// So when the cap would exclude EVERY non-IPv6 candidate and one exists, the least-preferred kept
/// slot is given to the best non-IPv6 candidate. IPv6 still leads the list — the reservation costs one
/// surplus IPv6 attempt, never the ordering.
fn reserve_fallback_slot_and_cap(candidates: &mut Vec<&CandidateAddr>) {
    if candidates.len() <= MAX_DIAL_CANDIDATES {
        return;
    }
    let kept_excludes_every_fallback = candidates[..MAX_DIAL_CANDIDATES]
        .iter()
        .all(|a| a.is_ipv6_literal());
    let fallback = kept_excludes_every_fallback
        .then(|| candidates.iter().find(|a| !a.is_ipv6_literal()).copied())
        .flatten();
    match fallback {
        Some(fallback) => {
            candidates.truncate(MAX_DIAL_CANDIDATES - 1);
            candidates.push(fallback);
        }
        None => candidates.truncate(MAX_DIAL_CANDIDATES),
    }
}

/// serde hook applied to every `addresses` field ([`ProviderRecord`], [`crate::routing::Contact`]),
/// so [`MAX_ADDRESSES_PER_RECORD`] holds **by construction** for any value that is deserialized —
/// from a peer's wire frame, a config file, or a cached snapshot — and not only at the ingest call
/// sites that remember to call [`sort_and_cap_addresses`] (§14). Deserialization is the ONE
/// unavoidable gate every untrusted address list passes through; enforcing the bound there means a
/// future ingest path cannot silently reintroduce an unbounded list.
///
/// It **bounds rather than rejects**: a list longer than the cap is sorted and truncated, never
/// turned into a decode error. Rejecting would make a nonconforming (or simply older, looser)
/// producer's record unparseable, which the store-format compatibility rule forbids — and would
/// hand a peer an easy way to poison a whole frame. Sorting before truncating keeps the
/// most-preferred candidates, so a hostile peer cannot bury the one reachable address behind filler.
pub(crate) fn deserialize_capped_addresses<'de, D>(
    deserializer: D,
) -> Result<Vec<CandidateAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut addresses = Vec::<CandidateAddr>::deserialize(deserializer)?;
    sort_and_cap_addresses(&mut addresses);
    Ok(addresses)
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
    /// Candidate addresses to reach the holder, ordered IPv6-first then most-direct-first by
    /// [`AddressKind::rank`] and bounded to [`MAX_ADDRESSES_PER_RECORD`] — held by BOTH
    /// [`ProviderRecord::new`] and deserialization ([`deserialize_capped_addresses`]), so a record
    /// off the wire carries the same guarantee as a constructed one.
    #[serde(deserialize_with = "deserialize_capped_addresses")]
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
        mut addresses: Vec<CandidateAddr>,
        expires_at: u64,
    ) -> Self {
        sort_and_cap_addresses(&mut addresses);
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

    /// The FIRST candidate only — the IPv6-preferred, most-direct dialable address, if any.
    ///
    /// **Prefer [`dial_candidates`](Self::dial_candidates) for dialing.** This returns one address,
    /// so a caller that dials it and stops has made a single attempt and cannot fall back: an
    /// unusable IPv6 candidate then masks a working IPv4 one, violating the IPv4-**fallback** half
    /// of §5.2 (exactly the #836 read-leg failure). Use this only where a single representative
    /// address is genuinely what is wanted — a log line, a display string, a metric label.
    pub fn best_address(&self) -> Option<&CandidateAddr> {
        self.addresses.iter().find(|a| a.kind.is_dialable())
    }

    /// This provider's dialable candidates in §5.2 dial order — see [`dial_candidates`] for the
    /// ordering contract. Dial these in order, falling through on failure, before concluding the
    /// holder is unreachable.
    pub fn dial_candidates(&self) -> Vec<&CandidateAddr> {
        dial_candidates(&self.addresses)
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

    #[test]
    fn provider_record_new_sorts_addresses_ipv6_first() {
        // Fed in IPv4-first order; the stored list must come out IPv6-first, then by rank.
        let key = Key::from_bytes([0u8; 32]);
        let rec = ProviderRecord::new(
            &key,
            &pid(1),
            vec![
                CandidateAddr::direct("203.0.113.7", 9444), // IPv4 direct
                CandidateAddr::direct("2001:db8::1", 9444), // IPv6 direct
                CandidateAddr {
                    host: "198.51.100.2".into(),
                    port: 1,
                    kind: AddressKind::Reflexive,
                }, // IPv4 reflexive
                CandidateAddr {
                    host: "2001:db8::2".into(),
                    port: 1,
                    kind: AddressKind::Reflexive,
                }, // IPv6 reflexive
            ],
            10,
        );
        let hosts: Vec<&str> = rec.addresses.iter().map(|a| a.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["2001:db8::1", "2001:db8::2", "203.0.113.7", "198.51.100.2"],
            "addresses must be IPv6-first, then ranked by AddressKind"
        );
    }

    #[test]
    fn family_key_derives_from_dig_ip_family() {
        // The FAMILY half of the sort key comes from `dig_ip::Family`, the single ecosystem source
        // of truth — not a hand-rolled `is_ipv6` heuristic. The load-bearing proof is the
        // IPv4-mapped IPv6 case: `dig_ip::Family::of` classifies `::ffff:a.b.c.d` as V4 (it is IPv4
        // reachability), so it must sort with IPv4, AFTER a genuine IPv6 address of the same kind. A
        // `host.parse::<IpAddr>()`-based family key would have (wrongly) treated it as IPv6.
        let key = Key::from_bytes([0u8; 32]);
        let rec = ProviderRecord::new(
            &key,
            &pid(1),
            vec![
                CandidateAddr::direct("::ffff:203.0.113.9", 9444), // IPv4-mapped → V4 per dig-ip
                CandidateAddr::direct("2001:db8::1", 9444),        // genuine IPv6 → V6
            ],
            10,
        );
        let hosts: Vec<&str> = rec.addresses.iter().map(|a| a.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["2001:db8::1", "::ffff:203.0.113.9"],
            "an IPv4-mapped IPv6 address must sort as V4 (dig_ip::Family), after a genuine IPv6"
        );
    }

    #[test]
    fn directness_kind_rank_preserved_as_tiebreak_within_a_family() {
        // Within ONE address family the dht-specific most-direct-first `AddressKind::rank` tiebreak
        // MUST survive the migration to dig-ip family keying: same family, different directness →
        // Direct before Mapped before Reflexive.
        let key = Key::from_bytes([0u8; 32]);
        let rec = ProviderRecord::new(
            &key,
            &pid(1),
            vec![
                CandidateAddr {
                    host: "2001:db8::3".into(),
                    port: 1,
                    kind: AddressKind::Reflexive,
                },
                CandidateAddr {
                    host: "2001:db8::2".into(),
                    port: 1,
                    kind: AddressKind::Mapped,
                },
                CandidateAddr::direct("2001:db8::1", 9444),
            ],
            10,
        );
        let hosts: Vec<&str> = rec.addresses.iter().map(|a| a.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["2001:db8::1", "2001:db8::2", "2001:db8::3"],
            "within one family, addresses must stay ordered by AddressKind::rank (most-direct first)"
        );
    }

    #[test]
    fn best_address_prefers_ipv6_over_ipv4_at_same_rank() {
        let key = Key::from_bytes([0u8; 32]);
        let rec = ProviderRecord::new(
            &key,
            &pid(1),
            vec![
                CandidateAddr::direct("203.0.113.7", 9444), // IPv4 direct, fed first
                CandidateAddr::direct("2001:db8::1", 9444), // IPv6 direct, fed second
            ],
            10,
        );
        assert_eq!(rec.best_address().unwrap().host, "2001:db8::1");
    }

    // ---- Address-list cap (MEDIUM: no cap on addresses[], SECURITY_AUDIT_P2P.md #179) ----

    #[test]
    fn provider_record_new_caps_addresses_at_the_constant() {
        // Feed far more than the cap — a hostile/misconfigured caller must never make a
        // constructed record carry an unbounded address list.
        let key = Key::from_bytes([0u8; 32]);
        let many: Vec<CandidateAddr> = (0..1000)
            .map(|i| CandidateAddr::direct(format!("203.0.113.{}", i % 255), 9444))
            .collect();
        let rec = ProviderRecord::new(&key, &pid(1), many, 10);
        assert_eq!(rec.addresses.len(), MAX_ADDRESSES_PER_RECORD);
    }

    #[test]
    fn provider_record_new_cap_keeps_most_preferred_after_sort() {
        // The cap must apply AFTER the IPv6-first-then-rank sort, so truncation drops the LEAST
        // preferred candidates, not an arbitrary prefix of the input order.
        let key = Key::from_bytes([0u8; 32]);
        let mut addrs: Vec<CandidateAddr> = Vec::new();
        // One preferred IPv6 direct address that must survive the cap...
        addrs.push(CandidateAddr::direct("2001:db8::1", 9444));
        // ...buried behind far more than the cap worth of low-preference IPv4 relay markers.
        for i in 0..1000u32 {
            addrs.push(CandidateAddr {
                host: format!("198.51.100.{}", i % 255),
                port: 1,
                kind: AddressKind::Relay,
            });
        }
        let rec = ProviderRecord::new(&key, &pid(1), addrs, 10);
        assert_eq!(rec.addresses.len(), MAX_ADDRESSES_PER_RECORD);
        assert_eq!(
            rec.addresses[0].host, "2001:db8::1",
            "the single most-preferred (IPv6 direct) candidate must survive truncation"
        );
    }

    // ---- Deserialization-time address bound (#1514) ----

    /// Build the JSON of a record carrying `n` addresses — the shape a hostile peer frames on the
    /// wire, bypassing `ProviderRecord::new` entirely (its fields are public).
    fn record_json_with_addresses(n: usize) -> String {
        let addrs: Vec<String> = (0..n)
            .map(|i| {
                format!(
                    r#"{{"host":"198.51.100.{}","port":1,"kind":"relay"}}"#,
                    i % 255
                )
            })
            .collect();
        format!(
            r#"{{"content_key":"{}","provider_peer_id":"{}","addresses":[{}],"expires_at":1}}"#,
            "aa".repeat(32),
            "bb".repeat(32),
            addrs.join(",")
        )
    }

    #[test]
    fn deserialization_bounds_the_address_count() {
        // #1514: the cap must hold BY CONSTRUCTION at the decode boundary, not only at the ingest
        // call sites that remember to call `sort_and_cap_addresses`. Stated over the CLASS: no
        // deserialized record, from any source, ever carries more than the cap.
        let rec: ProviderRecord = serde_json::from_str(&record_json_with_addresses(1000)).unwrap();
        assert_eq!(rec.addresses.len(), MAX_ADDRESSES_PER_RECORD);
    }

    #[test]
    fn deserialization_bound_is_one_off_exact() {
        // The one-off variant: exactly the cap survives untouched; exactly one more is bounded.
        let at_cap: ProviderRecord =
            serde_json::from_str(&record_json_with_addresses(MAX_ADDRESSES_PER_RECORD)).unwrap();
        assert_eq!(at_cap.addresses.len(), MAX_ADDRESSES_PER_RECORD);
        let over_by_one: ProviderRecord =
            serde_json::from_str(&record_json_with_addresses(MAX_ADDRESSES_PER_RECORD + 1))
                .unwrap();
        assert_eq!(over_by_one.addresses.len(), MAX_ADDRESSES_PER_RECORD);
    }

    #[test]
    fn deserialization_keeps_the_most_preferred_addresses() {
        // Bounding must drop the LEAST preferred candidates, so a hostile peer cannot bury the one
        // genuinely reachable address behind a wall of filler and have it truncated away.
        let mut addrs: Vec<String> =
            vec![r#"{"host":"2001:db8::1","port":9444,"kind":"direct"}"#.to_string()];
        for i in 0..1000 {
            addrs.push(format!(
                r#"{{"host":"198.51.100.{}","port":1,"kind":"relay"}}"#,
                i % 255
            ));
        }
        // The preferred candidate sits LAST in the wire order, so a naive prefix-truncation would
        // discard exactly the address that matters.
        addrs.rotate_left(1);
        let json = format!(
            r#"{{"content_key":"{}","provider_peer_id":"{}","addresses":[{}],"expires_at":1}}"#,
            "aa".repeat(32),
            "bb".repeat(32),
            addrs.join(",")
        );
        let rec: ProviderRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec.addresses.len(), MAX_ADDRESSES_PER_RECORD);
        assert_eq!(
            rec.addresses[0].host, "2001:db8::1",
            "the most-preferred candidate must survive the bound regardless of wire position"
        );
    }

    // ---- Ordered dial candidates (#1594) ----

    fn record_with(addresses: Vec<CandidateAddr>) -> ProviderRecord {
        ProviderRecord::new(&Key::from_bytes([0u8; 32]), &pid(1), addresses, 10)
    }

    #[test]
    fn dial_candidates_order_v6_then_v4_then_unresolvable() {
        let rec = record_with(vec![
            CandidateAddr::direct("not-a-literal", 9444),
            CandidateAddr::direct("203.0.113.7", 9444),
            CandidateAddr::direct("2001:db8::1", 9444),
        ]);
        let hosts: Vec<&str> = rec
            .dial_candidates()
            .iter()
            .map(|a| a.host.as_str())
            .collect();
        assert_eq!(
            hosts,
            vec!["2001:db8::1", "203.0.113.7", "not-a-literal"],
            "dial order is IPv6, then IPv4, then anything unresolvable (§5.2)"
        );
    }

    #[test]
    fn dial_candidates_keep_the_ipv4_fallback_behind_an_ipv6_candidate() {
        // The #836 failure this exists to prevent: a probe took `best_address()` alone, tried ONE
        // IPv6 literal, and gave up while a working IPv4 candidate sat unused. IPv4 is the FALLBACK
        // (§5.2), so it MUST still be present, after the v6 candidate, for a dialer to walk to.
        let rec = record_with(vec![
            CandidateAddr::direct("2001:db8::1", 9444),
            CandidateAddr::direct("172.31.79.22", 9444),
        ]);
        let candidates = rec.dial_candidates();
        assert_eq!(candidates.len(), 2, "the fallback must not be dropped");
        assert_eq!(candidates[0].host, "2001:db8::1");
        assert_eq!(candidates[1].host, "172.31.79.22");
    }

    #[test]
    fn dial_candidates_treat_v4_mapped_v6_as_ipv4() {
        // Canonical IPv4-in-IPv6 rule: `::ffff:a.b.c.d` is IPv4 REACHABILITY, so it must order with
        // IPv4 — after a genuine IPv6 candidate. This is the one case where a hand-rolled
        // `is_ipv6`-style check silently disagrees with `dig_ip::Family`.
        let rec = record_with(vec![
            CandidateAddr::direct("::ffff:203.0.113.9", 9444),
            CandidateAddr::direct("2001:db8::1", 9444),
        ]);
        let hosts: Vec<&str> = rec
            .dial_candidates()
            .iter()
            .map(|a| a.host.as_str())
            .collect();
        assert_eq!(hosts, vec!["2001:db8::1", "::ffff:203.0.113.9"]);
    }

    #[test]
    fn dial_candidates_exclude_relay_markers() {
        let rec = record_with(vec![
            CandidateAddr::relay_marker(),
            CandidateAddr::direct("2001:db8::1", 9444),
        ]);
        let candidates = rec.dial_candidates();
        assert_eq!(
            candidates.len(),
            1,
            "a relay marker is not directly dialable"
        );
        assert_eq!(candidates[0].host, "2001:db8::1");
    }

    #[test]
    fn dial_candidates_are_bounded_and_deduped() {
        // A record may legitimately carry up to MAX_ADDRESSES_PER_RECORD candidates; a dialer must
        // not turn one provider into an unbounded connect storm, and must not waste an attempt
        // re-dialing the same host:port twice.
        let mut addresses = vec![CandidateAddr::direct("2001:db8::1", 9444); 3];
        addresses.extend((0..5).map(|i| CandidateAddr::direct(format!("10.0.0.{i}"), 9444)));
        let rec = record_with(addresses);
        let candidates = rec.dial_candidates();
        assert_eq!(candidates.len(), MAX_DIAL_CANDIDATES);
        assert_eq!(
            candidates
                .iter()
                .filter(|a| a.host == "2001:db8::1")
                .count(),
            1,
            "a repeated host:port contributes exactly one dial attempt"
        );
    }

    #[test]
    fn dial_candidates_of_a_relay_only_record_are_empty() {
        let rec = record_with(vec![CandidateAddr::relay_marker()]);
        assert!(rec.dial_candidates().is_empty());
    }

    #[test]
    fn unresolvable_host_sorts_after_an_ipv4_literal_in_the_stored_order() {
        // The stored order and the dial order share ONE ranking policy, so a hostname (which is not
        // reachability the DHT can classify) must never outrank a usable IPv4 literal anywhere.
        let rec = record_with(vec![
            CandidateAddr::direct("not-a-literal", 1),
            CandidateAddr::direct("203.0.113.7", 1),
        ]);
        let hosts: Vec<&str> = rec.addresses.iter().map(|a| a.host.as_str()).collect();
        assert_eq!(hosts, vec!["203.0.113.7", "not-a-literal"]);
    }

    #[test]
    fn dial_candidates_reserve_a_slot_for_the_ipv4_fallback() {
        // #836 again, one layer down: truncating to MAX_DIAL_CANDIDATES *after* the family sort means
        // a record carrying four or more IPv6 candidates yields a dial set with ZERO IPv4 — so a
        // dialer walking every candidate it is given still never reaches the working address. That
        // contradicts the SPEC 5.5 MUST that a failed IPv6 attempt never masks a working IPv4 one.
        // A dual-stack holder legitimately emits direct + mapped + reflexive v6, so this is reachable
        // without an attacker; an IPv6 address with no working route is the common AWS case.
        let rec = record_with(vec![
            CandidateAddr::direct("2001:db8::1", 9444),
            CandidateAddr::direct("2001:db8::2", 9444),
            CandidateAddr::direct("2001:db8::3", 9444),
            CandidateAddr::direct("2001:db8::4", 9444),
            CandidateAddr::direct("203.0.113.7", 9444),
        ]);
        let candidates = rec.dial_candidates();
        assert_eq!(candidates.len(), MAX_DIAL_CANDIDATES);
        assert!(
            candidates.iter().any(|a| a.host == "203.0.113.7"),
            "the IPv4 fallback tier must keep a slot inside the cap, got {:?}",
            candidates.iter().map(|a| &a.host).collect::<Vec<_>>()
        );
        assert_eq!(
            candidates[0].host, "2001:db8::1",
            "IPv6 still leads — the reservation costs the LEAST preferred v6 slot, not the order"
        );
    }

    #[test]
    fn dial_candidates_reserve_the_fallback_only_when_it_would_be_lost() {
        // The one-off variant either side of the cap: at exactly the cap nothing is dropped and no
        // reservation is needed, so a v4 that already fits must not be promoted out of order.
        let rec = record_with(vec![
            CandidateAddr::direct("2001:db8::1", 9444),
            CandidateAddr::direct("2001:db8::2", 9444),
            CandidateAddr::direct("2001:db8::3", 9444),
            CandidateAddr::direct("203.0.113.7", 9444),
        ]);
        let hosts: Vec<&str> = rec
            .dial_candidates()
            .iter()
            .map(|a| a.host.as_str())
            .collect();
        assert_eq!(
            hosts,
            vec!["2001:db8::1", "2001:db8::2", "2001:db8::3", "203.0.113.7"]
        );
    }

    #[test]
    fn dial_candidates_dedupe_equivalent_spellings_of_one_address() {
        // Dedup on the RAW host string lets one address spelled four ways consume every slot, which
        // is the fallback-starvation above with no distinct addresses at all. Equivalence is a
        // property of the parsed IpAddr, not of the text.
        let rec = record_with(vec![
            CandidateAddr::direct("2001:db8::1", 9444),
            CandidateAddr::direct("2001:0db8::1", 9444),
            CandidateAddr::direct("2001:db8:0:0:0:0:0:1", 9444),
            CandidateAddr::direct("2001:DB8::1", 9444),
            CandidateAddr::direct("203.0.113.7", 9444),
        ]);
        let candidates = rec.dial_candidates();
        assert_eq!(
            candidates.len(),
            2,
            "four spellings of one IPv6 address are ONE dial attempt, got {:?}",
            candidates.iter().map(|a| &a.host).collect::<Vec<_>>()
        );
        assert!(candidates.iter().any(|a| a.host == "203.0.113.7"));
    }

    #[test]
    fn dial_candidates_treat_a_v4_mapped_spelling_as_the_same_address_as_its_ipv4() {
        // `::ffff:a.b.c.d` and `a.b.c.d` are the same endpoint and the same IPv4 reachability (which
        // is why `dig_ip::Family` ranks both V4), so they are one dial attempt, not two.
        let rec = record_with(vec![
            CandidateAddr::direct("::ffff:203.0.113.7", 9444),
            CandidateAddr::direct("203.0.113.7", 9444),
        ]);
        assert_eq!(rec.dial_candidates().len(), 1);
    }

    #[test]
    fn dial_candidates_keep_distinct_ports_of_one_host_apart() {
        // Dedup is per ENDPOINT: the same host on two ports is two genuine dial targets.
        let rec = record_with(vec![
            CandidateAddr::direct("2001:db8::1", 9444),
            CandidateAddr::direct("2001:db8::1", 9445),
        ]);
        assert_eq!(rec.dial_candidates().len(), 2);
    }
}
