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

/// Decode a canonical 64-hex string into 32 bytes, or `None` if it is not exactly 64 hex digits.
///
/// The ONE hex-decode in this crate (`peer_id`, content key and mirror-coin id all share this
/// shape), so a second, subtly different decoder cannot drift into existence.
pub(crate) fn hex64_to_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Encode 32 bytes as canonical lowercase 64-hex — the inverse of [`hex64_to_bytes`].
pub(crate) fn to_hex64(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Wire-boundary normalization for
/// [`unverified_mirror_coin_id`](ProviderRecord::unverified_mirror_coin_id): anything that is not a
/// 64-hex string becomes `None`, and a valid one is lowercased.
///
/// **Normalize, never reject.** This field is attacker-supplied and OPTIONAL, so a malformed value
/// must cost the record nothing: erroring here would let any peer destroy a whole provider record —
/// and with it the discovery the DHT exists for — by appending one junk field. Dropping it instead
/// leaves the record exactly as useful as one that never carried a pointer, which is the defined
/// fallback. It also bounds the field: a peer can otherwise put a body-sized string here (the frame
/// ceiling is [`MAX_FRAMED_BODY`](crate::wire::MAX_FRAMED_BODY), 256 KiB) which the victim would
/// store AND re-serve to every querying peer — the same amplification the address cap closes.
///
/// Lowercasing is not cosmetic: without it the same coin published in two cases yields two
/// non-equal records, so dedup and equality would split on presentation.
fn deserialize_mirror_coin_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(raw
        .as_ref()
        .and_then(|v| v.as_str())
        .map(str::to_ascii_lowercase)
        .filter(|s| hex64_to_bytes(s).is_some()))
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
    /// **UNTRUSTED POINTER, NOT EVIDENCE** — an optional 64-hex mirror-coin id the publisher claims
    /// bonds this `(store, root)` claim, carried so a verifier can fetch ONE coin instead of
    /// scanning by hint.
    ///
    /// Holding this proves nothing whatsoever. Any peer can publish any 32 bytes, and a hostile or
    /// merely stale publisher can supply a real, well-formed, fully-collateralised coin id that
    /// bonds a **different** store, a different root, a different epoch, or a different owner —
    /// every property checks out except the one that matters. A consumer MUST, against its own
    /// chain source:
    ///
    /// 1. fetch the coin and verify it sits at `dig_mirror_coin::mirror_coin_puzzle_hash()`,
    /// 2. verify it is $DIG with the asset id re-derived from the creating spend,
    /// 3. verify it carries the full collateral, and
    /// 4. confirm the coin's DECLARED bond matches the claim — `advertises(store, root, epoch)` is
    ///    an exact equality on the declared triple, and the owner is checked against the four-term
    ///    `dig_mirror_coin::mirror_hint(store, root, owner_puzzle_hash, epoch)`.
    ///
    /// Step 4 is what binds the coin to the claim; 1-3 alone prove only that *a* valid mirror coin
    /// exists somewhere. No verification happens in this crate — the DHT has no chain source.
    ///
    /// **Absence is normal and must never degrade discovery.** Old publishers, publishers that have
    /// not created the coin yet, and publishers mid-epoch-rollover all legitimately omit it; a
    /// republished record can also carry a pointer that has since gone stale across an epoch
    /// boundary. The fallback is the existing hint scan (`dig-mirror-coin`'s `discover` / `list`),
    /// which is slower, not weaker. Treating a missing pointer as "uncollateralised" is a defect.
    ///
    /// **A wrong pointer costs the publisher, not the verifier.** One chain read, no retry loop: a
    /// lookup that misses or fails the bond check falls straight back to the hint scan. A mismatch
    /// is not grounds for blocklisting — it is indistinguishable from an epoch rollover.
    ///
    /// Malformed values normalize to `None` at the wire boundary, so this is either a canonical
    /// lowercase 64-hex string or absent — never attacker-shaped bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_mirror_coin_id"
    )]
    pub unverified_mirror_coin_id: Option<String>,
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
            unverified_mirror_coin_id: None,
        }
    }

    /// Attach the publisher's claimed mirror-coin id — see
    /// [`unverified_mirror_coin_id`](ProviderRecord::unverified_mirror_coin_id) for why holding it
    /// proves nothing. Stored canonically (lowercase 64-hex) so two records naming the same coin are
    /// byte-identical.
    ///
    /// Kept off [`new`](ProviderRecord::new) deliberately: the pointer is per-CONTENT rather than
    /// per-node, because a mirror coin bonds a `(store, root, owner, epoch)` tuple, so only the
    /// caller that knows which content it is announcing can supply it.
    pub fn with_unverified_mirror_coin_id(mut self, coin_id: [u8; 32]) -> Self {
        self.unverified_mirror_coin_id = Some(to_hex64(&coin_id));
        self
    }

    /// The claimed mirror-coin id as 32 bytes, or `None` when absent (the normal fallback case).
    ///
    /// **The bytes are a lookup key, never a fact.** Returning `Some` means a publisher said
    /// something, not that a collateral coin exists.
    pub fn unverified_mirror_coin_id_bytes(&self) -> Option<[u8; 32]> {
        self.unverified_mirror_coin_id
            .as_deref()
            .and_then(hex64_to_bytes)
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

    /// The 32 bytes a well-formed pointer decodes to, and its canonical lowercase spelling.
    const COIN_ID: [u8; 32] = [
        0x9a, 0x0b, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x20, 0x30, 0x40,
        0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66,
    ];
    const COIN_ID_HEX: &str = "9a0bff0123456789abcdef102030405060708090a0b0c0d0e0f0112233445566";

    fn plain_record() -> ProviderRecord {
        ProviderRecord::new(
            &Key::from_bytes([0xAB; 32]),
            &pid(0x07),
            vec![CandidateAddr::direct("203.0.113.7", 9444)],
            1_000,
        )
    }

    /// The pre-pointer record shape, byte-for-byte. A record produced by THIS crate must still
    /// deserialize into it — that is what "an old peer parses a new record" means, and it is the
    /// half a same-crate round-trip test cannot see.
    #[derive(serde::Deserialize)]
    struct LegacyProviderRecord {
        content_key: String,
        provider_peer_id: String,
        addresses: Vec<CandidateAddr>,
        expires_at: u64,
    }

    #[test]
    fn a_pointer_round_trips_and_decodes_to_its_bytes() {
        let rec = plain_record().with_unverified_mirror_coin_id(COIN_ID);
        assert_eq!(rec.unverified_mirror_coin_id.as_deref(), Some(COIN_ID_HEX));

        let json = serde_json::to_string(&rec).unwrap();
        let back: ProviderRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
        assert_eq!(back.unverified_mirror_coin_id_bytes(), Some(COIN_ID));
    }

    /// An OLD peer must parse a NEW record. Deserializing into the legacy shape proves the addition
    /// is tolerated as an unknown field rather than merely being self-consistent.
    #[test]
    fn an_old_peer_parses_a_record_carrying_the_new_pointer() {
        let rec = plain_record().with_unverified_mirror_coin_id(COIN_ID);
        let json = serde_json::to_string(&rec).unwrap();

        let legacy: LegacyProviderRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(legacy.content_key, rec.content_key);
        assert_eq!(legacy.provider_peer_id, rec.provider_peer_id);
        assert_eq!(legacy.addresses, rec.addresses);
        assert_eq!(legacy.expires_at, rec.expires_at);
    }

    /// A NEW peer must parse an OLD record — absence is the normal case, never an error.
    #[test]
    fn a_new_peer_parses_a_record_with_no_pointer_field_at_all() {
        let legacy_json = r#"{
            "content_key": "abababababababababababababababababababababababababababababababab",
            "provider_peer_id": "0707070707070707070707070707070707070707070707070707070707070707",
            "addresses": [{"host":"203.0.113.7","port":9444,"kind":"direct"}],
            "expires_at": 1000
        }"#;
        let rec: ProviderRecord = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(rec.unverified_mirror_coin_id, None);
        assert_eq!(rec.unverified_mirror_coin_id_bytes(), None);
        assert_eq!(rec, plain_record());
    }

    /// An absent pointer must be OMITTED from the wire, not emitted as `null`, so a record from a
    /// publisher with no coin is byte-identical to one from a pre-pointer publisher.
    #[test]
    fn an_absent_pointer_is_omitted_from_the_wire_entirely() {
        let json = serde_json::to_string(&plain_record()).unwrap();
        assert!(
            !json.contains("unverified_mirror_coin_id"),
            "absent pointer leaked onto the wire: {json}"
        );
        assert!(
            !json.contains("null"),
            "absent pointer emitted as null: {json}"
        );
    }

    /// Every malformed shape a hostile peer can put in the field normalizes to `None` — and NONE of
    /// them may fail the parse. Erroring would let one junk field destroy a whole provider record,
    /// which turns an optional convenience into a discovery-denial primitive.
    ///
    /// The oversize case is sized FROM the protocol limit: `wire::MAX_FRAMED_BODY` is 256 KiB, so a
    /// peer really can put ~256 KiB here inside one legal frame.
    #[test]
    fn every_malformed_pointer_normalizes_to_none_without_failing_the_record() {
        let oversize = "a".repeat(crate::wire::MAX_FRAMED_BODY - 512);
        let cases: Vec<(&str, String)> = vec![
            ("json null", "null".to_string()),
            ("empty string", "\"\"".to_string()),
            ("63 hex (one under)", format!("\"{}\"", "a".repeat(63))),
            ("65 hex (one over)", format!("\"{}\"", "a".repeat(65))),
            ("64 chars, not hex", format!("\"{}\"", "z".repeat(64))),
            ("a number", "12345".to_string()),
            ("a bool", "true".to_string()),
            ("an object", "{\"coin\":1}".to_string()),
            ("an array", "[1,2,3]".to_string()),
            ("body-sized string", format!("\"{oversize}\"")),
        ];

        for (label, value) in cases {
            let json = format!(
                r#"{{
                    "content_key": "abababababababababababababababababababababababababababababababab",
                    "provider_peer_id": "0707070707070707070707070707070707070707070707070707070707070707",
                    "addresses": [{{"host":"203.0.113.7","port":9444,"kind":"direct"}}],
                    "expires_at": 1000,
                    "unverified_mirror_coin_id": {value}
                }}"#
            );
            let rec: ProviderRecord = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("{label} must not fail the record parse: {e}"));
            assert_eq!(
                rec.unverified_mirror_coin_id, None,
                "{label} should have normalized to None"
            );
            // The rest of the record survives intact — a junk pointer degrades to the no-pointer
            // case, which is exactly as useful as before.
            assert_eq!(
                rec,
                plain_record(),
                "{label} damaged the rest of the record"
            );
        }
    }

    /// The 64-hex bound pinned from BOTH sides: at-bound passes, one over fails. Tested through the
    /// wire boundary so it pins the field, not only the helper.
    #[test]
    fn the_sixty_four_hex_bound_holds_from_both_sides() {
        assert!(
            hex64_to_bytes(&"a".repeat(64)).is_some(),
            "at-bound must decode"
        );
        assert!(
            hex64_to_bytes(&"a".repeat(65)).is_none(),
            "one over must not decode"
        );
        assert!(
            hex64_to_bytes(&"a".repeat(63)).is_none(),
            "one under must not decode"
        );
    }

    /// Uppercase hex is a valid id in a different presentation. It must decode to the SAME bytes and
    /// be stored canonically, or two records naming one coin compare unequal and dedup splits.
    #[test]
    fn an_uppercase_pointer_is_canonicalized_rather_than_dropped() {
        let json = format!(
            r#"{{
                "content_key": "abababababababababababababababababababababababababababababababab",
                "provider_peer_id": "0707070707070707070707070707070707070707070707070707070707070707",
                "addresses": [{{"host":"203.0.113.7","port":9444,"kind":"direct"}}],
                "expires_at": 1000,
                "unverified_mirror_coin_id": "{}"
            }}"#,
            COIN_ID_HEX.to_ascii_uppercase()
        );
        let rec: ProviderRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec.unverified_mirror_coin_id.as_deref(), Some(COIN_ID_HEX));
        assert_eq!(rec.unverified_mirror_coin_id_bytes(), Some(COIN_ID));
        assert_eq!(
            rec,
            plain_record().with_unverified_mirror_coin_id(COIN_ID),
            "the same coin in two cases must produce equal records"
        );
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
