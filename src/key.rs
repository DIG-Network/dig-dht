//! The 256-bit Kademlia keyspace: [`Key`], XOR [`Distance`], and the maps from a [`PeerId`] and a
//! [`ContentId`](crate::ContentId) into it.
//!
//! Kademlia organizes both **nodes** and **content** in a single 256-bit metric space and measures
//! closeness by the **XOR** of two keys interpreted as a big-endian integer (Maymounkov & Mazières,
//! 2002). This module is the pure, network-free core of that metric:
//!
//! - A **node**'s key is its `peer_id` verbatim — `peer_id = SHA-256(TLS SPKI DER)` is already a
//!   uniform 256-bit value ([`Key::from_peer_id`]), so the DHT node id IS the peer id.
//! - A **content** key is the SHA-256 of the content id's canonical bytes
//!   ([`ContentId::to_key`](crate::ContentId::to_key)),
//!   which lands DIG content (store / capsule / root / resource) in the same 256-bit space so
//!   `find_node(key)` and `find_providers(content_key)` share one lookup.
//!
//! `Distance` is XOR; the routing table's **bucket index** for a key is `255 - leading_zeros` of the
//! distance from this node — the standard Kademlia longest-common-prefix bucketing.

use std::cmp::Ordering;

use dig_nat::PeerId;

/// A point in the 256-bit Kademlia keyspace — 32 big-endian bytes.
///
/// Both node ids (a peer's `peer_id`) and content keys live here; closeness is the XOR
/// [`Distance`]. A `Key` is `Ord` by its raw big-endian byte value (NOT a distance — distances are
/// only meaningful relative to a reference key), so it can be used as a stable map key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key([u8; 32]);

impl Key {
    /// Construct from raw 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Key(bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A node's key is its `peer_id` verbatim — both are a uniform SHA-256 256-bit value, so the
    /// DHT node id and the peer id are one and the same.
    pub fn from_peer_id(peer_id: &PeerId) -> Self {
        Key(*peer_id.as_bytes())
    }

    /// The XOR distance between this key and `other` (symmetric: `a.distance(b) == b.distance(a)`).
    pub fn distance(&self, other: &Key) -> Distance {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = self.0[i] ^ other.0[i];
        }
        Distance(out)
    }

    /// Lowercase hex (64 chars) — the canonical text rendering (matches `peer_id` hex).
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.to_hex())
    }
}

/// The XOR distance between two [`Key`]s — a point in the same 256-bit space, ordered as a
/// big-endian unsigned integer (smaller = closer).
///
/// Kademlia's metric: `d(a,b) = a XOR b`, and `d` is a valid metric (identity, symmetry, triangle
/// inequality) which is what makes iterative lookups converge. [`Ord`] compares big-endian so
/// `Distance::ZERO` (a key to itself) is the minimum.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Distance([u8; 32]);

impl Distance {
    /// The zero distance (a key to itself) — the minimum possible distance.
    pub const ZERO: Distance = Distance([0u8; 32]);

    /// The raw 32 bytes of the distance.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The Kademlia **bucket index** for this distance: `255 - leading_zero_bits`, i.e. the position
    /// of the most-significant set bit. Returns `None` for [`Distance::ZERO`] (a node never buckets
    /// itself). A larger index means a more-distant key (shares a shorter prefix with the reference).
    ///
    /// This is exactly the index into a 256-bucket routing table keyed by the length of the shared
    /// prefix between this node's id and the other key.
    pub fn bucket_index(&self) -> Option<usize> {
        for (i, byte) in self.0.iter().enumerate() {
            if *byte != 0 {
                let bit_in_byte = byte.leading_zeros() as usize; // 0..=7
                let leading_zero_bits = i * 8 + bit_in_byte;
                return Some(255 - leading_zero_bits);
            }
        }
        None
    }

    /// Lowercase hex (64 chars).
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl PartialOrd for Distance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Distance {
    /// Big-endian unsigned-integer comparison — byte 0 is most significant.
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::fmt::Debug for Distance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Distance({})", self.to_hex())
    }
}

/// Lowercase hex of a 32-byte array (shared by [`Key`] + [`Distance`]).
fn to_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte0: u8, rest: u8) -> Key {
        let mut b = [rest; 32];
        b[0] = byte0;
        Key::from_bytes(b)
    }

    #[test]
    fn xor_distance_is_symmetric() {
        let a = key(0x12, 0x34);
        let b = key(0xAB, 0xCD);
        assert_eq!(a.distance(&b), b.distance(&a));
    }

    #[test]
    fn distance_to_self_is_zero() {
        let a = key(0x99, 0x01);
        assert_eq!(a.distance(&a), Distance::ZERO);
        assert_eq!(a.distance(&a).bucket_index(), None);
    }

    #[test]
    fn xor_is_the_distance() {
        let a = Key::from_bytes([0x00; 32]);
        let mut bb = [0u8; 32];
        bb[31] = 0x01;
        let b = Key::from_bytes(bb);
        // distance(0, 1) == 1
        assert_eq!(a.distance(&b).as_bytes()[31], 0x01);
        assert_eq!(a.distance(&b).bucket_index(), Some(0));
    }

    #[test]
    fn bucket_index_tracks_most_significant_set_bit() {
        let zero = Key::from_bytes([0u8; 32]);

        // Distance with MSB set in byte 0 → shares no prefix → bucket 255.
        let mut hi = [0u8; 32];
        hi[0] = 0x80;
        assert_eq!(
            zero.distance(&Key::from_bytes(hi)).bucket_index(),
            Some(255)
        );

        // Distance == 1 (LSB) → longest shared prefix → bucket 0.
        let mut lo = [0u8; 32];
        lo[31] = 0x01;
        assert_eq!(zero.distance(&Key::from_bytes(lo)).bucket_index(), Some(0));

        // 0x40 in byte 0 → one leading zero bit → bucket 254.
        let mut b = [0u8; 32];
        b[0] = 0x40;
        assert_eq!(zero.distance(&Key::from_bytes(b)).bucket_index(), Some(254));

        // 0x01 in byte 0 → 7 leading zero bits → bucket 248.
        let mut c = [0u8; 32];
        c[0] = 0x01;
        assert_eq!(zero.distance(&Key::from_bytes(c)).bucket_index(), Some(248));
    }

    #[test]
    fn closer_keys_have_smaller_distance() {
        let target = Key::from_bytes([0u8; 32]);
        let near = key(0x00, 0x01); // differs only in low bytes
        let far = key(0xFF, 0x00); // differs in the top byte
        assert!(target.distance(&near) < target.distance(&far));
    }

    #[test]
    fn from_peer_id_is_verbatim() {
        let mut raw = [0u8; 32];
        raw[0] = 0xDE;
        raw[31] = 0xAD;
        let pid = PeerId::from_bytes(raw);
        assert_eq!(Key::from_peer_id(&pid).as_bytes(), &raw);
    }

    #[test]
    fn hex_round_trips_length() {
        let k = key(0x0a, 0xf0);
        assert_eq!(k.to_hex().len(), 64);
        assert!(k.to_hex().starts_with("0a"));
    }

    #[test]
    fn distance_ordering_is_big_endian() {
        // A difference high up dominates a difference low down.
        let mut a = [0u8; 32];
        a[0] = 0x01;
        let mut b = [0u8; 32];
        b[31] = 0xFF;
        assert!(Distance(b) < Distance(a));
    }
}
