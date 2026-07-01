//! [`ContentId`] — what a provider record is keyed by, at the granularities the L7
//! `dig.getAvailability` shapes use, mapped consistently into the [`crate::Key`] keyspace.
//!
//! A DIG Node advertises the content it holds so others can find it. The unit of advertisement is a
//! `ContentId`, which matches the availability granularities of the peer network (L7 spec §9):
//!
//! | Granularity | Fields | Answers |
//! |---|---|---|
//! | [`ContentId::Store`] | `store_id` | "does a peer serve this store at all?" |
//! | [`ContentId::Root`] | `store_id` + `root` | "does a peer have this generation `(store_id, root)`?" |
//! | [`ContentId::capsule`] | `store_id` + `root` | the immutable capsule `store_id:root` (alias of Root) |
//! | [`ContentId::Resource`] | `store_id` + `root` + `retrieval_key` | "does a peer have this resource within the capsule?" |
//!
//! **Keyspace mapping.** Each `ContentId` hashes to a 256-bit [`Key`] via SHA-256 over a
//! canonical, domain-separated byte encoding ([`ContentId::to_key`]). The domain separation (a
//! one-byte tag per granularity) guarantees that a store key, a root key, and a resource key are
//! distinct points even when they share the same `store_id` — so a store-level provider record and a
//! resource-level provider record for the same store never collide in the DHT. The encoding is
//! canonical (fixed field order, raw 32-byte hashes) so every implementation derives the identical
//! key for the same content — a frozen wire contract.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::key::Key;

/// A DIG content identifier at store / root(capsule) / resource granularity — the key a provider
/// record is stored under and a lookup asks for.
///
/// All hashes are the raw 32-byte forms (a `store_id`, a generation `root`, and a `retrieval_key`
/// are each a `Bytes32`). Use the constructors ([`Self::store`], [`Self::root`], [`Self::capsule`],
/// [`Self::resource`]) rather than building variants directly, and [`Self::to_key`] to map into the
/// DHT keyspace.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentId {
    /// A whole store — "does a peer serve this `store_id`?" (has_store).
    Store {
        /// The 32-byte store id.
        store_id: [u8; 32],
    },
    /// A specific generation `(store_id, root)` — the immutable capsule `store_id:root` (has_root).
    /// [`Self::capsule`] and [`Self::root`] both build this variant; a capsule IS a root generation.
    Root {
        /// The 32-byte store id.
        store_id: [u8; 32],
        /// The 32-byte generation root.
        root: [u8; 32],
    },
    /// A specific resource within a capsule — `(store_id, root, retrieval_key)` (has_resource).
    Resource {
        /// The 32-byte store id.
        store_id: [u8; 32],
        /// The 32-byte generation root.
        root: [u8; 32],
        /// The 32-byte resource retrieval key.
        retrieval_key: [u8; 32],
    },
}

/// Domain-separation tags so store / root / resource keys are distinct points even when they share a
/// `store_id`. These bytes are part of the frozen key-derivation contract — never renumber them.
const TAG_STORE: u8 = 0x01;
const TAG_ROOT: u8 = 0x02;
const TAG_RESOURCE: u8 = 0x03;

impl ContentId {
    /// A store-granularity content id (has_store).
    pub const fn store(store_id: [u8; 32]) -> Self {
        ContentId::Store { store_id }
    }

    /// A root/generation-granularity content id (has_root) — the generation `(store_id, root)`.
    pub const fn root(store_id: [u8; 32], root: [u8; 32]) -> Self {
        ContentId::Root { store_id, root }
    }

    /// The immutable capsule `store_id:root`. Alias of [`Self::root`] — a capsule is a generation.
    pub const fn capsule(store_id: [u8; 32], root: [u8; 32]) -> Self {
        ContentId::Root { store_id, root }
    }

    /// A resource-granularity content id (has_resource) — `(store_id, root, retrieval_key)`.
    pub const fn resource(store_id: [u8; 32], root: [u8; 32], retrieval_key: [u8; 32]) -> Self {
        ContentId::Resource {
            store_id,
            root,
            retrieval_key,
        }
    }

    /// The store id this content id belongs to (present at every granularity).
    pub const fn store_id(&self) -> &[u8; 32] {
        match self {
            ContentId::Store { store_id }
            | ContentId::Root { store_id, .. }
            | ContentId::Resource { store_id, .. } => store_id,
        }
    }

    /// The canonical, domain-separated byte encoding this content id hashes over. Fixed field order,
    /// raw 32-byte hashes, one leading tag byte per granularity — a frozen wire contract so every
    /// implementation derives the same [`Key`].
    fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            ContentId::Store { store_id } => {
                let mut v = Vec::with_capacity(1 + 32);
                v.push(TAG_STORE);
                v.extend_from_slice(store_id);
                v
            }
            ContentId::Root { store_id, root } => {
                let mut v = Vec::with_capacity(1 + 64);
                v.push(TAG_ROOT);
                v.extend_from_slice(store_id);
                v.extend_from_slice(root);
                v
            }
            ContentId::Resource {
                store_id,
                root,
                retrieval_key,
            } => {
                let mut v = Vec::with_capacity(1 + 96);
                v.push(TAG_RESOURCE);
                v.extend_from_slice(store_id);
                v.extend_from_slice(root);
                v.extend_from_slice(retrieval_key);
                v
            }
        }
    }

    /// Map this content id into the 256-bit DHT [`Key`] keyspace: `SHA-256(canonical_bytes)`.
    ///
    /// Deterministic + domain-separated: the same content always yields the same key, and different
    /// granularities of the same store yield different keys (so their provider records do not
    /// collide). This is how `announce_provider` / `find_providers` agree on where a record lives.
    pub fn to_key(&self) -> Key {
        let digest = Sha256::digest(self.canonical_bytes());
        let bytes: [u8; 32] = digest.into();
        Key::from_bytes(bytes)
    }
}

impl fmt::Debug for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentId::Store { store_id } => f
                .debug_struct("ContentId::Store")
                .field("store_id", &hex32(store_id))
                .finish(),
            ContentId::Root { store_id, root } => f
                .debug_struct("ContentId::Root")
                .field("store_id", &hex32(store_id))
                .field("root", &hex32(root))
                .finish(),
            ContentId::Resource {
                store_id,
                root,
                retrieval_key,
            } => f
                .debug_struct("ContentId::Resource")
                .field("store_id", &hex32(store_id))
                .field("root", &hex32(root))
                .field("retrieval_key", &hex32(retrieval_key))
                .finish(),
        }
    }
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push(char::from_digit((x >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((x & 0x0f) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: [u8; 32] = [0x11; 32];
    const R: [u8; 32] = [0x22; 32];
    const RK: [u8; 32] = [0x33; 32];

    #[test]
    fn to_key_is_deterministic() {
        assert_eq!(ContentId::store(S).to_key(), ContentId::store(S).to_key());
        assert_eq!(
            ContentId::resource(S, R, RK).to_key(),
            ContentId::resource(S, R, RK).to_key()
        );
    }

    #[test]
    fn different_granularities_of_same_store_have_distinct_keys() {
        let k_store = ContentId::store(S).to_key();
        let k_root = ContentId::root(S, R).to_key();
        let k_res = ContentId::resource(S, R, RK).to_key();
        assert_ne!(k_store, k_root);
        assert_ne!(k_root, k_res);
        assert_ne!(k_store, k_res);
    }

    #[test]
    fn capsule_is_an_alias_of_root() {
        assert_eq!(ContentId::capsule(S, R), ContentId::root(S, R));
        assert_eq!(
            ContentId::capsule(S, R).to_key(),
            ContentId::root(S, R).to_key()
        );
    }

    #[test]
    fn store_id_accessor_present_at_every_granularity() {
        assert_eq!(ContentId::store(S).store_id(), &S);
        assert_eq!(ContentId::root(S, R).store_id(), &S);
        assert_eq!(ContentId::resource(S, R, RK).store_id(), &S);
    }

    #[test]
    fn distinct_stores_have_distinct_keys() {
        let other = [0x99; 32];
        assert_ne!(
            ContentId::store(S).to_key(),
            ContentId::store(other).to_key()
        );
    }

    #[test]
    fn tag_prefix_prevents_field_shifting_collision() {
        // Without a domain tag, root{store=A,root=B} and resource{store=A,root=B,rk=..} could be
        // confused by a naive concat. The tag byte guarantees distinct preimages.
        let a = ContentId::root(S, R).to_key();
        let b = ContentId::resource(S, R, [0u8; 32]).to_key();
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_bytes_have_the_expected_tag_and_length() {
        // Store: tag + 32; Root: tag + 64; Resource: tag + 96. The leading byte is the domain tag.
        let store = ContentId::store(S).canonical_bytes();
        assert_eq!(store.len(), 1 + 32);
        assert_eq!(store[0], TAG_STORE);

        let root = ContentId::root(S, R).canonical_bytes();
        assert_eq!(root.len(), 1 + 64);
        assert_eq!(root[0], TAG_ROOT);

        let res = ContentId::resource(S, R, RK).canonical_bytes();
        assert_eq!(res.len(), 1 + 96);
        assert_eq!(res[0], TAG_RESOURCE);
    }

    #[test]
    fn debug_renders_hex_for_every_variant() {
        // Exercises the Debug impl + hex32 helper for all three variants.
        let store = format!("{:?}", ContentId::store(S));
        assert!(store.contains("ContentId::Store"));
        assert!(store.contains(&"11".repeat(32)));

        let root = format!("{:?}", ContentId::root(S, R));
        assert!(root.contains("ContentId::Root"));
        assert!(root.contains(&"22".repeat(32)));

        let res = format!("{:?}", ContentId::resource(S, R, RK));
        assert!(res.contains("ContentId::Resource"));
        assert!(res.contains(&"33".repeat(32)));
    }
}
