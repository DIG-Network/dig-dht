//! # dig-dht — a Kademlia DHT with provider records for the DIG Node peer network
//!
//! The DHT answers exactly one question for a DIG Node: **"which peers hold this content?"** A node
//! that holds a store / capsule / root / resource PUTs a **provider record** keyed by a
//! [`ContentId`]; a node that wants that content runs an iterative [`find_providers`] lookup and
//! gets back the set of holder `peer_id`s (with candidate addresses). It then connects to those
//! peers over [`dig_nat`] (mTLS, `peer_id = SHA-256(TLS SPKI DER)`) and fetches the bytes over the
//! **L7 peer RPC** (`dig.getAvailability` → `dig.fetchRange`). The DHT *locates* peers; dig-nat and
//! the peer RPC *move the bytes*.
//!
//! [`find_providers`]: DhtService::find_providers
//!
//! ## The Kademlia core
//!
//! Nodes and content share one 256-bit XOR-metric keyspace ([`Key`]): a node's key is its `peer_id`
//! verbatim, and a content key is the SHA-256 of its [`ContentId`]. Closeness is XOR distance, and
//! the routing table is 256 [`k-buckets`](routing::RoutingTable) keyed by the shared-prefix length
//! between this node and a peer. Lookups are **iterative** with α-parallelism, converging on the
//! `k` closest peers to a target ([`lookup`]). This is textbook Kademlia (Maymounkov & Mazières).
//!
//! ## Provider records (the point)
//!
//! [`announce_provider`](DhtService::announce_provider) PUTs a [`ProviderRecord`] at the `k` nodes
//! closest to the content key (and stores it locally); [`find_providers`](DhtService::find_providers)
//! walks toward the key and collects the providers found along the way. Records are **TTL'd** and
//! **republished** before expiry, so a provider that goes offline ages out automatically.
//!
//! ## Transport — riding dig-nat
//!
//! The four DHT RPC methods (`find_node`, `find_providers`, `add_provider`, `ping`) ride an
//! authenticated dig-nat [`PeerConnection`](dig_nat::PeerConnection): each RPC opens a logical
//! stream, writes a length-prefixed JSON [`wire`] request, and reads a length-prefixed JSON
//! response. The transport is abstracted behind the [`DhtTransport`] trait so the whole lookup +
//! provider machinery is tested over an **in-memory harness** (many virtual nodes in one process,
//! no real network).
//!
//! ## Bootstrap + maintenance
//!
//! A node seeds its routing table from bootstrap peers (the dig-gossip peer pool / relay introducer,
//! supplied as input — the crate never hard-depends on a live relay) and keeps it fresh with a
//! periodic self-lookup and per-bucket refresh.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod content;
pub mod error;
pub mod key;
pub mod lookup;
pub mod provider_store;
pub mod record;
pub mod routing;
pub mod service;
pub mod transport;
pub mod wire;

pub use config::DhtConfig;
pub use content::ContentId;
pub use error::DhtError;
pub use key::{Distance, Key};
pub use record::{AddressKind, CandidateAddr, ProviderRecord};
pub use routing::{Contact, RoutingTable};
pub use service::{BootstrapPeer, DhtService};
pub use transport::DhtTransport;
pub use wire::{DhtRequest, DhtResponse};

// Re-export the peer identity from dig-nat so consumers use ONE `PeerId` type across the transport
// and the DHT (no divergent shape).
pub use dig_nat::PeerId;
