# dig-dht

A Kademlia DHT with **provider records** for the DIG Node peer network. It answers exactly one
question for a DIG Node: **"which peers hold this content?"** A node that holds a store / capsule /
root / resource PUTs a provider record keyed by a content id; a node that wants that content runs an
iterative lookup and gets back the `peer_id`s of the holders (with candidate addresses). It then
connects to those peers over [`dig-nat`](https://github.com/DIG-Network/dig-nat) (mTLS,
`peer_id = SHA-256(TLS SPKI DER)`) and fetches the bytes over the L7 peer RPC
(`dig.getAvailability` → `dig.fetchRange`). **The DHT locates peers; dig-nat and the peer RPC move
the bytes.**

```rust
use std::sync::Arc;
use dig_dht::{DhtService, DhtConfig, ContentId, CandidateAddr, PeerId};

// One service per node: its id, the addresses it advertises, and a transport (over dig-nat).
let me = vec![CandidateAddr::direct("203.0.113.7", 9444)];
let dht = DhtService::new(local_id, me, DhtConfig::default(), transport);

// Join: seed the routing table from known peers (the dig-gossip pool / relay introducer).
dht.bootstrap(&bootstrap_peers).await?;

// I hold this capsule — advertise it so others can find me.
let capsule = ContentId::capsule(store_id, root);
dht.announce_provider(&capsule).await?;

// I want this capsule — who has it?
let providers = dht.find_providers(&capsule).await?;
for p in &providers {
    // Connect to p.provider_peer_id at p.addresses via dig-nat, then dig.fetchRange.
}
```

## What it is

Textbook Kademlia (Maymounkov & Mazières), specialized to DIG content discovery:

- **One 256-bit XOR keyspace** for both nodes and content. A node's key is its `peer_id` verbatim;
  a content key is `SHA-256` of its `ContentId`. Closeness is XOR distance.
- **256 k-buckets**, least-recently-seen ordered, with the standard ping-and-replace eviction
  (long-lived nodes are kept — they resist eviction attacks).
- **Iterative lookups** with α-parallelism, converging on the `k` closest peers to a target — one
  engine serves both `find_node` and `find_providers`.
- **Provider records** are the point: `(content_key, provider_peer_id, addresses, expires_at)`.
  Announced at the `k` nodes closest to the content key, **TTL'd**, and **republished** before
  expiry so offline providers age out automatically.

### Content granularities

A `ContentId` matches the L7 `dig.getAvailability` granularities, each a distinct (domain-separated)
key so their provider records never collide:

| Granularity | Constructor | Answers |
|---|---|---|
| store | `ContentId::store(store_id)` | does a peer serve this store? |
| root / capsule | `ContentId::root(store_id, root)` / `ContentId::capsule(...)` | does a peer have this generation `store_id:root`? |
| resource | `ContentId::resource(store_id, root, retrieval_key)` | does a peer have this resource in the capsule? |

## The four DHT RPC methods (wire)

The DHT RPC rides an authenticated dig-nat connection: each RPC opens a logical stream, writes a
`u32`-BE-length-prefixed JSON request, and reads the framed response (the same framing dig-nat uses
for its control messages). `type`-tagged JSON, aligned to the L7 peer-network style:

| Method | Request | Response |
|---|---|---|
| `find_node` | `{ "type":"find_node", "target":"<64hex>" }` | `{ "type":"nodes", "nodes":[Contact] }` |
| `find_providers` | `{ "type":"find_providers", "content_key":"<64hex>" }` | `{ "type":"providers", "providers":[ProviderRecord], "closer":[Contact] }` |
| `add_provider` | `{ "type":"add_provider", "record":ProviderRecord }` | `{ "type":"add_provider_ok" }` |
| `ping` | `{ "type":"ping", "nonce":<uint> }` | `{ "type":"pong", "nonce":<uint> }` |

where `Contact = { "peer_id":"<64hex>", "addresses":[{ "host":str, "port":uint, "kind":"direct"|"mapped"|"reflexive"|"relay" }] }`
and `ProviderRecord = { "content_key":"<64hex>", "provider_peer_id":"<64hex>", "addresses":[…], "expires_at":<unix-secs> }`
— the address shape is byte-compatible with the L7 `dig.getPeers` peers. A responder that cannot
answer returns `{ "type":"error", "code":uint, "message":str }` (advisory — a lookup treats it like
an unreachable peer).

## Public API

- `DhtService::new(local_id, local_addresses, config, transport)` — one service per node.
- `bootstrap(&[BootstrapPeer])` — seed the routing table + self-lookup (safe to re-call).
- `find_providers(&ContentId) -> Vec<ProviderRecord>` — who holds this content.
- `announce_provider(&ContentId) -> usize` — PUT a record for content THIS node holds.
- `withdraw_provider(&ContentId) -> bool` — stop announcing (record ages out via TTL).
- `find_node(&PeerId) -> Vec<Contact>` — the `k` closest peers (routing primitive).
- `republish() / refresh_buckets() / gc()` — the maintenance loop (drive on the config intervals).
- `handle_request_from(caller, DhtRequest) -> DhtResponse` — the serving side (wire an inbound DHT
  stream to it; pass the mTLS-authenticated caller so the routing table populates bidirectionally).

The transport is abstracted behind the `DhtTransport` trait, so the whole lookup + provider
machinery is tested over an in-memory swarm harness (many virtual nodes in one process, **no real
network**).

## Integrating with a DIG Node

- **On content-want** (a user asks for `store_id[:root]` / a resource): build the matching
  `ContentId`, call `find_providers`, then connect to each returned provider over dig-nat and fetch
  via `dig.getAvailability` + `dig.fetchRange`.
- **On inventory-change** (the node gains/loses content it serves): call `announce_provider` for
  each new content id, `withdraw_provider` for what it no longer holds. Drive `republish` on the
  config's `republish_interval` so records never expire while online.
- **Bootstrap** from the node's existing discovery (the dig-gossip peer pool / the relay
  introducer) — pass them as `BootstrapPeer`s. The crate never hard-depends on a live relay.
- **Serving** — wire inbound DHT streams to `handle_request_from`, supplying the caller's
  mTLS-verified `Contact` so every inbound RPC teaches the node about the caller.

## License

Apache-2.0 OR MIT.
