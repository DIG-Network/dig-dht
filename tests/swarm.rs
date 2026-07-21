//! End-to-end DHT swarm tests: many virtual [`DhtService`] nodes wired together through an
//! **async in-memory transport** (no sockets, no real network), exercising the full stack —
//! bootstrap, iterative `find_node`, `announce_provider` → `find_providers` roundtrip across
//! multiple hops, provider TTL expiry + republish, ping liveness eviction, and the
//! no-providers → closer-peers fallback.
//!
//! ## The harness
//!
//! [`SwarmRouter`] maps each node's `peer_id` to that node's `DhtService`; the [`RouterTransport`]
//! each node holds dispatches an outbound `rpc(peer, req)` to the target node's async
//! `handle_request` (or fails if the peer is marked offline). This is the production topology in
//! miniature: every node is both a client (running lookups over its transport) and a server
//! (answering inbound RPCs via `handle_request`) — just with the mTLS dig-nat hop replaced by a
//! direct in-process call.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use dig_dht::routing::Contact;
use dig_dht::transport::DhtTransport;
use dig_dht::wire::{DhtRequest, DhtResponse};
use dig_dht::{BootstrapPeer, CandidateAddr, ContentId, DhtConfig, DhtError, DhtService, PeerId};

/// The shared swarm: `peer_id` (64-hex) → that node's service, plus an offline set.
#[derive(Clone, Default)]
struct SwarmRouter {
    nodes: Arc<RwLock<HashMap<String, Arc<DhtService>>>>,
    offline: Arc<RwLock<HashMap<String, ()>>>,
}

impl SwarmRouter {
    fn new() -> Self {
        SwarmRouter::default()
    }

    async fn add(&self, service: Arc<DhtService>) {
        self.nodes
            .write()
            .await
            .insert(service.local_id().to_hex(), service);
    }

    async fn set_offline(&self, peer_id: &str) {
        self.offline.write().await.insert(peer_id.to_string(), ());
    }

    fn transport(&self) -> Arc<dyn DhtTransport> {
        Arc::new(RouterTransport {
            router: self.clone(),
        })
    }
}

/// A [`DhtTransport`] that routes an outbound RPC to the target node's async `handle_request`.
struct RouterTransport {
    router: SwarmRouter,
}

#[async_trait]
impl DhtTransport for RouterTransport {
    async fn rpc(
        &self,
        from: &Contact,
        peer: &Contact,
        request: &DhtRequest,
    ) -> Result<DhtResponse, DhtError> {
        if self.router.offline.read().await.contains_key(&peer.peer_id) {
            return Err(DhtError::transport("offline"));
        }
        // Round-trip through the wire framing so the e2e path also exercises encode/decode.
        let encoded = request.encode();
        let mut cur = std::io::Cursor::new(encoded);
        let decoded = DhtRequest::decode(&mut cur)
            .await
            .map_err(DhtError::transport)?;
        let service = {
            let nodes = self.router.nodes.read().await;
            nodes.get(&peer.peer_id).cloned()
        };
        match service {
            Some(s) => {
                // The transport is authenticated: the responder learns the caller (`from`) as the
                // mTLS-verified identity — this is what populates routing tables bidirectionally.
                let resp = s.handle_request_from(Some(from.clone()), decoded).await;
                let mut rcur = std::io::Cursor::new(resp.encode());
                DhtResponse::decode(&mut rcur)
                    .await
                    .map_err(DhtError::transport)
            }
            None => Err(DhtError::transport("no route")),
        }
    }
}

/// Deterministic peer id from a seed byte pair (distinct top bytes → distinct keyspace positions).
fn pid(hi: u8, lo: u8) -> PeerId {
    let mut b = [0u8; 32];
    b[0] = hi;
    b[1] = lo;
    PeerId::from_bytes(b)
}

fn addr() -> Vec<CandidateAddr> {
    vec![CandidateAddr::direct("203.0.113.1", 9444)]
}

/// Build a service for `id` on `router` (default config), register it, and return it.
async fn make_node(router: &SwarmRouter, id: PeerId, config: DhtConfig) -> Arc<DhtService> {
    let svc = Arc::new(DhtService::new(id, addr(), config, router.transport()));
    router.add(svc.clone()).await;
    svc
}

fn bootstrap_of(svc: &DhtService) -> BootstrapPeer {
    BootstrapPeer {
        peer_id: *svc.local_id(),
        addresses: addr(),
    }
}

/// Wire a fully-connected-ish swarm: every node bootstraps off node 0, so knowledge propagates.
async fn build_swarm(router: &SwarmRouter, n: u8, config: &DhtConfig) -> Vec<Arc<DhtService>> {
    let mut nodes = Vec::new();
    for i in 0..n {
        let svc = make_node(
            router,
            pid(i.wrapping_mul(7).wrapping_add(1), i),
            config.clone(),
        )
        .await;
        nodes.push(svc);
    }
    // Bootstrap each node off the first few nodes so the routing tables populate.
    let seeds: Vec<BootstrapPeer> = nodes.iter().take(3).map(|s| bootstrap_of(s)).collect();
    for svc in &nodes {
        svc.bootstrap(&seeds).await.unwrap();
    }
    // A second bootstrap round lets tables fill from the first round's discoveries.
    for svc in &nodes {
        svc.bootstrap(&seeds).await.unwrap();
    }
    nodes
}

#[tokio::test]
async fn announce_then_find_providers_roundtrip() {
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 15, &config).await;

    // Node 7 holds a capsule and announces it.
    let holder = &nodes[7];
    let content = ContentId::capsule([0x42; 32], [0x24; 32]);
    let accepted = holder.announce_provider(&content).await.unwrap();
    assert!(accepted > 0, "announce must PUT the record at some peers");

    // A DIFFERENT node (node 2) looks up the providers and finds node 7.
    let seeker = &nodes[2];
    let providers = seeker.find_providers(&content).await.unwrap();
    assert_eq!(providers.len(), 1, "exactly the one holder");
    assert_eq!(
        providers[0].provider_peer_id,
        holder.local_id().to_hex(),
        "the provider must be the announcing node"
    );
    // The record carries a dialable address so the seeker can fetch over the peer RPC.
    assert!(providers[0].best_address().is_some());
}

#[tokio::test]
async fn find_providers_returns_all_distinct_holders() {
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 15, &config).await;

    let content = ContentId::store([0x99; 32]);
    // Three different nodes hold the same store.
    nodes[3].announce_provider(&content).await.unwrap();
    nodes[8].announce_provider(&content).await.unwrap();
    nodes[11].announce_provider(&content).await.unwrap();

    let providers = nodes[1].find_providers(&content).await.unwrap();
    let holder_ids: std::collections::HashSet<String> = providers
        .iter()
        .map(|p| p.provider_peer_id.clone())
        .collect();
    assert!(holder_ids.contains(&nodes[3].local_id().to_hex()));
    assert!(holder_ids.contains(&nodes[8].local_id().to_hex()));
    assert!(holder_ids.contains(&nodes[11].local_id().to_hex()));
    assert_eq!(holder_ids.len(), 3, "all three distinct holders, deduped");
}

#[tokio::test]
async fn find_node_converges_across_the_swarm() {
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 20, &config).await;

    // Look up a target peer id that exists in the swarm from a node that may not directly know it.
    let target = *nodes[17].local_id();
    let found = nodes[0].find_node(&target).await.unwrap();
    let ids: std::collections::HashSet<String> = found.iter().map(|c| c.peer_id.clone()).collect();
    assert!(
        ids.contains(&target.to_hex()),
        "iterative find_node must locate the target peer across hops"
    );
}

#[tokio::test]
async fn no_providers_returns_empty_not_error() {
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 10, &config).await;

    // Content nobody announced.
    let content = ContentId::resource([0x01; 32], [0x02; 32], [0x03; 32]);
    let providers = nodes[4].find_providers(&content).await.unwrap();
    assert!(
        providers.is_empty(),
        "unknown content → empty provider set (not an error)"
    );
}

#[tokio::test]
async fn find_providers_with_no_peers_is_not_an_error() {
    // A lone, un-bootstrapped node: find_providers returns its local (empty) view, not NoPeers.
    let router = SwarmRouter::new();
    let solo = make_node(&router, pid(0xAA, 0), DhtConfig::default()).await;
    let content = ContentId::store([0x77; 32]);
    let providers = solo.find_providers(&content).await.unwrap();
    assert!(providers.is_empty());
}

#[tokio::test]
async fn find_node_with_no_peers_errors() {
    let router = SwarmRouter::new();
    let solo = make_node(&router, pid(0xBB, 0), DhtConfig::default()).await;
    let err = solo.find_node(&pid(0xCC, 0)).await;
    assert!(matches!(err, Err(DhtError::NoPeers)));
}

#[tokio::test]
async fn provider_record_ttl_expires_then_republish_restores() {
    // Short TTL so expiry is observable within the test without real waiting: we drive time via the
    // stored expiry. Use a config whose TTL is tiny; the holder's local record + remote records all
    // carry expires_at = now + ttl.
    let router = SwarmRouter::new();
    // records expire immediately (0-second TTL) so expiry is observable without real waiting
    let config = DhtConfig {
        provider_ttl: std::time::Duration::from_secs(0),
        ..Default::default()
    };
    let nodes = build_swarm(&router, 12, &config).await;

    let content = ContentId::capsule([0x55; 32], [0x66; 32]);
    nodes[5].announce_provider(&content).await.unwrap();

    // With a 0-second TTL, the record is already expired → find returns nothing.
    let providers = nodes[1].find_providers(&content).await.unwrap();
    assert!(
        providers.is_empty(),
        "expired provider records must not be returned"
    );

    // GC drops the expired records everywhere.
    for svc in &nodes {
        svc.gc().await;
    }

    // Now give the holder a healthy TTL and republish → providers are findable again.
    let router2 = SwarmRouter::new();
    let good_config = DhtConfig::default();
    let nodes2 = build_swarm(&router2, 12, &good_config).await;
    nodes2[5].announce_provider(&content).await.unwrap();
    let republished = nodes2[5].republish().await;
    assert_eq!(republished, 1, "the one announced key is republished");
    let providers2 = nodes2[1].find_providers(&content).await.unwrap();
    assert_eq!(providers2.len(), 1, "republished record is findable");
}

#[tokio::test]
async fn ping_liveness_evicts_dead_peer() {
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 8, &config).await;

    let pinger = &nodes[0];
    // Pick a peer the pinger knows.
    let target_key = dig_dht::Key::from_peer_id(nodes[3].local_id());
    let known = pinger.known_closest(&target_key).await;
    let victim = known
        .iter()
        .find(|c| c.peer_id == nodes[3].local_id().to_hex())
        .cloned()
        .expect("pinger should know node 3 after bootstrap");

    // Alive peer → ping succeeds, stays in table.
    assert!(pinger.ping(&victim).await, "live peer answers ping");
    let before = pinger.routing_len().await;

    // Mark it offline → ping fails → evicted.
    router.set_offline(&victim.peer_id).await;
    assert!(!pinger.ping(&victim).await, "offline peer fails ping");
    let after = pinger.routing_len().await;
    assert_eq!(
        after,
        before - 1,
        "failed-ping peer is evicted from the routing table"
    );
}

#[tokio::test]
async fn serving_side_find_providers_returns_closer_when_no_providers() {
    // Directly exercise handle_request: a node with peers but no providers for the key returns the
    // closer contacts so a lookup can walk on (the no-providers → closer-peers fallback).
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 10, &config).await;

    let key = ContentId::store([0xEE; 32]).to_key();
    let resp = nodes[0]
        .handle_request(DhtRequest::FindProviders {
            content_key: key.to_hex(),
        })
        .await;
    match resp {
        DhtResponse::Providers { providers, closer } => {
            assert!(providers.is_empty(), "no providers announced for this key");
            assert!(
                !closer.is_empty(),
                "must return closer peers to continue the walk"
            );
        }
        other => panic!("expected Providers, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_buckets_runs_over_populated_buckets() {
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 12, &config).await;
    // After bootstrap, node 0 has populated buckets → refresh visits them without error.
    let refreshed = nodes[0].refresh_buckets().await;
    assert!(refreshed > 0, "at least one populated bucket to refresh");
}

#[tokio::test]
async fn add_provider_over_global_capacity_is_rejected_not_stored() {
    // HIGH #1 (SECURITY_AUDIT_P2P.md #179): a single peer flooding add_provider for many distinct
    // content keys must be rejected once the responder's global provider-store ceiling is hit,
    // rather than accepted unconditionally (unbounded growth / OOM).
    let router = SwarmRouter::new();
    let config = DhtConfig {
        provider_store_limits: dig_dht::provider_store::ProviderStoreLimits {
            max_providers_per_key: 20,
            max_total_records: 2,
        },
        ..Default::default()
    };
    let victim = make_node(&router, pid(0x10, 0), config).await;

    let mk_record = |tag: u8| {
        dig_dht::ProviderRecord::new(
            &dig_dht::ContentId::store([tag; 32]).to_key(),
            &pid(0x20, tag),
            addr(),
            u64::MAX,
        )
    };

    // First two distinct-key announces are accepted (under the cap).
    let ok1 = victim
        .handle_request(DhtRequest::AddProvider {
            record: mk_record(1),
        })
        .await;
    assert_eq!(ok1, DhtResponse::AddProviderOk);
    let ok2 = victim
        .handle_request(DhtRequest::AddProvider {
            record: mk_record(2),
        })
        .await;
    assert_eq!(ok2, DhtResponse::AddProviderOk);

    // Third distinct key exceeds the global ceiling → rejected, not stored.
    let rejected = victim
        .handle_request(DhtRequest::AddProvider {
            record: mk_record(3),
        })
        .await;
    match rejected {
        DhtResponse::Error { .. } => {}
        other => panic!("expected an over-capacity Error response, got {other:?}"),
    }

    // Confirm the rejected record was never actually stored.
    let key3 = dig_dht::ContentId::store([3u8; 32]).to_key();
    let resp = victim
        .handle_request(DhtRequest::FindProviders {
            content_key: key3.to_hex(),
        })
        .await;
    match resp {
        DhtResponse::Providers { providers, .. } => {
            assert!(providers.is_empty(), "rejected record must not be stored")
        }
        other => panic!("expected Providers, got {other:?}"),
    }
}

#[tokio::test]
async fn add_provider_with_malicious_expiry_is_clamped_to_local_ttl() {
    // HIGH #2 (SECURITY_AUDIT_P2P.md #179): an inbound add_provider naming expires_at = u64::MAX
    // must NOT be stored verbatim, or the record never GCs for the process lifetime. The responder
    // MUST clamp it to `now + its own provider_ttl`.
    let router = SwarmRouter::new();
    let short_ttl = std::time::Duration::from_secs(60);
    let config = DhtConfig {
        provider_ttl: short_ttl,
        ..Default::default()
    };
    let victim = make_node(&router, pid(0x11, 0), config).await;

    let content = ContentId::store([0x77; 32]);
    let malicious = dig_dht::ProviderRecord::new(
        &content.to_key(),
        &pid(0x22, 0),
        addr(),
        u64::MAX, // attacker asks for "never expires"
    );
    let resp = victim
        .handle_request(DhtRequest::AddProvider { record: malicious })
        .await;
    assert_eq!(resp, DhtResponse::AddProviderOk);

    // Read back via the wire-facing find_providers path (not a private field) — the stored record
    // must report an expires_at bounded by now + provider_ttl, nowhere near u64::MAX.
    let key = content.to_key();
    let resp = victim
        .handle_request(DhtRequest::FindProviders {
            content_key: key.to_hex(),
        })
        .await;
    let stored = match resp {
        DhtResponse::Providers { providers, .. } => providers,
        other => panic!("expected Providers, got {other:?}"),
    };
    assert_eq!(stored.len(), 1);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        stored[0].expires_at <= now + short_ttl.as_secs() + 5, // small margin for test wall-clock
        "malicious expires_at must be clamped to local TTL, got {}",
        stored[0].expires_at
    );
    assert!(
        stored[0].expires_at < u64::MAX / 2,
        "clamp must actually bound the value, not just leave it near u64::MAX"
    );
}

#[tokio::test]
async fn add_provider_with_unbounded_addresses_is_capped_at_the_boundary() {
    // MEDIUM (SECURITY_AUDIT_P2P.md #179): a ProviderRecord built directly (as a wire decode
    // would, bypassing ProviderRecord::new's own cap since its fields are public) with thousands
    // of addresses must still be capped by the responder before storage.
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let victim = make_node(&router, pid(0x13, 0), config).await;

    let content = ContentId::store([0x88; 32]);
    let flood: Vec<CandidateAddr> = (0..2000)
        .map(|i| CandidateAddr::direct(format!("203.0.113.{}", i % 255), 9444))
        .collect();
    // Constructed as a raw struct literal — exactly what a `serde_json::from_slice` wire decode
    // would produce, bypassing `ProviderRecord::new`.
    let malicious = dig_dht::ProviderRecord {
        content_key: content.to_key().to_hex(),
        provider_peer_id: pid(0x24, 0).to_hex(),
        addresses: flood,
        expires_at: u64::MAX,
    };
    let resp = victim
        .handle_request(DhtRequest::AddProvider { record: malicious })
        .await;
    assert_eq!(resp, DhtResponse::AddProviderOk);

    let key = content.to_key();
    let resp = victim
        .handle_request(DhtRequest::FindProviders {
            content_key: key.to_hex(),
        })
        .await;
    let stored = match resp {
        DhtResponse::Providers { providers, .. } => providers,
        other => panic!("expected Providers, got {other:?}"),
    };
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].addresses.len(),
        dig_dht::record::MAX_ADDRESSES_PER_RECORD,
        "stored record's address list must be capped, not the raw flood"
    );
}

#[tokio::test]
async fn add_provider_naming_a_third_party_provider_is_rejected() {
    // LOW (SECURITY_AUDIT_P2P.md #179): an authenticated caller announcing a record whose
    // provider_peer_id is a DIFFERENT peer (unsigned, self-asserted) is provider-set poisoning —
    // it lets a caller point finders at an arbitrary third-party address for content that peer
    // never actually announced. The responder must reject unless caller == provider_peer_id.
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let victim = make_node(&router, pid(0x30, 0), config).await;

    let caller = Contact::new(&pid(0x31, 0), addr());
    let third_party = pid(0x32, 0); // NOT the caller
    let content = ContentId::store([0x55; 32]);
    let record = dig_dht::ProviderRecord::new(&content.to_key(), &third_party, addr(), u64::MAX);

    let resp = victim
        .handle_request_from(Some(caller), DhtRequest::AddProvider { record })
        .await;
    match resp {
        DhtResponse::Error { .. } => {}
        other => panic!("expected an Error response for third-party announce, got {other:?}"),
    }

    // Confirm it was never stored.
    let key = content.to_key();
    let resp = victim
        .handle_request(DhtRequest::FindProviders {
            content_key: key.to_hex(),
        })
        .await;
    match resp {
        DhtResponse::Providers { providers, .. } => assert!(
            providers.is_empty(),
            "third-party-named record must not be stored"
        ),
        other => panic!("expected Providers, got {other:?}"),
    }
}

#[tokio::test]
async fn add_provider_self_announce_is_accepted() {
    // The common case: caller announces ITS OWN peer_id as the provider — must still work.
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let victim = make_node(&router, pid(0x33, 0), config).await;

    let announcer_id = pid(0x34, 0);
    let caller = Contact::new(&announcer_id, addr());
    let content = ContentId::store([0x56; 32]);
    let record = dig_dht::ProviderRecord::new(&content.to_key(), &announcer_id, addr(), u64::MAX);

    let resp = victim
        .handle_request_from(Some(caller), DhtRequest::AddProvider { record })
        .await;
    assert_eq!(resp, DhtResponse::AddProviderOk);
}

#[tokio::test]
async fn add_provider_with_no_authenticated_caller_is_still_accepted() {
    // handle_request (no caller supplied, e.g. a transport that cannot authenticate) must keep
    // working -- the caller==provider check only applies when a caller identity IS available.
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let victim = make_node(&router, pid(0x35, 0), config).await;

    let content = ContentId::store([0x57; 32]);
    let record = dig_dht::ProviderRecord::new(&content.to_key(), &pid(0x36, 0), addr(), u64::MAX);
    let resp = victim
        .handle_request(DhtRequest::AddProvider { record })
        .await;
    assert_eq!(resp, DhtResponse::AddProviderOk);
}

#[tokio::test]
async fn find_providers_discovers_a_stranger_purely_via_iterative_lookup() {
    // Regression guard for the DISTRIBUTED property (the engine of #1394/#1423): a seeker that has
    // received NO announce/gossip from the holder — its local provider store is empty for the key —
    // must still DISCOVER the holder purely by walking the iterative Kademlia lookup toward the
    // content key. Proves fetch-from-strangers is real, not a same-node local-store artifact.
    let router = SwarmRouter::new();
    // Small `k` so `announce_provider` PUTs the record at only a FEW closest peers — guaranteeing
    // some node in the swarm did NOT receive it locally and can act as a genuine stranger seeker.
    let config = DhtConfig {
        k: 4,
        ..Default::default()
    };
    let nodes = build_swarm(&router, 20, &config).await;

    let holder = &nodes[9];
    let content = ContentId::capsule([0xA1; 32], [0xB2; 32]);
    let accepted = holder.announce_provider(&content).await.unwrap();
    assert!(accepted > 0, "announce must PUT the record at some peers");

    // Find a seeker that holds NOTHING locally for this key — anything it returns therefore came
    // from the network walk, not a local short-circuit.
    let key = content.to_key();
    let mut seeker = None;
    for n in &nodes {
        if n.local_id() == holder.local_id() {
            continue;
        }
        let local_only = n
            .handle_request(DhtRequest::FindProviders {
                content_key: key.to_hex(),
            })
            .await;
        if let DhtResponse::Providers { providers, .. } = local_only {
            if providers.is_empty() {
                seeker = Some(n);
                break;
            }
        }
    }
    let seeker = seeker.expect("a stranger node with no local record for the key must exist");

    let found = seeker.find_providers(&content).await.unwrap();
    assert_eq!(
        found.len(),
        1,
        "the stranger holder is discovered via lookup"
    );
    assert_eq!(found[0].provider_peer_id, holder.local_id().to_hex());
}

#[tokio::test]
async fn ingest_verified_provider_bypasses_self_announce_but_still_clamps_and_caps() {
    // SPEC §6.5: the authenticated-ingest path stores a THIRD-PARTY record (provider != this node,
    // no mTLS self-announce match) — proving the identity-check bypass — yet still clamps the TTL
    // and caps the address list.
    use dig_dht::provider_store::PutOutcome;

    let router = SwarmRouter::new();
    let short_ttl = std::time::Duration::from_secs(60);
    let config = DhtConfig {
        provider_ttl: short_ttl,
        ..Default::default()
    };
    let node = make_node(&router, pid(0x40, 0), config).await;

    let content = ContentId::store([0xC1; 32]);
    let holder = pid(0x41, 0); // a THIRD party, NOT the ingesting node
    let flood: Vec<CandidateAddr> = (0..2000)
        .map(|i| CandidateAddr::direct(format!("203.0.113.{}", i % 255), 9444))
        .collect();
    let record = dig_dht::ProviderRecord {
        content_key: content.to_key().to_hex(),
        provider_peer_id: holder.to_hex(),
        addresses: flood,
        expires_at: u64::MAX, // "never expires"
    };

    let outcome = node.ingest_verified_provider(record).await;
    assert_eq!(outcome, PutOutcome::Accepted, "third-party ingest accepted");

    // Read back via the wire-facing path: stored despite provider != node (bypass), TTL clamped,
    // addresses capped.
    let resp = node
        .handle_request(DhtRequest::FindProviders {
            content_key: content.to_key().to_hex(),
        })
        .await;
    let stored = match resp {
        DhtResponse::Providers { providers, .. } => providers,
        other => panic!("expected Providers, got {other:?}"),
    };
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].provider_peer_id, holder.to_hex());
    assert_eq!(
        stored[0].addresses.len(),
        dig_dht::record::MAX_ADDRESSES_PER_RECORD,
        "ingested address list must be capped"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        stored[0].expires_at <= now + short_ttl.as_secs() + 5,
        "ingested expires_at must be clamped to local TTL, got {}",
        stored[0].expires_at
    );
}

#[tokio::test]
async fn ingest_verified_provider_still_rejects_over_global_capacity() {
    // SPEC §6.5: bypassing the identity check does NOT bypass admission control — a global-cap
    // overflow is still rejected and stores nothing.
    use dig_dht::provider_store::{ProviderStoreLimits, PutOutcome};

    let router = SwarmRouter::new();
    let config = DhtConfig {
        provider_store_limits: ProviderStoreLimits {
            max_providers_per_key: 20,
            max_total_records: 1,
        },
        ..Default::default()
    };
    let node = make_node(&router, pid(0x42, 0), config).await;

    let mk = |tag: u8| dig_dht::ProviderRecord {
        content_key: ContentId::store([tag; 32]).to_key().to_hex(),
        provider_peer_id: pid(0x43, tag).to_hex(),
        addresses: addr(),
        expires_at: u64::MAX,
    };
    assert_eq!(
        node.ingest_verified_provider(mk(1)).await,
        PutOutcome::Accepted
    );
    assert_eq!(
        node.ingest_verified_provider(mk(2)).await,
        PutOutcome::RejectedOverCapacity,
        "ingest over the global ceiling must be rejected"
    );
}

#[tokio::test]
async fn remove_provider_record_removes_only_the_named_signer() {
    // SPEC §6.6: an authenticated retract removes exactly the (key, signer) record and leaves other
    // providers of the same key intact (censorship-resistance).
    let router = SwarmRouter::new();
    let node = make_node(&router, pid(0x44, 0), DhtConfig::default()).await;

    let content = ContentId::store([0xD1; 32]);
    let key_hex = content.to_key().to_hex();
    let holder_a = pid(0x45, 0);
    let holder_b = pid(0x46, 0);
    for h in [&holder_a, &holder_b] {
        let rec = dig_dht::ProviderRecord::new(&content.to_key(), h, addr(), u64::MAX);
        node.ingest_verified_provider(rec).await;
    }

    assert!(
        node.remove_provider_record(&key_hex, &holder_a.to_hex())
            .await,
        "the named record is removed"
    );
    assert!(
        !node
            .remove_provider_record(&key_hex, &holder_a.to_hex())
            .await,
        "removing an already-gone record returns false"
    );

    let resp = node
        .handle_request(DhtRequest::FindProviders {
            content_key: key_hex.clone(),
        })
        .await;
    match resp {
        DhtResponse::Providers { providers, .. } => {
            assert_eq!(providers.len(), 1, "the other holder survives the retract");
            assert_eq!(providers[0].provider_peer_id, holder_b.to_hex());
        }
        other => panic!("expected Providers, got {other:?}"),
    }
}

#[tokio::test]
async fn retract_own_provider_removes_self_from_find_providers_immediately() {
    // SPEC §6.6: the active own-retract deletes this node's local record now, so a solo node's
    // find_providers stops returning self immediately (the local-state half of #1423 evict+retract).
    let router = SwarmRouter::new();
    let solo = make_node(&router, pid(0x47, 0), DhtConfig::default()).await;
    let content = ContentId::capsule([0xE1; 32], [0xE2; 32]);

    solo.announce_provider(&content).await.unwrap();
    let before = solo.find_providers(&content).await.unwrap();
    assert_eq!(before.len(), 1, "self is a provider after announce");
    assert_eq!(before[0].provider_peer_id, solo.local_id().to_hex());

    assert!(
        solo.retract_own_provider(&content).await,
        "was providing → true"
    );
    let after = solo.find_providers(&content).await.unwrap();
    assert!(
        after.is_empty(),
        "self must be gone from find_providers immediately after retract"
    );
    // Republish now has nothing to do (announcement was unmarked too).
    assert_eq!(solo.republish().await, 0);
    assert!(
        !solo.retract_own_provider(&content).await,
        "second retract → not providing"
    );
}

#[tokio::test]
async fn holders_of_returns_peer_ids_over_the_distributed_lookup() {
    // SPEC §6.5: the thin holder-set query returns exactly the holder peer_ids find_providers finds.
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 15, &config).await;

    let content = ContentId::store([0xF1; 32]);
    nodes[4].announce_provider(&content).await.unwrap();
    nodes[10].announce_provider(&content).await.unwrap();

    let holders = nodes[1].holders_of(&content).await.unwrap();
    let got: std::collections::HashSet<String> = holders.iter().map(|p| p.to_hex()).collect();
    assert!(got.contains(&nodes[4].local_id().to_hex()));
    assert!(got.contains(&nodes[10].local_id().to_hex()));
    assert_eq!(got.len(), 2, "exactly the two distinct holders, deduped");
}

#[tokio::test]
async fn withdraw_provider_stops_republish() {
    let router = SwarmRouter::new();
    let config = DhtConfig::default();
    let nodes = build_swarm(&router, 10, &config).await;
    let content = ContentId::store([0x33; 32]);
    nodes[6].announce_provider(&content).await.unwrap();
    assert!(nodes[6].withdraw_provider(&content).await, "was announced");
    assert!(
        !nodes[6].withdraw_provider(&content).await,
        "no longer announced"
    );
    // Republish now has nothing to do.
    assert_eq!(nodes[6].republish().await, 0);
}
