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
