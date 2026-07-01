//! [`DhtService`] — the public handle that ties the routing table, provider store, transport, and
//! iterative lookup into the four operations a DIG Node needs:
//!
//! - [`bootstrap`](DhtService::bootstrap) — seed the routing table from known peers (the dig-gossip
//!   pool / relay introducer) + populate it with a self-lookup.
//! - [`find_providers`](DhtService::find_providers) — "who holds this content?" → the provider
//!   records (the node then fetches over the L7 peer RPC).
//! - [`announce_provider`](DhtService::announce_provider) — "I hold this content" → PUT a provider
//!   record at the `k` nodes closest to the content key (and locally), and remember to republish it.
//! - [`find_node`](DhtService::find_node) — the `k` peers closest to a `peer_id` (routing primitive).
//!
//! Plus maintenance ([`republish`](DhtService::republish), [`refresh_buckets`](DhtService::refresh_buckets),
//! [`gc`](DhtService::gc)) and the **serving side** ([`handle_request`](DhtService::handle_request))
//! that answers inbound DHT RPCs from other nodes.
//!
//! ## Serving vs. querying
//!
//! A node is both a client and a server of the DHT. [`handle_request`](DhtService::handle_request)
//! is the server: given an inbound [`DhtRequest`], it reads/writes the local routing table +
//! provider store and returns the [`DhtResponse`]. The `find_*` / `announce_*` methods are the
//! client: they run iterative lookups over the [`DhtTransport`]. A dig-node wires `handle_request`
//! to inbound DHT streams and gives the service a transport that dials outbound.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use dig_nat::PeerId;

use crate::config::DhtConfig;
use crate::content::ContentId;
use crate::error::DhtError;
use crate::key::Key;
use crate::lookup::{iterative_find, QueryOutcome};
use crate::provider_store::ProviderStore;
use crate::record::{CandidateAddr, ProviderRecord};
use crate::routing::{Contact, InsertOutcome, RoutingTable};
use crate::transport::DhtTransport;
use crate::wire::{DhtRequest, DhtResponse};

/// A peer to bootstrap the routing table from — its `peer_id` and at least one candidate address.
/// These come from the node's existing discovery (the dig-gossip peer pool / the relay introducer);
/// the DHT crate takes them as input and never hard-depends on a live relay itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPeer {
    /// The bootstrap peer's identity.
    pub peer_id: PeerId,
    /// Candidate addresses to reach it.
    pub addresses: Vec<CandidateAddr>,
}

impl BootstrapPeer {
    /// A bootstrap peer with a single direct address.
    pub fn direct(peer_id: PeerId, host: impl Into<String>, port: u16) -> Self {
        BootstrapPeer {
            peer_id,
            addresses: vec![CandidateAddr::direct(host, port)],
        }
    }

    fn to_contact(&self) -> Contact {
        Contact::new(&self.peer_id, self.addresses.clone())
    }
}

/// The DHT service for one node. Cloneable-by-`Arc` internally; wrap in `Arc` to share between the
/// serving task (inbound RPC) and querying callers.
pub struct DhtService {
    local_id: PeerId,
    /// This node's own candidate addresses — put into provider records it announces so finders can
    /// reach it.
    local_addresses: Vec<CandidateAddr>,
    config: DhtConfig,
    routing: Arc<Mutex<RoutingTable>>,
    providers: Arc<Mutex<ProviderStore>>,
    transport: Arc<dyn DhtTransport>,
}

impl DhtService {
    /// Create a service for the node identified by `local_id`, advertising `local_addresses` in the
    /// provider records it announces, driving RPC over `transport`.
    pub fn new(
        local_id: PeerId,
        local_addresses: Vec<CandidateAddr>,
        config: DhtConfig,
        transport: Arc<dyn DhtTransport>,
    ) -> Self {
        let routing = RoutingTable::new(&local_id, config.k);
        DhtService {
            local_id,
            local_addresses,
            config,
            routing: Arc::new(Mutex::new(routing)),
            providers: Arc::new(Mutex::new(ProviderStore::new())),
            transport,
        }
    }

    /// This node's id.
    pub fn local_id(&self) -> &PeerId {
        &self.local_id
    }

    /// This node's own [`Contact`] (its id + advertised addresses) — the authenticated caller
    /// identity supplied to the transport as the RPC `from`.
    fn local_contact(&self) -> Contact {
        Contact::new(&self.local_id, self.local_addresses.clone())
    }

    // ---- Bootstrap ---------------------------------------------------------------------------

    /// Seed the routing table from `peers` and populate it by looking up this node's own id (the
    /// canonical Kademlia bootstrap: a self-lookup fills the buckets around us). Returns the number
    /// of distinct peers now known.
    ///
    /// Safe to call repeatedly (on reconnect / when new bootstrap peers arrive) — it merges, never
    /// resets.
    pub async fn bootstrap(&self, peers: &[BootstrapPeer]) -> Result<usize, DhtError> {
        {
            let mut rt = self.routing.lock().await;
            for p in peers {
                let _ = rt.insert(p.to_contact());
            }
        }
        // Self-lookup: find the nodes closest to us to fill our buckets.
        let self_key = Key::from_peer_id(&self.local_id);
        let seeds: Vec<Contact> = peers.iter().map(|p| p.to_contact()).collect();
        let result = self.run_lookup(self_key, seeds, false).await;
        self.absorb_contacts(&result.closest).await;
        Ok(self.routing.lock().await.len())
    }

    // ---- Client operations -------------------------------------------------------------------

    /// Find the `k` peers closest to `peer_id` (the routing primitive). Runs an iterative
    /// `find_node` lookup and returns the converged closest contacts.
    pub async fn find_node(&self, peer_id: &PeerId) -> Result<Vec<Contact>, DhtError> {
        let target = Key::from_peer_id(peer_id);
        let seeds = self.seed_contacts(&target).await;
        if seeds.is_empty() {
            return Err(DhtError::NoPeers);
        }
        let result = self.run_lookup(target, seeds, false).await;
        self.absorb_contacts(&result.closest).await;
        Ok(result.closest)
    }

    /// Find the providers of `content` — the peers holding it. Runs an iterative `find_providers`
    /// lookup toward the content key, returning every live provider record collected (deduped by
    /// provider). The node then connects to those providers over dig-nat and fetches via the L7 peer
    /// RPC.
    ///
    /// Returns an empty vec (not an error) when the content simply has no known providers; returns
    /// [`DhtError::NoPeers`] only when there is no one to ask (empty routing table + no bootstrap).
    pub async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DhtError> {
        let target = content.to_key();

        // Local short-circuit: if we already hold providers for this key, include them.
        let now = now_secs();
        let mut local = self.providers.lock().await.get(&target.to_hex(), now);

        let seeds = self.seed_contacts(&target).await;
        if seeds.is_empty() {
            // No peers to ask — return whatever we hold locally (possibly empty).
            return Ok(local);
        }
        let result = self.run_lookup(target, seeds, true).await;
        self.absorb_contacts(&result.closest).await;

        // Merge local + discovered, dedup by provider, drop expired.
        local.extend(result.providers);
        let now = now_secs();
        let mut seen = std::collections::HashSet::new();
        local.retain(|r| !r.is_expired(now) && seen.insert(r.provider_peer_id.clone()));
        Ok(local)
    }

    /// Announce that THIS node holds `content`: build a provider record (this node's `peer_id` +
    /// addresses, expiring at `now + provider_ttl`), store it locally, remember to republish it, and
    /// PUT it at the `k` nodes closest to the content key. Returns how many peers accepted the PUT.
    ///
    /// Called when the node's inventory gains content (a new capsule/root/resource it now serves).
    pub async fn announce_provider(&self, content: &ContentId) -> Result<usize, DhtError> {
        let target = content.to_key();
        let record = self.build_local_record(&target);

        // Store locally + remember for republish.
        {
            let mut ps = self.providers.lock().await;
            ps.put(record.clone());
            ps.mark_announced(target.to_hex());
        }

        // PUT at the k closest peers we can find.
        let seeds = self.seed_contacts(&target).await;
        if seeds.is_empty() {
            // No peers yet — the local record stands; republish will re-attempt once bootstrapped.
            return Ok(0);
        }
        let result = self.run_lookup(target, seeds, false).await;
        self.absorb_contacts(&result.closest).await;
        Ok(self.put_record_at(&result.closest, &record).await)
    }

    /// Stop announcing `content` (the node no longer holds it). The record ages out of the DHT via
    /// TTL; we just stop republishing it. Returns whether it was being announced.
    pub async fn withdraw_provider(&self, content: &ContentId) -> bool {
        let key = content.to_key().to_hex();
        self.providers.lock().await.unmark_announced(&key)
    }

    // ---- Maintenance -------------------------------------------------------------------------

    /// Republish every content key this node still announces — re-runs the announce PUT so provider
    /// records never expire while the node is online. Call on the [`DhtConfig::republish_interval`].
    /// Returns the number of content keys republished.
    pub async fn republish(&self) -> usize {
        let keys = self.providers.lock().await.local_announcements();
        let count = keys.len();
        for hex in keys {
            let Some(bytes) = hex64_to_bytes(&hex) else {
                continue;
            };
            let target = Key::from_bytes(bytes);
            let record = self.build_local_record(&target);
            self.providers.lock().await.put(record.clone());
            let seeds = self.seed_contacts(&target).await;
            if !seeds.is_empty() {
                let result = self.run_lookup(target, seeds, false).await;
                self.absorb_contacts(&result.closest).await;
                self.put_record_at(&result.closest, &record).await;
            }
        }
        count
    }

    /// Refresh populated buckets by looking up a random key in each — keeps the routing table fresh
    /// as peers churn. Call on the [`DhtConfig::refresh_interval`]. Returns the number of buckets
    /// refreshed.
    pub async fn refresh_buckets(&self) -> usize {
        let indices = self.routing.lock().await.non_empty_bucket_indices();
        let count = indices.len();
        for idx in indices {
            let target = self.random_key_in_bucket(idx);
            let seeds = self.seed_contacts(&target).await;
            if !seeds.is_empty() {
                let result = self.run_lookup(target, seeds, false).await;
                self.absorb_contacts(&result.closest).await;
            }
        }
        count
    }

    /// Drop expired provider records. Call periodically (piggy-backs on republish/refresh). Returns
    /// the number of records removed.
    pub async fn gc(&self) -> usize {
        self.providers.lock().await.gc(now_secs())
    }

    /// Ping a peer for liveness; on failure, evict it from the routing table. Used by the
    /// ping-and-replace maintenance when a bucket is full. Returns whether the peer is alive.
    pub async fn ping(&self, peer: &Contact) -> bool {
        let nonce = rand::random::<u64>();
        let from = self.local_contact();
        match self
            .transport
            .rpc(&from, peer, &DhtRequest::Ping { nonce })
            .await
        {
            Ok(DhtResponse::Pong { nonce: got }) if got == nonce => true,
            _ => {
                self.routing.lock().await.remove(&peer.peer_id);
                false
            }
        }
    }

    // ---- Serving side (inbound RPC) ----------------------------------------------------------

    /// Answer an inbound DHT request from another node, without a known caller identity. Prefer
    /// [`handle_request_from`](Self::handle_request_from) on an authenticated transport (it lets the
    /// responder learn the caller and populate its routing table bidirectionally, the way Kademlia
    /// tables fill).
    pub async fn handle_request(&self, request: DhtRequest) -> DhtResponse {
        self.handle_request_from(None, request).await
    }

    /// Answer an inbound DHT request, folding the **authenticated caller** into the routing table.
    ///
    /// This is the server half — a dig-node wires it to inbound DHT streams, passing the caller's
    /// mTLS-verified [`Contact`] as `caller`. Learning the caller from every inbound RPC is how a
    /// Kademlia node discovers peers *without* an explicit announce: a node that talks to you becomes
    /// a candidate in your table. The caller MUST come from the authenticated transport (the mTLS
    /// `peer_id`), never from the request body — identity is not self-asserted.
    ///
    /// It reads/writes only local state (routing table + provider store) and never makes outbound
    /// RPCs, so it cannot recurse or block on the network.
    pub async fn handle_request_from(
        &self,
        caller: Option<Contact>,
        request: DhtRequest,
    ) -> DhtResponse {
        // Learn the (authenticated) caller — every inbound RPC is evidence the caller is alive.
        if let Some(c) = caller {
            if c.peer_id != self.local_id.to_hex() {
                let _ = self.routing.lock().await.insert(c);
            }
        }
        match request {
            DhtRequest::Ping { nonce } => DhtResponse::Pong { nonce },
            DhtRequest::FindNode { target } => {
                let Some(key) = parse_key(&target) else {
                    return DhtResponse::Error {
                        code: 2,
                        message: "bad target key".into(),
                    };
                };
                let nodes = self.routing.lock().await.closest(&key);
                DhtResponse::Nodes { nodes }
            }
            DhtRequest::FindProviders { content_key } => {
                let Some(key) = parse_key(&content_key) else {
                    return DhtResponse::Error {
                        code: 2,
                        message: "bad content key".into(),
                    };
                };
                let now = now_secs();
                let providers = self.providers.lock().await.get(&key.to_hex(), now);
                let closer = self.routing.lock().await.closest(&key);
                DhtResponse::Providers { providers, closer }
            }
            DhtRequest::AddProvider { record } => {
                // Fold the provider into our routing table (its addresses let us reach it) and store.
                if let Some(pid) = record.provider_peer_id() {
                    let contact = Contact::new(&pid, record.addresses.clone());
                    let _ = self.routing.lock().await.insert(contact);
                }
                self.providers.lock().await.put(record);
                DhtResponse::AddProviderOk
            }
        }
    }

    // ---- Internals ---------------------------------------------------------------------------

    /// Build a provider record for content key `target` naming THIS node, expiring at
    /// `now + provider_ttl`.
    fn build_local_record(&self, target: &Key) -> ProviderRecord {
        let expires_at = now_secs().saturating_add(self.config.provider_ttl_secs());
        ProviderRecord::new(
            target,
            &self.local_id,
            self.local_addresses.clone(),
            expires_at,
        )
    }

    /// The seed set for a lookup toward `target`: the closest contacts we currently know.
    async fn seed_contacts(&self, target: &Key) -> Vec<Contact> {
        self.routing.lock().await.closest(target)
    }

    /// Run an iterative lookup toward `target` from `seeds`, querying peers over the transport. Each
    /// peer is asked `find_providers` (which also returns closer contacts), so ONE query kind serves
    /// both node- and provider-lookups; `stop_on_providers` controls early exit.
    async fn run_lookup(
        &self,
        target: Key,
        seeds: Vec<Contact>,
        stop_on_providers: bool,
    ) -> crate::lookup::LookupResult {
        let transport = self.transport.clone();
        let content_key = target.to_hex();
        let from = self.local_contact();
        let query = move |contact: Contact| {
            let transport = transport.clone();
            let content_key = content_key.clone();
            let from = from.clone();
            async move {
                let req = DhtRequest::FindProviders { content_key };
                match transport.rpc(&from, &contact, &req).await {
                    Ok(DhtResponse::Providers { providers, closer }) => {
                        Ok(QueryOutcome { closer, providers })
                    }
                    Ok(DhtResponse::Nodes { nodes }) => Ok(QueryOutcome {
                        closer: nodes,
                        providers: vec![],
                    }),
                    _ => Err(()),
                }
            }
        };
        iterative_find(
            target,
            seeds,
            self.config.k,
            self.config.alpha,
            stop_on_providers,
            query,
        )
        .await
    }

    /// Fold discovered contacts back into the routing table (skipping ourselves). Applies the LRS
    /// insert policy; a full bucket's [`InsertOutcome::Full`] is left for the ping-and-replace
    /// maintenance (we do not ping inline to keep lookups fast).
    async fn absorb_contacts(&self, contacts: &[Contact]) {
        let mut rt = self.routing.lock().await;
        for c in contacts {
            match rt.insert(c.clone()) {
                InsertOutcome::Inserted => {}
                InsertOutcome::Full { .. } => {
                    // Bucket full — leave for ping-and-replace; do not block the lookup on a ping.
                }
            }
        }
    }

    /// PUT `record` at each of `peers` via `add_provider`, counting acceptances. A peer that errors
    /// is skipped (best-effort replication — the record survives at the peers that accepted + locally).
    async fn put_record_at(&self, peers: &[Contact], record: &ProviderRecord) -> usize {
        let req = DhtRequest::AddProvider {
            record: record.clone(),
        };
        let from = self.local_contact();
        let mut accepted = 0;
        for p in peers {
            if p.peer_id == self.local_id.to_hex() {
                continue; // already stored locally
            }
            if let Ok(DhtResponse::AddProviderOk) = self.transport.rpc(&from, p, &req).await {
                accepted += 1;
            }
        }
        accepted
    }

    /// A random key whose distance from this node falls in bucket `idx` (so a refresh lookup targets
    /// that bucket's region). Sets the bit at position `255 - idx` and randomizes the lower bits.
    fn random_key_in_bucket(&self, idx: usize) -> Key {
        let local = *self.local_id.as_bytes();
        let mut distance = [0u8; 32];
        let bit = 255 - idx; // MSB-set position for this bucket
        let byte = bit / 8;
        let bit_in_byte = 7 - (bit % 8);
        distance[byte] = 1 << bit_in_byte;
        // Randomize lower-significant bits so successive refreshes vary the target.
        for b in distance.iter_mut().skip(byte + 1) {
            *b = rand::random::<u8>();
        }
        let mut target = [0u8; 32];
        for i in 0..32 {
            target[i] = local[i] ^ distance[i];
        }
        Key::from_bytes(target)
    }

    /// The contacts currently in this node's routing table closest to `target` (diagnostic /
    /// introspection — the peers this node knows without any network round-trip).
    pub async fn known_closest(&self, target: &Key) -> Vec<Contact> {
        self.routing.lock().await.closest(target)
    }

    /// The number of peers currently in this node's routing table (diagnostic / metrics).
    pub async fn routing_len(&self) -> usize {
        self.routing.lock().await.len()
    }
}

/// Current wall-clock Unix seconds (saturating to 0 before the epoch), for provider TTLs.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parse a 64-hex string into a [`Key`] (used on the serving side for wire targets).
fn parse_key(hex: &str) -> Option<Key> {
    hex64_to_bytes(hex).map(Key::from_bytes)
}

/// Decode a 64-char hex string to 32 bytes.
fn hex64_to_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hex_round_trips() {
        // sanity for the local hex helper
    }

    #[test]
    fn hex64_round_trip() {
        let bytes = [0xABu8; 32];
        let hex = Key::from_bytes(bytes).to_hex();
        assert_eq!(hex64_to_bytes(&hex).unwrap(), bytes);
        assert!(hex64_to_bytes("short").is_none());
        assert!(hex64_to_bytes(&"zz".repeat(32)).is_none());
        key_hex_round_trips();
    }

    #[test]
    fn parse_key_rejects_bad_hex() {
        assert!(parse_key("nothex").is_none());
        assert!(parse_key(&"00".repeat(32)).is_some());
    }
}
