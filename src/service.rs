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
use crate::provider_store::{ProviderStore, PutOutcome};
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
        let providers = ProviderStore::with_limits(config.provider_store_limits);
        DhtService {
            local_id,
            local_addresses,
            config,
            routing: Arc::new(Mutex::new(routing)),
            providers: Arc::new(Mutex::new(providers)),
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

    /// Add a single live peer to the routing table as it connects (e.g. a `dig-gossip`
    /// `PoolEvent::PeerAdded`), WITHOUT the network round-trip [`bootstrap`](Self::bootstrap) does.
    ///
    /// This is the LIVE seam the one-shot pre-connect bootstrap cannot cover: in a freshly-formed
    /// network the pool is empty when `bootstrap` runs, so routing stays empty and `find_providers`
    /// finds nobody. Feeding each connected peer here populates routing as the pool fills, which is
    /// what makes cross-node discovery work (#1574). Idempotent — re-adding a known peer merges its
    /// address(es) via the routing table's insert policy; adding this node's own id is a no-op.
    pub async fn add_peer(&self, peer_id: &PeerId, addresses: Vec<CandidateAddr>) {
        let contact = Contact::new(peer_id, addresses);
        let _ = self.routing.lock().await.insert(contact);
    }

    /// Remove a peer from the routing table as it leaves (a `dig-gossip` `PoolEvent::PeerRemoved`),
    /// keeping routing accurate so lookups don't seed from a dead contact. Returns whether it was
    /// present. `peer_id_hex` is the 64-char hex id (as carried on `Contact::provider_peer_id` /
    /// [`PeerId::to_hex`]).
    pub async fn remove_peer(&self, peer_id_hex: &str) -> bool {
        self.routing.lock().await.remove(peer_id_hex)
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

        // Merge local + discovered, dedup by provider, drop expired. Discovered records come
        // straight off the wire from other peers' responses, bypassing `ProviderRecord::new`'s
        // address cap — capped here before handing them back to our caller (SPEC §5.5, §14).
        let mut discovered = result.providers;
        for r in &mut discovered {
            crate::record::sort_and_cap_addresses(&mut r.addresses);
        }
        local.extend(discovered);
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
    ///
    /// This is the **passive** withdraw: it leaves this node's own local provider record in place
    /// (it only expires with TTL) and merely stops re-publishing it, so a `find_providers` on this
    /// node may still return self until the local record's TTL elapses. For an **immediate**
    /// own-retract — the local-state half of the #1423 evict+retract step — use
    /// [`retract_own_provider`](Self::retract_own_provider).
    pub async fn withdraw_provider(&self, content: &ContentId) -> bool {
        let key = content.to_key().to_hex();
        self.providers.lock().await.unmark_announced(&key)
    }

    // ---- Real-time holdings API (#1394 / #1423) ----------------------------------------------

    /// Ingest a provider record for a THIRD-PARTY holder that the caller has ALREADY verified was
    /// signed by `record.provider_peer_id` — the inbound-**add** half of the real-time holdings map
    /// (SPEC §6.5). Returns the store admission outcome.
    ///
    /// This is the authenticated push path a node's announce receiver calls after verifying a
    /// signed `HoldingsAnnounce` (dig-gossip opcode 222): the holder's signature has replaced mTLS
    /// attribution as the proof of who provides the content, so — unlike the serving-side
    /// `add_provider` (§6.4) — this method **bypasses the mTLS self-announce identity check** (the
    /// caller, not the DHT, established authenticity). dig-dht itself stays crypto-free (SPEC §15):
    /// it NEVER verifies a signature; passing an unverified record here is a caller bug that
    /// poisons the local provider set.
    ///
    /// Every other admission guard still applies exactly as for `add_provider`: the address list is
    /// capped ([`MAX_ADDRESSES_PER_RECORD`](crate::MAX_ADDRESSES_PER_RECORD)), `expires_at` is
    /// clamped to `min(record.expires_at, now + provider_ttl)` (§6.2), and the per-key / global
    /// admission caps (§6.3) are enforced — an over-capacity ingest returns
    /// [`PutOutcome::RejectedOverCapacity`] and stores nothing. On acceptance the holder is folded
    /// into the routing table so this node can reach it.
    pub async fn ingest_verified_provider(&self, record: ProviderRecord) -> PutOutcome {
        self.admit_verified_record(record).await
    }

    /// Remove exactly the local provider record for `(content_key, provider_peer_id)` — the
    /// inbound-**retract** half of the real-time holdings map (SPEC §6.6). Returns whether a record
    /// was removed.
    ///
    /// `content_key` and `provider_peer_id` are the 64-hex forms as they appear on a
    /// [`ProviderRecord`] (`content` → `content.to_key().to_hex()`; the holder's `peer_id` hex).
    /// The caller MUST have verified the retract was signed by that same `provider_peer_id`
    /// (authenticated retract): a retract signed by one holder removes ONLY that holder's record and
    /// can never evict another provider of the same key (censorship-resistance, §6.6). dig-dht does
    /// not verify the signature (SPEC §15) — that is the caller's responsibility.
    pub async fn remove_provider_record(&self, content_key: &str, provider_peer_id: &str) -> bool {
        self.providers
            .lock()
            .await
            .remove(content_key, provider_peer_id)
    }

    /// Actively retract THIS node's own provider record for `content`: remove the local record AND
    /// stop republishing it, so `find_providers` on this node stops returning self as a holder
    /// immediately (SPEC §6.6). Returns whether this node was providing the content (a local record
    /// existed or the key was being announced).
    ///
    /// This is the local-state half of the #1423 atomic **evict + retract** step (on an LRU cache
    /// eviction the node no longer serves the content). Unlike the passive
    /// [`withdraw_provider`](Self::withdraw_provider) (which leaves the local record to expire via
    /// TTL), this deletes it now. The copies previously PUT at the `k` closest peers are NOT deleted
    /// by this call — they age out via TTL, or are removed sooner when dig-node floods the signed
    /// retract announce and each recipient calls
    /// [`remove_provider_record`](Self::remove_provider_record).
    pub async fn retract_own_provider(&self, content: &ContentId) -> bool {
        let key = content.to_key().to_hex();
        let self_id = self.local_id.to_hex();
        let mut ps = self.providers.lock().await;
        let removed_record = ps.remove(&key, &self_id);
        let was_announced = ps.unmark_announced(&key);
        removed_record || was_announced
    }

    /// The `peer_id`s of the peers that hold `content` — a thin, address-free convenience over
    /// [`find_providers`](Self::find_providers) for callers that only need "which peers hold X"
    /// (e.g. an RPC holder-set query) and do not dial the holders themselves.
    ///
    /// `find_providers` remains the PRIMARY API: it returns full [`ProviderRecord`]s with candidate
    /// addresses, which dig-download needs to actually connect and fetch. This method runs the same
    /// distributed iterative lookup and simply projects each record to its holder `peer_id`
    /// (records with a malformed peer id are skipped; the set is already deduped by provider).
    pub async fn holders_of(&self, content: &ContentId) -> Result<Vec<PeerId>, DhtError> {
        let records = self.find_providers(content).await?;
        Ok(records
            .iter()
            .filter_map(|r| r.provider_peer_id())
            .collect())
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
        // The authenticated caller's peer_id (if any), kept for the AddProvider self-announce check
        // below — taken BEFORE the caller Contact is (conditionally) moved into the routing table.
        let caller_peer_id = caller.as_ref().map(|c| c.peer_id.clone());

        // Learn the (authenticated) caller — every inbound RPC is evidence the caller is alive.
        // Cap its address list at the boundary (SPEC §5.5, §14): a `Contact` decoded off the wire
        // bypasses `Contact::new`'s cap entirely (its fields are public), so an uncapped caller
        // address list would otherwise be folded straight into our routing table and later re-served
        // to every peer that queries us.
        if let Some(mut c) = caller {
            if c.peer_id != self.local_id.to_hex() {
                crate::record::sort_and_cap_addresses(&mut c.addresses);
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
                // Self-announce check (SPEC §6.4, §14): when the caller identity is known (an
                // authenticated transport), the record's provider_peer_id MUST be the caller itself.
                // ProviderRecord carries no signature, so without this check any authenticated caller
                // could announce an arbitrary THIRD-PARTY peer_id as a provider of arbitrary content
                // at attacker-chosen addresses — provider-set poisoning. A caller we cannot identify
                // (`handle_request`, no transport-supplied identity) cannot be checked and is let
                // through unchanged — that path already deviates from the mTLS-authenticated model.
                if let Some(caller_id) = &caller_peer_id {
                    if *caller_id != record.provider_peer_id {
                        return DhtResponse::Error {
                            code: 4,
                            message:
                                "add_provider: provider_peer_id must match the authenticated caller"
                                    .into(),
                        };
                    }
                }

                // Address-cap, TTL-clamp, admission-control, and (on acceptance) fold into routing —
                // the shared verified-record admission pipeline (SPEC §6.3, §14).
                match self.admit_verified_record(record).await {
                    PutOutcome::Accepted => DhtResponse::AddProviderOk,
                    PutOutcome::RejectedOverCapacity => DhtResponse::Error {
                        code: 3,
                        message: "provider store over capacity".into(),
                    },
                }
            }
        }
    }

    // ---- Internals ---------------------------------------------------------------------------

    /// Admit a provider record whose provider attribution is ALREADY established — either the
    /// serving-side mTLS self-announce check passed (`handle_request_from`'s `AddProvider` arm) or
    /// the caller pre-verified the holder signature ([`ingest_verified_provider`]). This is the one
    /// admission pipeline both paths share (SPEC §6.3, §14), in order:
    ///
    /// 1. **Cap the address list** at [`MAX_ADDRESSES_PER_RECORD`](crate::MAX_ADDRESSES_PER_RECORD)
    ///    — a record decoded off the wire bypasses `ProviderRecord::new`'s cap (its fields are
    ///    public), so an attacker could otherwise pack thousands of addresses into one record.
    /// 2. **Clamp `expires_at`** to `now + provider_ttl` — an inbound record is never trusted to
    ///    self-report its expiry; without this a record naming `u64::MAX` would never GC.
    /// 3. **Admission-control** via [`ProviderStore::put`], enforcing the per-key + global caps so a
    ///    flood cannot grow the store without bound.
    /// 4. On [`PutOutcome::Accepted`], **fold the holder into the routing table** (its addresses let
    ///    us reach it). A rejected record folds nothing.
    ///
    /// [`ingest_verified_provider`]: Self::ingest_verified_provider
    async fn admit_verified_record(&self, mut record: ProviderRecord) -> PutOutcome {
        crate::record::sort_and_cap_addresses(&mut record.addresses);

        let clamp_ceiling = now_secs().saturating_add(self.config.provider_ttl_secs());
        record.expires_at = record.expires_at.min(clamp_ceiling);

        let outcome = self.providers.lock().await.put(record.clone());
        if outcome == PutOutcome::Accepted {
            if let Some(pid) = record.provider_peer_id() {
                let contact = Contact::new(&pid, record.addresses.clone());
                let _ = self.routing.lock().await.insert(contact);
            }
        }
        outcome
    }

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
    ///
    /// `contacts` come straight off the wire (a peer's `find_node`/`find_providers` response) and
    /// so bypass [`Contact::new`]'s address cap (its fields are public) — this is another
    /// untrusted-input boundary (SPEC §5.5, §14), capped here before insertion.
    async fn absorb_contacts(&self, contacts: &[Contact]) {
        let mut rt = self.routing.lock().await;
        for c in contacts {
            let mut c = c.clone();
            crate::record::sort_and_cap_addresses(&mut c.addresses);
            match rt.insert(c) {
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
