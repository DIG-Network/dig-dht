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

use tokio::sync::Mutex;

use dig_nat::PeerId;

use crate::clock::now_secs;
use crate::config::DhtConfig;
use crate::content::ContentId;
use crate::error::DhtError;
use crate::key::Key;
use crate::lookup::{iterative_find, QueryOutcome};
use crate::provider_store::{ProviderSnapshot, ProviderStore, PutOutcome};
use crate::record::{hex64_to_bytes, CandidateAddr, ProviderRecord};
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
    /// The AUTHORITATIVE provider store — records whose provider attribution this node established
    /// (its own announces, the mTLS-checked serving-side `add_provider`, the caller-verified
    /// [`ingest_verified_provider`](DhtService::ingest_verified_provider)). This is the store that
    /// answers an inbound `find_providers`, so everything in it becomes THIS NODE'S CLAIM about who
    /// holds what.
    providers: Arc<Mutex<ProviderStore>>,
    /// The DISCOVERY CACHE — records this node collected from its OWN lookups (SPEC §6.8). Same
    /// type, same admission control, different trust provenance and therefore a different store:
    /// see [`cache_discovered`](DhtService::cache_discovered) for why these two must never be one.
    discovered: Arc<Mutex<ProviderStore>>,
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
        let discovered = ProviderStore::with_limits(config.discovery_cache_limits);
        DhtService {
            local_id,
            local_addresses,
            config,
            routing: Arc::new(Mutex::new(routing)),
            providers: Arc::new(Mutex::new(providers)),
            discovered: Arc::new(Mutex::new(discovered)),
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

    /// Find the providers of `content` — the peers holding it. Answers from this node's
    /// **discovery cache** when a recent lookup for the same key is still live (SPEC §6.8);
    /// otherwise runs an iterative `find_providers` lookup toward the content key, caches what it
    /// learns, and returns every live provider record collected (deduped by provider). The node
    /// then connects to those providers over dig-nat and fetches via the L7 peer RPC.
    ///
    /// **Cached answers are what make a later direct dial free** (dig_ecosystem#3128 requirement 7):
    /// a `.dig` fetch issues many requests against the same store, and without the cache each one
    /// paid a fresh Kademlia walk. A live cache entry is treated as evidence that this node
    /// completed a lookup for the key recently, so the walk is skipped entirely — records this node
    /// holds AUTHORITATIVELY are deliberately NOT such evidence, since they may be its own announce
    /// and short-circuiting on them would stop a publisher ever learning the other holders of its
    /// own content.
    ///
    /// A cached holder is a claim by an untrusted peer, so a dial to it may fail. That costs one
    /// failed dial, never a wrong answer — the content is accepted because it verifies against the
    /// merkle root, never because a peer supplied it (NC-12). A caller that finds every cached
    /// candidate undialable calls [`forget_discovered`](Self::forget_discovered) and asks again,
    /// which re-runs the full walk.
    ///
    /// Returns an empty vec (not an error) when the content simply has no known providers; returns
    /// [`DhtError::NoPeers`] only when there is no one to ask (empty routing table + no bootstrap).
    pub async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DhtError> {
        let target = content.to_key();
        let key_hex = target.to_hex();

        // Local short-circuit: if we already hold providers for this key, include them.
        let now = now_secs();
        let local = self.providers.lock().await.get(&key_hex, now);

        let cached = self.discovered.lock().await.get(&key_hex, now);
        if !cached.is_empty() {
            return Ok(merge_dedup_by_provider(local, cached, now));
        }

        let seeds = self.seed_contacts(&target).await;
        if seeds.is_empty() {
            // No peers to ask — return whatever we hold locally (possibly empty).
            return Ok(local);
        }
        let result = self.run_lookup(target, seeds, true).await;
        self.absorb_contacts(&result.closest).await;

        // Discovered records come straight off the wire from other peers' responses, bypassing
        // `ProviderRecord::new`'s address cap — capped here before they are cached or handed back
        // to our caller (SPEC §5.5, §14). Records for a key we did not query were already discarded
        // at the wire boundary in `run_lookup`'s query closure (SPEC §6.7).
        // Discovered records go to the CALLER as well as the cache, so both fields a peer controls
        // are normalized here — the address list and the collateral pointer. Normalizing only on the
        // way into the cache would hand the caller the raw value.
        let mut discovered = result.providers;
        for r in &mut discovered {
            crate::record::sort_and_cap_addresses(&mut r.addresses);
            r.unverified_mirror_coin_id =
                crate::record::normalize_mirror_coin_id(r.unverified_mirror_coin_id.as_deref());
        }
        self.cache_discovered(&key_hex, &discovered).await;

        Ok(merge_dedup_by_provider(local, discovered, now_secs()))
    }

    /// The provider records this node has CACHED for `content` from its own lookups, live as of
    /// now — the direct-dial shortcut requirement 7 exists to provide, with no network round-trip
    /// and no fallback walk.
    ///
    /// # These records MUST NOT be re-served to anyone
    ///
    /// They are hearsay: some peer along a lookup said that some other peer holds this content, and
    /// nothing authenticated that claim — unlike an authoritative record, which either names the
    /// mTLS-verified caller that announced it or was signature-checked by the caller of
    /// [`ingest_verified_provider`](Self::ingest_verified_provider). Hearsay belongs on the FETCH
    /// path, where a wrong candidate is merely a wasted dial because the merkle bind catches it. On
    /// the ASSERTION path — an inbound `find_providers`, a redirect answer, anything a stranger
    /// reads — it becomes THIS NODE'S claim about the world, and re-serving it would launder an
    /// attacker's fabricated holder into an answer other nodes trust. This node therefore never
    /// serves the cache (see [`handle_request_from`](Self::handle_request_from), which reads the
    /// authoritative store only) and never publishes it (see
    /// [`provider_snapshot`](Self::provider_snapshot)).
    pub async fn cached_providers(&self, content: &ContentId) -> Vec<ProviderRecord> {
        self.discovered
            .lock()
            .await
            .get(&content.to_key().to_hex(), now_secs())
    }

    /// Forget every cached provider for `content`, so the next
    /// [`find_providers`](Self::find_providers) runs a real lookup again. Returns how many cached
    /// records were dropped.
    ///
    /// This is what keeps a cache miss CHEAP and keeps it from being mistaken for absence: a caller
    /// that has tried every cached candidate and reached none of them calls this and asks again,
    /// rather than concluding the content has no providers. It touches only this node's own cache —
    /// never the authoritative store, so it can neither censor a key this node serves nor be
    /// observed by any other peer.
    pub async fn forget_discovered(&self, content: &ContentId) -> usize {
        self.discovered
            .lock()
            .await
            .remove_key(&content.to_key().to_hex())
    }

    /// Announce that THIS node holds `content`: build a provider record (this node's `peer_id` +
    /// addresses, expiring at `now + provider_ttl`), store it locally, remember to republish it, and
    /// PUT it at the `k` nodes closest to the content key. Returns how many peers accepted the PUT.
    ///
    /// Called when the node's inventory gains content (a new capsule/root/resource it now serves).
    pub async fn announce_provider(&self, content: &ContentId) -> Result<usize, DhtError> {
        self.announce_provider_with_collateral(content, None).await
    }

    /// As [`announce_provider`](Self::announce_provider), but also publishing this node's claimed
    /// mirror-coin id so a verifier can fetch ONE coin instead of scanning by hint.
    ///
    /// The pointer is per-content because a mirror coin bonds a `(store, root, owner, epoch)`
    /// tuple, and it is remembered so every [`republish`](Self::republish) re-attaches it. Pass
    /// `None` — or call [`announce_provider`](Self::announce_provider) — when there is no coin yet;
    /// **absence is a normal, fully-supported state**, not a degraded one, since the verifier's
    /// fallback is the hint scan.
    ///
    /// To refresh the pointer across an epoch rollover, announce again with the new coin id.
    ///
    /// Publishing a pointer claims nothing that a consumer will believe: see
    /// [`ProviderRecord::unverified_mirror_coin_id`].
    pub async fn announce_provider_with_collateral(
        &self,
        content: &ContentId,
        unverified_mirror_coin_id: Option<[u8; 32]>,
    ) -> Result<usize, DhtError> {
        let target = content.to_key();
        let mut record = self.build_local_record(&target);
        if let Some(coin_id) = unverified_mirror_coin_id {
            record = record.with_unverified_mirror_coin_id(coin_id);
        }

        // Store locally + remember for republish (pointer included, so the first TTL rollover does
        // not silently drop it).
        {
            let mut ps = self.providers.lock().await;
            ps.put(record.clone());
            ps.mark_announced_with_collateral(
                target.to_hex(),
                record.unverified_mirror_coin_id.clone(),
            );
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
    /// capped ([`MAX_ADDRESSES_PER_RECORD`](crate::MAX_ADDRESSES_PER_RECORD)),
    /// `unverified_mirror_coin_id` is normalized to canonical lowercase 64-hex or dropped to `None`
    /// (so a caller need not bound it, and MUST NOT rely on it having survived verbatim),
    /// `expires_at` is clamped to `min(record.expires_at, now + provider_ttl)` (§6.2), and the
    /// per-key / global
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

    /// A bounded, AGGREGATED view of this node's provider store — content keys and their live
    /// provider COUNTS, with no provider identities (dig_ecosystem #1935).
    ///
    /// Exposed so a node can answer the relay's RLY-009 `get_dht_records` without the caller needing
    /// access to the store itself. Because a Kademlia node holds records for keys near its OWN
    /// `peer_id`, this describes MANY OTHER peers' content rather than what this node caches — which
    /// is what makes the union across nodes a usable view of the network's content layer.
    ///
    /// `max_keys` bounds the result; see [`ProviderStore::snapshot`] for the truncation and privacy
    /// contract. Expired records are excluded as of the current time, so the counts agree with what
    /// [`find_providers`](Self::find_providers) would actually return.
    pub async fn provider_snapshot(&self, max_keys: usize) -> ProviderSnapshot {
        self.providers.lock().await.snapshot(now_secs(), max_keys)
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
            let mut record = self.build_local_record(&target);
            // Re-attach the pointer this key was announced with. Rebuilding from
            // `build_local_record` alone would drop it on the first republish, so a node would
            // appear to have lost its collateral pointer one TTL after announcing it.
            record.unverified_mirror_coin_id = self
                .providers
                .lock()
                .await
                .announced_collateral(&hex)
                .map(str::to_owned);
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

    /// Drop expired provider records from BOTH the authoritative store and the discovery cache
    /// (SPEC §6.8). Call periodically (piggy-backs on republish/refresh). Returns the total number
    /// of records removed.
    ///
    /// One `now` for both sweeps, so a maintenance tick cannot leave the two stores disagreeing
    /// about which instant it ran at.
    pub async fn gc(&self) -> usize {
        let now = now_secs();
        let authoritative = self.providers.lock().await.gc(now);
        let cached = self.discovered.lock().await.gc(now);
        authoritative + cached
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
    /// 2. **Normalize `unverified_mirror_coin_id`** to a canonical lowercase 64-hex string or
    ///    `None`. Same reason as the address cap and the same blind spot: the wire boundary's
    ///    `deserialize_mirror_coin_id` only runs under serde, so a record built by literal (how a
    ///    consumer folds a verified holdings-announce in) could otherwise carry a body-sized
    ///    pointer that this node stores AND re-serves until every querier's frame check rejects the
    ///    answer, making the key undiscoverable through us for a full TTL.
    /// 3. **Clamp `expires_at`** to `now + provider_ttl` — an inbound record is never trusted to
    ///    self-report its expiry; without this a record naming `u64::MAX` would never GC.
    /// 4. **Admission-control** via [`ProviderStore::put`], enforcing the per-key + global caps so a
    ///    flood cannot grow the store without bound.
    /// 5. On [`PutOutcome::Accepted`], **fold the holder into the routing table** (its addresses let
    ///    us reach it). A rejected record folds nothing.
    ///
    /// [`ingest_verified_provider`]: Self::ingest_verified_provider
    async fn admit_verified_record(&self, mut record: ProviderRecord) -> PutOutcome {
        crate::record::sort_and_cap_addresses(&mut record.addresses);
        record.unverified_mirror_coin_id =
            crate::record::normalize_mirror_coin_id(record.unverified_mirror_coin_id.as_deref());

        let now = now_secs();
        let clamp_ceiling = now.saturating_add(self.config.provider_ttl_secs());
        record.expires_at = record.expires_at.min(clamp_ceiling);

        // `put_at` with the SAME instant the clamp used, so admission cannot reclaim a slot it
        // considers expired while the clamp considered it live (or vice versa).
        let outcome = self.providers.lock().await.put_at(record.clone(), now);
        if outcome == PutOutcome::Accepted {
            if let Some(pid) = record.provider_peer_id() {
                let contact = Contact::new(&pid, record.addresses.clone());
                let _ = self.routing.lock().await.insert(contact);
            }
        }
        outcome
    }

    /// Cache the records a lookup for `content_key` collected, so a later fetch of the same content
    /// can dial directly instead of walking the DHT again (SPEC §6.8, dig_ecosystem#3128 req 7).
    ///
    /// # Why this is a SEPARATE store from the authoritative one
    ///
    /// The two hold the same type and are admission-controlled by the same code, but they carry
    /// different trust provenance, and the difference decides who may read them. An authoritative
    /// record was attributed — the serving side checked the announcing record against its
    /// mTLS-verified caller, or the caller of `ingest_verified_provider` checked the holder's
    /// signature. A record collected during a lookup was attributed by NOBODY: an arbitrary peer
    /// along the walk asserted that some third party holds the content, at addresses of its
    /// choosing. Merging the two would make this node re-serve that assertion as its own on every
    /// inbound `find_providers` — turning one fabricated record fed to one node into a poisoned
    /// answer the rest of the network reads back, at a keyspace position this node has no `k`-closest
    /// duty over. Kept apart, the worst a fabricated record achieves is a wasted dial by the one
    /// node that cached it.
    ///
    /// Four admission rules, in order:
    ///
    /// 1. **Never cache a record naming THIS node.** It is useless as a dial target, and worse, it
    ///    would make the cache non-empty and so suppress the next real lookup — a peer that echoed
    ///    our own record back at us could pin us to a provider set of one entry we cannot use.
    /// 2. **Never cache a record for a different key.** The wire boundary already discards those
    ///    (SPEC §6.7); re-checking costs a string compare and this write outlives the lookup that
    ///    produced it, so the invariant is asserted rather than assumed.
    /// 3. **Normalize BOTH peer-controlled shape fields**: `unverified_mirror_coin_id` to canonical
    ///    64-hex or `None`, and `addresses` through `sort_and_cap_addresses` (SPEC §5.5). The one
    ///    caller today, [`find_providers`](Self::find_providers), already does both in its
    ///    post-lookup pass, so this is defence in depth rather than a live fix — but that is a
    ///    property of the caller, not of this write path, and a second caller added later must
    ///    inherit the guarantee rather than be expected to remember it. A record reaching local
    ///    state holds the same shape whichever path admitted it.
    /// 4. **Clamp the expiry DOWN to `now + discovery_cache_ttl`**, never up. A peer cannot extend
    ///    its residence in this node's cache by claiming a distant expiry, and a record that is
    ///    already expired is not cached at all.
    ///
    /// Every surviving record goes through [`ProviderStore::put_at`], so the discovery cache's
    /// per-key and global caps bound it exactly as the authoritative store's bound that one — this
    /// write path has no way to exceed them.
    async fn cache_discovered(&self, content_key: &str, discovered: &[ProviderRecord]) {
        let now = now_secs();
        let ceiling = now.saturating_add(self.config.discovery_cache_ttl_secs());
        let self_id = self.local_id.to_hex();

        let mut cache = self.discovered.lock().await;
        for record in discovered {
            if record.provider_peer_id == self_id || record.content_key != content_key {
                continue;
            }
            let mut entry = record.clone();
            crate::record::sort_and_cap_addresses(&mut entry.addresses);
            entry.unverified_mirror_coin_id =
                crate::record::normalize_mirror_coin_id(entry.unverified_mirror_coin_id.as_deref());
            entry.expires_at = entry.expires_at.min(ceiling);
            if entry.is_expired(now) {
                continue;
            }
            cache.put_at(entry, now);
        }
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
                let req = DhtRequest::FindProviders {
                    content_key: content_key.clone(),
                };
                match transport.rpc(&from, &contact, &req).await {
                    Ok(DhtResponse::Providers {
                        mut providers,
                        closer,
                    }) => {
                        // Answer-to-question binding (SPEC §6.7, §14): keep only records for the
                        // key we actually asked about. A responder is free to say ANYTHING here —
                        // `ProviderRecord` carries no signature and the peer is not the record's
                        // subject — so without this equality check any peer on the lookup path
                        // could stamp arbitrary provider peer_ids and address hints onto records
                        // for keys the finder never queried, and the finder would return them to
                        // its caller as dial targets (dial fan-out / wasted-dial DoS, and a
                        // spirit-defeat of the #1490 amplification bound).
                        //
                        // Filtering HERE, at the wire boundary, rather than at the final merge is
                        // load-bearing: the lookup's `stop_on_providers` early exit fires as soon
                        // as any provider is collected, so a mismatched record counted as "found"
                        // would end the walk before it reached a real holder — discovery
                        // censorship. Nothing downstream of this point sees an off-key record.
                        providers.retain(|r| r.content_key == content_key);
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

/// Merge two provider sets into one answer: `authoritative` first, then `extra`, deduped by
/// provider `peer_id` and with anything expired at `now` dropped.
///
/// Order is the contract, not an accident. The caller dials the list front-to-back, so the records
/// whose provenance this node established lead, and the weaker-provenance set (a discovery-cache
/// hit, or the records a lookup just collected) follows. A provider present in both keeps its
/// authoritative entry, because the first occurrence wins.
fn merge_dedup_by_provider(
    mut authoritative: Vec<ProviderRecord>,
    extra: Vec<ProviderRecord>,
    now: u64,
) -> Vec<ProviderRecord> {
    authoritative.extend(extra);
    let mut seen = std::collections::HashSet::new();
    authoritative.retain(|r| !r.is_expired(now) && seen.insert(r.provider_peer_id.clone()));
    authoritative
}

/// Parse a 64-hex string into a [`Key`] (used on the serving side for wire targets).
fn parse_key(hex: &str) -> Option<Key> {
    hex64_to_bytes(hex).map(Key::from_bytes)
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

#[cfg(test)]
mod collateral_pointer_tests {
    use super::*;
    use crate::record::CandidateAddr;

    const BONDED_COIN: [u8; 32] = [0x5c; 32];

    /// A transport that is never dialled: these tests exercise the LOCAL provider store only, so an
    /// unseeded routing table makes every lookup a no-op.
    struct UnusedTransport;

    #[async_trait::async_trait]
    impl crate::transport::DhtTransport for UnusedTransport {
        async fn rpc(
            &self,
            _from: &Contact,
            _peer: &Contact,
            _request: &DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            unreachable!("collateral-pointer tests never dial a peer")
        }
    }

    fn service() -> DhtService {
        DhtService::new(
            PeerId::from_bytes([9u8; 32]),
            vec![CandidateAddr::direct("h", 9444)],
            DhtConfig::default(),
            Arc::new(UnusedTransport),
        )
    }

    /// The local record this node published for `content`.
    async fn local_record(svc: &DhtService, content: &ContentId) -> ProviderRecord {
        svc.providers
            .lock()
            .await
            .get(&content.to_key().to_hex(), now_secs())
            .into_iter()
            .find(|r| r.provider_peer_id == svc.local_id.to_hex())
            .expect("this node should have a local record for the announced content")
    }

    #[tokio::test]
    async fn announcing_with_collateral_publishes_the_pointer_and_without_omits_it() {
        let svc = service();
        let bonded = ContentId::store([1u8; 32]);
        let bare = ContentId::store([2u8; 32]);

        svc.announce_provider_with_collateral(&bonded, Some(BONDED_COIN))
            .await
            .unwrap();
        svc.announce_provider(&bare).await.unwrap();

        assert_eq!(
            local_record(&svc, &bonded)
                .await
                .unverified_mirror_coin_id_bytes(),
            Some(BONDED_COIN)
        );
        assert_eq!(
            local_record(&svc, &bare).await.unverified_mirror_coin_id,
            None,
            "a bare announce must not acquire a pointer from a sibling announce"
        );
    }

    /// The PLACEMENT test. Republish rebuilds the record from scratch, so a pointer held anywhere
    /// but per-announced-key is lost on the first TTL rollover — a node would look collateralised
    /// for one TTL and bare afterwards.
    ///
    /// Two keys, exactly one pointered: a service-wide or config-held pointer would re-attach it to
    /// BOTH and pass a single-key version of this test. That is the nearest wrong implementation,
    /// so the bare key is the control that makes relocation observable.
    #[tokio::test]
    async fn republish_re_attaches_each_keys_own_pointer_and_only_its_own() {
        let svc = service();
        let bonded = ContentId::store([1u8; 32]);
        let bare = ContentId::store([2u8; 32]);

        svc.announce_provider_with_collateral(&bonded, Some(BONDED_COIN))
            .await
            .unwrap();
        svc.announce_provider(&bare).await.unwrap();

        assert_eq!(svc.republish().await, 2);

        assert_eq!(
            local_record(&svc, &bonded)
                .await
                .unverified_mirror_coin_id_bytes(),
            Some(BONDED_COIN),
            "republish dropped the pointer this key was announced with"
        );
        assert_eq!(
            local_record(&svc, &bare).await.unverified_mirror_coin_id,
            None,
            "republish invented a pointer for a key that never had one"
        );
    }

    /// Re-announcing after an epoch rollover replaces the pointer rather than accumulating one.
    #[tokio::test]
    async fn re_announcing_replaces_the_pointer() {
        let svc = service();
        let content = ContentId::store([1u8; 32]);
        let next_epoch_coin = [0xE7; 32];

        svc.announce_provider_with_collateral(&content, Some(BONDED_COIN))
            .await
            .unwrap();
        svc.announce_provider_with_collateral(&content, Some(next_epoch_coin))
            .await
            .unwrap();
        svc.republish().await;

        assert_eq!(
            local_record(&svc, &content)
                .await
                .unverified_mirror_coin_id_bytes(),
            Some(next_epoch_coin)
        );
    }

    /// The NON-SERDE ingress. `ingest_verified_provider` takes an already-constructed
    /// [`ProviderRecord`], whose fields are all `pub`, so `deserialize_mirror_coin_id` never runs on
    /// it - which is exactly how a consumer folding a verified holdings-announce into the DHT builds
    /// one. A test that goes through serde passes without the fix and proves nothing, so this one
    /// builds the record by struct literal.
    ///
    /// Three pointers, because "clears the field" and "normalizes the field" are different
    /// implementations and only a truthful control tells them apart: one oversized (sized FROM the
    /// protocol's own [`MAX_FRAMED_BODY`] ceiling, which is the value that makes the record
    /// unservable), one 64 chars but not hex (a length-only check would admit it), and one VALID,
    /// which must survive.
    #[tokio::test]
    async fn ingesting_a_record_built_by_literal_normalizes_its_pointer() {
        use crate::wire::MAX_FRAMED_BODY;

        let svc = service();
        let valid = crate::record::to_hex64(&BONDED_COIN);

        let cases: [(&str, String, Option<String>); 3] = [
            (
                "an oversized pointer must not be stored",
                "a".repeat(MAX_FRAMED_BODY),
                None,
            ),
            (
                "a 64-char non-hex pointer must not be stored",
                "z".repeat(64),
                None,
            ),
            (
                "a canonical pointer must survive ingest",
                valid.clone(),
                Some(valid.clone()),
            ),
        ];

        for (i, (why, pointer, expected)) in cases.into_iter().enumerate() {
            let content = ContentId::store([i as u8 + 40; 32]);
            let content_key = content.to_key().to_hex();
            let holder = PeerId::from_bytes([i as u8 + 70; 32]);

            let outcome = svc
                .ingest_verified_provider(ProviderRecord {
                    content_key: content_key.clone(),
                    provider_peer_id: holder.to_hex(),
                    addresses: vec![CandidateAddr::direct("holder.example", 9444)],
                    expires_at: now_secs() + 60,
                    unverified_mirror_coin_id: Some(pointer),
                })
                .await;
            assert_eq!(outcome, PutOutcome::Accepted, "{why}: ingest must accept");

            let providers = svc.providers.lock().await.get(&content_key, now_secs());
            let stored = providers
                .iter()
                .find(|r| r.provider_peer_id == holder.to_hex())
                .expect("the ingested record should be stored");
            assert_eq!(stored.unverified_mirror_coin_id, expected, "{why}");

            // The harm the bound exists to prevent: an oversized pointer is re-served in every
            // answer for this key, and no OUTBOUND cap trims it - so the frame the querier must
            // decode is what actually has to stay under the ceiling.
            let frame = crate::wire::DhtResponse::Providers {
                providers: providers.clone(),
                closer: vec![],
            }
            .encode();
            assert!(
                frame.len() <= MAX_FRAMED_BODY,
                "{why}: the answer for this key is unservable at {} bytes",
                frame.len()
            );
        }
    }

    /// Withdrawing forgets the pointer with the announcement, so a later bare re-announce cannot
    /// resurrect a stale coin id.
    #[tokio::test]
    async fn withdrawing_forgets_the_pointer() {
        let svc = service();
        let content = ContentId::store([1u8; 32]);

        svc.announce_provider_with_collateral(&content, Some(BONDED_COIN))
            .await
            .unwrap();
        svc.withdraw_provider(&content).await;
        svc.announce_provider(&content).await.unwrap();
        svc.republish().await;

        assert_eq!(
            local_record(&svc, &content).await.unverified_mirror_coin_id,
            None
        );
    }
}

#[cfg(test)]
mod provider_snapshot_tests {
    use super::*;
    use crate::record::CandidateAddr;

    /// A transport that is never dialled: these tests only exercise the LOCAL provider store.
    struct UnusedTransport;

    #[async_trait::async_trait]
    impl crate::transport::DhtTransport for UnusedTransport {
        async fn rpc(
            &self,
            _from: &Contact,
            _peer: &Contact,
            _request: &DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            unreachable!("provider-snapshot tests never dial a peer")
        }
    }

    fn service() -> DhtService {
        DhtService::new(
            PeerId::from_bytes([9u8; 32]),
            vec![CandidateAddr::direct("h", 9444)],
            DhtConfig::default(),
            Arc::new(UnusedTransport),
        )
    }

    async fn announce(svc: &DhtService, content_seed: u8, provider_seed: u8) {
        let content = ContentId::store([content_seed; 32]);
        svc.ingest_verified_provider(ProviderRecord::new(
            &content.to_key(),
            &PeerId::from_bytes([provider_seed; 32]),
            vec![CandidateAddr::direct("h", 9444)],
            now_secs() + 3600,
        ))
        .await;
    }

    /// The accessor RLY-009 answers from: counts reachable WITHOUT handing out the store, and
    /// without a single provider identity crossing the boundary (dig_ecosystem #1935).
    #[tokio::test]
    async fn provider_snapshot_reports_counts_and_no_identities() {
        let svc = service();
        announce(&svc, 1, 7).await;

        let snap = svc.provider_snapshot(100).await;

        assert_eq!(snap.total_keys, 1);
        assert_eq!(snap.entries[0].providers, 1);
        assert!(
            !format!("{snap:?}").contains(&PeerId::from_bytes([7u8; 32]).to_hex()),
            "a provider identity must never leave the store through this accessor"
        );
    }

    /// The bound is honoured: the store is attacker-influenced, so the answer size must be OURS.
    #[tokio::test]
    async fn provider_snapshot_honours_the_bound() {
        let svc = service();
        for i in 0..6u8 {
            announce(&svc, i, 100 + i).await;
        }
        let snap = svc.provider_snapshot(2).await;
        assert_eq!(snap.entries.len(), 2);
        assert!(snap.truncated);
        assert_eq!(snap.total_keys, 6, "the true total survives truncation");
    }
}

/// The `CandidateAddr::host` size bound, exercised through the PUBLIC `handle_request` ingress —
/// the reachable one. A record arriving there is decoded into a struct whose fields are all `pub`,
/// so a test that only goes through a constructor proves nothing about the attacker's path.
#[cfg(test)]
mod host_size_bound_tests {
    use std::sync::Arc;

    use super::*;
    use crate::record::{CandidateAddr, MAX_ADDRESSES_PER_RECORD, MAX_HOST_LEN};
    use crate::wire::MAX_FRAMED_BODY;

    /// A transport that is never dialled: these tests only exercise local admission + the answer.
    struct UnusedTransport;

    #[async_trait::async_trait]
    impl crate::transport::DhtTransport for UnusedTransport {
        async fn rpc(
            &self,
            _from: &Contact,
            _peer: &Contact,
            _request: &DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            unreachable!("host-size-bound tests never dial a peer")
        }
    }

    fn service() -> DhtService {
        DhtService::new(
            PeerId::from_bytes([9u8; 32]),
            vec![CandidateAddr::direct("local.example", 9444)],
            DhtConfig::default(),
            Arc::new(UnusedTransport),
        )
    }

    /// The control's host — an ordinary name, well under the bound, which must survive UNCHANGED.
    /// Without it, a fix that simply cleared every `host` would pass both assertions below while
    /// destroying the addresses the DHT exists to hand out.
    const HONEST_HOST: &str = "holder.example";

    /// The hostile host, sized FROM the protocol's own ceiling rather than from a round number: a
    /// single `MAX_FRAMED_BODY`-byte host makes this key's answer exceed the frame limit on its own,
    /// which is precisely the harm — every querier's `decode_framed` then rejects the answer and the
    /// key is undiscoverable through this node until the record expires.
    fn hostile_host() -> String {
        "a".repeat(MAX_FRAMED_BODY)
    }

    /// Announce `host` for `content_seed` through the public ingress, then return this node's answer
    /// to a `FindProviders` for that key — the exact bytes a querier would have to decode.
    async fn announce_then_answer(
        svc: &DhtService,
        content_seed: u8,
        provider_seed: u8,
        host: String,
    ) -> DhtResponse {
        let content = ContentId::store([content_seed; 32]);
        let content_key = content.to_key().to_hex();

        let accepted = svc
            .handle_request(DhtRequest::AddProvider {
                record: ProviderRecord {
                    content_key: content_key.clone(),
                    provider_peer_id: PeerId::from_bytes([provider_seed; 32]).to_hex(),
                    addresses: vec![CandidateAddr::direct(host, 9444)],
                    expires_at: now_secs() + 3600,
                    unverified_mirror_coin_id: None,
                },
            })
            .await;
        assert!(
            matches!(accepted, DhtResponse::AddProviderOk),
            "the announce must be ACCEPTED — the bound normalizes the record, it does not reject it"
        );

        svc.handle_request(DhtRequest::FindProviders { content_key })
            .await
    }

    /// `cache_discovered`'s OWN pointer normalization, called directly.
    ///
    /// The end-to-end swarm test for this exercises `find_providers`, which normalizes the record
    /// before handing it here — so that test passes with or without this line and cannot speak for
    /// it. This one calls the private write path directly, which is the only way to show the layer
    /// is real rather than carried by its single current caller. That is the whole point of the
    /// line: a second caller added later inherits the guarantee.
    #[tokio::test]
    async fn the_discovery_cache_normalizes_its_own_pointer() {
        let svc = service();
        let content = ContentId::store([0xC1; 32]);
        let content_key = content.to_key().to_hex();

        svc.cache_discovered(
            &content_key,
            &[ProviderRecord {
                content_key: content_key.clone(),
                provider_peer_id: PeerId::from_bytes([0x71; 32]).to_hex(),
                addresses: vec![CandidateAddr::direct(HONEST_HOST, 9444)],
                expires_at: now_secs() + 60,
                unverified_mirror_coin_id: Some(hostile_host()),
            }],
        )
        .await;

        let cached = svc.cached_providers(&content).await;
        assert_eq!(cached.len(), 1, "the record should have been cached");
        assert_eq!(
            cached[0].unverified_mirror_coin_id, None,
            "the cache must normalize the pointer itself, not rely on its caller having done it"
        );
    }

    /// `cache_discovered`'s OWN address cap, called directly — the sibling of the pointer test
    /// above, and blind in the same way for the same reason.
    ///
    /// Every end-to-end route into this write path runs through `find_providers`, which caps the
    /// addresses before handing them here, so no swarm-level assertion can distinguish "the cache
    /// caps" from "its one caller capped first". Calling the private write path directly is the
    /// only fixture that can, and SPEC §6.8 admission rule 3 states the cap as a MUST **at the cache
    /// write itself** — a normative claim that needs a test standing on that line alone.
    ///
    /// Both halves of the cap are exercised, because "drops the unrepresentable" and "bounds the
    /// count" are different implementations: an over-long host must not be cached, an honest one
    /// beside it must survive verbatim (a clear-everything fix fails that), and a list over
    /// `MAX_ADDRESSES_PER_RECORD` must come back at the cap.
    #[tokio::test]
    async fn the_discovery_cache_caps_its_own_addresses() {
        let svc = service();
        let content = ContentId::store([0xC2; 32]);
        let content_key = content.to_key().to_hex();

        // One unrepresentable host, one honest control, then enough filler to exceed the count cap.
        let mut addresses = vec![
            CandidateAddr::direct(hostile_host(), 9444),
            CandidateAddr::direct(HONEST_HOST, 9444),
        ];
        for i in 0..=MAX_ADDRESSES_PER_RECORD {
            addresses.push(CandidateAddr::direct(format!("filler-{i}.example"), 9444));
        }

        svc.cache_discovered(
            &content_key,
            &[ProviderRecord {
                content_key: content_key.clone(),
                provider_peer_id: PeerId::from_bytes([0x72; 32]).to_hex(),
                addresses,
                expires_at: now_secs() + 60,
                unverified_mirror_coin_id: None,
            }],
        )
        .await;

        let cached = svc.cached_providers(&content).await;
        assert_eq!(cached.len(), 1, "the record should have been cached");
        let hosts: Vec<String> = cached[0].addresses.iter().map(|a| a.host.clone()).collect();

        assert!(
            hosts.iter().all(|h| h.len() <= MAX_HOST_LEN),
            "the cache must drop an unrepresentable host itself, not rely on its caller having done it"
        );
        assert!(
            hosts.iter().any(|h| h == HONEST_HOST),
            "the cap must drop only what it cannot represent — an ordinary host survives verbatim"
        );
        assert_eq!(
            cached[0].addresses.len(),
            MAX_ADDRESSES_PER_RECORD,
            "the cache must bound the address COUNT itself as well as each entry's size"
        );
    }

    fn stored_hosts(answer: &DhtResponse) -> Vec<String> {
        match answer {
            DhtResponse::Providers { providers, .. } => providers
                .iter()
                .flat_map(|r| r.addresses.iter())
                .map(|a| a.host.clone())
                .collect(),
            other => panic!("expected a Providers answer, got {other:?}"),
        }
    }

    /// ASSERTION 1 — the oversized host does not survive admission, while an honest one does.
    ///
    /// Deliberately separate from the frame-size assertion below: the two are not carried by one
    /// another, and keeping them apart is what proves it. This one can be satisfied by a bound
    /// placed anywhere on the write path; the frame assertion names the actual harm.
    #[tokio::test]
    async fn an_oversized_host_does_not_survive_admission_and_an_honest_one_does() {
        let svc = service();

        let hostile = announce_then_answer(&svc, 1, 0x41, hostile_host()).await;
        assert!(
            stored_hosts(&hostile)
                .iter()
                .all(|h| h.len() <= MAX_HOST_LEN),
            "an over-long host was stored and re-served"
        );

        let honest = announce_then_answer(&svc, 2, 0x42, HONEST_HOST.to_string()).await;
        assert_eq!(
            stored_hosts(&honest),
            vec![HONEST_HOST.to_string()],
            "the bound must drop only what it cannot represent — an ordinary host survives verbatim"
        );
    }

    /// ASSERTION 2 — the answer this node serves for the attacked key stays inside the protocol's
    /// frame ceiling, so it remains decodable by every querier.
    ///
    /// This is the assertion that names the harm, and the one a future refactor is least likely to
    /// break by accident. It is checked on a service that has ALSO admitted an honest record, so the
    /// `closer` list the poisoned contact bloats is genuinely populated.
    #[tokio::test]
    async fn the_answer_for_an_attacked_key_stays_within_the_frame_ceiling() {
        let svc = service();

        announce_then_answer(&svc, 2, 0x42, HONEST_HOST.to_string()).await;
        let answer = announce_then_answer(&svc, 1, 0x41, hostile_host()).await;

        let frame = answer.encode();
        assert!(
            frame.len() <= MAX_FRAMED_BODY,
            "the answer for this key is unservable at {} bytes (ceiling {MAX_FRAMED_BODY})",
            frame.len()
        );
    }
}
