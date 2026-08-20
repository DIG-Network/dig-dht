//! [`DhtConfig`] — the Kademlia tuning parameters (replication `k`, lookup parallelism `α`, provider
//! TTL, the maintenance intervals, the provider-store admission-control caps, and the
//! discovery-cache bounds).

use std::time::Duration;

use crate::provider_store::ProviderStoreLimits;

/// Kademlia parameters for a [`DhtService`](crate::DhtService).
///
/// The defaults follow the canonical Kademlia paper (`k = 20`, `α = 3`) and typical provider-record
/// lifetimes; every field is documented so a node operator can tune replication vs. traffic.
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// **Replication parameter `k`** — the bucket size and the number of closest peers a lookup
    /// converges on. A provider record is announced to (and a `find_node` returns) up to `k` peers.
    /// Larger `k` = more redundancy against churn, more traffic. Canonical default: 20.
    pub k: usize,

    /// **Lookup parallelism `α`** — how many peers an iterative lookup queries concurrently per
    /// round. Larger `α` = faster convergence, more in-flight traffic. Canonical default: 3.
    pub alpha: usize,

    /// **Provider-record TTL** — how long a PUT provider record is considered valid. A holder
    /// republishes before this elapses; a finder discards records older than this. Default: 2 hours.
    ///
    /// This is also the **clamp ceiling** for inbound `add_provider` records (SPEC §6.2, §14): a
    /// responder never stores a third-party `expires_at` further in the future than
    /// `now + provider_ttl`, so a malicious record can never outlive local GC indefinitely.
    pub provider_ttl: Duration,

    /// **Republish interval** — how often the holder re-announces the content it still holds, so its
    /// provider records never expire while it is online. MUST be shorter than [`Self::provider_ttl`].
    /// Default: 1 hour.
    pub republish_interval: Duration,

    /// **Bucket-refresh interval** — how often a bucket with no recent activity is refreshed by
    /// looking up a random key that falls in it, keeping the routing table populated. Default: 1 hour.
    pub refresh_interval: Duration,

    /// **Per-RPC timeout** — how long a single request to one peer may take before that peer is
    /// treated as unresponsive and the lookup moves on. Default: 5 seconds.
    pub rpc_timeout: Duration,

    /// **Provider-store admission-control caps** — the per-content-key and global record limits
    /// enforced on every inbound `add_provider` (SPEC §6.3, §14). Bounds worst-case memory growth
    /// from a single peer (or a small set of colluding peers) flooding announces. Default:
    /// [`ProviderStoreLimits::default`].
    pub provider_store_limits: ProviderStoreLimits,

    /// **Discovery-cache TTL** — how long a provider record LEARNED FROM THIS NODE'S OWN LOOKUP is
    /// kept so a later fetch of the same content can dial directly instead of walking the DHT again
    /// (SPEC §6.8). Default: 15 minutes.
    ///
    /// Deliberately far shorter than [`Self::provider_ttl`], for a reason specific to this cache:
    /// **nothing republishes into it.** An authoritative record survives 2 hours because its holder
    /// refreshes it on [`Self::republish_interval`]; a cached one has no such keeper, so its age is
    /// pure guesswork about a holder this node has not spoken to since. 15 minutes spans a whole
    /// multi-range download of one store and the re-reads that immediately follow it — where the
    /// saving actually accrues — while keeping a holder that dropped the content (an LRU eviction
    /// upstream takes minutes, not hours) from being dialed for the rest of the afternoon.
    ///
    /// It is a CLAMP, never an extension: a cached record expires at
    /// `min(record.expires_at, now + discovery_cache_ttl)`, so a peer cannot lengthen its own
    /// residence in this node's cache by claiming a distant expiry.
    pub discovery_cache_ttl: Duration,

    /// **Discovery-cache caps** — the per-content-key and global record limits enforced on the
    /// cache (SPEC §6.8), by the same [`ProviderStore`](crate::provider_store::ProviderStore)
    /// admission control the authoritative store uses.
    ///
    /// Tighter than [`Self::provider_store_limits`] on both axes, because the cache answers a
    /// narrower question. Per key it holds **8** — a caller dials a handful of candidates and gives
    /// up, so a ninth is memory spent on a dial nobody will make, and it matches the
    /// `MAX_ADDRESSES_PER_RECORD` disclosure budget the node's redirect path already settled on.
    /// Globally it holds **10 000** keys' worth: the cache is keyed by what THIS node went looking
    /// for, which is bounded by its own fetch behaviour rather than by strangers' announces, so the
    /// authoritative store's 100 000-record ceiling would buy nothing but a larger footprint for a
    /// pathological workload to fill.
    pub discovery_cache_limits: ProviderStoreLimits,
}

impl Default for DhtConfig {
    fn default() -> Self {
        DhtConfig {
            k: 20,
            alpha: 3,
            provider_ttl: Duration::from_secs(2 * 60 * 60),
            republish_interval: Duration::from_secs(60 * 60),
            refresh_interval: Duration::from_secs(60 * 60),
            rpc_timeout: Duration::from_secs(5),
            provider_store_limits: ProviderStoreLimits::default(),
            discovery_cache_ttl: Duration::from_secs(15 * 60),
            discovery_cache_limits: ProviderStoreLimits {
                max_providers_per_key: 8,
                max_total_records: 10_000,
            },
        }
    }
}

impl DhtConfig {
    /// The provider TTL in whole seconds (records store an absolute Unix-seconds expiry).
    pub fn provider_ttl_secs(&self) -> u64 {
        self.provider_ttl.as_secs()
    }

    /// The discovery-cache TTL in whole seconds (the cache stores absolute Unix-seconds expiries).
    pub fn discovery_cache_ttl_secs(&self) -> u64 {
        self.discovery_cache_ttl.as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_kademlia() {
        let c = DhtConfig::default();
        assert_eq!(c.k, 20);
        assert_eq!(c.alpha, 3);
        assert_eq!(c.provider_ttl_secs(), 7200);
    }

    #[test]
    fn republish_is_shorter_than_ttl() {
        // Invariant: a record must be republished before it expires, or providers vanish while online.
        let c = DhtConfig::default();
        assert!(c.republish_interval < c.provider_ttl);
    }

    #[test]
    fn discovery_cache_ttl_is_shorter_than_the_provider_ttl() {
        // Invariant (SPEC §6.8): nothing republishes into the discovery cache, so a cached record
        // must age out sooner than an authoritative one that a live holder keeps refreshing.
        let c = DhtConfig::default();
        assert!(c.discovery_cache_ttl < c.provider_ttl);
        assert_eq!(c.discovery_cache_ttl_secs(), 900);
    }

    #[test]
    fn default_discovery_cache_limits_are_bounded() {
        // The cache is written from records supplied by untrusted peers, so its growth must be
        // bounded out of the box exactly as the authoritative store's is.
        let c = DhtConfig::default();
        assert!(c.discovery_cache_limits.max_providers_per_key > 0);
        assert!(c.discovery_cache_limits.max_total_records > 0);
        assert!(
            c.discovery_cache_limits.max_total_records
                < c.provider_store_limits.max_total_records
        );
    }

    #[test]
    fn default_provider_store_limits_are_bounded() {
        // The audit's "unbounded provider store" finding: the default config MUST carry a non-zero,
        // finite cap so a freshly constructed DhtService is never unbounded out of the box.
        let c = DhtConfig::default();
        assert!(c.provider_store_limits.max_providers_per_key > 0);
        assert!(c.provider_store_limits.max_total_records > 0);
    }
}
