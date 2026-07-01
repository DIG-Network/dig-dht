//! [`DhtConfig`] — the Kademlia tuning parameters (replication `k`, lookup parallelism `α`, provider
//! TTL, and the maintenance intervals).

use std::time::Duration;

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
        }
    }
}

impl DhtConfig {
    /// The provider TTL in whole seconds (records store an absolute Unix-seconds expiry).
    pub fn provider_ttl_secs(&self) -> u64 {
        self.provider_ttl.as_secs()
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
}
