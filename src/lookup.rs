//! The iterative Kademlia lookup: converge on the `k` closest peers to a target key by repeatedly
//! querying the `α` closest un-queried peers we know, folding their returned closer contacts back
//! into the shortlist, until no closer peer can be found.
//!
//! This is the heart of a Kademlia DHT. [`iterative_find`] drives it:
//!
//! 1. Seed a **shortlist** with the closest contacts we already know (routing table + bootstrap).
//! 2. Each round, pick the `α` closest **un-queried** contacts and query them in parallel with the
//!    supplied `query` closure (a `find_node` for node lookup, or a `find_providers` for provider
//!    lookup — the closure returns both closer contacts AND any providers it collected).
//! 3. Merge every returned contact into the shortlist (dedup by `peer_id`), keeping it sorted by XOR
//!    distance to the target and capped so it stays bounded.
//! 4. Stop when a full round of the `k` closest have all been queried and none produced a strictly
//!    closer un-queried contact — the shortlist has converged. Return the `k` closest and any
//!    providers collected.
//!
//! The closure abstraction means node-lookup and provider-lookup share ONE convergence engine; only
//! what each query returns differs. Transport failures to individual peers are non-fatal — a peer
//! that errors is simply marked queried and the walk continues (the service's query closure maps a
//! transport error to `Err(())`).
//!
//! Each round's `α`-sized batch is queried **truly concurrently**: every peer's RPC is
//! [`tokio::spawn`]ed as its own task, so all `α` requests are in flight at once rather than
//! awaited one at a time. A round of `α` peers that each stall to the transport timeout therefore
//! costs about one `rpc_timeout`, not `α × rpc_timeout`.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use crate::key::Key;
use crate::record::ProviderRecord;
use crate::routing::Contact;

/// Absolute ceiling on the number of iterative rounds a single lookup may run (#1352). A converging
/// Kademlia lookup needs O(log n) rounds; this bound only ever trips on a pathological/adversarial
/// swarm where responders keep feeding an endless stream of ever-closer contacts to prevent
/// convergence (a lookup-livelock DoS). 64 rounds is far beyond any honest convergence depth.
pub const MAX_LOOKUP_ROUNDS: usize = 64;

/// Baseline ceiling on how many provider records a single peer's response may contribute to a
/// lookup (#1352). An honest responder returns at most its per-key cap (`max_providers_per_key`,
/// default 20) live records; a response off the wire is untrusted and could otherwise pack an
/// unbounded set into one frame, inflating the collected-providers map. The effective cap is the
/// larger of this and `2·k`, so a network tuned to a large `k` is never under-bounded.
pub const MAX_PROVIDERS_PER_RESPONSE: usize = 64;

/// Baseline ceiling on how many `closer` contacts a single peer's response may contribute to a
/// lookup (#1352). An honest responder returns at most `k`; the effective cap is the larger of this
/// and `2·k`. Bounds the per-response merge work an adversarial peer can impose.
pub const MAX_CLOSER_PER_RESPONSE: usize = 64;

/// The outcome of querying one peer during a lookup: the closer contacts it knows, and any provider
/// records it holds for the target (empty for a pure node lookup).
#[derive(Debug, Default, Clone)]
pub struct QueryOutcome {
    /// Contacts the queried peer returned as closer to the target (its `find_node` answer).
    pub closer: Vec<Contact>,
    /// Provider records the queried peer holds for the target key (its `find_providers` answer).
    pub providers: Vec<ProviderRecord>,
}

/// The result of a completed iterative lookup.
#[derive(Debug, Default, Clone)]
pub struct LookupResult {
    /// The `k` closest contacts to the target the lookup converged on (closest-first).
    pub closest: Vec<Contact>,
    /// All distinct provider records collected across the walk (dedup by provider `peer_id`).
    pub providers: Vec<ProviderRecord>,
}

/// A single node in the lookup shortlist: a contact, its precomputed distance to the target, and
/// whether we have queried it yet.
struct ShortlistEntry {
    contact: Contact,
    distance: crate::key::Distance,
    queried: bool,
    /// A peer that returned an error / was unreachable — counts as queried, never re-tried.
    failed: bool,
}

/// Drive an iterative lookup toward `target`, seeded with `seeds`, querying at most `alpha` peers per
/// round and converging on the `k` closest.
///
/// `query` is invoked per peer to talk to it; it returns the peer's [`QueryOutcome`] (closer
/// contacts + any providers). An `Err` from `query` marks that peer failed and the walk continues —
/// a single unreachable peer never aborts the lookup. `stop_on_providers`, when `true`, ends the
/// lookup as soon as at least one provider has been collected (used by `find_providers`, which wants
/// the first holders fast, not the exhaustive `k`-closest walk).
///
/// The `query` closure is cloned per peer, so it must be `Clone` (the service passes an `Arc`-backed
/// closure over the transport). It must also be `Send + 'static` (and its future `Send + 'static`)
/// because each peer's query is [`tokio::spawn`]ed to run the round's `α`-sized batch concurrently.
pub async fn iterative_find<F, Fut>(
    target: Key,
    seeds: Vec<Contact>,
    k: usize,
    alpha: usize,
    stop_on_providers: bool,
    query: F,
) -> LookupResult
where
    F: Fn(Contact) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<QueryOutcome, ()>> + Send + 'static,
{
    let mut shortlist: Vec<ShortlistEntry> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // Collected providers, deduped by provider peer_id.
    let mut providers: HashMap<String, ProviderRecord> = HashMap::new();

    // Untrusted-response ceilings (#1352): bound how much one peer's response may contribute, so a
    // single adversarial responder cannot inflate the collected-providers map or the per-round merge
    // work. Scaled up for a large-`k` network so an honest responder is never truncated.
    let max_providers_per_response = MAX_PROVIDERS_PER_RESPONSE.max(k.saturating_mul(2));
    let max_closer_per_response = MAX_CLOSER_PER_RESPONSE.max(k.saturating_mul(2));

    // Seed.
    for c in seeds {
        merge_contact(&mut shortlist, &mut seen, &target, c);
    }
    sort_and_cap(&mut shortlist, k, alpha);

    // Round guard (#1352): an absolute cap so an adversarial swarm feeding endless ever-closer
    // contacts cannot livelock the lookup — it always terminates in at most `MAX_LOOKUP_ROUNDS`.
    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > MAX_LOOKUP_ROUNDS {
            break;
        }
        // Pick the α closest un-queried, non-failed entries.
        let batch: Vec<Contact> = shortlist
            .iter()
            .filter(|e| !e.queried && !e.failed)
            .take(alpha)
            .map(|e| e.contact.clone())
            .collect();

        if batch.is_empty() {
            break; // nothing left to ask → converged
        }

        // Query the batch CONCURRENTLY: spawn each peer's RPC as its own task so all `alpha`
        // requests are in flight at once, instead of awaiting them one at a time (which would cost
        // up to alpha * rpc_timeout when peers stall — SECURITY_AUDIT_P2P.md #179).
        let mut set = tokio::task::JoinSet::new();
        for c in &batch {
            let q = query.clone();
            let c2 = c.clone();
            set.spawn(async move { (c2.peer_id.clone(), q(c2).await) });
        }
        let mut results = Vec::with_capacity(batch.len());
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(pair) => results.push(pair),
                Err(_join_err) => {
                    // A spawned query task panicked or was cancelled. We don't know which peer_id
                    // it was (the JoinError doesn't carry our closure's captured id), so it cannot
                    // be marked queried/failed individually; the lookup still terminates because
                    // the batch-empty / converged checks below do not depend on every task
                    // succeeding, and a peer that never reports back simply stays eligible to be
                    // re-picked in the extremely unlikely event this happens (task panics are not
                    // expected from the query closure's Result-returning contract).
                }
            }
        }

        // Fold results back in.
        for (peer_id, res) in results {
            mark_queried(&mut shortlist, &peer_id, res.is_err());
            if let Ok(mut outcome) = res {
                // Truncate each list to the untrusted-response ceiling (#1352) BEFORE folding, so a
                // single peer cannot inflate the providers map or impose unbounded merge work.
                outcome.providers.truncate(max_providers_per_response);
                outcome.closer.truncate(max_closer_per_response);
                for p in outcome.providers {
                    providers.entry(p.provider_peer_id.clone()).or_insert(p);
                }
                for c in outcome.closer {
                    merge_contact(&mut shortlist, &mut seen, &target, c);
                }
            }
        }
        sort_and_cap(&mut shortlist, k, alpha);

        if stop_on_providers && !providers.is_empty() {
            break;
        }

        // Converged? If the α closest are all queried/failed and no un-queried peer is closer than
        // the k-th closest already-queried peer, we are done. The batch-empty check at the top of the
        // next loop handles the general case; this early-out avoids an extra idle round.
        let any_unqueried_in_top_k = shortlist.iter().take(k).any(|e| !e.queried && !e.failed);
        if !any_unqueried_in_top_k {
            break;
        }
    }

    let closest = shortlist
        .into_iter()
        .filter(|e| !e.failed)
        .take(k)
        .map(|e| e.contact)
        .collect();
    LookupResult {
        closest,
        providers: providers.into_values().collect(),
    }
}

/// Insert `contact` into the shortlist if new (dedup by `peer_id`), computing its distance to the
/// target. A contact with a malformed `peer_id` (no key) is skipped.
fn merge_contact(
    shortlist: &mut Vec<ShortlistEntry>,
    seen: &mut HashSet<String>,
    target: &Key,
    contact: Contact,
) {
    if seen.contains(&contact.peer_id) {
        return;
    }
    let Some(key) = contact.key() else {
        return;
    };
    seen.insert(contact.peer_id.clone());
    let distance = target.distance(&key);
    shortlist.push(ShortlistEntry {
        contact,
        distance,
        queried: false,
        failed: false,
    });
}

/// Mark the entry for `peer_id` as queried (and failed if the query errored).
fn mark_queried(shortlist: &mut [ShortlistEntry], peer_id: &str, failed: bool) {
    if let Some(e) = shortlist.iter_mut().find(|e| e.contact.peer_id == peer_id) {
        e.queried = true;
        e.failed = failed;
    }
}

/// Keep the shortlist sorted closest-first and bounded. We keep more than `k` so late-arriving
/// closer contacts still have room, but cap it to avoid unbounded growth on a large network.
fn sort_and_cap(shortlist: &mut Vec<ShortlistEntry>, k: usize, alpha: usize) {
    shortlist.sort_by_key(|e| e.distance);
    // A generous cap: the k closest we will return, plus headroom for α parallel probes and their
    // returned neighbours. Bounds memory without discarding a contact that could still be in the top-k.
    let cap = (k * 3).max(k + alpha * 2);
    if shortlist.len() > cap {
        shortlist.truncate(cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::CandidateAddr;
    use dig_nat::PeerId;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn contact_from_key(key_bytes: [u8; 32]) -> Contact {
        Contact::new(
            &PeerId::from_bytes(key_bytes),
            vec![CandidateAddr::direct("h", 1)],
        )
    }

    /// A simulated network: each node knows the `k` closest of all node ids to any target (a perfect
    /// oracle neighbour set). This lets us assert convergence to the true k-closest.
    fn oracle_query(
        all_ids: Vec<[u8; 32]>,
        target: Key,
        k: usize,
        counter: Arc<AtomicUsize>,
    ) -> impl Fn(Contact) -> std::pin::Pin<Box<dyn Future<Output = Result<QueryOutcome, ()>> + Send>>
           + Clone {
        move |_c: Contact| {
            counter.fetch_add(1, Ordering::SeqCst);
            let all_ids = all_ids.clone();
            Box::pin(async move {
                let mut sorted: Vec<[u8; 32]> = all_ids;
                sorted.sort_by_key(|id| *target.distance(&Key::from_bytes(*id)).as_bytes());
                let closer = sorted.into_iter().take(k).map(contact_from_key).collect();
                Ok(QueryOutcome {
                    closer,
                    providers: vec![],
                })
            })
        }
    }

    #[tokio::test]
    async fn converges_to_k_closest_in_simulated_network() {
        // 50 node ids with varied top bytes.
        let all_ids: Vec<[u8; 32]> = (0u8..50)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0] = i.wrapping_mul(5);
                b[1] = i;
                b
            })
            .collect();
        let target = Key::from_bytes([0u8; 32]);
        let k = 20;
        let counter = Arc::new(AtomicUsize::new(0));

        // Seed with just a couple of arbitrary (possibly far) nodes.
        let seeds = vec![contact_from_key(all_ids[40]), contact_from_key(all_ids[45])];
        let query = oracle_query(all_ids.clone(), target, k, counter.clone());

        let result = iterative_find(target, seeds, k, 3, false, query).await;

        // Compute the true k-closest.
        let mut expected = all_ids.clone();
        expected.sort_by_key(|id| *target.distance(&Key::from_bytes(*id)).as_bytes());
        let expected_top: Vec<Contact> =
            expected.into_iter().take(k).map(contact_from_key).collect();

        assert_eq!(result.closest.len(), k);
        // The closest returned must equal the true k-closest as a set.
        let got: HashSet<String> = result.closest.iter().map(|c| c.peer_id.clone()).collect();
        let exp: HashSet<String> = expected_top.iter().map(|c| c.peer_id.clone()).collect();
        assert_eq!(got, exp, "lookup must converge on the true k-closest");
        // The closest entry must be the globally closest id.
        assert_eq!(result.closest[0].peer_id, expected_top[0].peer_id);
    }

    #[tokio::test]
    async fn empty_seeds_returns_empty() {
        let target = Key::from_bytes([0u8; 32]);
        let result = iterative_find(target, vec![], 20, 3, false, |_c: Contact| async {
            Ok(QueryOutcome::default())
        })
        .await;
        assert!(result.closest.is_empty());
        assert!(result.providers.is_empty());
    }

    #[tokio::test]
    async fn stop_on_providers_ends_early() {
        let target = Key::from_bytes([0u8; 32]);
        let seed = contact_from_key([0x10; 32]);
        let provider = ProviderRecord::new(
            &target,
            &PeerId::from_bytes([0xAB; 32]),
            vec![CandidateAddr::direct("h", 9444)],
            u64::MAX,
        );
        let p2 = provider.clone();
        let result = iterative_find(target, vec![seed], 20, 3, true, move |_c: Contact| {
            let p = p2.clone();
            async move {
                Ok(QueryOutcome {
                    closer: vec![],
                    providers: vec![p],
                })
            }
        })
        .await;
        assert_eq!(result.providers.len(), 1);
        assert_eq!(
            result.providers[0].provider_peer_id,
            provider.provider_peer_id
        );
    }

    #[tokio::test]
    async fn failed_peers_do_not_abort_lookup() {
        // Every query fails → lookup still terminates, returns no closer/providers, no panic/hang.
        let target = Key::from_bytes([0u8; 32]);
        let seeds = vec![contact_from_key([0x01; 32]), contact_from_key([0x02; 32])];
        let result = iterative_find(target, seeds, 20, 3, false, |_c: Contact| async {
            Err::<QueryOutcome, ()>(())
        })
        .await;
        // Failed seeds are excluded from `closest`.
        assert!(result.closest.is_empty());
    }

    #[tokio::test]
    async fn dedups_providers_by_peer_id() {
        let target = Key::from_bytes([0u8; 32]);
        let seeds = vec![contact_from_key([0x01; 32]), contact_from_key([0x02; 32])];
        let provider =
            ProviderRecord::new(&target, &PeerId::from_bytes([0xAB; 32]), vec![], u64::MAX);
        let p = provider.clone();
        // Both seeds return the SAME provider → must be deduped to 1.
        let result = iterative_find(target, seeds, 20, 3, false, move |_c: Contact| {
            let p = p.clone();
            async move {
                Ok(QueryOutcome {
                    closer: vec![],
                    providers: vec![p],
                })
            }
        })
        .await;
        assert_eq!(result.providers.len(), 1);
    }

    // ---- Untrusted-response caps (#1352) ----

    #[tokio::test]
    async fn providers_per_response_is_capped() {
        // One seed returns a flood of DISTINCT providers in a single response; the collected set must
        // be bounded by the untrusted-response ceiling, not the raw flood.
        let target = Key::from_bytes([0u8; 32]);
        let seed = contact_from_key([0x10; 32]);
        let flood: Vec<ProviderRecord> = (0u32..10_000)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0..4].copy_from_slice(&i.to_be_bytes());
                ProviderRecord::new(&target, &PeerId::from_bytes(b), vec![], u64::MAX)
            })
            .collect();
        let result = iterative_find(target, vec![seed], 20, 3, false, move |_c: Contact| {
            let flood = flood.clone();
            async move {
                Ok(QueryOutcome {
                    closer: vec![],
                    providers: flood,
                })
            }
        })
        .await;
        let cap = MAX_PROVIDERS_PER_RESPONSE.max(20 * 2);
        assert!(
            result.providers.len() <= cap,
            "providers-per-response must be capped at {cap}, got {}",
            result.providers.len()
        );
    }

    #[tokio::test]
    async fn round_guard_terminates_a_non_converging_lookup() {
        // An adversarial responder that ALWAYS returns a brand-new, strictly-closer contact would
        // livelock a lookup forever without a round cap. The round guard (#1352) must bound total
        // work: at most MAX_LOOKUP_ROUNDS rounds of alpha queries (+ the seed).
        let target = Key::from_bytes([0xFF; 32]);
        let seed = contact_from_key([0x00; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        const ALPHA: usize = 3;
        let result = iterative_find(target, vec![seed], 20, ALPHA, false, move |_c: Contact| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            // Each call fabricates a unique contact ever-closer to the target (high bytes = 0xFF),
            // so the shortlist never converges — only the round guard stops it.
            let mut b = [0xFFu8; 32];
            b[24..32].copy_from_slice(&(n as u64).to_be_bytes());
            async move {
                Ok(QueryOutcome {
                    closer: vec![contact_from_key(b)],
                    providers: vec![],
                })
            }
        })
        .await;
        let total = calls.load(Ordering::SeqCst);
        assert!(
            total <= MAX_LOOKUP_ROUNDS * ALPHA + 1,
            "round guard must bound total queries to ~MAX_LOOKUP_ROUNDS*alpha, got {total}"
        );
        // It still terminates and returns a bounded result (proof it did not hang).
        assert!(result.closest.len() <= 20);
    }

    // ---- Concurrency (MEDIUM/optimization: join_all awaits sequentially, SECURITY_AUDIT_P2P.md #179) ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn alpha_batch_is_queried_concurrently_not_sequentially() {
        // Seed exactly `alpha` peers who each "stall" for DELAY, and never return closer contacts
        // (so the walk needs exactly one round). If the batch is awaited sequentially, wall clock
        // is ~alpha * DELAY; if concurrent, it is ~1 * DELAY. Assert well under alpha * DELAY so a
        // regression back to sequential awaiting fails this test.
        const ALPHA: usize = 4;
        const DELAY: std::time::Duration = std::time::Duration::from_millis(150);

        let target = Key::from_bytes([0u8; 32]);
        let seeds: Vec<Contact> = (1u8..=ALPHA as u8)
            .map(|i| contact_from_key([i; 32]))
            .collect();

        let start = std::time::Instant::now();
        let result = iterative_find(target, seeds, 20, ALPHA, false, |_c: Contact| async move {
            tokio::time::sleep(DELAY).await;
            Ok(QueryOutcome::default())
        })
        .await;
        let elapsed = start.elapsed();

        assert_eq!(result.closest.len(), ALPHA, "all alpha peers answered");
        assert!(
            elapsed < DELAY * (ALPHA as u32) / 2,
            "batch must run concurrently: expected well under {:?} (alpha * delay), got {:?}",
            DELAY * (ALPHA as u32),
            elapsed
        );
    }
}
