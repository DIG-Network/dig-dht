# dig-dht — development log

Durable realizations from building and hardening this crate: non-obvious mechanics, cross-repo
couplings, and sharp edges that cost real debugging time. Context, not a change diary — the
normative behaviour lives in `SPEC.md`, and the release history in `CHANGELOG.md`.

## A TTL clamp makes "soonest-to-expire" an attacker-chosen ordering

Every inbound provider record has its `expires_at` clamped to `now + provider_ttl` at admission
(§6.2) — a good rule on its own: it stops a record naming `u64::MAX` from outliving GC. But it also
means the expiry field is a **function of announce time**, so whoever announces LAST holds the
latest expiry.

Any policy that ranks records by `expires_at` therefore inherits an ordering the attacker controls
for free. Provider eviction did: "evict the soonest-to-expire" resolved deterministically to "evict
whoever got here first", and provider records are unsigned self-assertions, so 20 throwaway
identities could displace the only genuine holder of a capsule. The lesson generalizes beyond this
one site — **a clamped or derived field is not a trust signal.** Establishment (admission ORDER,
recorded locally, never taken from the wire) is, which is why eviction now reserves each key's
earliest-admitted half.

The same reasoning is why establishment is an admission ORDINAL rather than a timestamp: an ordinal
needs no clock threaded through `ProviderStore::put`, and there is nothing in it for a peer to
influence.

## Capping at call sites is not the same as capping by construction

`ProviderRecord` and `Contact` have **public fields**, so `ProviderRecord::new`'s address cap is
advisory: any value deserialized from the wire bypasses the constructor entirely. The crate handled
this by calling `sort_and_cap_addresses` at each ingest site — correct, but it is a rule every future
ingest path has to remember, and the audit that produced #1514 could not tell by reading one file
whether the bound actually held.

Enforcing the bound in the serde `deserialize_with` hook makes it structural: deserialization is the
one gate every untrusted address list must pass. Two details worth keeping:

- **Bound, do not reject.** Failing the decode of an over-long list would make a non-conforming or
  older producer's record unreadable and would let a peer poison a whole frame with one padded
  record. Truncation degrades gracefully; rejection is a denial-of-service lever.
- **Sort before truncating**, or a hostile sender simply lists the one reachable address last.

## Two crates independently "implementing §5.2" is how the rule quietly breaks

`dig-download` 0.7.3 wrote its own `dial_candidates` (V6 → V4 → unresolvable) after `best_address()`
caused the #836 read-leg failure — one IPv6 candidate tried, a working IPv4 candidate never dialed.
Fixing it locally was right for the release but left two orderings in the ecosystem, and they do not
agree on **IPv4-mapped IPv6** (`::ffff:a.b.c.d`):

- dig-download ranks it by `SocketAddr` variant, so a mapped address is V6 → tried FIRST;
- dig-dht ranks it via `dig_ip::Family::of`, the canonical source of truth, which classifies it as
  **V4** (it is IPv4 reachability) → tried as the fallback.

`dig_ip::Family` is the ecosystem contract, so dig-dht's classification is the correct one. Any
consumer that re-derives address family from a `parse::<IpAddr>()` or a `contains(':')` check will
disagree with it on exactly this case — which is the case AWS hosts actually advertise. Consume
`ProviderRecord::dial_candidates()` / `Contact::dial_candidates()` instead of re-deriving.

An API that returns ONE address invites single-attempt dialing no matter how its doc-comment is
worded, which is why `best_address()` is now documented as display-only and the ordered iterator is
the dial path.

## A peer's answer is not bound to your question unless you bind it

`find_providers` merged whatever a queried peer returned. Nothing in a Kademlia response ties a
provider record to the key that was asked for, and the record is unsigned, so any peer on a lookup
path could return records for keys the finder never queried.

The subtle part is WHERE the check belongs. Filtering at the final merge would have stopped off-key
records reaching the caller, but the lookup's `stop_on_providers` early exit fires on the first
provider collected — so an off-key record counted as "found" ends the walk before it reaches a real
holder. A wasted-dial defect at the merge point is a discovery-censorship defect one layer up.
Validate untrusted input at the boundary where it ENTERS, not where it leaves.

## The in-memory swarm harness is the cheapest place to model a hostile peer

`tests/swarm.rs` routes each node's RPCs to another node's real `handle_request_from`, so honest
behaviour is end-to-end. To model a MISBEHAVING peer, implement `DhtTransport` directly and answer
however the attacker would — no sockets, no fixtures.

Parameterize the misbehaviour rather than hard-wiring it. A double that can only lie cannot
distinguish "the guard works" from "the guard drops everything"; the same `StampingTransport` proves
both by varying one field.
