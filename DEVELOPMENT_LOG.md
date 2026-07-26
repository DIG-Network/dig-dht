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

## A preference policy must never outrank liveness

The establishment floor added for #1434 reserved a key's earliest-admitted providers from eviction —
and, as first written, reserved them by admission order ALONE. That silently inverted a property the
previous policy had for free: `min_by_key(expires_at)` always evicted an expired record first, so dead
slots were self-clearing. With a floor in front of it, a dead record inside the floor outranked a live
provider in the churn zone.

What makes this worth recording is that it needed no attacker. The node's GC tick is hourly while
`provider_ttl` is two hours, so ordinary churn — a holder shutting down, a cache evicting a capsule —
leaves expired records inside a key's floor for up to an hour, and during that window every new
announcement evicted a live provider. Announcing MORE holders made a capsule LESS discoverable. A
hardening change had turned the replication flywheel backwards.

The generalisable rule: when adding a preference/reservation policy on top of an eviction rule, check
what the OLD rule was giving you incidentally. Ranking by a value (`expires_at`) had encoded a liveness
test; ranking by a different value (`admitted_seq`) dropped it. Liveness is a precondition, not a
preference — it belongs before the policy, not inside it.

A related shape: the four #1434 tests were written with expiry values like `100` and passed through
`put`, which reads the wall clock — so every record in them was *already expired* by ~1.8 billion
seconds. They asserted establishment while testing nothing of the kind. Any test about record
preference must pin `now` explicitly (`put_at`), or the values silently mean something else.

## A cap applied after a sort can delete a whole tier

`dial_candidates` sorted IPv6-first then truncated to 4, which is correct in aggregate and wrong at the
boundary: a holder advertising four IPv6 candidates yielded a dial set containing NO IPv4, so a dialer
that faithfully walked every candidate still never reached the working address — the exact #836 failure
the iterator was built to prevent. Again reachable without an attacker, since a dual-stack holder
legitimately emits direct + mapped + reflexive v6 and the 8-address record cap leaves room.

Sort-then-truncate silently assumes the head of the list is REPRESENTATIVE of it. When the ordering is
by tier and a lower tier is a *fallback* (i.e. load-bearing precisely when the preferred tier fails),
the cap must reserve a slot for it. A ranking expresses preference; it must not be allowed to express
exclusion.

The dedup key interacts with this: deduplicating on the raw host string let one address spelled four
ways (`2001:db8::1`, `2001:0db8::1`, `2001:db8:0:0:0:0:0:1`, `2001:DB8::1`) consume the entire cap.
Dedup by PARSED endpoint, not by text, wherever the text has a canonical form.

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
