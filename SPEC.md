# dig-dht — Normative Specification

This document is the authoritative statement of what the `dig-dht` crate implements: a Kademlia
DHT with **provider records** for the DIG Node peer network. It specifies the wire protocol, the
keyspace and key derivation, the record and routing-table semantics, the lookup algorithm, the
public API surface, configuration defaults, error behavior, and security properties.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted
as described in RFC 2119. Statements marked as *wire contracts* are fixed at the field/byte level;
a conforming reimplementation must reproduce them exactly.

The ecosystem-level normative anchor for this protocol is the DIG Protocol **Peer network** page
(docs.dig.net → Protocol → Peer network, §4c "Content discovery — the DHT" and the "DHT RPC — a
distinct framed wire" subsection). Where this document and that page describe the same contract,
they agree; this document additionally pins the crate-level API semantics.

---

## 1. Scope and role

`dig-dht` answers exactly one question for a DIG Node: **"which peers hold this content?"**

- A node that holds content (a store / capsule / root / resource) **announces** a provider record
  keyed by a content identifier (§4).
- A node that wants content runs an iterative **find-providers lookup** (§8) and receives the set
  of holder `peer_id`s with candidate addresses.
- The DHT **locates** peers only. Byte transfer is out of scope: the finder connects to providers
  over `dig-nat` (mTLS, `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`) and fetches via the L7
  peer RPC (`dig.getAvailability` → `dig.fetchRange`), which are specified on the Peer network page.

Every node is simultaneously a DHT **client** (it runs lookups) and a DHT **server** (it holds a
slice of the routing table and of the global provider records and answers inbound RPCs, §10).

## 2. Identity and keyspace

### 2.1 Keys

- The keyspace is **256-bit**. A `Key` is 32 bytes, interpreted big-endian.
- A **node's key IS its `peer_id`, verbatim**. `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`
  (the `dig_nat::PeerId`) is already a uniform 256-bit value; the DHT node id and the peer id are
  one and the same. Implementations MUST NOT re-hash the peer id.
- A **content key** is derived from a `ContentId` per §4.2.
- The canonical text rendering of a key (and of a `peer_id`) is **lowercase 64-character hex**.
  Producers MUST emit lowercase hex on the wire (see §5.6 for why this is load-bearing for
  `content_key`).

### 2.2 Distance metric

- The distance between two keys is their bytewise **XOR**, compared as a **big-endian unsigned
  integer** (smaller = closer). Distance is symmetric; distance-to-self is zero.
- The **bucket index** of a nonzero distance is `255 − leading_zero_bits(distance)` — the position
  of the most-significant set bit, equivalently indexing by shared-prefix length with the local
  node. The zero distance has no bucket index (a node never buckets itself).

*Wire contract:* every implementation MUST derive the identical key, distance, and bucket index for
the same inputs, or provider records announced by one implementation are not found by another.

## 3. Content granularities

A `ContentId` matches the availability granularities of the L7 peer network:

| Variant | Fields | Answers |
|---|---|---|
| `Store` | `store_id` (32 bytes) | "does a peer serve this store at all?" |
| `Root` | `store_id` + `root` (32 bytes each) | "does a peer have this generation `(store_id, root)`?" — the immutable **capsule** `store_id:root` |
| `Resource` | `store_id` + `root` + `retrieval_key` (32 bytes each) | "does a peer have this resource within the capsule?" |

`ContentId::capsule(store_id, root)` is an exact alias of `ContentId::root(store_id, root)`: a
capsule IS a root generation; the two construct the same variant and derive the same key.

## 4. Content-key derivation (frozen wire contract)

### 4.1 Domain-separation tags

| Tag byte | Granularity | Canonical bytes |
|---|---|---|
| `0x01` | Store | `0x01 ‖ store_id` (33 bytes) |
| `0x02` | Root / capsule | `0x02 ‖ store_id ‖ root` (65 bytes) |
| `0x03` | Resource | `0x03 ‖ store_id ‖ root ‖ retrieval_key` (97 bytes) |

These tag values are **frozen**: they MUST NOT be renumbered or repurposed. New granularities MAY
be added only with new, previously unused tag bytes.

### 4.2 Derivation

```
content_key = SHA-256( tag ‖ fixed-order raw 32-byte fields )
```

- The encoding is canonical: fixed field order, raw (un-hexed) 32-byte hashes, one leading tag
  byte. Every implementation MUST derive the identical key for the same content.
- Domain separation guarantees that a store key, a root key, and a resource key are **distinct
  points** even when they share the same `store_id` (and that no field-shifting collision between
  granularities is possible), so their provider records never collide in the DHT.

## 5. Wire protocol

### 5.1 Transport binding

The DHT RPC rides an authenticated `dig-nat` peer connection (mTLS, multiplexed logical streams):
each RPC opens a logical stream, writes one framed request, and reads one framed response. The
caller's identity is established by the mTLS handshake, **never** by any field in the request body
(§10.2, §14).

### 5.2 Framing (wire contract)

Every DHT message — request and response — is framed as:

```
u32 big-endian body length ‖ JSON body
```

- This framing is byte-identical to the `dig-nat` control-message framing, so a node speaks one
  framing across the peer network.
- The body length MUST NOT exceed **`MAX_FRAMED_BODY` = 262 144 bytes (256 KiB)**. A receiver MUST
  reject a frame whose declared length exceeds this bound *before* allocating, with an
  invalid-data error. A truncated frame (fewer body bytes than declared) MUST error, not hang or
  yield a partial message.
- The JSON body is a `type`-tagged object (snake_case tags). Decoders MUST ignore unknown fields
  (forward compatibility: new fields are additive); an unknown `type` tag fails the decode.

### 5.3 The four RPC methods (wire contract)

| Method | Request | Response |
|---|---|---|
| `find_node` | `{ "type":"find_node", "target":"<64hex>" }` | `{ "type":"nodes", "nodes":[Contact] }` |
| `find_providers` | `{ "type":"find_providers", "content_key":"<64hex>" }` | `{ "type":"providers", "providers":[ProviderRecord], "closer":[Contact] }` |
| `add_provider` | `{ "type":"add_provider", "record":ProviderRecord }` | `{ "type":"add_provider_ok" }` |
| `ping` | `{ "type":"ping", "nonce":<u64> }` | `{ "type":"pong", "nonce":<u64> }` |

Semantics:

- **`find_node`** — the responder returns up to `k` contacts it knows closest (XOR) to `target`,
  closest-first, from its routing table.
- **`find_providers`** — the responder returns every **live** (non-expired, §6.2) provider record
  it holds for `content_key`, **plus, always,** the up-to-`k` closer contacts it knows
  (`closer`) — even when providers were found, because more providers may live nearer the key.
  This unconditional `closer` is what lets an iterative lookup keep converging.
- **`add_provider`** — the responder stores the record in its local provider store (§6.3) and
  additionally folds the record's provider (peer id + addresses) into its routing table as a
  contact. It replies `add_provider_ok` on acceptance.
- **`ping`** — the responder echoes the request's `nonce` in `pong`. A caller MUST treat a pong
  with a non-matching nonce as a failure.

### 5.4 Error envelope

A responder that cannot answer returns:

```json
{ "type":"error", "code":<uint>, "message":<string> }
```

- The error envelope is **advisory**: a lookup treats a peer that returns it exactly like an
  unreachable peer and walks on. It is never fatal to a lookup.
- Defined codes:
  - **`2` — invalid key** (the `target` / `content_key` was not valid 64-char hex).
  - **`3` — provider store over capacity** (an `add_provider` was rejected by the provider-store
    admission control, §6.3; the record was NOT stored).
  - **`4` — provider identity mismatch** (an `add_provider` named a `provider_peer_id` other than
    the authenticated caller, §6.4; the record was NOT stored).

  Other codes MAY be used by responders; callers MUST NOT rely on codes other than those defined
  here.

### 5.5 Wire shapes (wire contract)

```
Contact        = { "peer_id":"<64hex>", "addresses":[CandidateAddr] }
CandidateAddr  = { "host":<string>, "port":<u16>, "kind":"direct"|"mapped"|"reflexive"|"relay" }
ProviderRecord = { "content_key":"<64hex>", "provider_peer_id":"<64hex>",
                   "addresses":[CandidateAddr], "expires_at":<u64 unix-seconds> }
```

- The `CandidateAddr` shape and the lowercase `kind` tokens are **byte-compatible with the L7
  `dig.getPeers` `addresses[]` shape** (Peer network §7), so a returned `Contact` or
  `ProviderRecord` drops straight into a dial target for the NAT-traversal ladder.
- `kind` rank, most-direct-first: `direct` (0) < `mapped` (1) < `reflexive` (2) < `relay` (3).
- `host` is an IPv4/IPv6 literal or hostname; `port` is the peer's P2P port.
- **Address ordering is IPv6-first, then by `kind` rank** (ecosystem-wide IPv6-first, IPv4-fallback
  rule for peer communication): [`ProviderRecord::new`] and [`Contact::new`] sort their `addresses`
  so every IPv6-literal candidate sorts before every IPv4-literal or hostname candidate, and within
  each family candidates are ordered most-direct-first by `kind` rank. **The address-family half of
  the sort key comes from the canonical `dig-ip` crate (`dig_ip::Family::of`) — the ecosystem's
  single source of truth for the IPv6-first / IPv4-fallback family contract (CLAUDE.md §5.2)** — not
  a hand-rolled `is_ipv6` check, so dig-dht cannot drift off the canonical rule; the dht-specific
  most-direct-first `kind` rank remains dig-dht's own tiebreak within a family. `dig_ip::Family`
  classifies `host` from a real `IpAddr` parse (not a `contains(':')` heuristic), and in particular
  classifies an IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`) as **IPv4** — it is IPv4 reachability, so
  it sorts with the IPv4 family. Address order on the wire is therefore IPv6-first-then-rank as
  produced by a conforming implementation; a consumer that receives a record from a
  non-conforming/older peer MUST NOT assume the ordering and SHOULD still pick by family-then-rank
  itself. A bare `relay` marker (`host:""`, `port:0`) is not directly dialable and sorts as
  IPv4/hostname (its empty `host` does not parse as an IP). This ordering is additive: it does not
  change the `CandidateAddr` field names, types, or JSON encoding — only the list order.
- **Address-list cap is a receive-side limit, NOT a wire encoding change.** `addresses[]` carries
  no length prefix or bound of its own on the wire beyond the overall `MAX_FRAMED_BODY` frame
  (§5.2); an implementation MUST NOT reject or mis-decode a message because it carries more than
  `MAX_ADDRESSES_PER_RECORD` (**8**) addresses — the JSON shape and field shapes are unaffected and
  a conforming decoder MUST successfully parse a longer list. Instead, every point that admits an
  address list into local state (or hands one back to a caller) MUST sort it IPv6-first-then-rank
  (above) and then **truncate to `MAX_ADDRESSES_PER_RECORD`**, so the most-preferred candidates are
  the ones retained: [`ProviderRecord::new`], [`Contact::new`], the responder's `add_provider`
  handling (both the record's own `addresses` and the authenticated caller's `Contact`, §10.2),
  contacts absorbed from a lookup's `closer`/`nodes` results, and provider records returned to a
  `find_providers` caller. This bounds per-record memory and the amplification of re-serving a
  received list to other peers without changing what a conforming peer may transmit or how a
  receiver decodes it.

### 5.6 Hex-case requirement

The `target`, `content_key`, `peer_id`, and `provider_peer_id` fields MUST be **lowercase** 64-hex.
Responders parse-and-renormalize lookup keys, but a stored record's `content_key` string is the
lookup index in the provider store; a non-lowercase `content_key` in `add_provider` would be stored
under a string that lowercase-normalized lookups never match, making the record unfindable.

## 6. Provider records

### 6.1 Meaning

A provider record asserts: *peer `provider_peer_id` holds the content whose key is `content_key`,
reachable at `addresses`, until `expires_at`.* It is **soft state**, not a permanent entry.

### 6.2 TTL semantics

- `expires_at` is an **absolute Unix-seconds** timestamp. A record is expired when
  `now >= expires_at` (the expiry instant itself is expired — the boundary is inclusive).
- Reads MUST never return expired records; garbage collection (§9.4) drops them.
- An announcing node sets `expires_at = now + provider_ttl` (saturating addition) and republishes
  before the TTL elapses (§9.3), so a provider that goes offline ages out automatically.
- **Inbound clamp (wire contract).** A responder handling `add_provider` MUST NOT trust the
  record's `expires_at` as received: before admission (§6.3) it MUST clamp it to
  `min(record.expires_at, now + local provider_ttl)`. Without this clamp, a record naming
  `expires_at = u64::MAX` (or any value far beyond the responder's own TTL horizon) would never
  satisfy `now >= expires_at` and so would never be reclaimed by GC (§9.4) for the life of the
  process. The clamp bounds every third-party record to the responder's own TTL horizon
  regardless of what the announcer claims.

### 6.3 Provider store (per-node local state)

Every node keeps a local provider store, which MUST behave as:

- **Keyed by `content_key` (the 64-hex string) → one record per distinct `provider_peer_id`.**
- **Dedup-on-provider:** a second record from the same provider for the same key REPLACES the
  first (refreshing `expires_at` and `addresses`); it never accumulates duplicates. A refresh
  (same `content_key` + same `provider_peer_id`) MUST always succeed regardless of capacity — it
  does not grow the store.
- **TTL-filtered reads:** `get` returns only records live at the supplied `now`.
- **GC:** expired records (and content keys left with no live providers) are removed; GC returns
  the number of records dropped.
- **Bounded admission control (`put`).** A genuinely new `(content_key, provider_peer_id)` pair is
  subject to two caps, both enforced on every `put`, not just at GC time:
  - **Per-key cap** (`max_providers_per_key`, default **20** — equal to `k`): when a new provider
    for a key would exceed this, the **soonest-to-expire** existing record for that key is evicted
    to make room.
  - **Global cap** (`max_total_records`, default **100 000**): when a new `(content_key,
    provider_peer_id)` pair would exceed this, the `put` is **rejected**
    (`PutOutcome::RejectedOverCapacity`) rather than stored. Rejection MUST NOT evict a
    *different* content key's records — a single peer flooding new keys can never evict another
    key's legitimate holders.
  - A rejected `put` MUST leave the store byte-for-byte as it was before the call (no stray empty
    entry for a content key that was never actually populated).
- The store also tracks the set of content keys **this node itself announces** (its republish
  work list). Marking is idempotent; unmarking returns whether the key was being announced.

On the serving side, `handle_request_from`'s `AddProvider` arm MUST, in order:

1. **Check self-announce identity** (§6.4) when the caller identity is known — reject a
   third-party-named record before doing anything else.
2. **Clamp** `record.expires_at` to the local TTL ceiling (§6.2) — before admission control and
   before storage.
3. **Admit** the (now-clamped) record via `put` (this section) and check the outcome: on
   `RejectedOverCapacity` it MUST return the `error` envelope (§5.4, code `3` — provider store
   over capacity) instead of `add_provider_ok`, and MUST NOT fold the (rejected, unstored)
   record's provider into the routing table.

The implementation does not verify that it is among the `k` closest nodes to the record's key
before accepting an `add_provider` (§14) — that remains a known limitation distinct from capacity
admission.

### 6.4 Self-announce identity check

`ProviderRecord` carries **no signature** (§14): nothing on the wire cryptographically binds a
record to the peer it names as `provider_peer_id`. Without a check, any authenticated caller could
announce an arbitrary *third-party* `provider_peer_id` as a provider of arbitrary content at
attacker-chosen addresses — **provider-set poisoning**: a finder would receive and attempt to dial
a bogus provider, wasting `dig-nat` connection attempts (and, since finders bias toward
first-returned providers, this can also skew which legitimate providers get tried).

- When `handle_request_from` is given a caller identity (the common, authenticated-transport case,
  §10.2), the responder MUST reject an `add_provider` whose `record.provider_peer_id` does not
  equal the caller's `peer_id`, returning the `error` envelope (§5.4, code `4` — provider identity
  mismatch) and MUST NOT store the record or fold its provider into the routing table.
- `handle_request` (no caller identity supplied, §10.2) cannot perform this check — that path
  already deviates from the mTLS-authenticated model and is unaffected by this rule.
- This check is a coarse, unsigned substitute for real authenticity: it constrains announces to
  **self-announces only** (a peer may announce itself, not vouch for others). It does not by
  itself prevent a peer from lying about content it does not actually hold — that integrity comes
  from the download layer's per-chunk merkle verification, not from the record (§14). A future
  signed-record scheme (provider signs `content_key ‖ addresses ‖ expires_at`) would allow
  authenticated third-party relaying; until then, third-party announces are simply rejected.

### 6.5 Authenticated ingest (real-time holdings — engine of the content-replication flywheel)

The serving-side `add_provider` (§6.4) constrains announces to **self-announces** because a
`ProviderRecord` carries no signature and mTLS attribution is all the responder has. The real-time
holdings map lifts that constraint by moving verification to the CALLER: a node's announce receiver
verifies a signed holdings announce (the caller's cryptographic proof of who provides the content),
then pushes the already-verified record into the DHT store via **`ingest_verified_provider`**.

- **`ingest_verified_provider(record) -> PutOutcome`** — store a record whose `provider_peer_id`
  attribution the caller has ALREADY verified (a signature the caller checked; the DHT never sees
  it). Because that verification replaces mTLS attribution, this path **bypasses the §6.4
  self-announce identity check** — a node may thereby ingest a record naming a *third party* as the
  holder, which `add_provider` forbids. **This is the ONLY sanctioned bypass of §6.4**, and it is
  sound only because the caller established authenticity out-of-band.
- **dig-dht stays crypto-free (§15).** `ingest_verified_provider` performs NO signature check; the
  caller is solely responsible for verifying the holder signature before calling. Passing an
  unverified record is a caller bug that poisons the local provider set — the DHT cannot detect it.
- **Every other admission guard still applies, identically to `add_provider`:** the address list is
  capped (§5.5), `expires_at` is clamped to `min(record.expires_at, now + provider_ttl)` (§6.2),
  and the per-key + global admission caps (§6.3) are enforced — an over-capacity ingest returns
  `RejectedOverCapacity` and stores nothing. On acceptance the holder is folded into the routing
  table. `add_provider` (§6.4) and `ingest_verified_provider` share ONE admission pipeline; only the
  identity check differs (present for the former, delegated to the caller for the latter).
- **No chain anchor on ingest (NC-9).** Ingest does NOT require an on-chain proof — anchoring stays
  at FETCH time (the download layer's verification), because requiring a chain read per ingested
  announce would itself be a DoS vector. Ingest is bounded purely by the admission caps above.

### 6.6 Authenticated retract and active own-retract

Provider records are soft state that normally age out via TTL (§6.2). Two operations remove a record
**immediately**, for the content-replication flywheel where a holder that drops content must stop
being advertised at once rather than after a TTL:

- **`remove_provider_record(content_key, provider_peer_id) -> bool`** (inbound retract) — remove
  exactly the local record for `(content_key, provider_peer_id)`. Returns whether a record was
  removed. The caller MUST have verified the retract was signed by that same `provider_peer_id`
  (the DHT does not, §15). It MUST remove ONLY that (key, signer) record — **a retract signed by one
  holder can never evict another provider of the same key** (censorship-resistance). A content key
  left with no remaining providers is dropped.
- **`retract_own_provider(content) -> bool`** (active own-retract) — remove THIS node's own local
  provider record for `content` AND unmark it for republish, so `find_providers` on this node stops
  returning self as a holder immediately. Returns whether this node was providing the content.
  Contrast **`withdraw_provider`** (§9.2), which is passive (stops republish only, leaves the local
  record to expire via TTL). `retract_own_provider` is the local-state half of the flywheel's atomic
  **evict + retract** step; the copies previously PUT at the `k` closest peers are NOT deleted by
  this call — they age out via TTL, or sooner when the node floods the signed retract announce and
  each recipient calls `remove_provider_record`.
- **`holders_of(content) -> Result<Vec<PeerId>, DhtError>`** — a thin, address-free projection over `find_providers`
  (§9.2) for callers that only need "which peers hold X". `find_providers` (which returns full
  records with candidate addresses the download layer dials) remains the PRIMARY query.

## 7. Routing table

### 7.1 Structure

- **256 k-buckets**, each holding up to `k` contacts. A contact with key `K` lives in the bucket
  whose index is `bucket_index(local_key XOR K)` (§2.2) — i.e. bucketed by shared-prefix length
  with the local node.
- A node MUST NOT store its own id in the table. A contact with a malformed (non-64-hex)
  `peer_id` is silently ignored.

### 7.2 Least-recently-seen (LRS) policy

Buckets are ordered least-recently-seen at the front, most-recently-seen at the back:

- **Offer, already present** → the contact moves to the back (recency refreshed, addresses
  updated). The table never double-counts a peer.
- **Offer, room available** → the contact is appended at the back.
- **Offer, bucket full** → the newcomer is NOT inserted; the operation reports the current LRS
  (front) contact. The caller SHOULD then **ping-and-replace**: ping the LRS contact and, only if
  it fails to respond, evict it in favour of the newcomer. Long-lived nodes are kept — this is the
  standard Kademlia eviction-attack resistance.
- **Replace** is guarded: it succeeds only if the named LRS contact is *still* at the front of the
  bucket. If the slot changed in the meantime (e.g. the LRS answered a ping and was refreshed),
  the replace is a no-op and the newcomer is dropped.

### 7.3 Closest query

`closest(target)` returns the `k` contacts nearest `target` by XOR distance across all buckets,
closest-first. This is both the seed set for iterative lookups and the answer to `find_node` /
the `closer` list of `find_providers`.

## 8. Iterative lookup

One convergence engine serves node-lookup and provider-lookup. Given a `target` key, seeds, `k`,
and `α`:

1. **Seed** a shortlist with the closest contacts already known (dedup by `peer_id`; contacts with
   malformed peer ids are skipped), sorted by XOR distance to the target.
2. Each round, query the **`α` closest un-queried, non-failed** shortlist entries **concurrently**
   — implementations MUST issue all `α` RPCs of a round in flight at once (e.g. one task per peer)
   rather than awaiting them one at a time, so a round of `α` peers that each stall to the
   transport timeout costs about one `rpc_timeout`, not `α × rpc_timeout`. The reference
   implementation spawns each peer's query as its own task and joins the round's results as they
   arrive.
3. Fold each response in: collected provider records are deduplicated **by provider `peer_id`**
   (first record per provider wins); returned `closer`/`nodes` contacts merge into the shortlist.
4. Re-sort the shortlist by distance and **cap** it at `max(3·k, k + 2·α)` entries to bound memory.
5. **Failure is non-fatal:** a peer whose RPC errors (transport failure, timeout, error envelope,
   unexpected response shape) is marked failed-and-queried and never retried within the lookup;
   the walk continues.
6. **Termination:** the lookup ends when there is no un-queried, non-failed entry left to ask, or
   when none of the `k` closest entries is still un-queried (converged). If `stop_on_providers`
   is set (used by `find_providers`), the lookup additionally ends as soon as at least one
   provider record has been collected — finders want the first holders fast, not the exhaustive
   `k`-closest walk.
7. **Result:** the up-to-`k` closest **non-failed** contacts (closest-first) plus all distinct
   provider records collected.

**Untrusted-response bounds (wire contract).** A lookup consumes responses from untrusted peers, so
it MUST bound what any one response — or a colluding swarm — can impose:

- **Providers per response** — at most `max(64, 2·k)` provider records from a single response are
  folded into the collected set (the honest per-key cap is `max_providers_per_key`); the rest are
  discarded. Bounds the collected-providers map against a peer that packs an unbounded set into one
  frame.
- **Closer contacts per response** — at most `max(64, 2·k)` `closer`/`nodes` contacts from a single
  response are merged; the rest are discarded. Bounds per-round merge work.
- **Round guard** — a lookup runs at most `MAX_LOOKUP_ROUNDS` (64) iterative rounds. An honest
  lookup converges in O(log n) rounds; the guard only trips on an adversarial swarm feeding endless
  ever-closer contacts to livelock convergence, and guarantees the lookup always terminates.

**Client probe:** the client-side lookup issues `find_providers` as its per-peer probe for *all*
lookup flavours (bootstrap self-lookup, `find_node`, announce placement, and provider lookup),
because its response carries both closer contacts and any providers. A `nodes` response is also
accepted and treated as closer-contacts-only. Responders MUST therefore implement `find_providers`
even if they never store records; `find_node` remains a served wire method.

## 9. Service operations and lifecycle

`DhtService` is the per-node handle. All operations below are its public semantics.

### 9.1 Bootstrap

`bootstrap(peers)` — insert each `BootstrapPeer` (peer id + candidate addresses) into the routing
table, then run a **self-lookup** (an iterative lookup targeting the node's own key, seeded with
the bootstrap contacts) and absorb the discovered contacts. Returns the number of peers now known.

- Bootstrap peers come from the node's existing discovery (the gossip peer pool / the relay
  introducer); the crate takes them as input and MUST NOT hard-depend on a live relay.
- Bootstrap is idempotent-by-merge: calling it repeatedly merges, never resets.

### 9.2 Announce / withdraw / find

- **`announce_provider(content)`** — build a provider record naming THIS node (its id + advertised
  addresses, `expires_at = now + provider_ttl`), store it locally, mark the content key announced
  (for republish), then run a lookup toward the content key and `add_provider` the record at each
  of the converged `k` closest peers (skipping self). Returns the count of peers that accepted.
  Replication is **best-effort**: a peer that errors is skipped. With no peers to ask, the local
  record stands and the return value is 0 — republish re-attempts once bootstrapped.
- **`withdraw_provider(content)`** — stop republishing the key. The record is NOT actively deleted
  from other nodes; it ages out via TTL. Returns whether the key was being announced.
- **`find_providers(content)`** — merge (a) locally held live records for the key and (b) the
  records collected by an iterative lookup toward the key (`stop_on_providers = true`), dedup by
  provider `peer_id`, drop expired records, and return the result. An empty result is **not** an
  error — it means no known providers. `DhtError::NoPeers` is returned only when a lookup has no
  one to seed from *and* is expected to run (`find_node`); `find_providers` with an empty routing
  table returns whatever is held locally (possibly empty).
- **`find_node(peer_id)`** — iterative lookup toward the peer's key; returns the converged closest
  contacts. Errors with `NoPeers` when the routing table is empty.
- **`holders_of(content)`** — the peer ids of the holders `find_providers` finds; an address-free
  projection over `find_providers` (§6.6). Same distributed lookup, same errors.

**Real-time holdings operations** (§6.5, §6.6) — `ingest_verified_provider(record)` (authenticated
third-party inbound add), `remove_provider_record(content_key, provider_peer_id)` (authenticated
inbound retract), and `retract_own_provider(content)` (active own-retract) — mutate the local
provider store directly for the content-replication flywheel and are specified in §6.5/§6.6.

All lookups **absorb** the converged contacts back into the routing table. A full bucket's
LRS-report is left to ping-and-replace maintenance — lookups never block on a liveness ping.

### 9.3 Maintenance loop

The embedding node MUST drive maintenance on the configured intervals:

- **`republish()`** (every `republish_interval`) — for every announced content key: refresh the
  local record (new `expires_at = now + provider_ttl`) and re-run the announce PUT at the current
  `k` closest peers. This keeps records alive while the node is online and heals placement as the
  network churns. `republish_interval` MUST be shorter than `provider_ttl`.
- **`refresh_buckets()`** (every `refresh_interval`) — for every **non-empty** bucket, look up a
  random key whose distance from the local node falls in that bucket (the bit at position
  `255 − bucket_index` set, lower bits randomized), absorbing what the lookup finds.
- **`gc()`** (periodically; MAY piggy-back on the above) — drop expired provider records.
- **`ping(contact)`** — send a `ping` with a fresh random `u64` nonce; alive iff a `pong` echoing
  the same nonce arrives. On any failure (including a nonce mismatch) the peer is **evicted** from
  the routing table and `false` is returned. This is the ping half of ping-and-replace (§7.2).

### 9.4 Provider-record lifecycle (summary)

```
announce_provider ──► local store + announced-set + PUT at k closest
        │                                   │
        │ every republish_interval          │ TTL (provider_ttl) runs down
        ▼                                   ▼
    republish() re-PUTs (new expiry)   expired ⇒ hidden from reads, dropped by gc()
        │
        ▼
withdraw_provider ⇒ stop republishing ⇒ record ages out network-wide via TTL
```

## 10. Serving side

### 10.1 Request handling

`handle_request_from(caller, request)` answers one inbound RPC. It reads/writes only local state
(routing table + provider store) and MUST NOT make outbound RPCs — the server half can never
recurse or block on the network. Behavior per method is §5.3; an unparsable 64-hex key yields the
`error` envelope with code `2`.

### 10.2 Learning the caller (wire contract)

On **every** inbound RPC the responder folds the caller's `Contact` into its routing table (unless
the caller is itself) — every request is evidence the caller is alive, and this is how Kademlia
tables fill bidirectionally without explicit announces. The caller identity MUST come from the
**authenticated transport** (the mTLS-verified `peer_id`), never from a field in the request body —
identity is not self-asserted. `handle_request(request)` (no caller) exists for transports that
cannot supply one; `handle_request_from` SHOULD be preferred.

## 11. Transport abstraction

The crate is written against one trait:

```rust
#[async_trait]
pub trait DhtTransport: Send + Sync {
    async fn rpc(&self, from: &Contact, peer: &Contact, request: &DhtRequest)
        -> Result<DhtResponse, DhtError>;
}
```

A conforming production implementation (wired by the embedding node, e.g. `dig-node`):

- MUST connect to `peer` over `dig-nat` (verifying the mTLS identity against `peer.peer_id`),
  using `peer.addresses` as dial candidates; it MAY reuse a pooled connection.
- MUST perform the framed request/response exchange of §5.2 on one logical stream.
- MUST supply `from` (the caller's own contact) to the responder as the **authenticated** caller —
  on a real dig-nat connection the remote learns the identity from the mTLS certificate, not the
  wire body.
- MUST enforce the per-RPC timeout (`rpc_timeout`); the DHT core does not.
- MUST surface any failure (connect, stream, parse, timeout) as a `DhtError`; the lookup treats it
  as that one peer being unreachable and continues.

## 12. Configuration and defaults

| Parameter | Meaning | Default |
|---|---|---|
| `k` | Replication parameter: bucket size, lookup convergence set, announce fan-out | **20** |
| `alpha` | Lookup parallelism per round | **3** |
| `provider_ttl` | Provider-record validity window | **2 hours** |
| `republish_interval` | How often announced keys are re-PUT (MUST be `< provider_ttl`) | **1 hour** |
| `refresh_interval` | How often populated buckets are refreshed | **1 hour** |
| `rpc_timeout` | Per-RPC deadline (enforced by the transport, §11) | **5 seconds** |
| `provider_store_limits.max_providers_per_key` | Per-content-key provider-record cap, soonest-to-expire evicted on overflow (§6.3) | **20** |
| `provider_store_limits.max_total_records` | Global provider-record ceiling across all keys, new records rejected on overflow (§6.3) | **100 000** |

Defaults for `k` and `α` follow the canonical Kademlia paper (Maymounkov & Mazières, 2002).

## 13. Errors

`DhtError` variants and their meaning:

| Variant | Meaning | Lookup impact |
|---|---|---|
| `Transport(String)` | Connect/stream/timeout failure talking to one peer | That peer is unreachable; lookup continues |
| `MalformedResponse(String)` | A peer's response did not parse / match the request | As above |
| `InvalidHex(String)` | A hex identifier supplied to the API was not valid 64-hex | Operation rejected |
| `NoPeers` | Routing table + bootstrap set empty — no one to ask | Operation cannot run (see §9.2 for which ops return it) |
| `Timeout` | An RPC exceeded its deadline | That peer is unreachable; lookup continues |

Invariant: **no single peer failure is ever fatal to a lookup.**

## 14. Security properties

- **Identity.** All trust rests on the dig-nat mTLS identity: `peer_id = SHA-256(TLS SPKI DER)`.
  The DHT never derives trust from wire fields; the serving side learns callers only from the
  authenticated transport (§10.2). Node ids are therefore bound to key possession — a peer cannot
  claim an arbitrary id without holding the matching TLS key.
- **Allocation safety.** The framing bound (§5.2) caps any attacker-declared body at 256 KiB
  before allocation; truncated frames error deterministically.
- **Eviction resistance.** The LRS bucket policy (§7.2) keeps long-lived contacts unless proven
  dead, resisting table-flush attacks by newly minted ids.
- **Soft state.** Provider records self-expire (§6.2); a withdrawn or dead provider disappears
  within one `provider_ttl` without any delete protocol.
- **Bounded provider store.** `add_provider` is admission-controlled (§6.3): a per-key cap
  (soonest-to-expire eviction) and a global cap (rejection) bound the memory a single peer's
  `add_provider` traffic can consume, independent of any rate limiting the embedding node may add.
- **TTL clamp.** An inbound `expires_at` is never trusted as received: it is clamped to the
  responder's own TTL horizon (§6.2) before storage, so a malicious record can never outlive local
  GC indefinitely — combined with the bounded store above, this makes the worst case from a
  misbehaving peer bounded and self-healing, not permanent.
- **Address-list cap.** Every `addresses[]` admitted into local state (a stored `ProviderRecord`,
  a routing-table `Contact`, or a `find_providers` result handed back to a caller) is capped at
  `MAX_ADDRESSES_PER_RECORD` (§5.5) — a single record/contact can never carry an unbounded address
  list, which would otherwise inflate per-record memory and, once stored, be re-served (cloned) to
  every peer that later queries for it (bandwidth amplification).
- **Self-announce identity check.** When the caller identity is known, `add_provider` is rejected
  (error code `4`) unless `record.provider_peer_id == caller.peer_id` (§6.4) — an authenticated
  caller may announce only itself, never vouch for a third party.
- **Known limitations (as implemented).** Provider records are **not signed**: the self-announce
  check (§6.4) constrains WHO may be named as provider but does not cryptographically bind the
  record to that identity, and the check cannot run at all on the `handle_request` (no-caller)
  path. A finder gets content integrity from the content itself (per-chunk merkle verification in
  the download layer), not from the record. Responders also do not verify their own closeness to
  the key before accepting `add_provider`. Rate limiting per-caller (as opposed to the crate's own
  per-key/global capacity caps) is not implemented in this crate and, where needed, is the
  embedding node's responsibility.

## 15. Public API surface

Exported from the crate root (`#![forbid(unsafe_code)]`, MSRV **1.75.0**, license
**Apache-2.0 OR MIT**):

- `DhtService` — `new(local_id, local_addresses, config, transport)`, `local_id()`,
  `bootstrap(&[BootstrapPeer])`, `find_node(&PeerId)`, `find_providers(&ContentId)`,
  `announce_provider(&ContentId)`, `withdraw_provider(&ContentId)`, `republish()`,
  `refresh_buckets()`, `gc()`, `ping(&Contact)`, `handle_request(DhtRequest)`,
  `handle_request_from(Option<Contact>, DhtRequest)`, `known_closest(&Key)`, `routing_len()`,
  `ingest_verified_provider(ProviderRecord)`, `remove_provider_record(String, PeerId)`,
  `retract_own_provider(&ContentId)`, `holders_of(&ContentId)`.
- `DhtConfig` (§12), `ContentId` (§3–4), `Key` / `Distance` (§2), `ProviderRecord` /
  `CandidateAddr` / `AddressKind` / `MAX_ADDRESSES_PER_RECORD` (§5.5, §6), `Contact` /
  `RoutingTable` (§7), `BootstrapPeer` (§9.1), `DhtTransport` (§11), `DhtRequest` / `DhtResponse` +
  `MAX_FRAMED_BODY` (§5), `DhtError` (§13), and the re-exported `dig_nat::PeerId` (one
  peer-identity type across the transport and the DHT).
- `lookup::iterative_find` (§8) and `provider_store::ProviderStore` /
  `provider_store::ProviderStoreLimits` / `provider_store::PutOutcome` (§6.3) are public modules
  usable directly.

Dependency posture: the crate depends on `dig-nat` for identity/transport types only — not on the
gossip or Chia stacks — so the dependency tree stays minimal.

## 16. Quality gates

CI (push/PR to `main`) enforces: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --all`, a release build, `cargo doc --no-deps`, and **line coverage ≥ 80%**
(`cargo llvm-cov --fail-under-lines 80`). Releases are tag-driven (`vX.Y.Z`): the publish workflow
re-runs the gates, publishes to crates.io, and cuts a GitHub Release. The full stack — buckets,
lookup, provider store, wire framing, and service RPCs — is exercised end-to-end over an in-memory
multi-node swarm harness (no real network), including round-tripping every RPC through the §5.2
framing.

## 17. Conformance summary

| Contract | Fixed form | Interop requirement |
|---|---|---|
| Content-key derivation | `SHA-256(tag ‖ raw fields)`, tags `0x01` store / `0x02` root(capsule) / `0x03` resource (§4) | Byte-identical across implementations, or records are unfindable |
| Node key | `peer_id` verbatim (SHA-256 of TLS SPKI DER) (§2.1) | Nodes and content share one keyspace |
| Distance / bucketing | XOR, big-endian compare; bucket = `255 − leading_zeros` (§2.2) | Same closeness ordering everywhere |
| Framing | `u32`-BE length ‖ JSON, body ≤ 256 KiB, same as dig-nat control framing (§5.2) | One framing across the peer network |
| RPC methods | `find_node` / `find_providers` / `add_provider` / `ping` + `error` envelope, snake_case `type` tags (§5.3–5.4) | Any node's DHT speaks the same wire |
| `find_providers` response | ALWAYS carries `closer` (§5.3) | Iterative lookups converge |
| Address shape | `{host, port, kind}` with lowercase `kind` tokens, byte-compatible with L7 `dig.getPeers` (§5.5) | Results drop into dial targets |
| Address ordering | IPv6-first (family key from canonical `dig_ip::Family`), then by `kind` rank (§5.5) | Dialers try IPv6 before IPv4, per the ecosystem IPv6-first/IPv4-fallback rule (CLAUDE.md §5.2) |
| Address-list cap | `MAX_ADDRESSES_PER_RECORD` = 8, receive-side truncation post-sort, not a wire/decode limit (§5.5) | No record/contact can carry an unbounded address list; wire encoding is unaffected |
| Hex case | Lowercase 64-hex identifiers on the wire (§5.6) | Records remain findable |
| Provider TTL | Absolute `expires_at` Unix seconds; expired at `now >= expires_at`; republish < TTL (§6.2, §12) | Stale providers age out uniformly |
| Inbound TTL clamp | `add_provider`'s `expires_at` clamped to `min(received, now + local provider_ttl)` before storage (§6.2, §10.1) | A malicious/over-long expiry can never outlive local GC |
| Caller identity | mTLS-authenticated, never wire-asserted (§10.2) | Routing tables cannot be poisoned by claimed ids |
| Provider-store capacity | Per-key cap (soonest-to-expire eviction) + global cap (rejection), error code `3` on reject (§5.4, §6.3) | One peer's `add_provider` flood cannot exhaust responder memory |
| Self-announce identity | `add_provider` rejected (error code `4`) unless `provider_peer_id == caller.peer_id`, when caller is known (§5.4, §6.4) | A caller cannot announce a third party as a content provider |

Cross-repo: the wire and keyspace contracts above must match the DIG Protocol **Peer network** page
(docs.dig.net → Protocol → Peer network, §4c and its conformance table) exactly; `dig-nat` provides
the transport + `PeerId`, `dig-download` consumes `find_providers` results, and `dig-node` embeds
the service and wires both transport halves.
