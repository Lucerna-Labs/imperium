# Network Lightcone v5 condition evidence — precommit

Frozen at 2026-09-29T14:22:23Z, before the files and validator below were
implemented. This is a new **untrained, unsealed evidence revision**. It does
not change the v4 runtime, earlier v5 diagnostics, forwarding, or the host
firewall. Its parent is the unchanged v4 pack with SHA-256
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
Revision 4 remains blocked. This revision does not adopt its draft training
objective or relabel its split copies as fresh held-out evidence.

## Question and boundary

Can a typed, source-bound condition record and a packet/flow fact bundle tell
whether a particular **existing** positive or negative graph relation is
applicable, inapplicable, or unresolved for matched packets? The passive
Lightcone still returns graph neighborhoods and receipts; the condition
validator is an offline evidence check. It emits no authorization or packet
verdict. The host must own any later synchronous release gate.

All host traffic is the requested eventual scope. This slice intentionally
tests only forms represented by the current `imperium-net-observer` parser and
`imperium-net-mesh` flow tracker. Direct host sockets, kernel-originated
traffic, transit traffic, link-layer frames, authenticated-session evidence,
policy revision, and service permission have no packet-bound producer in this
revision and must remain `unknown`. Unknown must never be recast as `false`
or as an applicable positive authorization relation.

## Fixed files and ownership

- `predicates.json`: closed typed predicate catalog, producer, scope, and
  current producer availability.
- `sections.json`: source-section anchors in pinned primary documents with
  per-claim human relevance explanations. The gate verifies the pinned source
  hash, exact heading, anchor location, and declared claim linkage. It cannot
  prove semantic entailment by string matching alone.
- `conditions.json`: condition bindings to named existing revision-4 edge
  IDs. Exact directed graph edges, polarity, and provenance are inherited,
  never created by this file. An edge with unsupported host prerequisites is
  marked blocked and cannot become applicable.
- `corpus.json`: deterministic raw-packet fixtures, ordered flow histories,
  expected parser/flow facts, and condition results. A Rust replay test must
  compare every represented packet to the actual parser and flow tracker.

Every fact has a typed value plus a producer reference. The only presently
verifiable producers are `parse_raw_ip_flow`, `decode_raw_ip`, and
`FlowBehaviorTracker::observe_at`. The offline corpus supplies no live peer,
session authentication, current service policy, UID/cgroup, or delivery fact.
Those absent facts are missing, not falsified.

## Three-valued condition mechanics

Atomic equality is `true` when a fact with the required type and exact value
exists, `false` when a same-scope typed fact exists with a different value,
and `unknown` when the fact is missing, unavailable, stale, or unsupported.
Conjunction is false if any term is false, true if all are true, otherwise
unknown. A `none` exception is false if any exception is true, true if all
are false, otherwise unknown. `when.all` and `unless.any` combine with this
three-valued logic. No default true is allowed. Negative-polarity edges are
reported separately; a negative edge is never fitted as a positive relation.
Graph traversal in both directions does not reverse an edge's causal claim.

The first active bindings distinguish TCP from UDP header facts
(`v5e003`, `v5e004`), an unreassembled fragment (`v5e006`), and TCP
opening/ACK correlation (`v5e008`, `v5e009`). The frozen corpus exercises
IPv4 only. The positive host-context
bridge (`v5e027`) stays blocked because its current policy, zones, endpoints,
service, direction, identity, and validated flow-state facts are unavailable.
It is a prerequisite-direction relation and never a packet grant.

## Frozen matched corpus and acceptance

Cases, in order: `udp_service_a`, `udp_service_b_same_shape`,
`udp_reverse_correlated`, `udp_reverse_after_expiry`, `tcp_syn`,
`tcp_synack_correlated`, `tcp_ack_correlated`, `tcp_ack_ahead`,
`tcp_orphan_ack`, `icmp_echo_request`, `icmp_echo_reply_correlated`,
`icmp_echo_wrong_identifier`, `ipv4_udp_fragment`,
`unsupported_upper_protocol`, and `malformed_ipv4_checksum`.
UDP destination service changes must not change the structural TCP/UDP
condition result; it remains unknown whether either service is permitted.
TCP SYN and same-shape orphan/invalid progression must differ in tracked
history. Valid/expired UDP reverse tuples must differ in recorded state but
neither alone establishes a permitted service. Echo correspondence is a
flow fact, not a service grant. A fragment cannot supply a complete transport
header. Unsupported/malformed forms supply no positive packet relation.

Hard invariants:

1. The parent pack and all diagnostic-2/3/4 files retain their hashes.
2. All represented parser/flow expectations match actual Rust producers;
   no expected fact is accepted from a claimed unavailable producer.
3. Active condition records type-check, preserve exact edge ID/polarity,
   bind pinned source sections, and return the frozen true/false/unknown
   results for every corpus row. Swapping TCP/UDP next-protocol facts changes
   only the corresponding conditional edge. Removing a fact yields unknown.
4. Every case keeps the host authorization bridge unresolved; no condition
   result is called an allow/deny or delivery observation.
5. Source cache absence, hash mismatch, nonexistent section or misplaced
   anchor, wrong fact type, unknown predicate, duplicate ID, missing fact
   producer, and any unexplained corpus case fail the validator.

Execute one deterministic validation and one focused adversarial test suite.
No geometry training, pack compilation/promotion, production forwarding,
or all-traffic claim belongs to this experiment. Prior diagnostic-2 held-out
results are exposed. A future train run needs a separately frozen, fresh
mechanism split and an independently accepted training artifact. Current
source-section review is one agent's review, not independent proof.
