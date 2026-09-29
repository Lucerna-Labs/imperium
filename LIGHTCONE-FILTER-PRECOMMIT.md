# Network Lightcone filter experiment — precommit, 2026-09-29

## User contract

The network Lightcone itself remains passive. Traffic may cross the outer
network boundary only when its packet structure **and supported flow behavior**
are causally related to training in the current v4 world. Unrelated, unknown,
malformed, or unsupported traffic does not pass. No seal is requested.

## Frozen evidence and boundary

- Active `world.bin` SHA-256:
  `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
- `World::admit` takes a seed bitmap, query hash, and policy and returns a
  graph receipt. It also returns a valid **empty** receipt for zero seeds; a
  receipt alone is not a pass condition.
- The packet observer currently emits protocol/header structure, not a
  five-tuple or temporal flow history. The existing payload-blind regression
  requires ordinary and hostile text with the same headers to have identical
  graph seeds/nodes/edges.
- v4 edge 162 (`authorized_flow → approved_service`) and edges 163–166 are
  training-split, positive causal relations. Their embedded conditions require
  the host to supply current policy version, zones, endpoints, service, and
  state context. Those inputs are not currently configured in the live node.
- The pack contains 208 world concepts, but only 119 IDs in
  `training_node_ids`. Several normal packet fields observed at runtime, such
  as IPv4 TTL, are represented in v4 through regression relations while absent
  from that training-ID list. Treating the list as a direct allowlist would
  reject ordinary IPv4 traffic.

## Candidate comparisons, before an implementation choice

1. **Structural causal relationship only.** Decode the exact packet and
   require supported observation kind, nonempty seeds, and an admitted positive
   causal connection to the v4 training graph. Prediction: this can reject
   malformed/unknown structures, but cannot distinguish approved versus
   unapproved endpoint/service flows with the same protocol shape, or a
   valid progression from an orphan/out-of-window packet. Falsifier: matched
   forbidden flows yield a different world-grounded relationship without host
   flow/policy input. This candidate is a control, not sufficient for the
   user's complete packet-plus-flow filter contract.
2. **Causal relationship plus validated host flow context.** A separate
   host-owned parser/state tracker supplies the actual policy version,
   approved service/direction/endpoints/zones, peer/session identity and
   bounded flow progression required by v4's training edges. The passive
   Lightcone admits that typed structure; the outer network boundary permits
   only the complete causal relationship and drops every other input.
   Prediction: declared flows pass; same-shape forbidden endpoints and
   invalid progression fail; a missing/stale policy or observer capacity
   failure denies passage. This candidate requires an explicit real policy
   source and matched namespace tests before it can be promoted.

## Frozen acceptance matrix

- Positive: permitted ICMP/UDP/TCP traffic between declared zones/endpoints,
  including valid session/flow progression, crosses both directions of the
  three-node namespace tunnel and produces exact pack/format/flow receipts.
- Negative: unapproved destination with identical packet shape, orphan TCP
  ACK/out-of-window sequence, unknown protocol, malformed checksum/length,
  unsupported fragment, invalid mesh handshake, and unauthorized peer do not
  cross. A hostile payload with unchanged supported headers must not be called
  a novel network mechanism merely because its bytes differ.
- Failure: missing/mismatched pack, missing/stale policy, dropped observer
  event, stalled/quarantined strand, and admission error all deny at the
  forwarding boundary. A send attempt is not reported as a delivered packet.
- Controls: current receipt-only path and structural-only candidate run on the
  same packet corpus, with packet/flow identity, timing, and route state held
  matched. Record permitted deliveries, false rejects, false passes, and
  overload behavior separately. No threshold is changed after results.

## Current status

The receipt-only three-node run in `LIGHTCONE-CLUSTER-ACCEPTANCE.md` is a
diagnostic baseline. It did **not** test this filter. Candidate 1 has a
source-level flow input gap; candidate 2 is **UNRUN** until the host policy
source and concrete supported flow observations are fixed. Do not claim a
working filter or seal from the earlier receipt counts.

## Bounded follow-up precommit after the first live and matched probes

The first live baseline delivered an undeclared UDP service through the
three-node tunnel, and the first two matched tests showed identical graph
neighborhoods for different UDP endpoints and TCP sequence values. A read-only
probe of `Policy::NETWORK` also found 32-node saturation and exclusions for
representative ICMP, UDP, TCP, and mesh datagrams. These are recorded failures
of candidate 1, not a reason to loosen the acceptance matrix.

One diagnostic variant remains useful before concluding that the graph itself
cannot express the needed relationship: keep the same v4 pack, seeds, edge
eligibility, direction and three-hop limit, but raise only `max_nodes` from 32
to the world's existing 256-node capacity. Intrinsic rationale: the current
32-node breadth cap can hide reachable training edges; this variant isolates
capacity truncation from missing flow context. Frozen benefit metric: count
seed-to-positive-training-edge paths and excluded nodes for the same four
packets. Hard invariants: no changed seed extraction, no use of held-out edge
splits as positive training, no release of unrelated flows, no seal. Prediction:
exclusions may fall, but UDP endpoint and TCP sequence matched pairs remain
graph-indistinguishable because those values are not graph inputs. Falsifier:
the wider receipt contains a grounded distinction between each pair. This is
one additional read-only diagnostic, not a new production policy.

## Measured results, 2026-09-29

- `cargo test --offline -p imperium-net-lightcone --test filter_feasibility`
  passed 3/3. Matched valid IPv4 UDP packets to different destination
  addresses and ports yielded identical v4 seeds, nodes, edges, exclusions,
  and hop frontiers. Matched valid TCP ACKs with different sequence and
  acknowledgement numbers did too. The exact-byte query hashes differed;
  those hashes bind receipts but do not select graph paths. The test also
  traversed every positive edge in the complete embedded v4 graph and found
  no path from the packet concepts `ipv4`, `udp`, `tcp`, or
  `endpoint_addresses` to `authorized_flow` or `approved_service`.
- `IMPERIUM_FILTER_PROBE=1 scripts/mesh-multipeer-test.sh` exited 0 for its
  routing and passive-receipt checks, but its filter diagnostic printed
  `FILTER NOT WORKING: undeclared UDP service crossed the tunnel`. The hub
  delivered a UDP datagram to leaf B's port 45999 without any declared
  service policy. At the same time all three nodes reported v4 diagnostic
  Lightcone strand activity and zero observer drops. This is a live failure
  of receipt-only filtering, not a failure of tunnel connectivity. The
  diagnostic script was then changed to exit **1** when this negative control
  crosses; a repeat live run returned exit 1 with `Lightcone filter: FAILED`
  while its routing, receipt, and teardown subchecks passed.
- A read-only `Policy::NETWORK` probe on valid ICMP, UDP, TCP, and mesh
  datagrams found the 32-node cap reached with 14, 12, 17, and 12 excluded
  nodes respectively. Positive train-edge reachability from every observed
  seed failed for each sample. The precommitted 256-node capacity variant
  reduced excluded nodes to zero but left hop-frontier counts 7, 6, 7, and
  15. Forward positive train-edge reachability stayed 3/9, 4/11, 5/11,
  and 2/3 seeds. The valid UDP endpoint/port and TCP sequence pairs remained
  graph-identical. `authorized_flow` and `policy_decision` were absent from
  every sample. Increasing capacity therefore removed one truncation source
  without creating the missing flow relationship.

The explicit host policy version, approved zones/endpoints/services, and
flow-state source required by v4 edges 162-166 are not present in the current
node configuration; the user confirmed this is a scratch build with no such
policy source. More fundamentally, the embedded positive graph has no
path from packet structure to `authorized_flow`; supplying policy context as
an additional seed would put two disconnected observations into one receipt.
That would not establish the packet-to-approved-flow causal relationship
required by the user. Candidate 2 therefore cannot be promoted as a
Lightcone-backed release gate using this immutable v4 pack. The outer
forwarder remains receipt-only, `filter_enforced=false`, and no seal claim is
made.
