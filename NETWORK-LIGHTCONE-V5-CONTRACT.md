# Network Lightcone v5 experiment contract — 2026-09-29

## Scope and status

The user authorized expanding and retraining the **networking** Lightcone,
including packet and flow behavior. The world stays passive and unsealed.
"Everything imaginable" is an open-world coverage goal, not a claim any
finite pack can meet. A versioned registry must expose every known gap;
unknown, unrepresented, or unsupported traffic cannot be represented as
approved simply because a nearby graph node exists.

The user subsequently specified **all traffic**. Pending clarification of
loopback and namespace scope, treat that as a host-wide target covering direct
application sockets, inbound packets, forwarding, the Imperium underlay and
tunnel, IPv4/IPv6, and non-IP link traffic. The first slice below is only a
development gate and cannot satisfy this expanded deployment claim. The
separate `ALL-TRAFFIC-LIGHTCONE-BOUNDARY.md` records host hook coverage and
what remains unproven.

The v4 binary and its evidence remain an immutable baseline. It currently
has no positive graph path from observed packet structure to
`authorized_flow`, and same-shape UDP destinations and TCP sequence changes
produce the same graph neighborhood. The live three-node namespace probe
delivered an undeclared UDP service. These failed controls remain in
`LIGHTCONE-FILTER-PRECOMMIT.md` and must continue to fail a release gate
until an actually trained and tested replacement can distinguish them.

## Ownership and invariant

1. Sourced network evidence and typed curriculum define exact graph facts,
   conditions, exceptions, provenance, polarity, epistemic class, and frozen
   mechanism splits. Unsupported mechanisms are recorded as gaps.
2. Training learns full 48D coordinates from the frozen train split without
   adding or changing graph truth. A 4D `(x,y,z,w)` spatial projection is
   observer-only and cannot admit or release traffic.
3. The Lightcone admits represented facts into the exact typed graph and
   returns a reproducible receipt. It makes no packet decision.
4. The host extracts payload-blind packet/flow facts, validates authenticated
   peer, current versioned service/zone/endpoint policy, and bounded session
   progression. The outer forwarding boundary consumes the passive receipt
   and host facts synchronously before send or TUN write. Missing context,
   unsupported form, bad pack, exclusion of a required seed or causal edge,
   or overload denies passage. A hop frontier outside the declared bounded
   neighborhood is reported as a limit; it is not by itself a verdict about
   an otherwise complete required relation. Only the outer boundary reports
   delivery or rejection.

The world must not treat a packet header, query hash, embedding proximity, or
one host policy seed as proof of identity or authorization. Concrete service
rules must be supplied by the host because the scratch build has none.

## Frozen first acceptance slice

The first operational slice covers validated raw IPv4 and IPv6 packet forms
that the observer currently represents, with IPv4 ICMP echo request/reply,
UDP datagram/reply context, and TCP opening and bounded sequence/ACK
progression. Fragmented packets need verified reassembly before flow
attribution; otherwise they are unsupported. IPv6 echo is currently
unrepresented. Mesh datagrams need authenticated peer/session and replay
context before a payload reaches the TUN. Every other protocol and application
activity remains explicitly unknown until represented, sourced, trained,
and tested in a later registry revision.

## Precommitted evidence and metrics

- Record exact source version/URI/retrieval date/hash/rights, current source
  digest, frozen split manifest by mechanism group, training seed/config,
  actual device, full output hashes, and all failed as well as passing runs.
- Measure train, validation, held-out mechanism, cross-composition, negative,
  unknown, and adversarial performance separately. Report seed recovery,
  typed directed edge ranking, neighborhood continuity, and false proximity;
  no aggregate score substitutes for a failed category.
- Matched positive/negative traffic must differ at the **supported factual
  flow context** while keeping packet shape and route held constant: approved
  service versus undeclared service; matching versus orphan ICMP reply;
  valid TCP progression versus orphan or out-of-window ACK; authenticated
  current-session mesh payload versus invalid handshake/replay. Ordinary and
  hostile payload text with identical supported headers must not change the
  graph observation merely because content differs.
- The live three-node namespace gate must show declared ICMP/UDP/TCP traffic
  crossing both directions and matched undeclared/invalid traffic stopped
  **before** each send/TUN write. Failures of the Lightcone service, policy
  source, queue/receipt capacity, or pack integrity must block traffic and
  report rejection, never a delivered packet.
- Match the v4 control and any v5 policy-free versus policy-assisted host
  composition on the same traffic corpus. Preserve false passes, false
  rejects, delivery counts, and overload results. Do not move acceptance
  criteria after seeing held-out failures.

This slice can establish only its measured coverage. It cannot establish
universal network protection, exhaustive future protocol coverage, physical
security, or a seal. The current pack must not be promoted while any of the
above mandatory gates is unrun or failed.

## First local diagnostic outcome

`network-v5-diagnostic-2` authored 13 nodes, 31 typed edges, and seven
negative/unknown/adversarial controls from eight hash-verified primary-source
files. The compiled draft has 221 nodes and 219 edges. Its one precommitted
48D CPU training run executed text-only, typed-relation, and shuffled-target
controls on frozen mechanism splits. The typed candidate reached train
top-5 19/19, but validation top-5 was **1/6**, below both controls at **2/6**.
Sealed-test top-5 improved to 2/4, while cross-composition was 0/2. The
frozen requirement of strictly beating both controls on validation and
sealed-test therefore **failed**. `training-local.json` is
`rejected_local_diagnostic`, `release_ready=false`; its complete ranks and
input/output hashes are retained under `crates/imperium-net-world/v5/`.
An independent source audit subsequently found that diagnostic-2's trainer
also fed negative-polarity `does_not_establish` edges into its **positive**
hinge/ranking objective. That violates the intended causal/negative
separation and makes its rank scores unsuitable as security evidence, apart
from the already failed frozen gate. The failed report is preserved; a new
revision must separate positive fitting from negative repulsion and controls
before another run.
The v4 runtime pack remains active, and the forwarding filter remains
unenforced. A subsequent experiment needs fresh sourced mechanisms and
held-out groups because diagnostic-2's sealed-test outcomes are now exposed.
