# Network causal world v5 — frozen local diagnostic protocol

Date: 2026-09-29. Scope: **network packet, protocol, and flow mechanisms
only**. This protocol is subordinate to the repository's
`NETWORK-LIGHTCONE-V5-CONTRACT.md` and its live acceptance matrix.

## Immutable parent and claim boundary

- Parent v4 pack SHA-256:
  `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
  The parent pack and evidence are never overwritten by this experiment.
- This directory is an authored **delta** and a local diagnostic. It does not
  authorize packet release, change the runtime's active pack, or seal a world.
- The current runtime has 256 node and 512 edge slots. V4 uses 208 and 188.
  Remaining capacity is a first-slice limit; it is not a network coverage
  ceiling. A later wider world needs a versioned runtime and pack migration.
- The v4 `world.json`, geometry, split manifest, source registry, and trainer
  are absent in this checkout. Decoding parent metadata does not recreate
  original source rights or training provenance.

## Frozen authoring and split rules

The first delta may add **at most 24** typed nodes and **at most 48** typed
edges. A node or edge must have a stable ID, original factual paraphrase,
epistemic class, scope and limitation, source IDs, and a declared network
mechanism group. Edges additionally require relation, direction, polarity,
conditions, and exceptions. A causal edge is never a permission rule.

`splits.json` freezes entire mechanism groups to `train`, `validation`,
`sealed_test`, or `cross_composition` before training. No group, paraphrase, or
augmented variant may cross a split. The validator rejects dangling endpoints,
unknown source IDs or rights, duplicate IDs, undeclared types, split leakage,
and missing negative/unknown controls for the first slice. Registry gaps remain
visible and block a release claim even when the authored delta validates.

The first pretraining split design put the only positive packet-to-host-context
bridge in `cross_composition`. That could not train the relation the user
requested. Its exact bytes are preserved as `splits-v1-rejected.json` (SHA-256
`1246a3fce7fafc0a00f4b6099075b0132225dac93c8335169164d1916f4e59ce`).
Revision `network-v5-diagnostic-2` was frozen before any trainer run: the
sourced positive bridge and packet-alone negative are train groups; a distinct
fragment-plus-policy composition remains held out. The bridge lists required
host facts explicitly; graph reachability never substitutes for their current
validation or the host's own decision.

## Precommitted diagnostic comparison

- Seed: **73129**. Full geometry: **48 dimensions**. The 4D `(x,y,z,w)`
  projection is observer-only and is never read by graph admission or release.
- Candidate A: deterministic text-derived 48D node initialization without
  relation fitting. Candidate B: the same initialization plus train-split
  typed-relation fitting. A control shuffles **train** targets by seed 73129;
  held-out targets are never used for fitting or selecting parameters.
- Fixed fitting budget: **500** steps, learning rate **0.03**, hinge margin
  **0.20**, one seeded negative target per positive train edge per step.
  No follow-up tuning against validation or sealed-test metrics is permitted
  in this revision.
- Frozen Candidate B update: with `p = x_source + r_relation`, use hinge
  `max(0, 0.20 + ||p - x_target||² - ||p - x_negative||²)`. When active,
  subtract `0.03` times gradients `2(x_negative-x_target)` from source and
  relation, `2(x_target-p)` from target, and `2(p-x_negative)` from negative.
  The shuffled control uses this identical update after one seed-73129
  permutation of **train** targets. Negatives are sampled only from train-edge
  endpoint nodes. No vector clipping, held-out gradient, or post-fit tuning.
- Record relation-tail rank, top-1, top-5, mean reciprocal rank, and full
  rank list separately for train, validation, sealed-test, and
  cross-composition. Record graph-exact negative/unknown control counts,
  title-only seed recovery, neighborhood top-5 continuity, and unknown-node
  distance to the authorizing-context nodes relative to the train-edge median.
  This distance is diagnostic, never an admission threshold. Record 4D basis
  orthonormality (maximum Gram error at most **1e-8**) and pairwise
  non-expansion (maximum positive distance expansion at most **1e-8**), source
  and artifact hashes, actual platform/device, elapsed time, and every failure.
- Benefit falsifier: Candidate B must **strictly improve top-5 over both A and
  the shuffled-target control in validation and sealed-test**, with no graph
  invariant failure. A tie, lower score, omitted split, or missing control
  rejects diagnostic promotion. Passing this comparison still does not satisfy
  the live packet/flow release matrix or create a seal.

## Required matched network controls

Preserve the v4 failures and compare on held-constant packet shape/route:
approved versus undeclared service; matching versus orphan ICMP echo reply;
valid versus orphan/out-of-window TCP ACK; valid versus invalid mesh session
and replay; reassembled versus lone fragment; represented versus unrepresented
protocol. Identical supported headers with different payload text remain the
same structural mechanism. The observer now reports TCP header and transport
payload length (focused parser tests passed), but a live bounded sequence
tracker has not yet consumed them. The node also lacks a versioned
service/zone/endpoint policy source and verified fragment reassembly. Those
remain explicit registry blockers, not values to guess.
