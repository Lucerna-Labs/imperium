# Network causal world v5 diagnostic-4 — frozen before training

Frozen 2026-09-29T14:08:42Z. Networking packet, protocol, and flow mechanisms
only. This is a local, unsealed diagnostic subordinate to
`NETWORK-LIGHTCONE-V5-CONTRACT.md`; no runtime promotion or packet verdict.
The v4 parent pack SHA-256 is
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.

Diagnostic-2 artifacts remain byte-for-byte preserved. Its run is a failed
**and invalid-metric** record for negative-polarity claims: the old trainer
attracted `does_not_establish` edges as if they were positive edges, and its
validation top-5 was 1/6 against 2/6 for both controls. Diagnostic-3 inputs
are archived with exact hashes in `revision-3/REJECTED-PRETRAINING.md`; no
diagnostic-3 training or held-out evaluation ran. Its fresh validation,
sealed-test, and cross-composition groups may be carried forward here.

## Scope, source, and split freeze

The delta remains at most 24 new nodes and 48 new typed edges. `splits.json`
freezes whole mechanism groups. Exposed diagnostic-2 validation, sealed, and
cross groups are now train context only. Fresh groups are RFC 8085 UDP lifetime
validation, RFC 4443 ICMPv6 echo sealed-test diagnostic, and RFC 5722 + RFC
6946 overlap/atomic-fragment cross-composition. RFC 5961 reset challenge is
new train context. No paraphrase or variant of a held-out mechanism enters
train gradients. Source refs must resolve to a pinned primary document, an
existing exact section heading, and a manually reviewed group-specific
relevance note in `sections.json`; rights and bytes are pinned in
`sources.json`. RFC prose is citation-only and is not copied into training.
NIST PDF was cache-hash-verified but an independent fresh fetch returned 403;
that provenance gap is reported, never called a fresh retrieval proof.

The exact graph retains direction and polarity. In particular,
`authorized_flow -> host_flow_context -> observed_ip_tuple/service_rule_context`
are **prerequisite-direction** edges. `Policy::NETWORK` may traverse them
backward under `Both`; reachability of `authorized_flow` from a packet seed is
not packet-caused authorization. A future outer gate must verify oriented
edge conditions and all current host facts independently. The packet-seed
without-host-facts control must never release traffic.

## Frozen polarity-aware objective and controls

Retain seed **73129**, **48** full dimensions, **500** steps, learning rate
**0.03**, and margin **0.20**. Candidate A is text-derived initialization
without fitting; Candidate B trains on frozen train groups; the shuffled
control uses the same Candidate B update after one seed-73129 permutation of
**positive train** targets. Negative target sampling is from train-edge
endpoint nodes only. No vector clipping, held-out gradient, or post-fit
hyperparameter tuning.

- For each **positive** edge, with `p=x_source+r_relation`, fit hinge
  `max(0, 0.20 + ||p-x_target||² - ||p-x_sampled_negative||²)`. Active
  gradients are `2(x_sampled_negative-x_target)` for source/relation,
  `2(x_target-p)` for target, and `2(p-x_sampled_negative)` for sampled
  negative.
- For each **negative** `does_not_establish` edge, do **not** fit a
  relation-tail attractor. Fit repulsion hinge
  `max(0, 0.20 - ||x_source-x_target||²)`; active gradients are
  `-2(x_source-x_target)` for source and `2(x_source-x_target)` for target.
  Negative edges never enter positive top-k ranking. The shuffled control
  keeps real negative edges unchanged, isolating the positive target shuffle.

Report positive-edge top-1/top-5/MRR and full ranks **separately** from
negative-edge separation (fraction with squared distance at least 0.20)
for train, fresh validation, fresh sealed-test, and cross-composition.
Report both Candidate A/B/shuffled, all negative/unknown/adversarial controls,
source/input/trainer/output hashes, actual CPU and NumPy version, seed
recovery, neighborhood continuity, and unknown-node false proximity. Fit the
observer-only 4D `(x,y,z,w)` projection from train nodes only; Gram maximum
error must be ≤ **1e-8** and positive pairwise expansion ≤ **1e-8**.

The text initializer's use of held-out node titles/statements is a
**transductive** diagnostic, not blind mechanism generalization. A separate
**cold-node** control hides every held-out authored node's ID, title, and
statement from initialization and assigns an opaque deterministic vector
derived only from its position and seed. No held-out node participates in
gradients. Report complete metrics in both modes. Frozen local benefit gate:
Candidate B positive top-5 must strictly beat A and shuffled in validation
and sealed-test **in both transductive and cold-node modes**, while its
negative separation in those splits is no worse than both controls, with
finite full geometry and valid 4D invariants. Any tie, worse split, missing
negative metric, source-section failure, or omitted control rejects local
promotion. Cross-composition is reported separately; it cannot be hidden by
an average. Passing this local comparison still would not prove a live
packet/flow gate or seal.

Live blockers remain: the current observer does not represent ICMPv6 echo,
verified fragment reassembly and a current host service/zone/endpoint policy
source are absent, and synchronous two-direction three-node release testing
has not passed. A local geometry run cannot resolve these by itself.
