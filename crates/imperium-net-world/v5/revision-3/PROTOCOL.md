# Network causal world v5 diagnostic-3 — frozen before training

Frozen 2026-09-29T13:57:16Z. Networking packet, protocol, and flow mechanisms
only. Subordinate to `NETWORK-LIGHTCONE-V5-CONTRACT.md`. The v4 pack SHA-256
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`
and all diagnostic-2 source, split, compiled, geometry, and failed-training
artifacts remain byte-for-byte unchanged. No runtime promotion or seal.

## Why a new revision is warranted

Diagnostic-2 passed structural/source checks but failed its frozen benefit
comparison: typed training top-5 was 19/19, validation 1/6 versus text-only
2/6 and shuffled-target 2/6, and sealed-test 2/4 versus 0/4 and 1/4. Its
validation, sealed, and cross-composition mechanisms are now exposed. They may
serve as train/regression evidence here; they are never counted as fresh
held-out evidence. No learning rate, margin, step count, seed, metric, or
decision threshold is changed in response to that result.

## New source-grounded mechanisms and frozen split order

The v5 authored delta remains at most 24 nodes and 48 edges, within the
current 256-node/512-edge runtime first-slice capacity. This is not a network
coverage ceiling. `splits.json` freezes complete mechanism groups before code
or fitting:

1. **Train:** RFC 5961 TCP RST challenge/sequence validation joins the
   already trained packet-plus-host-context relation. The packet-alone
   negative relation remains in train.
2. **Validation:** RFC 8085 UDP flow lifetime and delayed response ambiguity.
   UDP reverse tuple from diagnostic-2 is exposed train context; the new
   lifetime mechanism is held out.
3. **Sealed-test diagnostic:** RFC 4443 ICMPv6 echo request/reply identifier
   and sequence correspondence. This is distinct from diagnostic-2's IPv4
   echo group and remains unrepresented in the current live observer.
4. **Cross-composition:** RFC 5722 overlapping IPv6 fragments and RFC 6946's
   atomic-fragment exception composed with host flow attribution. An atomic
   fragment (offset 0, M=0) is handled independently, never folded into an
   overlap/reassembly set. Current live reassembly is absent.

All authored statements are original factual paraphrases with exact primary
source references. RFC source text is citation-only evidence under IETF Trust
terms and is not copied into training. Full official source bytes are hashed
at retrieval; the repository stores locator, version, rights, hash, and
attribution rather than redistributing source texts. Original v4 authoring,
rights, split, and trainer inputs remain an unresolved parent gap.

## Frozen diagnostic comparison and falsifier

Retain seed **73129**, text-derived 48D Candidate A, typed-relation Candidate
B, and the identical shuffled-train-target control. Candidate B and shuffled
control each use **500** steps, learning rate **0.03**, hinge margin **0.20**,
one seeded negative target sampled only from train-edge endpoint nodes per
positive train edge per step. With `p = x_source + r_relation`, the hinge is
`max(0, 0.20 + ||p-x_target||² - ||p-x_negative||²)`. Active gradients are
`2(x_negative-x_target)` for source and relation, `2(x_target-p)` for target,
and `2(p-x_negative)` for negative. No vector clipping, held-out gradient, or
post-fit tuning. The shuffled control permutes train targets once with the
same seed. Candidate A fits no relation offsets.

Report full rank lists, relation-tail top-1/top-5/MRR, title-only seed
recovery, source-only neighborhood top-5, unknown-node false proximity,
negative/unknown/adversarial controls, all four splits, actual CPU/device and
NumPy version, source/input/trainer/output hashes, and elapsed time. Fit the
observer-only `(x,y,z,w)` projection from train nodes only: maximum 4D Gram
error ≤ **1e-8** and positive pairwise expansion ≤ **1e-8**. The frozen
benefit falsifier remains: B's top-5 must strictly beat **both** A and shuffled
on fresh validation **and** fresh sealed-test with finite geometry and no
graph invariant failure. A tie or worse result rejects local diagnostic
promotion. Cross-composition is reported separately and cannot be hidden by
an aggregate score. Even a passing local comparison does not establish the
live release gate or seal.

Matched negatives must hold packet shape/route constant: validated versus
unvalidated TCP RST sequence context; UDP reply before versus after current
host flow lifetime; matching versus mismatched ICMPv6 echo identifier and
sequence; nonoverlapping fragments versus overlap, with a distinct atomic
fragment control. No application payload text can create a mechanism or
permission. The live ICMPv6 parser, fragment reassembly, current service
policy source, and synchronous host release check remain separately owned
blockers until verified at the three-node traffic boundary.
