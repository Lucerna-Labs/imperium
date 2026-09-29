# Diagnostic-3 design rejected before training

No diagnostic-3 trainer run, held-out evaluation, runtime pack, or seal was
produced. The fresh validation, sealed-test, and cross-composition groups in
this directory were **not** used for gradients or metric selection and may be
carried into a new, separately frozen revision.

Independent review found four load-bearing problems before execution:

1. The then-current trainer optimized `polarity = -1` `does_not_establish`
   edges as positive translation targets. A packet-alone negative could be
   rewarded as if it were a positive authorized-flow relation.
2. The text initializer included held-out authored node identifiers, titles,
   and statements. Gradient splits were clean, but the evaluation was
   transductive and could not claim blind held-out mechanism generalization.
3. The validator checked only `source#section` syntax, not the existence or
   relevance of the cited source section. A diagnostic-2 RFC 9293 TCP-opening
   citation to section 3.4 (sequence numbers) should have named section 3.5
   (connection establishment). Diagnostic-3 corrected that citation, but its
   validator still lacked a section gate.
4. The validator hardcoded a diagnostic-1 superseded split and could not
   validate this directory's correctly archived diagnostic-2 split.

The exact pretraining design inputs are retained at these SHA-256 hashes:

| File | SHA-256 |
|---|---|
| `PROTOCOL.md` | `3f0e819d84c0c51021724769b76acb0967cd152f2e4ba489c8aac6c7c9477781` |
| `sources.json` | `cea1c139bc75a3875135612754931dfa36cb183a5717c167145e0a75f66a5081` |
| `registry.json` | `5f58327899a41b5caed45151a3a528f5cbcc4239119c560a5203434346c99cb0` |
| `splits.json` | `d79c9dcc55210230a6661480db3c0d2a1800148dd49003286d5629047b7f7c26` |
| `curriculum.json` | `ea05008804f819e7410ef8578348f9aa1f667d59044cdc8c9eef6db65927ce26` |
| `splits-v2-exposed.json` | `b93378371342c6f2d4ee28ff884e3f3b09371e4e71343facde797d1d5543d7ef` |

Diagnostic-2's failed A/B/shuffled metrics remain in the parent v5 directory
as an **invalid-metric** record for negative-polarity benefit claims. Neither
revision is promoted. A new diagnostic-4 protocol must separate positive
attraction and negative separation, add source-section entailment checks, and
label transductive versus cold-node evidence before any execution.
