# Diagnostic-4 blocked before training

The protocol draft was frozen at 2026-09-29T14:08:42Z, but its split and
curriculum files remain copies of diagnostic-3 and were **not** refrozen as a
valid diagnostic-4 comparison. No diagnostic-4 training, held-out evaluation,
runtime promotion, or seal occurred. Its fresh held-out mechanism groups have
not been consumed.

The proposed polarity-aware objective would correct diagnostic-2's negative
edge attraction. It would still fit only `(source node, relation, target node)`
triples and discard edge conditions, exceptions, and required host facts.
For example, `v5e003` and `v5e004` share the source
`v5_observed_ip_tuple` and relation `requires`, but TCP and UDP selection are
mutually conditioned by the packet's next-protocol value. Sampling one as the
other's negative would measure unconditioned graph topology, not conditional
packet/flow causality. The current curriculum has only prose conditions: no
typed condition variables, truth assignments, matched packet/flow feature
vectors, or current versioned host service-policy source. Claiming a causal
release benefit from another top-5 run would be unsupported.

Additional source gates remain open: the diagnostic-3 validator checked only
`source#section` syntax, not exact section existence and relevance. RFC 9293
section 3.5 is the connection-establishment source, whereas diagnostic-2
recorded section 3.4 for TCP opening. NIST SP 800-41 was hash-verified from
the earlier local official fetch, but an independent later PDF retrieval
returned HTTP 403; do not call it freshly reverified.

Exact diagnostic-4 draft hashes before the stop:

| File | SHA-256 |
|---|---|
| `PROTOCOL.md` | `c81f81e7b165633e99d17917e3f2238346b9a4610bf4b479b9cb40308ccb7081` |
| `sources.json` | `cea1c139bc75a3875135612754931dfa36cb183a5717c167145e0a75f66a5081` |
| `registry.json` | `5f58327899a41b5caed45151a3a528f5cbcc4239119c560a5203434346c99cb0` |
| `splits.json` | `d79c9dcc55210230a6661480db3c0d2a1800148dd49003286d5629047b7f7c26` |
| `curriculum.json` | `ea05008804f819e7410ef8578348f9aa1f667d59044cdc8c9eef6db65927ce26` |

A later experiment requires a new immutable revision with a typed condition
schema, source-section entailment registry, host-supplied factual context,
matched positive/negative packet-flow corpus, a condition-aware fitting and
evaluation contract, and fresh split freeze before execution. Do not relabel
this draft or reuse diagnostic-2's exposed holdouts as new evidence.
