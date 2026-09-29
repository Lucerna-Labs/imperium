# Imperium Thesis

**Status:** Architectural constitution. Read this before reading the blueprint. Refer back to it when any design decision feels uncertain.

**Current implementation note:** The watchtower subsystem has been removed from
the active build. The deterministic bus, classifier/signature sensors,
operator-triggered extraction, and operator approval flow are the current
architecture.

---

## What Imperium is

Imperium is an adaptive VPN cluster defense system built as a subsystem of the Imperium runtime. It defends against state-level Deep Packet Inspection adversaries by composing dumb, single-purpose components on a shared message bus, with intelligence layered on top as additive sharpening rather than load-bearing substrate.

It is not "an AI VPN." It is a deterministic defense system that uses small classifier models as additive sensors and uses operator-supervised learning to extend its detection inventory over time. Pull the AI out and the system still works at its deterministic floor.

This document defines the architectural principles. Every implementation decision must be evaluable against them. If a proposed change violates a principle, the principle wins.

---

## The principles, in priority order

### 1. The substrate is sacred

Imperium runs as a subsystem inside Imperium. One process. One Tokio runtime. One in-process bus. Crates communicate via typed messages on the bus. There are no separate processes, no localhost ports, no IPC boundaries between Imperium subsystems.

The bus and the message schemas in `imperium-protocol` are the constitution. New message types are designed, not improvised. Subscription patterns follow the patterns already established in Imperium's other subsystems.

**Forbidden patterns:** spawning child processes for "the UI" or "the orchestrator." Opening localhost HTTP servers for inter-subsystem communication. Treating any Imperium subsystem as a client of another. Serde-JSON round-trips between "frontend" and "backend." There is no frontend and backend. There is one process with multiple crates.

If a task seems to require any of those, the task has been misunderstood. Stop and ask before writing code.

### 2. Dumb tools, composed

Every component does one thing. The thing it does is described in one sentence. Its behavior is deterministic given its inputs. It does not classify, does not make policy decisions, does not have internal intelligence.

Intelligence is provided by separate, named sensor components whose outputs are messages on the bus. The dumb components consume those messages alongside other inputs and act according to deterministic policy.

A new component that "would just be cleaner if it could handle multiple cases" is two components, not one. Composition of simple things beats complexity in a single thing.

### 3. Complementary, not substitutive

Every intelligent or adaptive component in the system sits alongside a deterministic baseline. The deterministic baseline is load-bearing. The intelligent component is additive sharpening.

- Reflex classifier micro-models complement the orchestrator's deterministic policy.
- The signature engine complements the classifier. Both feed `ThreatAssessment` events into the same pipeline.
- Operator-extracted signatures complement the bundled signature database. The bundled set always loads. Extracted signatures are additions to it, never replacements for it.
- The Imperium stack as a whole complements standard cryptography. Cryptographic security must hold even if every strainer and every classifier is bypassed.

The test for every new component: *pull this component out. Does the system still function at a known-good floor?* If yes, the component is correctly additive. If no, the component is load-bearing and the architecture has failed.

### 4. Strainers as the load-bearing primitive

A strainer is a path with shape-selective geometry. It lets through what fits, denies passage to what doesn't. The denial is deterministic — defined by the strainer's geometry — not by classification.

Strainers are dumb. A single strainer filters one shape. To filter more shapes, compose more strainers in sequence. Each strainer in a stack is replaceable without disturbing the others.

Strainer composition is declared per-protocol and per-context. The strainer crates themselves are protocol-agnostic. Composition is data, not code.

Strainers do not modify forwarded user traffic. Strainers shape responses to suspected adversaries, filter authentication exchanges before they reach cryptographic verifiers, and mediate inputs to interpreting components such as classifiers. They never decide what to do with bytes. Routing decisions are made upstream; strainers are on-path or off-path for a given flow.

### 5. Deterministic substrate, intelligent edges

Every probabilistic component has a deterministic component running alongside it whose outputs are auditable and whose failures are uncorrelated with the probabilistic component's failures.

- Classifiers (probabilistic) shadowed by signature engine (deterministic).
- LLM-driven deploy agent (probabilistic) shadowed by compose-file validator (deterministic).
- Signature extraction proposal (probabilistic if model-driven) shadowed by operator-approved promotion (deterministic).

The cryptographic verifier is the deepest deterministic substrate. Standard, vetted primitives, hybrid PQC. No custom cryptography anywhere. The strainer stack sits in front of the verifier but never inside it.

### 6. Active/standby with healing, emergency shutdown as tripwire

Imperium runs two protocols. One is active. One is warm standby. When active fails (crashes, fingerprinted, threshold-crossed), the orchestrator promotes standby to active, quarantines the failed protocol, and runs a deterministic healing loop on the quarantined one — generate new profile, apply, self-test, promote back to standby only if self-test passes.

If active fails before healing produces a new standby, the orchestrator does **not** rotate aggressively or try to keep going under unclear conditions. It triggers **emergency shutdown**: both protocols torn down, vault sealed, operator notified, manual recovery required. Operator can configure safe-mode-lock as an alternative for non-adversarial environments, but emergency-shutdown is the default.

The orchestrator does not make decisions under unclear conditions. Going dark is the correct response when the system's assumptions are invalid.

### 7. Closed-loop signature extraction, operator-approved

When the operator or sensor layer identifies events that warrant signature extraction, a deterministic extraction crate produces a candidate signature. The candidate lands in a staging area. The operator reviews and approves. Only approved signatures join the active database.

**No automated signature promotion.** The operator-in-the-loop is the defense against adversarial-input poisoning of the signature database.

The bundled signature database (shipped with Imperium releases) and the operator-extracted signatures (from this operator's cluster's experience) are kept in **separate files**, loaded by **separate code paths**, with **separate provenance metadata**. The merge happens at match time, not at store time. The bundled set's integrity is verifiable by hash.

### 8. Every defensive surface is rotatable

Strainer compositions, shape parameters, key material, profile mimicry choices, the order of stages in the auth exchange — all of it is operational state that rotates on the operator's cadence. The architecture's primitives are static; everything composed from them rotates.

The operator's cost to rotate is small (configuration change). The attacker's cost to keep up is large (accumulated reconnaissance invalidated). Defender's knowledge persists across rotations via the log; attacker's knowledge does not.

### 9. The operator is the final authority

Every decision the system can't defend deterministically falls to the operator. The operator approves cluster joins. The operator approves signature promotions. The operator triggers manual recovery from emergency shutdown. The operator's signing keys are the only authority the cluster recognizes.

The system makes the operator's work cheap and the attacker's work visible. It does not make decisions on the operator's behalf in ambiguous situations.

### 10. Local-first, supply-chain conservative

No external dependencies for runtime correctness. No phone-home, no telemetry, no auto-update of signatures or models from vendor infrastructure. Bundled releases are signed by Lucerna Labs and verifiable by the operator on install.

Optional capabilities (cloud LLM providers, signaling rendezvous services) are clearly optional and the system functions correctly without them.

---

## What this rules out

A non-exhaustive list of things this thesis specifically forbids, so they don't get reinvented:

- LLMs deciding actions. LLMs classify, the deterministic substrate decides.
- Models with weights that drift based on operational experience. Models are static, hashed, swappable. Learning happens in the retrieval surface (memory log + projection) and in the operator-approved signature database, not in weight space.
- Centralized signaling, configuration, or signature distribution infrastructure. Peer-to-peer with operator-signed grants. Optional rendezvous services may exist for convenience but are never required.
- Custom cryptographic primitives. Hybrid PQC using vetted libraries (`ml-kem`, `ml-dsa`, classical pairs via `x25519-dalek`, `ed25519-dalek`). Strainers complement cryptography, never replace it.
- Modification of forwarded user traffic. Strainers degrade responses to *suspected adversaries* and filter *authentication exchanges*. User traffic flows through configured protocols unchanged.
- Aggressive rotation under double-degraded conditions. Emergency shutdown is the default. Aggressive rotation is a footgun; rotation patterns themselves are fingerprints.
- AI as the marketing lede. The system's correctness floor is deterministic. The AI is a luxury upgrade. *"Imperium works without its AI. The AI just makes it work better."*

---

## What stays open

These are real design decisions that have not been made and need to be made deliberately:

- **The flagship naming.** "Imperium" stays as a working name throughout this build. Lucerna Labs may rename before any external release. Crate names should use a stable prefix (suggest `imperium-net-*` or similar within the Imperium workspace) that's distinct from `imperium-protocol` to avoid naming collision with the message-schema crate.
- **Cross-operator signature sharing.** Single-operator-only by default. Manual submission to Lucerna Labs as an opt-in channel for v1.5+. Peer-to-peer signature mesh is research-grade and not in scope for v1.

---

## How to use this document

When implementing any part of Imperium:

1. Read the relevant section of the blueprint.
2. If the blueprint is unclear, return to this thesis and apply the principles.
3. If a design decision is ambiguous, the principle with the lower number wins. (Substrate is sacred. Dumb tools, composed. Complementary, not substitutive. Then the rest.)
4. If the implementation appears to require something this thesis rules out, stop and ask. Do not pattern-complete against training data — pattern-complete against this thesis.

The blueprint describes *what to build*. This thesis describes *what makes it correct*. Both are required.
