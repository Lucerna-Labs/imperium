# Imperium Blueprint

**Read THESIS.md first.** This document describes *what to build*. The thesis describes *what makes it correct*. Implementation decisions defer to the thesis when the blueprint is silent or ambiguous.

**Current implementation note:** The watchtower phase and
`imperium-net-watchtower` crate have been removed. Closed-loop extraction is now
driven by operator or sensor-selected events, then gated by operator approval.

---

## Scope of this build

Build Imperium as a subsystem inside the Imperium workspace. Reuse Imperium's existing crate primitives (`imperium-bus`, `imperium-protocol`, `imperium-store`, `imperium-secrets-*`, `imperium-memory-log`, `imperium-memory-projection`, `imperium-runtime`) wherever they apply. Add new crates only for capabilities that do not exist in the Imperium crate store.

This is **not** a rewrite of the existing Imperium codebase verbatim. The existing codebase (mesh, STUN, PSK encryption, multi-protocol controllers, dormant toolkit) is **reference material**. The new build folds the working parts into the Imperium architecture, extracts the reusable primitives into the crate store, and replaces the rest with implementations that match the thesis.

The end state is one binary: `imperium`, with Imperium capabilities present as crates in the workspace, activated by configuration.

---

## Phase plan

Build in phases. Each phase is independently shippable (the system works at the end of the phase). No phase depends on a later phase's components being implemented.

### Phase 0: Workspace integration and primitives audit
### Phase 1: P2P mesh with operator-signed membership + hybrid PQC
### Phase 2: Two-protocol transport with active/standby orchestration
### Phase 3: Strainer primitive and first concrete strainer stacks
### Phase 4: Classifier sensors + signature engine sensor
### Phase 5: Closed-loop signature extraction with operator approval
### Phase 7: Dormant toolkit + forensics primitives

Each phase has its own section below with concrete crate names, message types, and acceptance criteria.

---

## Crate naming convention

New Imperium crates use the prefix `imperium-net-` (network defense). This is distinct from `imperium-protocol` (the message schema crate) and from existing Imperium crates. If the project is later renamed, the prefix changes consistently.

- `imperium-net-mesh` — P2P transport, NAT traversal, peer connectivity
- `imperium-net-cluster` — operator-signed membership, bootstrap tokens, configuration gossip
- `imperium-net-transport` — VPN protocol controllers (Xray, AmneziaWG) and the active/standby orchestrator
- `imperium-net-strainer` — strainer primitive, composition runtime
- `imperium-net-sensors` — classifier micro-models, signature engine sensor, packet capture
- `imperium-net-signatures` — bundled and extracted signature databases, extraction crate, operator approval flow
- `imperium-net-toolkit` — dormant forensics and counter-forensics tools

Crates in the existing Imperium crate store that are extended:

- `imperium-secrets-*` — gain hybrid PQC signing surfaces (ML-DSA alongside Ed25519)
- `imperium-protocol` — gains the new message types listed in each phase
- `imperium-memory-log`, `imperium-memory-projection` - used for deterministic event history and operator-selected extraction context
- `imperium-runtime` — gains lifecycle hooks for the new Imperium subsystems

If a primitive needs to be extracted to the crate store from the existing Imperium codebase (e.g., `ManagedProcess` for subprocess lifecycle), extract it to a new crate in the Imperium store with a clear name. Do not embed reusable primitives inside `imperium-net-*` crates.

---

## Phase 0: Workspace integration and primitives audit

**Goal:** Imperium capabilities are addressable from the Imperium workspace. No new functionality yet; this is the architectural baseline.

**Tasks:**

1. Create the `imperium-net-*` crates as empty crate skeletons in the Imperium workspace. Each one declares its dependencies on `imperium-bus`, `imperium-protocol`, and the relevant Imperium primitives. Each one exports a single `init()` function that subscribes to the bus and registers its presence.

2. Audit `imperium-secrets-vault`, `imperium-secrets-broker`, `imperium-secrets-threshold`, `imperium-secrets-audit` for existing PQC primitives. Determine whether hybrid PQ signing already exists in any of them or is planned. Document what's there.

3. Add ML-KEM-768 and ML-DSA-65 as workspace dependencies if not present. Use vetted Rust crates (`ml-kem`, `ml-dsa` from the RustCrypto ecosystem, or `pqcrypto-mlkem`/`pqcrypto-mldsa`). Pin versions; do not use unvetted alternatives.

4. Add `imperium-net-crypto` as a thin crate (or fold it into an existing crate store member if one fits) that exports hybrid handshake primitives:
   - `HybridX25519Mlkem` — wraps X25519 + ML-KEM-768 key exchange, returns combined session key derived via HKDF
   - `HybridEd25519Mldsa` — wraps Ed25519 + ML-DSA-65 signing, produces and verifies dual signatures
   - Constant-time error handling, zeroization of intermediate values, no key material exposed in error paths.

5. Add `imperium-net-mesh`, `imperium-net-cluster`, etc. as workspace members. They depend on `imperium-net-crypto`. Empty modules at this point.

**Acceptance:** The Imperium workspace builds with all new crates present. `cargo test` passes. No new functionality is exercised, but the scaffolding is ready.

**Reference:** The existing Imperium codebase has `crypto.rs` with classical primitives (AES-GCM, ChaCha20-Poly1305, X25519, HKDF). Treat that file as reference for what the engine surface looks like, but do not port it directly; the new hybrid primitives go in `imperium-net-crypto`.

---

## Phase 1: P2P mesh with operator-signed membership + hybrid PQC

**Goal:** Cluster nodes can discover each other, authenticate via operator-signed bootstrap tokens, and establish hybrid-PQC-secured peer sessions.

### Crates touched

- `imperium-net-mesh` — UDP transport, STUN, peer connectivity
- `imperium-net-cluster` — bootstrap tokens, membership grants, configuration gossip
- `imperium-net-crypto` — hybrid handshake primitives (from Phase 0)
- `imperium-protocol` — new message types

### New message types in `imperium-protocol`

```
MeshHello { peer_id, mapped_addr_candidates, hybrid_kex_init }
MeshHelloResponse { peer_id, hybrid_kex_response, session_id }
MeshPing { session_id, seq }
MeshPong { session_id, seq }
MeshPeerAnnouncement { peer_id, endpoints, signed_by_operator }
BootstrapToken { cluster_id, operator_pubkey_bundle, single_use_signature, expires_at }
MembershipGrant { peer_id, cluster_id, granted_at, operator_signature }
MembershipGossip { known_peers: [peer_id], known_grants_hash }
ConfigurationVersion { version, operator_signature }
ConfigurationFetchRequest { current_version }
ConfigurationFetchResponse { config_blob, version, operator_signature }
```

All `*_signature` fields are hybrid Ed25519+ML-DSA-65 dual signatures. Verification requires both to validate.

### `imperium-net-mesh` responsibilities

Implements UDP-based peer-to-peer connectivity with NAT traversal. Reference the existing Imperium mesh implementation for the STUN logic and the signaling-rendezvous fallback pattern, but rebuild on Imperium's bus rather than the old direct-socket model.

- STUN client for public-address discovery using any cluster peer with a known public address as the STUN responder.
- Optional signaling rendezvous (HTTP `POST /register`, `GET /peers`) for clusters that have an operator-run rendezvous endpoint. **Must be optional.** The cluster works with hard-coded bootstrap peer addresses alone if no rendezvous is configured.
- Direct connectivity via STUN-derived mapped addresses. ICE-style candidate exchange is **out of scope for Phase 1** — Phase 1 handles most NATs via STUN. Symmetric-NAT survivors fall back to relay-through-public-peer (degraded mode).
- The session encryption between peers uses session keys derived from the hybrid handshake — **not** a pre-shared PSK. The PSK model in the existing Imperium code is reference-only; do not port it.

### `imperium-net-cluster` responsibilities

Implements operator-signed cluster membership.

**Bootstrap token generation (operator-side, CLI command):**

- Operator runs `imperium net cluster mint-token --cluster-id X --expires 7d`
- Token is a single-use signed payload containing the cluster ID, the operator's full hybrid public key bundle (Ed25519 + ML-DSA-65), expiry timestamp, and an operator signature over all of the above.
- Token is exported as a base32-encoded string or QR code suitable for out-of-band transfer.

**Join flow (new node):**

1. New node operator imports the bootstrap token via CLI.
2. New node starts. It discovers peers via mDNS (LAN) or hard-coded bootstrap peer addresses (internet) or the configured signaling rendezvous.
3. New node initiates a `MeshHello` to a discovered peer, including the bootstrap token as proof of operator authorization.
4. Existing peer verifies the token signature against the operator's pubkey bundle (which is embedded in the token).
5. Existing peer relays a `MembershipApprovalRequest` to its local store. The token is single-use; the existing peer records the token consumption and gossips this fact.
6. Operator (online or eventually online) reviews pending approval requests via the dashboard/CLI and approves.
7. Approval generates a `MembershipGrant` signed by the operator, gossiped to all peers.
8. New node receives its membership grant. It can now participate in full cluster operations.

**Pre-signed batch grants:** Operator can pre-mint a batch of grants for known node IDs ahead of time. Useful for adding nodes when the operator will be offline. Each grant is still single-use, still operator-signed.

**Configuration gossip:**

- Cluster configuration (strainer compositions, signature database, profile rotation schedule, etc.) is signed by the operator and version-numbered.
- New nodes pull current configuration after joining.
- Configuration updates propagate via gossip. Lamport-clock versioning resolves ordering. Operator's signature is the only authority.

### Acceptance criteria for Phase 1

- Two nodes can establish hybrid-PQC-secured peer sessions over UDP, with NAT traversal via STUN.
- A new node can join a running cluster by presenting an operator-signed bootstrap token, going through the approval flow, and receiving a gossiped membership grant.
- Configuration changes signed by the operator propagate to all cluster peers within a bounded time.
- All inter-peer traffic is encrypted with session keys from the hybrid handshake. No PSK in the live path.
- Bus events on the `cluster.*` topics emit for: peer joins, peer departures, configuration updates, gossip events.

### Out of scope for Phase 1

- ICE / hole-punching beyond what STUN provides
- Relay fallback (degraded mode is "connection fails," operator handles it)
- Cross-operator signature sharing

---

## Phase 2: Two-protocol transport with active/standby orchestration

**Goal:** Cluster runs two VPN protocols (Xray with VLESS+Reality, and AmneziaWG) in active/standby configuration with a deterministic orchestrator managing failover, healing, and emergency shutdown.

### Crates touched

- `imperium-net-transport` — protocol controllers + orchestrator
- `imperium-protocol` — new message types
- Crate store extraction: `imperium-managed-process` (subprocess lifecycle primitive, extracted from forensics tools in the existing codebase)

### New message types in `imperium-protocol`

```
ProtocolCommand { target_protocol_id, command: Activate | Deactivate | Reload | ApplyProfile }
ProtocolStatus { protocol_id, role: Active | Standby | Quarantined | Healing, health, telemetry }
ProtocolEvent { protocol_id, event: Started | Stopped | Crashed | ConfigReloaded | HealingCompleted | HealingFailed }
OrchestratorDecision { decision_type, affected_protocols, reason, evidence_event_ids }
EmergencyShutdown { reason, failed_protocols, diagnostic_summary }
```

### `imperium-managed-process` (new crate in the Imperium store)

Generic primitive for spawning, watching, gracefully stopping, and restarting subprocesses with resource budgets. Used by the protocol controllers and the dormant toolkit.

- Spawn with arguments and environment.
- Capture stdout/stderr into the tracing bus.
- Health-watch loop (configurable check intervals).
- Graceful stop via SIGTERM with timeout-then-SIGKILL escalation.
- Resource budget enforcement: memory cap, CPU cap, runtime cap.
- Restart policy: never / on-failure / always, with backoff.

Extracted from the existing Imperium codebase's eleven protocol controllers, which currently duplicate this logic.

### `imperium-net-transport` responsibilities

**Protocol controllers:**

Implement controllers for **two protocols only** in Phase 2:

1. **Xray (VLESS+Reality)** — TLS-mimicry, TCP-based, server-with-RPC. Richest config surface. Reference: existing `crates/imperium/src/vpn/xray.rs` or similar.
2. **AmneziaWG** — noise-pattern-disruption, UDP-based, kernel-module. Live-mutation surface. Reference: existing `crates/imperium/src/vpn/amneziawg.rs`.

Each controller is a crate (or module within `imperium-net-transport`) that:

- Owns a `ManagedProcess` for its external binary.
- Subscribes to `ProtocolCommand` messages addressed to its `protocol_id`.
- Emits `ProtocolStatus` on a heartbeat (every 5s default) and `ProtocolEvent` on state changes.
- Implements three thin functions: `render_config(template, params)`, `parse_status(binary_output)`, `map_profile(traffic_profile)`. These are the protocol-specific knowledge. Everything else (lifecycle, message handling) is generic.

**Orchestrator:**

A single subsystem inside `imperium-net-transport` that subscribes to `ProtocolStatus`, `ProtocolEvent`, `ThreatAssessment` (when Phase 4 lands), and emits `ProtocolCommand` and `OrchestratorDecision`.

The orchestrator's state machine has exactly four states:

- **Steady** — one Active, one Standby, both healthy.
- **Failover** — Active failed, Standby promoted, old Active enters Quarantine, healing loop begins. Standby slot is empty during this window.
- **Healing** — Quarantined protocol is being repaired. Self-test pending.
- **Emergency** — Active fails before healing produces a new Standby. Both protocols torn down. `EmergencyShutdown` emitted. Operator-only recovery.

The orchestrator's policy is **deterministic**. No model, no classifier in the decision path. The classifier outputs (Phase 4) feed in as additional inputs to deterministic rules.

**Configurable policy knobs (in cluster configuration, gossiped from operator):**

- Health-check threshold and interval
- Burn threshold (when does a profile move from "soft suspicious" to "burned, rotate now")
- Healing self-test requirements
- Double-degraded policy: `emergency_shutdown` (default) or `safe_mode_lock` (opt-in for non-adversarial environments)

### Acceptance criteria for Phase 2

- Cluster runs Xray and AmneziaWG simultaneously, one active, one warm standby.
- Killing the active protocol's external binary triggers failover within the health-check window. Standby becomes active. The killed protocol enters quarantine, healing runs, completes self-test, returns to standby.
- Killing both protocols in quick succession (faster than healing) triggers emergency shutdown. Both protocols torn down. Bus emits `EmergencyShutdown`. Cluster requires manual operator recovery.
- Configuration updates (new profile parameters, new rotation schedule) gossip through the cluster and take effect on the next scheduled rotation.

### Out of scope for Phase 2

- Strainer involvement in protocol responses (Phase 3)
- Classifier-driven failover decisions (Phase 4)

---

## Phase 3: Strainer primitive and first concrete strainer stacks

**Goal:** The strainer pattern is implemented as a reusable primitive. First concrete strainer stacks are deployed for response degradation and authentication-exchange filtering.

### Crates touched

- `imperium-net-strainer` — strainer primitive, composition runtime
- Individual strainer crates: `imperium-strainer-timing`, `imperium-strainer-byte-jitter`, `imperium-strainer-truncation`, `imperium-strainer-auth-shape`, etc.
- `imperium-protocol` — new message types
- `imperium-net-transport` — protocol controllers integrate strainer stacks into their response paths

### Strainer primitive contract

A strainer is a Rust type implementing the `Strainer` trait:

```rust
pub trait Strainer: Send + Sync {
    fn id(&self) -> &str;
    fn shape_filtered(&self) -> &str;  // human-readable description, for audit
    fn apply(&self, input: StrainerInput) -> StrainerOutput;
}
```

Key properties:

- Deterministic given input and configured parameters
- No internal classification logic
- No knowledge of upstream routing decisions
- On-path-or-off-path is a routing concern, never a strainer concern
- Configurable via declarative parameters (no code changes to retune)

### Strainer stack composition

A stack is declared in cluster configuration:

```yaml
strainer_stacks:
  xray_probe_response:
    - id: "timing"
      params: { distribution: "web_browsing_normal", jitter_ms: 50 }
    - id: "byte_jitter"
      params: { jitter_bytes: 8, seed_rotation_minutes: 60 }
    - id: "truncation"
      params: { max_response_length: 1400 }

  xray_auth_outer:
    - id: "auth_shape_outer"
      params: { expected_byte_count: 64, version: "v3" }

  xray_auth_inner:
    - id: "auth_shape_inner"
      params: { expected_structure: "vless_reality_v1" }
```

Stacks are referenced by name from the protocol controllers and the orchestrator's routing decisions.

### New message types in `imperium-protocol`

```
StrainerRejection { strainer_id, stack_id, shape_failed, source_identifier, timestamp }
StrainerStackComposition { stack_id, ordered_strainer_ids, parameters, version }
RoutingDecision { flow_id, source, applicable_strainer_stack: Option<stack_id> }
```

`StrainerRejection` events go into `imperium-memory-log`. They are retained as deterministic event history, can seed operator-triggered extraction, and surface in operator dashboards as attack-attempt telemetry.

### Concrete strainers to implement in Phase 3

**Response-degradation strainers (probe-response stacks):**

- `imperium-strainer-timing` — delays response by a distribution-sampled amount matching normal traffic for the protocol
- `imperium-strainer-byte-jitter` — perturbs non-validating fields by deterministic-pseudorandom (rotating seed) byte changes
- `imperium-strainer-truncation` — caps response length to the shorter of (normal distribution sample, actual length)

**Authentication-exchange strainers:**

- `imperium-strainer-auth-shape-outer` — filters the outer shape of an authentication exchange (e.g., expected total byte count, packet ordering)
- `imperium-strainer-auth-shape-inner` — filters the inner shape revealed by the outer strainer (multi-stage composition)

These are five small crates. Each does one thing. None of them know about the others.

### Integration into protocol controllers

Each protocol controller declares which strainer stacks compose its response path and its authentication path. The controller emits responses through the configured stack. The orchestrator decides whether a given flow's responses route through the stack or bypass it based on threat signals (Phase 4 will add the threat-signal-driven routing; Phase 3 routes based on simple rules — e.g., "always strain responses to sources flagged as suspicious").

### Acceptance criteria for Phase 3

- Strainer primitive exists in `imperium-net-strainer`. The `Strainer` trait is implemented by five concrete strainers.
- Stack compositions are declared in cluster configuration and gossiped via the cluster's config-propagation mechanism.
- Xray and AmneziaWG controllers route responses through their configured strainer stacks for sources matching a configurable rule set.
- StrainerRejection events appear in `imperium-memory-log` and are queryable.
- Rotating a strainer composition (changing the configuration, gossiping the new version, peers reloading) does not break legitimate clients and does invalidate any prior attacker reconnaissance of the previous composition.

### Out of scope for Phase 3

- Authentication strainer integrated with actual auth path (the auth strainer is implemented but not yet wired into the protocol auth flow — Phase 4 adds the wiring once the sensor stack exists)
- Smudge filter for malware C2 disruption on egress (deferred to v1.5)
- Strainer-driven signature extraction (Phase 5)

---

## Phase 4: Classifier sensors + signature engine sensor

**Goal:** The system has multiple sensor inputs feeding `ThreatAssessment` events. Classifier micro-models and a signature engine both contribute. Sensor diversity is established.

### Crates touched

- `imperium-net-sensors` — sensor framework, classifier integration, signature engine sensor
- `imperium-protocol` — new message types
- `imperium-net-transport` — orchestrator consumes sensor output

### New message types in `imperium-protocol`

```
ThreatAssessment {
    id, timestamp, source_identifier,
    severity: 0.0..1.0,
    source: Classifier(model_id) | SignatureEngine | TimingAnalyzer | ProbeDetector | Combined,
    evidence_event_ids,
    structured_payload,
}

SensorFeature { sensor_id, flow_id, feature_vector, timestamp }
```

### Classifier sensors

Three micro-models per the existing Imperium design (threat detector, pattern matcher, action selector), each ~0.5B parameters, GGUF format, runnable via `llama.cpp` adapter from `imperium-models`.

Each classifier sensor:

- Subscribes to `SensorFeature` events on its configured topic
- Runs inference with a target latency budget (default 30ms per model)
- Emits `ThreatAssessment` events with `source: Classifier(model_id)` and a confidence in [0, 1]
- Models are loaded on demand (use `imperium-managed-process` or equivalent for the model host lifecycle)

**Crucially:** the classifier's input is a **structured feature vector**, not raw bytes. A feature-extraction strainer (implemented as a regular strainer in `imperium-net-strainer`) sits between the packet capture and the classifier. The classifier never sees raw bytes.

### Signature engine sensor

Uses YARA as the matching engine. YARA is the right choice over ClamAV because:

- BSD-licensed (no GPL entanglement with the single-binary deployment story)
- Designed for byte-pattern matching against streams
- Lighter than ClamAV at runtime
- ClamAV stays as a dormant tool (Phase 7) for heavy-scan activations

The signature engine sensor:

- Subscribes to packet-capture events from the sensor fabric
- Runs YARA rules against the captured byte stream
- Emits `ThreatAssessment` events with `source: SignatureEngine` and matched-rule provenance
- Operates as a **verifier for high-confidence classifier outputs first**, not as a continuous full-stream scanner. The classifier emits a 0.7+ confidence assessment; the signature engine sensor verifies. This bounds CPU cost.

### Signature database structure

Two layers, kept distinct:

- **Bundled signatures** — ship with Imperium releases. Hash-verified on load. Loaded from `~/.config/imperium/imperium/signatures/bundled/`.
- **Extracted signatures** — operator-approved additions. Loaded from `~/.config/imperium/imperium/signatures/extracted/`. Each one has provenance metadata.

The engine loads both directories. Match results identify which layer the matching signature came from. Operator dashboard distinguishes them in every view.

### Sensor fusion in the orchestrator

The orchestrator's deterministic policy now consumes `ThreatAssessment` events. Policy rules (configurable, defaults shipped):

- Two sensors agreeing at confidence > 0.5 each → treat as high-confidence threat, rotate profile
- SignatureEngine match → treat as high-confidence threat regardless of classifier output (deterministic ground truth)
- Single classifier > 0.85 → route source through strainer stack, do not yet rotate
- Classifier disagreement → log, do nothing (low signal)

These are the v1 rules. The orchestrator's policy is expected to be tuned by operators per environment.

### Acceptance criteria for Phase 4

- All three classifier micro-models load and run with sub-100ms decision latency on modest hardware.
- The signature engine sensor matches bundled YARA rules against captured traffic and emits `ThreatAssessment` events.
- The orchestrator's policy correctly combines sensor outputs and either routes flows through strainer stacks or triggers profile rotation according to the configured rules.
- Adversarial inputs that produce specific classifier outputs by raw-byte manipulation are defeated by the feature-extraction strainer (the classifier sees feature vectors, not bytes).

### Out of scope for Phase 4

- Signature extraction from accumulated rejection patterns (Phase 5)

---

## Phase 5: Closed-loop signature extraction with operator approval

**Goal:** Patterns of attempted attacks observed by the sensor layer or selected by the operator become candidate signatures. Operator reviews and approves. Approved signatures join the extracted signature database. Future attempts with matching shapes are caught at the signature engine layer.

### Crates touched

- `imperium-net-signatures` — extraction crate, staging area, approval flow, database management
- `imperium-protocol` — new message types

### New message types in `imperium-protocol`

```
SignatureCandidate {
    id, extracted_at,
    rule_text,                    // YARA rule produced by extractor
    triggering_event_ids,          // events that motivated the extraction
    proposed_severity,
    false_positive_estimate,       // measured against the rest of the log
    extractor_version,
}

SignatureApproved { candidate_id, approved_at, operator_signature, deployment_version }
SignatureRejected { candidate_id, rejected_at, reason }
ExtractedSignatureActivated { signature_id, in_database_at }
ExtractedSignatureRollback { signature_id, reason }
```

### Extraction crate

A deterministic Rust function that takes a slice of log events (the triggering events flagged by sensors or selected by the operator) and produces a candidate YARA rule.

**The LLM is not in the extraction path.** Sensors and operators can flag events as candidates. The extractor turns flagged events into rule text deterministically based on byte patterns, surrounding context, and configured extraction heuristics. The operator can review what the extractor produced and verify it is a sensible rule.

If the extraction heuristics need to evolve (better feature selection, tighter rule shapes), the extractor is updated as a code change to the crate. The extractor never learns at runtime.

### Approval flow

1. The sensor layer or operator emits a `SignatureCandidate` event into a staging area persisted in `imperium-store`.
2. Operator dashboard shows pending candidates. Each candidate displays:
   - The proposed YARA rule
   - The triggering events that motivated it
   - A false-positive estimate computed by running the rule against the rest of the log
   - Provenance: when, what sensor pattern or operator selection, what extractor version
3. Operator approves or rejects.
4. On approval: candidate is signed by the operator (hybrid Ed25519+ML-DSA), the rule lands in the extracted signature database, the signature engine reloads (YARA hot-reload is cheap), the cluster's gossip propagates the new signature to all peers.
5. On rejection: candidate is archived. The reason for rejection is logged. If the same pattern recurs, future candidates with similar shape are flagged with reference to the prior rejection.

### Rollback

If an extracted signature turns out to false-positive against legitimate traffic, the operator can roll it back. The signature is moved out of the active extracted directory into an archived directory. The gossip propagates the rollback. Provenance is retained for audit.

### Acceptance criteria for Phase 5

- A simulated attack producing a recognizable pattern -> sensor/operator-selected events -> extractor produces a YARA rule -> operator approves -> signature lands in active database -> subsequent attempts with the same pattern are caught at the signature engine layer.
- Rollback of an extracted signature removes it from the active path and propagates to all cluster peers.
- The bundled signature database is unaffected by extraction or rollback operations. Bundled and extracted layers remain visibly distinct in the operator dashboard.

### Out of scope for Phase 5

- Cross-operator signature sharing (deferred to v1.5+ if ever)
- Fully automated promotion (forbidden by thesis)

---

## Phase 7: Dormant toolkit + forensics primitives

**Goal:** The forensics toolkit (packet capture, suricata, zeek, fail2ban, etc.) operates as dormant tools — zero-resource until triggered, run under bounded budgets, deactivate cleanly. The SDR radio bridge uses the same primitive.

### Crates touched

- `imperium-net-toolkit` — tool manifest, lifecycle integration
- Crate store extraction: `imperium-on-demand-subprocess` (dormancy primitive), possibly merge with `imperium-managed-process` from Phase 2
- Individual tool crates: `imperium-tool-suricata`, `imperium-tool-yara-scan`, `imperium-tool-zeek`, etc. Each is small — declares binary, args template, output parser, trigger conditions.

### Dormancy primitive

State machine: `Dormant → Initializing → Active → CoolingDown → Dormant`. Resource budgets enforced via cgroups. Auto-trigger conditions are bus-subscription patterns.

### Trigger conditions

Each tool declares:

- Manual activation (via dashboard / CLI)
- Auto-trigger conditions, e.g., "activate when `ThreatAssessment` with severity > 0.8 lands on the bus"
- Idle timeout for auto-deactivation

### Acceptance criteria for Phase 7

- Forensics tools start dormant (zero resource usage).
- Activating a tool (manually or via trigger) spawns its subprocess under the configured budget.
- Idle timeout deactivates the tool cleanly.
- The SDR radio bridge uses the same primitive (its existing implementation in Imperium's tree migrates to the new primitive).

---

## Cross-phase guidelines

### Bus message naming

All Imperium bus topics use the prefix `net.`:
- `net.cluster.*` — cluster membership, configuration
- `net.transport.*` — protocol controllers, orchestrator
- `net.strainer.*` — strainer events, stack changes
- `net.sensors.*` — sensor outputs, threat assessments
- `net.signatures.*` — signature lifecycle
- `net.toolkit.*` — dormant tool lifecycle

### Storage

Each Imperium crate that needs persistent state uses `imperium-store` (shared SQLite). No private databases. Schema migrations land in the relevant crate's migration set.

### Configuration

Cluster configuration is gossiped from the operator (Phase 1's `ConfigurationFetchResponse`). Per-node configuration is in `~/.config/imperium/imperium/local.toml`. Secrets go in `imperium-secrets-vault` and are referenced by ID from configuration.

### Testing

Every phase has acceptance criteria listed above. Each acceptance criterion has a corresponding integration test. The integration tests run in CI. Unit tests within each crate cover the deterministic logic; integration tests cover bus-mediated interactions.

### Documentation

Each crate has a `README.md` describing what it does in two paragraphs and linking to the relevant blueprint section. The blueprint and thesis live in the workspace root.

---

## What "done" looks like for v1

When Phases 0–7 are complete, the system has:

- Two-protocol VPN cluster with active/standby and emergency-shutdown failsafe
- P2P self-deployment with operator-signed membership and hybrid PQC
- Layered strainer defenses with rotatable compositions
- Multi-sensor threat detection (classifiers + signature engine)
- Closed-loop signature extraction with operator-approved promotion
- Dormant forensics toolkit available on-demand

That is a complete defensive system. Every layer is auditable. Every probabilistic component is shadowed by a deterministic one. Every defensive surface is rotatable. The bundled defense floor is load-bearing; the intelligence layer is additive.

Imperium is shippable at v1. Cross-operator features, fully automated extraction, and other extensions are v1.5+.

---

## What to do when this blueprint is wrong

The blueprint will be wrong in places. The thesis is the authority. When the blueprint and thesis conflict, the thesis wins.

When implementation reveals that a phase's design has a flaw:

1. Stop and document what's wrong.
2. Refer to the thesis principles. Which one would resolve the ambiguity?
3. Propose a revision in writing. Get review before implementing the revised design.
4. Update the blueprint in the same commit as the implementation change.

The blueprint is a living document. The thesis is not. Update the blueprint freely as you learn. Update the thesis only after careful discussion.
