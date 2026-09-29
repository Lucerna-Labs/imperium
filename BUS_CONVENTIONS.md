# Bus Topic Conventions

Topic strings on the in-process bus follow a hierarchical, dot-separated namespace.
`Bus::subscribe(prefix)` receives every event whose topic `starts_with(prefix)`.
This means topic segments must be ordered from general → specific so that prefix
subscriptions work correctly.

## Namespace layout

```
emergency.*              Runtime-level emergency shutdown signals
runtime.*                RuntimeCoordinator lifecycle
net.transport.*          Protocol controllers, orchestrator decisions
net.sensors.*            Classifier, signature engine
net.signatures.*         Signature staging, approval, activation, extraction
net.strainer.*           Strainer stack rejections
net.cluster.*            Cluster membership, config, gossip
net.mesh.*               Mesh transport (ping/pong)
net.toolkit.*            Toolkit activation, state
```

## Rules

1. **General → specific ordering.** The discriminating segment comes last so that
   prefix subscriptions remain valid. Example: `net.transport.event.wireguard`,
   not `net.transport.wireguard.event`.

2. **Emergency topics use the `emergency.*` namespace.** Any message that the
   `RuntimeCoordinator` must receive to trigger shutdown lives under `emergency.`.
   Subsystem-specific emergency topics use `emergency.{subsystem}.{reason}`.

3. **Subsystem ready topics** follow `{namespace}.ready` — e.g. `net.sensors.ready`,
   `net.transport.ready`.

4. **No implicit cross-namespace subscriptions.** A crate subscribing to `net.sensors.`
   should not receive `net.signatures.` events. Keep namespaces disjoint.

5. **Dynamic segments** (protocol kind, subsystem name) are always the final segment.

## Audit table

Generated 2026-05-13 (Round 5 update). Spot-checked 2026-09-22 against
current production code — see Drift supplement below. Covers every
`bus.publish()` and `bus.subscribe()` call in production code.

### Publishers

| # | Crate | File | Topic | Message | Subscriber match |
|---|-------|------|-------|---------|-----------------|
| 1 | imperium-runtime | lib.rs | `runtime.subsystem.ready.{name}` | SubsystemReady | `runtime.subsystem.ready` (runtime tests) ✓ |
| 2 | imperium-cli | control.rs | `emergency.cli.operator_shutdown` | EmergencyShutdown | `emergency` (coordinator) ✓ |
| 3 | imperium-cli | control.rs | `net.signatures.approve_request` | SubsystemReady | `net.signatures.` (signatures init) ✓ |
| 4 | imperium-cli | control.rs | `net.signatures.reject_request` | SignatureRejected | `net.signatures.` (signatures init) ✓ |
| 5 | imperium-cli | control.rs | `net.signatures.extraction_request` | ExtractionRequest | `net.signatures.extraction_request` (extraction loop) ✓ |
| 6 | imperium-net-transport | orchestrator.rs | `emergency.transport.double_degraded` | EmergencyShutdown | `emergency` (coordinator) ✓ |
| 7 | imperium-net-transport | orchestrator.rs | `net.transport.command` | ProtocolCmd | `net.transport.` (transport init) ✓ |
| 8 | imperium-net-transport | orchestrator.rs | `net.transport.decision` | OrchestratorDecision | `net.transport.` (transport init) ✓ |
| 9 | imperium-net-transport | controller.rs | `net.transport.event.{kind}` | ProtocolEvt | `net.transport.event` (orchestrator) ✓ |
| 10 | imperium-net-transport | lib.rs | `net.transport.ready` | SubsystemReady | `net.transport.` (transport init) ✓ |
| 11 | imperium-net-sensors | lib.rs | `net.sensors.ready` | SubsystemReady | `net.sensors.` (sensors init, orchestrator) ✓ |
| 12 | imperium-net-sensors | classifier.rs | `net.sensors.threat` | ThreatAssessment | `net.sensors.` (orchestrator) ✓ |
| 13 | imperium-net-sensors | signature_engine.rs | `net.sensors.signature_match` | ThreatAssessment | `net.sensors.` (orchestrator) ✓ |
| 14 | imperium-net-sensors | signature_engine.rs | `net.signatures.activated` | SignatureActivated | `net.signatures.` (signatures init) ✓ |
| 15 | imperium-net-sensors | signature_engine.rs | `net.signatures.activation_failed` | SignatureActivationFailed | `net.signatures.` (signatures init) ✓ |
| 16 | imperium-net-signatures | lib.rs | `net.signatures.ready` | SubsystemReady | `net.signatures.` (signatures init) ✓ |
| 17 | imperium-net-signatures | staging.rs | `net.signatures.candidate` | SignatureCandidate | `net.signatures.` (signatures init) ✓ |
| 18 | imperium-net-signatures | staging.rs | `net.signatures.approved` | SignatureApproved | `net.signatures.approved` (engine) ✓ |
| 19 | imperium-net-signatures | staging.rs | `net.signatures.rejected` | SignatureRejected | `net.signatures.` (signatures init) ✓ |
| 20 | imperium-net-signatures | extractor.rs | `net.signatures.candidate_pending` | SignatureCandidatePending | `net.signatures.` (signatures init) ✓ |
| 21 | imperium-net-signatures | extractor.rs | `net.signatures.extraction_failed` | ExtractionFailed | `net.signatures.` (signatures init) ✓ |
| 22 | imperium-net-strainer | lib.rs | `net.strainer.ready` | SubsystemReady | `net.strainer.` (strainer init) ✓ |
| 23 | imperium-net-strainer | stack.rs | `net.strainer.rejection` | StrainerRejection | `net.strainer.rejection` (memory-log), `net.strainer.` (init) ✓ |
| 24 | imperium-net-cluster | lib.rs | `net.cluster.ready` | SubsystemReady | `net.cluster.` (cluster init) ✓ |
| 25 | imperium-net-cluster | membership.rs | `net.cluster.membership.request` | MembershipApprovalReq | `net.cluster.` (cluster init) ✓ |
| 26 | imperium-net-cluster | membership.rs | `net.cluster.membership.granted` | MembershipGrant | `net.cluster.membership.granted` (membership), `net.cluster.` (init) ✓ |
| 27 | imperium-net-cluster | membership.rs | `net.cluster.membership.gossip` | MembershipGossip | `net.cluster.` (cluster init) ✓ |
| 28 | imperium-net-cluster | config.rs | `net.cluster.config.updated` | ConfigVersion | `net.cluster.` (cluster init) ✓ |
| 29 | imperium-net-cluster | config.rs | `net.cluster.config.fetch_request` | ConfigFetchReq | `net.cluster.` (cluster init) ✓ |
| 30 | imperium-net-cluster | config.rs | `net.cluster.config.fetch_response` | ConfigFetchResp | `net.cluster.config.fetch_response` (config), `net.cluster.` (init) ✓ |
| 34 | imperium-net-mesh | lib.rs | `net.mesh.ready` | SubsystemReady | `net.mesh.` (mesh init) ✓ |
| 35 | imperium-net-mesh | transport.rs | `net.mesh.ping.sent` | MeshPing | `net.mesh.` (mesh init) ✓ |
| 36 | imperium-net-mesh | transport.rs | `net.mesh.pong.sent` | MeshPong | `net.mesh.` (mesh init) ✓ |
| 37 | imperium-net-toolkit | lib.rs | `net.toolkit.activation` | ToolActivationReq | — (skeleton, no subscriber) ✓ |
| 38 | imperium-net-toolkit | lib.rs | `net.toolkit.state` | ToolStateChange | — (skeleton, no subscriber) ✓ |

### Subscribers

| # | Crate | File | Pattern | Matches topics |
|---|-------|------|---------|---------------|
| 1 | imperium-runtime | lib.rs | `emergency` | `emergency`, `emergency.*` |
| 2 | imperium-runtime | lib.rs (tests) | `runtime.subsystem.ready` | `runtime.subsystem.ready.*` |
| 3 | imperium-net-transport | lib.rs | `net.transport.` | all `net.transport.*` |
| 4 | imperium-net-transport | orchestrator.rs | `net.transport.event` | `net.transport.event`, `net.transport.event.*` |
| 5 | imperium-net-transport | orchestrator.rs | `net.sensors.` | all `net.sensors.*` |
| 7 | imperium-net-sensors | lib.rs | `net.sensors.` | all `net.sensors.*` |
| 8 | imperium-net-sensors | signature_engine.rs | `net.signatures.approved` | `net.signatures.approved` |
| 9 | imperium-net-signatures | lib.rs | `net.signatures.` | all `net.signatures.*` |
| 10 | imperium-net-signatures | extractor.rs | `net.signatures.extraction_request` | `net.signatures.extraction_request` |
| 11 | imperium-net-strainer | lib.rs | `net.strainer.` | all `net.strainer.*` |
| 12 | imperium-net-cluster | lib.rs | `net.cluster.` | all `net.cluster.*` |
| 13 | imperium-net-cluster | config.rs | `net.cluster.config.fetch_response` | exact match |
| 14 | imperium-net-cluster | membership.rs | `net.cluster.membership.granted` | `net.cluster.membership.granted` |
| 16 | imperium-net-mesh | lib.rs | `net.mesh.` | all `net.mesh.*` |
| 17 | imperium-memory-log | lib.rs | `net.strainer.rejection` | `net.strainer.rejection` |
| 18 | imperium-memory-log | lib.rs | `net.transport.` | all `net.transport.*` |

### Known issues

| Issue | Status |
|-------|--------|
| Toolkit orphan publishers (`net.toolkit.*`) | Partially resolved — `net.toolkit.request` now has a live production subscriber (`ToolManager::subscribe_activation_requests` in `imperium-net-toolkit/src/lib.rs`); `net.toolkit.activation` / `net.toolkit.state` still have no production subscribers (gui subscribes to all via `subscribe_all`) |
| `net.sensors.signature_match` published from orchestrator test helper (`imperium-net-transport/src/orchestrator.rs:617`) in addition to the production publisher in `imperium-net-sensors/src/signature_engine.rs` — same topic, different origin; audit row 13 covers only the production path | cosmetic — test-only second publisher, not a namespace violation |

## Drift supplement (spot-check 2026-09-22)

Topics found in current production code but missing from the audit table
above (table predates them). Verified against live `bus.publish()` /
`bus.subscribe()` calls, not tests.

### Missing publishers (production)

| Crate | File | Topic | Message |
|-------|------|-------|---------|
| imperium-net-sensors | probe.rs | `net.sensors.probe_profile` | ProbeProfile (deliberately NOT a `ThreatAssessment` — five separate readings, no confidence, no action) |
| imperium-cli | control.rs | `net.transport.killswitch.command` | KillSwitchCommand |
| imperium-cli | control.rs | `net.transport.masque.configure` | MasqueTunnelConfig |
| imperium-cli | control.rs | `net.transport.hardening.apply` (already in table as orchestrator/lib publish; control socket and gui are additional publishers) | ProtocolHardeningProfile |
| imperium-cli | control.rs | `net.toolkit.request` (in addition to orchestrator row) | ToolActivationReq |
| imperium-cli | control.rs | `net.cluster.policy.apply` | PolicyApplyRequest |
| imperium-cli | control.rs | `net.vpn.deployment.apply` | VpnDeploymentPlan |
| imperium-cli | control.rs | `net.vpn.deployment.status_request` | VpnDeploymentStatusRequest |
| imperium-net-mesh | daemon.rs | `net.transport.leak_guard.status` (initial and after applied kill switch commands) | LeakGuardStatus |
| imperium-net-transport | masque.rs | `net.transport.masque.status` | MasqueTunnelStatus |
| imperium-net-transport | orchestrator.rs | `net.toolkit.request` | ToolActivationReq |
| imperium-net-transport | orchestrator.rs | `net.transport.hardening.apply` (adaptive hardening path) | ProtocolHardeningProfile |
| imperium-net-toolkit | lib.rs | `net.toolkit.activation` (row 37 listed it; confirmed still the publisher, now also consumed by toolkit test harness) | ToolActivationReq |
| imperium-net-toolkit | lib.rs | `net.toolkit.state` | ToolStateChange |
| imperium-runtime | deployment.rs | `net.cluster.membership.gossip` | MembershipGossip |
| imperium-runtime | deployment.rs | `net.cluster.config.fetch_response` | ConfigFetchResp |
| imperium-runtime | deployment.rs | `net.mesh.nat.plan` | NatProbePlan |
| imperium-runtime | deployment.rs | `net.mesh.relay.selected` | RelayFallbackSelected |
| imperium-runtime | deployment.rs | `net.transport.hardening.apply` | ProtocolHardeningProfile |
| imperium-runtime | deployment.rs | `net.vpn.deployment.status` | VpnDeploymentStatus |
| imperium-gui | lib.rs | `net.transport.killswitch.command` | KillSwitchCommand |
| imperium-gui | lib.rs | `net.transport.hardening.apply` | ProtocolHardeningProfile |
| imperium-gui | lib.rs | `net.signatures.approve_request` | SignatureApprovalRequest |
| imperium-gui | lib.rs | `net.signatures.reject_request` | SignatureRejected |
| imperium-gui | lib.rs | `emergency.cli.operator_shutdown` | EmergencyShutdown |

### Missing subscribers (production)

| Crate | File | Pattern | Matches topics |
|-------|------|---------|---------------|
| imperium-cli | main.rs | `net.signatures.approve_request` | operator approval bridge |
| imperium-cli | main.rs | `net.signatures.reject_request` | operator rejection bridge |
| imperium-net-toolkit | lib.rs | `net.toolkit.request` (`ToolManager::subscribe_activation_requests`, spawned in `main.rs`) | `net.toolkit.request` |
| imperium-net-mesh | transport.rs | `net.transport.hardening.apply` (`subscribe_hardening_profiles`) | hardening profile updates |
| imperium-net-transport | controller.rs | `net.transport.hardening.apply` (`subscribe_hardening_profiles`) | hardening profile updates |
| imperium-net-transport | hardening.rs | `net.transport.hardening.apply` (+ test-only `net.transport.hardening.status` / `net.transport.probe_deception.decision` subscribers in `#[cfg(test)]`) | hardening profile updates |
| imperium-net-transport | orchestrator.rs | `net.toolkit.request` (test-only subscribers in `#[cfg(test)]`; production orchestrator *publishes* this topic) | toolkit requests |
| imperium-gui | lib.rs | `subscribe_all` (`spawn_pump` — monitoring surface, not auditable substrate) | all topics |

### Subscriber gaps worth a follow-up (reported, not fixed)

- `net.cluster.policy.apply`,
  `net.transport.masque.configure`, `net.transport.masque.status`,
  `net.transport.leak_guard.status`, `net.mesh.nat.plan`,
  `net.mesh.relay.selected`, `net.toolkit.state` have verified production
  publishers but no dedicated production subscriber found outside
  `subscribe_all` (gui) and test harnesses. The bus test
  (`bus_topic_pairs.rs`) asserts pair coverage for some of these
  (masque.status, leak_guard.status, nat.plan,
  relay.selected, toolkit.state), but the live consumer side should be
  confirmed before the table claims full coverage.
- Rows 31–33 and subscriber rows 6 / 15 are absent (numbering gaps in the
  original table); `net.vpn.deployment.*`, toolkit, and gui topics were
  never added after Round 5. A full regeneration pass is recommended.

## Current network Lightcone bus boundary

| Topic | Publisher | Consumer | Bus payload |
|---|---|---|---|
| `net.lightcone.ready` | `imperium-net-lightcone::init_with_service` | GUI and operator monitors | `SubsystemReady` means the v4 pack loaded; strand liveness is tracked separately. |
| `net.lightcone.frame` | `MeshDaemon` bounded observer worker | supervised `LightconeStrand` | `LightconeStructure`: capture format, direction, structural seeds/kind, and SHA-256 of the complete original bytes. Raw TUN/IP and mesh UDP payload bytes stay in the daemon's private bounded queue. |
| `net.lightcone.receipt` | supervised `LightconeStrand` | GUI and operator status | `LightconeReceipt`: exact-graph admission, frame format, direction, pack/query/receipt hashes, passive/no-verdict flags. |

The daemon counts queued, published, dropped, and failed observer handoffs.
`vpn lightcone status` reports these alongside receipt counts and the strand's
current lifecycle. A published frame is not itself proof of a receipt; a
receipt is observation evidence, not packet authorization or a seal.
