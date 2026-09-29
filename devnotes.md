# Imperium VPN Dev Notes

Last updated: 2026-09-22

## 2026-09-22 — Windows-path cleanup

Removed all `C:\Projects\...` paths (Linux-only by standing policy) and
replaced Windows control-pipe references with the Unix socket
(`$XDG_RUNTIME_DIR/imperium/control.sock`, `/tmp/imperium-control.sock`
fallback). Open path question: the `ordo-device-peer` sibling is referenced
below but no such directory exists under `/home/jesse/Desktop/Projects/`;
verify its location before treating those paths as current.

## Current Status

The project now has the watchtower path removed, the VPN control surface wired through the CLI/control socket, Ordo integration added in the sibling `ordo-device-peer` project (location unverified — see open path question above), and the hardening primitives connected into both the simulated runtime and live mesh/transport control paths.

Recent validation:

- `/home/jesse/Desktop/Projects/imperium-main` (this repo): `cargo test` passed.
- `/home/jesse/Desktop/Projects/imperium-main`: `cargo check` passed.
- `ordo-device-peer` sibling (location unverified): `cargo test` passed.
- `ordo-device-peer` sibling (location unverified): `cargo check` passed.

The full hardening simulation currently passes, including the fortress target profile. In the deterministic simulation, the fortress profile achieves 100% delivery under the modeled loss/probe/burn conditions, zero unrecovered packet loss, zero unauthenticated routes to the real endpoint, and successful illusion-space handling for adversarial probes.

## Watchtower Removal

The old watchtower crate was removed from the active workspace.

Removed files:

- `crates/imperium-net-watchtower/Cargo.toml`
- `crates/imperium-net-watchtower/src/lib.rs`
- `crates/imperium-net-watchtower/src/observer.rs`
- `crates/imperium-net-watchtower/src/projection.rs`

Related cleanup:

- Removed the watchtower workspace member from `Cargo.toml`.
- Removed watchtower protocol message variants from `crates/imperium-protocol/src/lib.rs`.
- Removed orchestrator/watchtower subscription assumptions from runtime integration tests.

Intent: keep observation and adaptive response inside the current bus, sensors, memory log, orchestrator, toolkit, and hardening controller flow instead of keeping a parallel watchtower subsystem.

## Runtime Wiring

`imperium node start` now wires the core pieces together instead of only standing up isolated subsystems.

Relevant files:

- `crates/imperium-cli/src/main.rs`
- `crates/imperium-cli/src/control.rs`
- `crates/imperium-runtime/src/lib.rs`
- `crates/imperium-protocol/src/lib.rs`

Runtime startup now initializes:

- Cluster membership/config/token/access pieces.
- Mesh transport and mesh hardening subscription.
- Transport controller and transport hardening subscription.
- Strainer stack.
- Sensors and signature engine.
- Signature staging/extraction loop.
- Memory log.
- Toolkit activation flow.
- Orchestrator threat/failover/hardening flow.
- Deployment orchestrator subscription.
- CLI control socket command handling.

The important design point: hardening profiles are now real bus messages, not just isolated configuration objects. The orchestrator can publish hardening actions, the transport hardening controller validates and reports status, and the mesh/transport paths subscribe and alter behavior.

## Ordo Device Peer Integration

The Ordo adapter lives in (sibling location unverified — see open path question above):

- `ordo-device-peer/src/lib.rs`
- `ordo-device-peer/README.md`

The adapter exposes an `imperium_vpn` peer presence and maps typed Ordo VPN commands into Imperium control socket lines.

Supported Ordo capabilities:

- VPN health.
- Profile rotation.
- Active transport selection.
- Policy apply.
- NAT aggressive mode on/off.
- Kill switch arm/disarm/engage.
- MASQUE configuration.
- Hardening preset selection.
- Hardening JSON apply.
- Deployment plan apply.
- Deployment status request.
- Toolkit activation.
- Signature commands.
- Shutdown.

The key test is `maps_vpn_commands_to_imperium_control_lines` in `ordo-device-peer/src/lib.rs` (sibling location unverified), which verifies that Ordo commands resolve to the Imperium CLI/control surface.

## Control Socket Commands

Implemented in:

- `crates/imperium-cli/src/control.rs`

Current VPN commands:

```text
vpn health
vpn profile rotate [protocol]
vpn transport set-active <protocol>
vpn policy apply <policy_id>
vpn nat aggressive on|off
vpn killswitch arm|disarm|engage [reason]
vpn masque configure <json>
vpn deployment apply <json>
vpn deployment status
vpn toolkit activate <tool> [trigger]
vpn hardening preset balanced|resilience|fortress [protocol]
vpn hardening apply <json>
```

Important tests:

- `dispatch_vpn_profile_rotate`
- `dispatch_vpn_nat_aggressive_on`
- `dispatch_vpn_killswitch_engage`
- `dispatch_vpn_toolkit_activate`
- `dispatch_vpn_deployment_apply`
- `dispatch_vpn_deployment_status`
- `dispatch_vpn_hardening_preset`
- `dispatch_vpn_hardening_apply_rejects_bad_json`
- `dispatch_no_dead_cli_topics`

Signature control socket cleanup:

- `signatures pending` now reads pending candidates from the live `StagingArea`
  when the node is running.
- `signatures show <candidate_id>` now returns a JSON candidate snapshot,
  candidate status, and rejection reason when available.
- Bus-only dispatch tests return an explicit `signature staging unavailable`
  error rather than a misleading placeholder.

## NAT Traversal

Implemented in:

- `crates/imperium-net-mesh/src/traversal.rs`

Default NAT policy:

- Direct UDP.
- STUN-style mapped address discovery.
- Limited coordinated probing.
- Relay-through-peer fallback.

Aggressive NAT mode:

- Explicit opt-in only.
- Adds the birthday-paradox multi-probe strategy.
- Uses a high probe count in simulation, currently 65,536 probes.

Reasoning: high-rate probing may improve NAT traversal odds in hostile or constrained networks, but it can also become a fingerprint. The default path stays conservative.

Important tests:

- `default_policy_excludes_aggressive_probe`
- `aggressive_policy_requires_explicit_opt_in`

## Protocol Hardening Primitives

Defined in:

- `crates/imperium-protocol/src/lib.rs`

Main protocol types:

- `TrafficMorphProfile`
- `PaddingDistribution`
- `RekeyPolicy`
- `ProbeResistancePolicy`
- `ProbeFailureMode`
- `ProbeDeceptionPolicy`
- `ProbeDeceptionMode`
- `ProbeDeceptionDecision`
- `PathHoppingPolicy`
- `FecPolicy`
- `ProtocolHardeningProfile`
- `ProtocolHardeningStatus`

Protocol message variants now include:

- `ProtocolHardeningProfile`
- `ProtocolHardeningStatus`
- `ProbeDeceptionDecision`

These primitives are intended to be composable. They can be applied as profiles, generated by orchestrator decisions, emitted from Ordo controls, and consumed by mesh/transport processes.

## Hardening Profiles

Implemented in:

- `crates/imperium-net-transport/src/hardening.rs`

Current presets:

- `balanced-rf-inspired`
- `resilience-rf-inspired`
- `fortress-rf-inspired`

Balanced profile:

- Conservative hardening.
- Deception disabled.
- Lower overhead.
- Good default candidate when stealth matters more than maximum simulated resilience.

Resilience profile:

- Enables stronger traffic morphing, recovery, and probe handling.
- Uses `ShadowEndpoint` style deception.
- Intended for active burn/loss scenarios.

Fortress profile:

- Strongest current simulation profile.
- Uses `DecoyTranscript` illusion-space behavior.
- Higher overhead, stronger probe deception and recovery.
- This is the profile that hits the current perfect deterministic simulation target.

Validation rejects unsafe or unbounded configurations, including excessive cover traffic and excessive FEC expansion.

Important tests:

- `balanced_profile_is_valid`
- `resilience_profile_is_valid`
- `fortress_profile_is_valid`
- `rejects_excessive_cover_traffic`
- `rejects_unbounded_fec`
- `apply_publishes_status`

## Probe Deception / Illusion Space

Implemented in:

- `crates/imperium-net-transport/src/hardening.rs`

The `ProbeDeceptionEngine` decides whether a probe should see the real endpoint, a decoy transcript, a shadow endpoint, or silence.

Behavior:

- Authenticated probes may route to the real endpoint.
- Unauthenticated high-confidence probes route to illusion space when deception is enabled.
- Unauthenticated probes are never routed to the real endpoint.
- Per-source response budgets prevent infinite decoy interaction.
- Once budget is exhausted, the engine degrades to `SilentDrop`.
- Decoy persona IDs are deterministic and derived from the configured seed.
- Decisions publish to `net.transport.probe_deception.decision`.

This is the feature requested as: send probes to an illusion space where the probing side believes it reached the actual endpoint.

Important tests:

- `deception_routes_unauthenticated_probe_to_illusion_space`
- `deception_budget_degrades_to_silent_drop`

Important safety note: the deception path should remain bounded. If future changes make decoy behavior too rich, too chatty, or too stable across sources, it can become a new fingerprint.

## Mesh Packet Hardening

Implemented in:

- `crates/imperium-net-mesh/src/hardening.rs`
- `crates/imperium-net-mesh/src/transport.rs`

Main types:

- `HardenedPacketFrame`
- `HardenedPayload`
- `MeshHardener`

Behavior:

- Outbound mesh payloads can be wrapped in a hardened frame.
- Padding, jitter, rekey epoch, and FEC metadata are attached to the frame.
- Inbound recovery accepts hardened frames but also preserves compatibility with raw payloads.
- `MeshTransport` subscribes to hardening profile messages and updates send behavior.
- `send_ping` and `send_pong` pass payloads through the hardener before UDP send.

Important tests:

- `hardens_and_recovers_payload`
- `rekey_epoch_advances_on_byte_budget`
- `hardening_profile_wraps_payload_for_send`
- `hardening_subscription_updates_send_path`

## Process-Backed Protocol Config Hardening

Implemented in:

- `crates/imperium-net-transport/src/controller.rs`

`ProtocolController` now stores an optional hardening profile and can render hardening values into process configuration templates.

Supported template values include:

```text
{{hardening.profile_id}}
{{hardening.protocol_name}}
{{hardening.padding.mode}}
{{hardening.padding.max_overhead_percent}}
{{hardening.jitter.max_delay_ms}}
{{hardening.cover_traffic.rate_per_minute}}
{{hardening.rekey.bytes}}
{{hardening.probe.auth_first_packet}}
{{hardening.deception.enabled}}
{{hardening.deception.mode}}
{{hardening.deception.min_confidence}}
{{hardening.deception.max_transcript_bytes}}
{{hardening.path_hopping.enabled}}
{{hardening.fec.enabled}}
{{hardening.fec.data_shards}}
{{hardening.fec.parity_shards}}
```

Important tests:

- `render_config_includes_hardening_params`
- `hardening_subscription_updates_config_rendering`

## Orchestrator and Toolkit Flow

Implemented in:

- `crates/imperium-net-transport/src/orchestrator.rs`
- `crates/imperium-net-toolkit/src/lib.rs`

The orchestrator now has policy settings for toolkit activation and adaptive hardening.

Behavior:

- High-confidence threats can trigger toolkit diagnostics.
- High-confidence threats can publish adaptive hardening profile requests.
- Emergency paths can request snapshot tooling.
- Failover and recovery still go through the existing orchestrator state flow.

Important tests:

- `high_threat_requests_diagnostics_tool`
- `high_threat_requests_adaptive_hardening`
- `emergency_shutdown_requests_snapshot_tool`
- `subscribe_threat_assessment_triggers_failover`
- `subscribe_protocol_events_processes_crash`

## Deployment Orchestrator

Implemented in:

- `crates/imperium-runtime/src/deployment.rs`
- `crates/imperium-protocol/src/lib.rs`
- `crates/imperium-cli/src/control.rs`
- `ordo-device-peer/src/lib.rs` (sibling location unverified)

Deployment is now a real runtime service instead of only a test loop. `imperium node start` creates a `DeploymentOrchestrator` and subscribes it to `net.vpn.deployment.apply` and `net.vpn.deployment.status_request`.

Ship-readiness update: the repository now includes a root `README.md` with
build/test/run instructions, current simulation files, Ordo bridge notes, and
the Unix control-socket command surface.

Deployment control flow:

```text
Ordo typed command
  -> Imperium control socket line
  -> net.vpn.deployment.apply
  -> DeploymentOrchestrator::deploy
  -> membership/config/mesh/relay/hardening bus events
  -> net.vpn.deployment.status
```

Status query flow:

```text
Ordo typed command
  -> Imperium control socket line
  -> net.vpn.deployment.status_request
  -> DeploymentOrchestrator::subscribe_status_requests
  -> last accepted/rejected deployment status, or explicit empty status
  -> net.vpn.deployment.status
```

Protocol messages:

- `VpnDeploymentPlan`
- `VpnDeploymentNodeSpec`
- `VpnDeploymentRole`
- `VpnDeploymentStatus`
- `VpnDeploymentStatusRequest`

Control socket commands:

```text
vpn deployment apply <json>
vpn deployment status
```

Ordo commands:

- `VpnControlCommand::DeploymentApply { plan_json }`
- `VpnControlCommand::DeploymentStatus`

Ordo bridge note (historical — sibling location unverified): `ordo-device-peer/Cargo.toml` reportedly pointed at the
live `/home/jesse/Desktop/Projects/Ordo-Light-Working/ordo-protocol` and
`/home/jesse/Desktop/Projects/Ordo-Light-Working/ordo-transport` crates. The previous
`Ordo+webview+avatar` dependency path no longer exists locally and
blocked reproducible bridge checks.

What the orchestrator currently reconciles:

- Validates one operator node exists.
- Generates a cluster id if the plan does not provide one.
- Generates missing peer ids.
- Mints unique bootstrap tokens.
- Verifies and consumes bootstrap tokens.
- Requests and approves membership.
- Publishes membership grants and gossip.
- Publishes cluster config updates and fetch responses.
- Builds peer tables.
- Establishes local mesh sessions in the current node model.
- Publishes NAT probe plans.
- Selects relay fallback for client nodes when `relay_auto` is enabled.
- Applies the requested hardening preset.
- Publishes deployment status.
- Republishes the latest deployment status when Ordo/control requests it.
- Reports `accepted=false` with deployment id `00000000-0000-0000-0000-000000000000` when status is requested before any deployment has run.

Current runtime tests:

- `deployment_orchestrator_converges_plan`
- `subscribes_to_deployment_plan_messages`
- `status_request_republishes_last_status`
- `status_request_without_deployment_reports_empty_state`
- `rejects_missing_operator`

Important caveat: this is now real bus-driven orchestration, but host-level remote provisioning is still modeled locally. The next step is replacing local node/session construction with real remote agent execution through Ordo/device peers.

## Bus Topics

Important hardening topics:

```text
net.vpn.deployment.apply
net.vpn.deployment.status
net.vpn.deployment.status_request
net.transport.hardening.apply
net.transport.hardening.status
net.transport.probe_deception.decision
```

Topic pair coverage is tested in:

- `crates/imperium-runtime/tests/bus_topic_pairs.rs`

Important tests:

- `all_topic_pairs_match`
- `emergency_topics_never_use_net_prefix`
- `no_namespace_cross_contamination`

## Simulation

Implemented in:

- `crates/imperium-runtime/tests/hardening_simulation.rs`
- `crates/imperium-runtime/tests/cluster_vpn_simulation.rs`

The deterministic simulation covers:

- Default NAT strategy.
- Aggressive NAT strategy.
- Probe resistance.
- Probe deception / illusion-space routing.
- Traffic morphing.
- Padding overhead.
- Jitter.
- Cover traffic.
- FEC recovery.
- Rekeying.
- Path hopping.
- Toolkit activation.
- Orchestrator failover and recovery.

The cluster VPN simulation covers:

- Automated five-node deployment convergence.
- Three-peer cluster membership.
- Bootstrap token verification.
- Rapid bootstrap token uniqueness.
- Membership grant propagation.
- Membership gossip merge.
- Cluster config version announcement and fetch response.
- Capability checks for VPN control, hardening apply, relay, and denied shutdown.
- Mesh peer discovery.
- Mesh session establishment.
- Default NAT traversal policy.
- Relay-through-peer fallback request and selection.
- Cluster VPN hardening profile activation.
- Orchestrator failover from direct path to relay path.
- Healing back to steady state.

Current simulation tests:

- `auto_vpn_cluster_deployment_converges_all_nodes`
- `cluster_vpn_three_peer_control_and_relay_simulation_holds`
- `high_confidence_burn_triggers_hardening_toolkit_failover_and_recovery`
- `full_protocol_primitive_simulation_holds_under_burn_and_loss`
- `hardened_profile_outperforms_unhardened_baseline_under_same_faults`
- `fortress_profile_hits_perfect_simulation_targets`
- `adversarial_probe_modulation_cannot_reach_real_endpoint_without_auth`
- `adversarial_probe_modulation_is_stronger_than_baseline_gate`
- `seeded_chaos_hardening_invariants_hold_across_mixed_attack_runs`

Key simulated comparison from the deterministic model:

```text
Resilience hardened profile:
  delivered: 512 / 512
  recovered: 30
  unrecovered: 0
  unauth probes rejected: 124
  authenticated probes accepted: 4
  illusion routes / decoy responses: 32
  unauth real endpoint routes: 0
  rekeys: 2
  path hops: 1
  padding overhead: 13.34%

Baseline:
  delivered: 504 / 512
  recovered: 0
  unrecovered: 8
  unauth probes rejected: 0
  authenticated probes accepted: 128
  illusion routes: 0
  path hops: 0
  rekeys: 0
```

Fortress profile target:

```text
delivery: 100%
unrecovered loss: 0
unauth real endpoint routes: 0
illusion routes: 64
decoy responses: 64
authenticated probes accepted: 4
rekeys: >= 4
path hops: >= 1
cover traffic: enabled
padding overhead: within budget
```

## Adversarial Probe Modulation

Implemented in:

- `crates/imperium-runtime/tests/hardening_simulation.rs`

The simulation now includes a harder adversarial pass that tries multiple probe styles against the live `ProbeDeceptionEngine` and the surrounding first-packet gate model.

Current modulation strategies:

- Threshold skating: alternates just below and just above the deception confidence threshold.
- Source rotation: rotates source address/port tuples to try to avoid per-source budgets.
- Budget burn: repeats against one source until the decoy budget is exhausted.
- Invalid auth-shape attempts: sends high-confidence unauthenticated probes that are treated as failed auth attempts by the gate.
- Authenticated controls: includes a small number of authenticated probes to prove the model still permits legitimate traffic.

Expected fortress behavior:

```text
unauthenticated real endpoint routes: 0
authenticated control routes: all accepted
threshold-skating attempts: shaped, rejected, or decoyed
source-rotation attempts: decoyed but not routed to the real endpoint
budget-burn attempts: decoyed until budget, then SilentDrop
delay window violations: 0
transcript budget violations: 0
```

The baseline comparison intentionally models a profile without authenticated first-packet gating. Under the same adversarial attempt matrix, the baseline routes unauthenticated attempts to the real endpoint, while the hardened profile routes none.

## Cluster VPN Simulation

Implemented in:

- `crates/imperium-runtime/tests/cluster_vpn_simulation.rs`

This simulation keeps the cluster behavior separate from the hardening/attack simulation so both can be run independently. It models one operator node, one mobile/client node, and one relay-capable node sharing the same cluster bus.

The auto-deployment path extends this to five nodes: one operator, two clients, and two relay-capable nodes. It exercises rapid token minting, auto-approval, config convergence, capability assignment, mesh session establishment, default NAT policy, relay selection, and fortress hardening activation.

Current cluster assertions:

```text
cluster peers: 3
all peers see operator/mobile/relay membership: true
config version distributed to mobile and relay: version 1
mobile vpn.control capability: allowed
mobile vpn.hardening.apply capability: allowed
mobile vpn.shutdown capability: denied
relay vpn.relay capability: allowed
mesh sessions per node: 2 established
default NAT aggressive mode: disabled
default NAT probe count: 32
relay fallback request: published
relay fallback selection: mobile -> relay
cluster hardening profile: fortress-rf-inspired accepted
orchestrator failover: xray-direct -> masque-relay
healing result: steady
```

Current auto-deployment assertions:

```text
planned nodes: 5
approved nodes: 5
config version: 1
shutdown capability denied for all nodes: true
default NAT plans created: 5
aggressive NAT plans checked as opt-in only: 5
mesh sessions established: 20
relay fallbacks selected: 2
hardening profiles accepted: 5
```

During this test pass, rapid token minting exposed a bootstrap-token collision risk: tokens minted in the same second could produce the same signed payload. The token payload now includes a `token_id`, and `rapid_tokens_are_independently_consumable` verifies that consuming one rapidly minted token does not consume another.

This is still a deterministic simulation, not a real multi-process or multi-host run. It proves the current cluster/control/relay/hardening choreography holds through the bus and local managers.

## Seeded Chaos Hardening Test

Implemented in:

- `crates/imperium-runtime/tests/hardening_simulation.rs`

This is currently the hardest repeatable simulation test. It runs many deterministic seeds, and each seed mixes probe and transport pressure in a different order. If a future change breaks an invariant, the failing seed can be replayed.

Current chaos dimensions:

- Mixed confidence levels, including just below and just above the deception threshold.
- Source and port churn.
- Repeated-source budget exhaustion.
- Unknown-source probes.
- High-confidence unauthenticated attempts.
- Low-confidence noise attempts.
- Authenticated control probes.
- Randomized payload sizes.
- Burst and random packet loss.
- FEC recovery pressure.
- Rekey pressure from threat-like intervals.
- Path-hop pressure from modeled burn windows.

Current chaos invariants:

```text
seeds: 64
probe attempts per seed: 512
total probe attempts: 32,768
unauthenticated real endpoint routes: 0
authenticated control routes: all accepted
delay window violations: 0
transcript budget violations: 0
unrecovered user packets: 0
recovered user packets: > 0
path hops: >= seed count
rekeys: >= seed count
padding overhead: within fortress profile budget
```

## Important Caveats

The simulation is deterministic and intentionally controlled. It proves that the code paths and modeled hardening behavior hold under the current assumptions. It does not prove real-world VPN perfection.

Real-world validation still needs:

- Multi-host tests across real NAT types.
- UDP reachability tests on common home routers.
- Symmetric NAT behavior testing.
- Relay fallback testing with real peer routing.
- Packet capture inspection for fingerprints.
- Latency and throughput benchmarks.
- Long-running soak tests.
- Failure injection against actual managed protocol processes.
- Abuse checks for aggressive probing and decoy response rates.

The aggressive NAT birthday-probe mode must remain opt-in. Do not make it the default without a separate fingerprinting and abuse analysis.

The deception/illusion-space feature should stay bounded and policy-driven. Avoid creating an unbounded interactive fake service.

## Recommended Next Steps

Short-term:

- Add a CLI command that prints the active hardening profile and last hardening status.
- Add a live integration test that sends a real mesh ping through a hardening-enabled local UDP transport pair.
- Add config examples showing how external process templates consume `{{hardening.*}}` values.
- Add Ordo-side examples for fortress/resilience profile activation.

Medium-term:

- Build a two-node local harness that runs Imperium node instances and validates Ordo control against them.
- Add packet capture fixtures to compare baseline vs hardened frame shapes.
- Add budget counters and telemetry for deception decisions.
- Add rate limiting metrics for aggressive NAT mode.
- Add relay-through-peer simulation and live tests.

Long-term:

- Run real NAT traversal trials across cone NAT, restricted cone NAT, port-restricted NAT, carrier-grade NAT, and symmetric NAT.
- Evaluate MASQUE integration against real endpoints.
- Add performance profiles for balanced, resilience, and fortress modes.
- Add fuzzing for hardening profile JSON and protocol message deserialization.
- Add adversarial probe transcript tests to make sure decoys do not leak stable identifying behavior.
