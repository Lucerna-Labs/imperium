# Imperium follow-up work

## Security review follow-up

- [x] Reject duplicate mesh session IDs and hold both peer/session indexes
  under one ownership check. Add matching send-time checks and concurrent
  regressions. The before/after in-memory probe, full mesh tests and isolated
  three-node routing run are recorded in `SESSION-OWNERSHIP-FIX-2026-09-30.md`.
- [ ] Preserve the separate S1 on-wire adversarial receiver acceptance as an
  unrun gate; automatic cybersecurity review rejected that live packet attack
  reproduction. Do not label the map fix as a measured plaintext-leak test.
- [ ] Repair replayed Hello session replacement, issuer-key distribution,
  inbound pin/source checks and the other prioritized security findings in
  `ADVERSARIAL-REVIEW-2026-09-30.md`. Keep their evidence limits explicit.

Status at the 2026-09-29 stopping checkpoint. This is a work list, not a
release or seal claim. The current v4 network Lightcone is passive and
diagnostic; `vpn lightcone status` reports `filter_enforced: false`.

## Decisions needed before a release rule can be frozen

- [ ] Confirm whether **all traffic** means every host network path, including
  direct applications, inbound and forwarded packets, mesh underlay, link
  traffic, other network namespaces, and local loopback. The working safety
  assumption is host-wide coverage; loopback and namespace handling still
  need an explicit answer.
- [ ] Decide whether an unseen endpoint/service can pass when its protocol and
  flow behavior match training, or whether that exact endpoint/service must
  be represented and approved. Standards cannot supply this host's policy.
- [ ] Define the trusted host/operator boundary, managed interfaces and
  namespaces, and what privileged `CAP_NET_ADMIN` / `CAP_NET_RAW` processes
  may do. An absolute guarantee against a hostile host administrator or
  uncontrolled hardware path is not a software test claim.

## P0 — Lightcone training and causal evidence

- [ ] Preserve the v4 failure and v5 diagnostic history. Diagnostic-2 failed
  its frozen comparison and mistakenly fitted negative edges as positive;
  diagnostic-3 was rejected before training and diagnostic-4 was blocked
  before training. Do not promote or relabel those artifacts.
- [ ] Extend the revision-5 typed condition catalog beyond its current **IPv4
  offline** slice. Add packet-bound, source-checked fact producers for IPv6,
  mesh authentication/replay, direct-host socket identity, forwarded traffic,
  ARP/NDP/DHCP, fragments/reassembly, and other supported network mechanisms.
  Keep every unknown or unsupported form explicit. The separate
  `ipv6_flow_evidence` Rust test now covers supported IPv6 parser/tracker
  behavior, but the condition catalog and trained pack do not yet include it.
- [ ] Obtain versioned host policy facts for services, endpoints, zones,
  direction, process/peer identity, freshness, and flow state. Bind each fact
  to the exact packet, network namespace, interface, policy revision, and
  producer. A parser success, graph path, or receipt alone is not permission.
- [ ] Verify source sections for existence **and** claim relevance. Preserve
  source rights, original factual paraphrases, negative/unknown controls,
  mechanism-level splits, and the original v4 source/provenance gap. The
  revision-5 checker verifies five pinned RFC section anchors; that is not a
  complete world audit.
- [ ] Freeze a new condition-aware, polarity-aware 48D training protocol and
  fresh held-out mechanisms before running it. Fit positive relations only
  when their typed conditions are true; keep negative relations separate;
  test missing/stale facts as unknown. Compare text-only, shuffled,
  polarity-only, and condition-aware controls, with a cold-node test. Keep the
  `(x,y,z,w)` projection observer-only. Report every failed metric without
  moving thresholds after evaluation.
- [ ] Build and load a **new** immutable pack only after source, graph,
  geometry, rights, split, negative, unknown, and provenance gates pass. The
  current 256-node/512-edge runtime cap leaves only 48 additional node slots
  beside v4; plan a versioned larger pack/runtime for wider networking
  coverage. Never call a finite open-world registry "everything imaginable".

## P0 — all-traffic enforcement and actual delivery tests

- [x] Implement the owned Rust NFQUEUE kernel transport and verify exact
  release/discard, no-listener, reader-exit and recovery controls for IPv4
  and IPv6 in a private user/network namespace. See
  `LIGHTCONE-QUEUE-TRANSPORT-OUTCOME-2026-10-01.md`. There is no production
  causal release caller yet; this is not functional-filter acceptance.

- [x] Log actual VM ingress/egress, application bytes and Lightcone query
  receipts with a matched healthy/quarantined comparison. The accepted run
  delivered 49/49 probes in both arms, matched 918 healthy receipts to captured
  hashes/direction, and passed an independent 5-in/0-out block control plus
  3-in/3-out recovery with zero capture loss. This proves the current causal
  gate is unenforced in the tested matrix; see
  `LIGHTCONE-VM-IO-OUTCOME-2026-10-01.md` and its raw evidence directory.

- [x] Establish an isolated three-QEMU/KVM-guest baseline with independent
  receiver captures. The eight IPv4/IPv6 input/output/forward/loopback paths
  passed baseline, no-listener blocking, and recovery controls. Native cluster
  receipts passed, but the undeclared UDP flow arrived: filter acceptance
  failed. See `LIGHTCONE-VM-OUTCOME.md` and `scripts/lightcone-vm-test.sh`.
- [ ] Run the guest-only accept/drop/hold/crash/overflow matrix frozen in
  `LIGHTCONE-VM-QUEUE-PRECOMMIT.md`. Automatic approval review rejected the
  listener source edit; explicit VM-only packet-verdict authorization is
  pending. No listener or causal release gate exists yet.

- [ ] Implement a bounded userspace packet-verdict service and atomically
  installed kernel hooks. The isolated
  `scripts/lightcone-nfqueue-boundary-test.sh` verifies that IPv4/IPv6
  input/output/forward/loopback queues **drop without a listener** and recover
  after cleanup; it does not implement a Lightcone verdict. Omit NFQUEUE
  `bypass` and fail-open. Verify queue binding, overload, crash, startup,
  shutdown, and recovery without an open interval. Automatic approval review
  rejected a packet-verdict listener implementation because its accept/drop
  capability was not explicitly authorized; namespace-only authorization is
  pending, and no real-host rules were changed.
- [ ] Cover non-IP/link and bypass paths separately: ARP, bridge and netdev
  ingress/egress, raw and packet sockets, offload, interface hotplug, and
  every managed network namespace. Prove each path at its actual kernel or
  receiver boundary before claiming all-host coverage.
- [ ] Gate the Imperium mesh underlay, handshake, NAT probes, cover frames,
  inner TUN send, and inbound TUN write **synchronously before I/O**. Today
  the bounded observer queue is post-I/O telemetry; loss of its events does
  not stop traffic. Authenticated peer/session and replay facts must be
  checked at the owner boundary.
- [ ] Wire the host-owned flow policy and flow-behavior tracker to the verified
  trained world and packet-bound facts. They currently have no forwarding
  call site. Do not treat a reverse tuple, a suspicious TCP `FlowFact`, an
  embedding neighbor, or backward traversal of a prerequisite edge as a
  release condition. A denied packet must not update flow state.
- [ ] Run an isolated multi-node positive/negative matrix: declared traffic
  delivered in both directions; matched undeclared or unsupported traffic,
  orphan/out-of-window flows, malformed packets, fragments without valid
  reassembly, invalid mesh sessions, queue loss, stalled Lightcone, and
  missing policy **not delivered**. Measure false passes, false rejects,
  latency, capacity, and actual receiver results. Then repeat on the intended
  host boundary before any real-host enablement or seal decision.

## P1 — other operational features and UX

- [ ] Complete and test live aggressive NAT peer probes only after a
  synchronous Lightcone gate exists. Current bounded socket/STUN groundwork
  sends no peer probe packet and promotes no authenticated winner.
- [ ] Supply and test real Xray and AmneziaWG binaries, configs, activation,
  deactivation, health, and active-path probes. Current rotate/set-active
  control is verified with test-only process fixtures, not real backend
  traffic. Keep incumbent routing on failed transitions.
- [ ] Decide whether the opt-in host guard should remain explicit-Engage-only
  (the currently approved behavior). Its namespace packet test proved
  Armed pass, Engaged non-loopback block, and Disarmed recovery; it is a
  manual kill switch, not an all-traffic Lightcone filter.
- [ ] Continue GUI usability checks on live configured states: host guard
  initial status, no-mesh/no-guard controls, keyboard and scaling behavior,
  transport errors, and screen-reader/contrast accessibility. Dashboard and
  Transport were visually checked at 960×640 and 1360×852 only.
- [ ] Re-run `cargo fmt --all -- --check`,
  `cargo test --offline --workspace --quiet`, the condition-evidence tests,
  the guarded NFQUEUE namespace probe, and a fresh three-node delivery test
  after any enforcement changes. The current full Rust suite and formatting
  passed; the live v4 filter negative control deliberately failed.

## Recovery and release hygiene

- [ ] Keep `filter_enforced: false` and the GUI's `FILTER NOT ENFORCED` warning
  until the real gate and full traffic matrix pass. Do not seal the world or
  describe receipt health as filtering.
- [ ] Resolve the older private test directory
  `/tmp/imperium-multipeer-test.ehyGzU` (mode 0700, generated test material).
  Automatic approval review rejected its deletion because destructive cleanup
  was not expressly authorized; preserve it until that authorization exists.
- [ ] Recheck the exact committed source, lockfile, v4/v5 evidence hashes,
  ignored build output, and recovery backups before distribution. No host-wide
  filter or Xray/AmneziaWG runtime deployment has been accepted.

Evidence and detailed limits: `LIGHTCONE-FILTER-PRECOMMIT.md`,
`NETWORK-LIGHTCONE-V5-CONTRACT.md`,
`ALL-TRAFFIC-LIGHTCONE-BOUNDARY.md`,
`crates/imperium-net-world/v5/revision-4/BLOCKED-PRETRAINING.md`, and
`crates/imperium-net-world/v5/revision-5/PROTOCOL.md`.
