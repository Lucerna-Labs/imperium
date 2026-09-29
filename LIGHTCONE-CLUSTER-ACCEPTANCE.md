# Network Lightcone and cluster integration check — 2026-09-29

> **Filter acceptance failed.** This report measures the receipt-producing
> runtime as it existed before Jesse's 2026-09-29 correction: the network
> Lightcone is intended to filter traffic so untrained/unadmitted packets and
> activity do not pass. The runs below prove observation and cluster routing,
> not that filtering invariant. A later live adversarial probe below confirmed
> an undeclared UDP service crossed the tunnel. Do not use this report as a
> filter or seal gate.

## Active boundary

The current embedded world is `atom-network-causal-v4`, SHA-256
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
The bytes match `crates/imperium-net-world/evidence/manifest.json`. It has 208
concepts, 188 typed relationships and 48D geometry. The pack is
`local_diagnostic`, **unsealed**, and the Lightcone is passive: it admits
structural observations and emits receipts; it never authorizes or blocks.

In the running node, `MeshDaemon` offers successful outbound UDP sends and
inbound UDP receives to a bounded private queue. `HostBridge` offers IP packets
read from the TUN and packets successfully written back to it. The queue worker
parses only bounded structure, hashes the complete original bytes, and sends
structure plus hash to the supervised `imperium-net-lightcone` strand on the
typed bus. Raw TUN and UDP payload bytes do not enter the shared `BusEvent`.
The operator command `vpn lightcone status` exposes pack identity, strand
lifecycle, receipt counts by direction and frame format, observer handoff
counts, and drops/errors. A handoff publication is not itself proof of a
receipt. The older `NetworkWorldTap` in `MeshTransport` remains a separate
pre-send/pre-auth diagnostic path and is not counted by this status command.

## Whole-cluster local acceptance

Commands: `cargo build --offline -p imperium-cli` and
`scripts/mesh-multipeer-test.sh`. The script ran three real Imperium processes,
three Linux TUN interfaces and two veth underlays in isolated unprivileged
user/network namespaces. It exited **0**.
After integration, `cargo test --offline --workspace --quiet` and
`cargo fmt --all -- --check` also exited **0**. Project tests requiring a
privileged host TUN or route operation remain ignored; the namespace test
executes those operations in its isolated network namespaces instead.

- Hub established two peer sessions. Both routed ICMP paths passed 3/3; an
  unserved address stayed unreachable; both hub routes were removed on exit.
- Every node reported the v4 strand `running`, `passive=true`, `sealed=false`,
  `working=true`, zero counted observer drops and publish errors, and zero
  pending observations at the acceptance snapshot.

| Node | Raw IP inbound/outbound receipts | Mesh UDP inbound/outbound receipts | Structures published | Drops |
|---|---:|---:|---:|---:|
| Hub | 20 / 13 | 42 / 50 | 125 | 0 |
| Leaf B | 3 / 10 | 25 / 21 | 59 | 0 |
| Leaf C | 3 / 10 | 25 / 21 | 59 | 0 |

The separate `lightcone_live_bus` test uses real UDP Hello/cookie traffic and
the real supervised strand. It checks frame direction, format, structural
seeds, exact original-byte query hash and receipt delivery; a failed UDP send
produces no outbound observation.

## Adversarial forwarding probe

`IMPERIUM_FILTER_PROBE=1 scripts/mesh-multipeer-test.sh` ran the same
three-process namespace topology with a UDP listener on leaf B's port 45999.
No host service policy was configured or present in this scratch build. A
datagram from the hub arrived at that listener. The script printed
`FILTER NOT WORKING: undeclared UDP service crossed the tunnel`. The
diagnostic script was then changed to exit on that failure; its repeat run
returned **1** with `Lightcone filter: FAILED` while routing, receipt, and
teardown subchecks passed. At the snapshot, all three nodes
reported healthy v4 passive receipts and zero observer drops. This directly
separates receipt health from packet/flow enforcement.

The matched packet tests in `crates/imperium-net-lightcone/tests/filter_feasibility.rs`
show valid UDP packets with different destinations and ports, and valid TCP
ACKs with different sequence values, produce the same v4 graph neighborhood.
An exhaustive traversal of positive edges in the current pack found no path
from packet structure to `authorized_flow`. The bounded 32-node and 256-node
receipt comparisons and exact limits are recorded in
`LIGHTCONE-FILTER-PRECOMMIT.md`. No forwarding gate was promoted from these
failed conditions.

## Failure drill

An isolated node started with `IMPERIUM_LIGHTCONE_CRASH_AFTER_FRAMES=1` and a
bound loopback mesh UDP socket. After twenty inert local datagrams, its
Lightcone strand was `quarantined`; `vpn lightcone status` returned
`status=degraded`, `working=false`, four retained receipts and twenty published
structures. The mesh runner remained active and the node shut down cleanly on
operator command. This proves the current status surface exposes the tested
quarantine. It also records the current policy: observation failure does not
automatically stop VPN traffic.

A separate isolated node used `IMPERIUM_LIGHTCONE_STALL_AFTER_FRAMES=1`. During
the bounded stall, additional inert UDP datagrams left 26 published
observations pending while the strand lifecycle still read `running`.
`vpn lightcone status` returned `status=incomplete`, `working=false` and one
receipt; clean operator shutdown exited 0. A living but non-advancing observer
therefore did not retain a stale healthy status during this drill.

## Claim limits and next decision

These are native local computations and isolated network-namespace runs, not
multi-host deployment evidence. The Lightcone does not detect every attack or
provide a firewall, host DNS guard, authorization verdict, or physical/network
seal. `working=true` means the specified local counters and lifecycle were
healthy at that snapshot; bounded queues can drop under other loads, and
replayed receipts after a strand restart can exceed unique wire events. The
historical v3 RTX integration receipt is not a current v4 seal receipt.

No sealing action was performed. Any seal decision should follow a frozen
whole-cluster protocol with negative/unknown controls, sustained load/drop
measurements, source/pack provenance, and explicit acceptance gates. A separate
host-owned policy decision is needed if the VPN must stop when the passive
observer becomes unavailable.
