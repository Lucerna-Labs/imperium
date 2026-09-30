# Isolated VM Lightcone experiment — 2026-09-30

## Frozen scope

Source baseline: `cd36665425aa7448e95a105d718b34909488f805`.
Active v4 world SHA-256:
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
Keep that world immutable and unsealed. No real-host firewall, interface,
route, existing VM, or sibling project is part of this experiment.

Boot three fresh Ubuntu 24.04 guests with QEMU/KVM. A dual-interface hub/DUT
connects a source and receiver through two private Unix-socket Ethernet
backends. No guest has a NAT/user/physical bridge network backend. Management
and evidence use serial/QMP and dedicated directory shares, outside IP.
Pin the official guest image SHA-256 before boot, record the guest kernels,
QEMU identity, KVM enabled state, commands, source/binary/world hashes, and
independent receiver/capture evidence. Use disposable disk overlays and retain
failed logs. Host tools and the native Imperium executable are copied into a
read-only guest share; no app-package changes are required on the host.

## Bounded phase 1 matrix

Allow at most two complete executions of the unchanged phase-1 matrix.
Boot/setup failures may be repaired and recorded; they are not traffic results.
If the matrix changes, freeze a new revision before executing it.

1. **Measurement baseline:** guest source-to-hub input, hub-to-receiver output,
   source-to-receiver forwarding, and hub loopback all deliver IPv4 and IPv6
   probes. Receiver logs and packet capture must agree. Warm neighbor discovery
   before bounded measurements and keep ARP/NDP outside the IP-only control.
2. **Kernel no-listener control:** install unique guest-only inet NFQUEUE
   input/output/forward rules, without bypass or fail-open, in the hub. All
   eight baseline IP paths must stop while the source and receiver stay alive.
   Counters must show each family/hook was exercised. This is an interception
   control, not Lightcone filtering. Keep serial/directory control available.
3. **Recovery control:** remove only that guest test table; all baseline paths
   deliver again. No real-host rule is changed.
4. **Current Imperium baseline:** run the actual native three-node mesh/TUN
   cluster across the guests with an ephemeral shared operator key. Establish
   both hub peers and verify routed ICMP and bidirectional raw-IP/mesh receipts.
   Send a tagged undeclared UDP flow and inspect the receiving guest, not only
   the status bus. Prediction: it crosses because the current forwarding gate
   is absent. This observed passage is a recorded filter failure.
5. **Lifecycle accounting:** terminate only owned guest processes; record
   routes and statuses. Shut down the three owned VMs and retain overlays,
   serial logs, captures, commands, and the machine-readable report.

Hard invariants: private guest links only; zero host network mutations; no
world/training/seal changes; no receipt count presented as packet permission;
no synthetic allowlist represented as causal learning; every failed or unrun
check remains explicit. A stopped source/receiver or absent baseline cannot
count as successful blocking.

## Subsequent phases

After phase 1, separately freeze bounded accept/drop queue-transport controls,
crash/overflow/startup/restart tests, then causal-world positive/negative
release experiments. An accept-all or drop-all fixture is a labeled mechanical
control only. It may not become the production Lightcone criterion. The current
v4 graph lacks grounded packet-to-flow reachability, so a useful filtering
claim requires new condition-sensitive world evidence plus a synchronous
packet boundary. ARP/NDP/link frames, raw sockets, additional namespaces,
offload, hotplug, fragments, and physical-host coverage remain open until their
actual boundaries are measured. No finite VM run proves every imaginable path.
