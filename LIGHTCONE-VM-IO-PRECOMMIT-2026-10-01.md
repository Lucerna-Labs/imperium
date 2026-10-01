# VM input/output logging experiment — frozen 2026-10-01

User request: run Imperium/Lightcone in a VM and log what enters and leaves
to determine whether it changes delivered traffic. Source baseline is
`61a2252ac297a30c9f4b06be4fdf55b25f4819c7`; v4 world SHA-256 remains
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
The world remains immutable, passive, local_diagnostic, and unsealed.

## Boundary and controls

Reuse the private three-QEMU/KVM-guest lab with fresh overlays, pinned Ubuntu
image, private Unix-socket virtual NIC links, and serial/directory management.
No physical host firewall, routes, existing VM, or Internet test target is used.
All generated application bytes are synthetic bounded test payloads.

Run one matched healthy/quarantined Lightcone comparison with the same node
configuration, guest kernels/resources, identities, routes, case payload IDs,
and traffic counts. The only node configuration difference is the existing
`IMPERIUM_LIGHTCONE_CRASH_AFTER_FRAMES=1` drill. Warm both arms using the same
20 inert datagrams at each guest's own mesh socket. Healthy receipts must be
verified in the healthy arm; all three strands must be observed quarantined
before the quarantine arm's measured traffic. A setup failure is not blocking
evidence. Keep the native mesh runner and source/receiver applications alive.

This does not replace the Lightcone with another filter and does not treat a
receipt, a graph path or a hash as permission. It tests whether current packet
passage depends on the actual Lightcone running. It cannot establish trained
causal discrimination in a v4 pack already known to lack that relationship.

## Frozen traffic matrix per arm

- Source leaf to receiver leaf through the native mesh/TUN hub: 10 IPv4 UDP
  request/echo messages, 5 IPv4 TCP request/echo connections, and 3 ICMP echoes.
- Source to receiver directly through the hub's ordinary IP forwarding:
  10 IPv4 UDP, 10 IPv6 UDP, and 5 IPv6 TCP request/echo messages/connections.
- Hub local loopback: 3 IPv4 UDP and 3 IPv6 UDP request/echo messages.
- Capture ARP/NDP and all other packets appearing on the three guests during
  the defined measurement windows; no unsupported path is silently excluded
  from the capture. The test matrix is bounded, not all imaginable traffic.

After the matched arms, stop the native nodes and run a separate measurement
control on ordinary forwarded IPv4 UDP: 5 requests with a guest-only forward
NFQUEUE rule, no listener and no bypass. Capture ingress must show those
requests; hub egress and receiver must show zero. Remove only that guest test
table and verify 3 request/echo messages recover. This proves that the logging
boundary can distinguish delivered and blocked packets, not Lightcone benefit.

## Evidence and metrics

Start independent full-snaplen tcpdump `any` captures in every guest before
starting each arm's Imperium nodes. Save raw pcaps, capture loss counters,
interface/ifindex mappings, application transmit/receive JSONL, ping summaries,
node logs, Lightcone status before/after each case, and node/VM teardown.
Linux SLL2 packet type and guest interface maps distinguish ingress/egress.
Normalize every captured frame to a packet JSONL with timestamps, direction,
interface, protocol, addresses/ports, raw bytes, exact hashes, and synthetic
case IDs when present. Do not infer delivery from an intended send alone.

Add opt-in trace-level receipt metadata logging at the existing successful
receipt emission point: sequence, capture format, direction, observation kind,
world/query/receipt hashes. No raw payload or secret enters that log or shared
bus. Enable the same trace configuration in both arms; associate RawIp hashes
with captured IP bytes and MeshDatagram hashes with captured UDP payload bytes.
Unmatched/duplicate receipts, missing capture data and dropped capture packets
remain explicit. Receipt logging changes no world, admission, or I/O verdict.

Primary metric: per case, unique application request IDs attempted, observed
at hub ingress/egress, received by the independent server, and echoed back.
Also report duplicates, failures, packet/capture counts, receipt/hash matches,
and lifecycle/queue status. Latencies are descriptive, not a performance
benefit claim from this bounded logged experiment.

Prediction: the current runtime delivers the same bounded case messages with
healthy and quarantined Lightcone; direct/loopback paths have no raw-IP causal
receipts. The separate no-listener measurement control stops its packets.
Falsifier: a reproducible change in delivery attributable to the declared
Lightcone-only configuration difference, with functioning senders/receivers
and complete captures. Record neutral or failed outcomes without changing the
metric, inputs, or threshold after results.

## Execution bound

One complete matched pair plus one blocking/recovery control. Preserve and
repair at most two setup attempts without changing the matrix. If a further
repair or changed matrix is needed, freeze a new revision before execution.
Only owned guest processes/VMs are stopped. Retain private failed logs and
overlays; export only the synthetic non-secret measurement evidence. No seal,
world promotion, production host gate, or packet-verdict listener is installed.
