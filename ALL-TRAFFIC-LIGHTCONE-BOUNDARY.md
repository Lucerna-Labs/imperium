# All-traffic network Lightcone boundary — 2026-09-29

## Status and meaning

The requested scope is **all Linux host network traffic**, not only packets
routed through Imperium's TUN or mesh. It covers IPv4, IPv6, incoming and
forwarded packets, the encrypted mesh underlay, DNS, ARP, neighbor discovery,
and non-IP link frames on managed interfaces. Under a literal all-traffic
interpretation, local loopback is included; final production handling of
loopback is pending the user's answer to a separate clarification. The
passive Lightcone may return causal geometry and a receipt; an **outer**
network boundary must hold each packet until that evidence supports passage.
Unknown, unsupported, stale, malformed, or unexamined activity must not pass.

**This is not implemented.** The active Lightcone status explicitly reports
`filter_enforced=false` and `filter_mode=diagnostic_only`
(`crates/imperium-cli/src/control.rs:949-956`). The v4 world cannot
distinguish matched endpoint/port or TCP sequence variants and has no
packet-to-`authorized_flow` causal path; see
`LIGHTCONE-FILTER-PRECOMMIT.md`. A nonempty receipt is not a release
condition. The namespace test below establishes only a possible Linux kernel
interception point, with **no Lightcone listener or verdict**.

## Current paths and missing enforcement

| Traffic path | Current Imperium path | Required pre-release coverage |
| --- | --- | --- |
| Ordinary app IPv4/IPv6 egress, including DNS over UDP/TCP/encrypted transport | Split routes only; default route is refused (`imperium-cli/src/main.rs:352-360`). Optional host guard allows packets in Armed/Disarmed and drops non-loopback egress only on explicit Engage (`imperium-net-host/src/firewall.rs:94-143`). | Host namespace `inet output` kernel queue before transmission, plus a trained causal flow relation for the actual packet. Encrypted DNS content cannot be inferred from its IP headers. |
| Incoming IPv4/IPv6 addressed to local apps | Mesh daemon reads only its own UDP socket. No Lightcone gate on other services. | `inet input` and per-device ingress coverage before local delivery. |
| Forwarded/NAT IPv4/IPv6 | The opt-in kill switch has an `inet postrouting` drop only when Engaged. There is no causal `forward` gate. | `inet forward` with original and translated flow context; verify against NAT, bridge, and flow-offload paths. Do not rely on NAT chains for filtering because only the first flow packet traverses them. |
| Mesh UDP underlay, handshake and NAT probes | Mesh observations are queued **after** `send_to` and after `recv_from`, before daemon parsing (`imperium-net-mesh/src/daemon.rs:589-608,940-949`). Queue failure only loses telemetry. | Kernel input/output interception and a synchronous daemon boundary before `send_to` / authenticated dispatch. Handshake bootstrap must have its own trained causal relationship; no assumed exception. |
| Inner TUN IPv4/IPv6 | HostBridge observes before sending to mesh but ignores queue failure; it observes inbound only **after** TUN write (`imperium-net-host/src/bridge.rs:218-225,318-322`). The TUN is IPv4-addressed and split routed. | Synchronous gate before mesh send and before TUN write, with kernel hooks as independent coverage. Include valid flow progression and peer/session context. |
| ARP and other non-IP Ethernet frames | Host guard has only ARP `output` blocking on Engage. `inet` hooks do not see ARP/non-IP frames. | Per-device `netdev ingress/egress`, relevant `arp input/output`, and `bridge` hooks, all verified on each managed interface. Their NFQUEUE behavior has **not** been tested here. |
| IPv6 neighbor discovery and local loopback | NDP is ICMPv6 but lacks a release gate. Host kill switch explicitly exempts `lo`. | Train and test NDP's causal path. Under literal all-traffic scope, loopback IPv4/IPv6 also crosses `inet output/input`; the final production choice is pending user clarification. Keep recovery control on a non-IP local socket. |
| Containers and other network namespaces | Current nft tables live only in the namespace in which installed; TUN observation covers only its tunnel. | Inventory every namespace and interface, install/verify gates before networking becomes usable, and block creation or attachment of an uninstrumented path. Host-side veth traffic does not prove coverage of a container's internal loopback. |
| Raw/packet sockets, kernel bypass and NIC offload | No inventory or acceptance evidence. | Probe `AF_INET` raw sockets, `AF_PACKET` transmit/receive, flowtable or hardware offload, XDP/AF_XDP, virtual functions, and any userspace NIC driver. Restrict `CAP_NET_RAW` and `CAP_NET_ADMIN` to trusted operators. Treat any path that evades the chosen hooks as unsupported and blocked. |

The [nftables hook reference](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
defines input, output, forward, ingress and postrouting. The
[family reference](https://wiki.nftables.org/wiki-nftables/index.php/Nftables_families)
separates IPv4/IPv6 `inet`, ARP, bridge, and per-device `netdev` traffic.
[TUN/TAP documentation](https://docs.kernel.org/networking/tuntap.html)
distinguishes TUN's IP packets from TAP's Ethernet frames. The
[packet-socket manual](https://man7.org/linux/man-pages/man7/packet.7.html)
documents device-level `AF_PACKET` access, and
[AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html)
describes another user-space packet path. These are reasons to test those
boundaries, not evidence that the present program controls them.

## Tested, isolated NFQUEUE feasibility

`scripts/lightcone-nfqueue-boundary-test.sh` is a reproducible kernel-only
probe. It refuses a root invocation, creates a mapped-root user namespace and
a private network namespace with `unshare -Urn`, verifies that namespace
before using nft, connects two further namespaces by veth, and creates a
unique `inet` table and queue. Its rules have this exact shape for
`input`, `output`, and `forward`, in both IPv4 and IPv6:

```sh
nft "add chain inet $table $hook { type filter hook $hook priority 0; policy accept; }"
nft "add rule inet $table $hook meta nfproto ipv4 counter queue num $queue_no"
nft "add rule inet $table $hook meta nfproto ipv6 counter queue num $queue_no"
```

The rules deliberately omit `bypass`; no queue listener runs. The
[nftables queue guide](https://wiki.nftables.org/wiki-nftables/index.php/Queueing_to_userspace)
says packets are dropped when no application listens unless `bypass` is
specified. The [Netfilter queue API](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html)
also identifies `NFQA_CFG_F_FAIL_OPEN`; a fail-closed implementation must
leave that flag disabled and return a verdict for every queued packet.

Run on kernel `7.1.5-76070105-generic`, nft `1.0.9`:

```sh
scripts/lightcone-nfqueue-boundary-test.sh
```

The script exited **0**. IPv4 and IPv6 output, input, forwarding, and
loopback ping baselines all passed; the same eight paths were blocked with
no queue listener; IPv4/IPv6 output and forwarding recovered after deleting
the table. All six queue rules recorded packets: input v4/v6 `2/7`,
output `3/3`, forward `2/2`. An earlier single-packet IPv6 forwarding
baseline timed out during neighbor discovery, so a warmed, three-packet
baseline was used; a separate repeat showed IPv6 forward baseline PASS,
no-listener BLOCKED, and recovery PASS. Tables and namespace processes were
removed by the script's trap. No real host firewall, route, or interface was
changed. This does not test a queue listener, causal admission, positive
release, performance, ARP, or kernel-bypass paths.

## Fail-closed deployment contract and acceptance gate

1. Before enabling network interfaces or forwarding in **each** managed
   namespace, verify the exact immutable world revision, its mechanism-level
   positive and negative coverage, parser and flow-state version, queue
   listener, kernel features, device inventory, and installed ruleset. A
   missing piece leaves the network blocked. The current v4 pack fails the
   causal flow criterion, so this deployment gate cannot pass today.
2. Keep packet bytes inside the trusted gate. Parse typed network structure
   and bounded flow activity; query the passive Lightcone synchronously.
   Only the outer boundary may issue `accept` after checking the exact
   causal relation to training. Every error, zero-seed/empty receipt,
   unsupported protocol, queue overflow, absent listener, timeout, crashed
   strand, or stale world returns `drop`. Never add nft `bypass` or NFQUEUE
   fail-open, and do not infer permission from a hash, graph proximity, or
   receipt count.
3. On crash or planned shutdown, retain a kernel block while network
   interfaces remain usable. The existing opt-in `HostKillSwitch` removes
   its tables in `Drop` (`imperium-net-host/src/firewall.rs:146-150`), so
   it is a distinct manual kill switch, not this lifecycle. Recovery must
   inspect the exact owned table/queue, world and gate health, then require
   an explicit operator action before removing the block. Startup and
   recovery must not create an open interval.
4. Before reporting `filter_enforced=true`, prove positive delivery and
   negative non-delivery at the real receiving boundary across IPv4/IPv6
   TCP, UDP, ICMP, DNS transports, mesh handshake/data, TUN, ARP/NDP,
   loopback under the selected scope, ingress, forwarding/NAT, bridge, namespace creation, raw/packet
   sockets, fragmentation, offload, device hotplug, and queue crash/overload.
   Compare same-shaped allowed and untrained flows. Recheck counters, queue
   binding, packet/flow receipts, and actual on-wire observations after every
   restart; preserve failed cases. The test here is only an early kernel
   interception prerequisite.

Even a complete kernel-hook implementation cannot be an absolute guarantee
against processes with `CAP_NET_ADMIN` that can remove the rules, alternate
network namespaces/interfaces, driver or hardware paths that bypass those
hooks, or packets transmitted before the gate starts. An all-traffic claim
must state the exact trusted host, interfaces, namespaces, privileges and
boot interval verified. It cannot mean every imaginable network mechanism
without evidence for each one.
