# Isolated VM baseline outcome — 2026-09-30

**The current v4 filtering requirement failed in real VMs.** The native
Imperium cluster delivered the tagged undeclared UDP packet to the receiving
guest. Receipt integration and the independent kernel-interception controls
worked; neither establishes useful causal filtering.

## Exact tested boundary

Frozen contract: `LIGHTCONE-VM-PRECOMMIT.md`, committed before implementation.
Completed run: `target/lightcone-vm/runs/20260930-144758/`.
Test source HEAD at run start: `19becb5` (clean).
Native executable SHA-256:
`ac807edb4d201830c06485f7ce9dcd0aeefaf32f5d0c5b49db27286565b5e8ea`.
Unchanged v4 pack:
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.

Three fresh Ubuntu 24.04.5 guests ran kernel `6.8.0-142-generic` under QEMU
8.2.2. QMP independently returned `enabled=true,present=true` for KVM on all
three guests. The official 20260926 image SHA-256 is
`6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2`.
The hub has two Unix-socket virtual Ethernet links; source and receiver have
one each. No NAT/user/TAP/physical bridge backend is in the saved commands.
The guest command/evidence channels use directory shares and serial/QMP.
Every nft/IP command in the experiment ran inside a guest; no real-host
network configuration or existing VM was used. All three owned VMs shut down.

## Measurements

| Control | Eight paths: IPv4/IPv6 input, output, forward, loopback | Receiver echo requests |
| --- | --- | ---: |
| Baseline, no queue rules | Each delivered 3/3 | 12 |
| Guest NFQUEUE rules, no listener, no bypass | Each delivered 0/3; pings returned the expected non-delivery status | 0 |
| Remove only the guest test table | Each delivered 3/3 | 12 |

Source and receiver local liveness probes passed during the blocked phase.
All six family/hook counters advanced: input v4/v6 3/3, output 14/8,
forward 3/3. Independent receiver pcaps are included in the exported evidence.
These are IP no-listener controls; ARP remains necessary for the virtual links,
and link-layer filtering has not been demonstrated.

Native mesh: the hub established both peers; both routed leaf ICMP paths passed
3/3; hub peer routes were removed after owned process shutdown. The receiving
guest bound UDP port 45999 on 10.99.0.1. It received the exact synthetic payload
`imperium-vm-untrained-flow` from 10.77.0.1. The independent pcap includes that
26-byte UDP packet at the receiving boundary.

| Node | Raw IP rx/tx receipts | Mesh rx/tx receipts | Pending/dropped/publish errors |
| --- | ---: | ---: | --- |
| Hub | 18/11 | 40/51 | 0/0/0 |
| Source leaf | 3/9 | 25/20 | 0/0/0 |
| Receiver leaf | 4/9 | 26/20 | 0/0/0 |

Every runtime status reports the exact v4 pack hash, passive=true,
holds_verdict=false, local_diagnostic, sealed=false and filter_enforced=false.
An independent report audit checked those fields after the complete run.
The initial harness exit was 0 for successful operational controls despite the
separate filter failure. The wrapper is corrected to exit 3 on observed
undeclared passage, 2 on inconclusive non-arrival, and 1 on setup/control
failure; it does not produce a green filtering result.

## Preserved setup failures

Four earlier runs stopped before completing the declared matrix. Their private
logs and overlays are retained: 143740 (tcpdump tried to chown a savefile on the
shared filesystem), 143858 (incorrect raw key fixture instead of native JSON),
144152 (ANSI log escapes hid the already-established peer count), and 144519
(an stdin redirect overrode the receiver's Python heredoc). These harness
errors were repaired without changing the traffic matrix. The 143858, 144152,
and 144519 kernel controls passed, but their unrun filter probe is not a
filtering result. Exactly one full matrix completed; no failed attempt was
relabeled as passing.

## Evidence and remaining work

Small non-secret evidence is committed under
`evidence/lightcone-vm-20260930-phase1/`: report, image/source/binary/world
manifest, exact guest commands, guest identities, receiver pcaps, receiver
payload record, and SHA-256 evidence manifest. Private guest keys, disks and
full logs remain under the owner-only local run directory and are not exported.

The guest-only accept/drop/hold Rust NFQUEUE fixture was rejected by automatic
approval review because the current command did not explicitly authorize its
packet-verdict capability. No proposed listener source/dependency/marker
change executed. `LIGHTCONE-VM-QUEUE-PRECOMMIT.md` freezes the next controls;
explicit VM-only listener authorization is pending. Those controls are unrun.

The v4 world is still unsealed. A useful causal release criterion, new valid
training evidence, synchronous forwarding, positive/negative delivery,
restart persistence, queue overload/crash behavior, non-IP/namespace/offload
coverage and eventual physical-host tests remain open. No production filtering
or all-traffic security claim follows from this VM baseline.
