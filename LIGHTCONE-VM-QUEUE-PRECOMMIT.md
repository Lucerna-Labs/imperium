# VM queue transport controls — frozen 2026-09-30

This phase follows the unchanged phase-1 contract. It tests a conventional
Linux packet handoff in the private QEMU lab, not an Atom stack or a trained
Lightcone release rule. No world, production node path, host firewall, or seal
changes. The user authorized continuing the isolated VM plan in this session.
Automatic approval review requires a separate explicit authorization for the
packet-verdict listener; that request is pending with the user.

Implement a test-only Rust example beside `imperium-net-host`, using the
installed Linux NETLINK_NETFILTER UAPI and existing libc dependency. Refuse
execution unless effective UID is root, DMI identifies QEMU, and the VM agent
created `/run/imperium-vm-lab`. Bind only queue 42777. Leave fail-open disabled,
bound the kernel queue to 64 packets, copy complete supported IP packets, and
validate every netlink length/attribute, queue ID, packet ID, and capture size.
Malformed/incomplete metadata stops the fixture and closes its queue socket;
no implicit accept exists. Record family, hook, interface indexes, packet IDs,
payload size and hash. Accept-all, drop-all and hold-without-verdict are
mechanical controls only; none is a causal Lightcone criterion.

Freeze at most two complete runs of this matrix; setup repairs remain recorded.
Every declared traffic control is measured at independent source/receiver
boundaries across the same eight IPv4/IPv6 input/output/forward/loopback paths:

1. Warm and verify delivery before guest rules. Install guest-only queue rules
   without bypass before a listener. The no-listener matrix must block.
2. Start accept-all fixture; all paths deliver, both families and all three
   hooks yield complete packet records, and the receiver capture agrees.
3. Close the fixture while retaining rules; all paths block.
4. Start drop-all fixture; every path blocks while its record counts advance.
5. Kill an accept-all fixture with SIGKILL; rules remain and all paths block.
6. Start the hold fixture and send 256 tagged UDP datagrams through forwarding.
   Kernel queue depth reaches 64 and drop count increases. The live receiving
   socket and independent capture must see zero tagged datagrams. Closing the
   fixture must not release its held packets.
7. Delete only the guest test table; the eight-path delivery matrix recovers.

Parser gates: valid packet metadata/payload retained exactly; malformed and
truncated netlink/attribute lengths, missing/duplicate packet ID or payload,
wrong queue, wrong message/version/family, oversized/truncated captures and
invalid hook rejected. The host invocation itself must be refused. Run focused
example parser tests and build before guest execution.

Evidence includes source/binary/world/image hashes, KVM status, guest kernels,
exact commands, receiver captures, fixture logs, queue counters and failures.
Success establishes packet hold/accept/drop transport and bounded failure
behavior only. Reboot persistence, complete link-layer/offload/namespace
coverage, condition-sensitive world benefit and useful causal forwarding are
separate mandatory gates. Lightcone remains unsealed and filter_enforced=false.

Primary references: installed `linux/netfilter/nfnetlink_queue.h` and
`linux/netfilter/nfnetlink.h`; Netfilter's queue API documentation at
https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html
(copy mode, capture truncation, queue capacity, and fail-open semantics).

## Execution status

The proposed guest-guarded example source edit was rejected by automatic
approval review on 2026-09-30 as an unauthorised destructive packet accept/drop
capability under the current command. The patch did not execute; no example,
dependency change, guest marker, or verdict listener was installed. Phase 2
is unrun. Phase 1's existing no-listener guest controls continue independently.
