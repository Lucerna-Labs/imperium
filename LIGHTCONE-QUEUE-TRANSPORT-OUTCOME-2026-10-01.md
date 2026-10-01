# Kernel-held packet transport result — 2026-10-01

The Rust NFQUEUE packet transport is implemented and its isolated kernel
controls passed. **This is not yet a functional geometric traffic filter.**
No world was trained/promoted, no mesh forwarding call was changed, and
Lightcone remains passive, unsealed and diagnostic. The endpoint/service
world-scope question is pending with Jesse; inventing that relationship would
change his requested architecture.

## Actual code and runtime

`imperium-net-host::PacketQueue` binds one owned NETLINK_NETFILTER queue,
requests full packet copies and a bounded kernel capacity, and explicitly
clears FAIL_OPEN. The codec retains exact packet bytes and kernel metadata;
malformed messages, missing IDs/payload, duplicate attributes, capture
truncation, wrong queue/family and non-kernel senders cannot yield an accepted
packet. Held packets belong to one reader instance and are consumed once.
The low-level OS disposition operation makes no causal judgment.

No production caller uses this operation to release traffic. The
`queue_lab` example is only a mechanical control and refuses execution
without its explicit lab marker and separate user/network namespaces.
The wrapper installs and removes its unique table inside `unshare -Urn`;
no real-host firewall, route, interface or existing VM was changed.

Command: `scripts/lightcone-queue-transport-test.sh`.
Accepted source/binary hashes and original private run location are bound in
`evidence/lightcone-queue-transport-20261001/result.json`.

| Control | IPv4 replies / 2 | IPv6 replies / 2 |
| --- | ---: | ---: |
| Before rule installation | 2 | 2 |
| Queue rule, no reader | 0 | 0 |
| Reader explicitly releases each held packet | 2 | 2 |
| Release reader exits, queue rule retained | 0 | 0 |
| Reader explicitly discards each held packet | 0 | 0 |
| Discard reader exits, queue rule retained | 0 | 0 |
| Remove only the owned test table | 2 | 2 |

The release reader logged eight held packets (request/reply for both
families); the discard reader logged four requests. All control logs and
the final rules/counters are retained with hashes. A preceding run passed
the same controls before the reader-instance ownership guard was added;
the accepted exported run includes that guard.

Verification: three adversarial codec tests passed; the complete host crate
test command passed 17 tests with two existing privileged unit tests and two
existing integration tests ignored. Bash syntax and full workspace formatting
passed. These results do not test Lightcone geometry, trained flow conditions,
all interfaces/namespaces, L2/ARP/bridge interception, checksum/offload
normalization, native mesh/TUN passage or the final three-VM filter matrix.
Those remain required work for the functional filter.

The UAPI was checked against local Linux headers and the
[Linux NFQUEUE header](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/netfilter/nfnetlink_queue.h).
The fail-open, truncation and checksum metadata behavior was checked against
[Netfilter's queue documentation](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html).
The rule intentionally has no bypass, consistent with the
[nftables queue documentation](https://wiki.nftables.org/wiki-nftables/index.php/Queueing_to_userspace).

## Next dependent work

Freeze the endpoint/service relationship semantics, compile/train a fresh
condition-sensitive immutable world, and connect its admitted structure to
the held packet's only passage path. Then run the complete positive/negative
and geometry-failure matrix in fresh VMs with independent ingress, egress,
receiver and receipt logs. A successful kernel release control is never
reported as successful geometric admission.
