# NFQUEUE userspace handoff experiment — 2026-09-30

## Boundary and claim

The existing `scripts/lightcone-nfqueue-boundary-test.sh` proves that, in an
isolated user/network namespace, nftables `inet` input/output/forward queue
rules without `bypass` drop IPv4/IPv6 traffic when no listener exists. This
experiment tests the next mechanical boundary: a Rust process binding an
NFQUEUE number, receiving the exact kernel-held packet bytes and metadata,
and returning an explicit `accept` or `drop` verdict. It does not use the
Lightcone, approve a flow, install rules on the real host, promote a v5 pack,
or seal anything.

The passive Lightcone remains passive. A later separately owned host gate may
consume its receipt and decide whether to send `accept`; until such a gate
passes the frozen traffic matrix, `filter_enforced` remains false. `accept`
in this namespace experiment means only that the kernel verdict transport
works, not that the packet is causally permitted.

## Mechanically justified implementation

- Use the Linux `NETLINK_NETFILTER` / `NFNL_SUBSYS_QUEUE` UAPI shipped on this
  host and documented by the Netfilter project. Keep its queue number,
  message type, attribute lengths, and network byte order explicit. Bind a
  single queue, request complete packet copies, set a finite queue length,
  and explicitly leave `NFQA_CFG_F_FAIL_OPEN` clear.
- Accept only well-framed `NFQNL_MSG_PACKET` messages with a complete packet
  header, bounded payload, exact queue ID, and no capture-length truncation.
  Preserve packet ID, family, hook, interface indexes, and optional UID/GID as
  factual metadata. Any malformed netlink message yields an error; it must
  never manufacture an `accept` verdict.
- Send one explicit verdict for a received packet ID. The reusable API
  supports `Drop` and `Accept` so the namespace test can prove both kernel
  effects. No production caller is wired to `Accept` in this experiment.

## Frozen test matrix

1. Refuse the privileged integration test unless running as mapped root in a
   private unprivileged user and network namespace; no real-host nft changes.
2. With one unique nft `inet` table and queue, verify no-listener IPv4 and
   IPv6 loopback pings fail closed.
3. Bind the Rust queue reader, choose `Accept` for **all packets only in the
   isolated test fixture**, and verify IPv4/IPv6 loopback pings succeed and
   packet IDs/payloads were received.
4. Change the fixture to `Drop` and verify IPv4/IPv6 pings fail while reader
   counters advance.
5. Close the reader while keeping the queue rules; verify no-listener drop.
   Remove only the test table and verify IPv4/IPv6 recovery. Teardown must run
   after any test failure.
6. Unit-test malformed/truncated netlink attributes, missing packet ID or
   payload, wrong queue ID, and oversized captures. The exact parser result
   is an error rather than a partial packet.

This is a bounded kernel handoff gate. It cannot establish all-traffic
coverage: ARP/link frames, other interfaces/namespaces, raw/packet sockets,
offload, queue crash/overload, or the Lightcone release criterion remain
separate open items in `TODO.md`. Failures stay recorded; the Lightcone stays
unsealed.

## Current execution status

The proposed Rust listener source edit was **rejected by automatic approval
review** as a destructive packet accept/drop capability without explicit
authorization. No listener code or kernel verdict service was installed by
this experiment. The isolated no-listener NFQUEUE test from the earlier
checkpoint remains the only verified kernel behavior. The namespace-only
authorization request is pending; this protocol is unrun.
