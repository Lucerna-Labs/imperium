# Imperium Mesh Runbook — running the link for real

The mesh was a library of primitives with no runtime: nothing bound a socket,
nothing drove a handshake, and nothing carried a host packet. This is how to run
what now exists, and what to watch while it runs.

## What runs now

| Piece | Crate | What it does |
|---|---|---|
| `MeshDaemon` | `imperium-net-mesh` | Owns one UDP socket, classifies each datagram, resolves the session from the source address, drives the handshake, emits cover traffic and expires idle sessions. |
| `TunDevice` | `imperium-net-host` | Creates and configures a Linux TUN interface with `ioctl`. No netlink dependency. |
| `HostBridge` | `imperium-net-host` | Carries real IP packets between the TUN device and the daemon, both directions. |
| `imperium node start --mesh-bind …` | `imperium-cli` | Starts the daemon and the bridge inside the one node process. |

Two keys are in play and they are different things:

- the **operator key** is the cluster trust anchor. Every node in a cluster
  shares it. It signs each peer's *identity binding* — "this peer id owns this
  identity key".
- the **mesh identity** is per node. It signs that node's own handshake
  messages.

## Prerequisites

- Linux. `/dev/net/tun` must exist (the `tun` module loaded).
- **Root** (`CAP_NET_ADMIN`) only for the host interface. The link itself runs
  unprivileged.
- `--mtu` is capped at 1_437, the largest MTU whose sealed frame still fits a
  1_500-byte path MTU once the outer IP and UDP headers are counted. Above that,
  every full-size frame would fragment at the IP layer.
- One **operator key** file, shared by every node. One **mesh identity** file per
  node, minted locally on first run.
- One **cluster id**, the same on every node. `--cluster-id` is required with
  `--mesh-bind`, because a node only accepts peers whose binding carries its own
  cluster id: without one every node invents a different id and no handshake can
  complete.

### The helpers

```bash
mesh-privileged show        # paths, and whether the binary carries cap_net_admin
mesh-privileged tun-test    # the ignored TUN device test, under sudo
mesh-privileged grant       # cap_net_admin on the binary, so node start needs no sudo
mesh-tunnel-test            # two nodes: tunnel, routing, control, teardown
mesh-multipeer-test         # three nodes: one hub, two leaves, one prefix each
```

`mesh-privileged route-test` runs the ignored route install/remove test.

These live in `scripts/` and are symlinked onto `PATH` from `~/.local/bin`. They
resolve their own location (following symlinks), so they run from any directory.
By hand, `scripts/mesh-privileged.sh <command>` works the same way.

Do not run `sudo cargo`: `sudo`'s PATH lacks `~/.cargo/bin`, and building as root
leaves root-owned files in `target/` that break your next normal build. Build as
yourself and run only the resulting binary under sudo.

Paths (both overridable):

```
operator key    $IMPERIUM_OPERATOR_KEY    else ~/.config/imperium/imperium/operator-key
mesh identity   $IMPERIUM_MESH_IDENTITY   else ~/.config/imperium/imperium/mesh-identity
```

Each node also needs its own `XDG_RUNTIME_DIR`, because the control socket lives
there and two nodes on one host would collide.

---

## 1. Loopback, no privileges — proves the link

Two nodes on one host, real UDP on 127.0.0.1, no host interface. This is the
fastest way to see a handshake complete.

```bash
cd imperium-main/imperium-main
BIN=./target/debug/imperium
ROOT=/tmp/impm         # scratch: swap for real key locations when you care
CL=33333333-3333-4333-8333-333333333333
mkdir -p $ROOT/a $ROOT/b
export IMPERIUM_OPERATOR_KEY=$ROOT/operator-key

# First run mints this node's identity and prints the peer id it generated.
XDG_RUNTIME_DIR=$ROOT/a IMPERIUM_MESH_IDENTITY=$ROOT/a/identity \
  timeout 5 $BIN node start --mesh-bind 127.0.0.1:41000 --no-tun --cluster-id $CL \
  > $ROOT/a.log 2>&1

# The bound line prints the id it generated:
#   INFO imperium: mesh link bound bound=127.0.0.1:41000 peer_id=<PEER_A> …
PEER_A=$(sed 's/\x1b\[[0-9;]*m//g' $ROOT/a.log \
         | grep -oE 'peer_id=[0-9a-f-]{36}' | head -1 | cut -d= -f2)
echo "PEER_A=$PEER_A"
```

If `PEER_A` is empty, the node never bound — read `$ROOT/a.log` for the reason
(most often a stale `XDG_RUNTIME_DIR`, a port already in use, or a missing
operator key path).

Then run both. A is a responder; B dials it. B must name the peer it dials.

```bash
# terminal 1 — responder. Start this one FIRST: the initiator has to name the
# peer it dials, and a peer id only exists once the node has minted it.
XDG_RUNTIME_DIR=$ROOT/a IMPERIUM_MESH_IDENTITY=$ROOT/a/identity \
  $BIN node start --mesh-bind 127.0.0.1:41000 --no-tun \
  --cluster-id $CL --report-secs 2
# read PEER_A out of its log, as above

# terminal 2 — initiator
XDG_RUNTIME_DIR=$ROOT/b IMPERIUM_MESH_IDENTITY=$ROOT/b/identity \
  $BIN node start --mesh-bind 127.0.0.1:41001 \
  --peer "$PEER_A@127.0.0.1:41000" \
  --no-tun --cluster-id $CL --report-secs 2
```

A peer is `<peer-id>` or `<peer-id>@<address>`. Without an address the node
expects that peer but does not dial it, which is the responder shape — the
address is learned from the handshake. With no `--peer` at all, the node accepts
any peer whose identity is operator-bound.

**What success looks like.** The initiator logs once:

```
INFO imperium_net_mesh::daemon: mesh handshake complete source=127.0.0.1:41000
```

and both nodes then report every `--report-secs`:

```
INFO imperium: mesh link health (no host interface) established=true killed=false
     mesh_datagrams=1 handshakes=1 frames_opened=0 frames_failed=0 cover_sent=0
```

`established=true` on **both** sides is the thing to check. `handshakes=1` on
each. If A says established and B does not, the response did not come back.

---

## 2. Single host with host interfaces — prove the tunnel (needs namespaces)

**Do not test this with two interfaces in one kernel.** It does not work, and it
fails in the worst way: silently.

If node A binds `10.77.0.1` and node B binds `10.77.0.2` on the same host, then
`10.77.0.2` is a **local address**. The kernel answers `ping 10.77.0.2` over the
loopback path and the packet never enters `impa` — the tunnel is bypassed and the
ping succeeds anyway, proving nothing. `ip route get 10.77.0.2` shows
`local 10.77.0.2 dev lo table local`, which is the tell.

The fix is to put each node in its own network namespace, so the peer's tunnel
address is remote from the pinging side. The helper does all of it:

```bash
cargo build -p imperium-cli        # as yourself, first
mesh-tunnel-test                   # no root, no capability grant
```

It creates two namespaces joined by a veth pair (the underlay, `192.168.77.0/24`,
carries the mesh UDP; the tunnel carries `10.77.0.0/24`), starts both nodes,
pings `10.77.0.1 → 10.77.0.2` through the tunnel, prints the interface state,
the handshake result and the bridge counters, then tears everything down.

**It needs no privileges at all.** The whole test runs inside an *unprivileged
user namespace* (`unshare -Urn`), which is enough to hold `CAP_NET_ADMIN` over
the namespaces it creates — so it can make the veth pair and create TUN devices
without root and without granting any capability to any binary. It falls back to
telling you to re-run as root only if unprivileged user namespaces are disabled
on your kernel.

Nothing leaves the namespace: no interface, no route, and no address touches the
host, and the cleanup is verified.

**Reading the result.** A successful ping is necessary but not sufficient — the
counters are what prove packets went through the seal:

- `established=true` on both, else the handshake never completed and the bridge
  had nowhere to send.
- `host_in` and `host_out` **non-zero on both nodes**. `host_in` is IP packets
  read from the TUN and sealed out; `host_out` is decrypted payloads written
  back. Zero on either side means the packet came from somewhere else.
- `frames_failed` should stay at 0. Anything else means frames are being refused.

It also proves routing: node A is started with `--route 10.88.0.0/24` and node
B is given `10.88.0.1/24`, a subnet that exists only behind B. Three checks run,
and all three must pass:

- **routing** — `10.88.0.1` answers from node A, reachable only because of the
  installed route;
- **control** — `10.99.0.1`, with no route, still does **not** answer. Without
  this, a passing ping would not distinguish routing from routing-everything;
- **teardown** — the route is gone once node A exits, with no `ip route del`.

Observed on a passing run: both nodes `established=true handshakes=1`, counters
climbing on both, `frames_failed=0`, `host_in_dropped=0`, 3/3 pings answered,
and routing/control/teardown all PASS.

Two notes from that run. The interfaces report state `UNKNOWN`, which is normal
for TUN devices and does not prevent traffic — the ping is the proof. And
`host_in_dropped` should be 0: the bridge now queues pre-session packets in a
bounded, ageing queue and flushes them once the session establishes, rather
than dropping the first packets after bring-up. It rises only if that queue
fills or a send fails.

What is deliberately **not** done: no DEFAULT route is installed, so the
tunnel never hijacks all traffic. The default `/24` netmask gives each namespace
its own *connected* route for `10.77.0.0/24`, which is all the ping needs, plus
the explicit `--peer-route` / `--route` prefixes the operator names. Routing
real traffic through the tunnel beyond those is a separate, opt-in step and is
not implemented.

---

## 3. Two hosts on a LAN

The same commands with real addresses instead of loopback:

```bash
# host A (10.0.0.10)
... --mesh-bind 0.0.0.0:41000 --tunnel-ip 10.77.0.1

# host B (10.0.0.11)
... --mesh-bind 0.0.0.0:41001 --peer "$PEER_A@10.0.0.10:41000" \
    --tunnel-ip 10.77.0.2
```

Copy the **same** operator key file to both. Copy nothing else — the mesh
identity must be different per node, and is minted locally on first run.

This is where a real network bites and loopback does not:

- **Fragmentation.** Handshake datagrams are multi-kilobyte hybrid
  post-quantum material and exceed a 1500-byte path MTU. On loopback nothing
  fragments; on a LAN, middleware that drops fragments will break the handshake
  while loopback looked fine. Watch for the handshake never completing.
- **NAT.** The session is bound to the address a datagram actually arrives
  from, not the endpoint the peer advertised. Behind NAT the source address
  differs from the advertised one, and the address→session lookup has nothing to
  match. This is a known gap, not a fixed thing.
- **Firewall.** Both sides need the UDP port open inbound.

---

## 4. Several peers — a hub with two leaves

`--peer` repeats, and `--peer-route <peer-id>=<cidr>` says which prefixes each
peer serves. Those routes decide which peer a packet goes to: the packet's own
IPv4 destination is matched against every peer's prefixes, longest prefix first.
A destination no peer serves is **not** sent to any of them — with several peers
to choose from, guessing would leak the packet to the wrong network.

Each `--peer-route` also installs a kernel route, because a prefix with a peer
route but no kernel route is a prefix whose traffic never enters the tunnel, so
the daemon would never see it in order to choose.

```bash
# the hub, expecting two leaves and knowing what each serves
$BIN node start --mesh-bind 0.0.0.0:41000 \
  --tunnel-ip 10.77.0.1 --tun impa \
  --peer "$PEER_B@10.0.0.11:41000" --peer-route "$PEER_B=10.88.0.0/24" \
  --peer "$PEER_C@10.0.0.12:41000" --peer-route "$PEER_C=10.99.0.0/24"
```

The helper runs the whole thing on one host, in three network namespaces:

```bash
mesh-multipeer-test
```

It checks four things, and all four must pass: a packet reaches leaf B's prefix,
a packet reaches leaf C's prefix, an unserved destination reaches neither, and
every route is gone once the hub exits.

**Two things the leaves need that a two-node setup does not.** Each leaf is on
its own subnet, so its connected route does not cover the hub's tunnel address —
each needs `--route 10.77.0.0/24` or a reply has nowhere to go. And the two
underlay links must be on *different* subnets, because one subnet shared by two
interfaces on the same host gives the kernel an ambiguous route, the same class
of mistake as the local-address trap in section 2.

## What to watch, and what is already known to be wrong

`--report-secs N` prints the live counters. These are the fields that matter:

| Field | Reading |
|---|---|
| `established` | Session up on this side. |
| `handshakes` | Completed handshakes. Should be 1 on each side. |
| `mesh_datagrams` | Datagrams received from the wire. |
| `frames_opened` / `frames_failed` | Decrypted vs refused. Failures with zero opens mean the session or the key is wrong. |
| `host_in` / `host_out` | Host packets sealed out, and decrypted payloads written back. |
| `host_in_dropped` | Host packets discarded **before a session existed**. Should be 0 — they are queued instead and flushed when the session comes up. |
| `cover_sent` | Cover frames emitted under the active hardening profile. |
| `handshake_verifications` | Hellos that reached a full hybrid signature verification. On a flooded listener this must stay at **0**. |
| `handshake_cookies_sent` | Cookies handed out in place of doing that work. |
| `handshake_rate_limited` | Hellos dropped by the per-source token bucket before any work. |
| `handshake_datagrams_reassembled` | Handshake messages rebuilt from fragments. Non-zero means fragmentation is working. |
| `handshake_fragments_rejected` | Fragment sets refused or abandoned. Should be 0 on a healthy link. |
| `sessions_rekeyed` | Sessions torn down and re-established because the key budget was spent. |
| `nat_rebinds` | Sessions rebound to a new source address (the peer moved, e.g. behind NAT). |

### The handshake gate

A hybrid Ed25519 + ML-DSA-65 verification is the expensive part of accepting a
peer, and it must not be reachable by an arbitrary datagram. Two cheap
mechanisms now stand in front of it:

1. an ungated Hello earns a **cookie** and nothing else — no JSON parsing, no
   signature work;
2. a Hello returning that cookie's MAC is checked against the **source address**
   it arrived from, and only then verified.

A per-source **token bucket** bounds how much of that work one address can
compel, because a cookie cannot stop a flood from a real address. The MAC is
`HMAC(cookie, hello_datagram)`, so it admits exactly the Hello that was sent
rather than any Hello from that address. This costs one extra round trip per
handshake, paid once.

Measured, not asserted: 200 forged Hellos from one source produce
`handshake_verifications = 0`.

### Fixed since the first draft of this runbook

1. **The handshake codec was JSON**, and `serde_json` encodes `Vec<u8>` as an
   array of decimal integers — about 3.5 bytes on the wire per byte. A 12 KB
   Hello was being sent as a **43 KB** datagram. It is now hand-encoded binary,
   which also drops a serialisation dependency from the handshake path.
2. **Handshake messages are fragmented.** Even at 12 KB they exceed any path
   MTU, and relying on IP fragmentation means relying on middleboxes that drop
   it. Messages are split into 1200-byte fragments and reassembled, with every
   dimension bounded (fragment count, message size, partials per source and in
   total, age). Reassembled bytes are attacker-controlled, so the reassembled
   datagram is dispatched through a path that refuses fragments outright — a
   fragment set that reassembles into another fragment would otherwise recurse
   without bound.
3. **A HelloResponse's identity is now operator-bound in-protocol.** The
   response carries the responder's own operator-signed binding, covered by its
   signature, and the initiator checks that binding before trusting the key.
   `--pinned-identity` remains as an extra operator constraint, not as the only
   defence.
4. **The cluster id is compared.** It was signed and never checked, so a peer
   from a different cluster was accepted as long as the operator key matched.
5. **The session key rotates.** `--rekey-bytes` (default 64 GiB) is enforced on
   the data path and rotation is a re-handshake, so it establishes genuinely new
   key material. `0` means never. Before this the budget was never even passed
   to the seal, so the key lived for the life of the session.
6. **A peer whose address changes keeps working.** The address→session index is
   tried first; if it misses, the one session this link could belong to is tried
   and the AEAD decides. A successful open rebinds the session, so the fast path
   resumes. Rate limited, because an unmatched datagram compels that work.
7. **The operator kill switch reaches the data path.** The control socket's
   `vpn killswitch engage` publishes on the bus and the daemon now subscribes:
   engaged stops sealing and sending, disarmed resumes, and *armed* is recorded
   without black-holing a healthy link.

8. **Several peers, with the packet's destination choosing one.** The daemon
   holds a link per peer, dials every configured peer, and selects on send by
   longest-prefix match against each peer's routes. A single-peer node behaves
   exactly as before.
9. **A first-run race that produced two different trust anchors.** Two nodes
   starting at once on a fresh host both found the operator key file missing,
   both generated a key, and both wrote — so one node kept a key that was not on
   disk, and the two rejected each other's identity bindings. It reproduced in
   about half of repeated three-node runs as
   `mesh hello rejected error=operator identity binding invalid`. Key files are
   now created by linking a temporary file into place, so the filesystem
   arbitrates and exactly one writer wins.

10. **A rebind is resolved against every peer, not one of them.** With several
    peers, an unmatched datagram's address could belong to any of them. Trying a
    single arbitrary candidate meant the frame was tested against the wrong
    peer's session, failed, and was dropped — so a peer whose address had moved
    could never rebind while the node served more than one peer. Every
    established session is now a candidate, and the frame is opened exactly once
    whichever path wins.
11. **Cover traffic goes to every established link.** It was emitted once per
    tick on one link, which left the others distinguishable by their silence —
    the property cover traffic exists to remove.
12. **A cluster id is required, instead of failing at runtime.** Adding the
    cluster comparison turned the default configuration, which omitted
    `--cluster-id`, into `peer belongs to a different cluster` — naming a cluster
    the operator never chose. It is now refused at startup by name.
13. **Key files are restricted before they are reachable.** The file was created,
    linked into place, and only then chmod'd, leaving a window in which the
    private key was world-readable — and the window is exactly when another
    process is racing to read it. Permissions are now set on the temporary file
    before it is linked. Temporary names are also unique per call rather than per
    process, because two concurrent callers inside one process shared a single
    temporary file and corrupted each other's key material.
14. **The frame-shaping layer's rekey accounting is gone.** It counted bytes and
    incremented an epoch that nothing read, which is what let "rekeying" look
    satisfied while no key ever rotated. The real budget is `session_max_bytes`
    in the session layer, enforced and rotated by re-handshaking.

15. **The frame ceiling did not account for the outer headers.** It was 1_500,
    which is the frame alone: a frame at the ceiling plus IP (20) and UDP (8)
    makes a 1_528-byte datagram that fragments at the IP layer — the very
    fragmentation this layer fragments in order to avoid. The ceiling is now
    1_472, `MAX_SAFE_TUN_MTU` (1_437) is derived from it, and an `--mtu` above
    that is refused at startup. `--mtu` previously had no upper bound at all, so
    an operator could configure a tunnel in which every full-size frame
    fragmenting was the normal case.

### Knowingly still wrong

1. **Only split-tunnel routing.** `--route` routes the destinations you name;
   there is no default-route mode and the default route is never touched.
2. **The kill switch covers what the mesh carries, not the whole host.**
   Keeping non-tunnel traffic off the wire when the tunnel is down needs route
   and firewall state this component does not own.
3. **The GUI console runs off the process main thread.** The node's startup
   chain needs more stack than the 8 MiB main thread provides (see below), so
   the whole node runs on a sized thread. Linux/X11 and Wayland tolerate this;
   macOS and Windows would not, and this project is Linux-only.

## Two crashes that only running found

Neither of these is visible in the test suite, because every test runs its
crypto on a 64 MiB thread and the binary did not.

1. **`thread 'main' has overflowed its stack`, before any log line.** The
   node's startup is one deep fully-inlined async state machine; `block_on` laid
   it out on the 8 MiB main stack. Fixed by running the node on a sized thread
   and boxing the future.
2. **The same abort again, after "node wiring complete".** A second deep step in
   startup — supervisor engagement and strand installation — also exceeds the
   main stack. The same fix covers it.

Worker threads needed it too: a mesh handshake signs with ML-DSA-65 inside a
spawned task, and tokio's default worker stack is 2 MiB.

## Running the privileged test

The TUN device test is real but needs root, so it is `#[ignore]`d.

**Do not run `sudo cargo`.** Two reasons: `sudo`'s secure PATH does not include
`~/.cargo/bin`, so it fails with `sudo: cargo: command not found`; and even with
the PATH fixed it leaves root-owned files in `target/`, which then break your
next non-root build.

Use the helper, which builds as you and runs only the resulting binary under
sudo:

```bash
./scripts/mesh-privileged.sh tun-test    # the TUN device test
./scripts/mesh-privileged.sh grant       # let `node start` make the tunnel without sudo
./scripts/mesh-privileged.sh show        # paths, and whether the capability is set
```

The commands must run from the project root (or use the script's absolute path) —
`./target/debug/imperium` does not exist if you are in `~`.

By hand, if you prefer:

```bash
cargo test -p imperium-net-host --no-run          # prints the executable path
sudo ./target/debug/deps/imperium_net_host-<hash> --ignored --nocapture
```

Run without the capability and the failure is clean, not a crash:
`create TUN: Create(Os { code: 1, kind: PermissionDenied, message: "Operation not
permitted" })`.

What the test does: creates `imptest…`, assigns 10.77.0.1/24, sets MTU 1280,
brings it up, switches the fd non-blocking, and tears the interface down on drop.
Nothing touches routes.