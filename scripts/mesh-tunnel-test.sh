#!/usr/bin/env bash
#
# End-to-end tunnel test: a real IP packet through the seal, no root required.
#
# WHY TWO NETWORK NAMESPACES: a TUN tunnel cannot be tested with two interfaces
# in one kernel. If node A binds 10.77.0.1 and node B binds 10.77.0.2 on one
# host, then 10.77.0.2 is a LOCAL address — the kernel answers `ping 10.77.0.2`
# over the loopback path, the packet never enters impa, and the test passes while
# proving nothing. `ip route get 10.77.0.2` would say `local ... dev lo table
# local`. Each node therefore gets its own network stack, so the peer's tunnel
# address is remote and the packet is forced through the interface, the bridge,
# the seal, and back.
#
# WHY NO ROOT: this runs inside an unprivileged user namespace (`unshare -Urn`).
# Within it we hold CAP_NET_ADMIN over the network namespaces we create, which is
# enough to make a veth pair, configure the underlay, and create TUN devices.
# Nothing outside the namespace is touched, and no capability is granted to any
# binary. Requires unprivileged user namespaces to be permitted, which is the
# default on mainstream kernels.
#
# Topology, all inside the namespace:
#
#   ns A                          ns B
#   underlay 192.168.77.1  <---veth--->  192.168.77.2   (carries the mesh UDP)
#   tunnel   10.77.0.1                   10.77.0.2      (carries the real packet)
#   route    10.88.0.0/24 -> impa        10.88.0.1      (a subnet behind B)
#
# Three things are proved, in order:
#   1. the tunnel carries a packet between the two tunnel addresses;
#   2. a destination that is NOT one of those addresses is reachable because of
#      an installed route — and a destination with no route is not reachable;
#   3. the route is gone once the node exits, with no `ip route del` by hand.
#
# Run:  scripts/mesh-tunnel-test.sh

set -euo pipefail

# Setup and acceptance parse INFO-level mesh events. Ignore a caller's global
# RUST_LOG (which may be warn/error); allow an explicit test-specific override.
TEST_RUST_LOG="${IMPERIUM_TEST_RUST_LOG:-info}"

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
BIN="$ROOT/target/debug/imperium"
SELF_ABS="$(readlink -f "${BASH_SOURCE[0]}")"

UNDERLAY_A=192.168.77.1
UNDERLAY_B=192.168.77.2
TUNNEL_A=10.77.0.1
TUNNEL_B=10.77.0.2
# A subnet that exists only behind node B. Nothing on node A's side is in it,
# so the only way to reach it is through the tunnel.
BEHIND_B=10.88.0.0
BEHIND_B_HOST=10.88.0.1
# A destination with no route at all, as the control.
UNROUTED=10.99.0.1
CLUSTER=33333333-3333-4333-8333-333333333333

strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

# ---- the inner half: runs INSIDE the user namespace ------------------------
if [[ "${1:-}" == "--inside" ]]; then
    WORK="$2"
    read -r PA PB < "$WORK/pids"

    cleanup() {
        [[ -n "${PID_A:-}" ]] && kill "$PID_A" 2>/dev/null || true
        [[ -n "${PID_B:-}" ]] && kill "$PID_B" 2>/dev/null || true
        kill "$PA" "$PB" 2>/dev/null || true
    }
    trap cleanup EXIT

    # The responder starts first, because the initiator has to name the peer it
    # dials and a peer id is only known once the node has minted its identity.
    echo "=== starting node B (responder, tunnel $TUNNEL_B) ==="
    # nsenter runs the child itself in the target namespace. A bare
    # `nsenter CMD` form is correct here; do not wrap it in `bash -c`,
    # whose extra quoting layer breaks argument passing.
    nsenter --net="/proc/$PB/ns/net" -- env \
        XDG_RUNTIME_DIR="$WORK/b" \
        IMPERIUM_OPERATOR_KEY="$WORK/operator-key" \
        IMPERIUM_MESH_IDENTITY="$WORK/b/identity" \
        RUST_LOG="$TEST_RUST_LOG" \
        "$BIN" node start \
            --mesh-bind "$UNDERLAY_B:41000" \
            --tunnel-ip "$TUNNEL_B" --tun impb \
            --cluster-id "$CLUSTER" --report-secs 5 \
            > "$WORK/b.log" 2>&1 &
    PID_B=$!

    for _ in $(seq 1 60); do
        grep -q "mesh link bound" "$WORK/b.log" 2>/dev/null && break
        sleep 0.25
    done
    PEER_B="$(strip_ansi < "$WORK/b.log" | grep -oE 'peer_id[^0-9a-f-]*[0-9a-f-]{36}' | head -1 | grep -oE '[0-9a-f-]{36}$')"
    if [[ -z "$PEER_B" ]]; then
        echo "node B never bound. Log:" >&2
        strip_ansi < "$WORK/b.log" | tail -25 >&2
        exit 1
    fi
    echo "node B peer id: $PEER_B"

    echo "=== starting node A (initiator, tunnel $TUNNEL_A) ==="
    nsenter --net="/proc/$PA/ns/net" -- env \
        XDG_RUNTIME_DIR="$WORK/a" \
        IMPERIUM_OPERATOR_KEY="$WORK/operator-key" \
        IMPERIUM_MESH_IDENTITY="$WORK/a/identity" \
        RUST_LOG="$TEST_RUST_LOG" \
        "$BIN" node start \
            --mesh-bind "$UNDERLAY_A:41000" \
            --tunnel-ip "$TUNNEL_A" --tun impa \
            --peer "$PEER_B@$UNDERLAY_B:41000" \
            --peer-route "$PEER_B=$BEHIND_B/24" \
            --cluster-id "$CLUSTER" --report-secs 5 \
            > "$WORK/a.log" 2>&1 &
    PID_A=$!

    for _ in $(seq 1 80); do
        grep -q "mesh handshake complete" "$WORK/a.log" 2>/dev/null && break
        sleep 0.25
    done
    sleep 3

    echo
    echo "=== interfaces ==="
    nsenter --net="/proc/$PA/ns/net" ip -brief addr show impa || echo "impa MISSING in ns A"
    nsenter --net="/proc/$PB/ns/net" ip -brief addr show impb || echo "impb MISSING in ns B"

    echo
    echo "=== handshake ==="
    strip_ansi < "$WORK/a.log" | grep -E "mesh handshake complete" \
        || echo "A: NO HANDSHAKE (A is the initiator, so it logs the completion)"
    strip_ansi < "$WORK/b.log" | grep -E "mesh handshake complete" \
        || echo "B: no 'handshake complete' line (expected: B is the responder)"

    echo
    echo "=== ping through the tunnel: $TUNNEL_A -> $TUNNEL_B ==="
    if nsenter --net="/proc/$PA/ns/net" ping -c 3 -W 2 "$TUNNEL_B"; then
        PING_OK=yes
    else
        PING_OK=no
    fi

    echo
    echo "=== routing: a subnet behind node B ==="
    # Stand up the far subnet on B's own interface. From A it is not local and
    # not on any directly connected network, so only the route can reach it.
    nsenter --net="/proc/$PB/ns/net" ip addr add "$BEHIND_B_HOST/24" dev impb
    echo "node B now owns $BEHIND_B_HOST/24"
    echo "--- node A's route table for $BEHIND_B/24 ---"
    nsenter --net="/proc/$PA/ns/net" ip route show "$BEHIND_B/24" \
        || echo "(no route — the ping below cannot work)"
    echo "--- node A's default route (must be untouched) ---"
    nsenter --net="/proc/$PA/ns/net" ip route show default || echo "(none in ns A)"

    echo
    echo "=== CONTROL: $UNROUTED has no route and must NOT be reachable ==="
    if nsenter --net="/proc/$PA/ns/net" ping -c 1 -W 2 "$UNROUTED" >/dev/null 2>&1; then
        CONTROL_OK=no
        echo "UNEXPECTED: $UNROUTED answered without a route"
    else
        CONTROL_OK=yes
        echo "as expected: no route, no answer"
    fi

    echo
    echo "=== ROUTED: $TUNNEL_A -> $BEHIND_B_HOST through the tunnel ==="
    if nsenter --net="/proc/$PA/ns/net" ping -c 3 -W 2 "$BEHIND_B_HOST"; then
        ROUTED_OK=yes
    else
        ROUTED_OK=no
    fi

    sleep 6   # let a health report land with the counters moved
    echo
    echo "=== bridge counters ==="
    echo "--- node A (responder) ---"
    strip_ansi < "$WORK/a.log" | grep -E "mesh link health" | tail -2 || echo "(none)"
    echo "--- node B (initiator) ---"
    strip_ansi < "$WORK/b.log" | grep -E "mesh link health" | tail -2 || echo "(none)"

    echo
    echo "=== teardown: the route must be gone once the node exits ==="
    kill "$PID_A" 2>/dev/null || true
    PID_A=""
    for _ in $(seq 1 40); do
        nsenter --net="/proc/$PA/ns/net" ip route show "$BEHIND_B/24" 2>/dev/null \
            | grep -q . || break
        sleep 0.25
    done
    if nsenter --net="/proc/$PA/ns/net" ip route show "$BEHIND_B/24" 2>/dev/null | grep -q .; then
        ROUTE_CLEANED=no
        echo "LEAKED: the route survived the process"
        nsenter --net="/proc/$PA/ns/net" ip route show "$BEHIND_B/24"
    else
        ROUTE_CLEANED=yes
        echo "removed: no route to $BEHIND_B/24 remains"
    fi

    echo
    [[ "$PING_OK" == yes ]] && echo "RESULT: ping succeeded through the tunnel." \
                           || echo "RESULT: ping FAILED."
    echo
    echo "The evidence that matters is the counters, not the ping. host_in and"
    echo "host_out must be NON-ZERO on BOTH nodes. host_in = IP packets read"
    echo "from the TUN and sealed out; host_out = decrypted payloads written"
    echo "back. A ping passing with those at zero would mean the packet was"
    echo "answered locally and never crossed the seal."
    echo
    echo "routing  : $([ "$ROUTED_OK" = yes ] && echo "PASS" || echo "FAIL") \
(a subnet behind the peer reachable through the tunnel)"
    echo "control  : $([ "$CONTROL_OK" = yes ] && echo "PASS" || echo "FAIL") \
(an unrouted destination still unreachable)"
    echo "teardown : $([ "${ROUTE_CLEANED:-no}" = yes ] && echo "PASS" || echo "FAIL") \
(the route removed when the node exited)"
    exit 0
fi

# ---- the outer half: check the environment, then re-enter in a userns ------
if [[ ! -x "$BIN" ]]; then
    echo "not built: $BIN" >&2
    echo "build it first:  cargo build -p imperium-cli" >&2
    exit 1
fi

if ! unshare -Urn true 2>/dev/null; then
    echo "unprivileged user namespaces are unavailable on this system." >&2
    echo "re-run as root instead:  sudo $0" >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/imperium-tunnel-test.XXXXXX")"
mkdir -m 700 -p "$WORK/a" "$WORK/b"
trap 'rm -rf "$WORK"' EXIT
OUTER_WORK="$WORK"
export OUTER_WORK

PLUMB=$(cat <<PLUMB_EOF
set -e
OUTER_WORK="$WORK"
ip link set lo up
ip link add va type veth peer name vb
# The children write their own \$\$ from inside the new namespace, so the pid is
# already the right one -- but confirm the transition happened rather than infer
# it, and reap the namespace holders on the way out: a leaked sleep command keeps
# its namespace, and its veth end, alive for ten minutes after a failed run.
wait_for_ns() {
    local pid="\$1" here="\$2" i=0
    while [ "\$i" -lt 1000 ]; do
        [ "\$(readlink /proc/\$pid/ns/net 2>/dev/null)" != "\$here" ] && return 0
        i=\$((i + 1))
        sleep 0.01
    done
    echo "child \$pid never entered its own network namespace" >&2
    return 1
}
HUB_NS="\$(readlink /proc/self/ns/net)"
trap 'kill \$PA \$PB \$NSA_PID \$NSB_PID 2>/dev/null' EXIT
unshare -n bash -c 'echo \$\$ > "$OUTER_WORK/pA"; ip link set lo up; exec sleep 600' &
NSA_PID=\$!
unshare -n bash -c 'echo \$\$ > "$OUTER_WORK/pB"; ip link set lo up; exec sleep 600' &
NSB_PID=\$!
for _ in \$(seq 1 200); do
    [ -s "$OUTER_WORK/pA" ] && [ -s "$OUTER_WORK/pB" ] && break
    sleep 0.1
done
[ -s "$OUTER_WORK/pA" ] || { echo "namespace holder A never wrote its pid file" >&2; exit 2; }
[ -s "$OUTER_WORK/pB" ] || { echo "namespace holder B never wrote its pid file" >&2; exit 2; }
PA=\$(cat "$OUTER_WORK/pA"); PB=\$(cat "$OUTER_WORK/pB")
wait_for_ns "\$PA" "\$HUB_NS"
wait_for_ns "\$PB" "\$HUB_NS"
echo "\$PA \$PB" > "$OUTER_WORK/pids"
ip link set va netns "\$PA"
ip link set vb netns "\$PB"
nsenter --net=/proc/\$PA/ns/net ip addr add $UNDERLAY_A/24 dev va
nsenter --net=/proc/\$PA/ns/net ip link set va up
nsenter --net=/proc/\$PB/ns/net ip addr add $UNDERLAY_B/24 dev vb
nsenter --net=/proc/\$PB/ns/net ip link set vb up
exec "$SELF_ABS" --inside "$OUTER_WORK"
PLUMB_EOF
)

echo "=== entering an unprivileged user namespace (no root, no capability grant) ==="
unshare -Urn bash -c "$PLUMB"
