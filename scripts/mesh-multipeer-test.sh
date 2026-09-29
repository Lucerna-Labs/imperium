#!/usr/bin/env bash
#
# Three-node live test: one hub, two leaves, each leaf serving its own subnet.
#
# Proves the multi-peer path end to end on a real host:
#
#   - the hub establishes with BOTH leaves at once;
#   - a packet for one leaf's prefix goes to that leaf and not the other;
#   - a destination no leaf serves is NOT sent to either (with several peers to
#     choose from, guessing would leak the packet to the wrong network);
#   - every route installed for a peer is removed when the node exits.
#
# Topology, all inside one unprivileged user namespace:
#
#   ns A (hub)                      ns B (leaf)
#     192.168.77.1  <----veth---->  192.168.77.2      underlay for the mesh
#     192.168.78.1  <----veth---->  192.168.78.2      (second veth, to C)
#     tunnel 10.77.0.1               tunnel 10.88.0.1  <- serves 10.88.0.0/24
#   ns C (leaf)
#     tunnel 10.99.0.1  <- serves 10.99.0.0/24
#
# The two underlays are separate subnets on purpose: one subnet shared by two
# interfaces on the same host gives the kernel an ambiguous route, which is the
# same class of mistake as the local-address trap in `mesh-tunnel-test.sh`.
#
# No root: an unprivileged user namespace grants CAP_NET_ADMIN over the
# namespaces it creates, which is enough for veth pairs, TUN devices and routes.
#
# Run:  scripts/mesh-multipeer-test.sh

set -euo pipefail

# Setup and acceptance parse INFO-level mesh events. Ignore a caller's global
# RUST_LOG (which may be warn/error); allow an explicit test-specific override.
TEST_RUST_LOG="${IMPERIUM_TEST_RUST_LOG:-info}"

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
BIN="$ROOT/target/debug/imperium"

# Underlay for the mesh, one subnet per veth pair.
UNDERLAY_A_B=192.168.77
UNDERLAY_A_C=192.168.78
# Tunnel addresses.
TUNNEL_A=10.77.0.1
TUNNEL_B=10.88.0.1
TUNNEL_C=10.99.0.1
# The hub's tunnel subnet. Each leaf needs a route back to it: the leaves are
# on their own /24s, so unlike the two-node case their connected route does not
# cover the hub and a reply would have nowhere to go.
HUB_TUNNEL_SUBNET=10.77.0.0/24
# Prefixes each leaf serves, and one nobody serves.
PREFIX_B=10.88.0.0/24
PREFIX_C=10.99.0.0/24
UNSERVED=10.66.0.1
CLUSTER=44444444-4444-4444-8444-444444444444

strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

lightcone_status() {
    python3 - "$1" "$2" <<'PY'
import json
import socket
import sys
import time

path, label = sys.argv[1:]
last = None
for _ in range(60):
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect(path)
            client.sendall(b"vpn lightcone status\n")
            data = b""
            while not data.endswith(b"\n"):
                data += client.recv(65536)
        last = json.loads(data)
    except (OSError, ValueError) as error:
        last = {"error": str(error)}
    if (
        last.get("working") is True
        and last.get("world_version") == 4
        and last.get("training_platform") == "local_diagnostic"
        and last.get("passive") is True
        and last.get("sealed") is False
        and last.get("holds_verdict") is False
        and last.get("strand_lifecycle") == "running"
        and last.get("rx", 0) > 0
        and last.get("tx", 0) > 0
        and last.get("raw_ip_rx", 0) > 0
        and last.get("raw_ip_tx", 0) > 0
        and last.get("mesh_rx", 0) > 0
        and last.get("mesh_tx", 0) > 0
        and last.get("lightcone_observations_dropped") == 0
        and last.get("lightcone_publish_errors") == 0
        and last.get("pending_observations") == 0
    ):
        print(f"{label}: PASS v4 unsealed passive "
              f"raw_ip={last['raw_ip_rx']}/{last['raw_ip_tx']} "
              f"mesh={last['mesh_rx']}/{last['mesh_tx']} "
              f"published={last['lightcone_observations_published']} dropped=0")
        sys.exit(0)
    time.sleep(0.1)
print(f"{label}: FAIL Lightcone status {last}")
sys.exit(1)
PY
}

if [[ "${1:-}" == "--inside" ]]; then
    WORK="$2"
    # This script already runs inside the hub's namespace (see the plumbing
    # below), so the hub's commands need no nsenter. B and C are children.
    read -r PB PC < "$WORK/pids"

    cleanup() {
        for pid in "${PID_A:-}" "${PID_B:-}" "${PID_C:-}"; do
            [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
        done
        kill "$PB" "$PC" 2>/dev/null || true
    }
    trap cleanup EXIT

    # Leaves first: each mints its identity, and the hub needs their peer ids to
    # declare them. A leaf with no --peer accepts any operator-bound peer.
    echo "=== starting leaf B (tunnel $TUNNEL_B, serves $PREFIX_B) ==="
    nsenter --net="/proc/$PB/ns/net" -- env \
        XDG_RUNTIME_DIR="$WORK/b" \
        IMPERIUM_OPERATOR_KEY="$WORK/operator-key" \
        IMPERIUM_MESH_IDENTITY="$WORK/b/identity" \
        RUST_LOG="$TEST_RUST_LOG" \
        "$BIN" node start \
            --mesh-bind "$UNDERLAY_A_B.2:41000" \
            --tunnel-ip "$TUNNEL_B" --tun impb \
            --route "$HUB_TUNNEL_SUBNET" \
            --cluster-id "$CLUSTER" --report-secs 5 \
            > "$WORK/b.log" 2>&1 &
    PID_B=$!

    echo "=== starting leaf C (tunnel $TUNNEL_C, serves $PREFIX_C) ==="
    nsenter --net="/proc/$PC/ns/net" -- env \
        XDG_RUNTIME_DIR="$WORK/c" \
        IMPERIUM_OPERATOR_KEY="$WORK/operator-key" \
        IMPERIUM_MESH_IDENTITY="$WORK/c/identity" \
        RUST_LOG="$TEST_RUST_LOG" \
        "$BIN" node start \
            --mesh-bind "$UNDERLAY_A_C.2:41000" \
            --tunnel-ip "$TUNNEL_C" --tun impc \
            --route "$HUB_TUNNEL_SUBNET" \
            --cluster-id "$CLUSTER" --report-secs 5 \
            > "$WORK/c.log" 2>&1 &
    PID_C=$!

    # Generous, because key generation and the full runtime start on a loaded
    # machine can take a while, and a setup timeout reported as four routing
    # failures is indistinguishable from a broken mesh.
    for _ in $(seq 1 240); do
        grep -q "mesh link bound" "$WORK/b.log" 2>/dev/null \
            && grep -q "mesh link bound" "$WORK/c.log" 2>/dev/null && break
        sleep 0.25
    done
    PEER_B="$(strip_ansi < "$WORK/b.log" | grep -oE 'peer_id[^0-9a-f-]*[0-9a-f-]{36}' | head -1 | grep -oE '[0-9a-f-]{36}$')"
    PEER_C="$(strip_ansi < "$WORK/c.log" | grep -oE 'peer_id[^0-9a-f-]*[0-9a-f-]{36}' | head -1 | grep -oE '[0-9a-f-]{36}$')"
    if [[ -z "$PEER_B" || -z "$PEER_C" ]]; then
        echo
        echo "SETUP FAILED: a leaf never bound, so NO CHECKS RAN." >&2
        echo "This is not a mesh result — the nodes did not come up. Leaf logs:" >&2
        for leaf in b c; do
            echo "--- leaf $leaf ---" >&2
            strip_ansi < "$WORK/$leaf.log" | grep -viE "\[kernel\]|registered" | tail -12 >&2
        done
        exit 2
    fi
    echo "leaf B peer id: $PEER_B"
    echo "leaf C peer id: $PEER_C"

    echo "=== starting hub A with both leaves as peers ==="
    env \
        XDG_RUNTIME_DIR="$WORK/a" \
        IMPERIUM_OPERATOR_KEY="$WORK/operator-key" \
        IMPERIUM_MESH_IDENTITY="$WORK/a/identity" \
        RUST_LOG="$TEST_RUST_LOG" \
        "$BIN" node start \
            --mesh-bind "0.0.0.0:41000" \
            --tunnel-ip "$TUNNEL_A" --tun impa \
            --peer "$PEER_B@$UNDERLAY_A_B.2:41000" \
            --peer-route "$PEER_B=$PREFIX_B" \
            --peer "$PEER_C@$UNDERLAY_A_C.2:41000" \
            --peer-route "$PEER_C=$PREFIX_C" \
            --cluster-id "$CLUSTER" --report-secs 5 \
            > "$WORK/a.log" 2>&1 &
    PID_A=$!

    # Wait for both links.
    for _ in $(seq 1 240); do
        strip_ansi < "$WORK/a.log" | grep -q "peers_established=2" && break
        sleep 0.25
    done
    sleep 2

    echo
    echo "=== interfaces ==="
    ip -brief addr show impa || echo "impa MISSING"
    nsenter --net="/proc/$PB/ns/net" -- ip -brief addr show impb || echo "impb MISSING"
    nsenter --net="/proc/$PC/ns/net" -- ip -brief addr show impc || echo "impc MISSING"

    echo
    echo "=== the hub's route table (one route per peer) ==="
    ip route show | grep -E "10\.(88|99)" || echo "(none — the pings below cannot work)"

    echo
    echo "=== ROUTED: $TUNNEL_A -> $TUNNEL_B (leaf B's subnet) ==="
    if ping -c 3 -W 2 "$TUNNEL_B"; then ROUTED_B=yes; else ROUTED_B=no; fi

    echo
    echo "=== ROUTED: $TUNNEL_A -> $TUNNEL_C (leaf C's subnet) ==="
    if ping -c 3 -W 2 "$TUNNEL_C"; then ROUTED_C=yes; else ROUTED_C=no; fi

    echo
    echo "=== CONTROL: $UNSERVED is served by nobody and must NOT be reachable ==="
    if ping -c 1 -W 2 "$UNSERVED" >/dev/null 2>&1; then
        CONTROL=no
        echo "UNEXPECTED: $UNSERVED answered"
    else
        CONTROL=yes
        echo "as expected: no route, no answer"
    fi

    # Diagnostic for the currently receipt-only Lightcone path. No service
    # policy declares this UDP endpoint; seeing it at B proves that causal
    # receipt publication is not a synchronous forwarding filter. Run only
    # when explicitly requested so the normal routing gate stays unchanged.
    FILTER_RESULT=not_run
    if [[ "${IMPERIUM_FILTER_PROBE:-}" == 1 ]]; then
        echo
        echo "=== FILTER DIAGNOSTIC: undeclared UDP service 45999 ==="
        nsenter --net="/proc/$PB/ns/net" -- python3 - "$WORK/udp-ready" "$WORK/udp-received" <<'PY' &
import pathlib
import socket
import sys

ready, received = map(pathlib.Path, sys.argv[1:])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
    listener.bind(("10.88.0.1", 45999))
    listener.settimeout(5)
    ready.touch()
    try:
        payload, _ = listener.recvfrom(128)
    except socket.timeout:
        pass
    else:
        if payload == b"imperium-filter-probe":
            received.touch()
PY
        UDP_LISTENER=$!
        for _ in $(seq 1 40); do
            [[ -e "$WORK/udp-ready" ]] && break
            sleep 0.05
        done
        python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
    sender.sendto(b"imperium-filter-probe", ("10.88.0.1", 45999))
PY
        wait "$UDP_LISTENER" || true
        if [[ -e "$WORK/udp-received" ]]; then
            FILTER_RESULT=failed
            echo "FILTER NOT WORKING: undeclared UDP service crossed the tunnel"
        else
            FILTER_RESULT=inconclusive
            echo "undeclared UDP service did not arrive; inspect logs before attributing cause"
        fi
    fi

    sleep 6
    echo
    echo "=== link health (the hub must show peers_established=2) ==="
    echo "--- hub A ---"
    strip_ansi < "$WORK/a.log" | grep -E "mesh link health" | tail -2 || echo "(none)"
    echo "--- leaf B ---"
    strip_ansi < "$WORK/b.log" | grep -E "mesh link health" | tail -1 || echo "(none)"
    echo "--- leaf C ---"
    strip_ansi < "$WORK/c.log" | grep -E "mesh link health" | tail -1 || echo "(none)"

    echo
    echo "=== passive Lightcone receipts from the running three-node cluster ==="
    if lightcone_status "$WORK/a/imperium/control.sock" hub; then LC_A=yes; else LC_A=no; fi
    if lightcone_status "$WORK/b/imperium/control.sock" leaf-b; then LC_B=yes; else LC_B=no; fi
    if lightcone_status "$WORK/c/imperium/control.sock" leaf-c; then LC_C=yes; else LC_C=no; fi

    echo
    echo "=== teardown: every route must be gone once the hub exits ==="
    kill "$PID_A" 2>/dev/null || true
    PID_A=""
    for _ in $(seq 1 40); do
        ip route show 2>/dev/null | grep -qE "10\.(88|99)" || break
        sleep 0.25
    done
    if ip route show 2>/dev/null | grep -qE "10\.(88|99)"; then
        TEARDOWN=no
        echo "LEAKED: a route survived the process"
        ip route show | grep -E "10\.(88|99)"
    else
        TEARDOWN=yes
        echo "removed: no peer routes remain"
    fi

    ESTABLISHED=$(strip_ansi < "$WORK/a.log" | grep -oE "peers_established=[0-9]+" | tail -1 | cut -d= -f2)
    echo
    echo "hub peers established: ${ESTABLISHED:-unknown} (2 expected)"
    echo "routing to leaf B : $([ "$ROUTED_B" = yes ] && echo PASS || echo FAIL)"
    echo "routing to leaf C : $([ "$ROUTED_C" = yes ] && echo PASS || echo FAIL)"
    echo "control (unserved): $([ "$CONTROL" = yes ] && echo PASS || echo FAIL)"
    echo "teardown          : $([ "$TEARDOWN" = yes ] && echo PASS || echo FAIL)"
    echo "Lightcone hub/B/C : $([ "$LC_A" = yes ] && [ "$LC_B" = yes ] && [ "$LC_C" = yes ] && echo PASS || echo FAIL)"
    if [[ "${IMPERIUM_FILTER_PROBE:-}" == 1 ]]; then
        echo "Lightcone filter  : ${FILTER_RESULT^^}"
        if [[ "$FILTER_RESULT" == failed ]]; then
            exit 1
        fi
        # No declared flow policy or positive control is present in this
        # scratch build; a missed datagram alone cannot certify filtering.
        exit 2
    fi
    if [ "$ESTABLISHED" = 2 ] && [ "$ROUTED_B" = yes ] && [ "$ROUTED_C" = yes ] \
        && [ "$CONTROL" = yes ] && [ "$TEARDOWN" = yes ] \
        && [ "$LC_A" = yes ] && [ "$LC_B" = yes ] && [ "$LC_C" = yes ]; then
        exit 0
    fi
    exit 1
fi

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

WORK="$(mktemp -d "${TMPDIR:-/tmp}/imperium-multipeer-test.XXXXXX")"
mkdir -m 700 -p "$WORK/a" "$WORK/b" "$WORK/c"
echo "work dir: $WORK"
# KEEP=1 leaves the logs behind for diagnosis.
trap 'if [ -z "${KEEP:-}" ]; then rm -rf "$WORK"; fi' EXIT

PLUMB=$(cat <<PLUMB_EOF
set -e
ip link set lo up
# The veth ends that stay here are the hub's. Only B and C get child
# namespaces, so the hub's namespace is this one — which is why the --inside
# half needs no nsenter for it.
ip link add va1 type veth peer name vb
ip link add va2 type veth peer name vc
# B and C live in child network namespaces. \$! names the unshare process,
# but /proc/\$!/ns/net only points at the NEW namespace once unshare(2) has run
# inside it -- before that it still points at this one, and moving a device
# "into" the namespace it is already in is refused. So wait for the transition
# rather than assume it: an assumption here fails as a setup error, which looks
# nothing like a mesh failure.
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
# Kill the namespace holders on the way out, including on failure: a leaked
# sleep command keeps its namespace (and its veth ends) alive for 15 minutes.
trap 'kill \$PB \$PC \$NSB_PID \$NSC_PID 2>/dev/null' EXIT
unshare -n bash -c 'ip link set lo up; exec sleep 900' &
NSB_PID=\$!
PB=\$NSB_PID
wait_for_ns "\$PB" "\$HUB_NS"
unshare -n bash -c 'ip link set lo up; exec sleep 900' &
NSC_PID=\$!
PC=\$NSC_PID
wait_for_ns "\$PC" "\$HUB_NS"
for _ in \$(seq 1 200); do
    [ "\$(readlink /proc/\$PB/ns/net 2>/dev/null)" != "\$HUB_NS" ] && [ "\$(readlink /proc/\$PC/ns/net 2>/dev/null)" != "\$HUB_NS" ] && break
    sleep 0.1
done
[ "\$(readlink /proc/\$PB/ns/net 2>/dev/null)" != "\$HUB_NS" ] || { echo "child namespace B never separated" >&2; exit 2; }
[ "\$(readlink /proc/\$PC/ns/net 2>/dev/null)" != "\$HUB_NS" ] || { echo "child namespace C never separated" >&2; exit 2; }
echo "\$PB \$PC" > "$WORK/pids"
ip link set vb netns "\$PB"
ip link set vc netns "\$PC"
ip addr add $UNDERLAY_A_B.1/24 dev va1
ip link set va1 up
ip addr add $UNDERLAY_A_C.1/24 dev va2
ip link set va2 up
nsenter --net=/proc/\$PB/ns/net ip addr add $UNDERLAY_A_B.2/24 dev vb
nsenter --net=/proc/\$PB/ns/net ip link set vb up
nsenter --net=/proc/\$PC/ns/net ip addr add $UNDERLAY_A_C.2/24 dev vc
nsenter --net=/proc/\$PC/ns/net ip link set vc up
exec "$0" --inside "$WORK"
PLUMB_EOF
)

echo "=== entering an unprivileged user namespace (no root, no capability grant) ==="
unshare -Urn bash -c "$PLUMB"
