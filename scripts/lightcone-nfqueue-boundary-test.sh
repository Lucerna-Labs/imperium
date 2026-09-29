#!/usr/bin/env bash
# Kernel NFQUEUE interception probe only. It does not run Imperium or Lightcone.
set -euo pipefail

if [[ "${1:-}" != "--inside" ]]; then
    if (( EUID == 0 )); then
        echo "Refusing root invocation: run as an unprivileged user." >&2
        exit 2
    fi
    exec unshare -Urn -- "$0" --inside
fi

read -r ns_uid host_uid ns_length < /proc/self/uid_map
if (( EUID != 0 || ns_uid != 0 || host_uid == 0 || ns_length != 1 )) ||
   [[ "$(readlink /proc/self/ns/net)" == "$(readlink /proc/1/ns/net)" ]]; then
    echo "Refusing to touch nftables outside a private, unprivileged user and network namespace." >&2
    exit 2
fi

for binary in ip nft nsenter ping unshare sysctl; do
    command -v "$binary" >/dev/null || { echo "Missing $binary" >&2; exit 2; }
done

table="imperium_lc_nfq_${BASHPID}_${RANDOM}"
queue_no=$((10000 + RANDOM % 50000))
peer_a=""
peer_b=""
cleanup() {
    nft delete table inet "$table" >/dev/null 2>&1 || true
    for peer in "$peer_a" "$peer_b"; do
        [[ -z "$peer" ]] || kill "$peer" >/dev/null 2>&1 || true
    done
    for peer in "$peer_a" "$peer_b"; do
        [[ -z "$peer" ]] || wait "$peer" 2>/dev/null || true
    done
}
trap cleanup EXIT

expect_pass() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '%s PASS\n' "$label"
    else
        printf '%s FAIL\n' "$label" >&2
        exit 1
    fi
}

expect_drop() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '%s UNEXPECTED DELIVERY\n' "$label" >&2
        exit 1
    else
        printf '%s BLOCKED\n' "$label"
    fi
}

# Three network namespaces: this router and two peers, linked only by veth.
unshare -n sleep 120 & peer_a=$!
unshare -n sleep 120 & peer_b=$!
sleep 0.2
ip link set lo up
ip link add lc0 type veth peer name lc1
ip link add lc2 type veth peer name lc3
ip link set lc1 netns "$peer_a"
ip link set lc3 netns "$peer_b"
ip addr add 198.18.5.1/30 dev lc0
ip addr add 198.18.6.1/30 dev lc2
ip -6 addr add fd42:496d:5::1/64 dev lc0 nodad
ip -6 addr add fd42:496d:6::1/64 dev lc2 nodad
ip link set lc0 up
ip link set lc2 up

nsenter -t "$peer_a" -n ip link set lo up
nsenter -t "$peer_a" -n ip addr add 198.18.5.2/30 dev lc1
nsenter -t "$peer_a" -n ip -6 addr add fd42:496d:5::2/64 dev lc1 nodad
nsenter -t "$peer_a" -n ip link set lc1 up
nsenter -t "$peer_a" -n ip route add 198.18.6.0/30 via 198.18.5.1
nsenter -t "$peer_a" -n ip -6 route add fd42:496d:6::/64 via fd42:496d:5::1
nsenter -t "$peer_b" -n ip link set lo up
nsenter -t "$peer_b" -n ip addr add 198.18.6.2/30 dev lc3
nsenter -t "$peer_b" -n ip -6 addr add fd42:496d:6::2/64 dev lc3 nodad
nsenter -t "$peer_b" -n ip link set lc3 up
nsenter -t "$peer_b" -n ip route add 198.18.5.0/30 via 198.18.6.1
nsenter -t "$peer_b" -n ip -6 route add fd42:496d:5::/64 via fd42:496d:6::1
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1

# Multiple IPv6 attempts warm neighbour discovery before the comparison.
expect_pass baseline_out_v4 ping -n -c 2 -W 2 198.18.5.2
expect_pass baseline_out_v6 ping -n -6 -c 3 -W 2 fd42:496d:5::2
expect_pass baseline_in_v4 nsenter -t "$peer_a" -n ping -n -c 2 -W 2 198.18.5.1
expect_pass baseline_in_v6 nsenter -t "$peer_a" -n ping -n -6 -c 3 -W 2 fd42:496d:5::1
expect_pass baseline_fwd_v4 nsenter -t "$peer_a" -n ping -n -c 2 -W 2 198.18.6.2
expect_pass baseline_fwd_v6 nsenter -t "$peer_a" -n ping -n -6 -c 3 -W 2 fd42:496d:6::2
expect_pass baseline_lo_v4 ping -n -c 1 -W 1 127.0.0.1
expect_pass baseline_lo_v6 ping -n -6 -c 1 -W 1 ::1

nft add table inet "$table"
for hook in input output forward; do
    nft "add chain inet $table $hook { type filter hook $hook priority 0; policy accept; }"
    nft "add rule inet $table $hook meta nfproto ipv4 counter queue num $queue_no"
    nft "add rule inet $table $hook meta nfproto ipv6 counter queue num $queue_no"
done

expect_drop no_listener_out_v4 ping -n -c 2 -W 1 198.18.5.2
expect_drop no_listener_out_v6 ping -n -6 -c 2 -W 1 fd42:496d:5::2
expect_drop no_listener_in_v4 nsenter -t "$peer_a" -n ping -n -c 2 -W 1 198.18.5.1
expect_drop no_listener_in_v6 nsenter -t "$peer_a" -n ping -n -6 -c 2 -W 1 fd42:496d:5::1
expect_drop no_listener_fwd_v4 nsenter -t "$peer_a" -n ping -n -c 2 -W 1 198.18.6.2
expect_drop no_listener_fwd_v6 nsenter -t "$peer_a" -n ping -n -6 -c 2 -W 1 fd42:496d:6::2
expect_drop no_listener_lo_v4 ping -n -c 1 -W 1 127.0.0.1
expect_drop no_listener_lo_v6 ping -n -6 -c 1 -W 1 ::1

rules=$(nft -nn list table inet "$table")
printf '%s\n' "$rules"
if ! printf '%s\n' "$rules" | awk '
    /chain (input|output|forward) \{/ { hook = $2 }
    /counter packets/ && $6 > 0 { seen[hook ":" $3] = 1 }
    END {
        for (i = 1; i <= 3; i++) {
            hook = (i == 1 ? "input" : i == 2 ? "output" : "forward")
            if (!seen[hook ":2"] || !seen[hook ":10"]) exit 1
        }
    }
'; then
    echo "A required IPv4 or IPv6 queue hook saw no packets." >&2
    exit 1
fi

nft delete table inet "$table"
expect_pass recovery_out_v4 ping -n -c 1 -W 2 198.18.5.2
expect_pass recovery_out_v6 ping -n -6 -c 1 -W 2 fd42:496d:5::2
expect_pass recovery_fwd_v4 nsenter -t "$peer_a" -n ping -n -c 1 -W 2 198.18.6.2
expect_pass recovery_fwd_v6 nsenter -t "$peer_a" -n ping -n -6 -c 1 -W 2 fd42:496d:6::2
echo "Kernel NFQUEUE namespace interception PASS; no Lightcone gate was tested."
