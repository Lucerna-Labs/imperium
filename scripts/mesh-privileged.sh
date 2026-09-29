#!/usr/bin/env bash
#
# Privileged mesh checks.
#
# Root (CAP_NET_ADMIN) is needed for exactly one thing here: creating a Linux
# TUN interface. The encrypted link itself runs unprivileged.
#
# Do NOT run `sudo cargo`. Two reasons: sudo's secure PATH does not include
# ~/.cargo/bin, so it fails with "cargo: command not found"; and even with the
# PATH fixed it leaves root-owned files in target/, which break your next
# non-root build. Build as yourself, then run only the resulting binary under
# sudo (or grant it the capability once).

set -euo pipefail

# Resolve the script's own location, FOLLOWING SYMLINKS. Without the readlink
# step, invoking this through a symlink on PATH (e.g. ~/.local/bin/...) makes
# BASH_SOURCE the symlink path, and `dirname/..` resolves to the symlink's
# directory instead of the repository — so the repo root comes out as ~/.local
# and every path below is wrong.
ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
cd "$ROOT"

usage() {
    cat <<'EOF'
usage: scripts/mesh-privileged.sh <command>

  tun-test   Build as yourself, then run the ignored TUN device test under sudo.
             Creates an interface, assigns 10.77.0.1/24, sets MTU 1280, brings
             it up, and tears it down on drop. Touches no routes.

  route-test Run the ignored route install/remove test. Needs CAP_NET_ADMIN,
             which an unprivileged user namespace provides, so no root is
             required — unlike the TUN device test below.

  grant      Grant cap_net_admin to the imperium binary so
             `imperium node start --tunnel-ip ...` can create the tunnel
             without sudo. A rebuild replaces the binary and drops the
             capability, so re-run this after rebuilding.

  show       Print the paths this script would use, and whether the capability
             is currently set.
EOF
}

host_test_binary() {
    # Ask cargo for the path instead of guessing the hash: the hash changes
    # with the build configuration and there are several stale ones in deps/.
    cargo test -p imperium-net-host --no-run --message-format=json 2>/dev/null \
        | grep -oE '"executable":"[^"]*imperium_net_host-[^"]*"' \
        | tail -1 | cut -d'"' -f4
}

cmd_tun_test() {
    echo "building the test binary as $(id -un) ..."
    cargo test -p imperium-net-host --no-run >/dev/null
    local bin
    bin="$(host_test_binary)"
    if [ -z "$bin" ]; then
        echo "could not locate the host test binary" >&2
        exit 1
    fi
    echo "running: sudo $bin --ignored --nocapture"
    sudo "$bin" --ignored --nocapture
}

cmd_route_test() {
    echo "building the test binary as $(id -un) ..."
    cargo test -p imperium-net-host --no-run >/dev/null
    local bin
    bin="$(host_test_binary)"
    if [ -z "$bin" ]; then
        echo "could not locate the host test binary" >&2
        exit 1
    fi
    if ! unshare -Urn true 2>/dev/null; then
        echo "unprivileged user namespaces unavailable; running under sudo" >&2
        sudo "$bin" --ignored --nocapture route
        return
    fi
    # A route needs a live interface under it, and a fresh netns has lo down.
    echo "running: unshare -Urn <test binary> --ignored route"
    unshare -Urn bash -c 'ip link set lo up; exec "$0" --ignored --nocapture route' "$bin"
}

cmd_grant() {
    echo "building the imperium binary as $(id -un) ..."
    cargo build -p imperium-cli >/dev/null
    local bin="$ROOT/target/debug/imperium"
    if [ ! -x "$bin" ]; then
        echo "not found: $bin" >&2
        exit 1
    fi
    sudo setcap cap_net_admin+ep "$bin"
    echo "granted cap_net_admin to $bin"
    echo "note: a rebuild replaces the binary and drops the capability."
    command -v getcap >/dev/null && getcap "$bin" || true
}

cmd_show() {
    local bin="$ROOT/target/debug/imperium"
    local test_bin
    test_bin="$(host_test_binary || true)"
    echo "repo root     : $ROOT"
    echo "imperium      : $bin $([ -x "$bin" ] && echo '(present)' || echo '(not built)')"
    echo "host test bin : ${test_bin:-(not built)}"
    if [ -x "$bin" ] && command -v getcap >/dev/null; then
        echo -n "capabilities  : "; getcap "$bin" || echo "(none)"
    fi
}

case "${1:-}" in
    tun-test) cmd_tun_test ;;
    route-test) cmd_route_test ;;
    grant)    cmd_grant ;;
    show)     cmd_show ;;
    *)        usage; exit 2 ;;
esac