#!/usr/bin/env bash
# Owned user/network namespace only: kernel transport, not geometric filtering.
set -euo pipefail
task_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${IMPERIUM_QUEUE_PRIVATE_NS:-} != 1 ]]; then
  cargo build --offline --manifest-path "$task_root/Cargo.toml" -p imperium-net-host --example queue_lab
  exec unshare -Urn env IMPERIUM_QUEUE_PRIVATE_NS=1 IMPERIUM_QUEUE_LAB=1 "$0"
fi
[[ $(readlink /proc/self/ns/net) != "$(readlink /proc/1/ns/net)" ]]
[[ $(readlink /proc/self/ns/user) != "$(readlink /proc/1/ns/user)" ]]
[[ $(id -u) == 0 ]]
task_evidence=$(mktemp -d "$task_root/target/lightcone-queue-transport.XXXXXX")
task_reader_pid=
task_table=lc_transport_$$
task_queue=42779
cleanup() {
  if [[ -n $task_reader_pid ]]; then kill "$task_reader_pid" 2>/dev/null || true; wait "$task_reader_pid" 2>/dev/null || true; fi
  nft delete table inet "$task_table" 2>/dev/null || true
}
trap cleanup EXIT
ip link set lo up
echo "Evidence: $task_evidence"
probe() {
  local phase=$1 expected=$2
  for task_address in 127.0.0.1 ::1; do
    if ping -n -q -c 2 -W 1 "$task_address" >"$task_evidence/$phase-${task_address//:/_}.txt" 2>&1; then
      [[ $expected == pass ]]
    else
      [[ $expected == block ]]
      rg -q '0 received' "$task_evidence/$phase-${task_address//:/_}.txt"
    fi
  done
}
probe baseline pass
nft -f - <<NFT
add table inet $task_table
add chain inet $task_table output { type filter hook output priority 0; policy accept; }
add rule inet $task_table output counter queue num $task_queue
NFT
probe no-listener block
for task_mode in accept drop; do
  "$task_root/target/debug/examples/queue_lab" "$task_queue" "$task_mode" 25 >"$task_evidence/$task_mode.log" 2>&1 &
  task_reader_pid=$!
  for task_try in {1..50}; do
    if rg -q '^READY$' "$task_evidence/$task_mode.log"; then break; fi
    kill -0 "$task_reader_pid"
    sleep .1
  done
  rg -q '^READY$' "$task_evidence/$task_mode.log"
  if [[ $task_mode == accept ]]; then probe accept pass; else probe drop block; fi
  rg -q 'family=2 ' "$task_evidence/$task_mode.log"
  rg -q 'family=10 ' "$task_evidence/$task_mode.log"
  kill "$task_reader_pid"
  wait "$task_reader_pid" 2>/dev/null || true
  task_reader_pid=
  probe "$task_mode-reader-exit" block
done
nft -j list table inet "$task_table" >"$task_evidence/rules.json"
nft delete table inet "$task_table"
probe recovery pass
echo 'PASS: IPv4/IPv6 baseline, no listener, exact release/discard, reader exit and recovery'
