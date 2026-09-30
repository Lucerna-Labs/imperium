#!/usr/bin/env bash
# Reproduce the frozen three-VM baseline without host network configuration.
set -euo pipefail
umask 077

if test "$(id -u)" -eq 0; then
    echo 'Run this VM lab as your ordinary user, not root.' >&2
    exit 2
fi
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
for tool in qemu-system-x86_64 qemu-img curl python3 cargo dpkg-deb; do
    command -v "$tool" >/dev/null
done
test -r /dev/kvm && test -w /dev/kvm
image_dir="$repo_dir/target/lightcone-vm/images"
deps_dir="$repo_dir/target/lightcone-vm/deps"
mkdir -p "$image_dir" "$deps_dir"
image_name=noble-server-cloudimg-amd64.img
image_origin=https://cloud-images.ubuntu.com/noble/20260926
image_hash=6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2
if ! test -f "$image_dir/$image_name"; then
    curl --fail --location --show-error --output "$image_dir/$image_name" "$image_origin/$image_name"
fi
printf '%s  %s\n' "$image_hash" "$image_dir/$image_name" | sha256sum --check
if ! test -f "$image_dir/SHA256SUMS"; then
    curl --fail --location --show-error --output "$image_dir/SHA256SUMS" "$image_origin/SHA256SUMS"
fi
if ! test -x "$deps_dir/usr/bin/genisoimage"; then
    (cd "$deps_dir" && apt download genisoimage=9:1.1.11-3.5 && dpkg-deb -x genisoimage_1.1.11-3.5_amd64.deb .)
fi
cargo build --offline -p imperium-cli --example lab_operator_key
cargo build --offline -p imperium-cli
python3 scripts/lightcone-vm/phase1.py "$@"
