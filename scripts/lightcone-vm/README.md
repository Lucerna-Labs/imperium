# Private Lightcone VM lab

Run from the Imperium checkout as the ordinary user:

```bash
bash scripts/lightcone-vm-test.sh
```

For the frozen input/output effect comparison, use:

```bash
bash scripts/lightcone-vm-test.sh --io
```

This mode captures all three guests' attached interfaces, generates bounded
synthetic UDP/TCP/ICMP and loopback traffic, and compares the same cases with
healthy and deliberately quarantined Lightcone strands. It also proves that
the independent ingress/egress measurement can detect a guest-only no-listener
blocking control. Raw pcaps, full captured bytes as packet JSONL, compact CSV,
application send/receive logs, Lightcone receipt/hash correlation, status,
capture-loss counts and a readable comparison are retained under
`target/lightcone-vm/io-runs/<timestamp>/`. See
`LIGHTCONE-VM-IO-PRECOMMIT-2026-10-01.md` for the exact matrix and limits.

Requires QEMU/KVM access, Python, curl, Cargo's cached workspace dependencies,
and host nft/tcpdump executables. The wrapper obtains a pinned official Ubuntu
24.04 cloud image and a local extracted genisoimage package if absent. It does
not install system packages. Builds the native Imperium executable and the
native operator-key fixture helper. Image SHA-256 is checked before boot.

Three fresh 3 GiB/two-vCPU guests run on KVM with disposable qcow2 overlays.
The hub has two private Unix-socket Ethernet links; source and receiver have
one each. No NAT/user/TAP/physical bridge backend is attached. The dedicated
read-only input share and per-guest control/evidence shares provide management
without an IP exception. No host firewall, route, interface, or existing VM
configuration is changed. Shutdown targets only the three subprocesses owned
by this run. The local artifact directories and socket directory are retained.

`LIGHTCONE-VM-PRECOMMIT.md` freezes the matrix and its limits. The script
returns 1 for setup/control/integration failure, 3 when the undeclared UDP
probe crosses (filter failure), and 2 for non-arrival without an enforced
causal gate (inconclusive). **Read `report.json` for each measured result**.
The current v4 baseline must not be reported as useful filtering. An undeclared
UDP arrival is a filter failure; non-arrival without an enforced causal gate
is inconclusive. The Lightcone stays unsealed throughout.

Evidence is under `target/lightcone-vm/runs/<timestamp>/`: exact VM/guest
commands, KVM identity, image/source/binary/world hashes, independent receiver
pcaps, eight-path results, receipt statuses, and serial/node logs. This private
directory also contains ephemeral guest key files and disks. Do not commit
the whole directory. Export only the small allowlisted evidence with:

```bash
python3 scripts/lightcone-vm/export_evidence.py <run-directory> <new-evidence-directory>
```

Image source: https://cloud-images.ubuntu.com/noble/20260926/
Guest seed: cloud-init's NoCloud `cidata` disk.
QEMU stream backend documentation: https://www.qemu.org/docs/master/system/invocation.html

Guest kernel/image differs from the real host. VM IP queue results do not
cover physical NIC offload, ARP/link-layer gates, additional namespaces, or
host boot persistence. Those paths remain explicit future experiments.
