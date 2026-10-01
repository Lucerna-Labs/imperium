# Lightcone VM input/output result — 2026-10-01

**The current Lightcone had no observed forwarding effect in this bounded
test.** All 49 probes received replies with healthy Lightcone strands, and
all 49 still received replies after all three strands were quarantined.
Independent ingress/egress captures, receiver data logs, and exact receipt
hash joins support the result. This does not establish a useful causal filter.

## Actual measured setup

Source at accepted run start: clean `9b8c6b9` on `work/unsealed-lightcone`.
Run: `target/lightcone-vm/io-runs/20261001-095948/`.
Three fresh Ubuntu 24.04.5/KVM guests used kernel `6.8.0-142-generic`, QEMU
8.2.2, two private Unix-socket virtual Ethernet links and directory/serial/QMP
management. Each VM's KVM state was independently checked through QMP. No
Internet test target, real-host rule, route, interface or existing VM was used.
All three owned VMs stopped. The manifest binds source, binary, guest image,
guest interface/ifindex maps and world hashes.

World SHA-256 stayed
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`:
v4, 208 concepts, 188 relationships, 48D, local_diagnostic, passive and
**unsealed**. Every node continued to report `filter_enforced=false`.

The same configured three-node mesh, routes, identities, synthetic payload
IDs and traffic counts ran in both arms. The quarantined arm alone enabled
the existing crash-after-one-frame drill. All three Lightcone lifecycle
states were checked as `quarantined` before and after the measured traffic;
mesh runners and independent echo-server workers remained alive. Fresh
handshake keys and ordinary kernel TCP/IP fields vary across native node
restarts; the comparison uses matched application bytes/IDs and protocol
operations, not bit-identical encrypted underlay frames.

## Data entering and leaving the hub

| Path/case | Probes | Healthy hub requests in/out | Healthy replies | Quarantined hub requests in/out | Quarantined replies |
| --- | ---: | --- | ---: | --- | ---: |
| Native mesh/TUN IPv4 UDP | 10 | 10/10 | 10 | 10/10 | 10 |
| Native mesh/TUN IPv4 TCP | 5 | 5/5 | 5 | 5/5 | 5 |
| Native mesh/TUN IPv4 ICMP | 3 | 3/3 | 3 | 3/3 | 3 |
| Ordinary forwarded IPv4 UDP | 10 | 10/10 | 10 | 10/10 | 10 |
| Ordinary forwarded IPv6 UDP | 10 | 10/10 | 10 | 10/10 | 10 |
| Ordinary forwarded IPv6 TCP | 5 | 5/5 | 5 | 5/5 | 5 |
| Local IPv4 UDP loopback | 3 | Local capture + app logs | 3 | Local capture + app logs | 3 |
| Local IPv6 UDP loopback | 3 | Local capture + app logs | 3 | Local capture + app logs | 3 |
| **Total** | **49** | | **49** | | **49** |

There are 46 application messages and 3 ICMP probes per arm. All 46 messages
arrived with the same payload SHA-256 as their corresponding send log, with
zero receiver duplicates, payload mismatches or client errors in either arm.
The independent receiver captures contain every expected request ID. These
are messages/probes, not a count of all wire frames: TCP handshakes, ACKs,
encrypted mesh frames, ARP and NDP are also logged in the pcaps/packet JSONL.
IP TTL/checksum changes caused by routing are preserved, rather than described
as unchanged packet bytes.

Loopback remains inside the same guest and has no external NIC egress.
Linux cooked capture labels/de-duplicates loopback packets differently from
forwarded NIC traffic. The raw direction field is retained; local delivery
is checked through application logs and replies. A zero NIC-style `out`
count in a loopback row must not be interpreted as blocked local delivery.

## Lightcone receipt comparison

| Arm | Hub receipts | Source receipts | Receiver receipts | Exact capture hash/direction matches |
| --- | ---: | ---: | ---: | --- |
| Healthy | 452 | 233 | 233 | **918/918** |
| Quarantined | 4 | 4 | 4 | **12/12**, all startup/drill receipts |

The quarantined counters stopped at four per node before the case matrix and
remained there through its end. Its measured case requests generated no new
Lightcone receipts, yet still crossed and received replies. In the healthy
hub, tagged tunnel requests joined 20 UDP, 10 TCP and 6 ICMP RawIp receipt
records across its input/output boundaries. Tagged ordinary direct IP and
loopback requests joined **zero** RawIp receipts, while being delivered.

Receipt tracing logs sequence, direction, format, observation kind and exact
world/query/receipt hashes after successful receipt publication. It logs no
raw payload or key and changes no admission, world or packet verdict. Packet
bytes are independently retained by tcpdump in the owned lab. RawIp queries
are joined to captured IP bytes; MeshDatagram queries to captured UDP payloads.
The normalized SLL2 field layout/direction values were checked against
[libpcap's own header](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap/sll.h).
Per-role receipt JSONL retains the exact matching packet-record indices.

## Independent measurement control

| Guest-only ordinary-forwarding control | Requests captured at hub input | Requests at hub output | Receiver IDs | Replies |
| --- | ---: | ---: | ---: | ---: |
| NFQUEUE rule, no listener/bypass | 5 | **0** | **0** | **0** |
| Remove only that test table | 3 | **3** | **3** | **3** |

The test rule's counter recorded the blocked requests. The source/receiver
applications remained alive. This control proves that these logging boundaries
can distinguish passage from blocking; it is a kernel measurement control,
not Lightcone filtering or a trained release rule. All guest captures in the
accepted run reported zero kernel drops and every normalized record was full
length with zero truncation.

## Preserved capture setup failures

The original frozen matrix and resource revision are in
`LIGHTCONE-VM-IO-PRECOMMIT-2026-10-01.md` and
`LIGHTCONE-VM-IO-CAPTURE-REV2-2026-10-01.md`.

- `20261001-094907`: both traffic arms delivered 49/49, but the buffered hub
  recovery capture stopped before its pending ring packets were read. It had
  0 captured/12 filter-received packets even though the receiver got all three
  replies. Measurement-control acceptance failed; that is a logging setup
  failure, not a Lightcone effect.
- `20261001-095519`: immediate capture with a 4 MiB buffer reported 42 hub
  kernel drops. The test stopped after the healthy arm, before a matched
  comparison. It is not accepted evidence for full input/output accounting.
- Revision 2 retained full snaplen and immediate capture, added bounded
  pre-stop draining and a 64 MiB buffer per guest. The accepted run above
  passed the original case counts, zero-loss and blocking/recovery checks.

The failures and their original private overlays/logs are retained. Small
failure summaries are exported alongside the accepted synthetic data.

## Logs to inspect

The committed measurement directory is `evidence/lightcone-vm-io-20261001/`:

- `comparison.json` / `comparison.md`: per-case counts and paired effect flags.
- `healthy-hub-packets.csv` / `quarantined-hub-packets.csv`: timestamps,
  interfaces, direction, addresses, ports, lengths and hashes at the hub.
- Corresponding `*-packets.jsonl`: every captured record's raw bytes as hex,
  exact IP/UDP/frame hashes, protocol fields and synthetic case IDs.
- Each guest's `control/*.pcap`: raw captures, including unrecognized forms,
  ARP/NDP and opaque encrypted underlay bytes in the measured windows.
- `healthy-*-receipts.jsonl` / `quarantined-*-receipts.jsonl`: receipt metadata
  and exact packet-record hash/direction joins.
- Each guest's `control/application.jsonl` and `*-client.json`: bytes sent,
  independently received and echoed, errors and descriptive roundtrip timings.
- `application-integrity.json`, status snapshots, node logs, capture counters,
  exact QEMU/guest commands, and `evidence-hashes.json` bind the evidence.

Private guest signing keys, original disks and input binaries stay in the
owner-only local run directory and are excluded from export. All payloads in
this measurement are bounded synthetic test data.

## What the data establishes

For this current runtime and declared VM matrix, packet passage does not
depend on the Lightcone receipt strand being operational. Healthy geometry
produces reproducible wire-bound receipts, but a quarantined geometry strand
does not stop the same traffic, and direct/loopback paths bypass its RawIp
observation path. This is empirical evidence that the requested causal
traffic gate is not enforced here.

The result does not assess every protocol/host path, prove a trained world
benefit, or provide physical-host/accelerator acceptance. It does not certify
any packet as causally allowed. A valid conditioned world and a separately
owned synchronous release boundary remain necessary; the Lightcone stays
passive and unsealed while those parts are built and measured.
