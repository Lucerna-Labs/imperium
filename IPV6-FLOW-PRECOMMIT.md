# IPv6 packet and flow evidence precommit — 2026-09-30

This bounded experiment extends coverage evidence for the **unsealed**
networking Lightcone work. It does not modify the active v4 world, train or
promote a v5 pack, create host policy, or issue forwarding verdicts. Its
source mechanics are IPv6 header/extension/fragment rules in RFC 8200, UDP
header/checksum structure in RFC 768, and TCP opening/sequence behavior in
RFC 9293. The parser and tracker remain separate factual owners.

## Frozen cases and predictions

1. A valid IPv6 UDP packet behind one Destination Options header is parsed
   with its exact addresses, ports, and protocol. A reverse packet in the
   same authenticated-session **fixture** is observed as a reverse tuple;
   the same bytes under another session are only a new tuple.
2. A valid IPv6 TCP SYN, reversed SYN-ACK, and original ACK in one fixture
   session yield opening, response, and correlated-handshake facts. The
   byte-identical ACK without that history is unsupported midstream. A later
   ahead sequence/ACK is recorded as such, never labeled valid passage.
3. An IPv6 fragment returns an explicit fragment identity with no invented
   transport ports and is unsupported by the flow tracker without reassembly.
   A malformed UDP checksum and an unrepresented IPv6 echo form do not become
   represented flow facts.

Hard invariants: all packets are built from bounded wire fields with valid
checksums where required; no payload content selects causal nodes; peer and
session IDs in tests are fixtures, not authentication evidence; no test
returns an allow/deny or delivery claim. All declared cases must run once
under the current Rust parser/tracker. An unexpected result stays recorded
as a failure, with no threshold tuning or seal.

## Recorded result

`cargo test --offline -p imperium-net-mesh --test ipv6_flow_evidence` ran the
three declared groups and passed 3/3. IPv6 UDP (including a Destination
Options header) and TCP handshake facts matched their session histories;
the byte-identical orphan ACK was unsupported, an ahead sequence/ACK stayed
a factual ahead relation, the fragment had no ports, and malformed UDP and
unrepresented ICMPv6 echo did not become flow facts. This is parser/tracker
evidence only. The revision-5 condition catalog remains IPv4-only, the
Lightcone forwarding filter remains unenforced, and no pack was trained or
sealed by this test.
