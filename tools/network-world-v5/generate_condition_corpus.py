#!/usr/bin/env python3
"""Emit frozen raw-packet fixtures for revision-5 condition evidence.

This generator contains packet construction and independently authored
expected producer facts. It does not train a world or decide packet release.
The Rust replay test checks every expected fact against the actual parser and
flow tracker rather than trusting this generator as a producer.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / "crates/imperium-net-world/v5/revision-5/corpus.json"
CASE_DIRECTORY = DESTINATION.parent / "cases"
PEER = "11111111-1111-4111-8111-111111111111"
SESSIONS = {
    "udp": "22222222-2222-4222-8222-222222222222",
    "tcp": "33333333-3333-4333-8333-333333333333",
    "tcp_orphan": "44444444-4444-4444-8444-444444444444",
    "icmp": "55555555-5555-4555-8555-555555555555",
    "other": "66666666-6666-4666-8666-666666666666",
}
A = bytes((10, 1, 0, 1))
B = bytes((10, 2, 0, 2))
OBSERVER = "observer.parse_raw_ip_flow"
TRACKER = "mesh.FlowBehaviorTracker.observe_at"
EDGES = ("v5e003", "v5e004", "v5e006", "v5e008", "v5e009", "v5e027")


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(protocol: int, payload: bytes, source: bytes = A, target: bytes = B,
         flags_offset: int = 0, identification: int = 0x1234) -> bytes:
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = struct.pack("!H", 20 + len(payload))
    header[4:6] = struct.pack("!H", identification)
    header[6:8] = struct.pack("!H", flags_offset)
    header[8] = 64
    header[9] = protocol
    header[12:16] = source
    header[16:20] = target
    header[10:12] = struct.pack("!H", checksum(bytes(header)))
    return bytes(header) + payload


def udp(source_port: int, target_port: int, source: bytes = A,
        target: bytes = B, flags_offset: int = 0) -> bytes:
    # Zero UDP checksum is represented by the current IPv4 observer.
    segment = struct.pack("!HHHH", source_port, target_port, 8, 0)
    return ipv4(17, segment, source, target, flags_offset)


def tcp(source_port: int, target_port: int, sequence: int, acknowledgment: int,
        flags: int, source: bytes = A, target: bytes = B) -> bytes:
    segment = bytearray(20)
    segment[0:2] = struct.pack("!H", source_port)
    segment[2:4] = struct.pack("!H", target_port)
    segment[4:8] = struct.pack("!I", sequence)
    segment[8:12] = struct.pack("!I", acknowledgment)
    segment[12] = 0x50
    segment[13] = flags
    segment[14:16] = struct.pack("!H", 4096)
    pseudo = source + target + struct.pack("!BBH", 0, 6, len(segment))
    segment[16:18] = struct.pack("!H", checksum(pseudo + segment))
    return ipv4(6, bytes(segment), source, target)


def icmp(message_type: int, identifier: int, sequence: int,
         source: bytes = A, target: bytes = B) -> bytes:
    message = bytearray(struct.pack("!BBHHH", message_type, 0, 0, identifier, sequence))
    message[2:4] = struct.pack("!H", checksum(bytes(message)))
    return ipv4(1, bytes(message), source, target)


def known_facts(protocol: str, fragmented: bool, event: str | None,
                source_port: int | None = None, target_port: int | None = None) -> list[dict]:
    facts = [
        {"id": "packet.validation", "value": "fragment" if fragmented else "parsed", "producer": OBSERVER},
        {"id": "packet.ip_version", "value": "ipv4", "producer": OBSERVER},
        {"id": "packet.next_protocol", "value": protocol, "producer": OBSERVER},
        {"id": "packet.fragmented", "value": fragmented, "producer": OBSERVER},
        {"id": "packet.transport_complete", "value": not fragmented, "producer": OBSERVER},
    ]
    if source_port is not None and target_port is not None:
        facts.extend((
            {"id": "packet.source_port", "value": source_port, "producer": OBSERVER},
            {"id": "packet.destination_port", "value": target_port, "producer": OBSERVER},
        ))
    if event is not None:
        facts.append({"id": "flow.event", "value": event, "producer": TRACKER})
    return facts


def row(identifier: str, packet: bytes, session: str, direction: str,
        at_ms: int, facts: list[dict], values: tuple[str, str, str, str, str, str],
        control: str) -> dict:
    return {
        "id": identifier,
        "control": control,
        "peer_id": PEER,
        "session_id": SESSIONS[session],
        "direction": direction,
        "at_ms": at_ms,
        "packet_hex": packet.hex(),
        "packet_sha256": hashlib.sha256(packet).hexdigest(),
        "facts": facts,
        "expected_applicability": dict(zip(EDGES, values, strict=True)),
        "expected_delivery": "unobserved",
    }


def main() -> None:
    tcp_ack = tcp(40001, 443, 1001, 2001, 0x10)
    udp_reply = udp(5353, 40000, B, A)
    cases = [
        row("udp_service_a", udp(40000, 5353), "udp", "outbound", 0,
            known_facts("udp", False, "udp_tuple_observed", 40000, 5353),
            ("false", "true", "false", "false", "false", "unknown"), "same_shape_service"),
        row("udp_service_b_same_shape", udp(40000, 9999), "udp", "outbound", 10,
            known_facts("udp", False, "udp_tuple_observed", 40000, 9999),
            ("false", "true", "false", "false", "false", "unknown"), "same_shape_service"),
        row("udp_reverse_correlated", udp_reply, "udp", "inbound", 1000,
            known_facts("udp", False, "udp_reverse_tuple_observed", 5353, 40000),
            ("false", "true", "false", "false", "false", "unknown"), "udp_lifetime"),
        row("udp_reverse_after_expiry", udp_reply, "udp", "inbound", 121001,
            known_facts("udp", False, "udp_tuple_observed", 5353, 40000),
            ("false", "true", "false", "false", "false", "unknown"), "udp_lifetime"),
        row("tcp_syn", tcp(40001, 443, 1000, 0, 0x02), "tcp", "outbound", 0,
            known_facts("tcp", False, "tcp_syn_observed", 40001, 443),
            ("true", "false", "false", "false", "false", "unknown"), "tcp_progression"),
        row("tcp_synack_correlated", tcp(443, 40001, 2000, 1001, 0x12, B, A), "tcp", "inbound", 10,
            known_facts("tcp", False, "tcp_synack_correlated", 443, 40001),
            ("true", "false", "false", "false", "true", "unknown"), "tcp_progression"),
        row("tcp_ack_correlated", tcp_ack, "tcp", "outbound", 20,
            known_facts("tcp", False, "tcp_handshake_correlated", 40001, 443),
            ("true", "false", "false", "true", "false", "unknown"), "tcp_progression"),
        row("tcp_ack_ahead", tcp(40001, 443, 5000, 2001, 0x10), "tcp", "outbound", 30,
            known_facts("tcp", False, "tcp_segment_ahead", 40001, 443),
            ("true", "false", "false", "false", "false", "unknown"), "tcp_progression"),
        row("tcp_orphan_ack", tcp_ack, "tcp_orphan", "outbound", 21,
            known_facts("tcp", False, "tcp_midstream_unsupported", 40001, 443),
            ("true", "false", "false", "false", "false", "unknown"), "tcp_progression"),
        row("icmp_echo_request", icmp(8, 9, 7), "icmp", "outbound", 0,
            known_facts("icmpv4", False, "icmp_echo_request_observed"),
            ("false", "false", "false", "false", "false", "unknown"), "icmp_correlation"),
        row("icmp_echo_reply_correlated", icmp(0, 9, 7, B, A), "icmp", "inbound", 10,
            known_facts("icmpv4", False, "icmp_echo_reply_correlated"),
            ("false", "false", "false", "false", "false", "unknown"), "icmp_correlation"),
        row("icmp_echo_wrong_identifier", icmp(0, 10, 7, B, A), "icmp", "inbound", 20,
            known_facts("icmpv4", False, "icmp_unmatched_reply_unsupported"),
            ("false", "false", "false", "false", "false", "unknown"), "icmp_correlation"),
        row("ipv4_udp_fragment", udp(40000, 5353, flags_offset=0x2000), "other", "outbound", 0,
            known_facts("udp", True, "fragmented_unsupported"),
            ("false", "false", "true", "false", "false", "unknown"), "fragment_unknown"),
        row("unsupported_upper_protocol", ipv4(132, b""), "other", "outbound", 10,
            [{"id": "packet.validation", "value": "unsupported", "producer": OBSERVER}],
            ("false", "false", "false", "unknown", "unknown", "unknown"), "unknown_protocol"),
    ]
    malformed = bytearray(udp(40000, 5353))
    malformed[10] ^= 1
    cases.append(row("malformed_ipv4_checksum", bytes(malformed), "other", "outbound", 20,
                     [{"id": "packet.validation", "value": "malformed", "producer": OBSERVER}],
                     ("false", "false", "false", "unknown", "unknown", "unknown"), "malformed_packet"))
    CASE_DIRECTORY.mkdir(exist_ok=True)
    references = []
    for case in cases:
        relative = f"cases/{case['id']}.json"
        contents = (json.dumps(case, indent=2) + "\n").encode("utf-8")
        (DESTINATION.parent / relative).write_bytes(contents)
        references.append({"id": case["id"], "file": relative,
                           "sha256": hashlib.sha256(contents).hexdigest()})
    document = {
        "schema": 1,
        "revision": "network-v5-condition-evidence-1",
        "scope": "offline_parser_and_flow_facts_only",
        "producer_binding": "actual Rust parser and tracker checked by v5_condition_evidence.rs",
        "cases": references,
    }
    DESTINATION.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
