"""Normalize independent Linux SLL2 pcaps; preserve bytes and unknown forms."""

import csv
import hashlib
import ipaddress
import json
import re
import struct
from pathlib import Path

MARKER = re.compile(rb"LCIO\|([a-z0-9_]+)\|(\d{3})\|synthetic\n")


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def decode_network(data, protocol):
    result = {"network_protocol": {0x0800: "ipv4", 0x86DD: "ipv6", 0x0806: "arp"}.get(protocol, "other")}
    offset = None
    upper = None
    network = data
    if protocol == 0x0800 and len(data) >= 20:
        length = int.from_bytes(data[2:4], "big")
        header = (data[0] & 15) * 4
        if data[0] >> 4 == 4 and 20 <= header <= len(data) and header <= length <= len(data):
            network = data[:length]
            result.update(source=str(ipaddress.ip_address(data[12:16])),
                          destination=str(ipaddress.ip_address(data[16:20])))
            upper, offset = data[9], header
            if int.from_bytes(data[6:8], "big") & 0x1FFF:
                offset = None
                result["fragment"] = True
    elif protocol == 0x86DD and len(data) >= 40 and data[0] >> 4 == 6:
        length = 40 + int.from_bytes(data[4:6], "big")
        if length <= len(data):
            network = data[:length]
            result.update(source=str(ipaddress.ip_address(data[8:24])),
                          destination=str(ipaddress.ip_address(data[24:40])))
            upper, offset = data[6], 40
            for _ in range(8):
                if upper not in (0, 43, 60, 44):
                    break
                if offset + 8 > len(network):
                    offset = None
                    break
                next_upper = network[offset]
                size = 8 if upper == 44 else (network[offset + 1] + 1) * 8
                if upper == 44 and int.from_bytes(network[offset + 2:offset + 4], "big") & 0xFFF8:
                    result["fragment"] = True
                    offset = None
                    break
                offset += size
                upper = next_upper
    if protocol in (0x0800, 0x86DD):
        result["raw_ip_sha256"] = checksum(network)
    result["transport"] = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}.get(upper, "other")
    payload = b""
    if offset is not None and offset <= len(network):
        segment = network[offset:]
        if upper == 17 and len(segment) >= 8:
            udp_length = int.from_bytes(segment[4:6], "big")
            result.update(source_port=int.from_bytes(segment[0:2], "big"),
                          destination_port=int.from_bytes(segment[2:4], "big"))
            payload = segment[8:min(udp_length, len(segment))]
            result["udp_payload_sha256"] = checksum(payload)
            if 41000 in (result["source_port"], result["destination_port"]):
                result["mesh_datagram_sha256"] = checksum(payload)
        elif upper == 6 and len(segment) >= 20:
            header = (segment[12] >> 4) * 4
            result.update(source_port=int.from_bytes(segment[0:2], "big"),
                          destination_port=int.from_bytes(segment[2:4], "big"), tcp_flags=segment[13])
            if 20 <= header <= len(segment):
                payload = segment[header:]
        elif upper in (1, 58) and len(segment) >= 8:
            result.update(icmp_type=segment[0], icmp_id=int.from_bytes(segment[4:6], "big"),
                          icmp_sequence=int.from_bytes(segment[6:8], "big"))
            payload = segment[8:]
    result["application_payload_hex"] = payload.hex()
    result["case_ids"] = [case.decode() + ":" + index.decode() for case, index in MARKER.findall(payload)]
    return result


def read_pcap(path, role, phase, interfaces):
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError("short pcap header")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
               b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    endian, scale = formats[data[:4]]
    link_type = struct.unpack(endian + "I", data[20:24])[0]
    if link_type != 276:
        raise ValueError(f"expected Linux SLL2 pcap, got link type {link_type}")
    records = []
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("truncated pcap record header")
        seconds, fraction, included, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        packet = data[offset:offset + included]
        if len(packet) != included or included < 20:
            raise ValueError("truncated SLL2 capture record")
        offset += included
        protocol = int.from_bytes(packet[0:2], "big")
        interface_index = int.from_bytes(packet[4:8], "big")
        packet_type = packet[10]
        record = {"record": len(records), "phase": phase, "role": role,
                  "time_ns": seconds * 1_000_000_000 + fraction * scale,
                  "interface_index": interface_index,
                  "interface": interfaces.get(interface_index, f"ifindex-{interface_index}"),
                  "direction": "out" if packet_type == 4 else "in",
                  "sll2_packet_type": packet_type, "captured_bytes": included,
                  "original_bytes": original, "truncated": included != original,
                  "captured_frame_sha256": checksum(packet), "captured_frame_hex": packet.hex()}
        record.update(decode_network(packet[20:], protocol))
        records.append(record)
    return records


def receipt_logs(path):
    if not Path(path).is_file():
        return []
    output = []
    for line in Path(path).read_text().splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        if "LIGHTCONE_RECEIPT" not in line:
            continue
        values = dict(re.findall(r"(\w+)=([^\s]+)", line))
        values["log_time"] = line.split()[0]
        output.append(values)
    return output


def export_packet_logs(run_dir, phase):
    root = Path(run_dir)
    summary = {}
    for role in ("hub", "source", "receiver"):
        control = root / role / "control"
        interfaces = json.loads((control / f"{phase}-interfaces.json").read_text())
        names = {entry["ifindex"]: entry["ifname"] for entry in interfaces}
        packets = read_pcap(control / f"{phase}.pcap", role, phase, names)
        destination = root / f"{phase}-{role}-packets.jsonl"
        destination.write_text("".join(json.dumps(record) + "\n" for record in packets))
        columns = ["record", "time_ns", "phase", "role", "interface", "direction", "network_protocol",
                   "transport", "source", "destination", "source_port", "destination_port",
                   "captured_bytes", "raw_ip_sha256", "mesh_datagram_sha256", "case_ids"]
        with (root / f"{phase}-{role}-packets.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(packets)
        index = {}
        for packet in packets:
            for key, kind in (("raw_ip_sha256", "RawIp"), ("mesh_datagram_sha256", "MeshDatagram")):
                if key in packet:
                    index.setdefault((kind, packet[key]), []).append(packet)
        receipts = receipt_logs(control / f"{phase}-node.log")
        for receipt in receipts:
            matches = index.get((receipt.get("frame_format"), receipt.get("query_sha256")), [])
            receipt["capture_records"] = [item["record"] for item in matches]
            expected_direction = "in" if receipt.get("direction") == "0" else "out"
            receipt["direction_capture_records"] = [item["record"] for item in matches
                                                     if item["direction"] == expected_direction]
        (root / f"{phase}-{role}-receipts.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in receipts))
        summary[role] = {"packets": len(packets), "truncated_packets": sum(p["truncated"] for p in packets),
                         "receipt_records": len(receipts),
                         "receipts_with_capture_hash_match": sum(bool(r["capture_records"]) for r in receipts),
                         "receipts_with_direction_match": sum(bool(r["direction_capture_records"]) for r in receipts)}
    return summary
