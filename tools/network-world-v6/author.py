#!/usr/bin/env python3
"""Author fresh static conditional networking records; never train or release."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / "crates/imperium-net-world/v6"
FIELDS = {"valid": 0, "family": 1, "protocol": 2, "flow": 3, "service": 4,
          "source": 5, "destination": 6, "authenticated": 7, "wire_kind": 8}
FLOW = {"udp_open": 1, "udp_same": 2, "udp_reverse": 3, "tcp_syn": 4,
        "tcp_synack": 5, "tcp_handshake": 6, "tcp_segment": 7,
        "tcp_retransmission": 8, "icmp_request": 9, "icmp_reply": 10,
        "ndp_request": 11, "ndp_reply": 12, "arp_request": 13, "arp_reply": 14}
PROTOCOL = {"icmp": 1, "tcp": 6, "udp": 17, "ndp": 58, "arp": 206}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def term(field, operation, value):
    return {"field": FIELDS[field], "operation": operation, "value": value}


def author(destination, cache):
    if destination.exists():
        raise RuntimeError("refusing to replace an existing world revision")
    sources = []
    for number, sections, explanation in (
        (791, ["3.1", "3.2"], "Exact IPv4 length/header/checksum and fragment fields."),
        (768, ["Format"], "UDP fields and IPv4 optional transport checksum context; IPv6 rules are separately sourced to RFC 8200."),
        (792, ["Echo or Echo Reply"], "IPv4 echo request/reply identifier and sequence correspondence."),
        (826, ["Packet format"], "Ethernet/IPv4 ARP request and mapping reply fields; mapping is not identity."),
        (8200, ["3.", "4.5", "8.1"], "IPv6 header, exact payload, fragment boundary and required upper-layer checksums."),
        (4861, ["4.3", "4.4", "7.1"], "Neighbor solicitation/advertisement validation and request/target correspondence."),
        (9293, ["3.1", "3.3", "3.5"], "TCP fields, sequence progression and connection-establishment correspondence."),
    ):
        path = cache / f"rfc{number}.txt"
        raw = path.read_bytes()
        if not raw or f"{number}".encode() not in raw[:4000]:
            raise RuntimeError(f"invalid source cache: {path}")
        sources.append({"id": f"rfc{number}", "uri": f"https://www.rfc-editor.org/rfc/rfc{number}.txt",
                        "sha256": sha(raw), "rights_lane": "citation_only",
                        "sections": sections, "claim_relevance": explanation,
                        "training_material": "original factual paraphrases and typed mechanisms only"})
    nodes = []
    edges = []
    def node(identifier, role="mechanism", source="operator_lab_declaration"):
        index = len(nodes)
        nodes.append({"id": identifier, "title": identifier.replace("_", " "),
                      "passage_role": role, "source_ref": source,
                      "epistemic_class": "synthetic_deployment" if source == "operator_lab_declaration" else "source_grounded_mechanism"})
        return index
    def edge(source, target, conditions, source_ref, polarity=1, split="train"):
        edges.append({"id": f"v6e{len(edges):03d}", "source": source, "target": target,
                      "relation": "enables", "direction": "forward", "polarity": polarity,
                      "split": split, "conditions": conditions, "source_ref": source_ref})
    entry = node("bounded_packet_facts", "input", "rfc791#3.1")
    valid = node("validated_represented_packet", source="rfc791#3.1")
    edge(entry, valid, [term("valid", "eq", True)], "rfc791#3.1")
    terminal = node("complete_causal_packet_relationship", "complete")
    protocol_nodes = {}
    flow_nodes = {}
    for protocol, flow_names, source_ref in (
        ("udp", ["udp_open", "udp_same", "udp_reverse"], "rfc768#Format"),
        ("tcp", ["tcp_syn", "tcp_synack", "tcp_handshake", "tcp_segment", "tcp_retransmission"], "rfc9293#3.5"),
        ("icmp", ["icmp_request", "icmp_reply"], "rfc792#Echo or Echo Reply"),
        ("ndp", ["ndp_request", "ndp_reply"], "rfc4861#7.1"),
        ("arp", ["arp_request", "arp_reply"], "rfc826#Packet format"),
    ):
        p = node(f"represented_{protocol}", source=source_ref)
        protocol_nodes[protocol] = p
        edge(valid, p, [term("protocol", "eq", PROTOCOL[protocol])], source_ref)
        for name in flow_names:
            f = node(name, source=source_ref)
            flow_nodes[name] = f
            edge(p, f, [term("flow", "eq", FLOW[name])], source_ref)
    profiles = []
    def profile(identifier, protocol, family, source, target, services, kinds=(0,)):
        profiles.append({"id": identifier, "protocol": protocol, "family": family,
                         "source": str(ipaddress.ip_network(source)),
                         "destination": str(ipaddress.ip_network(target)),
                         "services": services, "wire_kinds": list(kinds),
                         "source_port_scope": "variable validated transport field",
                         "provenance": "explicit synthetic VM deployment declaration"})
    for subnet in ("192.0.2.0/24", "198.51.100.0/24"):
        profile("mesh_" + subnet.split('.')[0], "udp", 4, subnet, subnet, [41000], (1, 2, 3))
    profile("direct_udp4", "udp", 4, "192.0.2.0/24", "198.51.100.0/24", [45998])
    profile("direct_udp6", "udp", 6, "fd77::/64", "fd78::/64", [45998])
    profile("direct_tcp6", "tcp", 6, "fd77::/64", "fd78::/64", [46001])
    profile("tunnel_udp", "udp", 4, "10.0.0.0/8", "10.0.0.0/8", [45999])
    profile("tunnel_tcp", "tcp", 4, "10.0.0.0/8", "10.0.0.0/8", [46000])
    profile("tunnel_icmp", "icmp", 4, "10.0.0.0/8", "10.0.0.0/8", [0])
    for family, prefix in ((4, "127.0.0.0/8"), (6, "::1/128")):
        profile(f"loopback_udp{family}", "udp", family, prefix, prefix, [45997])
    for subnet in ("192.0.2.0/24", "198.51.100.0/24"):
        profile("arp_" + subnet.split('.')[0], "arp", 4, subnet, subnet, [0], (4, 5))
    profile("ndp", "ndp", 6, "::/0", "::/0", [0], (6, 7))
    for declaration in profiles:
        p = node("declared_" + declaration["id"])
        edge(p, terminal, [], "operator_lab_declaration")
        for flow_name, flow_node in flow_nodes.items():
            if flow_name.split('_')[0] != declaration["protocol"]:
                continue
            for reverse in (False, True):
                source = declaration["destination"] if reverse else declaration["source"]
                target = declaration["source"] if reverse else declaration["destination"]
                conditions = [term("family", "eq", declaration["family"]),
                              term("service", "in", declaration["services"]),
                              term("wire_kind", "in", declaration["wire_kinds"]),
                              term("source", "cidr", source), term("destination", "cidr", target)]
                edge(flow_node, p, conditions, "operator_lab_declaration")
                if source == target:
                    break
    invalid = node("invalid_packet_cannot_supply_relationship", source="rfc791#3.1")
    edge(entry, invalid, [term("valid", "eq", False)], "rfc791#3.1", -1)
    cold = node("untrained_relation_control", source="synthetic_control")
    edge(entry, cold, [term("protocol", "eq", 132)], "synthetic_control", split="sealed_test")
    edge(cold, terminal, [], "synthetic_control", split="sealed_test")
    catalog = {"schema": 6, "revision": "network-static-conditional-6", "world_version": 6,
               "scope": "explicit_synthetic_vm_deployment_patterns",
               "sealed": False, "passive": True, "dimensions": 48,
               "fields": FIELDS, "flow_values": FLOW, "sources": sources,
               "nodes": nodes, "edges": edges, "deployment_profiles": profiles,
               "training": {"seed": 73161, "steps": 1600, "learning_rate": 0.01,
                            "margin": 0.5, "positive_squared_distance_max": 0.02,
                            "unknown_false_paths_max": 0, "conditions_ignored_false_paths_min": 1,
                            "objective": "conditional positive continuity; negative/unknown context separation",
                            "platform": "local_diagnostic", "observer": "train_fitted_svd_4d_spatial_only"}}
    if len(nodes) > 256 or len(edges) > 512:
        raise RuntimeError("initial artifact exceeds existing world capacity")
    destination.mkdir(parents=True)
    (destination / "catalog.json").write_bytes(canonical(catalog) + b'\n')
    (destination / "SOURCE-AND-SPLIT-FREEZE.json").write_bytes(canonical({
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "catalog_sha256": sha(canonical(catalog) + b'\n'),
        "source_hashes": {s["id"]: s["sha256"] for s in sources},
        "train_edges": [e["id"] for e in edges if e["split"] == "train"],
        "cold_untrained_edges": [e["id"] for e in edges if e["split"] != "train"],
        "training_has_run": False,
        "split_note": "Known protocol/flow mechanisms train; unseen SCTP control never supplies runtime passage. New-instance tests within static variable scope are composition tests, not unseen-mechanism benefit claims."}) + b'\n')
    print(json.dumps({"nodes": len(nodes), "edges": len(edges), "directory": str(destination)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=DEFAULT)
    parser.add_argument("--source-cache", type=Path, required=True)
    args = parser.parse_args()
    author(args.destination, args.source_cache)
