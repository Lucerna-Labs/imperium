"""Strict binary encoding of source-bound static conditions and 48D geometry."""
import hashlib
import ipaddress
import json
import struct

HEADER, NODE, EDGE = 1044, 216, 16
SPLIT = {"train": 0, "validation": 1, "sealed_test": 2, "cross_composition": 3}
OP = {"eq": 0, "range": 1, "cidr": 2, "in": 3}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).digest()


def encode_term(term):
    field, operation, value = term["field"], term["operation"], term["value"]
    if field not in range(9) or operation not in OP:
        raise ValueError("unknown field/operation")
    if field in (0, 7):
        if operation != "eq" or type(value) is not bool:
            raise ValueError("boolean term type")
        raw = bytes((int(value),))
    elif field in (5, 6):
        if operation != "cidr":
            raise ValueError("address term operation")
        network = ipaddress.ip_network(value, strict=True)
        raw = bytes((network.version, network.prefixlen)) + network.network_address.packed
    else:
        values = [value] if operation == "eq" else value
        if operation not in ("eq", "range", "in") or not isinstance(values, list) or not values:
            raise ValueError("number term type")
        if any(type(item) is not int or not 0 <= item <= 65535 for item in values):
            raise ValueError("number term range")
        if operation == "range" and (len(values) != 2 or values[0] > values[1]):
            raise ValueError("interval term")
        raw = b"".join(struct.pack("<H", item) for item in values)
    if len(raw) > 255:
        raise ValueError("term too long")
    return bytes((field, OP[operation], len(raw))) + raw


def condition_record(edge):
    terms = edge["conditions"]
    if len(terms) > 64:
        raise ValueError("too many edge terms")
    return b"".join(encode_term(term) for term in terms)


def applies(term, facts):
    value = facts.get(str(term["field"]))
    if value is None:
        return False
    operation, expected = term["operation"], term["value"]
    if operation == "eq":
        return type(value) is type(expected) and value == expected
    if operation == "in":
        return type(value) is int and value in expected
    if operation == "range":
        return type(value) is int and expected[0] <= value <= expected[1]
    if operation == "cidr":
        return ipaddress.ip_address(value) in ipaddress.ip_network(expected)
    raise ValueError("unknown term")


def neighborhood(catalog, facts, ignore_conditions=False, include_untrained=False):
    root = next(i for i, n in enumerate(catalog["nodes"]) if n["passage_role"] == "input")
    nodes = {root}
    active = [e for e in catalog["edges"] if e["polarity"] == 1
              and (include_untrained or e["split"] == "train")
              and (ignore_conditions or all(applies(t, facts) for t in e["conditions"]))]
    changed = True
    while changed:
        changed = False
        for e in active:
            if e["source"] in nodes and e["target"] not in nodes:
                nodes.add(e["target"]); changed = True
    terminal = next(i for i, n in enumerate(catalog["nodes"]) if n["passage_role"] == "complete")
    return terminal in nodes


def build(catalog, source_hash, training_hash, points, center, basis, shadow):
    if len(points) != len(catalog["nodes"]) or any(len(row) != 48 for row in points):
        raise ValueError("full geometry dimensions")
    strings = bytearray()
    def metadata(value):
        raw = canonical(value)
        offset = len(strings); strings.extend(raw)
        return struct.pack("<II", offset, len(raw))
    node_records = []
    for i, node in enumerate(catalog["nodes"]):
        coordinates = list(points[i]) + list(shadow[i])
        node_records.append(metadata(node) + struct.pack("<52i", *coordinates))
    edge_records = []
    conditions = bytearray(b"LCPASS6\0" + struct.pack("<4H", 6,
        next(i for i, n in enumerate(catalog["nodes"]) if n["passage_role"] == "input"),
        next(i for i, n in enumerate(catalog["nodes"]) if n["passage_role"] == "complete"),
        len(catalog["edges"])) + source_hash)
    for edge in catalog["edges"]:
        raw = condition_record(edge)
        record = dict(edge, condition_sha256=digest(raw).hex())
        edge_records.append(struct.pack("<HHBbBB", edge["source"], edge["target"], 4,
                                        edge["polarity"], SPLIT[edge["split"]], 0) + metadata(record))
        conditions.extend(struct.pack("<H", len(edge["conditions"])) + raw)
    header = bytearray(b"ATLCNET2" + struct.pack("<4H", len(node_records), len(edge_records), 48, 6)
                       + struct.pack("<I", len(strings)) + source_hash + training_hash)
    header.extend(struct.pack("<48i", *center))
    header.extend(struct.pack("<192i", *(value for row in basis for value in row)))
    if len(header) != HEADER or any(len(r) != NODE for r in node_records) or any(len(r) != EDGE for r in edge_records):
        raise ValueError("pack record size")
    return bytes(header) + b"".join(node_records) + b"".join(edge_records) + strings, bytes(conditions)
