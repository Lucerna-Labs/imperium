#!/usr/bin/env python3
"""Validate the authored network v5 delta without promoting a runtime pack."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "crates/imperium-net-world/v5"
PARENT_PACK = ROOT / "crates/imperium-net-world/src/world.bin"
ALLOWED_RELATIONS = {"requires", "describes", "depends_on", "does_not_establish", "enables"}
ALLOWED_SPLITS = {"train", "validation", "sealed_test", "cross_composition"}
ALLOWED_KINDS = {"negative", "unknown", "adversarial"}
ALLOWED_CLASSES = {
    "source_grounded_mechanism", "implementation_observation", "unsupported_inference"
}
ALLOWED_RIGHTS = {"citation_only", "green_us"}


class ValidationError(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ValidationError(f"{path.name} must be a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def text_field(record: dict, key: str, where: str) -> str:
    value = record.get(key)
    require(isinstance(value, str) and bool(value.strip()), f"{where}: missing {key}")
    return value


def unique_ids(items: list, where: str) -> set[str]:
    seen: set[str] = set()
    for item in items:
        require(isinstance(item, dict), f"{where}: record is not an object")
        identifier = text_field(item, "id", where)
        require(identifier not in seen, f"{where}: duplicate id {identifier}")
        seen.add(identifier)
    return seen


def inherited_node_ids(pack: bytes) -> tuple[set[str], int, int]:
    require(len(pack) >= 1044 and pack[:8] == b"ATLCNET2", "parent pack format mismatch")
    node_count, edge_count = struct.unpack_from("<HH", pack, 8)
    require(0 < node_count <= 256 and edge_count <= 512, "parent pack count mismatch")
    strings = 1044 + 216 * node_count + 16 * edge_count
    ids: set[str] = set()
    for index in range(node_count):
        offset, length = struct.unpack_from("<II", pack, 1044 + index * 216)
        raw = pack[strings + offset : strings + offset + length]
        require(len(raw) == length, f"parent node {index} metadata truncated")
        try:
            identifier = json.loads(raw)["id"]
        except (ValueError, KeyError, TypeError) as error:
            raise ValidationError(f"parent node {index} metadata invalid: {error}") from error
        require(identifier not in ids, f"parent duplicate node {identifier}")
        ids.add(identifier)
    return ids, node_count, edge_count


def validate_sources(sources: dict, cache: Path | None) -> tuple[dict[str, dict], dict[str, str]]:
    require(sources.get("schema") == 1, "sources schema must be 1")
    records = sources.get("sources")
    require(isinstance(records, list) and records, "sources list missing")
    unique_ids(records, "sources")
    indexed: dict[str, dict] = {}
    checks: dict[str, str] = {}
    for record in records:
        identifier = record["id"]
        for key in ("title", "maintainer", "version", "uri", "sha256", "rights_uri", "attribution"):
            text_field(record, key, f"source {identifier}")
        uri = record["uri"]
        host = urlparse(uri).hostname
        require(host in {"www.rfc-editor.org", "nvlpubs.nist.gov"}, f"source {identifier}: non-primary host")
        require(re.fullmatch(r"[a-f0-9]{64}", record["sha256"]) is not None, f"source {identifier}: bad digest")
        require(isinstance(record.get("bytes"), int) and record["bytes"] > 0, f"source {identifier}: bad size")
        require(record.get("rights_lane") in ALLOWED_RIGHTS, f"source {identifier}: unresolved rights")
        require(record.get("training_use") == "original_factual_paraphrase_only", f"source {identifier}: raw-source training not allowed")
        if identifier.startswith("rfc"):
            require(record["rights_lane"] == "citation_only", f"source {identifier}: RFC rights overclaimed")
        if cache is not None:
            extension = Path(urlparse(uri).path).suffix
            cached = cache / f"{identifier}{extension}"
            try:
                contents = cached.read_bytes()
            except OSError as error:
                raise ValidationError(f"source {identifier}: local verification copy missing: {error}") from error
            require(len(contents) == record["bytes"], f"source {identifier}: size changed")
            require(sha256(contents) == record["sha256"], f"source {identifier}: hash changed")
            checks[identifier] = "hash_verified"
        else:
            checks[identifier] = "registry_only"
        indexed[identifier] = record
    return indexed, checks


def validate_refs(refs: object, sources: dict[str, dict], where: str) -> None:
    require(isinstance(refs, list) and refs, f"{where}: source_refs missing")
    for ref in refs:
        require(isinstance(ref, str) and "#" in ref, f"{where}: source section missing")
        source, section = ref.split("#", 1)
        require(source in sources and bool(section), f"{where}: unknown source/section {ref}")


def normalize(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def validate(v5: Path = V5, parent_pack: Path = PARENT_PACK, cache: Path | None = None) -> dict:
    paths = {name: v5 / name for name in ("registry.json", "sources.json", "splits.json", "curriculum.json", "PROTOCOL.md")}
    inputs = {name: sha256(path.read_bytes()) for name, path in paths.items()}
    registry = read_json(paths["registry.json"])
    source_file = read_json(paths["sources.json"])
    splits = read_json(paths["splits.json"])
    curriculum = read_json(paths["curriculum.json"])
    pack = parent_pack.read_bytes()
    parent_hash = sha256(pack)
    require(parent_hash == registry.get("parent_pack_sha256") == curriculum.get("parent_pack_sha256"), "parent pack hash mismatch")
    require(registry.get("open_world") is True, "registry must remain open-world")
    require(registry.get("schema") == splits.get("schema") == curriculum.get("schema") == 1, "schema mismatch")
    require(registry.get("revision") == splits.get("revision") == curriculum.get("revision"), "revision mismatch")
    supersedes = splits.get("supersedes")
    require(isinstance(supersedes, dict), "rejected pretraining split revision must be retained")
    archived = v5 / text_field(supersedes, "file", "supersedes")
    require(sha256(archived.read_bytes()) == supersedes.get("sha256"), "rejected split archive hash changed")
    require(read_json(archived).get("revision") == "network-v5-diagnostic-1", "rejected split revision missing")
    inherited, parent_nodes, parent_edges = inherited_node_ids(pack)
    sources, source_checks = validate_sources(source_file, cache)

    groups = splits.get("groups")
    require(isinstance(groups, list) and groups, "split groups missing")
    unique_ids(groups, "splits")
    group_split: dict[str, str] = {}
    for group in groups:
        identifier = group["id"]
        require(group.get("split") in ALLOWED_SPLITS, f"group {identifier}: invalid split")
        text_field(group, "reason", f"group {identifier}")
        group_split[identifier] = group["split"]
    require(set(group_split.values()) == ALLOWED_SPLITS, "all four splits must have groups")

    nodes = curriculum.get("nodes")
    edges = curriculum.get("edges")
    controls = curriculum.get("controls")
    require(isinstance(nodes, list) and isinstance(edges, list) and isinstance(controls, list), "curriculum collections missing")
    node_ids = unique_ids(nodes, "nodes")
    edge_ids = unique_ids(edges, "edges")
    unique_ids(controls, "controls")
    require(not (node_ids & inherited), "new node ID collides with parent")
    require(parent_nodes + len(nodes) <= 256 and len(nodes) <= 24, "first-slice node capacity exceeded")
    require(parent_edges + len(edges) <= 512 and len(edges) <= 48, "first-slice edge capacity exceeded")
    statements: set[str] = set()
    for node in nodes:
        identifier = node["id"]
        for key in ("title", "statement", "record_kind", "scope", "limitations", "as_of"):
            text_field(node, key, f"node {identifier}")
        require(node.get("epistemic_class") in ALLOWED_CLASSES, f"node {identifier}: unknown epistemic class")
        require(node.get("mechanism_group") in group_split, f"node {identifier}: unfrozen group")
        axes = node.get("coverage_axes")
        require(isinstance(axes, list) and len(set(axes)) >= 3, f"node {identifier}: sparse coverage axes")
        validate_refs(node.get("source_refs"), sources, f"node {identifier}")
        normalized = normalize(node["statement"])
        require(normalized not in statements, f"node {identifier}: normalized statement duplicate")
        statements.add(normalized)

    split_counts = collections.Counter()
    for edge in edges:
        identifier = edge["id"]
        for key in ("source", "target", "relation", "direction", "mechanism_group", "conditions", "exceptions", "evidence"):
            text_field(edge, key, f"edge {identifier}")
        require(edge["source"] in inherited | node_ids and edge["target"] in inherited | node_ids, f"edge {identifier}: dangling endpoint")
        require(edge["relation"] in ALLOWED_RELATIONS, f"edge {identifier}: undeclared relation")
        require(edge["direction"] == "forward", f"edge {identifier}: unsupported direction")
        require(edge.get("polarity") == (-1 if edge["relation"] == "does_not_establish" else 1), f"edge {identifier}: polarity mismatch")
        group = edge["mechanism_group"]
        require(group in group_split, f"edge {identifier}: unfrozen group")
        validate_refs(edge.get("source_refs"), sources, f"edge {identifier}")
        split_counts[group_split[group]] += 1
    require(all(split_counts[split] > 0 for split in ALLOWED_SPLITS), "empty edge split")
    by_edge = {edge["id"]: edge for edge in edges}
    full_host_facts = {
        "current_policy_version", "source_zone", "destination_zone",
        "source_endpoint", "destination_endpoint", "service", "direction",
        "validated_flow_state",
    }
    for identifier in ("v5e027", "v5e028", "v5e029"):
        require(identifier in by_edge, f"positive host-context bridge {identifier} missing")
        edge = by_edge[identifier]
        require(group_split[edge["mechanism_group"]] == "train", f"{identifier}: host bridge withheld from training")
        require("nist80041#executive_summary" in edge["source_refs"], f"{identifier}: host policy source absent")
        facts = edge.get("required_host_facts")
        require(isinstance(facts, list) and len(set(facts)) == len(facts), f"{identifier}: host fact list invalid")
        require(set(facts) <= full_host_facts and facts, f"{identifier}: undeclared host fact")
        require("host" in edge["conditions"].lower(), f"{identifier}: host condition not explicit")
    require(set(by_edge["v5e027"]["required_host_facts"]) == full_host_facts, "positive bridge omits a mandatory host fact")
    require("host decision" in by_edge["v5e027"]["exceptions"].lower(), "positive bridge lacks external decision boundary")
    require(group_split[by_edge["v5e015"]["mechanism_group"]] == "train", "packet-alone negative withheld from training")
    require(group_split[by_edge["v5e030"]["mechanism_group"]] == "cross_composition", "fragment composition not held out")

    control_counts = collections.Counter()
    for control in controls:
        identifier = control["id"]
        require(control.get("kind") in ALLOWED_KINDS, f"control {identifier}: unknown kind")
        require(control.get("mechanism_group") in group_split, f"control {identifier}: unfrozen group")
        text_field(control, "pair", f"control {identifier}")
        text_field(control, "expected", f"control {identifier}")
        validate_refs(control.get("source_refs"), sources, f"control {identifier}")
        control_counts[control["kind"]] += 1
    require(all(control_counts[kind] > 0 for kind in ALLOWED_KINDS), "negative/unknown/adversarial controls incomplete")
    require(any(control["id"] == "v5c007" and control["kind"] == "negative" for control in controls), "graph-reachability-is-not-release negative control missing")

    coverage = registry.get("coverage")
    frontier = registry.get("open_frontier")
    require(isinstance(coverage, list) and isinstance(frontier, list), "coverage registry missing")
    unique_ids(coverage, "coverage")
    unique_ids(frontier, "open_frontier")
    blockers = []
    for item in coverage:
        identifier = item["id"]
        status = item.get("status")
        require(status in {"authored", "blocked", "discovered"}, f"coverage {identifier}: invalid status")
        if status == "authored":
            for evidence in item.get("evidence", []):
                require((v5 / evidence).exists(), f"coverage {identifier}: absent authored evidence {evidence}")
            require(item.get("evidence"), f"coverage {identifier}: no authored evidence")
        if status != "authored" or item.get("gap"):
            blockers.append(f"coverage:{identifier}:{item.get('gap', status)}")
    for item in frontier:
        status = text_field(item, "status", f"frontier {item['id']}")
        text_field(item, "reason", f"frontier {item['id']}")
        if status != "retired":
            blockers.append(f"frontier:{item['id']}:{status}")
    if cache is None:
        blockers.append("source hashes have not been independently rechecked in this run")
    blockers.append("parent v4 original source/geometry/split/trainer inputs absent in active checkout")
    blockers.append("live three-node packet/flow release acceptance matrix not yet passed")

    return {
        "schema": 1,
        "status": "local_diagnostic_structural_valid",
        "release_ready": False,
        "revision": registry["revision"],
        "parent_pack_sha256": parent_hash,
        "input_sha256": inputs,
        "counts": {"parent_nodes": parent_nodes, "parent_edges": parent_edges, "new_nodes": len(nodes), "new_edges": len(edges)},
        "split_edge_counts": dict(sorted(split_counts.items())),
        "control_counts": dict(sorted(control_counts.items())),
        "source_checks": source_checks,
        "blockers": blockers,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v5", type=Path, default=V5)
    parser.add_argument("--parent-pack", type=Path, default=PARENT_PACK)
    parser.add_argument("--source-cache", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--release-check", action="store_true")
    arguments = parser.parse_args()
    try:
        report = validate(arguments.v5, arguments.parent_pack, arguments.source_cache)
    except (OSError, ValidationError) as error:
        print(json.dumps({"status": "invalid", "error": str(error)}, sort_keys=True))
        return 1
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.report:
        arguments.report.write_text(output, encoding="utf-8")
    print(output, end="")
    return 2 if arguments.release_check and report["blockers"] else 0


if __name__ == "__main__":
    sys.exit(main())
