#!/usr/bin/env python3
"""Validate revision-5 typed condition evidence without training or release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "crates/imperium-net-world/v5/revision-5"
SOURCE_REGISTRY = ROOT / "crates/imperium-net-world/v5/revision-4/sources.json"
PARENT_CURRICULUM = ROOT / "crates/imperium-net-world/v5/revision-4/curriculum.json"
PARENT_PACK = ROOT / "crates/imperium-net-world/src/world.bin"
REVISION_ID = "network-v5-condition-evidence-1"
PARENT_PACK_HASH = "7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf"
CASES = (
    "udp_service_a", "udp_service_b_same_shape", "udp_reverse_correlated",
    "udp_reverse_after_expiry", "tcp_syn", "tcp_synack_correlated",
    "tcp_ack_correlated", "tcp_ack_ahead", "tcp_orphan_ack",
    "icmp_echo_request", "icmp_echo_reply_correlated",
    "icmp_echo_wrong_identifier", "ipv4_udp_fragment",
    "unsupported_upper_protocol", "malformed_ipv4_checksum",
)
PRODUCERS = {"observer.parse_raw_ip_flow", "mesh.FlowBehaviorTracker.observe_at"}
KINDS = {"bool", "enum", "u16", "u32", "u64"}
TRUTH = {"true", "false", "unknown"}


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def document(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read {path}: {error}") from error
    require(isinstance(data, dict), f"{path.name}: not an object")
    return data


def unique(records: list[dict], label: str) -> dict[str, dict]:
    require(isinstance(records, list) and bool(records), f"{label}: empty")
    result: dict[str, dict] = {}
    for item in records:
        require(isinstance(item, dict), f"{label}: item not an object")
        identifier = item.get("id")
        require(isinstance(identifier, str) and bool(identifier), f"{label}: missing id")
        require(identifier not in result, f"{label}: duplicate id {identifier}")
        result[identifier] = item
    return result


def check_type(spec: dict, value: object, where: str) -> None:
    kind = spec["type"]
    if kind == "bool":
        require(type(value) is bool, f"{where}: expected bool")
    elif kind == "enum":
        require(value in spec["values"] and type(value) is str, f"{where}: invalid enum")
    else:
        bits = int(kind[1:])
        require(type(value) is int and 0 <= value < 2**bits, f"{where}: invalid {kind}")


def predicates(path: Path) -> dict[str, dict]:
    data = document(path)
    require(data.get("schema") == 1 and data.get("revision") == REVISION_ID,
            "predicate schema/revision mismatch")
    indexed = unique(data.get("predicates"), "predicates")
    for identifier, item in indexed.items():
        require(set(item) in (
            {"id", "type", "scope", "producer", "available"},
            {"id", "type", "values", "scope", "producer", "available"},
        ), f"predicate {identifier}: invalid keys")
        require(item.get("type") in KINDS, f"predicate {identifier}: invalid type")
        require(isinstance(item.get("scope"), str) and bool(item["scope"]),
                f"predicate {identifier}: invalid scope")
        require(isinstance(item.get("producer"), str) and bool(item["producer"]),
                f"predicate {identifier}: missing producer")
        require(type(item.get("available")) is bool, f"predicate {identifier}: availability invalid")
        if item["type"] == "enum":
            values = item.get("values")
            require(isinstance(values, list) and bool(values)
                    and all(type(value) is str and value for value in values)
                    and len(values) == len(set(values)),
                    f"predicate {identifier}: enum values invalid")
        else:
            require("values" not in item, f"predicate {identifier}: non-enum values")
        if item["available"]:
            require(item["producer"] in PRODUCERS,
                    f"predicate {identifier}: no current concrete producer")
    require(all(not indexed[key]["available"] for key in (
        "subject.kind", "subject.uid", "subject.cgroup_id", "subject.netns_id",
        "mesh.session_authenticated", "host.policy_current", "host.service_rule_match",
        "host.flow_state_valid")), "unproven host/identity producer marked available")
    return indexed


def section_sources(section_rows: dict[str, dict], source_cache: Path) -> set[str]:
    registry = unique(document(SOURCE_REGISTRY).get("sources"), "source registry")
    checked: set[str] = set()
    for identifier, section in section_rows.items():
        require(set(section) == {"id", "heading", "end_heading", "anchor", "edge_ids", "relevance"},
                f"section {identifier}: invalid keys")
        require("#" in identifier, f"section {identifier}: missing source fragment")
        source_id = identifier.split("#", 1)[0]
        require(source_id in registry, f"section {identifier}: unknown source")
        source = registry[source_id]
        require(source["uri"].startswith("https://www.rfc-editor.org/rfc/"),
                f"section {identifier}: source is not supported official RFC")
        require(all(isinstance(section[key], str) and section[key].strip()
                    for key in ("heading", "end_heading", "anchor", "relevance")),
                f"section {identifier}: empty evidence")
        require(isinstance(section["edge_ids"], list) and bool(section["edge_ids"]),
                f"section {identifier}: no claim linkage")
        suffix = Path(source["uri"]).suffix
        cache_path = source_cache / f"{source_id}{suffix}"
        try:
            contents = cache_path.read_bytes()
        except OSError as error:
            raise EvidenceError(f"section {identifier}: pinned source cache absent: {error}") from error
        require(len(contents) == source["bytes"] and digest(contents) == source["sha256"],
                f"section {identifier}: pinned source hash/size mismatch")
        text = contents.decode("utf-8", "replace")
        heading = "\n" + section["heading"] + "\n"
        ending = "\n" + section["end_heading"] + "\n"
        start = text.find(heading)
        stop = text.find(ending, start + len(heading)) if start >= 0 else -1
        require(start >= 0 and stop > start, f"section {identifier}: exact heading missing")
        require(section["anchor"] in text[start:stop],
                f"section {identifier}: support anchor outside named section")
        checked.add(identifier)
    return checked


def validate_clause(clause: dict, catalog: dict[str, dict], where: str,
                    available_only: bool) -> None:
    require(set(clause) == {"fact", "eq"}, f"{where}: invalid clause")
    identifier = clause["fact"]
    require(identifier in catalog, f"{where}: unknown predicate {identifier}")
    spec = catalog[identifier]
    check_type(spec, clause["eq"], where)
    if available_only:
        require(spec["available"], f"{where}: no current fact producer")


def bindings(path: Path, catalog: dict[str, dict], sections: dict[str, dict]) -> dict[str, dict]:
    data = document(path)
    require(data.get("schema") == 1 and data.get("revision") == REVISION_ID,
            "condition schema/revision mismatch")
    raw_parent = PARENT_CURRICULUM.read_bytes()
    require(data.get("parent_curriculum_sha256") == digest(raw_parent),
            "parent curriculum changed")
    parent = unique(document(PARENT_CURRICULUM).get("edges"), "parent edges")
    # Bindings use edge_id rather than id, so check them without rewriting input.
    require(isinstance(data.get("bindings"), list), "bindings missing")
    result = {}
    for entry in data["bindings"]:
        identifier = entry.get("edge_id")
        require(isinstance(identifier, str) and identifier in parent,
                f"binding {identifier}: unknown parent edge")
        require(identifier not in result, f"binding {identifier}: duplicate")
        result[identifier] = entry
        require(entry.get("status") in {"evaluable", "blocked_missing_host_facts"},
                f"binding {identifier}: invalid status")
        require(isinstance(entry.get("when"), dict)
                and isinstance(entry["when"].get("all"), list)
                and bool(entry["when"]["all"]), f"binding {identifier}: empty when")
        require(set(entry["when"]) == {"all"} and isinstance(entry.get("unless"), dict)
                and set(entry["unless"]) == {"any"}
                and isinstance(entry["unless"]["any"], list),
                f"binding {identifier}: invalid condition grammar")
        active = entry["status"] == "evaluable"
        expected_keys = {"edge_id", "status", "source_sections", "when", "unless"}
        if active:
            require(set(entry) == expected_keys, f"binding {identifier}: invalid keys")
            require(entry.get("source_sections") == parent[identifier]["source_refs"],
                    f"binding {identifier}: source refs changed")
            for section_id in entry["source_sections"]:
                require(section_id in sections and identifier in sections[section_id]["edge_ids"],
                        f"binding {identifier}: section claim linkage absent")
        else:
            require(set(entry) == expected_keys | {"blockers"}
                    and not entry["source_sections"]
                    and isinstance(entry["blockers"], list) and bool(entry["blockers"]),
                    f"binding {identifier}: unsupported host edge not blocked")
        for clause in entry["when"]["all"] + entry["unless"]["any"]:
            validate_clause(clause, catalog, f"binding {identifier}", active)
    require(set(result) == {"v5e003", "v5e004", "v5e006", "v5e008", "v5e009", "v5e027"},
            "first-slice edge set changed")
    require(parent["v5e006"]["polarity"] == -1
            and all(parent[key]["polarity"] == 1 for key in result if key != "v5e006"),
            "parent edge polarity changed")
    return result


def atom(clause: dict, facts: dict[str, object]) -> str:
    identifier = clause["fact"]
    if identifier not in facts:
        return "unknown"
    return "true" if facts[identifier] == clause["eq"] else "false"


def conjunction(values: list[str]) -> str:
    if "false" in values:
        return "false"
    if all(value == "true" for value in values):
        return "true"
    return "unknown"


def applicability(binding: dict, facts: dict[str, object]) -> str:
    if binding["status"] != "evaluable":
        return "unknown"
    required = conjunction([atom(clause, facts) for clause in binding["when"]["all"]])
    exceptions = [atom(clause, facts) for clause in binding["unless"]["any"]]
    if "true" in exceptions:
        return "false"
    if "unknown" in exceptions:
        return conjunction([required, "unknown"])
    return required


def corpus(path: Path, catalog: dict[str, dict], edges: dict[str, dict]) -> dict:
    data = document(path)
    require(data.get("schema") == 1 and data.get("revision") == REVISION_ID,
            "corpus schema/revision mismatch")
    references = unique(data.get("cases"), "corpus cases")
    cases = {}
    for identifier, reference in references.items():
        require(set(reference) == {"id", "file", "sha256"}
                and reference["file"] == f"cases/{identifier}.json",
                f"case {identifier}: unsafe case reference")
        case_path = path.parent / reference["file"]
        require(digest(case_path.read_bytes()) == reference["sha256"],
                f"case {identifier}: case file hash mismatch")
        case = document(case_path)
        require(case.get("id") == identifier, f"case {identifier}: ID mismatch")
        cases[identifier] = case
    require(tuple(cases) == CASES, "frozen corpus case IDs/order changed")
    for identifier, case in cases.items():
        require(case.get("expected_delivery") == "unobserved",
                f"case {identifier}: invented delivery evidence")
        require(case.get("direction") in {"inbound", "outbound"}
                and type(case.get("at_ms")) is int and case["at_ms"] >= 0,
                f"case {identifier}: direction/time invalid")
        require(re.fullmatch(r"[0-9a-f]{8,4096}", case.get("packet_hex", "")) is not None
                and len(case["packet_hex"]) % 2 == 0, f"case {identifier}: packet invalid")
        require(digest(bytes.fromhex(case["packet_hex"])) == case.get("packet_sha256"),
                f"case {identifier}: packet hash mismatch")
        require(re.fullmatch(r"[0-9a-f-]{36}", case.get("peer_id", "")) is not None
                and re.fullmatch(r"[0-9a-f-]{36}", case.get("session_id", "")) is not None,
                f"case {identifier}: fixture identity malformed")
        facts = unique(case.get("facts"), f"case {identifier} facts")
        values: dict[str, object] = {}
        for fact_id, fact in facts.items():
            require(fact_id in catalog, f"case {identifier}: unknown predicate {fact_id}")
            spec = catalog[fact_id]
            require(spec["available"] and fact.get("producer") == spec["producer"],
                    f"case {identifier}: unverified fact producer {fact_id}")
            require(set(fact) == {"id", "value", "producer"},
                    f"case {identifier}: malformed fact {fact_id}")
            check_type(spec, fact["value"], f"case {identifier} {fact_id}")
            values[fact_id] = fact["value"]
        require("packet.validation" in values,
                f"case {identifier}: packet validation fact missing")
        expected = case.get("expected_applicability")
        require(isinstance(expected, dict) and set(expected) == set(edges),
                f"case {identifier}: incomplete expected conditions")
        for edge_id, state in expected.items():
            require(state in TRUTH, f"case {identifier}: invalid truth state")
            got = applicability(edges[edge_id], values)
            require(got == state,
                    f"case {identifier} {edge_id}: expected {state}, measured {got}")
        require(expected["v5e027"] == "unknown",
                f"case {identifier}: host bridge falsely resolved")
    require(cases["udp_service_a"]["packet_hex"] != cases["udp_service_b_same_shape"]["packet_hex"]
            and len(cases["udp_service_a"]["packet_hex"]) == len(cases["udp_service_b_same_shape"]["packet_hex"]),
            "UDP service controls not same shape")
    require(cases["udp_reverse_correlated"]["packet_sha256"]
            == cases["udp_reverse_after_expiry"]["packet_sha256"],
            "UDP lifetime controls not byte identical")
    require(cases["tcp_ack_correlated"]["packet_sha256"]
            == cases["tcp_orphan_ack"]["packet_sha256"],
            "TCP history controls not byte identical")
    return {"cases": len(cases), "truth_checks": len(cases) * len(edges)}


def validate(source_cache: Path, revision: Path = REVISION) -> dict:
    require(digest(PARENT_PACK.read_bytes()) == PARENT_PACK_HASH, "v4 parent pack changed")
    catalog = predicates(revision / "predicates.json")
    section_doc = document(revision / "sections.json")
    require(section_doc.get("schema") == 1 and section_doc.get("revision") == REVISION_ID,
            "section schema/revision mismatch")
    sections = unique(section_doc.get("sections"), "sections")
    checked = section_sources(sections, source_cache)
    edges = bindings(revision / "conditions.json", catalog, sections)
    measured = corpus(revision / "corpus.json", catalog, edges)
    return {
        "schema": 1,
        "revision": REVISION_ID,
        "status": "offline_condition_evidence_validated",
        "trained": False,
        "pack_promoted": False,
        "release_ready": False,
        "all_host_traffic_proven": False,
        "source_sections_verified": len(checked),
        "active_edges_checked": sum(item["status"] == "evaluable" for item in edges.values()),
        "blocked_edges": sum(item["status"] != "evaluable" for item in edges.values()),
        **measured,
        "rust_producer_replay_required": True,
        "known_gaps": ["host_policy", "direct_host_subject_capture", "mesh_authentication_receipt",
                       "fragment_reassembly", "unsupported_transports", "non_TUN_host_hooks"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-cache", type=Path, required=True,
                        help="directory with exact pinned RFC text files")
    parser.add_argument("--revision", type=Path, default=REVISION)
    args = parser.parse_args()
    try:
        report = validate(args.source_cache, args.revision)
    except (EvidenceError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f"condition evidence rejected: {error}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
