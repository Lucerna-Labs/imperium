#!/usr/bin/env python3
"""Adversarial checks for the untrained revision-5 condition evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from condition_evidence import (
    REVISION, EvidenceError, applicability, bindings, corpus, document,
    predicates, section_sources, unique,
)


class ConditionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="imperium-condition-evidence-")
        self.root = Path(self.scratch.name) / "revision-5"
        shutil.copytree(REVISION, self.root)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def save(self, filename: str, data: dict) -> None:
        (self.root / filename).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def load_context(self) -> tuple[dict, dict]:
        catalog = predicates(self.root / "predicates.json")
        sections = unique(document(self.root / "sections.json")["sections"], "sections")
        edges = bindings(self.root / "conditions.json", catalog, sections)
        return catalog, edges

    def edit_case(self, identifier: str, change) -> None:
        manifest = document(self.root / "corpus.json")
        reference = next(item for item in manifest["cases"] if item["id"] == identifier)
        case = document(self.root / reference["file"])
        change(case)
        contents = (json.dumps(case, indent=2) + "\n").encode("utf-8")
        (self.root / reference["file"]).write_bytes(contents)
        reference["sha256"] = hashlib.sha256(contents).hexdigest()
        self.save("corpus.json", manifest)

    def test_frozen_corpus_has_90_typed_truth_checks_without_release(self) -> None:
        catalog, edges = self.load_context()
        result = corpus(self.root / "corpus.json", catalog, edges)
        self.assertEqual(result, {"cases": 15, "truth_checks": 90})
        for reference in document(self.root / "corpus.json")["cases"]:
            case = document(self.root / reference["file"])
            self.assertEqual(case["expected_delivery"], "unobserved")
            self.assertEqual(case["expected_applicability"]["v5e027"], "unknown")

    def test_missing_fact_is_unknown_and_opposite_protocol_is_false(self) -> None:
        _, edges = self.load_context()
        self.assertEqual(applicability(edges["v5e003"], {
            "packet.validation": "parsed", "packet.next_protocol": "tcp",
            "packet.fragmented": False,
        }), "unknown")
        self.assertEqual(applicability(edges["v5e003"], {
            "packet.validation": "parsed", "packet.next_protocol": "udp",
            "packet.transport_complete": True, "packet.fragmented": False,
        }), "false")
        self.assertEqual(applicability(edges["v5e027"], {
            "host.policy_current": True, "host.service_rule_match": True,
        }), "unknown")

    def test_unavailable_host_fact_cannot_become_claimed_current(self) -> None:
        data = document(self.root / "predicates.json")
        next(item for item in data["predicates"] if item["id"] == "host.policy_current")["available"] = True
        self.save("predicates.json", data)
        with self.assertRaisesRegex(EvidenceError, "no current concrete producer"):
            predicates(self.root / "predicates.json")

    def test_wrong_fact_type_and_unknown_predicate_fail(self) -> None:
        self.edit_case("udp_service_a", lambda case: next(
            fact for fact in case["facts"] if fact["id"] == "packet.destination_port"
        ).update(value=True))
        catalog, edges = self.load_context()
        with self.assertRaisesRegex(EvidenceError, "invalid u16"):
            corpus(self.root / "corpus.json", catalog, edges)

        self.edit_case("udp_service_a", lambda case: next(
            fact for fact in case["facts"] if fact["id"] == "packet.destination_port"
        ).update(id="packet.invented", value=5353))
        with self.assertRaisesRegex(EvidenceError, "unknown predicate"):
            corpus(self.root / "corpus.json", catalog, edges)

    def test_case_tamper_and_invented_delivery_fail(self) -> None:
        path = self.root / "cases/udp_service_a.json"
        path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        catalog, edges = self.load_context()
        with self.assertRaisesRegex(EvidenceError, "case file hash mismatch"):
            corpus(self.root / "corpus.json", catalog, edges)

        shutil.copyfile(REVISION / "cases/udp_service_a.json", path)
        self.edit_case("udp_service_a", lambda case: case.update(expected_delivery="allowed"))
        with self.assertRaisesRegex(EvidenceError, "invented delivery"):
            corpus(self.root / "corpus.json", catalog, edges)

    def test_condition_cannot_use_unavailable_host_predicate(self) -> None:
        data = document(self.root / "conditions.json")
        data["bindings"][1]["when"]["all"].append({"fact": "host.policy_current", "eq": True})
        self.save("conditions.json", data)
        catalog = predicates(self.root / "predicates.json")
        sections = unique(document(self.root / "sections.json")["sections"], "sections")
        with self.assertRaisesRegex(EvidenceError, "no current fact producer"):
            bindings(self.root / "conditions.json", catalog, sections)

    def test_parent_edge_source_binding_cannot_drift(self) -> None:
        data = document(self.root / "conditions.json")
        data["bindings"][0]["source_sections"] = ["rfc768#format"]
        self.save("conditions.json", data)
        catalog = predicates(self.root / "predicates.json")
        sections = unique(document(self.root / "sections.json")["sections"], "sections")
        with self.assertRaisesRegex(EvidenceError, "source refs changed"):
            bindings(self.root / "conditions.json", catalog, sections)

    def test_section_gate_requires_pinned_bytes_and_anchor_inside_heading(self) -> None:
        source = b"\n3.5.  Establishing a Connection\n\nSYN and ACK evidence.\n3.5.1.  Half-Open Connections\n"
        cache = self.root / "source-cache"
        cache.mkdir()
        (cache / "rfc9293.txt").write_bytes(source)
        source_registry = self.root / "source-registry.json"
        source_registry.write_text(json.dumps({"sources": [{
            "id": "rfc9293",
            "uri": "https://www.rfc-editor.org/rfc/rfc9293.txt",
            "bytes": len(source),
            "sha256": hashlib.sha256(source).hexdigest(),
        }]}), encoding="utf-8")
        section = {"rfc9293#3.5": {
            "id": "rfc9293#3.5", "heading": "3.5.  Establishing a Connection",
            "end_heading": "3.5.1.  Half-Open Connections",
            "anchor": "SYN and ACK evidence.", "edge_ids": ["v5e008"],
            "relevance": "The named section provides the opening-segment evidence.",
        }}
        with patch("condition_evidence.SOURCE_REGISTRY", source_registry):
            self.assertEqual(section_sources(section, cache), {"rfc9293#3.5"})
            section["rfc9293#3.5"]["anchor"] = "not in the named section"
            with self.assertRaisesRegex(EvidenceError, "outside named section"):
                section_sources(section, cache)
            section["rfc9293#3.5"]["anchor"] = "SYN and ACK evidence."
            (cache / "rfc9293.txt").write_bytes(source + b"tampered")
            with self.assertRaisesRegex(EvidenceError, "hash/size mismatch"):
                section_sources(section, cache)
            (cache / "rfc9293.txt").unlink()
            with self.assertRaisesRegex(EvidenceError, "source cache absent"):
                section_sources(section, cache)


if __name__ == "__main__":
    unittest.main()
