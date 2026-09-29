#!/usr/bin/env python3
"""Adversarial structural checks for the local diagnostic v5 pipeline."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from compile import compile_graph
from validate import PARENT_PACK, V5, ValidationError, validate


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="imperium-v5-test-")
        self.root = Path(self.scratch.name) / "v5"
        shutil.copytree(V5, self.root)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def edit(self, filename: str, change) -> None:
        path = self.root / filename
        document = json.loads(path.read_text(encoding="utf-8"))
        change(document)
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_current_delta_compiles_deterministically_with_release_blockers(self) -> None:
        report = validate(self.root, PARENT_PACK)
        self.assertEqual(report["status"], "local_diagnostic_structural_valid")
        self.assertEqual(report["counts"]["new_nodes"], 13)
        self.assertEqual(report["counts"]["new_edges"], 31)
        self.assertFalse(report["release_ready"])
        self.assertTrue(any("host_service_policy" in gap for gap in report["blockers"]))
        compiled = compile_graph(self.root, PARENT_PACK)
        self.assertEqual(len(compiled["nodes"]), 221)
        self.assertEqual(len(compiled["edges"]), 219)
        self.assertEqual(compiled, compile_graph(self.root, PARENT_PACK))

    def test_dangling_edge_and_unknown_source_fail(self) -> None:
        self.edit("curriculum.json", lambda value: value["edges"][0].update(target="invented"))
        with self.assertRaisesRegex(ValidationError, "dangling endpoint"):
            validate(self.root, PARENT_PACK)

        shutil.copyfile(V5 / "curriculum.json", self.root / "curriculum.json")
        self.edit("curriculum.json", lambda value: value["nodes"][0].update(source_refs=["unknown#section"]))
        with self.assertRaisesRegex(ValidationError, "unknown source"):
            validate(self.root, PARENT_PACK)

    def test_positive_bridge_must_be_trained_and_host_facts_complete(self) -> None:
        def withhold_bridge(value):
            next(group for group in value["groups"] if group["id"] == "flow_authorization_composition")["split"] = "cross_composition"

        self.edit("splits.json", withhold_bridge)
        with self.assertRaisesRegex(ValidationError, "host bridge withheld"):
            validate(self.root, PARENT_PACK)

        shutil.copyfile(V5 / "splits.json", self.root / "splits.json")
        def omit_host_fact(value):
            next(edge for edge in value["edges"] if edge["id"] == "v5e027")["required_host_facts"].remove("service")

        self.edit("curriculum.json", omit_host_fact)
        with self.assertRaisesRegex(ValidationError, "omits a mandatory host fact"):
            validate(self.root, PARENT_PACK)

    def test_graph_reachability_negative_control_and_split_history_are_required(self) -> None:
        self.edit("curriculum.json", lambda value: value["controls"].pop())
        with self.assertRaisesRegex(ValidationError, "graph-reachability-is-not-release"):
            validate(self.root, PARENT_PACK)

        shutil.copyfile(V5 / "curriculum.json", self.root / "curriculum.json")
        with (self.root / "splits-v1-rejected.json").open("a", encoding="utf-8") as handle:
            handle.write(" ")
        with self.assertRaisesRegex(ValidationError, "archive hash changed"):
            validate(self.root, PARENT_PACK)

    def test_authored_status_cannot_point_to_absent_evidence(self) -> None:
        def falsify_evidence(value):
            next(item for item in value["coverage"] if item["id"] == "raw_ip_tuple")["evidence"] = ["missing.json"]

        self.edit("registry.json", falsify_evidence)
        with self.assertRaisesRegex(ValidationError, "absent authored evidence"):
            validate(self.root, PARENT_PACK)


if __name__ == "__main__":
    unittest.main()
