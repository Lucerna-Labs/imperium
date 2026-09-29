#!/usr/bin/env python3
"""Compile a deterministic v5 diagnostic graph beside, never over, v4."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from validate import PARENT_PACK, V5, validate

HEADER = 1044
NODE = 216
EDGE = 16


def parent_records(pack: bytes) -> tuple[list[dict], list[dict]]:
    count_nodes, count_edges = struct.unpack_from("<HH", pack, 8)
    strings = HEADER + count_nodes * NODE + count_edges * EDGE

    def record(offset: int) -> dict:
        start, length = struct.unpack_from("<II", pack, offset)
        return json.loads(pack[strings + start : strings + start + length])

    nodes = [record(HEADER + index * NODE) for index in range(count_nodes)]
    edges = [record(HEADER + count_nodes * NODE + index * EDGE + 8) for index in range(count_edges)]
    return nodes, edges


def compile_graph(v5: Path = V5, parent_pack: Path = PARENT_PACK, cache: Path | None = None) -> dict:
    report = validate(v5, parent_pack, cache)
    parent_nodes, parent_edges = parent_records(parent_pack.read_bytes())
    curriculum = json.loads((v5 / "curriculum.json").read_text(encoding="utf-8"))
    splits = json.loads((v5 / "splits.json").read_text(encoding="utf-8"))
    group_split = {group["id"]: group["split"] for group in splits["groups"]}

    nodes = [dict(record, origin="inherited_v4_unreproduced") for record in parent_nodes]
    nodes.extend(dict(record, origin="authored_v5") for record in curriculum["nodes"])
    edges = [dict(record, origin="inherited_v4_unreproduced") for record in parent_edges]
    edges.extend(
        dict(record, split=group_split[record["mechanism_group"]], origin="authored_v5")
        for record in curriculum["edges"]
    )
    return {
        "schema": 1,
        "status": "local_diagnostic_compiled_untrained",
        "release_ready": False,
        "revision": report["revision"],
        "parent_pack_sha256": report["parent_pack_sha256"],
        "input_sha256": report["input_sha256"],
        "blockers": report["blockers"],
        "nodes": nodes,
        "edges": edges,
        "controls": curriculum["controls"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v5", type=Path, default=V5)
    parser.add_argument("--parent-pack", type=Path, default=PARENT_PACK)
    parser.add_argument("--source-cache", type=Path)
    parser.add_argument("--output", type=Path, default=V5 / "compiled-local.json")
    args = parser.parse_args()
    compiled = compile_graph(args.v5, args.parent_pack, args.source_cache)
    args.output.write_text(json.dumps(compiled, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": compiled["status"],
        "output": str(args.output),
        "nodes": len(compiled["nodes"]),
        "edges": len(compiled["edges"]),
        "authored_edges": sum(edge["origin"] == "authored_v5" for edge in compiled["edges"]),
        "release_ready": compiled["release_ready"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
