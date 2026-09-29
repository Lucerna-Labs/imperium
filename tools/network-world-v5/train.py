#!/usr/bin/env python3
"""Deterministic, unsealed 48D diagnostic for the authored network v5 delta.

No output of this script is an active world pack or packet-release decision.
Only authored v5 *train* edges enter optimization. Held-out v5 edges are used
for evaluation only; inherited v4 graph records remain context, not gradients.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import re
import time
from pathlib import Path

os.environ["OPENBLAS_NUM_THREADS"] = "1"
import numpy as np

from compile import PARENT_PACK, V5, compile_graph
from validate import sha256, validate

SEED = 73129
DIMS = 48
STEPS = 500
LEARNING_RATE = 0.03
MARGIN = 0.20
SPLITS = ("train", "validation", "sealed_test", "cross_composition")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def node_text(node: dict) -> str:
    if node["origin"] == "authored_v5":
        return " ".join((node["id"], node["title"], node["statement"]))
    # The original v4 source rights/trainer are absent. Use short identifier
    # and title labels as context, never copied source-derived statement prose.
    return " ".join((node["id"], node["title"]))


def initial_features(nodes: list[dict], train_nodes: list[int]) -> tuple[np.ndarray, dict, np.ndarray]:
    documents = [tokens(node_text(node)) for node in nodes]
    vocabulary = sorted({token for index in train_nodes for token in documents[index]})
    positions = {token: index for index, token in enumerate(vocabulary)}
    document_frequency = np.zeros(len(vocabulary), dtype=np.float64)
    for index in train_nodes:
        for token in set(documents[index]):
            document_frequency[positions[token]] += 1
    idf = np.log((len(train_nodes) + 1) / (document_frequency + 1)) + 1
    matrix = np.zeros((len(nodes), len(vocabulary)), dtype=np.float64)
    for index, words in enumerate(documents):
        for word in words:
            position = positions.get(word)
            if position is not None:
                matrix[index, position] += idf[position]
    rng = np.random.default_rng(SEED)
    projection = rng.normal(0, 1 / math.sqrt(DIMS), size=(len(vocabulary), DIMS))
    embedded = matrix @ projection
    lengths = np.linalg.norm(embedded, axis=1)
    np.divide(embedded, lengths[:, None], out=embedded, where=lengths[:, None] > 0)
    return embedded, positions, projection


def fit_relation_edges(
    initialized: np.ndarray,
    train_edges: list[tuple[int, int, int]],
    train_nodes: list[int],
    relation_count: int,
    shuffle_targets: bool,
) -> tuple[np.ndarray, np.ndarray, int]:
    points = initialized.copy()
    relation = np.zeros((relation_count, DIMS), dtype=np.float64)
    rng = np.random.default_rng(SEED)
    targets = [target for _, target, _ in train_edges]
    if shuffle_targets:
        shuffled = np.array(targets, dtype=np.int64)
        rng.shuffle(shuffled)
        targets = shuffled.tolist()
    updates = 0
    for _step in range(STEPS):
        for position in rng.permutation(len(train_edges)):
            source, _true_target, kind = train_edges[int(position)]
            target = targets[int(position)]
            negative = train_nodes[int(rng.integers(len(train_nodes)))]
            if negative == target:
                negative = train_nodes[(train_nodes.index(negative) + 1) % len(train_nodes)]
            source_vector = points[source].copy()
            target_vector = points[target].copy()
            negative_vector = points[negative].copy()
            predicted = source_vector + relation[kind]
            positive_distance = float(np.sum((predicted - target_vector) ** 2))
            negative_distance = float(np.sum((predicted - negative_vector) ** 2))
            if MARGIN + positive_distance > negative_distance:
                grad_predicted = 2 * (negative_vector - target_vector)
                points[source] -= LEARNING_RATE * grad_predicted
                relation[kind] -= LEARNING_RATE * grad_predicted
                points[target] -= LEARNING_RATE * (2 * (target_vector - predicted))
                points[negative] -= LEARNING_RATE * (2 * (predicted - negative_vector))
                updates += 1
        if not np.isfinite(points).all() or not np.isfinite(relation).all():
            raise ArithmeticError("nonfinite diagnostic geometry")
    return points, relation, updates


def rank_metrics(points: np.ndarray, relation: np.ndarray, edges: list[tuple[int, int, int]]) -> dict:
    ranks = []
    continuity = 0
    candidate_ids = np.arange(len(points))
    for source, target, kind in edges:
        predicted = points[source] + relation[kind]
        scores = np.sum((points - predicted) ** 2, axis=1)
        ordered = np.lexsort((candidate_ids, scores))
        rank = int(np.flatnonzero(ordered == target)[0]) + 1
        ranks.append(rank)
        nearby = np.sum((points - points[source]) ** 2, axis=1)
        nearby[source] = np.inf
        continuity += target in np.lexsort((candidate_ids, nearby))[:5]
    count = len(ranks)
    return {
        "edges": count,
        "ranks": ranks,
        "top1": sum(rank == 1 for rank in ranks) / count,
        "top5": sum(rank <= 5 for rank in ranks) / count,
        "mrr": sum(1 / rank for rank in ranks) / count,
        "neighborhood_top5": int(continuity),
    }


def seed_recovery(
    points: np.ndarray, nodes: list[dict], train_nodes: list[int],
    vocab: dict[str, int], projection: np.ndarray, id_to_index: dict[str, int],
    split_groups: dict[str, str],
) -> dict:
    idf = np.zeros(len(vocab), dtype=np.float64)
    docs = [tokens(node_text(node)) for node in nodes]
    for token, position in vocab.items():
        df = sum(token in set(docs[index]) for index in train_nodes)
        idf[position] = math.log((len(train_nodes) + 1) / (df + 1)) + 1
    recovered = {split: [0, 0] for split in SPLITS}
    for node in nodes:
        if node["origin"] != "authored_v5":
            continue
        split = split_groups[node["mechanism_group"]]
        query = np.zeros(len(vocab), dtype=np.float64)
        for word in tokens(node["title"]):
            position = vocab.get(word)
            if position is not None:
                query[position] += idf[position]
        vector = query @ projection
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector /= norm
        scores = np.sum((points - vector) ** 2, axis=1)
        choice = int(np.lexsort((np.arange(len(points)), scores))[0])
        recovered[split][0] += int(choice == id_to_index[node["id"]])
        recovered[split][1] += 1
    return {split: {"exact": values[0], "total": values[1]} for split, values in recovered.items()}


def observer_geometry(points: np.ndarray, train_nodes: list[int]) -> tuple[dict, dict]:
    center = np.mean(points[train_nodes], axis=0)
    _u, _singular, right = np.linalg.svd(points[train_nodes] - center, full_matrices=False)
    basis = right[:4].T
    shadow = (points - center) @ basis
    gram_error = float(np.max(np.abs(basis.T @ basis - np.eye(4))))
    full_distance = np.linalg.norm(points[:, None, :] - points[None, :, :], axis=2)
    shadow_distance = np.linalg.norm(shadow[:, None, :] - shadow[None, :, :], axis=2)
    expansion = float(np.max(np.maximum(shadow_distance - full_distance, 0)))
    return (
        {"center": center.tolist(), "basis": basis.tolist(), "axes": ["x", "y", "z", "w"], "shadow": shadow.tolist()},
        {"orthonormal_max_error": gram_error, "nonexpansion_max_positive_error": expansion},
    )


def false_proximity(points: np.ndarray, ids: dict[str, int], train_edges: list[tuple[int, int, int]]) -> dict:
    train_distances = [float(np.linalg.norm(points[source] - points[target])) for source, target, _ in train_edges]
    median = float(np.median(train_distances))
    unknown = ["v5_unknown_transport_observation", "v5_packet_not_authorization"]
    authority = ["authorized_flow", "v5_host_flow_context"]
    distances = {
        item: min(float(np.linalg.norm(points[ids[item]] - points[ids[target]])) for target in authority)
        for item in unknown
    }
    return {
        "train_edge_median": median,
        "unknown_to_authority": distances,
        "unknown_below_train_median": sum(distance < median for distance in distances.values()),
        "use_for_admission": False,
    }


def run_diagnostic(v5: Path = V5, parent_pack: Path = PARENT_PACK, cache: Path | None = None) -> tuple[dict, dict, dict]:
    started = dt.datetime.now(dt.timezone.utc)
    clock = time.monotonic()
    validation = validate(v5, parent_pack, cache)
    compiled = compile_graph(v5, parent_pack, cache)
    nodes = compiled["nodes"]
    id_to_index = {node["id"]: index for index, node in enumerate(nodes)}
    relation_ids = sorted({edge["relation"] for edge in compiled["edges"] if edge["origin"] == "authored_v5"})
    relation_index = {name: index for index, name in enumerate(relation_ids)}
    split_groups = {group["id"]: group["split"] for group in json.loads((v5 / "splits.json").read_text())["groups"]}
    edges_by_split = {
        split: [
            (id_to_index[edge["source"]], id_to_index[edge["target"]], relation_index[edge["relation"]])
            for edge in compiled["edges"] if edge["origin"] == "authored_v5" and edge["split"] == split
        ]
        for split in SPLITS
    }
    train_edges = edges_by_split["train"]
    train_nodes = sorted({node for source, target, _ in train_edges for node in (source, target)})
    initialized, vocabulary, projection = initial_features(nodes, train_nodes)
    baseline_relation = np.zeros((len(relation_ids), DIMS), dtype=np.float64)
    trained, relation, updates = fit_relation_edges(initialized, train_edges, train_nodes, len(relation_ids), False)
    shuffled, shuffled_relation, shuffled_updates = fit_relation_edges(initialized, train_edges, train_nodes, len(relation_ids), True)
    candidates = {
        "A_text_only": (initialized, baseline_relation),
        "B_typed_train": (trained, relation),
        "shuffled_train_targets": (shuffled, shuffled_relation),
    }
    metrics = {
        name: {split: rank_metrics(points, rel, edges_by_split[split]) for split in SPLITS}
        for name, (points, rel) in candidates.items()
    }
    seed_metrics = seed_recovery(trained, nodes, train_nodes, vocabulary, projection, id_to_index, split_groups)
    observer, geometry_checks = observer_geometry(trained, train_nodes)
    proximity = false_proximity(trained, id_to_index, train_edges)
    finite = bool(np.isfinite(trained).all() and np.isfinite(relation).all())
    benefit = all(
        metrics["B_typed_train"][split]["top5"] > metrics["A_text_only"][split]["top5"]
        and metrics["B_typed_train"][split]["top5"] > metrics["shuffled_train_targets"][split]["top5"]
        for split in ("validation", "sealed_test")
    )
    geometric = geometry_checks["orthonormal_max_error"] <= 1e-8 and geometry_checks["nonexpansion_max_positive_error"] <= 1e-8
    diagnostic_pass = finite and benefit and geometric
    geometry = {
        "schema": 1,
        "status": "local_diagnostic_unsealed",
        "revision": compiled["revision"],
        "node_ids": [node["id"] for node in nodes],
        "full_dimensions": 48,
        "full_coordinates": trained.tolist(),
        "relation_ids": relation_ids,
        "relation_vectors": relation.tolist(),
        "observer_4d": observer,
        "observer_only": True,
        "authorizes_packets": False,
    }
    compiled_hash = sha256(canonical(compiled))
    geometry_hash = sha256(canonical(geometry))
    report = {
        "schema": 1,
        "status": "passed_local_diagnostic_not_release" if diagnostic_pass else "rejected_local_diagnostic",
        "release_ready": False,
        "sealed": False,
        "revision": compiled["revision"],
        "source_revision": "network-v5-diagnostic-2",
        "source_dirty": True,
        "platform": "local_diagnostic",
        "actual_device": "cpu",
        "host_platform": platform.platform(),
        "numpy": np.__version__,
        "started_at_utc": started.isoformat(),
        "elapsed_seconds": time.monotonic() - clock,
        "seed": SEED,
        "configuration": {"dimensions": DIMS, "steps": STEPS, "learning_rate": LEARNING_RATE, "margin": MARGIN, "negative_targets": "one_train_node_per_edge_step"},
        "input_sha256": validation["input_sha256"],
        "parent_pack_sha256": validation["parent_pack_sha256"],
        "compiled_sha256": compiled_hash,
        "geometry_sha256": geometry_hash,
        "trainer_sha256": sha256(Path(__file__).read_bytes()),
        "source_checks": validation["source_checks"],
        "split_edge_counts": validation["split_edge_counts"],
        "control_counts": validation["control_counts"],
        "train_nodes": [nodes[index]["id"] for index in train_nodes],
        "train_updates": updates,
        "shuffled_updates": shuffled_updates,
        "metrics": metrics,
        "seed_recovery": seed_metrics,
        "false_proximity": proximity,
        "observer_checks": geometry_checks,
        "gates": {"finite": finite, "typed_top5_strictly_beats_both_controls_on_validation_and_sealed_test": benefit, "observer_orthonormal_and_nonexpansive": geometric},
        "release_blockers": validation["blockers"] + ["live packet/flow acceptance matrix unrun", "no active v5 runtime pack"],
    }
    return report, geometry, compiled


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v5", type=Path, default=V5)
    parser.add_argument("--parent-pack", type=Path, default=PARENT_PACK)
    parser.add_argument("--source-cache", type=Path)
    parser.add_argument("--report", type=Path, default=V5 / "training-local.json")
    parser.add_argument("--geometry", type=Path, default=V5 / "geometry-local.json")
    parser.add_argument("--compiled", type=Path, default=V5 / "compiled-local.json")
    args = parser.parse_args()
    report, geometry, compiled = run_diagnostic(args.v5, args.parent_pack, args.source_cache)
    args.compiled.write_bytes(canonical(compiled))
    args.geometry.write_bytes(canonical(geometry))
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "release_ready": False, "report": str(args.report), "geometry_sha256": report["geometry_sha256"], "gates": report["gates"]}, sort_keys=True))
    return 0 if report["status"] == "passed_local_diagnostic_not_release" else 2


if __name__ == "__main__":
    raise SystemExit(main())
