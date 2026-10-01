#!/usr/bin/env python3
"""Train and validate a fresh unsealed local static conditional world."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

os.environ["OPENBLAS_NUM_THREADS"] = "1"
import numpy as np
from pack import applies, build, canonical, digest, neighborhood


def training_fixtures(catalog):
    rows = []
    for profile in catalog["deployment_profiles"]:
        protocol = {"icmp": 1, "tcp": 6, "udp": 17, "ndp": 58, "arp": 206}[profile["protocol"]]
        source = ipaddress.ip_network(profile["source"])
        target = ipaddress.ip_network(profile["destination"])
        source_ip = str(source.network_address + min(1, source.num_addresses - 1))
        target_ip = str(target.network_address + min(2, target.num_addresses - 1))
        for name, flow in catalog["flow_values"].items():
            if name.split('_')[0] != profile["protocol"]: continue
            for reverse in (False, True):
                for kind in profile["wire_kinds"]:
                    facts = {"0": True, "1": profile["family"], "2": protocol,
                             "3": flow, "4": profile["services"][0],
                             "5": target_ip if reverse else source_ip,
                             "6": source_ip if reverse else target_ip, "8": kind}
                    rows.append({"id": f"train_{profile['id']}_{name}_{int(reverse)}_{kind}",
                                 "facts": facts, "expected_complete_path": True,
                                 "scope": "synthetic_training_context_instantiating_declared_variables"})
    rows.append({"id": "train_invalid_structure", "facts": {"0": False},
                 "expected_complete_path": False, "scope": "negative_training_context"})
    return rows


def applicable_edges(catalog, facts):
    edges = [e for e in catalog["edges"] if e["split"] == "train"
             and all(applies(t, facts) for t in e["conditions"])]
    nodes = {next(i for i, n in enumerate(catalog["nodes"]) if n["passage_role"] == "input")}
    previous = -1
    while previous != len(nodes):
        previous = len(nodes)
        for e in edges:
            if e["polarity"] == 1 and e["source"] in nodes: nodes.add(e["target"])
    return {e["id"] for e in edges if e["source"] in nodes}


def fixtures(catalog):
    # Independent declared matched cases. Expected passage is frozen in the
    # protocol before training; this generator does not call admission to label.
    base = {"0": True, "1": 4, "2": 17, "3": 1, "4": 45998,
            "5": "192.0.2.2", "6": "198.51.100.2", "8": 0}
    rows = []
    def add(name, changes, expected):
        facts = dict(base); facts.update(changes)
        for key in list(facts):
            if facts[key] is None: del facts[key]
        rows.append({"id": name, "facts": facts, "expected_complete_path": expected})
    add("udp_open", {}, True)
    add("udp_new_endpoint_in_pattern", {"5": "192.0.2.57", "6": "198.51.100.91"}, True)
    add("udp_service_unknown", {"4": 46002}, False)
    add("udp_endpoint_unknown", {"6": "203.0.113.2"}, False)
    add("udp_reverse", {"3": 3, "5": "198.51.100.2", "6": "192.0.2.2"}, True)
    add("udp_orphan_reverse", {"4": 52000, "5": "198.51.100.2", "6": "192.0.2.2"}, False)
    add("udp_flow_missing", {"3": None}, False)
    add("validation_missing", {"0": None}, False)
    add("malformed_packet", {"0": False}, False)
    add("unknown_protocol", {"2": 132}, False)
    add("cold_untrained_relation", {"2": 132, "0": True}, False)
    add("ipv6_udp", {"1": 6, "5": "fd77::2", "6": "fd78::2"}, True)
    add("ipv6_udp_unknown_endpoint", {"1": 6, "5": "fd77::2", "6": "fd79::2"}, False)
    for event in (4, 5, 6, 7, 8):
        add(f"ipv6_tcp_event_{event}", {"1": 6, "2": 6, "3": event, "4": 46001,
                                      "5": "fd77::2", "6": "fd78::2"}, True)
    add("tcp_invalid_progression", {"1": 6, "2": 6, "3": None, "4": 46001,
                                    "5": "fd77::2", "6": "fd78::2"}, False)
    add("icmp_request", {"2": 1, "3": 9, "4": 0, "5": "10.88.0.1", "6": "10.99.0.1"}, True)
    add("icmp_orphan_reply", {"2": 1, "3": None, "4": 0, "5": "10.99.0.1", "6": "10.88.0.1"}, False)
    add("ndp_solicitation", {"1": 6, "2": 58, "3": 11, "4": 0,
                             "5": "fd77::2", "6": "ff02::1:ff00:1", "8": 6}, True)
    add("ndp_unsolicited_advertisement", {"1": 6, "2": 58, "3": None, "4": 0,
                                         "5": "fd77::1", "6": "fd77::2", "8": 7}, False)
    add("arp_request", {"2": 206, "3": 13, "4": 0, "5": "192.0.2.2", "6": "192.0.2.1", "8": 4}, True)
    add("mesh_unknown_shape", {"4": 41000, "6": "192.0.2.1", "8": 0}, False)
    add("mesh_handshake_shape", {"4": 41000, "6": "192.0.2.1", "8": 1}, True)
    return rows


def train(catalog_path, output, cache):
    if output.exists(): raise RuntimeError("refusing to overwrite a training run")
    output.mkdir(parents=True)
    catalog_bytes = catalog_path.read_bytes()
    catalog = json.loads(catalog_bytes)
    freeze = json.loads((catalog_path.parent / "SOURCE-AND-SPLIT-FREEZE.json").read_text())
    config = catalog["training"]
    report = {"schema": 6, "status": "running_local_diagnostic", "sealed": False,
              "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "device": platform.machine(),
              "platform": "local_diagnostic_numpy_cpu", "catalog_sha256": digest(catalog_bytes).hex(),
              "configuration": config, "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], text=True)),
              "tool_hashes": {p.name: digest(p.read_bytes()).hex() for p in Path(__file__).parent.glob('*.py')}}
    def save(): (output / "training.json").write_bytes(canonical(report) + b'\n')
    try:
        if freeze["catalog_sha256"] != report["catalog_sha256"]: raise ValueError("catalog changed after freeze")
        for source in catalog["sources"]:
            if source["rights_lane"] != "citation_only": raise ValueError("unsupported training rights lane")
            raw = (cache / (source["id"] + '.txt')).read_bytes()
            if digest(raw).hex() != source["sha256"]: raise ValueError("pinned source mismatch")
            text = raw.decode()
            for section in source["sections"]:
                if section not in text: raise ValueError("source section missing")
        rows = fixtures(catalog)
        frozen = json.loads((catalog_path.parent / "fixtures.json").read_text())
        if rows != frozen: raise ValueError("fixture source changed after freeze")
        contexts = training_fixtures(catalog)
        if contexts != json.loads((catalog_path.parent / "training-contexts.json").read_text()):
            raise ValueError("training contexts changed after freeze")
        n = len(catalog["nodes"])
        rng = np.random.default_rng(config["seed"])
        points = rng.normal(size=(n, 48)); points /= np.linalg.norm(points, axis=1)[:, None]
        initialized = points.copy()
        train_edges = [e for e in catalog["edges"] if e["split"] == "train"]
        context_edges = [applicable_edges(catalog, row['facts']) for row in contexts]
        covered = set().union(*context_edges)
        if covered != {e['id'] for e in train_edges}:
            raise ValueError("a declared training relation has no true, reachable frozen context")
        eligible_contexts = {e['id']: [i for i, active in enumerate(context_edges) if e['id'] in active]
                             for e in train_edges}
        # The exact conditioned graph supplies applicable edge updates. False
        # and unknown contexts do not become positive training observations.
        updates = 0
        for _ in range(config["steps"]):
            for index in rng.permutation(len(train_edges)):
                edge = train_edges[int(index)]
                context_index = int(rng.choice(eligible_contexts[edge['id']]))
                if edge['id'] not in context_edges[context_index]:
                    raise ValueError("condition-inapplicable optimizer input")
                a, b = edge["source"], edge["target"]
                difference = points[a] - points[b]
                distance = float(difference @ difference)
                if edge["polarity"] == 1:
                    gradient = 2 * config["learning_rate"] * difference
                    points[a] -= gradient; points[b] += gradient; updates += 1
                elif distance < config["margin"]:
                    gradient = config["learning_rate"] * difference / max(np.sqrt(distance), 1e-9)
                    points[a] += gradient; points[b] -= gradient; updates += 1
            if not np.isfinite(points).all(): raise ArithmeticError("nonfinite geometry")
        positives = [e for e in train_edges if e["polarity"] == 1]
        distances = [float(np.sum((points[e['source']] - points[e['target']]) ** 2)) for e in positives]
        negative_distances = [float(np.sum((points[e['source']] - points[e['target']]) ** 2))
                              for e in train_edges if e["polarity"] == -1]
        direct_pairs = {(min(e['source'],e['target']),max(e['source'],e['target'])) for e in positives}
        unrelated = [float(np.sum((points[a]-points[b])**2)) for a in range(n) for b in range(a+1,n)
                     if (a,b) not in direct_pairs]
        outcomes = [{"id": r["id"], "expected": r["expected_complete_path"],
                     "actual": neighborhood(catalog, r["facts"]),
                     "conditions_ignored": neighborhood(catalog, r["facts"], ignore_conditions=True)} for r in rows]
        false_paths = sum(not r["expected"] and r["actual"] for r in outcomes)
        false_rejects = sum(r["expected"] and not r["actual"] for r in outcomes)
        ignored_false_paths = sum(not r["expected"] and r["conditions_ignored"] for r in outcomes)
        trained_ids = sorted({e[k] for e in train_edges for k in ('source', 'target')})
        center = points[trained_ids].mean(axis=0)
        _u, _s, vt = np.linalg.svd(points[trained_ids] - center, full_matrices=False)
        basis = vt[:4].T
        shadow = (points - center) @ basis
        qpoints = np.rint(points * 1_000_000).astype(np.int32)
        qcenter = np.rint(center * 1_000_000).astype(np.int32)
        qbasis = np.rint(basis * 1_000_000).astype(np.int32)
        qshadow = ((qpoints.astype(np.int64) - qcenter) @ qbasis.astype(np.int64) // 1_000_000).astype(np.int32)
        geometry = {"dimensions": 48, "coordinates": points.tolist(), "initial_coordinates": initialized.tolist(),
                    "center": center.tolist(), "observer_basis": basis.tolist(), "observer_coordinates": shadow.tolist(),
                    "observer_fit_nodes": trained_ids, "observer_only": True, "updates": updates,
                    "quantized_coordinates": qpoints.tolist(), "quantized_center": qcenter.tolist(),
                    "quantized_basis": qbasis.tolist(), "quantized_shadow": qshadow.tolist()}
        (output / "geometry.json").write_bytes(canonical(geometry) + b'\n')
        gates = {"conditional_false_paths_zero": false_paths == 0,
                 "represented_positive_false_rejects_zero": false_rejects == 0,
                 "ignored_condition_control_fails": ignored_false_paths >= config["conditions_ignored_false_paths_min"],
                 "positive_continuity": max(distances) <= config["positive_squared_distance_max"],
                 "negative_separation": min(negative_distances) >= 0.45,
                 "observer_orthonormal": float(np.max(np.abs(basis.T @ basis - np.eye(4)))) <= 1e-10,
                 "cold_relation_never_trains": all(e["id"] not in freeze["cold_untrained_edges"] for e in train_edges)}
        report.update({"status": "locally_validated" if all(gates.values()) else "failed_local_validation",
                       "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "gates": gates,
                       "geometry_sha256": digest((output/'geometry.json').read_bytes()).hex(),
                       "metrics": {"positive_edge_max_squared_distance": max(distances), "false_paths": false_paths,
                                   "negative_edge_min_squared_distance": min(negative_distances),
                                   "raw_coordinate_nonedge_false_proximity_fraction": sum(d <= 0.02 for d in unrelated)/len(unrelated),
                                   "false_rejects": false_rejects, "conditions_ignored_false_paths": ignored_false_paths},
                       "cases": outcomes,
                       "training_contexts_sha256": digest((catalog_path.parent/'training-contexts.json').read_bytes()).hex(),
                       "conditioned_update_count": updates,
                       "claim_limit": "Static conditional mechanism and synthetic deployment patterns; no neural security advantage, unseen-mechanism admission or physical-host policy claim."})
        save()
        if not all(gates.values()): return 1
        pack, conditions = build(catalog, digest(catalog_bytes), digest((output/'training.json').read_bytes()),
                                 qpoints.tolist(), qcenter.tolist(), qbasis.tolist(), qshadow.tolist())
        (output/'world.bin').write_bytes(pack); (output/'conditions.bin').write_bytes(conditions)
        manifest = {"schema": 6, "status": "locally_validated_unsealed", "sealed": False,
                    "passive": True, "world_version": 6, "scope": catalog["scope"],
                    "catalog_sha256": digest(catalog_bytes).hex(),
                    "files": {name: digest((output/name).read_bytes()).hex() for name in
                              ('world.bin','conditions.bin','geometry.json','training.json')}}
        (output/'manifest.json').write_bytes(canonical(manifest) + b'\n')
        print(json.dumps(report['metrics'])); return 0
    except Exception as error:
        report.update({"status": "failed", "error": str(error)}); save(); raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--source-cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.exit(train(args.catalog, args.output, args.source_cache))
