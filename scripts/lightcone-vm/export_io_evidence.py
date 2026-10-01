"""Export synthetic packet evidence; private guest keys/disks are excluded."""

import argparse
import json
import shutil
from pathlib import Path

from lab import atomic_json, digest
from packet_io import read_jsonl
from packet_log import MARKER


def application_integrity(root):
    rows = []
    for phase in ("healthy", "quarantined", "kernel_blocked", "kernel_recovered"):
        sent = {}
        received = {}
        duplicates = {}
        errors = 0
        for role in ("hub", "source", "receiver"):
            for event in read_jsonl(root / role / "control/application.jsonl"):
                if event.get("phase") != phase:
                    continue
                if event.get("event") == "client_error":
                    errors += 1
                raw = bytes.fromhex(event.get("data_hex", ""))
                for case, sequence in MARKER.findall(raw):
                    key = case.decode() + ":" + sequence.decode()
                    if event["event"] == "client_sent":
                        sent[key] = event["sha256"]
                    elif event["event"] == "server_received":
                        received.setdefault(key, []).append(event["sha256"])
        for key, values in received.items():
            if len(values) > 1:
                duplicates[key] = len(values)
        mismatches = [key for key, values in received.items()
                      if key not in sent or any(value != sent[key] for value in values)]
        rows.append({"phase": phase, "application_ids_sent": len(sent),
                     "application_ids_received": len(received), "receiver_duplicates": duplicates,
                     "receiver_payload_hash_mismatches": mismatches, "client_errors": errors,
                     "icmp_note": "ICMP is independently measured by ping and packet captures, outside this application byte log"})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    root = args.run.resolve()
    report = json.loads((root / "report.json").read_text())
    if not report.get("owned_vms_stopped") or not report.get("comparison", {}).get("measurement_block_recovery_pass"):
        raise RuntimeError("refusing to label an incomplete/failed measurement run as accepted evidence")
    args.destination.mkdir(parents=True, exist_ok=False)
    paths = [root / name for name in ("manifest.json", "report.json", "commands.json", "comparison.json",
                                     "comparison.md", "healthy-result.json", "quarantined-result.json",
                                     "measurement-control.json")]
    for pattern in ("*-packets.jsonl", "*-packets.csv", "*-receipts.jsonl"):
        paths += list(root.glob(pattern))
    for role in ("hub", "source", "receiver"):
        paths.append(root / role / "qemu-command.json")
        control = root / role / "control"
        for pattern in ("ready.json", "*.pcap", "*-capture.log", "*-interfaces.json", "application.jsonl",
                        "*-client.json", "healthy-node.log", "quarantined-node.log", "traffic-health.json",
                        "traffic-server.log"):
            paths += list(control.glob(pattern))
    hashes = {}
    for path in sorted(set(paths)):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"missing or unsafe evidence: {path}")
        relative = path.relative_to(root)
        destination = args.destination / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        hashes[str(relative)] = {"sha256": digest(destination), "bytes": destination.stat().st_size}
    integrity = application_integrity(root)
    atomic_json(args.destination / "application-integrity.json", integrity)
    hashes["application-integrity.json"] = {"sha256": digest(args.destination / "application-integrity.json"),
                                             "bytes": (args.destination / "application-integrity.json").stat().st_size}
    for relative, expected in hashes.items():
        if digest(args.destination / relative) != expected["sha256"]:
            raise RuntimeError(f"export checksum mismatch: {relative}")
    atomic_json(args.destination / "evidence-hashes.json", {"files": hashes,
                "private_original_run": str(root), "guest_keys_and_disks_exported": False})
    print(f"Exported and verified {len(hashes)} files; {sum(value['bytes'] for value in hashes.values())} bytes")
    print(json.dumps(integrity))


if __name__ == "__main__":
    main()
