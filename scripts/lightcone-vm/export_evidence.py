"""Export small, non-secret VM evidence; guest disk/key files stay private."""

import argparse
import shutil
from pathlib import Path

from lab import atomic_json, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    root = args.run.resolve()
    args.destination.mkdir(parents=True, exist_ok=False)
    paths = [root / name for name in ("manifest.json", "report.json", "commands.json")]
    for role in ("hub", "source", "receiver"):
        paths += list((root / role / "control").glob("ready.json"))
        paths += list((root / role / "control").glob("*.pcap"))
        paths += list((root / role / "control").glob("udp-received.json"))
    paths += list(root.glob("baseline.json")) + list(root.glob("no-listener.json"))
    paths += list(root.glob("recovery.json")) + list(root.glob("mesh.json"))
    hashes = {}
    for path in paths:
        if not path.is_file():
            raise RuntimeError(f"missing evidence: {path}")
        relative = path.relative_to(root)
        destination = args.destination / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        hashes[str(relative)] = {"sha256": digest(destination), "size": destination.stat().st_size}
    log_hashes = {}
    for path in root.glob("*/serial.log"):
        log_hashes[str(path.relative_to(root))] = {"sha256": digest(path), "size": path.stat().st_size}
    for path in root.glob("*/control/node.log"):
        log_hashes[str(path.relative_to(root))] = {"sha256": digest(path), "size": path.stat().st_size}
    atomic_json(args.destination / "evidence-hashes.json", {"copied": hashes, "retained_local_logs": log_hashes,
                "private_original_run": str(root), "guest_keys_and_disks_exported": False})
    print(f"Exported {len(hashes)} evidence files; private keys and disks remain in {root}")


if __name__ == "__main__":
    main()
