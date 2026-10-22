"""LIVE-BRAIN-1 (DOOR-TWO-BRAIN-PRECOMMIT-2026-10-21.md): door two running inside live Imperium nodes.

Three fresh-start episodes in the three-VM lab. Each node runs with its lightcone role and
IMPERIUM_BRAIN_STATE=/control/brain (evidence kept across restarts). After each episode the driver
reads every node's `vpn brain status` through its control socket.
"""

import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path

from lab import CACHE, Lab, atomic_json
from packet_io import CASES_PER_ARM, case_probe, set_phase, start_servers, stop_nodes
from phase1 import required, start_node, status

ROLES = ("hub", "source", "receiver")
EPISODES = 3
BRAIN_ENV = "IMPERIUM_BRAIN_STATE=/control/brain"
PACK_DIR = None  # set by --pack-dir: door one's world comes from /lab/packs (RESEAL-1 VM test)


def nodes(lab):
    env = BRAIN_ENV + (" IMPERIUM_LIGHTCONE_PACK_DIR=/lab/packs" if PACK_DIR else "")
    args = {"environment": env, "log_filter": "info"}
    left = start_node(lab, "source", "192.0.2.2", "10.88.0.1", "impb", "--route 10.77.0.0/24 --route 10.99.0.0/24", **args)
    right = start_node(lab, "receiver", "198.51.100.2", "10.99.0.1", "impc", "--route 10.77.0.0/24 --route 10.88.0.0/24", **args)
    start_node(lab, "hub", "0.0.0.0", "10.77.0.1", "impa",
               f"--peer {left}@192.0.2.2:41000 --peer-route {left}=10.88.0.0/24 "
               f"--peer {right}@198.51.100.2:41000 --peer-route {right}=10.99.0.0/24", **args)
    required(lab, "hub", "for i in $(seq 1 150); do sed 's/\\x1b\\[[0-9;]*m//g' /control/node.log | grep -q 'peers_established=2' && exit 0; sleep .2; done; tail -5 /control/node.log; exit 1", 35)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if all(status(lab, r).get("working") is True for r in ROLES):
            return
        time.sleep(0.3)


def brain_status(lab, role):
    result = required(lab, role, "python3 - <<'PY'\nimport socket\nwith socket.socket(socket.AF_UNIX) as s:\n s.settimeout(3); s.connect('/run/lcnode/imperium/control.sock'); s.sendall(b'vpn brain status\\n'); data=b''\n while not data.endswith(b'\\n'):\n  part=s.recv(65536)\n  if not part: break\n  data+=part\n print(data.decode())\nPY")
    return json.loads(result["stdout"])


def main():
    global PACK_DIR
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pack-dir", type=Path, default=None, help="candidate packs for door one (<role>.pathpack)")
    PACK_DIR = ap.parse_args().pack_dir
    lab = Lab(CACHE / "brain-live-runs" / time.strftime("%Y%m%d-%H%M%S"))
    report = {"experiment": "RESEAL-1 VM test" if PACK_DIR else "LIVE-BRAIN-1", "episodes": {}, "pack_dir": str(PACK_DIR)}
    print(f"Run directory: {lab.path}", flush=True)
    try:
        lab.prepare()
        shutil.copy2(Path(__file__).with_name("traffic_guest.py"), lab.input / "traffic_guest.py")
        if PACK_DIR:
            (lab.input / "packs").mkdir()
            for role in ROLES:
                shutil.copy2(PACK_DIR / f"{role}.pathpack", lab.input / "packs" / f"{role}.pathpack")
        lab.start()
        start_servers(lab)
        for ep in range(1, EPISODES + 1):
            name = f"ep{ep}"
            set_phase(lab, name)
            print(f"-- episode {ep}", flush=True)
            nodes(lab)
            time.sleep(4)  # let fresh-TUN housekeeping (MLD/RS repeats) happen
            echoes = {}
            for case in CASES_PER_ARM:
                r = case_probe(lab, name, case)
                echoes[case] = [r["echoed"], r["attempted"]]
            time.sleep(2)
            brains = {role: brain_status(lab, role) for role in ROLES}
            for role, b in brains.items():
                print(f"   {role}: active={b.get('active')} world={b.get('world')} observed={b.get('observed')} "
                      f"self_caused={b.get('self_caused')} unexplained={b.get('unexplained')} evidence={b.get('evidence')} "
                      f"added={b.get('added')} add_only={b.get('review_add_only')} deny_clean={b.get('review_deny_clean')} "
                      f"admits_all={b.get('review_admits_all_evidence')} reseal_ready={b.get('reseal_ready')}", flush=True)
            report["episodes"][ep] = {"echoes": echoes, "brain": brains}
            stop_nodes(lab, name)
    except Exception as error:
        report["execution_error"] = str(error)
        print(f"Experiment error: {error}", flush=True)
    finally:
        lab.close()
        report["owned_vms_stopped"] = all(p.poll() is not None for p in lab.processes.values())
        atomic_json(lab.path / "brain-live-report.json", report)
    return 0 if "execution_error" not in report else 1


if __name__ == "__main__":
    raise SystemExit(main())
