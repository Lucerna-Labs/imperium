"""Console/directory-managed guest agent; no IP management interface."""

import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

CONTROL = Path("/control")
MACS = {
    "hub": [("52:54:00:77:00:01", "192.0.2.1/24", "fd77::1/64"),
            ("52:54:00:78:00:01", "198.51.100.1/24", "fd78::1/64")],
    "source": [("52:54:00:77:00:02", "192.0.2.2/24", "fd77::2/64")],
    "receiver": [("52:54:00:78:00:02", "198.51.100.2/24", "fd78::2/64")],
}


def run(args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def atomic(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def setup(role):
    run(["ip", "link", "set", "lo", "up"])
    for mac, ipv4, ipv6 in MACS[role]:
        interface = next(p.name for p in Path("/sys/class/net").iterdir()
                         if (p / "address").read_text().strip() == mac)
        run(["ip", "link", "set", interface, "up"])
        run(["ip", "addr", "replace", ipv4, "dev", interface])
        run(["ip", "-6", "addr", "replace", ipv6, "dev", interface, "nodad"])
    if role == "hub":
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
        Path("/proc/sys/net/ipv6/conf/all/forwarding").write_text("1\n")
    else:
        routes = ("198.51.100.0/24", "192.0.2.1", "fd78::/64", "fd77::1") if role == "source" else (
            "192.0.2.0/24", "198.51.100.1", "fd77::/64", "fd78::1")
        run(["ip", "route", "replace", routes[0], "via", routes[1]])
        run(["ip", "-6", "route", "replace", routes[2], "via", routes[3]])
    atomic(CONTROL / "ready.json", {"role": role, "kernel": platform.release(),
           "uid": os.getuid(), "interfaces": json.loads(run(["ip", "-j", "addr"])),
           "routes": json.loads(run(["ip", "-j", "route"])),
           "ipv6_routes": json.loads(run(["ip", "-6", "-j", "route"]))})


def main():
    role = sys.argv[1]
    setup(role)
    sequence = 1
    while True:
        path = CONTROL / f"cmd-{sequence:04d}.json"
        if not path.exists():
            time.sleep(0.1)
            continue
        command = json.loads(path.read_text())
        started = time.monotonic()
        try:
            result = subprocess.run(["bash", "-c", command["command"]], text=True,
                                    capture_output=True, timeout=command["timeout"])
            data = {"returncode": result.returncode, "stdout": result.stdout,
                    "stderr": result.stderr, "elapsed": time.monotonic() - started}
        except subprocess.TimeoutExpired as error:
            data = {"returncode": 124, "stdout": str(error.stdout or ""),
                    "stderr": "guest command timeout", "elapsed": time.monotonic() - started}
        atomic(CONTROL / f"result-{sequence:04d}.json", data)
        sequence += 1


if __name__ == "__main__":
    main()
