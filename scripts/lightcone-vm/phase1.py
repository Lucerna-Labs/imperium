"""Execute the frozen VM baseline; failed filtering is recorded, not hidden."""

import argparse
import json
import re
import time
from pathlib import Path

from lab import CACHE, Lab, atomic_json

PATHS = [("input4", "source", "192.0.2.1"), ("input6", "source", "fd77::1"),
         ("output4", "hub", "198.51.100.2"), ("output6", "hub", "fd78::2"),
         ("forward4", "source", "198.51.100.2"), ("forward6", "source", "fd78::2"),
         ("loopback4", "hub", "127.0.0.1"), ("loopback6", "hub", "::1")]


def required(lab, role, command, timeout=45):
    result = lab.run(role, command, timeout)
    if result["returncode"] != 0:
        raise RuntimeError(f"{role}: {command}: {result}")
    return result


def capture(lab, phase, start):
    if start:
        command = f"/lab/tcpdump -U -n -i any -w /tmp/{phase}.pcap 'icmp or icmp6 or udp port 45999' "
        command += f">/control/{phase}-capture.log 2>&1 </dev/null & echo $! >/control/capture.pid"
        required(lab, "receiver", command)
        required(lab, "receiver", f"for i in $(seq 1 30); do grep -q 'listening on' /control/{phase}-capture.log && exit 0; sleep .1; done; exit 1")
    else:
        required(lab, "receiver", f"kill -INT $(cat /control/capture.pid); sleep .5; cp /tmp/{phase}.pcap /control/{phase}.pcap")


def probes(lab, name, blocked=False):
    print(f"Running {name} eight-path IPv4/IPv6 matrix", flush=True)
    capture(lab, name, True)
    entries = []
    try:
        for label, role, address in PATHS:
            result = lab.run(role, f"ping -n -q -c 3 -W 1 {address}", 12)
            match = re.search(r"(\d+) received", result["stdout"])
            received = int(match.group(1)) if match else None
            passed = received == (0 if blocked else 3) and result["returncode"] == (1 if blocked else 0)
            entries.append({"path": label, "received": received, "pass": passed, **result})
            print(f"  {label}: received={received} expected={0 if blocked else 3}", flush=True)
        for role in ("source", "receiver"):
            required(lab, role, "ping -n -q -c 1 -W 1 127.0.0.1")
    finally:
        capture(lab, name, False)
    pcap = lab.path / "receiver/control" / (name + ".pcap")
    result = required(lab, "receiver", f"/lab/tcpdump -nn -r /control/{name}.pcap")
    echo_requests = sum("echo request" in line for line in result["stdout"].splitlines())
    evidence = {"paths": entries, "receiver_echo_requests": echo_requests,
                "receiver_capture": str(pcap.relative_to(lab.path)),
                "pass": all(x["pass"] for x in entries) and (echo_requests == 0 if blocked else echo_requests >= 12)}
    atomic_json(lab.path / (name + ".json"), evidence)
    if not evidence["pass"]:
        raise RuntimeError(f"{name} control failed; inspect {name}.json")
    return evidence


def start_node(lab, role, bind, tunnel, tun, extra="", environment="", log_filter="info"):
    required(lab, role, "mkdir -p /run/lcnode; chmod 700 /run/lcnode")
    # Door one: each guest judges with its own role's trained-path world.
    command = (f"{environment} IMPERIUM_LIGHTCONE_ROLE={role} XDG_RUNTIME_DIR=/run/lcnode IMPERIUM_OPERATOR_KEY=/lab/operator-key "
               f"IMPERIUM_MESH_IDENTITY=/control/identity RUST_LOG={log_filter} /lab/imperium node start "
               f"--mesh-bind {bind}:41000 --tunnel-ip {tunnel} --tun {tun} "
               "--cluster-id 44444444-4444-4444-8444-444444444444 --report-secs 2 "
               f"{extra} >/control/node.log 2>&1 </dev/null & echo $! >/control/node.pid")
    required(lab, role, command)
    ready = required(lab, role, "for i in $(seq 1 150); do grep -q 'mesh link bound' /control/node.log && exit 0; sleep .2; done; tail -20 /control/node.log; exit 1", 35)
    text = (lab.path / role / "control/node.log").read_text()
    ids = re.findall(r"peer_id[^0-9a-f-]*([0-9a-f-]{36})", re.sub(r"\x1b\[[0-9;]*m", "", text))
    if not ids:
        raise RuntimeError(f"{role} peer id absent after node bound: {ready}")
    return ids[0]


def status(lab, role):
    result = required(lab, role, "python3 - <<'PY'\nimport socket\nwith socket.socket(socket.AF_UNIX) as s:\n s.settimeout(3); s.connect('/run/lcnode/imperium/control.sock'); s.sendall(b'vpn lightcone status\\n'); data=b''\n while not data.endswith(b'\\n'):\n  part=s.recv(65536)\n  if not part: break\n  data+=part\n print(data.decode())\nPY")
    return json.loads(result["stdout"])


def mesh(lab):
    print("Starting native Imperium in all three VMs", flush=True)
    b = start_node(lab, "source", "192.0.2.2", "10.88.0.1", "impb", "--route 10.77.0.0/24")
    c = start_node(lab, "receiver", "198.51.100.2", "10.99.0.1", "impc", "--route 10.77.0.0/24")
    start_node(lab, "hub", "0.0.0.0", "10.77.0.1", "impa",
               f"--peer {b}@192.0.2.2:41000 --peer-route {b}=10.88.0.0/24 "
               f"--peer {c}@198.51.100.2:41000 --peer-route {c}=10.99.0.0/24")
    required(lab, "hub", "for i in $(seq 1 150); do sed 's/\\x1b\\[[0-9;]*m//g' /control/node.log | grep -q 'peers_established=2' && exit 0; sleep .2; done; tail -5 /control/node.log; exit 1", 35)
    routed = [required(lab, "hub", "ping -n -q -c 3 -W 2 " + addr) for addr in ("10.88.0.1", "10.99.0.1")]
    capture(lab, "mesh", True)
    required(lab, "receiver", "python3 - <<'PY' >/control/udp.log 2>&1 &\nimport socket,json,pathlib\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.99.0.1',45999));s.settimeout(8);pathlib.Path('/control/udp-ready').touch()\ntry:\n data,peer=s.recvfrom(256);pathlib.Path('/control/udp-received.json').write_text(json.dumps({'payload':data.decode(),'peer':peer}))\nexcept socket.timeout: pass\nPY")
    required(lab, "receiver", "for i in $(seq 1 40); do test -e /control/udp-ready && exit 0; sleep .1; done; cat /control/udp.log; exit 1")
    required(lab, "hub", "python3 - <<'PY'\nimport socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'imperium-vm-untrained-flow',('10.99.0.1',45999))\nPY")
    time.sleep(2)
    capture(lab, "mesh", False)
    received_file = lab.path / "receiver/control/udp-received.json"
    delivered = received_file.exists() and json.loads(received_file.read_text())["payload"] == "imperium-vm-untrained-flow"
    statuses = {role: status(lab, role) for role in ("hub", "source", "receiver")}
    receipts = all(value.get("working") is True and value.get("sealed") is False
                   and value.get("world_version") == 4
                   and value.get("pack_sha256") == lab.manifest["world_sha256"]
                   and value.get("training_platform") == "local_diagnostic"
                   and value.get("passive") is True and value.get("holds_verdict") is False
                   and value.get("raw_ip_rx", 0) > 0 and value.get("raw_ip_tx", 0) > 0
                   and value.get("mesh_rx", 0) > 0 and value.get("mesh_tx", 0) > 0
                   and value.get("lightcone_observations_dropped") == 0
                   and value.get("lightcone_publish_errors") == 0
                   and value.get("pending_observations") == 0
                   and value.get("filter_enforced") is False for value in statuses.values())
    for role in ("hub", "source", "receiver"):
        required(lab, role, "kill -TERM $(cat /control/node.pid)")
    required(lab, "hub", "for i in $(seq 1 40); do ip route show | grep -qE '10\\.(88|99)' || exit 0; sleep .25; done; exit 1", 15)
    result = {"routed": routed, "statuses": statuses, "receipt_integration_pass": receipts,
              "undeclared_udp_delivered": delivered, "filter_pass": False,
              "filter_probe_outcome": "failed" if delivered else "inconclusive",
              "teardown_routes_removed": True}
    atomic_json(lab.path / "mesh.json", result)
    if not receipts:
        raise RuntimeError("VM mesh receipt integration failed")
    print(f"VM mesh receipt integration PASS; undeclared UDP delivered={delivered}; filter_pass=False", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=CACHE / "runs" / time.strftime("%Y%m%d-%H%M%S"))
    args = parser.parse_args()
    lab = Lab(args.run_dir)
    report = {"matrix": "phase1", "phase1_controls_pass": False, "filter_pass": False}
    print(f"VM evidence directory: {lab.path}", flush=True)
    try:
        lab.prepare()
        print("Pinned guest image and binaries verified; booting three KVM guests", flush=True)
        lab.start()
        print("All three guests ready with private links", flush=True)
        for label, role, address in PATHS:
            required(lab, role, f"ping -n -q -c 1 -W 2 {address}")
        report["baseline"] = probes(lab, "baseline")
        rules = "add table inet lc_vm\n"
        for hook in ("input", "output", "forward"):
            rules += f"add chain inet lc_vm {hook} {{ type filter hook {hook} priority 0; policy accept; }}\n"
            for family in ("ipv4", "ipv6"):
                rules += f"add rule inet lc_vm {hook} meta nfproto {family} counter queue num 42777\n"
        required(lab, "hub", "/lab/nft -f - <<'NFT'\n" + rules + "NFT")
        report["blocked"] = probes(lab, "no-listener", True)
        counters = required(lab, "hub", "/lab/nft -j list table inet lc_vm")
        report["queue_rules"] = json.loads(counters["stdout"])
        counter_values = [expr["counter"]["packets"] for item in report["queue_rules"]["nftables"]
                          for expr in item.get("rule", {}).get("expr", []) if "counter" in expr]
        if len(counter_values) != 6 or not all(value > 0 for value in counter_values):
            raise RuntimeError("not every family/hook queue counter advanced")
        required(lab, "hub", "/lab/nft delete table inet lc_vm")
        report["recovery"] = probes(lab, "recovery")
        report["phase1_controls_pass"] = True
        report["mesh"] = mesh(lab)
        report["filter_pass"] = report["mesh"]["filter_pass"]
    except Exception as error:
        report["execution_error"] = str(error)
        print(f"Experiment stopped: {error}", flush=True)
    finally:
        lab.close()
        report["owned_vms_stopped"] = all(process.poll() is not None for process in lab.processes.values())
        atomic_json(lab.path / "report.json", report)
    print(json.dumps({key: value for key, value in report.items() if not isinstance(value, dict)}), flush=True)
    if not report["phase1_controls_pass"] or not report.get("mesh", {}).get("receipt_integration_pass"):
        return 1
    return 3 if report["mesh"]["undeclared_udp_delivered"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
