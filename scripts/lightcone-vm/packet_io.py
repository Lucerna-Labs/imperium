"""Measure VM ingress/egress with healthy and quarantined passive Lightcone."""

import argparse
import json
import re
import shutil
import time
from pathlib import Path

from lab import CACHE, Lab, atomic_json
from packet_log import export_packet_logs
from phase1 import required, start_node, status
from traffic_guest import CASES

CASES_PER_ARM = ["tunnel_udp4", "tunnel_tcp4", "tunnel_icmp4", "direct_udp4",
                 "direct_udp6", "direct_tcp6", "loopback_udp4", "loopback_udp6"]


def set_phase(lab, name):
    for role in ("hub", "source", "receiver"):
        directory = lab.path / role / "control"
        temporary = directory / "current_phase.tmp"
        temporary.write_text(name)
        temporary.replace(directory / "current_phase")


def start_servers(lab):
    set_phase(lab, "setup")
    for role in ("hub", "receiver"):
        required(lab, role, f"python3 /lab/traffic_guest.py serve {role} >/control/traffic-server.log 2>&1 </dev/null & echo $! >/control/traffic-server.pid")
        required(lab, role, "for i in $(seq 1 50); do test -e /control/traffic-ready && exit 0; sleep .1; done; cat /control/traffic-server.log; exit 1")


def server_health(lab):
    result = {}
    for role in ("hub", "receiver"):
        value = json.loads(required(lab, role, "cat /control/traffic-health.json")["stdout"])
        if value["alive_threads"] != value["expected_threads"]:
            raise RuntimeError(f"{role} receiver worker stopped: {value}")
        result[role] = value
    return result


def captures(lab, name, start):
    metadata = {}
    if not start:
        # Allow pending capture delivery before interrupting readers. The
        # previous buffered reader could exit with packets still in its ring.
        time.sleep(1.2)
    for role in ("hub", "source", "receiver"):
        if start:
            required(lab, role, f"/lab/tcpdump --immediate-mode -U -n -s 0 -B 4096 -i any -w /tmp/{name}.pcap >/control/{name}-capture.log 2>&1 </dev/null & echo $! >/control/capture.pid")
            required(lab, role, f"for i in $(seq 1 40); do grep -q 'listening on' /control/{name}-capture.log && exit 0; sleep .1; done; cat /control/{name}-capture.log; exit 1")
        else:
            required(lab, role, f"kill -INT $(cat /control/capture.pid); sleep .5; cp /tmp/{name}.pcap /control/{name}.pcap")
            log = (lab.path / role / "control" / f"{name}-capture.log").read_text()
            match = re.search(r"(\d+) packets dropped by kernel", log)
            if not match or int(match.group(1)) != 0:
                raise RuntimeError(f"capture missing/lost packets in {role}/{name}: {log}")
            captured = re.search(r"(\d+) packets captured", log)
            filtered = re.search(r"(\d+) packets received by filter", log)
            metadata[role] = {"dropped_by_kernel": int(match.group(1)),
                              "packets_captured": int(captured.group(1)) if captured else None,
                              "packets_received_by_filter": int(filtered.group(1)) if filtered else None,
                              "log": log}
    return metadata


def save_interfaces(lab, name):
    for role in ("hub", "source", "receiver"):
        value = json.loads(required(lab, role, "ip -j addr")["stdout"])
        atomic_json(lab.path / role / "control" / f"{name}-interfaces.json", value)


def nodes(lab, name):
    injected = "IMPERIUM_LIGHTCONE_CRASH_AFTER_FRAMES=1" if name == "quarantined" else ""
    arguments = {"environment": injected, "log_filter": "info,imperium_net_lightcone=trace"}
    left = start_node(lab, "source", "192.0.2.2", "10.88.0.1", "impb",
                      "--route 10.77.0.0/24 --route 10.99.0.0/24", **arguments)
    right = start_node(lab, "receiver", "198.51.100.2", "10.99.0.1", "impc",
                       "--route 10.77.0.0/24 --route 10.88.0.0/24", **arguments)
    start_node(lab, "hub", "0.0.0.0", "10.77.0.1", "impa",
               f"--peer {left}@192.0.2.2:41000 --peer-route {left}=10.88.0.0/24 "
               f"--peer {right}@198.51.100.2:41000 --peer-route {right}=10.99.0.0/24", **arguments)
    required(lab, "hub", "for i in $(seq 1 150); do sed 's/\\x1b\\[[0-9;]*m//g' /control/node.log | grep -q 'peers_established=2' && exit 0; sleep .2; done; tail -5 /control/node.log; exit 1", 35)
    for role, address in (("hub", "192.0.2.1"), ("source", "192.0.2.2"), ("receiver", "198.51.100.2")):
        required(lab, role, "python3 - <<'PY'\nimport socket,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
                 f"for i in range(20):\n s.sendto(b'lc-io-control-stimulus',('{address}',41000));time.sleep(.01)\nPY")
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        snapshots = {role: status(lab, role) for role in ("hub", "source", "receiver")}
        if name == "healthy" and all(item.get("working") is True for item in snapshots.values()):
            return snapshots
        if name == "quarantined" and all(item.get("strand_lifecycle") == "quarantined" for item in snapshots.values()):
            return snapshots
        time.sleep(0.2)
    raise RuntimeError(f"{name} Lightcone control was not established: {snapshots}")


def stop_nodes(lab, name):
    for role in ("hub", "source", "receiver"):
        required(lab, role, "kill -INT $(cat /control/node.pid)")
    required(lab, "hub", "for i in $(seq 1 60); do ip route show | grep -qE '10\\.(88|99)' || exit 0; sleep .2; done; exit 1", 15)
    time.sleep(0.5)
    for role in ("hub", "source", "receiver"):
        required(lab, role, f"cp /control/node.log /control/{name}-node.log")


def case_probe(lab, name, case):
    print(f"  {name}: {case}", flush=True)
    if case == "tunnel_icmp4":
        value = lab.run("source", "ping -n -q -c 3 -W 1 10.99.0.1", 10)
        match = re.search(r"(\d+) received", value["stdout"])
        result = {"phase": name, "case": case, "attempted": 3,
                  "echoed": int(match.group(1)) if match else None, **value}
        atomic_json(lab.path / "source/control" / f"{name}-{case}-client.json", result)
    else:
        role = "hub" if case.startswith("loopback") else "source"
        result = json.loads(required(lab, role, f"python3 /lab/traffic_guest.py probe {case}", 30)["stdout"])
    print(f"    attempted={result['attempted']} echoes={result['echoed']}", flush=True)
    return result


def arm(lab, name):
    set_phase(lab, name)
    print(f"Starting {name} matched arm", flush=True)
    captures(lab, name, True)
    beginning = nodes(lab, name)
    save_interfaces(lab, name)
    cases = {}
    snapshots = {}
    for case in CASES_PER_ARM:
        server_health(lab)
        cases[case] = case_probe(lab, name, case)
        snapshots[case] = {role: status(lab, role) for role in ("hub", "source", "receiver")}
        server_health(lab)
    ending = {role: status(lab, role) for role in ("hub", "source", "receiver")}
    if name == "quarantined" and not all(value.get("strand_lifecycle") == "quarantined" for value in ending.values()):
        raise RuntimeError("quarantine control ended before measured traffic finished")
    stop_nodes(lab, name)
    capture_stats = captures(lab, name, False)
    normalized = export_packet_logs(lab.path, name)
    result = {"beginning_status": beginning, "ending_status": ending, "cases": cases,
              "case_status_snapshots": snapshots, "capture_stats": capture_stats,
              "packet_receipt_summary": normalized, "receiver_health": server_health(lab)}
    atomic_json(lab.path / f"{name}-result.json", result)
    return result


def measurement_control(lab):
    result = {}
    for name, case in (("kernel_blocked", "blocked_udp4"), ("kernel_recovered", "recovered_udp4")):
        set_phase(lab, name)
        captures(lab, name, True)
        save_interfaces(lab, name)
        if name == "kernel_blocked":
            required(lab, "hub", "/lab/nft -f - <<'NFT'\nadd table inet lc_io_control\nadd chain inet lc_io_control forward { type filter hook forward priority 0; policy accept; }\nadd rule inet lc_io_control forward ip saddr 192.0.2.2 ip daddr 198.51.100.2 udp dport 45998 counter queue num 42778\nNFT")
        else:
            required(lab, "hub", "/lab/nft delete table inet lc_io_control")
        health = server_health(lab)
        measured = case_probe(lab, name, case)
        counters = (json.loads(required(lab, "hub", "/lab/nft -j list table inet lc_io_control")["stdout"])
                    if name == "kernel_blocked" else None)
        capture_stats = captures(lab, name, False)
        normalized = export_packet_logs(lab.path, name)
        result[name] = {"case": measured, "capture_stats": capture_stats,
                        "packet_receipt_summary": normalized, "queue_rules": counters,
                        "receiver_health_before": health, "receiver_health_after": server_health(lab)}
    atomic_json(lab.path / "measurement-control.json", result)
    return result


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()] if Path(path).is_file() else []


def case_summary(lab, name, case, result):
    packets = {role: read_jsonl(lab.path / f"{name}-{role}-packets.jsonl")
               for role in ("hub", "source", "receiver")}
    if case == "tunnel_icmp4":
        def wanted(packet):
            return packet.get("source") == "10.88.0.1" and packet.get("destination") == "10.99.0.1" and packet.get("icmp_type") == 8
        key = lambda packet: (packet.get("icmp_id"), packet.get("icmp_sequence"))
    else:
        family, protocol, source, destination, port, count = CASES[case]
        def wanted(packet):
            return packet.get("destination") == destination and packet.get("destination_port") == port and any(value.startswith(case + ":") for value in packet["case_ids"])
        key = lambda packet: tuple(value for value in packet["case_ids"] if value.startswith(case + ":"))
    count_at = lambda role, direction: len({key(packet) for packet in packets[role]
                                           if wanted(packet) and packet["direction"] == direction})
    server_role = "hub" if case.startswith("loopback") else "receiver"
    application = read_jsonl(lab.path / server_role / "control/application.jsonl")
    received = {record.get("data_utf8", "") for record in application
                if record.get("phase") == name and record.get("event") == "server_received"
                and record.get("data_utf8", "").startswith("LCIO|" + case + "|")}
    row = {"phase": name, "case": case, "attempted": result["attempted"], "client_echoes": result["echoed"],
           "source_capture_out": count_at("source", "out"), "hub_capture_in": count_at("hub", "in"),
           "hub_capture_out": count_at("hub", "out"), "receiver_capture_in": count_at(server_role, "in"),
           "server_unique_received": len(received) if case != "tunnel_icmp4" else None}
    receipts = read_jsonl(lab.path / f"{name}-hub-receipts.jsonl")
    matching_packet_indexes = {p["record"] for p in packets["hub"] if wanted(p)}
    row["hub_raw_ip_receipts_with_case_hash_match"] = sum(
        r.get("frame_format") == "RawIp" and bool(matching_packet_indexes.intersection(r["capture_records"])) for r in receipts)
    return row


def summarize(lab, report):
    rows = []
    for name in ("healthy", "quarantined"):
        rows += [case_summary(lab, name, case, value) for case, value in report[name]["cases"].items()]
    for name, value in report["measurement_control"].items():
        rows.append(case_summary(lab, name, value["case"]["case"], value["case"]))
    paired = {}
    for case in CASES_PER_ARM:
        healthy = next(row for row in rows if row["phase"] == "healthy" and row["case"] == case)
        stopped = next(row for row in rows if row["phase"] == "quarantined" and row["case"] == case)
        paired[case] = {"healthy_echoes": healthy["client_echoes"], "quarantined_echoes": stopped["client_echoes"],
                        "delivery_changed": healthy["client_echoes"] != stopped["client_echoes"]}
    baseline_complete = all(value["echoed"] == value["attempted"] for value in report["healthy"]["cases"].values())
    blocked = next(row for row in rows if row["phase"] == "kernel_blocked")
    recovered = next(row for row in rows if row["phase"] == "kernel_recovered")
    measurement_pass = (blocked["hub_capture_in"] == 5 and blocked["hub_capture_out"] == 0
                        and blocked["server_unique_received"] == 0 and blocked["client_echoes"] == 0
                        and recovered["hub_capture_in"] == 3 and recovered["hub_capture_out"] == 3
                        and recovered["server_unique_received"] == 3 and recovered["client_echoes"] == 3)
    result = {"rows": rows, "paired_cases": paired, "healthy_delivery_baseline_complete": baseline_complete,
              "measurement_block_recovery_pass": measurement_pass,
              "delivery_change_detected": any(value["delivery_changed"] for value in paired.values()),
              "claim_limit": "Bounded synthetic VM traffic, receipt availability and current forwarding dependency only; no trained-world benefit or all-host protection claim"}
    atomic_json(lab.path / "comparison.json", result)
    markdown = ["# VM packet input/output comparison", "", "| Arm | Case | Attempts | Hub in | Hub out | Receiver data IDs | Echoes |", "| --- | --- | ---: | ---: | ---: | ---: | ---: |"]
    markdown += [f"| {row['phase']} | {row['case']} | {row['attempted']} | {row['hub_capture_in']} | {row['hub_capture_out']} | {row['server_unique_received']} | {row['client_echoes']} |" for row in rows]
    markdown += ["", f"Healthy baseline complete: {baseline_complete}", f"Measurement blocking/recovery control passed: {measurement_pass}",
                 f"Delivery change detected between healthy and quarantined Lightcone: {result['delivery_change_detected']}", "", result["claim_limit"]]
    (lab.path / "comparison.md").write_text("\n".join(markdown) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=CACHE / "io-runs" / time.strftime("%Y%m%d-%H%M%S"))
    args = parser.parse_args()
    lab = Lab(args.run_dir)
    report = {"experiment": "input-output-v1", "world_unsealed": True}
    print(f"Packet evidence directory: {lab.path}", flush=True)
    try:
        lab.prepare()
        shutil.copy2(Path(__file__).with_name("traffic_guest.py"), lab.input / "traffic_guest.py")
        lab.start()
        start_servers(lab)
        report["healthy"] = arm(lab, "healthy")
        report["quarantined"] = arm(lab, "quarantined")
        report["measurement_control"] = measurement_control(lab)
        report["comparison"] = summarize(lab, report)
    except Exception as error:
        report["execution_error"] = str(error)
        print(f"Experiment error: {error}", flush=True)
    finally:
        lab.close()
        report["owned_vms_stopped"] = all(process.poll() is not None for process in lab.processes.values())
        atomic_json(lab.path / "report.json", report)
    print(json.dumps({key: value for key, value in report.items() if not isinstance(value, dict)}), flush=True)
    return 0 if "comparison" in report and report["comparison"]["measurement_block_recovery_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
