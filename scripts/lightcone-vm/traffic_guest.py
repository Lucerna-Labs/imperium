"""Bounded synthetic echo traffic and application logs inside owned lab guests."""

import argparse
import hashlib
import json
import os
import socket
import threading
import time
from pathlib import Path

CONTROL = Path("/control")
LOCK = threading.Lock()
CASES = {
    "tunnel_udp4": (4, "udp", "10.88.0.1", "10.99.0.1", 45999, 10),
    "tunnel_tcp4": (4, "tcp", "10.88.0.1", "10.99.0.1", 46000, 5),
    "direct_udp4": (4, "udp", "192.0.2.2", "198.51.100.2", 45998, 10),
    "direct_udp6": (6, "udp", "fd77::2", "fd78::2", 45998, 10),
    "direct_tcp6": (6, "tcp", "fd77::2", "fd78::2", 46001, 5),
    "loopback_udp4": (4, "udp", "127.0.0.1", "127.0.0.1", 45997, 3),
    "loopback_udp6": (6, "udp", "::1", "::1", 45997, 3),
    "blocked_udp4": (4, "udp", "192.0.2.2", "198.51.100.2", 45998, 5),
    "recovered_udp4": (4, "udp", "192.0.2.2", "198.51.100.2", 45998, 3),
}


def phase():
    return (CONTROL / "current_phase").read_text().strip()


def append(event, **values):
    record = {"event": event, "phase": phase(), "time_ns": time.time_ns(), **values}
    with LOCK, (CONTROL / "application.jsonl").open("a") as output:
        output.write(json.dumps(record) + "\n")


def contents(payload):
    return {"data_hex": payload.hex(), "data_utf8": payload.decode("ascii", errors="replace"),
            "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def make_socket(family, kind, address, port):
    connection = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, kind)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == 6:
        connection.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    connection.bind((address, port))
    connection.settimeout(1)
    return connection


def udp_server(connection, family):
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            payload, peer = connection.recvfrom(4096)
        except socket.timeout:
            continue
        append("server_received", family=family, protocol="udp", peer=peer,
               local=connection.getsockname(), **contents(payload))
        try:
            connection.sendto(payload, peer)
            append("server_echoed", family=family, protocol="udp", peer=peer,
                   local=connection.getsockname(), **contents(payload))
        except OSError as error:
            append("server_error", protocol="udp", error=str(error))


def tcp_server(connection, family):
    connection.listen(16)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            client, peer = connection.accept()
        except socket.timeout:
            continue
        with client:
            client.settimeout(2)
            try:
                payload = b""
                while not payload.endswith(b"\n") and len(payload) < 4096:
                    chunk = client.recv(4096 - len(payload))
                    if not chunk:
                        break
                    payload += chunk
                append("server_received", family=family, protocol="tcp", peer=peer,
                       local=client.getsockname(), **contents(payload))
                client.sendall(payload)
                append("server_echoed", family=family, protocol="tcp", peer=peer,
                       local=client.getsockname(), **contents(payload))
            except OSError as error:
                append("server_error", protocol="tcp", error=str(error))


def serve(role):
    specs = ([(4, "udp", "127.0.0.1", 45997), (6, "udp", "::1", 45997)]
             if role == "hub" else
             [(4, "udp", "0.0.0.0", 45999), (4, "udp", "0.0.0.0", 45998),
              (6, "udp", "::", 45998), (4, "tcp", "0.0.0.0", 46000),
              (6, "tcp", "::", 46001)])
    threads = []
    for family, protocol, address, port in specs:
        connection = make_socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM,
                                 address, port)
        worker = threading.Thread(target=udp_server if protocol == "udp" else tcp_server,
                                  args=(connection, family), daemon=True)
        worker.start()
        threads.append(worker)
    (CONTROL / "traffic-ready").write_text(role)
    deadline = time.monotonic() + 590
    while time.monotonic() < deadline:
        health = {"time_ns": time.time_ns(), "expected_threads": len(threads),
                  "alive_threads": sum(worker.is_alive() for worker in threads)}
        temporary = CONTROL / "traffic-health.tmp"
        temporary.write_text(json.dumps(health))
        temporary.replace(CONTROL / "traffic-health.json")
        time.sleep(0.25)
    for worker in threads:
        worker.join()


def probe(case):
    family, protocol, source, destination, port, count = CASES[case]
    results = []
    for sequence in range(count):
        payload = f"LCIO|{case}|{sequence:03d}|synthetic\n".encode()
        start = time.monotonic_ns()
        try:
            with make_socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM,
                             source, 0) as connection:
                connection.connect((destination, port))
                append("client_sent", case=case, sequence=sequence, family=family,
                       protocol=protocol, local=connection.getsockname(), peer=connection.getpeername(),
                       **contents(payload))
                connection.sendall(payload)
                reply = b""
                while not reply.endswith(b"\n") and len(reply) < 4096:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    reply += chunk
                echoed = reply == payload
                append("client_received", case=case, sequence=sequence, family=family,
                       protocol=protocol, **contents(reply))
                results.append({"sequence": sequence, "echoed": echoed,
                                "elapsed_ns": time.monotonic_ns() - start})
        except OSError as error:
            append("client_error", case=case, sequence=sequence, family=family,
                   protocol=protocol, error=str(error))
            results.append({"sequence": sequence, "echoed": False, "error": str(error),
                            "elapsed_ns": time.monotonic_ns() - start})
    result = {"phase": phase(), "case": case, "attempted": count,
              "echoed": sum(item["echoed"] for item in results), "results": results}
    (CONTROL / f"{phase()}-{case}-client.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "results"}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve", "probe"))
    parser.add_argument("name")
    args = parser.parse_args()
    if args.action == "serve":
        serve(args.name)
    else:
        probe(args.name)


if __name__ == "__main__":
    main()
