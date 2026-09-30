"""Private QEMU guests for the Lightcone traffic experiment (ordinary test code)."""

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "target/lightcone-vm"
IMAGE = CACHE / "images/noble-server-cloudimg-amd64.img"
MACS = {
    "hub": ["52:54:00:77:00:01", "52:54:00:78:00:01"],
    "source": ["52:54:00:77:00:02"],
    "receiver": ["52:54:00:78:00:02"],
}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def execute(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


class Lab:
    def __init__(self, run_dir):
        self.path = Path(run_dir).resolve()
        self.path.mkdir(parents=True, mode=0o700, exist_ok=False)
        os.chmod(self.path, 0o700)
        self.input = self.path / "input"
        self.input.mkdir(mode=0o700)
        self.sockets = Path(tempfile.mkdtemp(prefix="imperium-lcvm-"))
        self.processes = {}
        self.sequence = {role: 0 for role in MACS}
        self.commands = []
        self.manifest = {"schema": 1, "private_unix_links_only": True,
                         "sealed": False, "filter_enforced": False,
                         "runtime_socket_directory": str(self.sockets)}

    def prepare(self):
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise RuntimeError("KVM is not accessible")
        sums = (IMAGE.parent / "SHA256SUMS").read_text().splitlines()
        expected = next(line.split()[0] for line in sums if line.endswith(IMAGE.name))
        if digest(IMAGE) != expected:
            raise RuntimeError("official guest-image SHA-256 mismatch")
        self.manifest.update({
            "image_url": "https://cloud-images.ubuntu.com/noble/20260926/" + IMAGE.name,
            "image_sha256": expected,
            "qemu": execute(["qemu-system-x86_64", "--version"]).stdout.splitlines()[0],
            "source_head": execute(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip(),
            "source_status": execute(["git", "status", "--porcelain"], cwd=ROOT).stdout,
            "binary_sha256": digest(ROOT / "target/debug/imperium"),
            "world_sha256": digest(ROOT / "crates/imperium-net-world/src/world.bin"),
        })
        shutil.copy2(Path(__file__).with_name("guest.py"), self.input / "guest.py")
        runtime = self.input / "runtime"
        for name, original in {"imperium": ROOT / "target/debug/imperium",
                               "nft": Path(shutil.which("nft")),
                               "tcpdump": Path(shutil.which("tcpdump"))}.items():
            destination = runtime / str(original).lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, destination)
            output = execute(["ldd", str(original)]).stdout
            if "not found" in output:
                raise RuntimeError(f"missing dependencies for {name}")
            for library in re.findall(r"(/[^\s()]+)", output):
                dest = runtime / library.lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(library, dest)
            wrapper = self.input / name
            wrapper.write_text("#!/bin/sh\nexec /lab/runtime/lib64/ld-linux-x86-64.so.2 "
                               "--library-path /lab/runtime/lib/x86_64-linux-gnu:"
                               "/lab/runtime/usr/lib/x86_64-linux-gnu "
                               f"/lab/runtime/{str(original).lstrip('/')} \"$@\"\n")
            wrapper.chmod(0o755)
        copied_binary = runtime / str(ROOT / "target/debug/imperium").lstrip("/")
        if digest(copied_binary) != self.manifest["binary_sha256"]:
            raise RuntimeError("guest executable copy differs from the built executable")
        execute([str(ROOT / "target/debug/examples/lab_operator_key"), str(self.input / "operator-key")])
        self.manifest["operator_key_sha256"] = digest(self.input / "operator-key")
        for role, macs in MACS.items():
            directory = self.path / role
            directory.mkdir(mode=0o700)
            control = directory / "control"
            control.mkdir(mode=0o700)
            seed = directory / "seed"
            seed.mkdir()
            (seed / "meta-data").write_text(json.dumps({"instance-id": self.path.name + role,
                                                        "local-hostname": "lc-" + role}))
            data = {"hostname": "lc-" + role, "ssh_pwauth": False,
                    "package_update": False, "package_upgrade": False,
                    "runcmd": [["mkdir", "-p", "/lab", "/control"],
                               ["mount", "-t", "9p", "-o", "trans=virtio,version=9p2000.L,ro", "lab", "/lab"],
                               ["mount", "-t", "9p", "-o", "trans=virtio,version=9p2000.L,cache=none", "control", "/control"],
                               ["python3", "/lab/guest.py", role]]}
            (seed / "user-data").write_text("#cloud-config\n" + json.dumps(data))
            network = {"version": 2, "ethernets": {f"lab{i}": {
                "match": {"macaddress": mac}, "dhcp4": False, "dhcp6": False,
                "optional": True} for i, mac in enumerate(macs)}}
            (seed / "network-config").write_text(json.dumps(network))
            execute([str(CACHE / "deps/usr/bin/genisoimage"), "-quiet", "-output",
                     str(directory / "seed.iso"), "-volid", "cidata", "-joliet", "-rock",
                     str(seed / "user-data"), str(seed / "meta-data"), str(seed / "network-config")])
            execute(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(IMAGE),
                     str(directory / "disk.qcow2"), "8G"])
        atomic_json(self.path / "manifest.json", self.manifest)

    def qmp(self, role, command):
        path = self.sockets / (role + "-qmp.sock")
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(3)
            client.connect(str(path))
            stream = client.makefile("rwb")
            json.loads(stream.readline())
            for index, name in enumerate(("qmp_capabilities", command)):
                stream.write(json.dumps({"execute": name, "id": index}).encode() + b"\n")
                stream.flush()
                while True:
                    answer = json.loads(stream.readline())
                    if answer.get("id") == index:
                        if "error" in answer:
                            raise RuntimeError(answer["error"])
                        break
            return answer["return"]

    def start(self):
        links = {"source": self.sockets / "left.sock", "receiver": self.sockets / "right.sock"}
        for role in ("hub", "source", "receiver"):
            directory = self.path / role
            args = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "3072",
                    "-smp", "2", "-name", "imperium-lc-" + role, "-nodefaults", "-no-reboot",
                    "-display", "none", "-monitor", "none", "-serial", "file:" + str(directory / "serial.log"),
                    "-qmp", "unix:" + str(self.sockets / (role + "-qmp.sock")) + ",server=on,wait=off",
                    "-drive", f"file={directory / 'disk.qcow2'},if=virtio,format=qcow2",
                    "-drive", f"file={directory / 'seed.iso'},if=ide,media=cdrom,readonly=on",
                    "-fsdev", f"local,id=lab,path={self.input},security_model=none,readonly=on",
                    "-device", "virtio-9p-pci,fsdev=lab,mount_tag=lab",
                    "-fsdev", f"local,id=control,path={directory / 'control'},security_model=none",
                    "-device", "virtio-9p-pci,fsdev=control,mount_tag=control"]
            paths = list(links.values()) if role == "hub" else [links[role]]
            for i, path in enumerate(paths):
                args += ["-netdev", f"stream,id=n{i},server={'on' if role == 'hub' else 'off'},"
                         f"addr.type=unix,addr.path={path}", "-device",
                         f"virtio-net-pci,netdev=n{i},mac={MACS[role][i]}"]
            atomic_json(directory / "qemu-command.json", args)
            stderr = (directory / "qemu-stderr.log").open("w")
            self.processes[role] = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=stderr)
            stderr.close()
            self.wait_for(lambda: (self.sockets / (role + "-qmp.sock")).exists(), 15)
            state = self.qmp(role, "query-kvm")
            if state != {"enabled": True, "present": True}:
                raise RuntimeError(f"KVM is not enabled: {state}")
            self.manifest[role + "_kvm"] = state
        for role in MACS:
            ready = self.path / role / "control/ready.json"
            self.wait_for(ready.exists, 240)
            self.manifest[role + "_guest"] = json.loads(ready.read_text())
        atomic_json(self.path / "manifest.json", self.manifest)

    def wait_for(self, predicate, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            for role, process in self.processes.items():
                if process.poll() is not None:
                    raise RuntimeError(f"{role} VM exited; inspect its serial/stderr logs")
            if predicate():
                return
            time.sleep(0.2)
        raise TimeoutError(f"guest setup/action exceeded {seconds}s")

    def run(self, role, command, timeout=45):
        self.sequence[role] += 1
        number = self.sequence[role]
        directory = self.path / role / "control"
        record = {"sequence": number, "role": role, "command": command, "timeout": timeout}
        self.commands.append(record)
        atomic_json(self.path / "commands.json", self.commands)
        atomic_json(directory / f"cmd-{number:04d}.json", record)
        result = directory / f"result-{number:04d}.json"
        self.wait_for(result.exists, timeout + 10)
        return json.loads(result.read_text())

    def close(self):
        for role, process in self.processes.items():
            if process.poll() is None:
                try:
                    self.qmp(role, "system_powerdown")
                except (OSError, ValueError, RuntimeError):
                    process.terminate()
        for process in self.processes.values():
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
