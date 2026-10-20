"""Hermetic command/core doubles for policy-routing unit tests.

Runtime verification lives in the VPS gate; these doubles pin command shape,
secret handling and rollback without requiring CAP_NET_ADMIN in pytest.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


class FakeProcess:
    _next_pid = 50000

    def __init__(self) -> None:
        type(self)._next_pid += 1
        self.pid = type(self)._next_pid
        self.returncode = None

    def poll(self): return self.returncode
    def wait(self, timeout=None):
        self.returncode = 0
        return 0


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.interfaces: set[str] = set()
        self.ns_interfaces: dict[str, set[str]] = {}
        self.routes: dict[str, str] = {}
        self.nft_scripts: list[str] = []

    @staticmethod
    def completed(argv, rc=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(argv, rc, stdout, stderr)

    def _network_command(self, argv: list[str]):
        namespace = None
        inner = argv
        if argv[:3] == ["ip", "netns", "exec"]:
            namespace = argv[3]
            inner = argv[4:]
        interfaces = self.ns_interfaces.setdefault(namespace, set()) \
            if namespace else self.interfaces
        if inner[:4] == ["ip", "link", "show", "dev"]:
            rc = 0 if inner[4] in interfaces else 1
            return self.completed(argv, rc)
        if inner[:5] == ["ip", "-j", "address", "show", "dev"]:
            if inner[5] not in interfaces:
                return self.completed(argv, 1, "[]")
            return self.completed(
                argv, 0,
                json.dumps([{
                    "ifname": inner[5], "flags": ["POINTOPOINT", "UP"],
                    "addr_info": [{"family": "inet", "local": "10.0.0.2"}],
                }]),
            )
        if inner[:4] == ["ip", "link", "add", "dev"]:
            interfaces.add(inner[4])
        elif inner[:4] == ["ip", "link", "del", "dev"]:
            interfaces.discard(inner[4])
        return None

    def run(self, argv, *, check=True, input_text=None, timeout=30):
        argv = [str(item) for item in argv]
        self.calls.append((argv, input_text))
        if argv[:3] == ["ip", "netns", "add"]:
            self.ns_interfaces.setdefault(argv[3], set())
        elif argv[:3] == ["ip", "netns", "del"]:
            self.ns_interfaces.pop(argv[3], None)
        network_result = self._network_command(argv)
        if network_result is not None:
            return network_result
        if argv[:4] == ["ip", "link", "add", argv[3] if len(argv) > 3 else ""]:
            self.interfaces.add(argv[3])
        if argv[:4] == ["ip", "route", "replace", "table"]:
            table = argv[4]
            self.routes[table] = argv[-1]
        elif argv[:4] == ["ip", "route", "get", "1.1.1.1"]:
            mark = argv[-1]
            iface = self.routes.get(mark, "missing")
            rc = 0 if iface != "missing" else 2
            return self.completed(argv, rc, f"1.1.1.1 dev {iface}\n")
        elif argv[:3] == ["ip", "route", "get"]:
            return self.completed(argv, 0, f"{argv[3]} dev eth0 src 192.0.2.1\n")
        elif len(argv) >= 6 and argv[:3] == ["ip", "netns", "exec"] \
                and argv[4:6] == ["ss", "-lnt"]:
            return self.completed(argv, 0, "LISTEN 0 128 127.0.0.1:9930 0.0.0.0:*\n")
        elif len(argv) >= 6 and argv[:3] == ["ip", "netns", "exec"] \
                and argv[4] == "cat" \
                and argv[-1] == "/proc/sys/net/ipv4/ip_forward":
            return self.completed(argv, 0, "1\n")
        elif argv[:4] == ["ip", "rule", "del", "priority"]:
            return self.completed(argv, 2)
        elif argv[:4] == ["nft", "list", "table", "inet"]:
            return self.completed(argv, 1)
        elif argv[:2] == ["nft", "-f"]:
            self.nft_scripts.append(input_text or "")
        return self.completed(argv)

    def tcp_ready(self, host, port): return True

    def popen(self, argv, *, stdout):
        argv = [str(item) for item in argv]
        self.calls.append((argv, None))
        namespace = argv[3] if argv[:3] == ["ip", "netns", "exec"] else None
        interfaces = self.ns_interfaces.setdefault(namespace, set()) \
            if namespace else self.interfaces
        if "--dev" in argv:
            interfaces.add(argv[argv.index("--dev") + 1])
        elif "-c" in argv:
            path = Path(argv[argv.index("-c") + 1])
            if path.exists():
                doc = json.loads(path.read_text())
                for inbound in doc.get("inbounds", []):
                    if inbound.get("type") == "tun":
                        interfaces.add(inbound["interface_name"])
        if "udhcpc" in argv and "-s" in argv:
            script = Path(argv[argv.index("-s") + 1])
            (script.parent / "address").write_text("192.168.30.10\n")
            (script.parent / "gateway").write_text("192.168.30.1\n")
        elif argv and argv[-1].endswith("dhcp-watch.sh"):
            lease = Path(argv[-1]).parent
            (lease / "address").write_text("192.168.30.10\n")
            (lease / "gateway").write_text("192.168.30.1\n")
        return FakeProcess()


class EmptyCoreManager:
    def list_cores(self): return []
    def get(self, core_id): raise KeyError(core_id)
