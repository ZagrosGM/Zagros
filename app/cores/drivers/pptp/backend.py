"""Local ACCEL-PPP 1.14.0 runtime boundary for the independent PPTP core."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Sequence

from app.cores.exceptions import CoreError
from app.cores.process import ManagedProcess
from app.cores.types import CoreMetrics
from app.cores.drivers.pptp.accounting import PptpSession

PINNED_VERSION = "1.14.0"
PINNED_COMMIT = "048d31cb446879e0d1a1471b4ab99135a92bf289"
PINNED_SHA256 = "ee391e34b237e3e2c12d037bc1c36d23bdb9ec76956d771e4a9425c9193a193d"
REQUIRED_MODULES = (
    "libpptp.so", "libauth_mschap_v2.so", "libchap-secrets.so", "libippool.so",
    "libsigchld.so", "libpppd_compat.so", "liblog_file.so", "libtriton.so",
)
_FORBIDDEN_MODULES = (
    "libauth_pap.so", "libauth_chap_md5.so", "libauth_mschap_v1.so",
    "libipv6pool.so", "libipv6_dhcp.so", "libipv6_nd.so",
)


class LocalPptpBackend:
    """One process, one fixed listener, one explicitly owned nftables table."""

    def __init__(self, settings: dict[str, Any], *, runner: Any | None = None) -> None:
        self.settings = settings
        self.executable = str(settings.get("executable_path") or
                              "/opt/zagros/accel-ppp/1.14.0/sbin/accel-pppd")
        self.module_dir = str(settings.get("module_dir") or
                              "/opt/zagros/accel-ppp/1.14.0/lib/accel-ppp")
        self.work_dir = str(settings.get("work_dir") or
                            "/var/lib/zagros/cores/pptp")
        self.management_port = int(settings.get("management_port") or 22001)
        self.config_path = os.path.join(self.work_dir, "accel-ppp.conf")
        self.chap_path = os.path.join(self.work_dir, "chap-secrets")
        self.secret_path = os.path.join(self.work_dir, ".management-secret")
        self.hook_path = os.path.join(self.work_dir, "accounting-hook.py")
        self.generation_path = os.path.join(self.work_dir, "generation")
        self.accounting_path = os.path.join(self.work_dir, "accounting.sqlite3")
        self.manifest_path = os.path.join(self.work_dir, "runtime-ownership.json")
        self.pid_path = os.path.join(self.work_dir, "accel-pppd.pid")
        self._runner = runner
        self._proc: ManagedProcess | None = None
        self._observed_interfaces: dict[str, int] = {}

    def _ensure_dir(self) -> None:
        Path(self.work_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.work_dir, 0o700)

    @staticmethod
    def _atomic_write(path: str, content: str, mode: int) -> None:
        parent = os.path.dirname(path)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        tmp = f"{path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, path)
            directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def ensure_management_secret(self) -> str:
        try:
            secret = Path(self.secret_path).read_text(encoding="ascii").strip()
        except FileNotFoundError:
            secret = ""
        if not secret:
            secret = secrets.token_urlsafe(36)
            self._atomic_write(self.secret_path, secret + "\n", 0o600)
        os.chmod(self.secret_path, 0o600)
        return secret

    def configure(self, config: str, chap_secrets: str, hook_script: str) -> None:
        """Replace every sensitive runtime input atomically."""
        self._ensure_dir()
        self._atomic_write(self.config_path, config, 0o600)
        self._atomic_write(self.chap_path, chap_secrets, 0o600)
        self._atomic_write(self.hook_path, hook_script, 0o700)

    def _run(
        self, argv: list[str], *, input_text: str | None = None,
        check: bool = True, timeout: int = 30,
    ) -> subprocess.CompletedProcess[str]:
        if self._runner is not None:
            return self._runner.run(argv, input_text=input_text, check=check, timeout=timeout)
        result = subprocess.run(
            argv, input=input_text, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
        if check and result.returncode:
            detail = (result.stderr or result.stdout or "command failed").strip()
            raise CoreError(f"{os.path.basename(argv[0])} failed: {detail[-500:]}")
        return result

    def version(self) -> str | None:
        if not os.path.isfile(self.executable):
            return None
        result = self._run([self.executable, "--version"], check=False)
        match = re.search(r"accel-ppp\s+([0-9]+(?:\.[0-9]+){2})", result.stdout or "")
        return match.group(1) if match else None

    def verify_installation(self) -> None:
        if self.version() != PINNED_VERSION:
            raise CoreError("the bundled ACCEL-PPP runtime is missing or not version 1.14.0")
        module_path = Path(self.module_dir)
        missing = [name for name in REQUIRED_MODULES if not (module_path / name).is_file()]
        forbidden = [name for name in _FORBIDDEN_MODULES if (module_path / name).exists()]
        if missing:
            raise CoreError(f"ACCEL-PPP runtime modules are incomplete: {missing}")
        if forbidden:
            raise CoreError(f"forbidden ACCEL-PPP runtime modules are present: {forbidden}")

    @staticmethod
    def _effective_capability(bit: int) -> bool:
        try:
            for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << bit))
        except (OSError, ValueError, IndexError):
            return False
        return False

    @staticmethod
    def _module_loaded(name: str) -> bool:
        return Path(f"/sys/module/{name}").is_dir()

    @staticmethod
    def _ppp_device_ready() -> tuple[bool, str]:
        try:
            info = os.stat("/dev/ppp")
        except OSError as exc:
            return False, f"/dev/ppp is unavailable: {exc}"
        if not stat.S_ISCHR(info.st_mode) or os.major(info.st_rdev) != 108:
            return False, "/dev/ppp is not the PPP character device (major 108)"
        try:
            fd = os.open("/dev/ppp", os.O_RDWR | os.O_NONBLOCK)
            os.close(fd)
        except OSError as exc:
            return False, f"/dev/ppp exists but cannot be opened: {exc}"
        return True, ""

    @staticmethod
    def _tcp_available(address: str, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((address, port))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    @staticmethod
    def _gre_ready() -> tuple[bool, str]:
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)
            raw.close()
        except OSError as exc:
            return False, f"cannot create an IPv4 GRE raw socket: {exc}"
        # Linux ACCEL-PPP PPTP sessions use the kernel PPPOX/PPTP channel
        # (AF_PPPOX=24, PX_PROTO_PPTP=2), in addition to the control socket.
        try:
            channel = socket.socket(getattr(socket, "AF_PPPOX", 24), socket.SOCK_STREAM, 2)
            channel.close()
        except OSError as exc:
            return False, f"kernel PPPOX/PPTP channel is unavailable: {exc}"
        return True, ""

    def preflight(self, listen: str = "0.0.0.0") -> None:
        self.verify_installation()
        failures: list[str] = []
        ready, reason = self._ppp_device_ready()
        if not ready:
            failures.append(reason)
        if not self._effective_capability(12):
            failures.append("CAP_NET_ADMIN is not effective")
        if not self._effective_capability(13):
            failures.append("CAP_NET_RAW is not effective")
        if not self._module_loaded("ppp_generic"):
            failures.append("kernel module ppp_generic is not loaded")
        if not self._module_loaded("ppp_mppe"):
            failures.append("kernel module ppp_mppe is not loaded")
        try:
            forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        except OSError:
            forwarding = "unknown"
        if forwarding != "1":
            failures.append("net.ipv4.ip_forward must already be 1 on the host")
        if shutil.which("nft") is None:
            failures.append("nft is not installed")
        else:
            for table, chain in (("filter", "FORWARD"), ("nat", "POSTROUTING")):
                result = self._run(
                    ["nft", "list", "chain", "ip", table, chain], check=False)
                if result.returncode:
                    failures.append(f"required nftables base chain ip {table} {chain} is missing")
        if shutil.which("ip") is None:
            failures.append("ip is not installed")
        if not self._tcp_available(listen, 1723):
            failures.append("TCP/1723 is already in use")
        if not self._tcp_available("127.0.0.1", self.management_port):
            failures.append(f"loopback management port {self.management_port} is already in use")
        gre, reason = self._gre_ready()
        if not gre:
            failures.append(reason)
        if failures:
            raise CoreError("PPTP preflight failed: " + "; ".join(failures))

    def validate_subnet(self, subnet: str) -> list[str]:
        """Reject overlap with current non-PPTP kernel routes."""
        import ipaddress

        wanted = ipaddress.ip_network(subnet, strict=False)
        if shutil.which("ip") is None:
            return []
        result = self._run(["ip", "-4", "route", "show"], check=False)
        errors: list[str] = []
        for line in (result.stdout or "").splitlines():
            words = line.split()
            if not words or words[0] == "default":
                continue
            dev = words[words.index("dev") + 1] if "dev" in words and words.index("dev") + 1 < len(words) else ""
            if dev.startswith("ppp"):
                continue
            try:
                route = ipaddress.ip_network(words[0], strict=False)
            except ValueError:
                continue
            if wanted.overlaps(route):
                errors.append(f"PPTP subnet {wanted} overlaps live route {route} on {dev or 'unknown'}")
        return errors

    @staticmethod
    def _firewall_owner(tag: str) -> str:
        return "zagros:pptp:" + hashlib.sha256(tag.encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _firewall_resources(owner: str, *, include_input: bool) -> list[dict[str, str]]:
        resources = [
            {"family": "ip", "table": "filter", "chain": "FORWARD",
             "comment": owner + ":forward-up"},
            {"family": "ip", "table": "filter", "chain": "FORWARD",
             "comment": owner + ":forward-down"},
            {"family": "ip", "table": "nat", "chain": "POSTROUTING",
             "comment": owner + ":masquerade"},
        ]
        if include_input:
            resources[0:0] = [
                {"family": "ip", "table": "filter", "chain": "INPUT",
                 "comment": owner + ":input-tcp"},
                {"family": "ip", "table": "filter", "chain": "INPUT",
                 "comment": owner + ":input-gre"},
            ]
        return resources

    def _manifest(self) -> dict[str, Any] | None:
        try:
            value = json.loads(Path(self.manifest_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def cleanup_firewall(self) -> None:
        manifest = self._manifest()
        if not manifest:
            return
        if manifest.get("provider") != "pptp":
            raise CoreError("refusing to remove a firewall manifest not owned by PPTP")
        owner = str(manifest.get("nft_owner") or "")
        if not re.fullmatch(r"zagros:pptp:[0-9a-f]{12}", owner):
            raise CoreError("refusing to remove invalid/unowned PPTP nftables rules")
        resources = manifest.get("resources") or self._firewall_resources(
            owner, include_input=True)
        if shutil.which("nft"):
            for resource in resources:
                family = str(resource.get("family") or "")
                table = str(resource.get("table") or "")
                chain = str(resource.get("chain") or "")
                comment = str(resource.get("comment") or "")
                valid_target = (
                    family == "ip"
                    and ((table == "filter" and chain in {"INPUT", "FORWARD"})
                         or (table == "nat" and chain == "POSTROUTING"))
                )
                if not valid_target or not comment.startswith(owner + ":"):
                    raise CoreError("refusing to remove malformed PPTP firewall ownership")
                listed = self._run(
                    ["nft", "-a", "list", "chain", family, table, chain],
                    check=False,
                ).stdout or ""
                handles = [
                    int(match.group(1))
                    for line in listed.splitlines() if f'comment "{comment}"' in line
                    for match in [re.search(r"# handle (\d+)", line)] if match
                ]
                for handle in handles:
                    self._run(
                        ["nft", "delete", "rule", family, table, chain,
                         "handle", str(handle)], check=False)
            owned_table = str(manifest.get("owned_input_table") or "")
            if owned_table:
                if not re.fullmatch(r"zg_pptp_in_[0-9a-f]{8}", owned_table):
                    raise CoreError("refusing to remove invalid PPTP input table")
                self._run(["nft", "delete", "table", "ip", owned_table], check=False)
        try:
            os.unlink(self.manifest_path)
        except FileNotFoundError:
            pass

    def apply_firewall(self, tag: str, subnet: str) -> None:
        if self._manifest():
            self.cleanup_firewall()
        owner = self._firewall_owner(tag)
        input_exists = self._run(
            ["nft", "list", "chain", "ip", "filter", "INPUT"],
            check=False,
        ).returncode == 0
        resources = self._firewall_resources(owner, include_input=input_exists)
        owned_input_table = "" if input_exists else (
            "zg_pptp_in_" + hashlib.sha256(tag.encode("utf-8")).hexdigest()[:8]
        )
        manifest = {
            "provider": "pptp", "nft_owner": owner, "tag": tag,
            "subnet": subnet, "resources": resources,
            "owned_input_table": owned_input_table,
        }
        self._atomic_write(
            self.manifest_path,
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            0o600,
        )
        # These scoped rules must live in the existing base chains: an ACCEPT
        # in a separate earlier base chain does not override a later FORWARD
        # policy drop. Insertion is one nft transaction, and cleanup resolves
        # only exact ownership comments to rule handles.
        if input_exists:
            input_script = (
                f'insert rule ip filter INPUT tcp dport 1723 counter accept comment "{owner}:input-tcp"\n'
                f'insert rule ip filter INPUT ip protocol gre counter accept comment "{owner}:input-gre"\n'
            )
        else:
            input_script = f"""add table ip {owned_input_table}
add chain ip {owned_input_table} input {{ type filter hook input priority -10; policy accept; }}
add rule ip {owned_input_table} input tcp dport 1723 counter accept
add rule ip {owned_input_table} input ip protocol gre counter accept
"""
        script = input_script + f"""insert rule ip filter FORWARD ip saddr {subnet} counter accept comment \"{owner}:forward-up\"
insert rule ip filter FORWARD ip daddr {subnet} ct state established,related counter accept comment \"{owner}:forward-down\"
insert rule ip nat POSTROUTING ip saddr {subnet} counter masquerade comment \"{owner}:masquerade\"
"""
        try:
            self._run(["nft", "-f", "-"], input_text=script)
        except Exception:
            self.cleanup_firewall()
            raise

    def start(self, *, tag: str, subnet: str, listen: str = "0.0.0.0") -> None:
        if self.is_running():
            raise CoreError("ACCEL-PPP PPTP process is already running")
        self.cleanup_firewall()  # stale resources from an unclean process generation
        self.preflight(listen)
        generation = uuid.uuid4().hex
        self._atomic_write(self.generation_path, generation + "\n", 0o600)
        self.apply_firewall(tag, subnet)
        self._proc = ManagedProcess(
            [self.executable, "--config", self.config_path, "--pid", self.pid_path],
            cwd=self.work_dir,
        )
        try:
            self._proc.start()
            self.wait_ready()
        except Exception:
            if self._proc:
                self._proc.stop()
            self.cleanup_firewall()
            raise

    def wait_ready(self, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        last = "management endpoint not ready"
        while time.monotonic() < deadline:
            if not self.is_running():
                detail = "\n".join(self.logs(20)) or "no process output"
                raise CoreError(f"ACCEL-PPP exited during startup: {detail[-1000:]}")
            try:
                self.command("show stat", timeout=2.0)
                with socket.create_connection(("127.0.0.1", 1723), timeout=1):
                    return
            except (OSError, CoreError) as exc:
                last = str(exc)
                time.sleep(0.25)
        raise CoreError(f"ACCEL-PPP did not become ready: {last}")

    def stop(self) -> None:
        observed: dict[str, int] = {}
        if self.is_running():
            try:
                for session in self.sessions():
                    result = self._run(["ip", "-o", "link", "show", "dev", session.ifname], check=False)
                    match = re.match(r"(\d+):", result.stdout or "")
                    if match:
                        observed[session.ifname] = int(match.group(1))
            except Exception:
                observed = {}
        if self._proc is not None:
            self._proc.stop()
        self._proc = None
        self.cleanup_firewall()
        deadline = time.monotonic() + 5
        while observed and time.monotonic() < deadline:
            for name, ifindex in list(observed.items()):
                result = self._run(["ip", "-o", "link", "show", "dev", name], check=False)
                match = re.match(r"(\d+):", result.stdout or "")
                if not match:
                    observed.pop(name, None)
                elif int(match.group(1)) != ifindex:
                    observed.pop(name, None)  # name was reused; it is not ours
            if observed:
                time.sleep(0.1)
        if observed:
            raise CoreError(f"ACCEL-PPP stopped but owned PPP interfaces remain: {sorted(observed)}")
        for path in (self.pid_path, self.generation_path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def restart(self, *, tag: str, subnet: str, listen: str = "0.0.0.0") -> None:
        self.stop()
        self.start(tag=tag, subnet=subnet, listen=listen)

    def is_running(self) -> bool:
        return bool(self._proc and self._proc.is_running)

    def metrics(self) -> CoreMetrics:
        return self._proc.metrics() if self._proc else CoreMetrics()

    def logs(self, tail: int = 200) -> Sequence[str]:
        return self._proc.logs(tail) if self._proc else []

    def command(self, command: str, *, timeout: float = 5.0) -> str:
        if "\n" in command or "\r" in command:
            raise CoreError("invalid ACCEL-PPP management command")
        secret = Path(self.secret_path).read_text(encoding="ascii").strip()
        payload = (secret + "\n" + command + "\nexit\n").encode("utf-8")
        chunks: list[bytes] = []
        try:
            with socket.create_connection(("127.0.0.1", self.management_port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(payload)
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                    if sum(len(item) for item in chunks) > 4 * 1024 * 1024:
                        raise CoreError("ACCEL-PPP management response exceeded safety limit")
        except OSError as exc:
            raise CoreError(f"ACCEL-PPP management endpoint unavailable: {exc}") from exc
        response = b"".join(chunks).decode("utf-8", errors="replace")
        if any(marker in response.lower() for marker in ("command failed", "syntax error", "command unknown")):
            raise CoreError(f"ACCEL-PPP management command failed: {command.split()[0]}")
        return response

    @staticmethod
    def parse_sessions(output: str) -> list[PptpSession]:
        lines = [line for line in output.splitlines() if "|" in line]
        if not lines:
            return []
        headers = [item.strip() for item in lines[0].strip().strip("|").split("|")]
        sessions: list[PptpSession] = []
        for line in lines[1:]:
            if set(line.replace("+", "").replace("-", "").strip()) == set():
                continue
            values = [item.strip() for item in line.strip().strip("|").split("|")]
            if len(values) != len(headers) or all(not value for value in values):
                continue
            row = dict(zip(headers, values))
            if row.get("type") != "pptp":
                continue
            def number(key: str) -> int:
                try:
                    return max(0, int(row.get(key) or 0))
                except ValueError:
                    return 0
            sessions.append(PptpSession(
                ifname=row.get("ifname", ""), username=row.get("username", ""),
                calling_sid=row.get("calling-sid", ""), assigned_ip=row.get("ip", ""),
                session_id=row.get("sid", ""), state=row.get("state", ""),
                compression=row.get("comp", ""), uptime_seconds=number("uptime-raw"),
                rx_bytes=number("rx-bytes-raw"), tx_bytes=number("tx-bytes-raw"),
            ))
        return [item for item in sessions if item.ifname and item.username]

    def sessions(self) -> list[PptpSession]:
        columns = (
            "ifname,username,calling-sid,ip,type,comp,state,uptime-raw,sid,"
            "rx-bytes-raw,tx-bytes-raw"
        )
        return self.parse_sessions(self.command(f"show sessions {columns}"))

    def reload(self) -> None:
        if self.is_running():
            self.command("reload")

    def terminate_account(self, account_id: str) -> None:
        if not self.is_running():
            return
        for session in self.sessions():
            if session.username == account_id and re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", session.ifname):
                self.command(f"terminate if {session.ifname} hard")

    def purge(self) -> None:
        self.stop()
        if os.path.isdir(self.work_dir):
            shutil.rmtree(self.work_dir, ignore_errors=False)
