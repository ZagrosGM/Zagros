"""Backend boundary for the OpenVPN driver.

Mechanics (what the protocol requires):
  * :class:`OpenVPNBackend` — everything the driver needs: process lifecycle,
    config/PKI/hook-script materialization, the management channel, and the
    authoritative disconnect-log accounting source.
  * :class:`LocalOpenVPNBackend` — production implementation composing
    ``ManagedProcess`` + ``ManagementClient``; PKI generated with ``openssl``
    (present on every target distro); user auth happens LIVE over the
    management channel, so adding/removing users never restarts the core.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from app.cores.exceptions import CoreError
from app.cores.process import ManagedProcess
from app.cores.types import CoreMetrics
from app.cores.drivers.openvpn.mgmt import (
    AuthRequest,
    DisconnectRecord,
    ManagementClient,
    StatusClient,
    parse_status3,
)

logger = logging.getLogger("zagros.cores.drivers.openvpn")


AuthCallback = Any  # (username: str, password: str, meta: dict) -> bool


@runtime_checkable
class OpenVPNBackend(Protocol):
    # process
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def restart(self) -> None: ...
    def is_running(self) -> bool: ...
    def version(self) -> str | None: ...
    def metrics(self) -> CoreMetrics: ...
    def logs(self, tail: int = 200) -> Sequence[str]: ...

    # setup
    def ensure_pki(self) -> dict[str, str]:
        """Create CA/server cert + tls-crypt key if missing.
        Returns {"ca_crt": pem, "tls_crypt": key} for client profiles."""
        ...

    def apply_config(self, server_conf: str) -> None: ...
    def install_hook_script(self, script: str) -> str:
        """Install the client-disconnect accounting hook; returns its path."""
        ...

    def install_packages(self) -> str: ...

    # management channel
    def connect_management(self, timeout: float = 15.0) -> None: ...
    def management_alive(self) -> bool: ...
    def command(self, cmd: str, timeout: float = 30.0) -> str: ...
    def status_clients(self) -> list[StatusClient]: ...
    def kill_client(self, common_name: str) -> bool: ...
    def set_auth_handler(self, handler: Any) -> None: ...

    # accounting
    def read_disconnect_log(self) -> list[DisconnectRecord]:
        """Return hook-written final counters and clear the file atomically."""
        ...


class LocalOpenVPNBackend:
    """Production backend for the OpenVPN driver."""

    def __init__(self, settings: dict[str, Any]):
        self.executable = settings.get("executable_path", "openvpn")
        self.work_dir = settings.get("work_dir", "/var/lib/zagros/cores/openvpn")
        self.mgmt_host = "127.0.0.1"
        self.mgmt_port = int(settings.get("management_port", 17505))
        self.config_path = os.path.join(self.work_dir, "server.conf")
        self.disconnect_log = os.path.join(self.work_dir, "disconnect-log.jsonl")
        self.hook_path = os.path.join(self.work_dir, "client-disconnect.sh")
        os.makedirs(self.work_dir, exist_ok=True)
        self._proc = ManagedProcess(
            [self.executable, "--config", self.config_path],
            cwd=self.work_dir,
        )
        self._mgmt: ManagementClient | None = None

    # ------------------------------------------------------------------ #
    # process
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self._proc.start()
        self.connect_management()

    def stop(self) -> None:
        if self._mgmt is not None:
            self._mgmt.close()
            self._mgmt = None
        self._proc.stop()

    def restart(self) -> None:
        self.stop()
        self.start()

    def is_running(self) -> bool:
        return self._proc.is_running

    def version(self) -> str | None:
        try:
            out = subprocess.check_output(
                [self.executable, "--version"], text=True, timeout=10
            )
            for line in out.splitlines():
                if line.startswith("OpenVPN"):
                    return line.split()[1]
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return None

    def metrics(self) -> CoreMetrics:
        return self._proc.metrics()

    def logs(self, tail: int = 200) -> Sequence[str]:
        return self._proc.logs(tail)

    # ------------------------------------------------------------------ #
    # setup: PKI / config / hook / packages
    # ------------------------------------------------------------------ #
    def _run(self, argv: list[str], timeout: float = 120.0) -> str:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise CoreError(f"command failed {' '.join(argv[:2])}: {proc.stderr.strip()}")
        return proc.stdout

    def ensure_pki(self) -> dict[str, str]:
        paths = {name: os.path.join(self.work_dir, name) for name in
                 ("ca.key", "ca.crt", "server.key", "server.csr", "server.crt", "ta.key")}
        if shutil.which("openssl") is None:
            raise CoreError("openssl not found on this host (install it first).")
        if not os.path.exists(paths["ca.crt"]):
            self._run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                       "-keyout", paths["ca.key"], "-out", paths["ca.crt"],
                       "-days", "3650", "-nodes", "-subj", "/CN=zagros-ovpn-ca"])
        if not os.path.exists(paths["server.crt"]):
            self._run(["openssl", "req", "-newkey", "rsa:2048",
                       "-keyout", paths["server.key"], "-out", paths["server.csr"],
                       "-nodes", "-subj", "/CN=zagros-ovpn-server"])
            self._run(["openssl", "x509", "-req", "-in", paths["server.csr"],
                       "-CA", paths["ca.crt"], "-CAkey", paths["ca.key"],
                       "-CAcreateserial", "-out", paths["server.crt"], "-days", "3650"])
        if not os.path.exists(paths["ta.key"]):
            self._run([self.executable, "--genkey", "--secret", paths["ta.key"]])
        with open(paths["ca.crt"], encoding="utf-8") as fh:
            ca_crt = fh.read()
        with open(paths["ta.key"], encoding="utf-8") as fh:
            tls_key = fh.read()
        return {"ca_crt": ca_crt, "tls_crypt": tls_key}

    def apply_config(self, server_conf: str) -> None:
        tmp = f"{self.config_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(server_conf)
        os.replace(tmp, self.config_path)

    def install_hook_script(self, script: str) -> str:
        with open(self.hook_path, "w", encoding="utf-8") as fh:
            fh.write(script)
        os.chmod(self.hook_path, 0o755)
        return self.hook_path

    def install_packages(self) -> str:
        for manager, argv in (
            ("apt-get", ["apt-get", "install", "-y", "openvpn", "openssl"]),
            ("dnf", ["dnf", "install", "-y", "openvpn", "openssl"]),
            ("yum", ["yum", "install", "-y", "openvpn", "openssl"]),
            ("pacman", ["pacman", "-S", "--noconfirm", "openvpn", "openssl"]),
            ("apk", ["apk", "add", "openvpn", "openssl"]),
        ):
            if shutil.which(manager):
                if manager == "apt-get":
                    # container images carry no apt lists: refresh first or
                    # every package reports "Unable to locate package"
                    self._run(["apt-get", "update"], timeout=600)
                return self._run(argv, timeout=600)
        raise CoreError("no supported package manager found (apt/dnf/yum/pacman/apk).")

    # ------------------------------------------------------------------ #
    # management channel
    # ------------------------------------------------------------------ #
    def connect_management(self, timeout: float = 15.0) -> None:
        client = ManagementClient()
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                client.connect(self.mgmt_host, self.mgmt_port, timeout=3)
                self._mgmt = client
                return
            except OSError as exc:  # core still booting
                last_error = exc
                time.sleep(0.4)
        raise CoreError(f"cannot reach openvpn management interface: {last_error}")

    def management_alive(self) -> bool:
        if self._mgmt is None:
            return False
        try:
            self.command("pid", timeout=5)
            return True
        except CoreError:
            return False

    def command(self, cmd: str, timeout: float = 30.0) -> str:
        if self._mgmt is None:
            raise CoreError("management interface is not connected.")
        return self._mgmt.command(cmd, timeout=timeout)

    def status_clients(self) -> list[StatusClient]:
        return parse_status3(self.command("status 3"))

    def kill_client(self, common_name: str) -> bool:
        try:
            out = self.command(f"kill {common_name}", timeout=10)
            return out.startswith("SUCCESS:")
        except CoreError:
            return False

    def set_auth_handler(self, handler: AuthCallback) -> None:
        def _bridge(request: AuthRequest) -> bool:
            meta = {
                "platform": request.platform,
                "client_version": request.client_version,
                "reauth": request.reauth,
                **{k: v for k, v in request.env.items()
                   if k.startswith("IV_") or k in ("remote_ip", "untrusted_ip")},
            }
            return bool(handler(request.username, request.password, meta))

        client = self._mgmt or ManagementClient()
        if self._mgmt is None:
            self._mgmt = client
        self._mgmt.set_auth_handler(_bridge)

    # ------------------------------------------------------------------ #
    # accounting
    # ------------------------------------------------------------------ #
    def read_disconnect_log(self) -> list[DisconnectRecord]:
        if not os.path.exists(self.disconnect_log):
            return []
        tmp = f"{self.disconnect_log}.swap"
        try:
            os.replace(self.disconnect_log, tmp)   # atomic-ish: new appends go to a fresh file
        except OSError:
            return []
        records: list[DisconnectRecord] = []
        with open(tmp, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    records.append(DisconnectRecord(
                        common_name=row["cn"],
                        bytes_received=int(row.get("bytes_received", 0)),
                        bytes_sent=int(row.get("bytes_sent", 0)),
                        duration_seconds=int(row.get("duration", 0)),
                        ended_at=int(row.get("ts", 0)),
                    ))
                except (ValueError, KeyError) as exc:
                    logger.warning("bad disconnect-log line skipped: %s", exc)
        os.unlink(tmp)
        return records
