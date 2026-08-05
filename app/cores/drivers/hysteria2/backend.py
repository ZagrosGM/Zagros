"""Backend boundary for the Hysteria2 driver.

  * :class:`Hysteria2Backend` — Protocol: process lifecycle, config/cert
    materialization, and the HTTP Traffic Stats API.
  * :class:`LocalHysteria2Backend` — production implementation on
    ManagedProcess; stats via stdlib HTTP so the driver is testable without
    the binary (fakes / other transports can implement the same Protocol).
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from app.cores.drivers.hysteria2.hycfg import parse_online, parse_traffic
from app.cores.exceptions import CoreError
from app.cores.process import ManagedProcess
from app.cores.types import CoreMetrics

logger = logging.getLogger("zagros.cores.drivers.hysteria2")


@runtime_checkable
class Hysteria2Backend(Protocol):
    # process
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def restart(self) -> None: ...
    def is_running(self) -> bool: ...
    def version(self) -> str | None: ...
    def metrics(self) -> CoreMetrics: ...
    def logs(self, tail: int = 200) -> Sequence[str]: ...

    # setup
    def install_binary(self) -> str: ...
    def ensure_tls(self, common_name: str) -> tuple[str, str]:
        """Create (or reuse) the server cert; returns (cert_path, key_path)."""
        ...
    def apply_config(self, yaml_text: str) -> None: ...

    # traffic stats API
    def traffic(self) -> dict[str, tuple[int, int]]: ...
    def online(self) -> dict[str, int]: ...
    def kick(self, users: list[str]) -> None: ...


class LocalHysteria2Backend:
    """Production backend (local hysteria binary + loopback stats API)."""

    def __init__(self, settings: dict):
        self.executable = settings.get("executable_path", "hysteria")
        self.work_dir = settings.get("work_dir", "/var/lib/zagros/cores/hysteria2")
        self.traffic_listen = settings.get("traffic_listen", "127.0.0.1:19999")
        self.traffic_secret = settings.get("traffic_secret") or None
        self.timeout = float(settings.get("stats_timeout", 10.0))
        os.makedirs(self.work_dir, exist_ok=True)
        self.config_path = os.path.join(self.work_dir, "server.yaml")
        self.cert_path = os.path.join(self.work_dir, "server.crt")
        self.key_path = os.path.join(self.work_dir, "server.key")
        self._proc = self._make_proc()

    def _make_proc(self) -> ManagedProcess:
        return ManagedProcess(
            [self.executable, "server", "--disable-update-check", "--config", self.config_path],
            cwd=self.work_dir,
        )

    # ------------------------------------------------------------------ #
    # process
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self._proc.start()

    def stop(self) -> None:
        self._proc.stop()

    def restart(self) -> None:
        self._proc.restart()

    def is_running(self) -> bool:
        return self._proc.is_running

    def version(self) -> str | None:
        try:
            out = subprocess.check_output(
                [self.executable, "version"], text=True, timeout=10
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            return None
        for line in out.splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
        return out.strip().splitlines()[0] if out.strip() else None

    def metrics(self) -> CoreMetrics:
        stats = self._proc.metrics()
        try:
            traffic = self.traffic()
            stats.network_rx_bytes = sum(rx for _tx, rx in traffic.values())
            stats.network_tx_bytes = sum(tx for tx, _rx in traffic.values())
        except CoreError:
            pass
        return stats

    def logs(self, tail: int = 200) -> Sequence[str]:
        return self._proc.logs(tail)

    # ------------------------------------------------------------------ #
    # setup
    # ------------------------------------------------------------------ #
    def install_binary(self) -> str:
        from app.cores.github_install import host_arch, host_os, install_from_github

        system, arch = host_os(), host_arch()
        target = os.path.join(self.work_dir, f"hysteria-{system}-{arch}")
        if os.path.basename(self.executable) == self.executable and not shutil.which(self.executable):
            tag = install_from_github(
                repo="apernet/hysteria",
                target_executable=target,
                asset_match=lambda name: (
                    name == f"hysteria-{system}-{arch}"
                    or name == f"hysteria-{system}-{arch}.exe"
                ),
                direct_asset=f"hysteria-{system}-{arch}",
            )
            self.executable = target
            if not self._proc.is_running:
                self._proc = self._make_proc()  # argv captured the old path otherwise
            return tag
        return "system-package"

    def ensure_tls(self, common_name: str) -> tuple[str, str]:
        from app.cores.pki import ensure_self_signed_cert

        return ensure_self_signed_cert(self.cert_path, self.key_path, common_name)

    def apply_config(self, yaml_text: str) -> None:
        tmp = f"{self.config_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(yaml_text)
        os.replace(tmp, self.config_path)

    # ------------------------------------------------------------------ #
    # traffic stats API
    # ------------------------------------------------------------------ #
    def _request(self, method: str, path: str, body: str | None = None) -> str:
        url = f"http://{self.traffic_listen}{path}"
        req = urllib.request.Request(
            url, method=method,
            data=body.encode() if body is not None else None,
        )
        if self.traffic_secret:
            req.add_header("Authorization", self.traffic_secret)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode()
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise CoreError(f"hysteria traffic API {method} {path} failed: {exc}") from exc

    def traffic(self) -> dict[str, tuple[int, int]]:
        return parse_traffic(self._request("GET", "/traffic"))

    def online(self) -> dict[str, int]:
        return parse_online(self._request("GET", "/online"))

    def kick(self, users: list[str]) -> None:
        self._request("POST", "/kick", body=json.dumps(users))
