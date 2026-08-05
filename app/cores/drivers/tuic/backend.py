"""Backend boundary for the TUIC driver.

  * :class:`TUICBackend` — Protocol: process lifecycle, config/cert
    materialization, self-install.
  * :class:`LocalTUICBackend` — production implementation on ManagedProcess;
    no stats surface exists in the protocol (driver stays honest about it).
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from app.cores.process import ManagedProcess
from app.cores.types import CoreMetrics

logger = logging.getLogger("zagros.cores.drivers.tuic")


@runtime_checkable
class TUICBackend(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def restart(self) -> None: ...
    def is_running(self) -> bool: ...
    def version(self) -> str | None: ...
    def metrics(self) -> CoreMetrics: ...
    def logs(self, tail: int = 200) -> Sequence[str]: ...
    def install_binary(self) -> str: ...
    def ensure_tls(self, common_name: str) -> tuple[str, str]: ...
    def apply_config(self, config: dict[str, Any]) -> None: ...


class LocalTUICBackend:
    def __init__(self, settings: dict):
        self.executable = settings.get("executable_path", "tuic-server")
        self.work_dir = settings.get("work_dir", "/var/lib/zagros/cores/tuic")
        self.repo = settings.get("release_repo", "EAimTY/tuic")
        self.release_version = settings.get("release_version", "tuic-server-1.0.0")
        os.makedirs(self.work_dir, exist_ok=True)
        self.config_path = os.path.join(self.work_dir, "config.json")
        self.cert_path = os.path.join(self.work_dir, "server.crt")
        self.key_path = os.path.join(self.work_dir, "server.key")
        self._proc = self._make_proc()

    def _make_proc(self) -> ManagedProcess:
        return ManagedProcess(
            [self.executable, "-c", self.config_path], cwd=self.work_dir
        )

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
                [self.executable, "--version"], text=True, timeout=10
            )
            return out.strip().splitlines()[0]
        except (subprocess.SubprocessError, FileNotFoundError, IndexError):
            return None

    def metrics(self) -> CoreMetrics:
        return self._proc.metrics()

    def logs(self, tail: int = 200) -> Sequence[str]:
        return self._proc.logs(tail)

    def install_binary(self) -> str:
        from app.cores.github_install import host_arch, install_from_github

        arch = host_arch(rust=True)
        version = self.release_version
        target = os.path.join(self.work_dir, "tuic-server")
        if os.path.basename(self.executable) == self.executable and not shutil.which(self.executable):
            tag = install_from_github(
                repo=self.repo,
                target_executable=target,
                asset_match=lambda name: name == f"{version}-{arch}-unknown-linux-gnu",
                direct_asset=f"{version}-{arch}-unknown-linux-gnu",
            )
            self.executable = target
            if not self._proc.is_running:
                self._proc = self._make_proc()  # argv captured the old path otherwise
            logger.info("tuic: installed %s (%s)", tag, target)
            return tag
        return "system-package"

    def ensure_tls(self, common_name: str) -> tuple[str, str]:
        from app.cores.pki import ensure_self_signed_cert

        return ensure_self_signed_cert(self.cert_path, self.key_path, common_name)

    def apply_config(self, config: dict[str, Any]) -> None:
        tmp = f"{self.config_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, self.config_path)
