"""Backend boundary for the WireGuard driver.

  * :class:`WireGuardBackend` — Protocol: everything the driver needs from
    the host (key management, interface up/down, live sync, stats dump).
  * :class:`LocalWireGuardBackend` — production implementation driving the
    standard `wireguard-tools` binaries (`wg`, `wg-quick`).

Live updates use ``wg syncconf`` (non-disruptive, kernel-native) which is why
the driver can honestly claim HOT_RELOAD; interface bootstrap/teardown goes
through ``wg-quick``.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from app.cores.drivers.wireguard.wgtool import (
    WireGuardDump,
    parse_wg_dump,
    strip_config,
)
from app.cores.exceptions import CoreError
from app.cores.types import CoreMetrics

logger = logging.getLogger("zagros.cores.drivers.wireguard")


@runtime_checkable
class WireGuardBackend(Protocol):
    # setup
    def is_installed(self) -> bool: ...
    def install_packages(self) -> str: ...
    def missing_dependencies(self) -> dict[str, str]:
        """tool → os-package for everything wg / wg-quick hard-require."""
        ...
    def ensure_server_keys(self) -> tuple[str, str]:
        """Persisted server keypair → (private_key, public_key)."""
        ...
    def generate_keypair(self) -> tuple[str, str]: ...
    def generate_preshared(self) -> str: ...
    def public_from_private(self, private: str) -> str:
        """Derive the public key for an operator-supplied private key."""
        ...
    def write_server_private_key(self, private: str) -> None:
        """Persist an operator-supplied server private key (0600)."""
        ...

    # lifecycle
    def up(self, config_text: str) -> None: ...
    def sync(self, config_text: str) -> None:
        """Live-apply desired state (wg syncconf); interface must be up."""
        ...
    def down(self) -> None: ...
    def is_running(self) -> bool: ...

    # telemetry
    def dump(self) -> WireGuardDump: ...
    def version(self) -> str | None: ...
    def logs(self, tail: int = 200) -> Sequence[str]: ...
    def metrics(self) -> CoreMetrics: ...


class LocalWireGuardBackend:
    """Production backend based on wireguard-tools (`wg` / `wg-quick`)."""

    # wg-quick is a bash wrapper that shells out to more than just `wg`:
    # `ip` (iproute2) is a strict requirement (alpha.7 report: "ip: command
    # not found"); iptables backs the default-route/PostUp hooks operators
    # rely on.  DNS helpers are deliberately NOT required server-side:
    # panel-rendered server interfaces carry no `DNS =` lines.
    _REQUIRED_TOOLS: dict[str, str] = {
        "wg": "wireguard-tools",
        "wg-quick": "wireguard-tools",
        "ip": "iproute2",
        "iptables": "iptables",
    }

    def __init__(self, settings: dict):
        self.interface = settings.get("interface", "mzwg0")
        self.work_dir = settings.get("work_dir", "/var/lib/zagros/cores/wireguard")
        self.executable = settings.get("executable_wg", "wg")
        self.quick = settings.get("executable_wgquick", "wg-quick")
        self.config_path = os.path.join(self.work_dir, f"{self.interface}.conf")
        self.key_path = os.path.join(self.work_dir, "server.key")
        self.stripped_path = os.path.join(self.work_dir, f"{self.interface}.stripped.conf")
        os.makedirs(self.work_dir, exist_ok=True)

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _run(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        timeout: float = 30.0,
    ) -> str:
        try:
            proc = subprocess.run(
                argv, input=input_text, capture_output=True, text=True, timeout=timeout
            )
        except FileNotFoundError as exc:
            raise CoreError(
                f"wireguard-tools not found ('{argv[0]}') — install the core first."
            ) from exc
        if proc.returncode != 0:
            raise CoreError(
                f"{' '.join(argv)!r} failed (rc={proc.returncode}): {proc.stderr.strip()}"
            )
        return proc.stdout

    def _atomic_write(self, path: str, content: str, mode: int = 0o600) -> None:
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)

    # ------------------------------------------------------------------ #
    # setup
    # ------------------------------------------------------------------ #
    def is_installed(self) -> bool:
        return shutil.which(self.executable) is not None

    def missing_dependencies(self) -> dict[str, str]:
        """tool → package mapping for tools wg / wg-quick need but lack."""
        missing: dict[str, str] = {}
        for tool, package in self._REQUIRED_TOOLS.items():
            if shutil.which(tool) is None:
                missing[tool] = package
        return missing

    def _ensure_host_tools(self) -> None:
        """Self-heal host prerequisites before touching the interface.

        Raises an honest CoreError that names the missing OS packages when
        they are absent (and after a failed install attempt) instead of
        surfacing wg-quick's raw ``ip: command not found``.
        """
        missing = self.missing_dependencies()
        if not missing:
            return
        logger.warning(
            "wireguard: host prerequisites missing %s — installing…",
            ", ".join(sorted(set(missing.values()))),
        )
        self.install_packages()  # CoreError from the PM propagates as-is
        still_missing = self.missing_dependencies()
        if still_missing:
            packages = ", ".join(sorted(set(still_missing.values())))
            raise CoreError(
                f"wireguard prerequisites still missing after install attempt: "
                f"{packages}. Install them with your OS package manager and retry."
            )

    def install_packages(self) -> str:
        # wg-quick hard-requires `ip` and (for the default-route/PostUp
        # firewall hooks) iptables — install all three in one shot.
        for manager, argv in (
            ("apt-get", ["apt-get", "install", "-y", "wireguard-tools", "iproute2", "iptables"]),
            ("dnf", ["dnf", "install", "-y", "wireguard-tools", "iproute", "iptables"]),
            ("yum", ["yum", "install", "-y", "wireguard-tools", "iproute", "iptables"]),
            ("pacman", ["pacman", "-S", "--noconfirm", "wireguard-tools", "iproute2", "iptables"]),
        ):
            if shutil.which(manager):
                if manager == "apt-get":
                    # fresh containers/minimal cloud images ship EMPTY apt
                    # lists — install without update fails with
                    # "Unable to locate package" (reported on alpha.7 VPS)
                    self._run(["apt-get", "update"], timeout=600)
                return self._run(argv, timeout=600)
        raise CoreError("no supported package manager found (apt/dnf/yum/pacman).")

    def generate_keypair(self) -> tuple[str, str]:
        private = self._run([self.executable, "genkey"]).strip()
        public = self._run([self.executable, "pubkey"], input_text=private).strip()
        return private, public

    def generate_preshared(self) -> str:
        return self._run([self.executable, "genpsk"]).strip()

    def public_from_private(self, private: str) -> str:
        """Derive the public key for an operator-supplied private key (the
        studio wizard accepts a custom server key)."""
        return self._run([self.executable, "pubkey"], input_text=private.strip()).strip()

    def write_server_private_key(self, private: str) -> None:
        """Persist an operator-supplied server private key (0600), replacing
        the generated one — next start/render uses it."""
        self._atomic_write(self.key_path, private.strip() + "\n", mode=0o600)
        logger.info("wireguard: server key file replaced (%s).", self.key_path)

    def ensure_server_keys(self) -> tuple[str, str]:
        if os.path.exists(self.key_path):
            with open(self.key_path, encoding="utf-8") as fh:
                private = fh.read().strip()
            public = self._run([self.executable, "pubkey"], input_text=private).strip()
            return private, public
        private, public = self.generate_keypair()
        self._atomic_write(self.key_path, private + "\n", mode=0o600)
        logger.info("wireguard: generated new server keypair (%s).", self.key_path)
        return private, public

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def up(self, config_text: str) -> None:
        self._ensure_host_tools()
        self._atomic_write(self.config_path, config_text)
        if self.is_running():
            self.sync(config_text)
            return
        self._run([self.quick, "up", self.config_path], timeout=60)

    def sync(self, config_text: str) -> None:
        self._atomic_write(self.config_path, config_text)
        stripped = strip_config(config_text)
        self._atomic_write(self.stripped_path, stripped)
        try:
            self._run([self.executable, "syncconf", self.interface, self.stripped_path])
        except CoreError:
            # interface not up yet (or just died) — bring it back with full config
            self._run([self.quick, "up", self.config_path], timeout=60)

    def down(self) -> None:
        try:
            self._run([self.quick, "down", self.config_path], timeout=60)
        except CoreError:
            pass  # already down / config absent — desired state reached

    def is_running(self) -> bool:
        if not self.is_installed():
            return False
        try:
            out = self._run([self.executable, "show", "interfaces"])
        except CoreError:
            return False
        return self.interface in out.split()

    # ------------------------------------------------------------------ #
    # telemetry
    # ------------------------------------------------------------------ #
    def dump(self) -> WireGuardDump:
        return parse_wg_dump(self._run([self.executable, "show", "all", "dump"]))

    def version(self) -> str | None:
        try:
            out = self._run([self.executable, "--version"])
        except CoreError:
            return None
        parts = out.strip().split()
        return parts[-1] if parts else None

    def logs(self, tail: int = 200) -> Sequence[str]:
        if shutil.which("journalctl"):
            proc = subprocess.run(
                ["journalctl", "-k", "-n", str(tail), "--no-pager",
                 "--grep", "wireguard"],
                capture_output=True, text=True, timeout=20,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.splitlines()
        return []  # kernel module logs nowhere else; honest empty

    def metrics(self) -> CoreMetrics:
        stats = CoreMetrics()
        try:
            dump = self.dump()
        except CoreError:
            return stats
        stats.active_accounts = len(dump.peers)
        stats.network_rx_bytes = sum(p.transfer_rx for p in dump.peers)
        stats.network_tx_bytes = sum(p.transfer_tx for p in dump.peers)
        return stats
