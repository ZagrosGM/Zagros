"""Backend boundary for the SoftEther driver.

  * :class:`SoftEtherBackend` — Protocol: hub user/session management via
    the official `vpncmd` management CLI.
  * :class:`LocalSoftEtherBackend` — production implementation; every change
    applies instantly to the live server (SoftEther has full runtime
    management — no restart semantics, honest HOT_RELOAD).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Protocol, runtime_checkable

from app.cores.drivers.softether.setool import (
    SESession,
    UserStatistics,
    parse_session_list,
    parse_user_get,
    parse_user_list,
)
from app.cores.exceptions import CoreError

logger = logging.getLogger("zagros.cores.drivers.softether")

#: a permanently-past date used to suspend users natively (honest switch):
_SUSPENDED_EXPIRES = "2000/01/01 00:00:00"


@runtime_checkable
class SoftEtherBackend(Protocol):
    def reachable(self) -> bool: ...
    def user_create(self, username: str, note: str = "") -> None: ...
    def user_delete(self, username: str) -> None: ...
    def user_password_set(self, username: str, password: str) -> None: ...
    def user_expires_set(self, username: str, expires: str | None) -> None: ...
    def suspend_user(self, username: str) -> None: ...
    def user_get(self, username: str) -> UserStatistics: ...
    def user_list(self) -> list[str]: ...
    def session_list(self) -> list[SESession]: ...
    def session_disconnect(self, session_name: str) -> None: ...
    def ipsec_psk(self) -> str | None: ...


class LocalSoftEtherBackend:
    """vpncmd-based backend (localhost hub administration)."""

    def __init__(self, settings: dict):
        self.vpncmd = settings.get("executable_path", "vpncmd")
        self.server = settings.get("server", "localhost")
        self.hub = settings.get("hub", "DEFAULT")
        self.password = settings.get("admin_password", "")
        self.timeout = float(settings.get("vpncmd_timeout", 30.0))

    # ------------------------------------------------------------------ #
    # command plumbing
    # ------------------------------------------------------------------ #
    def _cmd(self, command: str, *, csv: bool = False) -> str:
        if shutil.which(self.vpncmd) is None:
            raise CoreError(
                "vpncmd not found — press Install for this core (or run its "
                "install_packages()): apt 'softether-vpnserver' on supported "
                "distros, otherwise the official GitHub release is fetched."
            )
        argv = [
            self.vpncmd, self.server, "/SERVER", f"/HUB:{self.hub}",
            f"/PASSWORD:{self.password}",
        ]
        if csv:
            argv.append("/CSV")
        argv += ["/CMD", command]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout
            )
        except subprocess.TimeoutExpired as exc:
            raise CoreError(f"vpncmd timed out on '{command}'.") from exc
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise CoreError(f"vpncmd '{command}' failed (rc={proc.returncode}): {out.strip()[:400]}")
        error_line = next(
            (line.strip() for line in out.splitlines()
             if line.strip().startswith("Error") or "error occurred" in line.lower()),
            None,
        )
        if error_line:
            raise CoreError(f"vpncmd '{command}' failed: {error_line}")
        return proc.stdout or ""

    # ------------------------------------------------------------------ #
    # setup — real SELF_INSTALL
    # ------------------------------------------------------------------ #
    def install_packages(self) -> str:
        """Install SoftEther VPN Server for real; returns a human description.

        Strategy chain (first success wins):
        1. apt, on distros shipping it: ``apt-get update`` (containers ship
           empty lists — the update is what makes the candidate exist) then
           ``apt-get install -y softether-vpnserver``.
        2. Official GitHub releases (SoftEtherVPN/SoftEtherVPN): the
           ``softether-vpnserver-…-linux-<arch>-64bit.tar.gz`` asset — the
           tarball bundles ``vpnserver`` + ``vpncmd`` + ``hamcore.se2``; laid
           out under ``/usr/local/softether`` and symlinked onto PATH.
        Raises CoreError with the attempted detail when everything failed.
        """
        errors: list[str] = []
        if shutil.which("apt-get"):
            try:
                self._run(["apt-get", "update"], timeout=600)
                self._run(["apt-get", "install", "-y", "softether-vpnserver"], timeout=900)
                if shutil.which("vpnserver") or os.path.exists("/usr/lib/softether/vpnserver"):
                    return "installed softether-vpnserver via apt"
                errors.append("apt install completed but vpnserver not found on PATH")
            except CoreError as exc:
                errors.append(f"apt: {exc}")
        # GitHub fallback is always eligible (official SoftEtherVPN releases)
        try:
            return self._install_from_github()
        except Exception as exc:  # noqa: BLE001 — report every attempt
            errors.append(f"github: {exc}")
        raise CoreError(
            "could not self-install SoftEther VPN Server — attempts: "
            + " | ".join(errors or ["no strategy applicable on this host"])
        )

    def _install_from_github(self) -> str:
        from app.cores.github_install import host_arch, host_os, install_from_github

        system, arch = host_os(), host_arch()
        if system != "linux" or arch not in ("amd64", "arm64"):
            raise CoreError(f"no official SoftEther build for {system}/{arch}")
        arch_bits = ("x64-64bit",) if arch == "amd64" else ("arm64-64bit",)
        root = "/usr/local/softether"
        os.makedirs(root, exist_ok=True)
        tag = install_from_github(
            repo="SoftEtherVPN/SoftEtherVPN",
            target_executable=os.path.join(root, "vpnserver"),
            asset_match=lambda n: (
                n.startswith("softether-vpnserver-")
                and n.endswith(".tar.gz")
                and any(bit in n for bit in arch_bits)
            ),
            member_match=lambda m: m.rsplit("/", 1)[-1] == "vpnserver",
            extra_members={
                "vpncmd": os.path.join(root, "vpncmd"),
                "hamcore.se2": os.path.join(root, "hamcore.se2"),
            },
        )
        os.chmod(os.path.join(root, "vpncmd"), 0o755)
        for name in ("vpnserver", "vpncmd"):
            link = os.path.join("/usr/local/bin", name)
            try:
                if os.path.lexists(link):
                    os.remove(link)
                os.symlink(os.path.join(root, name), link)
            except OSError as exc:
                logger.warning("softether PATH link %s failed: %s", link, exc)
        return f"installed SoftEther {tag} from GitHub releases"

    def _run(self, argv: list[str], *, timeout: float = 120.0) -> str:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise CoreError(f"executable not found: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CoreError(f"command timed out: {' '.join(argv)}") from exc
        if proc.returncode != 0:
            detail = ((proc.stderr or "") + (proc.stdout or "")).strip()
            raise CoreError(f"command failed {' '.join(argv)}: {detail[:300]}")
        return proc.stdout or ""

    def server_binary(self) -> str | None:
        """Path of the vpnserver daemon binary, PATH first then known layouts."""
        hit = shutil.which("vpnserver")
        if hit:
            return hit
        for candidate in ("/usr/local/bin/vpnserver", "/usr/local/softether/vpnserver",
                          "/usr/lib/softether/vpnserver", "/usr/libexec/softether/vpnserver"):
            if os.path.exists(candidate):
                return candidate
        return None

    def server_start(self) -> None:
        """Launch the SoftEther daemon (it self-forks); idempotent by design —
        callers check reachable() first, and the daemon itself refuses
        double-starts harmlessly."""
        binary = self.server_binary()
        if binary is None:
            raise CoreError(
                "vpnserver binary not found — install the core first "
                "(Install action on the Cores page)."
            )
        self._run([binary, "start"], timeout=60)

    # ------------------------------------------------------------------ #
    # Protocol implementation
    # ------------------------------------------------------------------ #
    def reachable(self) -> bool:
        try:
            self._cmd("ServerInfoGet")
            return True
        except CoreError:
            return False

    def user_create(self, username: str, note: str = "") -> None:
        self._cmd(f'UserCreate {username} /GROUP: /REALNAME:"{note}" /NOTE:panel')

    def user_delete(self, username: str) -> None:
        self._cmd(f"UserDelete {username}")

    def user_password_set(self, username: str, password: str) -> None:
        self._cmd(f"UserPasswordSet {username} /PASSWORD:{password}")

    def user_expires_set(self, username: str, expires: str | None) -> None:
        if expires is None:
            self._cmd(f"UserExpiresSet {username} /EXPIRES:none")
        else:
            self._cmd(f'UserExpiresSet {username} /EXPIRES:"{expires}"')

    def suspend_user(self, username: str) -> None:
        self._cmd(f'UserExpiresSet {username} /EXPIRES:"{_SUSPENDED_EXPIRES}"')

    def user_get(self, username: str) -> UserStatistics:
        return parse_user_get(self._cmd(f"UserGet {username}"))

    def user_list(self) -> list[str]:
        return [u.username for u in parse_user_list(self._cmd("UserList", csv=True))]

    def session_list(self) -> list[SESession]:
        return parse_session_list(self._cmd("SessionList", csv=True))

    def session_disconnect(self, session_name: str) -> None:
        self._cmd(f"SessionDisconnect {session_name}")

    def ipsec_psk(self) -> str | None:
        return None  # optional: IPsecEnable inspection (kept honest: unset)
