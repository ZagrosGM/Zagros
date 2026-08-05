"""Backend boundary for the SoftEther driver.

  * :class:`SoftEtherBackend` — Protocol: hub user/session management via
    the official `vpncmd` management CLI.
  * :class:`LocalSoftEtherBackend` — production implementation; every change
    applies instantly to the live server (SoftEther has full runtime
    management — no restart semantics, honest HOT_RELOAD).
"""
from __future__ import annotations

import logging
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
                "vpncmd not found — install SoftEther VPN Server first "
                "(SELF_INSTALL is intentionally not claimed for this core)."
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
