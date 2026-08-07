"""Backend boundary for the SSH tunnel driver.

  * :class:`SSHBackend` — Protocol: unix account management + session discovery.
  * :class:`LocalSystemSSHBackend` — production implementation with the
    standard system tools (useradd/usermod/userdel/chpasswd/pkill/ps).
    Requires root, like the rest of the panel's host-managing cores.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from app.cores.drivers.ssh.sshtool import SSHSession, parse_ps_sshd
from app.cores.exceptions import CoreError

logger = logging.getLogger("zagros.cores.drivers.ssh")


@runtime_checkable
class SSHBackend(Protocol):
    def user_exists(self, username: str) -> bool: ...
    def create_user(self, username: str, password: str, shell: str, create_home: bool) -> None: ...
    def set_password(self, username: str, password: str) -> None: ...
    def lock_user(self, username: str) -> None: ...
    def unlock_user(self, username: str) -> None: ...
    def delete_user(self, username: str) -> None: ...
    def sessions(self) -> list[SSHSession]: ...
    def kill_sessions(self, username: str) -> int: ...
    def sshd_running(self) -> bool: ...
    def logs(self, tail: int = 200) -> Sequence[str]: ...
    def install_packages(self) -> str: ...


class LocalSystemSSHBackend:
    """Production backend driving the host's standard account tools."""

    def __init__(self, settings: dict):
        self.settings = settings

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _run(argv: list[str], *, input_text: str | None = None,
             timeout: float = 30.0, check: bool = True) -> str:
        try:
            proc = subprocess.run(
                argv, input=input_text, capture_output=True, text=True, timeout=timeout
            )
        except FileNotFoundError as exc:
            raise CoreError(f"required system tool '{argv[0]}' not found.") from exc
        if check and proc.returncode != 0:
            raise CoreError(
                f"'{' '.join(argv)}' failed (rc={proc.returncode}): {proc.stderr.strip()}"
            )
        return proc.stdout

    # ------------------------------------------------------------------ #
    # accounts
    # ------------------------------------------------------------------ #
    def user_exists(self, username: str) -> bool:
        proc = subprocess.run(["id", "-u", username], capture_output=True, text=True)
        return proc.returncode == 0

    def create_user(self, username: str, password: str, shell: str, create_home: bool) -> None:
        argv = ["useradd", "--shell", shell]
        argv.append("--create-home" if create_home else "--no-create-home")
        argv.append(username)
        self._run(argv)
        self.set_password(username, password)
        logger.info("ssh: created tunnel account '%s'.", username)

    def set_password(self, username: str, password: str) -> None:
        self._run(["chpasswd"], input_text=f"{username}:{password}\n")

    def lock_user(self, username: str) -> None:
        self._run(["usermod", "--lock", username])

    def unlock_user(self, username: str) -> None:
        self._run(["usermod", "--unlock", username])

    def delete_user(self, username: str) -> None:
        self._run(["userdel", username], check=False)  # idempotent

    # ------------------------------------------------------------------ #
    # sessions
    # ------------------------------------------------------------------ #
    def sessions(self) -> list[SSHSession]:
        out = self._run(["ps", "-eo", "user=,pid=,etimes=,args="], check=False)
        return parse_ps_sshd(out)

    def kill_sessions(self, username: str) -> int:
        sessions = [s for s in self.sessions() if s.user == username]
        for session in sessions:
            self._run(["kill", "-KILL", str(session.pid)], check=False)
        return len(sessions)

    # ------------------------------------------------------------------ #
    # daemon state / logs / packages
    # ------------------------------------------------------------------ #
    def sshd_running(self) -> bool:
        if shutil.which("systemctl"):
            for unit in ("sshd", "ssh"):
                proc = subprocess.run(
                    ["systemctl", "is-active", "--quiet", unit],
                    capture_output=True,
                )
                if proc.returncode == 0:
                    return True
        out = self._run(["pgrep", "-x", "sshd"], check=False)
        return bool(out.strip())

    def logs(self, tail: int = 200) -> Sequence[str]:
        if shutil.which("journalctl"):
            proc = subprocess.run(
                ["journalctl", "-u", "sshd", "-u", "ssh", "-n", str(tail), "--no-pager"],
                capture_output=True, text=True, timeout=20,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.splitlines()
        return []

    def install_packages(self) -> str:
        for manager, argv in (
            ("apt-get", ["apt-get", "install", "-y", "openssh-server"]),
            ("dnf", ["dnf", "install", "-y", "openssh-server"]),
            ("yum", ["yum", "install", "-y", "openssh-server"]),
            ("pacman", ["pacman", "-S", "--noconfirm", "openssh"]),
            ("apk", ["apk", "add", "openssh"]),
        ):
            if shutil.which(manager):
                if manager == "apt-get":
                    # container images carry no apt lists: without update the
                    # candidate lookup fails ("no installation candidate")
                    self._run(["apt-get", "update"], timeout=600)
                return self._run(argv, timeout=600)
        raise CoreError("no supported package manager found (apt/dnf/yum/pacman/apk).")
