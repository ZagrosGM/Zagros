"""Backend boundary for the SSH tunnel driver.

  * :class:`SSHBackend` — Protocol: unix account management + session discovery.
  * :class:`LocalSystemSSHBackend` — production implementation with the
    standard system tools (useradd/usermod/userdel/chpasswd/pkill/ps).
    Requires root, like the rest of the panel's host-managing cores.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from app.cores.drivers.ssh.sshtool import (
    ACCT_CHAIN,
    SSHSession,
    parse_acct_counters,
    parse_ps_sshd,
)
from app.cores.exceptions import CoreError

logger = logging.getLogger("zagros.cores.drivers.ssh")

_UID_RULE_S = re.compile(r"--uid-owner (\d+)")

#: the accounting chain is panel-owned; every writer lives in THIS process
#: (usage ticks), so one lock gives exact-once converge semantics
_ACCT_LOCK = threading.Lock()


@runtime_checkable
class SSHBackend(Protocol):
    def user_exists(self, username: str) -> bool: ...
    def create_user(self, username: str, password: str, shell: str, create_home: bool) -> None: ...
    def set_password(self, username: str, password: str) -> None: ...
    def authorize_key(self, username: str, public_key: str) -> str: ...
    def lock_user(self, username: str) -> None: ...
    def unlock_user(self, username: str) -> None: ...
    def delete_user(self, username: str) -> None: ...
    def sessions(self) -> list[SSHSession]: ...
    def kill_sessions(self, username: str) -> int: ...
    def sshd_running(self) -> bool: ...
    def logs(self, tail: int = 200) -> Sequence[str]: ...
    def install_packages(self) -> str: ...


class LocalSystemSSHBackend:
    # sshd lives outside PATH (sbin) on Debian-family service environments,
    # so `which` alone is not enough; keep the well-known fallbacks as an
    # explicit seam (tests patch it to simulate a host without sshd).
    SSHD_FALLBACK_PATHS = ("/usr/sbin/sshd", "/usr/local/sbin/sshd")

    """Production backend driving the host's standard account tools."""

    def __init__(self, settings: dict):
        self.settings = settings
        self.work_dir = str(settings.get("work_dir") or
                            "/var/lib/zagros/cores/ssh")
        self._sftp_socket_path = str(settings.get("sftp_accounting_socket") or
                                     os.path.join(self.work_dir, "accounting.sock"))
        self._sftp_state_path = os.path.join(self.work_dir,
                                             "sftp-usage.json")
        self._sftp_lock = threading.Lock()
        self._sftp_totals: dict[int, tuple[int, int]] = {}
        self._sftp_socket: socket.socket | None = None
        self._sftp_thread: threading.Thread | None = None
        self._sftp_stop = threading.Event()
        self._load_sftp_totals()

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

    @staticmethod
    def _rc(argv: list[str], *, timeout: float = 15.0) -> int:
        """Exit-code-only run for kernel-checked idempotency guards (the
        netlink table itself answers whether a rule exists — an exception
        here maps to 'not satisfied' so the caller retries the real op)."""
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout)
        except (subprocess.SubprocessError, OSError):
            return 127
        return proc.returncode

    # ------------------------------------------------------------------ #
    # SFTP/SCP stream accounting — both directions, capability independent
    # ------------------------------------------------------------------ #
    def _load_sftp_totals(self) -> None:
        try:
            raw = json.loads(open(self._sftp_state_path, encoding="utf-8").read())
            self._sftp_totals = {
                int(uid): (max(0, int(values[0])), max(0, int(values[1])))
                for uid, values in raw.items()
                if isinstance(values, list) and len(values) == 2
            }
        except (OSError, ValueError, TypeError):
            self._sftp_totals = {}

    def _save_sftp_totals_locked(self) -> None:
        os.makedirs(self.work_dir, mode=0o755, exist_ok=True)
        part = self._sftp_state_path + ".part"
        with open(part, "w", encoding="utf-8") as fh:
            json.dump({str(uid): [up, down]
                       for uid, (up, down) in self._sftp_totals.items()}, fh)
        os.chmod(part, 0o600)
        os.replace(part, self._sftp_state_path)

    def _sftp_collect(self) -> None:
        sock = self._sftp_socket
        assert sock is not None
        cred_size = struct.calcsize("3i")
        while not self._sftp_stop.is_set():
            try:
                data, ancdata, _flags, _address = sock.recvmsg(1024,
                    socket.CMSG_SPACE(cred_size))
            except socket.timeout:
                continue
            except OSError:
                break
            uid: int | None = None
            for level, kind, payload in ancdata:
                if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                    _pid, uid, _gid = struct.unpack("3i", payload[:cred_size])
                    break
            if uid is None or uid <= 0:
                continue
            try:
                event = json.loads(data.decode("utf-8"))
                up = max(0, int(event["uplink"]))
                down = max(0, int(event["downlink"]))
            except (ValueError, TypeError, KeyError, UnicodeDecodeError):
                continue
            # Bound one event to prevent a compromised account from integer
            # bombing the quota store; legitimate sessions can report up to
            # one PiB per direction.
            if up > 1 << 50 or down > 1 << 50:
                continue
            with self._sftp_lock:
                old_up, old_down = self._sftp_totals.get(uid, (0, 0))
                self._sftp_totals[uid] = (old_up + up, old_down + down)
                try:
                    self._save_sftp_totals_locked()
                except OSError as exc:
                    logger.warning("ssh SFTP accounting state write failed: %s", exc)

    def sftp_acct_start(self) -> str:
        """Start the credential-checked local collector used by the OpenSSH
        ForceCommand helper; returns its socket path."""
        if self._sftp_thread is not None and self._sftp_thread.is_alive():
            return self._sftp_socket_path
        if not hasattr(socket, "SO_PASSCRED"):
            raise CoreError("kernel/Python lacks SO_PASSCRED for secure SFTP accounting")
        socket_dir = os.path.dirname(self._sftp_socket_path)
        os.makedirs(socket_dir, mode=0o755, exist_ok=True)
        # The sshd child has already dropped to the account UID when the
        # wrapper connects; every parent directory must be traversable while
        # state files inside remain root-only 0600.
        os.chmod(socket_dir, 0o755)
        try:
            os.remove(self._sftp_socket_path)
        except FileNotFoundError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        sock.bind(self._sftp_socket_path)
        os.chmod(self._sftp_socket_path, 0o666)
        sock.settimeout(0.5)
        self._sftp_socket = sock
        self._sftp_stop.clear()
        self._sftp_thread = threading.Thread(
            target=self._sftp_collect, name="zagros-ssh-sftp-accounting",
            daemon=True)
        self._sftp_thread.start()
        return self._sftp_socket_path

    def sftp_acct_stop(self) -> None:
        self._sftp_stop.set()
        if self._sftp_socket is not None:
            self._sftp_socket.close()
            self._sftp_socket = None
        if self._sftp_thread is not None:
            self._sftp_thread.join(timeout=2)
            self._sftp_thread = None
        try:
            os.remove(self._sftp_socket_path)
        except FileNotFoundError:
            pass

    def sftp_acct_read(self) -> dict[int, tuple[int, int]]:
        with self._sftp_lock:
            return dict(self._sftp_totals)

    # ------------------------------------------------------------------ #
    # per-UID forwarding uplink accounting — iptables owner match
    # ------------------------------------------------------------------ #
    def acct_available(self) -> str | None:
        """None when per-UID accounting can run; else a DIAGNOSIS for the
        operator (iptables absent, or NET_ADMIN missing — the panel
        container needs the capability: installer compose grants it)."""
        iptables = shutil.which("iptables") or next(
            (p for p in ("/usr/sbin/iptables", "/sbin/iptables") if os.path.exists(p)),
            None,
        )
        if iptables is None:
            return ("iptables not found — SSH forwarding accounting needs it "
                    "(SFTP accounting remains independent).")
        # Probe the actual kernel owner matcher, not merely the iptables
        # executable. Minimal/container kernels can list rules yet reject
        # `-m owner` with rc=4; the old readiness check produced a false PASS.
        probe = subprocess.run(
            [iptables, "-C", "OUTPUT", "-m", "owner", "--uid-owner", "0",
             "-j", "ACCEPT"],
            capture_output=True, text=True, timeout=15)
        if probe.returncode not in (0, 1):
            detail = (probe.stderr or probe.stdout or "owner matcher unavailable").strip()
            return f"iptables owner matcher unavailable: {detail}"
        try:
            self._run([iptables, "-S", ACCT_CHAIN], timeout=15)
        except CoreError as exc:
            text = str(exc)
            if "Permission" in text or "Operation not permitted" in text:
                return ("iptables unavailable inside this container — grant "
                        "NET_ADMIN (installer compose does; existing installs: "
                        "zagros update --force).")
            return None  # any other error = chain simply absent: creatable
        return None

    def _iptables(self) -> str:
        return shutil.which("iptables") or next(
            (p for p in ("/usr/sbin/iptables", "/sbin/iptables") if os.path.exists(p)),
            "iptables",
        )

    def acct_ensure(self) -> None:
        ipt = self._iptables()
        try:
            self._run([ipt, "-N", ACCT_CHAIN], check=False)
        except CoreError:
            pass  # exists already
        rules = self._run([ipt, "-S", "OUTPUT"], check=False)
        if f" -j {ACCT_CHAIN}" not in rules:
            self._run([ipt, "-I", "OUTPUT", "1", "-j", ACCT_CHAIN])

    def acct_sync_users(self, uids: set[int]) -> None:
        """Converge per-UID accounting rules to exactly ``uids`` — exactly
        once each (alpha.7.5 item 13).

        Field bug: racing usage ticks left DUPLICATED owner-match rules
        (the kernel counts a packet against EVERY matching rule → the
        user's traffic was double-counted), and symmetric racing drains
        could over-delete to zero. The chain is panel-owned and the race
        is between this process's threads, so the converge runs under a
        module-level lock; the kernel-level `-C` existence checks and the
        bounded duplicate drain stay as defense against out-of-band edits
        and already-damaged state.
        """
        with _ACCT_LOCK:
            self._acct_sync_users_locked(uids)

    def _acct_sync_users_locked(self, uids: set[int]) -> None:
        ipt = self._iptables()
        self.acct_ensure()
        rule_args = lambda uid: ["-m", "owner", "--uid-owner",  # noqa: E731
                                 str(uid), "-j", "RETURN"]

        def occurrences(uid: int) -> int:
            count = 0
            for line in self._run([ipt, "-S", ACCT_CHAIN]).splitlines():
                m = _UID_RULE_S.search(line)
                if m and int(m.group(1)) == uid:
                    count += 1
            return count

        current: set[int] = set()
        for line in self._run([ipt, "-S", ACCT_CHAIN]).splitlines():
            m = _UID_RULE_S.search(line)
            if m:
                current.add(int(m.group(1)))

        for uid in sorted(uids):
            if uid not in current and self._rc(
                    [ipt, "-C", ACCT_CHAIN, *rule_args(uid)]) != 0:
                self._run([ipt, "-A", ACCT_CHAIN, *rule_args(uid)])
            for _ in range(8):  # drain duplicates (double-count source)
                if occurrences(uid) <= 1:
                    break
                if self._rc([ipt, "-D", ACCT_CHAIN, *rule_args(uid)]) != 0:
                    break
        # rule deletion counters-reset is fine for removed accounts — their
        # tracker baseline is forgotten alongside (driver does both)
        for uid in sorted(current - uids):
            for _ in range(8):  # remove every stale instance, incl. dupes
                if self._rc([ipt, "-D", ACCT_CHAIN, *rule_args(uid)]) != 0:
                    break

    def acct_read(self) -> dict[int, int]:
        out = self._run([self._iptables(), "-L", ACCT_CHAIN, "-n", "-v", "-x"])
        return parse_acct_counters(out)

    def acct_teardown(self) -> None:
        """Remove jump + chain (best-effort; uninstall keeps the host clean)."""
        ipt = self._iptables()
        try:
            self._run([ipt, "-D", "OUTPUT", "-j", ACCT_CHAIN], check=False)
            self._run([ipt, "-F", ACCT_CHAIN], check=False)
            self._run([ipt, "-X", ACCT_CHAIN], check=False)
        except CoreError:
            logger.debug("ssh acct teardown skipped: chain not removable")

    def uid_of(self, username: str) -> int | None:
        try:
            out = self._run(["id", "-u", username], timeout=10)
        except CoreError:
            return None
        try:
            return int(out.strip())
        except ValueError:
            return None

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
        key_file = os.path.join(self._keys_dir, username)
        if os.path.exists(key_file):
            os.remove(key_file)

    # ------------------------------------------------------------------ #
    # authorized keys (panel-owned dir, home-dir independent; sshd reads it
    # via the drop-in's AuthorizedKeysFile line — works even for
    # --no-create-home tunnel accounts)
    # ------------------------------------------------------------------ #
    _keys_dir = "/etc/ssh/zagros_keys"

    def authorize_key(self, username: str, public_key: str) -> str:
        """Install *public_key* as the account's panel-owned authorized key.

        StrictModes-compliant: directory and file root-owned, sshd only
        requires the chain to be non-group/world-writable, while the file
        itself is made readable by the target user's primary group is NOT
        needed — sshd reads authorized keys as root before dropping
        privileges, so root:root 0600 is sufficient and safest.
        """
        key = public_key.strip()
        if not key.startswith(("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-", "sk-")):
            raise CoreError(
                f"refusing to install non-SSH public key for '{username}' "
                "(expected ssh-ed25519/ssh-rsa/ecdsa-*/sk-*)."
            )
        os.makedirs(self._keys_dir, exist_ok=True)
        os.chmod(self._keys_dir, 0o755)
        path = os.path.join(self._keys_dir, username)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(key + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return path

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

    # ------------------------------------------------------------------ #
    # full service bring-up (alpha.7.1): the old behaviour was a bare
    # "sshd is not running — enable the system ssh service" error. A core
    # must reach the READY state itself: install → host keys → panel-owned
    # drop-in → validate → enable+start → verify.
    # ------------------------------------------------------------------ #
    @property
    def _dropin_path(self) -> str:
        return self.settings.get(
            "dropin_path", "/etc/ssh/sshd_config.d/zagros.conf"
        )

    def _sshd_bin(self) -> str | None:
        found = shutil.which("sshd")
        if found:
            return found
        for candidate in self.SSHD_FALLBACK_PATHS:
            if os.path.exists(candidate):
                return candidate
        return None

    def render_dropin(self) -> str:
        """Panel-owned sshd overrides. SAFETY CONTRACT: port 22 is always
        kept — a `Port` directive replaces the default listener set, and a
        panel that removed 22 would lock the operator out of their own box.

        Multi-inbound (alpha.7.2): one `Port` line per panel listener
        (settings['listeners']); the legacy single 'port' is the fallback
        for pre-7.2 settings blobs."""
        s = self.settings
        listeners: list[tuple[int, str]] = []  # (port, listen)
        for row in (s.get("listeners") or []):
            try:
                port = int((row or {}).get("port"))
            except (TypeError, ValueError):
                continue
            listen = str((row or {}).get("listen") or "0.0.0.0")
            if 1 <= port <= 65535 and port != 22 and all(p != port for p, _ in listeners):
                listeners.append((port, listen))
        if not listeners:
            panel_port = int(s.get("port") or 22)
            if panel_port != 22:
                listeners.append((panel_port, "0.0.0.0"))
        lines = [
            "# zagros-managed sshd drop-in — rewritten by the panel; do not edit by hand.",
            "Port 22  # operator access must never be locked out",
        ]
        for port, listen in listeners:
            lines.append(f"Port {port}")
            if listen not in ("", "0.0.0.0", "::"):
                lines.append(f"ListenAddress {listen}")
        lines.append(
            "PasswordAuthentication " + ("yes" if s.get("password_auth", True) else "no")
        )
        lines.append(
            "PubkeyAuthentication " + ("yes" if s.get("pubkey_auth", True) else "no")
        )
        if s.get("pubkey_auth", True):
            # panel-owned per-user key files (root:root 0600 — StrictModes clean,
            # sshd reads them as root pre-setuid); works without home dirs
            lines.append(
                f"AuthorizedKeysFile .ssh/authorized_keys {self._keys_dir}/%u"
            )
        if s.get("max_sessions"):
            lines.append(f"MaxSessions {int(s['max_sessions'])}")
        if s.get("banner"):
            banner_path = os.path.join(
                os.path.dirname(self._dropin_path), "zagros.banner"
            )
            with open(banner_path, "w", encoding="utf-8") as fh:
                fh.write(str(s["banner"]).rstrip("\n") + "\n")
            lines.append(f"Banner {banner_path}")
        if s.get("sftp", True):
            # Do not redeclare Subsystem in a drop-in (Debian's main config
            # already defines it and duplicate declarations make `sshd -t`
            # fail). Intercept only panel users via ForceCommand; the helper
            # delegates non-SFTP commands unchanged.
            wrapper = os.path.join(os.path.dirname(__file__),
                                   "sftp_accounting.py")
            lines += [
                "Match User zg-*",
                f"    ForceCommand {sys.executable} {wrapper} {self._sftp_socket_path}",
                "Match all",
            ]
        return "\n".join(lines) + "\n"

    def _write_dropin_if_changed(self) -> bool:
        content = self.render_dropin()
        path = self._dropin_path
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                if fh.read() == content:
                    return False  # idempotent: no rewrite, no reload ripple
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        return True

    def _ensure_host_keys(self) -> None:
        import glob

        if glob.glob("/etc/ssh/ssh_host_*_key"):
            return
        keygen = shutil.which("ssh-keygen")
        if keygen is None:
            raise CoreError(
                "no ssh host keys and ssh-keygen is unavailable — "
                "generate host keys (ssh-keygen -A) before starting sshd."
            )
        self._run([keygen, "-A"], timeout=120)

    def _systemd_alive(self) -> bool:
        if not shutil.which("systemctl"):
            return False
        proc = subprocess.run(
            ["systemctl", "is-system-running"], capture_output=True, text=True
        )
        return proc.returncode == 0 and proc.stdout.strip() in {
            "running", "degraded", "starting", "maintenance",
        }

    def _ssh_unit(self) -> str | None:
        for unit in ("ssh.service", "sshd.service"):
            proc = subprocess.run(
                ["systemctl", "cat", unit], capture_output=True, text=True
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return unit
        return None

    def _enable_start_or_reload(self, changed: bool, was_running: bool) -> str:
        """systemd (enable --now / reload when live config only) → service(8)
        → direct `sshd` launch (ssh-daemonises itself — the container path).
        sshd RELOAD is non-disruptive: never bounce a healthy daemon and kick
        the operator's own sessions."""
        if self._systemd_alive():
            unit = self._ssh_unit()
            if unit:
                if was_running and changed:
                    self._run(["systemctl", "reload", unit], timeout=60)
                elif not was_running:
                    self._run(["systemctl", "enable", "--now", unit], timeout=60)
                return f"systemctl ({unit})"
        if shutil.which("service"):
            for name in ("ssh", "sshd"):
                proc = subprocess.run(
                    ["service", name, "reload" if (was_running and changed) else "start"],
                    capture_output=True, text=True,
                )
                if proc.returncode == 0:
                    return f"service ({name})"
        if not was_running:
            bin_ = self._sshd_bin()
            assert bin_ is not None  # ensured before we get here
            self._run([bin_])
            return "direct sshd launch"
        return "no-op (already running, config unchanged)"

    def ensure_service(self) -> str:
        """Bring sshd to READY and return HOW it was done (for status/logs)."""
        if self._sshd_bin() is None:
            self.install_packages()
        bin_ = self._sshd_bin()
        if bin_ is None:
            raise CoreError(
                "sshd is still missing after installing openssh-server — "
                "read the package-manager output in the core logs."
            )
        self._ensure_host_keys()
        changed = self._write_dropin_if_changed()
        try:
            self._run([bin_, "-t"], timeout=30)
        except CoreError as exc:
            raise CoreError(
                f"generated sshd configuration failed validation — nothing "
                f"was started; the panel-owned drop-in is the suspect:\n{exc}"
            ) from exc
        was_running = self.sshd_running()
        how = self._enable_start_or_reload(changed, was_running)
        if not self.sshd_running():
            raise CoreError(
                f"sshd did not come up via {how} — run 'journalctl -u ssh -u sshd "
                f"-n 50' (or read the core logs) for the daemon's own reason."
            )
        return how
