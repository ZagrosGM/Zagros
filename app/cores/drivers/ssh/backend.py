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
import time
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from app.cores.drivers.ssh.sshtool import (
    ACCT_CHAIN,
    ACCT_INPUT_CHAIN,
    ACCT_MARK_CHAIN,
    SSHSession,
    forwarding_mark,
    parse_acct_counters,
    parse_connmark_counters,
    parse_ps_sshd,
    uid_from_forwarding_mark,
)
from app.cores.exceptions import CoreError

logger = logging.getLogger("zagros.cores.drivers.ssh")

_UID_RULE_S = re.compile(r"--uid-owner (\d+)")
_CONNMARK_RULE_S = re.compile(r"--mark (0x[0-9a-fA-F]+|\d+)(?:/0x[0-9a-fA-F]+)?")

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
    def version(self) -> str | None: ...
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

        # Generic SSH forwarding accounting uses the accepted encrypted
        # transport socket itself. ``ss -tinp`` exposes cumulative sent/
        # received bytes and both the privileged + dropped-UID sshd-session
        # PIDs, so attribution remains exact even when OpenSSH creates the
        # forwarding socket in its root monitor.
        self._transport_state_path = os.path.join(
            self.work_dir, "transport-usage.json")
        self._host_transport_state_path = os.path.join(
            self.work_dir, "host-transport-usage.json")
        self._transport_ports_path = os.path.join(
            self.work_dir, "accounting-listeners.json")
        self._transport_forget_path = os.path.join(
            self.work_dir, "accounting-forget.json")
        self._host_transport = False
        self._transport_lock = threading.Lock()
        self._transport_totals: dict[int, tuple[int, int]] = {}
        self._transport_live: dict[str, tuple[int, int, int]] = {}
        self._transport_ports: set[int] = set()
        self._transport_thread: threading.Thread | None = None
        self._transport_stop = threading.Event()
        self._load_transport_totals()

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
    # Generic forwarding — bidirectional encrypted transport accounting
    # ------------------------------------------------------------------ #
    def _load_transport_totals(self) -> None:
        try:
            raw = json.loads(open(
                self._transport_state_path, encoding="utf-8").read())
            totals = raw.get("totals") or {}
            live = raw.get("live") or {}
            self._transport_totals = {
                int(uid): (max(0, int(values[0])), max(0, int(values[1])))
                for uid, values in totals.items()
                if isinstance(values, list) and len(values) == 2
            }
            self._transport_live = {
                str(key): (int(values[0]), max(0, int(values[1])),
                           max(0, int(values[2])))
                for key, values in live.items()
                if isinstance(values, list) and len(values) == 3
            }
        except (OSError, ValueError, TypeError):
            self._transport_totals = {}
            self._transport_live = {}

    def _save_transport_totals_locked(self) -> None:
        os.makedirs(self.work_dir, mode=0o755, exist_ok=True)
        part = self._transport_state_path + ".part"
        with open(part, "w", encoding="utf-8") as fh:
            json.dump({
                "totals": {str(uid): [up, down]
                           for uid, (up, down) in self._transport_totals.items()},
                "live": {key: [uid, received, sent]
                         for key, (uid, received, sent)
                         in self._transport_live.items()},
            }, fh, separators=(",", ":"))
        os.chmod(part, 0o600)
        os.replace(part, self._transport_state_path)

    @staticmethod
    def _pid_uid(pid: int) -> int | None:
        try:
            with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
                line = next(row for row in fh if row.startswith("Uid:"))
            values = line.split()[1:]
            # Real/effective UIDs are both non-root on the dropped session.
            non_root = [int(value) for value in values if int(value) > 0]
            return non_root[0] if non_root else None
        except (OSError, StopIteration, ValueError):
            return None

    def _write_transport_ports(self) -> None:
        self._atomic_json(self._transport_ports_path,
                          sorted(self._transport_ports))

    @staticmethod
    def _atomic_json(path: str, value: Any) -> None:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        part = path + ".part"
        with open(part, "w", encoding="utf-8") as fh:
            json.dump(value, fh, separators=(",", ":"))
        os.chmod(part, 0o600)
        os.replace(part, path)

    def _host_transport_payload(self, *, max_age: float = 5.0) -> dict[str, Any] | None:
        try:
            if time.time() - os.path.getmtime(self._host_transport_state_path) > max_age:
                return None
            raw = json.loads(open(
                self._host_transport_state_path, encoding="utf-8").read())
            if raw.get("version") != 1 or not isinstance(raw.get("totals"), dict):
                return None
            return raw
        except (OSError, ValueError, TypeError):
            return None

    def transport_acct_available(self) -> str | None:
        if self._host_transport_payload() is not None:
            return None
        if os.path.exists("/.dockerenv"):
            return ("host SSH accounting collector is not active or its "
                    "snapshot is stale; run 'zagros install-host-agent'")
        binary = shutil.which("ss")
        if not binary:
            return "iproute2 ss is required for SSH transport accounting"
        try:
            proc = subprocess.run(
                [binary, "-Htinp", "sport = :1"], capture_output=True,
                text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            return f"SSH transport accounting probe failed: {exc}"
        if proc.returncode not in (0, 1):
            detail = (proc.stderr or proc.stdout or "ss rejected socket query").strip()
            return f"SSH transport accounting unavailable: {detail}"
        if os.geteuid() != 0:
            return "SSH transport accounting needs root to map socket PIDs to account UIDs"
        return None

    def _transport_snapshot(self) -> dict[str, tuple[int, int, int]]:
        binary = shutil.which("ss") or "ss"
        snapshot: dict[str, tuple[int, int, int]] = {}
        for port in sorted(self._transport_ports):
            proc = subprocess.run(
                [binary, "-Htinp", f"sport = :{port}"],
                capture_output=True, text=True, timeout=15)
            if proc.returncode not in (0, 1):
                continue
            current: str | None = None
            blocks: list[str] = []
            for line in proc.stdout.splitlines():
                if line and not line[0].isspace():
                    if current:
                        blocks.append(current)
                    current = line
                elif current is not None:
                    current += " " + line.strip()
            if current:
                blocks.append(current)
            for block in blocks:
                pids = sorted({int(value) for value in
                               re.findall(r"\bpid=(\d+)", block)})
                uids = [uid for uid in (self._pid_uid(pid) for pid in pids)
                        if uid is not None]
                if not uids:
                    continue
                sent = re.search(r"\bbytes_sent:(\d+)", block)
                received = re.search(r"\bbytes_received:(\d+)", block)
                if sent is None or received is None:
                    continue
                uid = min(uids)
                key = f"{port}:" + ",".join(str(pid) for pid in pids)
                snapshot[key] = (uid, int(received.group(1)), int(sent.group(1)))
        return snapshot

    def _transport_collect_once(self) -> None:
        current = self._transport_snapshot()
        with self._transport_lock:
            changed = current != self._transport_live
            for key, (uid, received, sent) in current.items():
                previous = self._transport_live.get(key)
                if previous is not None and previous[0] == uid:
                    up_delta = received - previous[1] if received >= previous[1] else received
                    down_delta = sent - previous[2] if sent >= previous[2] else sent
                else:
                    up_delta, down_delta = received, sent
                if up_delta or down_delta:
                    up, down = self._transport_totals.get(uid, (0, 0))
                    self._transport_totals[uid] = (
                        up + max(0, up_delta), down + max(0, down_delta))
                    changed = True
            self._transport_live = current
            if changed:
                self._save_transport_totals_locked()

    def transport_acct_start(self, ports: set[int]) -> None:
        self._transport_ports = {int(port) for port in ports
                                 if 1 <= int(port) <= 65535}
        if not self._transport_ports:
            raise CoreError("SSH transport accounting has no listener ports")
        self._write_transport_ports()
        # The host collector emits a heartbeat even with no live sockets. Give
        # a just-installed/restarted service a bounded window to acknowledge
        # the listener manifest before declaring honest degradation.
        for _ in range(20):
            if self._host_transport_payload() is not None:
                self._host_transport = True
                return
            if not os.path.exists("/.dockerenv"):
                break
            time.sleep(0.25)
        reason = self.transport_acct_available()
        if reason:
            raise CoreError(reason)
        self._host_transport = False
        if self._transport_thread is not None and self._transport_thread.is_alive():
            return
        self._transport_stop.clear()

        def collect() -> None:
            while not self._transport_stop.wait(1.0):
                try:
                    self._transport_collect_once()
                except Exception as exc:  # noqa: BLE001 — collector survives ticks
                    logger.warning("SSH transport accounting poll failed: %s", exc)

        self._transport_thread = threading.Thread(
            target=collect, name="zagros-ssh-transport-accounting", daemon=True)
        self._transport_thread.start()
        self._transport_collect_once()

    def transport_acct_stop(self) -> None:
        if self._host_transport:
            self._host_transport = False
            return
        self._transport_stop.set()
        if self._transport_thread is not None:
            self._transport_thread.join(timeout=3)
            self._transport_thread = None
        try:
            self._transport_collect_once()
        except Exception:  # noqa: BLE001 — shutdown remains best-effort
            pass

    def transport_acct_read(self) -> dict[int, tuple[int, int]]:
        if self._host_transport:
            payload = self._host_transport_payload(max_age=10.0)
            if payload is None:
                raise CoreError("host SSH accounting snapshot is stale")
            return {
                int(uid): (max(0, int(values[0])), max(0, int(values[1])))
                for uid, values in payload["totals"].items()
                if isinstance(values, list) and len(values) == 2
            }
        self._transport_collect_once()
        with self._transport_lock:
            return dict(self._transport_totals)

    def transport_acct_forget(self, uid: int) -> None:
        if self._host_transport or os.path.exists(self._host_transport_state_path):
            existing: list[int] = []
            try:
                raw = json.loads(open(
                    self._transport_forget_path, encoding="utf-8").read())
                if isinstance(raw, list):
                    existing = [int(value) for value in raw]
            except (OSError, ValueError, TypeError):
                pass
            self._atomic_json(self._transport_forget_path,
                              sorted(set(existing) | {int(uid)}))
            return
        with self._transport_lock:
            self._transport_totals.pop(uid, None)
            self._transport_live = {
                key: values for key, values in self._transport_live.items()
                if values[0] != uid
            }
            self._save_transport_totals_locked()

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
    # per-UID bidirectional forwarding accounting — owner + conntrack
    # ------------------------------------------------------------------ #
    def acct_available(self) -> str | None:
        """None when exact forwarding accounting can run; else diagnosis.

        OUTPUT ownership identifies the user's forwarding socket. CONNMARK
        carries that identity onto reverse INPUT packets, which is the missing
        downlink attribution xt_owner alone cannot provide.
        """
        iptables = shutil.which("iptables") or next(
            (p for p in ("/usr/sbin/iptables", "/sbin/iptables") if os.path.exists(p)),
            None,
        )
        if iptables is None:
            return ("iptables not found — SSH forwarding accounting needs "
                    "owner and conntrack support (SFTP remains independent).")
        probes = [
            [iptables, "-C", "OUTPUT", "-m", "owner", "--uid-owner", "0",
             "-j", "ACCEPT"],
            [iptables, "-t", "mangle", "-C", "OUTPUT", "-m", "owner",
             "--uid-owner", "0", "-m", "conntrack", "--ctstate", "NEW",
             "-j", "CONNMARK", "--set-xmark", "0x10000000/0xffffffff"],
            [iptables, "-C", "INPUT", "-m", "connmark", "--mark",
             "0x10000000/0xffffffff", "-j", "ACCEPT"],
        ]
        for probe in probes:
            result = subprocess.run(
                probe, capture_output=True, text=True, timeout=15)
            if result.returncode not in (0, 1):
                detail = (result.stderr or result.stdout or
                          "owner/conntrack matcher unavailable").strip()
                return f"iptables SSH accounting unavailable: {detail}"
        try:
            self._run([iptables, "-S", "OUTPUT"], timeout=15)
            self._run([iptables, "-t", "mangle", "-S", "OUTPUT"], timeout=15)
        except CoreError as exc:
            text = str(exc)
            if "Permission" in text or "Operation not permitted" in text:
                return ("iptables unavailable inside this container — grant "
                        "NET_ADMIN (installer compose does; existing installs: "
                        "zagros update --force).")
        return None

    def _iptables(self) -> str:
        return shutil.which("iptables") or next(
            (p for p in ("/usr/sbin/iptables", "/sbin/iptables") if os.path.exists(p)),
            "iptables",
        )

    def acct_ensure(self) -> None:
        ipt = self._iptables()
        for table, chain in ((None, ACCT_CHAIN), (None, ACCT_INPUT_CHAIN),
                             ("mangle", ACCT_MARK_CHAIN)):
            prefix = [ipt] + (["-t", table] if table else [])
            self._run([*prefix, "-N", chain], check=False)
        hooks = (
            (None, "OUTPUT", ACCT_CHAIN),
            (None, "INPUT", ACCT_INPUT_CHAIN),
            ("mangle", "OUTPUT", ACCT_MARK_CHAIN),
        )
        for table, parent, child in hooks:
            prefix = [ipt] + (["-t", table] if table else [])
            rules = self._run([*prefix, "-S", parent], check=False)
            if f" -j {child}" not in rules:
                self._run([*prefix, "-I", parent, "1", "-j", child])

    @staticmethod
    def _forwarding_rules(uid: int) -> tuple[list[str], list[str], list[str]]:
        mark = f"0x{forwarding_mark(uid):08x}/0xffffffff"
        uplink = ["-m", "owner", "--uid-owner", str(uid), "-j", "RETURN"]
        assign = ["-m", "owner", "--uid-owner", str(uid),
                  "-m", "conntrack", "--ctstate", "NEW",
                  "-j", "CONNMARK", "--set-xmark", mark]
        downlink = ["-m", "connmark", "--mark", mark, "-j", "RETURN"]
        return uplink, assign, downlink

    def acct_sync_users(self, uids: set[int]) -> None:
        """Converge all three per-UID rules exactly once under one lock."""
        with _ACCT_LOCK:
            self._acct_sync_users_locked(uids)

    def _acct_sync_users_locked(self, uids: set[int]) -> None:
        ipt = self._iptables()
        self.acct_ensure()

        specs = (
            (None, ACCT_CHAIN, 0),
            ("mangle", ACCT_MARK_CHAIN, 1),
            (None, ACCT_INPUT_CHAIN, 2),
        )

        def prefix(table: str | None) -> list[str]:
            return [ipt] + (["-t", table] if table else [])

        def occurrences(table: str | None, chain: str, args: list[str]) -> int:
            needle = " ".join(args)
            return sum(
                1 for line in self._run([*prefix(table), "-S", chain]).splitlines()
                if line.endswith(needle)
            )

        current: set[int] = set()
        for table, chain, index in specs:
            for line in self._run([*prefix(table), "-S", chain]).splitlines():
                match = _UID_RULE_S.search(line)
                if match:
                    current.add(int(match.group(1)))
                    continue
                if index == 2:
                    mark_match = _CONNMARK_RULE_S.search(line)
                    if mark_match:
                        uid = uid_from_forwarding_mark(int(mark_match.group(1), 0))
                        if uid is not None:
                            current.add(uid)

        for uid in sorted(uids):
            rules = self._forwarding_rules(uid)
            for table, chain, index in specs:
                args = rules[index]
                if self._rc([*prefix(table), "-C", chain, *args]) != 0:
                    self._run([*prefix(table), "-A", chain, *args])
                for _ in range(8):
                    if occurrences(table, chain, args) <= 1:
                        break
                    if self._rc([*prefix(table), "-D", chain, *args]) != 0:
                        break

        # Removing an account intentionally drops its counters; the driver's
        # tracker forgets the same account in the provisioning transaction.
        for uid in sorted(current - uids):
            rules = self._forwarding_rules(uid)
            for table, chain, index in specs:
                args = rules[index]
                for _ in range(8):
                    if self._rc([*prefix(table), "-D", chain, *args]) != 0:
                        break

    def acct_read(self) -> dict[int, int]:
        out = self._run([self._iptables(), "-L", ACCT_CHAIN,
                         "-n", "-v", "-x"])
        return parse_acct_counters(out)

    def acct_read_bidirectional(self) -> dict[int, tuple[int, int]]:
        ipt = self._iptables()
        uplink = self.acct_read()
        downlink = parse_connmark_counters(self._run(
            [ipt, "-L", ACCT_INPUT_CHAIN, "-n", "-v", "-x"]))
        return {
            uid: (uplink.get(uid, 0), downlink.get(uid, 0))
            for uid in uplink.keys() | downlink.keys()
        }

    def acct_teardown(self) -> None:
        """Remove all panel-owned hooks and chains, never unrelated rules."""
        ipt = self._iptables()
        for table, parent, chain in (
            (None, "OUTPUT", ACCT_CHAIN),
            (None, "INPUT", ACCT_INPUT_CHAIN),
            ("mangle", "OUTPUT", ACCT_MARK_CHAIN),
        ):
            prefix = [ipt] + (["-t", table] if table else [])
            try:
                self._run([*prefix, "-D", parent, "-j", chain], check=False)
                self._run([*prefix, "-F", chain], check=False)
                self._run([*prefix, "-X", chain], check=False)
            except CoreError:
                logger.debug("ssh acct teardown skipped for %s", chain)

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

        StrictModes-compliant and immutable by the tunnel user: the directory
        and file stay root-owned and non-writable, while mode 0644 is required
        because current OpenSSH temporarily adopts the target UID before
        opening an absolute AuthorizedKeysFile. Root:root 0600 made every
        valid key fail with EACCES.
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
        os.chmod(tmp, 0o644)
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

    def version(self) -> str | None:
        binary = self._sshd_bin()
        if binary is None:
            return None
        try:
            proc = subprocess.run(
                [binary, "-V"], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        output = (proc.stdout or "") + (proc.stderr or "")
        match = re.search(r"OpenSSH_([^,\s]+)", output)
        return match.group(1) if match else None

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
