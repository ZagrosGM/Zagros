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

    def configure(self, specs: list[dict[str, Any]]) -> None:
        """Materialize the whole listener set: one server.conf + accounting
        hook per tag (multi-inbound, alpha.7.2)."""
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


class _Listener:
    """One openvpn process bound to one tag: own config, own management
    channel, own accounting hook/log (multi-inbound, alpha.7.2)."""

    __slots__ = ("tag", "directory", "config_path", "disconnect_log",
                 "hook_path", "network_hook_path", "mgmt_port", "proc", "mgmt")

    def __init__(self, tag: str, directory: str, mgmt_port: int, executable: str):
        self.tag = tag
        self.directory = directory
        self.config_path = os.path.join(directory, "server.conf")
        self.disconnect_log = os.path.join(directory, "disconnect-log.jsonl")
        self.hook_path = os.path.join(directory, "client-disconnect.sh")
        self.network_hook_path = os.path.join(directory, "network-hook.sh")
        self.mgmt_port = mgmt_port
        self.proc = ManagedProcess(
            [executable, "--config", self.config_path],
            cwd=directory,
        )
        self.mgmt: ManagementClient | None = None


class LocalOpenVPNBackend:
    """Production backend for the OpenVPN driver.

    Multi-inbound (alpha.7.2): the class manages a SET of listeners keyed
    by tag — one openvpn process each (the protocol itself is one listener
    per process; several ports ⇒ several processes, exactly how distros
    run openvpn@server1/openvpn@server2). PKI (CA / server cert / tls-crypt
    key) stays core-wide in work_dir and is shared by every listener."""

    def __init__(self, settings: dict[str, Any]):
        self.executable = settings.get("executable_path", "openvpn")
        self.work_dir = settings.get("work_dir", "/var/lib/zagros/cores/openvpn")
        self.mgmt_host = "127.0.0.1"
        self._base_mgmt_port = int(settings.get("management_port", 17505))
        os.makedirs(self.work_dir, exist_ok=True)
        self._listeners: dict[str, _Listener] = {}
        self._order: list[str] = []
        # Stored before any listener opens. Auto-reconnecting clients can send
        # >CLIENT:CONNECT immediately after the UDP/TCP socket binds; attaching
        # auth only after start created a real no-response window and left the
        # client stuck forever at PUSH_REQUEST.
        self._auth_handler: AuthCallback | None = None

    # ------------------------------------------------------------------ #
    # listener-set materialization                                        #
    # ------------------------------------------------------------------ #
    def disconnect_log_path(self, tag: str) -> str:
        return os.path.join(self.work_dir, "listeners", tag, "disconnect-log.jsonl")

    @staticmethod
    def _write_atomic(path: str, content: str, mode: int | None = None) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)

    def configure(self, specs: list[dict[str, Any]]) -> None:
        """Materialize the whole listener set (xray-style): write each
        listener's server.conf + accounting hook, create process handles
        for new tags, and STOP+drop listeners that left the set. Processes
        are NOT (re)started here — the driver decides via start/restart."""
        wanted = {str(spec["tag"]) for spec in specs}
        for tag in list(self._order):
            if tag not in wanted:
                self._stop_listener(self._listeners.pop(tag))
                self._order.remove(tag)
        for spec in specs:
            tag = str(spec["tag"])
            directory = os.path.dirname(self.disconnect_log_path(tag))
            listener = self._listeners.get(tag)
            if listener is None:
                listener = _Listener(tag, directory,
                                     int(spec["mgmt_port"]), self.executable)
                self._listeners[tag] = listener
            else:
                listener.mgmt_port = int(spec["mgmt_port"])
            self._write_atomic(listener.config_path, str(spec["server_conf"]))
            self._write_atomic(listener.hook_path, str(spec["hook_script"]),
                               mode=0o755)
            self._write_atomic(listener.network_hook_path,
                               str(spec.get("network_hook_script") or "#!/bin/sh\nexit 0\n"),
                               mode=0o755)
        # preserve the tag order of the spec list
        self._order = [str(s["tag"]) for s in specs]

    # ------------------------------------------------------------------ #
    # process
    # ------------------------------------------------------------------ #
    @staticmethod
    def _in_container() -> bool:
        return (os.path.exists("/.dockerenv")
                or os.path.exists("/run/.containerenv")
                or bool(os.environ.get("container")))

    def _needs_forwarding(self) -> bool:
        for listener in self._listeners.values():
            try:
                with open(listener.config_path, encoding="utf-8") as fh:
                    if "redirect-gateway" in fh.read():
                        return True
            except OSError:
                continue
        return False

    def _ensure_forwarding(self) -> None:
        if not self._needs_forwarding():
            return
        try:
            with open("/proc/sys/net/ipv4/ip_forward", encoding="ascii") as fh:
                if fh.read().strip() == "1":
                    return
        except OSError as exc:
            raise CoreError(f"cannot verify net.ipv4.ip_forward: {exc}") from exc
        guidance = ("enable net.ipv4.ip_forward=1 on the Docker HOST and persist "
                    "it in /etc/sysctl.d/99-zagros-forwarding.conf")
        if self._in_container():
            raise CoreError(f"OpenVPN full-tunnel routing requires IPv4 forwarding; {guidance}")
        sysctl = shutil.which("sysctl")
        if sysctl is None:
            raise CoreError(f"OpenVPN full-tunnel routing requires IPv4 forwarding; {guidance}")
        self._run([sysctl, "-w", "net.ipv4.ip_forward=1"])

    def preflight_start(self) -> None:
        """Root-cause readiness before any launch attempt. The field failure
        was a bare 'cannot reach openvpn management interface: Connection
        refused' — which hid whichever of these actually died first.

        Network-stack readiness is a STRUCTURED diagnosis (alpha.7.2):
        TUN device, CAP_NET_ADMIN, kernel module, container context — each
        failed check ships its own host-specific fix, not a bare error."""
        if shutil.which(self.executable) is None and not os.path.exists(self.executable):
            # self-heal on Start (same contract as xray/sing-box): install,
            # then RE-verify — a failed package install must surface here,
            # not as a bogus management-interface error later.
            self.install_packages()
            if shutil.which(self.executable) is None and not os.path.exists(self.executable):
                raise CoreError(
                    f"'{self.executable}' is still missing right after the "
                    f"package install step — read the package-manager output "
                    f"in the core logs."
                )
        missing_network_tools = [tool for tool in ("ip", "iptables")
                                 if shutil.which(tool) is None]
        if missing_network_tools and self._needs_forwarding():
            raise CoreError(
                "OpenVPN full-tunnel NAT needs host tools: "
                + ", ".join(missing_network_tools)
                + " (install iproute2 and iptables)."
            )
        self._ensure_forwarding()

        from app.cores.netdiag import diagnose_tun, format_guidance, tun_device_state

        checks = diagnose_tun("OpenVPN")
        if any(not check.ok for check in checks):
            state = tun_device_state()
            if state == "missing":
                header = ("/dev/net/tun is missing on this host — OpenVPN "
                          "cannot create a tunnel interface without it.")
            elif state == "unreadable":
                header = ("/dev/net/tun exists but cannot be opened — a "
                          "capability or device-mapping problem.")
            else:
                header = "OpenVPN cannot start a tunnel on this host."
            raise CoreError(format_guidance(checks, header))

    def start(self) -> None:
        self.preflight_start()
        if not self._order:
            raise CoreError(
                "openvpn has no listeners configured — create an inbound "
                "in the studio (or via the wizard) before starting the core."
            )
        started: list[_Listener] = []
        try:
            for tag in self._order:
                listener = self._listeners[tag]
                try:
                    listener.proc.start()
                    self._connect_management(listener)
                except CoreError as exc:
                    raise CoreError(f"listener '{tag}': {exc}") from exc
                started.append(listener)
        except CoreError:
            # never leave a half-up listener set behind
            for listener in started:
                self._stop_listener(listener)
            raise

    def _stop_listener(self, listener: _Listener) -> None:
        if listener.mgmt is not None:
            listener.mgmt.close()
            listener.mgmt = None
        listener.proc.stop()

    def stop(self) -> None:
        for tag in self._order:
            self._stop_listener(self._listeners[tag])

    def restart(self) -> None:
        self.stop()
        self.start()

    def is_running(self) -> bool:
        return bool(self._order) and all(
            self._listeners[tag].proc.is_running for tag in self._order
        )

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
        """Aggregate process metrics across the listener set."""
        total = CoreMetrics()
        for tag in self._order:
            m = self._listeners[tag].proc.metrics()
            total.cpu_percent += m.cpu_percent
            total.memory_bytes += m.memory_bytes
            total.network_rx_bytes += m.network_rx_bytes
            total.network_tx_bytes += m.network_tx_bytes
            total.active_accounts += m.active_accounts
            total.active_sessions += m.active_sessions
        return total

    def logs(self, tail: int = 200) -> Sequence[str]:
        lines: list[str] = []
        for tag in self._order:
            lines.extend(f"[{tag}] {line}"
                         for line in self._listeners[tag].proc.logs(tail))
        return lines[-tail:] if tail else lines

    # ------------------------------------------------------------------ #
    # setup: PKI / config / hook / packages
    # ------------------------------------------------------------------ #
    def _run(self, argv: list[str], timeout: float = 120.0) -> str:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise CoreError(f"command failed {' '.join(argv[:2])}: {proc.stderr.strip()}")
        return proc.stdout

    @staticmethod
    def _server_pki_valid(cert_path: str, key_path: str, ca_path: str) -> bool:
        """The profile uses remote-cert-tls server, so a matching key alone
        is insufficient: KU digitalSignature and EKU serverAuth are required."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

            cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
            ca = x509.load_pem_x509_certificate(open(ca_path, "rb").read())
            cert.verify_directly_issued_by(ca)
            key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
            cert_pub = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            key_pub = key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            return cert_pub == key_pub and ku.digital_signature \
                and ExtendedKeyUsageOID.SERVER_AUTH in eku
        except (OSError, ValueError, x509.ExtensionNotFound):
            return False

    def ensure_pki(self) -> dict[str, str]:
        paths = {name: os.path.join(self.work_dir, name) for name in
                 ("ca.key", "ca.crt", "server.key", "server.csr", "server.crt", "ta.key")}
        if shutil.which("openssl") is None:
            raise CoreError("openssl not found on this host (install it first).")
        if not (os.path.exists(paths["ca.crt"]) and os.path.exists(paths["ca.key"])):
            ca_key, ca_crt = paths["ca.key"] + ".part", paths["ca.crt"] + ".part"
            for part in (ca_key, ca_crt):
                try: os.remove(part)
                except OSError: pass
            self._run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                       "-keyout", ca_key, "-out", ca_crt,
                       "-days", "3650", "-nodes", "-subj", "/CN=zagros-ovpn-ca"])
            os.chmod(ca_key, 0o600)
            os.replace(ca_key, paths["ca.key"])
            os.replace(ca_crt, paths["ca.crt"])

        server_exists = all(os.path.exists(paths[name])
                            for name in ("server.crt", "server.key"))
        server_valid = server_exists and self._server_pki_valid(
            paths["server.crt"], paths["server.key"], paths["ca.crt"])
        if server_exists and not server_valid:
            # Automatically migrate only Zagros' own historical certificate
            # (pre-fix certificates lacked KU/EKU). Never overwrite an
            # operator certificate silently.
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                cert = x509.load_pem_x509_certificate(open(paths["server.crt"], "rb").read())
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:  # noqa: BLE001
                cn = ""
            if cn != "zagros-ovpn-server":
                raise CoreError(
                    "OpenVPN server certificate is not usable with "
                    "remote-cert-tls server (needs matching key, keyUsage "
                    "digitalSignature and extendedKeyUsage serverAuth)."
                )

        if not server_valid:
            key_part = paths["server.key"] + ".part"
            csr_part = paths["server.csr"] + ".part"
            cert_part = paths["server.crt"] + ".part"
            ext_path = os.path.join(self.work_dir, "server-ext.cnf.part")
            for part in (key_part, csr_part, cert_part, ext_path):
                try: os.remove(part)
                except OSError: pass
            with open(ext_path, "w", encoding="utf-8") as fh:
                fh.write("[server_cert]\n"
                         "basicConstraints=critical,CA:FALSE\n"
                         "keyUsage=critical,digitalSignature,keyEncipherment\n"
                         "extendedKeyUsage=serverAuth\n"
                         "subjectAltName=DNS:zagros-ovpn-server\n")
            self._run(["openssl", "req", "-newkey", "rsa:2048",
                       "-keyout", key_part, "-out", csr_part,
                       "-nodes", "-subj", "/CN=zagros-ovpn-server"])
            self._run(["openssl", "x509", "-req", "-in", csr_part,
                       "-CA", paths["ca.crt"], "-CAkey", paths["ca.key"],
                       "-CAcreateserial", "-out", cert_part, "-days", "3650",
                       "-extfile", ext_path, "-extensions", "server_cert"])
            self._run(["openssl", "verify", "-CAfile", paths["ca.crt"], cert_part])
            os.chmod(key_part, 0o600)
            os.replace(key_part, paths["server.key"])
            os.replace(csr_part, paths["server.csr"])
            os.replace(cert_part, paths["server.crt"])
            try: os.remove(ext_path)
            except OSError: pass
            if not self._server_pki_valid(paths["server.crt"], paths["server.key"], paths["ca.crt"]):
                raise CoreError("generated OpenVPN server certificate failed KU/EKU validation")

        if not os.path.exists(paths["ta.key"]):
            part = paths["ta.key"] + ".part"
            self._run([self.executable, "--genkey", "--secret", part])
            os.chmod(part, 0o600)
            os.replace(part, paths["ta.key"])
        for private in ("ca.key", "server.key", "ta.key"):
            try:
                os.chmod(paths[private], 0o600)
            except OSError:
                pass
        with open(paths["ca.crt"], encoding="utf-8") as fh:
            ca_crt = fh.read()
        with open(paths["ta.key"], encoding="utf-8") as fh:
            tls_key = fh.read()
        return {"ca_crt": ca_crt, "tls_crypt": tls_key}

    def apply_config(self, server_conf: str) -> None:
        """Legacy single-listener shim retained for external callers; the
        studio path uses configure(). Requires exactly one configured
        listener so the target is unambiguous."""
        if len(self._order) != 1:
            raise CoreError(
                "apply_config() is single-listener only — use configure() "
                "with explicit tags on a multi-inbound core."
            )
        listener = self._listeners[self._order[0]]
        self._write_atomic(listener.config_path, server_conf)

    def install_packages(self) -> str:
        for manager, argv in (
            ("apt-get", ["apt-get", "install", "-y", "openvpn", "openssl", "iproute2", "iptables"]),
            ("dnf", ["dnf", "install", "-y", "openvpn", "openssl", "iproute", "iptables"]),
            ("yum", ["yum", "install", "-y", "openvpn", "openssl", "iproute", "iptables"]),
            ("pacman", ["pacman", "-S", "--noconfirm", "openvpn", "openssl", "iproute2", "iptables"]),
            ("apk", ["apk", "add", "openvpn", "openssl", "iproute2", "iptables"]),
        ):
            if shutil.which(manager):
                if manager == "apt-get":
                    # container images carry no apt lists: refresh first or
                    # every package reports "Unable to locate package"
                    self._run(["apt-get", "update"], timeout=600)
                return self._run(argv, timeout=600)
        raise CoreError("no supported package manager found (apt/dnf/yum/pacman/apk).")

    # ------------------------------------------------------------------ #
    # management channel (one per listener)
    # ------------------------------------------------------------------ #
    def _connect_management(self, listener: _Listener,
                            timeout: float = 15.0) -> None:
        client = ManagementClient()
        if self._auth_handler is not None:
            # Install the callback BEFORE connect starts the reader thread.
            # Otherwise an eager reconnect can complete ENV while no handler
            # exists, and OpenVPN blocks that session waiting for a verdict.
            client.set_auth_handler(self._bridge_auth_request)
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if not listener.proc.is_running:
                # openvpn DIED during boot (bad config, missing tun, port
                # clash, …): the real reason lives in its own log, not in a
                # socket error — surface it verbatim.
                tail = "\n".join(listener.proc.logs(15)) or "(no process output captured)"
                raise CoreError(
                    f"openvpn exited during startup — management interface "
                    f"never came up. Process output:\n{tail}"
                )
            try:
                client.connect(self.mgmt_host, listener.mgmt_port, timeout=3)
                listener.mgmt = client
                return
            except OSError as exc:  # core still booting
                last_error = exc
                time.sleep(0.4)
        raise CoreError(
            f"openvpn management interface did not answer within "
            f"{int(timeout)}s ({last_error}); the process is still alive — "
            f"recent output:\n" + ("\n".join(listener.proc.logs(15)) or "(none)")
        )

    def management_alive(self) -> bool:
        return bool(self._order) and all(
            self._listener_alive(self._listeners[tag]) for tag in self._order
        )

    @staticmethod
    def _listener_alive(listener: _Listener) -> bool:
        if listener.mgmt is None:
            return False
        try:
            listener.mgmt.command("pid", timeout=5)
            return True
        except CoreError:
            return False

    def command(self, cmd: str, timeout: float = 30.0, *,
                tag: str | None = None) -> str:
        listener = (self._listeners.get(tag) if tag
                    else (self._listeners[self._order[0]] if self._order else None))
        if listener is None or listener.mgmt is None:
            raise CoreError("management interface is not connected.")
        return listener.mgmt.command(cmd, timeout=timeout)

    def status_clients(self) -> list[StatusClient]:
        """Union of live sessions across every listener (one account may be
        connected to several ports at once — all are reported)."""
        clients: list[StatusClient] = []
        for tag in self._order:
            listener = self._listeners[tag]
            if listener.mgmt is None:
                continue
            clients.extend(parse_status3(listener.mgmt.command("status 3")))
        return clients

    def kill_client(self, common_name: str) -> bool:
        """Kill on every listener — the same CN may hold sessions on
        several ports simultaneously."""
        killed = False
        for tag in self._order:
            listener = self._listeners[tag]
            if listener.mgmt is None:
                continue
            try:
                out = listener.mgmt.command(f"kill {common_name}", timeout=10)
                killed = killed or out.startswith("SUCCESS:")
            except CoreError:
                continue
        return killed

    def _bridge_auth_request(self, request: AuthRequest) -> bool:
        handler = self._auth_handler
        if handler is None:
            return False
        meta = {
            "platform": request.platform,
            "client_version": request.client_version,
            "reauth": request.reauth,
            **{k: v for k, v in request.env.items()
               if k.startswith("IV_") or k in ("remote_ip", "untrusted_ip")},
        }
        return bool(handler(request.username, request.password, meta))

    def set_auth_handler(self, handler: AuthCallback) -> None:
        self._auth_handler = handler
        for tag in self._order:
            listener = self._listeners[tag]
            if listener.mgmt is not None:
                listener.mgmt.set_auth_handler(self._bridge_auth_request)

    # ------------------------------------------------------------------ #
    # accounting
    # ------------------------------------------------------------------ #
    def read_disconnect_log(self) -> list[DisconnectRecord]:
        """Union of hook finals across the whole listener set. Orphaned
        directories (listeners removed by the studio between polls) are
        drained too — usage must never silently disappear with an inbound."""
        roots = [listener.disconnect_log for listener in self._listeners.values()]
        listeners_root = os.path.join(self.work_dir, "listeners")
        try:
            for entry in os.listdir(listeners_root):
                candidate = os.path.join(listeners_root, entry, "disconnect-log.jsonl")
                if candidate not in roots and os.path.isfile(candidate):
                    roots.append(candidate)
        except OSError:
            pass
        records: list[DisconnectRecord] = []
        for path in roots:
            records.extend(self._read_one_log(path))
        return records

    @staticmethod
    def _read_one_log(path: str) -> list[DisconnectRecord]:
        if not os.path.exists(path):
            return []
        tmp = f"{path}.swap"
        try:
            os.replace(path, tmp)   # atomic-ish: new appends go to a fresh file
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
