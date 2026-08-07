"""OpenVPNDriver — OpenVPN as a first-class panel core.

Real capabilities used (no pretend features):
  * **Live user management** via ``--management-client-auth``: the panel answers
    every handshake on the management channel → add/edit/delete/suspend take
    effect *without a restart*. ``--username-as-common-name`` makes the
    username the CN, so ``kill <cn>`` ties sessions to accounts.
  * **Accounting**: authoritative per-session finals from the
    ``client-disconnect`` hook (env ``bytes_received/bytes_sent``), merged with
    interim deltas from ``status 3`` through the shared
    :class:`SessionUsageTracker` — interim and final never double-counted.
  * **Online + device detection**: ``status 3`` rows + handshake env
    (``IV_PLAT``/``IV_VER``).
  * Honestly NOT claimed: ROUTING (per-user rules don't exist server-side),
    HOT_RELOAD (SIGUSR1 reloads, not rule-level), PROCESS/GEO routing.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.exceptions import CoreError
from app.cores.stats import SessionUsageTracker
from app.cores.types import (
    Capability,
    ClientConfig,
    CoreMetadata,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    UsageRecord,
    UserAccount,
)

_DISCONNECT_HOOK = """#!/bin/sh
# zagros openvpn accounting hook -- authoritative per-session final counters.
printf '%s\\n' "{{\\"cn\\":\\"$common_name\\",\\"bytes_received\\":$bytes_received,\\"bytes_sent\\":$bytes_sent,\\"duration\\":$time_duration,\\"ts\\":$(date +%s)}}" >> "{log_path}"
"""


class OpenVPNDriver(BaseCoreDriver):
    """Driver for OpenVPN community server (management-interface managed)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="openvpn",
        name="OpenVPN",
        description=(
            "OpenVPN community server. Live user auth via management-client-auth, "
            "authoritative usage via client-disconnect hook + status, online "
            "sessions and device detection (IV_PLAT/IV_VER)."
        ),
        protocols=["ovpn"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.DEVICE_DETECTION,
            Capability.SERVICE_CONTROL,
            Capability.CLIENT_CONFIG,
            Capability.UDP_SUPPORT,
            Capability.SELF_INSTALL,
        },
        config_schema={
            "type": "object",
            "properties": {
                "executable_path": {"type": "string"},
                "work_dir": {"type": "string"},
                "listen": {"type": "string", "default": "0.0.0.0"},
                "port": {"type": "integer", "default": 1194},
                "proto": {"type": "string", "enum": ["udp", "tcp"]},
                "subnet": {"type": "string", "default": "10.8.0.0"},
                "netmask": {"type": "string", "default": "255.255.255.0"},
                "management_port": {"type": "integer", "default": 17505},
                "redirect_gateway": {"type": "boolean", "default": True},
                "dns_servers": {"type": "array", "items": {"type": "string"}},
                "advertise_host": {"type": "string"},
                "topology": {"type": "string", "enum": ["subnet", "net30", "p2p"],
                             "default": "subnet"},
                "cipher": {"type": "string", "default": "AES-256-GCM"},
                "cipher_fallback": {"type": "string", "default": "AES-128-GCM"},
                "auth_digest": {"type": "string",
                                "description": "HMAC digest directive (blank = omit — "
                                               "AEAD ciphers ignore --auth)"},
                "compression": {"type": "string",
                                "enum": ["", "lz4-v2", "lzo"], "default": ""},
                "auth_mode": {"type": "string",
                              "enum": ["management", "static"], "default": "management",
                              "description": "management = per-user panel credentials "
                                             "via management-client-auth; static = one "
                                             "shared username/password "
                                             "(auth-user-pass-verify)"},
                "static_user": {"type": "string"},
                "static_pass": {"type": "string"},
                "extra_directives": {"type": "string",
                                     "description": "raw server.conf lines appended "
                                                    "(operator escape hatch, e.g. "
                                                    "'max-clients 512')"},
            },
        },
        default_settings={
            "executable_path": "openvpn",
            "work_dir": "/var/lib/zagros/cores/openvpn",
            "listen": "0.0.0.0",
            "port": 1194,
            "proto": "udp",
            "subnet": "10.8.0.0",
            "netmask": "255.255.255.0",
            "management_port": 17505,
            "redirect_gateway": True,
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
            "advertise_host": "127.0.0.1",
            "topology": "subnet",
            "cipher": "AES-256-GCM",
            "cipher_fallback": "AES-128-GCM",
            "auth_digest": "",
            "compression": "",
            "auth_mode": "management",
            "static_user": "",
            "static_pass": "",
            "extra_directives": "",
        },
        homepage="https://openvpn.net/community/",
        provides=set(),
        requires=set(),
        # ONE server listener set per core — studio manages it as a
        # single-entry inbound (apply re-renders server.conf + restarts).
        studio_inbounds_path="/inbounds",
        studio_max_inbounds=1,
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.openvpn.backend import LocalOpenVPNBackend

            backend = LocalOpenVPNBackend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._device_meta: dict[str, dict[str, Any]] = {}
        self._usage = SessionUsageTracker()
        self._pki: dict[str, str] | None = None

    # ------------------------------------------------------------------ #
    # Config Studio bridge (single-listener engine; apply re-renders
    # server.conf, restarts when running, same validated path as Start)
    # ------------------------------------------------------------------ #
    def export_config_document(self) -> dict[str, Any]:
        """Studio seed: the openvpn listener modelled as a one-entry inbound
        (pure settings read; secrets never exported — wizard write-only)."""
        s = self.settings
        return {
            "inbounds": [{
                "tag": "openvpn",
                "protocol": "ovpn",
                "listen": s.get("listen") or "0.0.0.0",
                "port": int(s.get("port") or 1194),
                "transport": s.get("proto") or "udp",
                "topology": s.get("topology") or "subnet",
                "cipher": s.get("cipher") or "AES-256-GCM",
                "auth": s.get("auth_digest") or "",
                "compression": s.get("compression") or "",
                "auth_mode": s.get("auth_mode") or "management",
                "username": "",
                "password": "",
                "redirect_gateway": bool(s.get("redirect_gateway", True)),
                "dns": ", ".join(str(d) for d in (s.get("dns_servers") or [])),
                "has_static_credentials": bool(s.get("static_user")),
                "has_ca_certificate": bool(s.get("ca_crt_text")),
            }],
        }

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        inbounds = (document or {}).get("inbounds") or []
        if len(inbounds) != 1:
            raise CoreError(
                f"openvpn serves exactly ONE listener set; the studio document "
                f"carries {len(inbounds)} inbounds — keep exactly one."
            )
        ib = inbounds[0]
        if str(ib.get("protocol") or "ovpn") not in ("ovpn", "openvpn"):
            raise CoreError(f"an openvpn core cannot host a '{ib.get('protocol')}' listener.")
        s = self.settings
        if ib.get("port") is not None:
            port = int(ib["port"])
            if not 1 <= port <= 65535:
                raise CoreError(f"openvpn port out of range: {port}")
            s["port"] = port
        if ib.get("listen"):
            s["listen"] = str(ib["listen"])
        transport = str(ib.get("transport") or ib.get("proto") or "").lower()
        if transport in ("udp", "tcp"):
            s["proto"] = transport
        elif transport:
            raise CoreError(f"openvpn serves udp or tcp, not '{transport}'.")
        if ib.get("topology"):
            topology = str(ib["topology"])
            if topology not in ("subnet", "net30", "p2p"):
                raise CoreError(f"unknown openvpn topology '{topology}' "
                                "(subnet / net30 / p2p).")
            s["topology"] = topology
        if ib.get("cipher"):
            s["cipher"] = str(ib["cipher"])
        if ib.get("cipher_fallback"):
            s["cipher_fallback"] = str(ib["cipher_fallback"])
        if ib.get("auth") is not None:
            s["auth_digest"] = str(ib["auth"])
        if ib.get("compression") is not None:
            compression = str(ib["compression"])
            if compression not in ("", "lz4-v2", "lzo"):
                raise CoreError(f"unknown openvpn compression '{compression}'.")
            s["compression"] = compression
        if ib.get("dns") is not None:
            s["dns_servers"] = [d.strip() for d in str(ib["dns"]).split(",") if d.strip()]
        if ib.get("redirect_gateway") is not None:
            s["redirect_gateway"] = bool(ib["redirect_gateway"])
        auth_mode = str(ib.get("auth_mode") or "").lower()
        if auth_mode in ("management", "static"):
            s["auth_mode"] = auth_mode
        if ib.get("username"):
            s["static_user"] = str(ib["username"])
        if ib.get("password"):
            s["static_pass"] = str(ib["password"])
        if s.get("auth_mode") == "static":
            # validated eagerly — a shared-cred server without the creds is
            # a brick (the install raises with a clear message)
            self._install_static_auth()
        if str(ib.get("extra_directives") or ""):
            s["extra_directives"] = str(ib["extra_directives"])
        # PKI uploads (CA / server cert / server key — operator-owned chains
        # replace the panel-generated PKI); private key never in the export
        self._materialize_uploaded_pki(
            ca_pem=ib.get("ca_certificate") or ib.get("ca"),
            cert_pem=ib.get("certificate"),
            key_pem=ib.get("certificate_key"),
        )
        await self._publish()

    def _materialize_uploaded_pki(self, *, ca_pem: Any, cert_pem: Any,
                                  key_pem: Any) -> None:
        """Write operator-uploaded PEMs into the work_dir PKI (validated as a
        MATCHING cert/key pair; idempotent — unchanged files are not
        rewritten, so no needless restart ripple)."""
        import os
        if not (ca_pem or cert_pem or key_pem):
            return
        if bool(cert_pem) != bool(key_pem):
            raise CoreError(
                "upload the server certificate AND private key together."
            )
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        work_dir = str(self.settings.get("work_dir") or ".")
        os.makedirs(work_dir, exist_ok=True)
        if cert_pem:
            try:
                cert_obj = x509.load_pem_x509_certificate(str(cert_pem).encode())
                key_obj = serialization.load_pem_private_key(
                    str(key_pem).encode(), password=None
                )
            except ValueError as exc:
                raise CoreError(f"uploaded certificate/key is not valid PEM: {exc}") from exc
            if (cert_obj.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                    != key_obj.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo)):
                raise CoreError(
                    "uploaded certificate does NOT match the uploaded private key."
                )
            for name, text in (("server.crt", str(cert_pem)), ("server.key", str(key_pem))):
                self._write_if_changed(os.path.join(work_dir, name), text,
                                       0o600 if name.endswith(".key") else 0o644)
        if ca_pem:
            try:
                x509.load_pem_x509_certificate(str(ca_pem).encode())
            except ValueError as exc:
                raise CoreError(f"uploaded CA certificate is not valid PEM: {exc}") from exc
            self._write_if_changed(os.path.join(work_dir, "ca.crt"), str(ca_pem), 0o644)
        self._pki = None  # force ensure_pki/client-profile re-read

    @staticmethod
    def _write_if_changed(path: str, text: str, mode: int) -> None:
        import os
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                if fh.read() == text:
                    return
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)

    async def _publish(self) -> None:
        """Re-render server.conf into the backend; restart when running."""
        running = await asyncio.to_thread(self._backend.is_running)
        if not running:
            return  # stopped core: settings land on next start()
        log_path = getattr(self._backend, "disconnect_log", "disconnect-log.jsonl")
        hook_path = await asyncio.to_thread(
            self._backend.install_hook_script, self._render_hook(log_path)
        )
        await asyncio.to_thread(
            self._backend.apply_config, self.render_server_conf(hook_path)
        )
        await asyncio.to_thread(self._backend.restart)

    # ------------------------------------------------------------------ #
    # config rendering
    # ------------------------------------------------------------------ #
    def render_server_conf(self, hook_path: str) -> str:
        s = self.settings
        pushes = []
        if s["redirect_gateway"]:
            pushes.append('push "redirect-gateway def1 bypass-dhcp"')
        pushes += [f'push "dhcp-option DNS {dns}"' for dns in s["dns_servers"]]
        cipher = str(s.get("cipher") or "AES-256-GCM")
        fallback = str(s.get("cipher_fallback") or "AES-128-GCM")
        lines = [
            f"port {s['port']}",
            f"proto {s['proto']}",
            "dev tun",
            f"topology {s.get('topology') or 'subnet'}",
            f"server {s['subnet']} {s['netmask']}",
            "ifconfig-pool-persist ipp.txt",
            "ca ca.crt", "cert server.crt", "key server.key",
            "dh none",
            "tls-crypt ta.key",
            f"data-ciphers {cipher}:{fallback}",
            f"data-ciphers-fallback {fallback}",
            "tls-version-min 1.2",
            f"management {self._mgmt_addr()}",
        ]
        if str(s.get("auth_digest") or ""):
            lines.append(f"auth {s['auth_digest']}")
        compression = str(s.get("compression") or "")
        if compression:
            lines += ["allow-compression yes", f"compress {compression}",
                      f'push "compress {compression}"']
        if str(s.get("auth_mode") or "management") == "static":
            # one shared username/password, verified by a root-owned script:
            # real auth-user-pass-verify (via-env), management interface stays
            # for status/usage but NOT for auth
            lines += [
                f"auth-user-pass-verify {self._static_auth_script_path()} via-env",
            ]
        else:
            lines += [
                "management-client-auth",
                "client-cert-not-required",
                "username-as-common-name",
            ]
        lines += [
            f"client-disconnect {hook_path}",
            *pushes,
            "keepalive 10 60",
            "persist-key", "persist-tun",
            "verb 3",
        ]
        extra = str(s.get("extra_directives") or "").strip()
        if extra:
            lines.append("# operator extra directives (studio)")
            lines += [ln.rstrip() for ln in extra.splitlines() if ln.strip()]
        lines.append("")
        return "\n".join(lines)

    def _static_auth_script_path(self) -> str:
        import os
        return os.path.join(str(self.settings.get("work_dir") or "."),
                            "zagros-static-auth.sh")

    _STATIC_AUTH_SCRIPT = """#!/bin/sh
# zagros openvpn static auth — auth-user-pass-verify (via-env).
# Credentials live root-only 0600 next to this script; the daemon compares.
set -eu
creds="$(cat "$(dirname "$0")/.ovpn-static-auth")" || exit 1
want_user="${creds%%:*}"
want_pass="${creds#*:}"
[ "${username:-}" = "$want_user" ] && [ "${password:-}" = "$want_pass" ]
"""

    def _install_static_auth(self) -> None:
        """Root-owned verify script + 0600 credential file for static mode."""
        import os
        s = self.settings
        work_dir = str(s.get("work_dir") or ".")
        os.makedirs(work_dir, exist_ok=True)
        user, password = str(s.get("static_user") or ""), str(s.get("static_pass") or "")
        if not user or not password:
            raise CoreError(
                "openvpn static auth_mode needs username AND password "
                "(the wizard's Static Authentication section)."
            )
        if ":" in user or "\n" in user or "\n" in password:
            raise CoreError("static openvpn credentials may not contain ':' or newlines.")
        script = self._static_auth_script_path()
        with open(script + ".tmp", "w", encoding="utf-8") as fh:
            fh.write(self._STATIC_AUTH_SCRIPT)
        os.chmod(script + ".tmp", 0o700)
        os.replace(script + ".tmp", script)
        creds = os.path.join(work_dir, ".ovpn-static-auth")
        with open(creds + ".tmp", "w", encoding="utf-8") as fh:
            fh.write(f"{user}:{password}")
        os.chmod(creds + ".tmp", 0o600)
        os.replace(creds + ".tmp", creds)

    def _mgmt_addr(self) -> str:
        return f"127.0.0.1 {self.settings['management_port']}"

    def _render_hook(self, log_path: str) -> str:
        return _DISCONNECT_HOOK.format(log_path=log_path)

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        log_path = getattr(self._backend, "disconnect_log", "disconnect-log.jsonl")
        hook_path = await asyncio.to_thread(
            self._backend.install_hook_script, self._render_hook(log_path)
        )
        self._pki = await asyncio.to_thread(self._backend.ensure_pki)
        if str(self.settings.get("auth_mode") or "management") == "static":
            await asyncio.to_thread(self._install_static_auth)
        await asyncio.to_thread(self._backend.apply_config, self.render_server_conf(hook_path))
        await asyncio.to_thread(self._backend.start)
        await asyncio.to_thread(self._backend.set_auth_handler, self._authorize)

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def restart(self) -> None:
        await asyncio.to_thread(self._backend.restart)
        await asyncio.to_thread(self._backend.set_auth_handler, self._authorize)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        health = HealthStatus.UNKNOWN
        version: str | None = None
        metrics = None
        if running:
            version = await asyncio.to_thread(self._backend.version)
            metrics = await asyncio.to_thread(self._backend.metrics)
            alive = await asyncio.to_thread(self._backend.management_alive)
            health = HealthStatus.HEALTHY if alive else HealthStatus.DEGRADED
        return CoreStatus(
            core_id=self.metadata.id, state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=health, core_version=version, metrics=metrics,
        )

    async def health_check(self) -> CoreStatus:
        return await self.status()

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def install(self) -> None:
        await asyncio.to_thread(self._backend.install_packages)

    async def uninstall(self, purge: bool = False) -> None:
        await asyncio.to_thread(self._backend.stop)

    # ------------------------------------------------------------------ #
    # live authentication (management-client-auth)
    # ------------------------------------------------------------------ #
    def _authorize(self, username: str, password: str, meta: dict[str, Any]) -> bool:
        account = self._accounts.get(username)
        allowed = bool(
            account and account.enabled
            and account.settings.get("password") == password
        )
        if allowed:
            self._device_meta[username] = {
                "platform": meta.get("platform"),
                "app_version": meta.get("client_version"),
                "seen_at": datetime.now(timezone.utc).isoformat(),
            }
        return allowed

    # ------------------------------------------------------------------ #
    # user management
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol != "ovpn":
            raise CoreError(f"OpenVPN core only serves protocol 'ovpn', got '{protocol}'.")

    def _ensure_credentials(self, account: UserAccount) -> None:
        # static auth_mode authenticates EVERY client with the shared pair;
        # a per-user password is only mandatory in management auth mode
        if str(self.settings.get("auth_mode") or "management") == "static":
            return
        if not account.settings.get("password"):
            raise CoreError(f"OpenVPN account '{account.account_id}' needs settings.password.")

    async def _kill_if_connected(self, account_id: str) -> None:
        try:
            await asyncio.to_thread(self._backend.kill_client, account_id)
        except CoreError:
            pass  # mgmt down or never connected — desired state already updated

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        self._accounts[account.account_id] = account
        if not account.enabled:
            await self._kill_if_connected(account.account_id)

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        previous = self._accounts.get(account.account_id)
        self._accounts[account.account_id] = account
        password_changed = bool(
            previous
            and previous.settings.get("password") != account.settings.get("password")
        )
        if password_changed or not account.enabled:
            await self._kill_if_connected(account.account_id)  # force re-auth

    async def delete_account(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)
        self._device_meta.pop(account_id, None)
        await self._kill_if_connected(account_id)

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await self._kill_if_connected(account_id)

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        self._accounts = {a.account_id: a for a in accounts if a.protocol == "ovpn"}
        live = {a.account_id for a in self._accounts.values() if a.enabled}
        try:
            for client in await asyncio.to_thread(self._backend.status_clients):
                if client.common_name not in live:
                    await asyncio.to_thread(self._backend.kill_client, client.common_name)
        except CoreError:
            pass  # core down — next boot reconciles anyway

    # ------------------------------------------------------------------ #
    # statistics: hook finals (authoritative) + status deltas (interim)
    # ------------------------------------------------------------------ #
    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        records: list[UsageRecord] = []

        def _wanted(cn: str) -> bool:
            return account_ids is None or cn in account_ids

        # 1) authoritative finals first (ordering matters: close sessions)
        finals = await asyncio.to_thread(self._backend.read_disconnect_log)
        for final in finals:
            if not _wanted(final.common_name):
                continue
            up, down = self._usage.close(
                (final.common_name, "*"), final.bytes_received, final.bytes_sent
            )
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=final.common_name,
                uplink_bytes=up, downlink_bytes=down,
            ))

        # 2) interim deltas of still-connected sessions
        try:
            clients = await asyncio.to_thread(self._backend.status_clients)
        except CoreError:
            clients = []
        sessions = await self._session_keys(clients)
        for client in clients:
            if not _wanted(client.common_name):
                continue
            up, down = self._usage.poll(
                sessions[client.session_key], client.bytes_received, client.bytes_sent
            )
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=client.common_name,
                uplink_bytes=up, downlink_bytes=down,
            ))
        return records

    async def _session_keys(self, clients: list[Any]) -> dict[tuple[str, str, str], tuple[str, str]]:
        """Map precise session keys ((cn, since, ip)) to the tracker key.

        ``SessionUsageTracker`` is keyed per (cn, "*") so a disconnect final
        closes the session regardless of which precise key the interim used;
        the newest poll wins the tracker quote. Documented in docs §13.3.
        """
        return {client.session_key: (client.common_name, "*") for client in clients}

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        sessions: list[DeviceSession] = []
        for client in await asyncio.to_thread(self._backend.status_clients):
            if account_ids is not None and client.common_name not in account_ids:
                continue
            meta = self._device_meta.get(client.common_name, {})
            sessions.append(DeviceSession(
                core_id=self.metadata.id,
                account_id=client.common_name,
                ip=client.real_ip or None,
                connected_at=self._parse_started(client.connected_since),
                metadata={
                    "virtual_ip": client.virtual_address,
                    "platform": meta.get("platform"),
                    "app_version": meta.get("app_version"),
                    "cipher": client.cipher,
                    "real_port": client.real_port,
                },
            ))
        return sessions

    @staticmethod
    def _parse_started(value: str) -> Any:
        if not value:
            return None
        try:
            from datetime import datetime

            return datetime.strptime(value, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only)
    # ------------------------------------------------------------------ #
    def render_client_profile(self, account: UserAccount) -> str:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        if self._pki is None:
            raise CoreError("PKI not initialized yet — start the core first.")
        s = self.settings
        return "\n".join([
            "client",
            "dev tun",
            f"proto {s['proto']}",
            f"remote {s['advertise_host']} {s['port']}",
            "resolv-retry infinite",
            "nobind",
            "persist-key", "persist-tun",
            "remote-cert-tls server",
            "auth-user-pass",
            f"data-ciphers {s.get('cipher') or 'AES-256-GCM'}:"
            f"{s.get('cipher_fallback') or 'AES-128-GCM'}",
            f"data-ciphers-fallback {s.get('cipher_fallback') or 'AES-128-GCM'}",
            *([f"compress {s['compression']}"] if str(s.get("compression") or "") else []),
            "verb 3",
            "<ca>", self._pki["ca_crt"].strip(), "</ca>",
            "<tls-crypt>", self._pki["tls_crypt"].strip(), "</tls-crypt>",
            "",
        ])

    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        """OpenVPN delivery: downloadable .ovpn profile + auth credentials."""
        from app.cores.delivery import (
            ArtifactKind,
            DeliveryArtifact,
            DeliveryField,
            DeliveryProfile,
            DeliverySection,
        )

        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        config = await self.build_client_config(account, node=None)
        section = DeliverySection(
            protocol="ovpn",
            title=f"{self.metadata.name} · OpenVPN",
            engine="openvpn",
            artifacts=[
                DeliveryArtifact(
                    kind=ArtifactKind.FILE,
                    label="OpenVPN profile",
                    content=str(config.payload["profile"]),
                    filename=f"{account.username}.ovpn",
                    mime="application/x-openvpn-profile",
                ),
                DeliveryArtifact(
                    kind=ArtifactKind.FIELDS,
                    label="Authentication",
                    fields=(
                        [
                            DeliveryField(key="username", label="Username (shared)",
                                          value=str(self.settings.get("static_user") or "")),
                            DeliveryField(key="password", label="Password (shared)",
                                          value=str(self.settings.get("static_pass") or ""),
                                          secret=True),
                        ]
                        if str(self.settings.get("auth_mode") or "management") == "static"
                        else [
                            DeliveryField(key="username", label="Username",
                                          value=account.account_id),
                            DeliveryField(key="password", label="Password",
                                          value=str(account.settings["password"]),
                                          secret=True),
                        ]
                    ),
                ),
                DeliveryArtifact(
                    kind=ArtifactKind.NOTE,
                    label="How to connect",
                    note="Import the .ovpn profile into any OpenVPN client and "
                         "enter the username/password when prompted.",
                ),
            ],
        )
        return DeliveryProfile(core_id=self.metadata.id, sections=[section])

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        profile = self.render_client_profile(account)
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="ovpn",
            engine="openvpn",
            payload={"format": "ovpn", "profile": profile, "auth": "user-pass"},
            display_name="OpenVPN",
        )
