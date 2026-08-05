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
        },
        homepage="https://openvpn.net/community/",
        provides=set(),
        requires=set(),
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
    # config rendering
    # ------------------------------------------------------------------ #
    def render_server_conf(self, hook_path: str) -> str:
        s = self.settings
        pushes = []
        if s["redirect_gateway"]:
            pushes.append('push "redirect-gateway def1 bypass-dhcp"')
        pushes += [f'push "dhcp-option DNS {dns}"' for dns in s["dns_servers"]]
        return "\n".join([
            f"port {s['port']}",
            f"proto {s['proto']}",
            "dev tun",
            "topology subnet",
            f"server {s['subnet']} {s['netmask']}",
            "ifconfig-pool-persist ipp.txt",
            "ca ca.crt", "cert server.crt", "key server.key",
            "dh none",
            "tls-crypt ta.key",
            "data-ciphers AES-256-GCM:AES-128-GCM",
            "data-ciphers-fallback AES-128-GCM",
            "tls-version-min 1.2",
            f"management {self._mgmt_addr()}",
            "management-client-auth",
            "client-cert-not-required",
            "username-as-common-name",
            f"client-disconnect {hook_path}",
            *pushes,
            "keepalive 10 60",
            "persist-key", "persist-tun",
            "verb 3",
            "",
        ])

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
            "data-ciphers AES-256-GCM:AES-128-GCM",
            "data-ciphers-fallback AES-128-GCM",
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
                    fields=[
                        DeliveryField(key="username", label="Username",
                                      value=account.account_id),
                        DeliveryField(key="password", label="Password",
                                      value=str(account.settings["password"]), secret=True),
                    ],
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
