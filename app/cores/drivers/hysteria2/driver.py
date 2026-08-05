"""Hysteria2Driver — Hysteria 2 (QUIC) as a first-class panel core.

Real capabilities used (verified against the official docs):
  * **User management** via ``auth: userpass`` in the server config; changes
    are published and the server restarted (hysteria has no hot-reload — being
    stateless QUIC, restarts are sub-second). Honest: HOT_RELOAD is NOT claimed.
  * **Usage accounting** via the Traffic Stats API ``GET /traffic``
    (cumulative per-user counters; tx = client upload, rx = client download
    per the official docs) → DeltaTracker deltas.
  * **Online + device count** via ``GET /online`` (officially: number of
    Hysteria client *instances* per user — the closest thing to a device
    count the protocol exposes).
  * **Instant kick** (suspend/delete) via ``POST /kick`` + config removal.
  * **Chain ingress**: other cores (sing-box) tunnel INTO this server with
    their native hysteria2 outbound; a dedicated chain user is provisioned.
  * **TLS**: panel-generated self-signed ECDSA cert by default (clients use
    ``insecure``+SNI pin); admin-supplied certs supported via settings.
  * **Self-install** from GitHub releases (raw binary assets).

Honestly NOT claimed (documented):
  * SPEED_LIMIT per-user — possible upstream only via an HTTP-auth callback
    endpoint (the panel's API layer will expose one in P5; the driver stays
    honest about not having it today). Server-wide bandwidth hints are
    configurable via settings.
  * ROUTING / OUTBOUND_MANAGEMENT — hysteria is a point-to-point tunnel with
    no routing table to program.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.drivers.hysteria2.hycfg import (
    Hy2User,
    render_client_share,
    render_server_yaml,
)
from app.cores.exceptions import CoreError
from app.cores.stats import DeltaTracker
from app.cores.types import (
    Capability,
    ChainEndpoint,
    ClientConfig,
    CoreMetadata,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    UsageRecord,
    UserAccount,
)


_HY2_UNSAFE = __import__("re").compile(r"[^A-Za-z0-9_-]")


def _hy2_name(account_id: str) -> str:
    """Map a panel account id to the hysteria-side username.

    hysteria's config decoder expands `.` inside map keys as a nested key
    path — verified against the real binary: ``userpass: {1.e2e: pw}``
    FATALs with ``expected type 'string', got map``. Panels with numeric
    prefixes ("1.alice") are exactly the conventional Marzban-style ids, so
    the driver sanitizes deterministically (and checks collisions at
    render time, never silently merging two accounts).
    """
    return _HY2_UNSAFE.sub("_", account_id)


class Hysteria2Driver(BaseCoreDriver):
    """Driver for hysteria 2.x (apernet/hysteria)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="hysteria2",
        name="Hysteria 2",
        description=(
            "Hysteria 2 QUIC tunnel. userpass auth (config-render + restart), "
            "official traffic stats API (/traffic, /online, /kick), real "
            "hysteria2 chain ingress for sing-box outbounds."
        ),
        protocols=["hysteria2"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.SERVICE_CONTROL,
            Capability.SELF_INSTALL,
            Capability.CLIENT_CONFIG,
            Capability.UDP_SUPPORT,
            Capability.CHAIN_ROUTING,
        },
        config_schema={
            "type": "object",
            "properties": {
                "executable_path": {"type": "string"},
                "work_dir": {"type": "string"},
                "listen": {"type": "string", "default": "::"},
                "port": {"type": "integer", "default": 443},
                "masquerade_url": {"type": "string"},
                "traffic_listen": {"type": "string", "default": "127.0.0.1:19999"},
                "traffic_secret": {"type": "string"},
                "cert_path": {"type": "string"},
                "key_path": {"type": "string"},
                "advertise_host": {"type": "string"},
                "advertise_sni": {"type": "string"},
                "cert_common_name": {"type": "string", "default": "updates.microsoft.com"},
                "bandwidth_up": {"type": "string"},
                "bandwidth_down": {"type": "string"},
                "obfs_password": {"type": "string"},
            },
        },
        default_settings={
            "executable_path": "hysteria",
            "work_dir": "/var/lib/zagros/cores/hysteria2",
            "listen": "::",
            "port": 443,
            "masquerade_url": "https://www.bing.com",
            "traffic_listen": "127.0.0.1:19999",
            "traffic_secret": "",
            "cert_path": "",
            "key_path": "",
            "advertise_host": "127.0.0.1",
            "advertise_sni": "",
            "cert_common_name": "updates.microsoft.com",
            "bandwidth_up": "",
            "bandwidth_down": "",
            "obfs_password": "",
        },
        homepage="https://v2.hysteria.network/",
        provides=set(),
        requires=set(),
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.hysteria2.backend import LocalHysteria2Backend

            backend = LocalHysteria2Backend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._bootstrap: str | None = None
        self._chain_users: dict[str, str] = {}          # name → password
        self._usage = DeltaTracker()
        self._cert: tuple[str, str] | None = None
        self._last_error: str | None = None

    # ------------------------------------------------------------------ #
    # config rendering + publishing
    # ------------------------------------------------------------------ #
    def _bootstrap_password(self) -> str:
        if self._bootstrap is None:
            import os
            import secrets

            path = os.path.join(self.settings["work_dir"], ".bootstrap-secret")
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    self._bootstrap = fh.read().strip()
            else:
                self._bootstrap = secrets.token_hex(24)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(self._bootstrap + "\n")
        return self._bootstrap

    def _users_for_config(self) -> list[Hy2User]:
        names: dict[str, str] = {}
        for a in self._accounts.values():
            core_name = _hy2_name(a.account_id)
            previous = names.setdefault(core_name, a.account_id)
            if previous != a.account_id:
                raise CoreError(
                    "hysteria2 core-name collision after sanitization: "
                    f"'{previous}' and '{a.account_id}' both map to "
                    f"'{core_name}' — refusing to render an ambiguous config."
                )
        users = [
            Hy2User(name=_hy2_name(a.account_id), password=str(a.settings["password"]))
            for a in sorted(self._accounts.values(), key=lambda x: x.account_id)
            if a.enabled and a.settings.get("password")
        ]
        users += [Hy2User(name=n, password=p) for n, p in sorted(self._chain_users.items())]
        if not users:
            # hysteria 2.x refuses an empty userpass map (verified against the
            # real binary: "invalid config: auth.userpass: empty auth
            # userpass"). Boot the fresh core with a closed, random,
            # persisted bootstrap credential — replaced the moment a real
            # account exists; never exposed anywhere.
            return [Hy2User(name="zagros-bootstrap",
                            password=self._bootstrap_password())]
        return users

    def render_server_config(self) -> str:
        cert, key = self._cert or ("", "")
        if self.settings.get("cert_path") and self.settings.get("key_path"):
            cert, key = self.settings["cert_path"], self.settings["key_path"]
        s = self.settings
        return render_server_yaml(
            listen=s["listen"], port=int(s["port"]),
            cert_path=cert, key_path=key,
            users=self._users_for_config(),
            masquerade_url=s["masquerade_url"],
            traffic_listen=s["traffic_listen"],
            traffic_secret=s["traffic_secret"] or None,
            bandwidth_up=s["bandwidth_up"] or None,
            bandwidth_down=s["bandwidth_down"] or None,
            obfs_password=s["obfs_password"] or None,
        )

    async def _publish(self) -> None:
        await asyncio.to_thread(self._backend.apply_config, self.render_server_config())
        if await asyncio.to_thread(self._backend.is_running):
            await asyncio.to_thread(self._backend.restart)

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        if self.settings.get("cert_path") and self.settings.get("key_path"):
            self._cert = (self.settings["cert_path"], self.settings["key_path"])
        else:
            self._cert = await asyncio.to_thread(
                self._backend.ensure_tls, self.settings["cert_common_name"]
            )
        await asyncio.to_thread(self._backend.apply_config, self.render_server_config())
        await asyncio.to_thread(self._backend.start)

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        health = HealthStatus.UNKNOWN
        version = None
        metrics = None
        if running:
            version = await asyncio.to_thread(self._backend.version)
            metrics = await asyncio.to_thread(self._backend.metrics)
            try:
                await asyncio.to_thread(self._backend.traffic)
                health = HealthStatus.HEALTHY if not self._last_error else HealthStatus.DEGRADED
            except CoreError as exc:
                health = HealthStatus.DEGRADED
                metrics = None
                version = version or "unknown"
                return CoreStatus(
                    core_id=self.metadata.id, state=CoreState.RUNNING,
                    health=health, core_version=version, message=str(exc),
                )
        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=health, core_version=version, metrics=metrics,
            message=self._last_error,
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def install(self) -> None:
        await asyncio.to_thread(self._backend.install_binary)

    async def uninstall(self, purge: bool = False) -> None:
        await self.stop()

    # ------------------------------------------------------------------ #
    # user management
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol != "hysteria2":
            raise CoreError(
                f"Hysteria2 core only serves protocol 'hysteria2', got '{protocol}'."
            )

    def _ensure_credentials(self, account: UserAccount) -> None:
        if not account.settings.get("password"):
            raise CoreError(
                f"Hysteria2 account '{account.account_id}' needs settings.password."
            )

    async def _kick_if_online(self, account_id: str) -> None:
        try:
            await asyncio.to_thread(self._backend.kick, [_hy2_name(account_id)])
        except CoreError:
            pass  # stats API down — the restart on publish kills sessions anyway

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        self._accounts[account.account_id] = account
        await self._publish()

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        previous = self._accounts.get(account.account_id)
        password_changed = bool(
            previous
            and previous.settings.get("password") != account.settings.get("password")
        )
        self._accounts[account.account_id] = account
        await self._publish()
        if password_changed:
            await self._kick_if_online(account.account_id)

    async def delete_account(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)
        self._usage.forget(account_id)
        await self._publish()
        await self._kick_if_online(account_id)

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await self._publish()
            await self._kick_if_online(account_id)

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})
        await self._publish()

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        for account in accounts:
            self._ensure_supported(account.protocol)
            self._ensure_credentials(account)
        self._accounts = {a.account_id: a for a in accounts}
        await self._publish()

    # ------------------------------------------------------------------ #
    # statistics — official traffic stats API
    # ------------------------------------------------------------------ #
    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        counters = await asyncio.to_thread(self._backend.traffic)
        reverse = {_hy2_name(a): a for a in self._accounts}
        records: list[UsageRecord] = []
        for core_name, (uplink_total, downlink_total) in counters.items():
            account_id = reverse.get(core_name)
            if account_id is None:
                continue  # chain users / removed accounts are never billed
            if account_ids is not None and account_id not in account_ids:
                continue
            up, down = self._usage.observe(account_id, uplink_total, downlink_total)
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=account_id,
                uplink_bytes=up, downlink_bytes=down,
            ))
        return records

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        """Official /online endpoint → N client instances per user.

        Each instance becomes one DeviceSession (metadata notes the source);
        hysteria exposes no IPs/platform, so those fields stay honestly empty.
        """
        from datetime import datetime, timezone

        online = await asyncio.to_thread(self._backend.online)
        reverse = {_hy2_name(a): a for a in self._accounts}
        now = datetime.now(timezone.utc)
        sessions: list[DeviceSession] = []
        for core_name, count in online.items():
            account_id = reverse.get(core_name)
            if account_id is None:
                continue
            if account_ids is not None and account_id not in account_ids:
                continue
            for index in range(max(0, count)):
                sessions.append(DeviceSession(
                    core_id=self.metadata.id,
                    account_id=account_id,
                    ip=None,  # the API reports no client IPs
                    last_activity=now,
                    metadata={
                        "connection_index": index,
                        "device_count": count,
                        "identity_note": "hysteria /online counts client "
                                         "instances; no fingerprint available",
                    },
                ))
        return sessions

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only)
    # ------------------------------------------------------------------ #
    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        s = self.settings
        own_cert = not (s.get("cert_path") and s.get("key_path"))
        share = render_client_share(
            name=_hy2_name(account.account_id),
            password=str(account.settings["password"]),
            host=s["advertise_host"], port=int(s["port"]),
            sni=s["advertise_sni"] or s["cert_common_name"],
            insecure=own_cert,  # self-signed default → clients pin SNI+insecure
            obfs_password=s["obfs_password"] or None,
            remark=f"Hysteria2 · {account.username}",
        )
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="hysteria2",
            engine="hysteria",
            payload={"format": "share-url", "url": share},
            display_name="Hysteria 2",
        )

    # ------------------------------------------------------------------ #
    # chain ingress — real hysteria2 upstream for sing-box outbounds
    # ------------------------------------------------------------------ #
    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        if "_zg-chain" not in self._chain_users:
            return []
        return [self._chain_endpoint()]

    async def ensure_chain_listener(self, protocol: str, port: int) -> ChainEndpoint:
        if protocol != "hysteria2":
            raise CoreError(
                f"Hysteria2 cannot host a '{protocol}' chain endpoint — chains "
                f"into this core use the native hysteria2 outbound."
            )
        if "_zg-chain" not in self._chain_users:
            import secrets
            import string

            alphabet = string.ascii_letters + string.digits
            self._chain_users["_zg-chain"] = "".join(
                secrets.choice(alphabet) for _ in range(24)
            )
            await self._publish()
        return self._chain_endpoint()

    def _chain_endpoint(self) -> ChainEndpoint:
        s = self.settings
        own_cert = not (s.get("cert_path") and s.get("key_path"))
        return ChainEndpoint(
            core_id=self.metadata.id,
            protocol="hysteria2",
            host=s["advertise_host"],
            port=int(s["port"]),
            network="udp",
            requires_credentials=True,
            metadata={
                "password": self._chain_users["_zg-chain"],
                "sni": s["advertise_sni"] or s["cert_common_name"],
                "insecure": own_cert,
            },
        )
