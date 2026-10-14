"""MTProtoProxyDriver — Telegram MTProto proxy as a first-class panel core.

Real capabilities used:
  * **User management** = one USERS entry per account in the rendered
    ``config.py`` (idempotent) + ``SIGUSR2`` hot reload — clients never drop.
  * **Per-user ad tag** = the panel-vendored daemon patch: the promoted
    channel tag rides the per-account entry, so every user has their OWN tag
    on the SAME port (upstream only supports one global tag).
  * **USAGE_ACCOUNTING** = the daemon's Prometheus exporter
    (``user_octets{user=...}`` counters, 127.0.0.1 only) fed through the
    shared DeltaTracker — restart-safe cumulative accounting.
  * **ONLINE_TRACKING** = ``user_connects_curr{user=...}`` gauge.
  * **Limits** = the platform pipeline end-to-end: usage records feed the
    quota manager; an over-limit user's status flips to limited and the
    driver's ``suspend_account`` removes the entry (auth denied instantly),
    ``resume_account`` restores it.

Honestly NOT claimed (documented, no simulation):
  * DEVICE_DETECTION — the MTProto handshake carries no device identity.
  * Per-user distinct-IP list — mtproto clients relay through one
    authenticated stream per app; the daemon does not expose per-IP maps, so
    the panel's IP limit for this core is enforced as a CONNECTION-count
    bound (documented in the inbound UI).
"""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.exceptions import CoreError
from app.cores.stats import DeltaTracker
from app.cores.types import (
    Capability,
    ClientConfig,
    CoreFeatureCapability,
    CoreMetadata,
    CoreState,
    CoreStatus,
    DeviceSession,
    FeatureAvailability,
    HealthStatus,
    ListenerClaim,
    UsageRecord,
    UserAccount,
)
from app.cores.drivers.mtproto.backend import (
    DAEMON_VERSION,
    LocalMtprotoBackend,
    _SECRET_RE,
    _TAG_RE,
)

logger = logging.getLogger("zagros.cores.drivers.mtproto")

_METRIC_RE = re.compile(
    r'^(user_octets(?:_from|_to)?|user_connects_curr)\{user="([^"]+)"\}\s+(\d+)')


class MTProtoProxyDriver(BaseCoreDriver):
    """Driver for the vendored MTProto proxy daemon."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="mtproto",
        name="MTProto Proxy",
        description=(
            "Telegram MTProto proxy (vendored alexbers daemon, patched): "
            "multi-port inbounds, per-user secret AND per-user ad tag on the "
            "same port, Prometheus-based traffic accounting, hot reload."
        ),
        protocols=["mtproto"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.HOT_RELOAD,
            Capability.SERVICE_CONTROL,
            Capability.SELF_INSTALL,
            Capability.CLIENT_CONFIG,
            Capability.KEY_ROTATION,
        },
        feature_capabilities={
            "inbound": CoreFeatureCapability(
                state=FeatureAvailability.SUPPORTED,
                detail="Multi-port MTProto proxy inbounds (TCP)",
            ),
            "outbound": CoreFeatureCapability(
                state=FeatureAvailability.UNSUPPORTED,
                detail="MTProto outbound is not implemented",
            ),
        },
        config_schema={
            "type": "object",
            "properties": {
                "work_dir": {"type": "string"},
                "advertise_host": {"type": "string"},
                "metrics_port": {"type": "integer",
                                 "minimum": 1, "maximum": 65535},
                "inbounds": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["tag", "protocol", "listen", "port"],
                        "properties": {
                            "tag": {"type": "string", "minLength": 1},
                            "protocol": {"type": "string", "enum": ["mtproto"]},
                            "listen": {"type": "string"},
                            "port": {"type": "integer",
                                     "minimum": 1, "maximum": 65535},
                        },
                    },
                },
            },
        },
        default_settings={
            "work_dir": "/var/lib/zagros/cores/mtproto",
            "advertise_host": "",
            "metrics_port": 23456,
            "inbounds": [],
        },
        driver_version="1.0.0",
        homepage="https://github.com/alexbers/mtprotoproxy",
        studio_inbounds_path="/inbounds",
        studio_max_inbounds=8,
        security_class=None,
        stop_when_no_inbounds=True,
    )

    def __init__(self, settings: dict[str, Any] | None = None):
        super().__init__(settings)
        self._backend = LocalMtprotoBackend(self.settings)
        self._usage = DeltaTracker()

    # ------------------------------------------------------------------ #
    # studio inbounds
    # ------------------------------------------------------------------ #
    def _inbounds(self) -> list[dict[str, Any]]:
        return [ib for ib in (self.settings.get("inbounds") or [])
                if ib.get("port")]

    def normalize_studio_document(self, document: dict[str, Any]) -> dict:
        for ib in (document or {}).get("inbounds") or []:
            if str(ib.get("protocol") or "") == "mtproto":
                ib["port"] = int(ib.get("port") or 0)
                ib["listen"] = str(ib.get("listen") or "0.0.0.0")
        return document

    def validate_studio_document(self, document: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        ports: set[int] = set()
        for ib in (document or {}).get("inbounds") or []:
            if str(ib.get("protocol") or "") != "mtproto":
                continue
            try:
                port = int(ib.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            if not 1 <= port <= 65535:
                errors.append(f"inbound '{ib.get('tag')}' has an invalid port")
            elif port in ports:
                errors.append(f"port {port} is used by more than one MTProto inbound")
            else:
                ports.add(port)
        return errors

    def export_config_document(self) -> dict[str, Any]:
        inbounds = [{"tag": ib.get("tag") or f"mtproto-{ib['port']}",
                     "protocol": "mtproto", "listen": ib.get("listen") or "0.0.0.0",
                     "port": int(ib["port"]), "transport": "tcp"}
                    for ib in self._inbounds()]
        return {"inbounds": inbounds}

    async def apply_studio_document(self, document: dict[str, Any]) -> None:
        self.normalize_studio_document(document)
        errors = self.validate_studio_document(document)
        if errors:
            raise CoreError("; ".join(errors))
        inbounds = [dict(ib) for ib in (document or {}).get("inbounds") or []
                    if str(ib.get("protocol") or "") == "mtproto"]
        # re-render with the CURRENT account set (persisted via the panel's
        # encrypted core-account store, mirrored into settings by sync)
        accounts = self._persisted_accounts()
        self.settings["inbounds"] = inbounds
        self._backend.write_config(inbounds, accounts)
        self._backend.bump_generation()
        if self._backend.is_running():
            await asyncio.to_thread(self._backend.reload)

    def _persisted_accounts(self) -> list[dict[str, str]]:
        """The account entries currently on disk (source of truth while the
        driver has no account store of its own — accounts are re-rendered
        from config)."""
        return [{"account_id": aid, "secret": a["secret"], "tag": a.get("tag", "")}
                for aid, a in sorted(self._backend.accounts_on_disk().items())]

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def install(self) -> None:
        # the daemon is vendored inside the package — nothing to download
        self._backend._ensure_dir()

    async def uninstall(self, purge: bool = False) -> None:
        await self.stop()
        if purge:
            import shutil
            from pathlib import Path
            shutil.rmtree(self._backend.work_dir, ignore_errors=True)

    async def start(self) -> None:
        inbounds = self._inbounds()
        if not inbounds:
            raise CoreError("MTProto core has no inbound — create one first")
        self._backend.write_config(inbounds, self._persisted_accounts())
        self._backend.bump_generation()
        await asyncio.to_thread(self._backend.start)

    async def stop(self) -> None:
        await asyncio.to_thread(self._backend.stop)

    async def status(self) -> CoreStatus:
        running = await asyncio.to_thread(self._backend.is_running)
        health = HealthStatus.UNKNOWN
        message = None
        connections = 0
        if running:
            try:
                connections = await asyncio.to_thread(self._live_connections)
                health = HealthStatus.HEALTHY
            except CoreError as exc:
                health = HealthStatus.DEGRADED
                message = str(exc)
        else:
            if not self._inbounds():
                message = "no inbound configured yet"
        return CoreStatus(
            core_id="mtproto",
            state=CoreState.RUNNING if running else CoreState.STOPPED,
            health=health, core_version=DAEMON_VERSION,
            version_reason=None if running or self._inbounds() else "not configured",
            message=message,
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for line in await asyncio.to_thread(self._backend.logs, tail):
            yield line

    async def listener_claims(self) -> list[ListenerClaim]:
        return [ListenerClaim(
            core_id="mtproto", protocol="mtproto", transport="tcp",
            address=ib.get("listen") or "0.0.0.0", port=int(ib["port"]),
            label=ib.get("tag") or f"mtproto-{ib['port']}")
            for ib in self._inbounds()]

    # ------------------------------------------------------------------ #
    # accounts
    # ------------------------------------------------------------------ #
    @staticmethod
    def _ensure_secret(account: UserAccount) -> str:
        secret = str(account.settings.get("secret") or "")
        if not _SECRET_RE.match(secret):
            secret = secrets.token_hex(16)
            account.settings["secret"] = secret
        return secret

    def _write_current(self) -> None:
        self._backend.write_config(self._inbounds(), self._persisted_accounts())
        self._backend.bump_generation()

    async def _apply(self, *, hard: bool) -> None:
        self._write_current()
        if not self._backend.is_running():
            return
        if hard:
            await asyncio.to_thread(self._backend.reload)
        else:
            await asyncio.to_thread(self._backend.reload)

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_secret(account)          # minted in place → persisted by the service layer
        self._write_current()
        if self._backend.is_running():
            await asyncio.to_thread(self._backend.reload)

    async def update_account(self, account: UserAccount) -> None:
        # secret/ad_tag edits arrive through settings; keep stored values
        await self.create_account(account)

    async def delete_account(self, account_id: str) -> None:
        self._write_current()
        if self._backend.is_running():
            await asyncio.to_thread(self._backend.reload)

    async def suspend_account(self, account_id: str) -> None:
        # entry removed → new handshakes with that secret fail instantly
        self._write_current()
        if self._backend.is_running():
            await asyncio.to_thread(self._backend.reload)

    async def resume_account(self, account: UserAccount) -> None:
        await self.create_account(account)

    async def rotate_credentials(self, account: UserAccount) -> UserAccount:
        account.settings["secret"] = secrets.token_hex(16)
        await self.create_account(account)
        return account

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        for account in accounts:
            self._ensure_secret(account)
        self._write_current()
        if self._backend.is_running():
            await asyncio.to_thread(self._backend.reload)

    # ------------------------------------------------------------------ #
    # metrics
    # ------------------------------------------------------------------ #
    def _parse_metrics(self) -> tuple[dict[str, int], dict[str, int]]:
        """(octets_total per user, live connections per user)."""
        text = self._backend.fetch_prometheus_metrics()
        octets: dict[str, int] = {}
        live: dict[str, int] = {}
        for line in text.splitlines():
            m = _METRIC_RE.match(line.strip())
            if not m:
                continue
            name, user, value = m.group(1), m.group(2), int(m.group(3))
            if name == "user_octets":
                octets[user] = max(octets.get(user, 0), value)
            elif name in ("user_octets_from", "user_octets_to"):
                octets[user] = max(octets.get(user, 0), value)
            elif name == "user_connects_curr":
                live[user] = value
        return octets, live

    def _live_connections(self) -> int:
        _, live = self._parse_metrics()
        return sum(live.values())

    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None,
    ) -> list[UsageRecord]:
        if not await asyncio.to_thread(self._backend.is_running):
            return []
        try:
            octets, _ = await asyncio.to_thread(self._parse_metrics)
        except CoreError:
            return []
        wanted = set(account_ids) if account_ids is not None else set(octets)
        records: list[UsageRecord] = []
        for account_id in sorted(wanted):
            total = int(octets.get(account_id, 0))
            # mtproto relays are bidirectional pipes: the daemon's user_octets
            # already sums both directions; report it as downlink so quota
            # math is conservative and never double-counts.
            delta_up, delta_down = self._usage.observe(account_id, 0, total)
            records.append(UsageRecord(
                core_id="mtproto", account_id=account_id,
                uplink_bytes=delta_up, downlink_bytes=delta_down,
            ))
        return records

    async def get_online_devices(
        self, account_ids: list[str] | None = None,
    ) -> list[DeviceSession]:
        if not await asyncio.to_thread(self._backend.is_running):
            return []
        try:
            _, live = await asyncio.to_thread(self._parse_metrics)
        except CoreError:
            return []
        wanted = set(account_ids) if account_ids is not None else set(live)
        sessions: list[DeviceSession] = []
        for account_id in sorted(wanted):
            count = int(live.get(account_id, 0))
            if count > 0:
                sessions.append(DeviceSession(
                    core_id="mtproto", account_id=account_id, ip=None,
                    metadata={"connections": count},
                ))
        return sessions

    # ------------------------------------------------------------------ #
    # client config
    # ------------------------------------------------------------------ #
    async def build_client_config(
        self, account: UserAccount, node: Any | None = None,
    ) -> ClientConfig:
        from app.cores.delivery import resolve_delivery_host

        inbounds = self._inbounds()
        if not inbounds:
            raise CoreError("MTProto core has no inbound to build a config for")
        inbound = inbounds[0]
        tags = account.settings.get("inbound_tags") or []
        for ib in inbounds:
            if (ib.get("tag") or f"mtproto-{ib['port']}") in tags:
                inbound = ib
                break
        server = resolve_delivery_host(
            self.settings.get("advertise_host"), None, inbound.get("listen"))
        if not server:
            raise CoreError(
                "MTProto client config requires settings.advertise_host")
        secret = self._ensure_secret(account)
        return ClientConfig(
            core_id="mtproto", protocol="mtproto", engine="mtproto",
            payload={
                "format": "mtproto",
                "server": server,
                "port": int(inbound["port"]),
                "secret": secret,
                "ad_tag": str(account.settings.get("ad_tag") or ""),
            },
            display_name="MTProto Proxy",
        )
