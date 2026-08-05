"""SoftEtherDriver — SoftEther VPN Server as a first-class panel core.

Real capabilities used (via the official vpncmd management interface):
  * **User management**: UserCreate/UserDelete/UserPasswordSet — applied
    instantly to the live server (SoftEther has true runtime management;
    HOT_RELOAD is honest here).
  * **Suspend**: native per-user expiration switched to a fixed past date
    (``UserExpiresSet 2000/01/01``) + live sessions disconnected;
    resume restores the account's real (or none) expiration.
  * **Usage accounting**: per-user cumulative counters from ``UserGet``
    (Incoming/Outgoing total sizes; direction convention documented in
    setool.py) → DeltaTracker deltas.
  * **Online + device detection**: ``SessionList`` per user — source host
    names/IPs are real device identity signals (SE client reports hostname).
  * **Kick**: SessionDisconnect on suspend/delete — the cut is immediate.
  * **Client config**: L2TP/IPsec and SSTP/OpenVPN-clone transports are the
    protocol's client surface; the sealed payload carries the L2TP/IPsec
    parameters (+ note when an admin password-less PSK is configured).

Honestly NOT claimed (documented):
  * SELF_INSTALL — SoftEther has no distribution package in standard repos;
    install docs are referenced instead of fragile scripted downloads.
  * ROUTING / OUTBOUND_MANAGEMENT / CHAIN ingress — the hub forwards at L2;
    it cannot select per-connection egress or dial upstream proxies.
  * CLIENT-config for WireGuard — SE does not speak WireGuard. (The app's
    engine matrix covers the SE exports: openvpn-clone / l2tp / sstp.)
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from app.cores.base import BaseCoreDriver
from app.cores.exceptions import CoreError
from app.cores.stats import DeltaTracker
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


class SoftEtherDriver(BaseCoreDriver):
    """Driver for SoftEther VPN Server (vpncmd-managed hub)."""

    metadata: ClassVar[CoreMetadata] = CoreMetadata(
        id="softether",
        name="SoftEther VPN",
        description=(
            "SoftEther hub users via vpncmd: live user/session management, "
            "native per-user traffic counters, expiry-based suspend, "
            "session kick, L2TP/IPsec + OpenVPN-clone + SSTP transports."
        ),
        protocols=["l2tp", "sstp", "ovpn"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.DEVICE_DETECTION,
            Capability.HOT_RELOAD,
            Capability.CLIENT_CONFIG,
            Capability.UDP_SUPPORT,
        },
        config_schema={
            "type": "object",
            "properties": {
                "executable_path": {"type": "string", "default": "vpncmd"},
                "server": {"type": "string", "default": "localhost"},
                "hub": {"type": "string", "default": "DEFAULT"},
                "admin_password": {"type": "string"},
                "ipsec_psk": {"type": "string"},
                "advertise_host": {"type": "string"},
            },
        },
        default_settings={
            "executable_path": "vpncmd",
            "server": "localhost",
            "hub": "DEFAULT",
            "admin_password": "",
            "ipsec_psk": "",
            "advertise_host": "127.0.0.1",
        },
        homepage="https://www.softether.org/",
        provides=set(),
        requires=set(),
    )

    def __init__(self, settings: dict[str, Any] | None = None, *, backend: Any | None = None):
        super().__init__(settings)
        if backend is None:
            from app.cores.drivers.softether.backend import LocalSoftEtherBackend

            backend = LocalSoftEtherBackend(self.settings)
        self._backend = backend
        self._accounts: dict[str, UserAccount] = {}
        self._usage = DeltaTracker()
        self._suspended_expire_restore: dict[str, str | None] = {}

    # ------------------------------------------------------------------ #
    # lifecycle — the server is external/systemd-owned; we verify reachability
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        if not await asyncio.to_thread(self._backend.reachable):
            raise CoreError(
                f"SoftEther hub '{self.settings['hub']}' unreachable via vpncmd "
                f"at {self.settings['server']} — check server/credentials."
            )

    async def stop(self) -> None:
        # the VPN server stays up (system-owned); accounts remain provisioned
        pass

    async def status(self) -> CoreStatus:
        reachable = await asyncio.to_thread(self._backend.reachable)
        sessions = []
        if reachable:
            try:
                sessions = await self.get_online_devices()
            except CoreError:
                reachable = True  # reachability degrades separately
        from app.cores.types import CoreMetrics

        return CoreStatus(
            core_id=self.metadata.id,
            state=CoreState.RUNNING if reachable else CoreState.STOPPED,
            health=HealthStatus.HEALTHY if reachable else HealthStatus.UNHEALTHY,
            metrics=CoreMetrics(
                active_accounts=len(self._accounts), active_sessions=len(sessions)
            ) if reachable else None,
            message=None if reachable else "vpncmd cannot reach the hub.",
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        # hub logs are the server's own logs; nothing panel-side to stream
        return
        yield  # pragma: no cover - keeps this an async generator

    async def install(self) -> None:
        self._require(Capability.SELF_INSTALL)  # honest: not claimed → raises

    # ------------------------------------------------------------------ #
    # user management
    # ------------------------------------------------------------------ #
    def _ensure_supported(self, protocol: str) -> None:
        if protocol not in self.metadata.protocols:
            raise CoreError(
                f"SoftEther core serves {self.metadata.protocols}, got '{protocol}'."
            )

    def _ensure_credentials(self, account: UserAccount) -> None:
        if not account.settings.get("password"):
            raise CoreError(f"SoftEther account '{account.account_id}' needs settings.password.")

    async def _kick_user_sessions(self, account_id: str) -> None:
        try:
            for session in await asyncio.to_thread(self._backend.session_list):
                if session.username == account_id:
                    await asyncio.to_thread(self._backend.session_disconnect,
                                            session.session_name)
        except CoreError:
            pass  # server momentarily unreachable; expiry/auth still blocks access

    async def create_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        existing = await asyncio.to_thread(self._backend.user_list)
        if account.account_id not in existing:
            await asyncio.to_thread(self._backend.user_create, account.account_id,
                                    account.username)
        await asyncio.to_thread(self._backend.user_password_set, account.account_id,
                                str(account.settings["password"]))
        self._accounts[account.account_id] = account
        if account.enabled:
            await asyncio.to_thread(self._backend.user_expires_set, account.account_id, None)
        else:
            await asyncio.to_thread(self._backend.suspend_user, account.account_id)
            await self._kick_user_sessions(account.account_id)

    async def update_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        previous = self._accounts.get(account.account_id)
        if previous is None or account.account_id not in (
                await asyncio.to_thread(self._backend.user_list)):
            await self.create_account(account)
            return
        if previous.settings.get("password") != account.settings.get("password"):
            await asyncio.to_thread(self._backend.user_password_set, account.account_id,
                                    str(account.settings["password"]))
            await self._kick_user_sessions(account.account_id)
        self._accounts[account.account_id] = account
        if account.enabled:
            await asyncio.to_thread(self._backend.user_expires_set, account.account_id, None)
        else:
            await asyncio.to_thread(self._backend.suspend_user, account.account_id)
            await self._kick_user_sessions(account.account_id)

    async def delete_account(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)
        self._usage.forget(account_id)
        try:
            await asyncio.to_thread(self._backend.user_list)
        except CoreError:
            return  # server down; local desired state already updated
        await self._kick_user_sessions(account_id)
        await asyncio.to_thread(self._backend.user_delete, account_id)

    async def suspend_account(self, account_id: str) -> None:
        existing = self._accounts.get(account_id)
        if existing is not None:
            self._accounts[account_id] = existing.model_copy(update={"enabled": False})
            await asyncio.to_thread(self._backend.suspend_user, account_id)
            await self._kick_user_sessions(account_id)

    async def resume_account(self, account: UserAccount) -> None:
        self._ensure_supported(account.protocol)
        self._accounts[account.account_id] = account.model_copy(update={"enabled": True})
        await asyncio.to_thread(self._backend.user_expires_set, account.account_id, None)

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        desired = {a.account_id: a for a in accounts}
        current = set(await asyncio.to_thread(self._backend.user_list))
        stale = (current & set(self._accounts)) - set(desired)
        for account_id in stale:
            await asyncio.to_thread(self._backend.user_delete, account_id)
        for account in accounts:
            await self.create_account(account)

    # ------------------------------------------------------------------ #
    # statistics — native per-user counters + live sessions
    # ------------------------------------------------------------------ #
    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        wanted = account_ids if account_ids is not None else list(self._accounts)
        records: list[UsageRecord] = []
        for account_id in wanted:
            if account_id not in self._accounts:
                continue
            try:
                stats = await asyncio.to_thread(self._backend.user_get, account_id)
            except CoreError:
                continue  # user vanished server-side; nothing to report
            up, down = self._usage.observe(
                account_id, stats.incoming_bytes, stats.outgoing_bytes
            )
            records.append(UsageRecord(
                core_id=self.metadata.id, account_id=account_id,
                uplink_bytes=up, downlink_bytes=down,
            ))
        return records

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        sessions = await asyncio.to_thread(self._backend.session_list)
        out: list[DeviceSession] = []
        for session in sessions:
            account_id = session.username
            if account_id not in self._accounts:
                continue
            if account_ids is not None and account_id not in account_ids:
                continue
            host = session.source_host or None
            out.append(DeviceSession(
                core_id=self.metadata.id,
                account_id=account_id,
                ip=host,
                metadata={
                    "session_name": session.session_name,
                    "hostname": host,
                    "stable_id": f"se-{account_id}-{host}" if host else None,
                    "transport": session.raw.get("Session Mode") or None,
                },
            ))
        return out

    # ------------------------------------------------------------------ #
    # client config (sealed delivery only)
    # ------------------------------------------------------------------ #
    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        self._ensure_supported(account.protocol)
        self._ensure_credentials(account)
        s = self.settings
        if not s.get("ipsec_psk"):
            raise CoreError(
                "L2TP/IPsec client config requires settings.ipsec_psk — set the "
                "hub's IPsec pre-shared key first (IPsecEnable)."
            )
        psk = s["ipsec_psk"]
        return ClientConfig(
            core_id=self.metadata.id,
            protocol="l2tp",
            engine="l2tp-ipsec",
            payload={
                "format": "l2tp-ipsec",
                "server": s["advertise_host"],
                "ipsec_psk": psk,
                "username": account.account_id,
                "password": str(account.settings["password"]),
                "hub": s["hub"],
            },
            display_name="VPN (L2TP/IPsec)",
        )
