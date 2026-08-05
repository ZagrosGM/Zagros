"""Unified Device Manager — every device of a user, across every core, in one list.

Each DeviceInfo has: id, user, name, platform, app_version, last_ip,
last_seen, current_core — regardless of which core/protocol the device used.

Honest identity model (documented, never overclaimed):
  * If a driver reports a stable device fingerprint (the official app will
    send ``X-Device-Id``), that wins — one physical device = one id on every
    core it uses.
  * Otherwise identity is the heuristic tuple ``(user, ip)`` merged across
    cores: the same phone hopping between Xray and WireGuard shows as ONE
    device; two users behind the same CGNAT address are NOT merged (different
    users), but two devices of one user sharing an IP address count as one —
    a documented limitation liftable only with client cooperation.
"""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DeviceInfo(BaseModel):
    """One physical device as the panel sees it (unified across cores)."""

    device_id: str
    user_id: int
    name: str = ""
    platform: str | None = None
    app_version: str | None = None
    last_ip: str | None = None
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    current_core: str | None = None
    cores: set[str] = Field(default_factory=set)
    online: bool = False


def device_identity(user_id: int, stable_id: str | None, ip: str | None) -> str:
    """Deterministic identity key for a device (see module docstring)."""
    if stable_id:
        raw = f"stable:{stable_id}"
    elif ip:
        raw = f"ip:{user_id}:{ip}"
    else:
        raw = f"anon:{user_id}"  # stats-only cores (no IPs): unify per user
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@runtime_checkable
class DeviceStore(Protocol):
    """Port: device registry persistence (SQL adapter in Phase 3)."""

    async def get(self, device_id: str) -> DeviceInfo | None: ...
    async def upsert(self, device: DeviceInfo) -> None: ...
    async def for_user(self, user_id: int) -> list[DeviceInfo]: ...
    async def all(self) -> list[DeviceInfo]: ...


class InMemoryDeviceStore:
    def __init__(self) -> None:
        self._devices: dict[str, DeviceInfo] = {}
        self._lock = asyncio.Lock()

    async def get(self, device_id: str) -> DeviceInfo | None:
        return self._devices.get(device_id)

    async def upsert(self, device: DeviceInfo) -> None:
        async with self._lock:
            self._devices[device.device_id] = device

    async def for_user(self, user_id: int) -> list[DeviceInfo]:
        return [d for d in self._devices.values() if d.user_id == user_id]

    async def all(self) -> list[DeviceInfo]:
        return list(self._devices.values())


class DeviceViolation(BaseModel):
    user_id: int
    active_devices: int
    device_limit: int
    devices: list[DeviceInfo]


class DeviceManager:
    """Maintains the unified device registry from cross-core live sessions."""

    def __init__(self, store: DeviceStore) -> None:
        self._store = store

    async def refresh(
        self,
        sessions_by_owner: dict[tuple[str, str], tuple[int, list]],
    ) -> list[DeviceInfo]:
        """Fold live cross-core sessions into the device registry.

        ``sessions_by_owner``: ``{(core_id, account_id): (user_id, [DeviceSession])}``
        as collected by CoreManager.online_devices + the account repository.
        Returns the devices currently online.
        """
        online_now: dict[str, DeviceInfo] = {}
        for (core_id, _account_id), (user_id, sessions) in sessions_by_owner.items():
            for session in sessions:
                meta = session.metadata or {}
                stable = meta.get("stable_id")
                ip = session.ip or meta.get("ip")
                device_id = device_identity(user_id, stable, ip)
                existing = await self._store.get(device_id) or online_now.get(device_id)
                now = _utcnow()
                device = DeviceInfo(
                    device_id=device_id,
                    user_id=user_id,
                    name=stable or existing.name if existing else (stable or ip or ""),
                    platform=meta.get("platform") or (existing.platform if existing else None),
                    app_version=(meta.get("app_version")
                                 or (existing.app_version if existing else None)),
                    last_ip=ip or (existing.last_ip if existing else None),
                    first_seen=existing.first_seen if existing else now,
                    last_seen=now,
                    current_core=core_id,
                    cores=(existing.cores | {core_id}) if existing else {core_id},
                    online=True,
                )
                online_now[device_id] = device
                await self._store.upsert(device)
        # devices that vanished from every core are marked offline
        for device in await self._store.all():
            if device.online and device.device_id not in online_now:
                await self._store.upsert(device.model_copy(update={"online": False}))
        return list(online_now.values())

    async def active_devices(self, user_id: int) -> list[DeviceInfo]:
        """Distinct devices of a user online right now — across ALL cores."""
        return [d for d in await self._store.for_user(user_id) if d.online]

    async def list_devices(self, user_id: int | None = None) -> list[DeviceInfo]:
        if user_id is None:
            return await self._store.all()
        return await self._store.for_user(user_id)

    async def enforce_limits(
        self, limits: dict[int, int | None]
    ) -> list[DeviceViolation]:
        """Global device-limit check: N devices total, regardless of protocol."""
        violations: list[DeviceViolation] = []
        for user_id, limit in limits.items():
            if limit is None:
                continue
            active = await self.active_devices(user_id)
            if len(active) > limit:
                violations.append(DeviceViolation(
                    user_id=user_id,
                    active_devices=len(active),
                    device_limit=limit,
                    devices=sorted(active, key=lambda d: d.last_seen, reverse=True),
                ))
        return violations
