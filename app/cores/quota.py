"""Unified Quota Service — one shared usage bucket per user across all cores.

The panel's core guarantee (doc §10):
    1 GB on Xray + 2 GB on OpenVPN + 3 GB on WireGuard + 4 GB on sing-box
    ⇒ exactly 10 GB deducted from the user's single quota.

How correctness is achieved:
  * Drivers emit **delta** records (DeltaTracker / SessionUsageTracker), so
    re-polling the same cumulative counters can never double count.
  * This service applies each delta batch **exactly once** to the per-user
    totals behind the :class:`QuotaStore` port. The SQL adapter (Phase 3)
    persists record-ids + totals in one transaction; even a crash between
    "apply" and "persist" cannot double count because the recorder job's
    baselines live in the same store.
  * Records for accounts the panel does not own are dropped and reported —
    never silently absorbed into someone else's quota.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from app.cores.types import UsageRecord


class QuotaEntry(BaseModel):
    """Persistent per-user usage totals (one row per user)."""

    user_id: int
    uplink_bytes: int = 0
    downlink_bytes: int = 0

    @property
    def total_bytes(self) -> int:
        return self.uplink_bytes + self.downlink_bytes


class QuotaView(BaseModel):
    """What the admin UI / app shows: totals + remaining against the limit."""

    user_id: int
    uplink_bytes: int
    downlink_bytes: int
    total_bytes: int
    limit_bytes: int | None
    remaining_bytes: int | None
    exceeded: bool


class AppliedUsage(BaseModel):
    """Per-user result of applying one record batch to the ledger."""

    user_id: int
    applied_bytes: int = 0
    new_total_bytes: int = 0
    limit_bytes: int | None = None
    exceeded: bool = False
    cores: set[str] = Field(default_factory=set)


@runtime_checkable
class QuotaStore(Protocol):
    """Port: persistence of per-user totals. Implemented by SQL adapter (P3)
    and in-memory fakes (tests). Implementations must be atomic per batch."""

    async def get(self, user_id: int) -> QuotaEntry | None: ...

    async def add(self, user_id: int, uplink: int, downlink: int) -> QuotaEntry:
        """Atomically add a delta and return the new totals."""
        ...

    async def all(self) -> list[QuotaEntry]: ...

    async def reset(self, user_id: int) -> None:
        """Atomically zero the user's totals (admin action)."""
        ...


class InMemoryQuotaStore:
    """Reference implementation (asyncio-lock guarded → concurrency safe)."""

    def __init__(self) -> None:
        self._entries: dict[int, QuotaEntry] = {}
        self._lock = asyncio.Lock()

    async def get(self, user_id: int) -> QuotaEntry | None:
        return self._entries.get(user_id)

    async def add(self, user_id: int, uplink: int, downlink: int) -> QuotaEntry:
        async with self._lock:
            entry = self._entries.get(user_id) or QuotaEntry(user_id=user_id)
            entry = entry.model_copy(update={
                "uplink_bytes": entry.uplink_bytes + uplink,
                "downlink_bytes": entry.downlink_bytes + downlink,
            })
            self._entries[user_id] = entry
            return entry

    async def all(self) -> list[QuotaEntry]:
        return list(self._entries.values())

    async def reset(self, user_id: int) -> None:
        async with self._lock:
            self._entries[user_id] = QuotaEntry(user_id=user_id)


@dataclass(frozen=True)
class DroppedRecord:
    """A usage record that could not be attributed to any panel user."""

    record: UsageRecord
    reason: str


class UnifiedQuotaService:
    """Folds per-core usage deltas into one shared quota per user."""

    def __init__(self, store: QuotaStore, limits: dict[int, int] | None = None) -> None:
        self._store = store
        self._limits = limits if limits is not None else {}

    def set_limit(self, user_id: int, limit_bytes: int | None) -> None:
        if limit_bytes is None:
            self._limits.pop(user_id, None)
        else:
            self._limits[user_id] = limit_bytes

    async def apply_usage(
        self,
        records: list[UsageRecord],
        owners: dict[tuple[str, str], int],
    ) -> tuple[list[AppliedUsage], list[DroppedRecord]]:
        """Apply one polling batch.

        ``owners``: ``{(core_id, account_id): user_id}`` attribution map
        (supplied by the account repository — drivers never know user ids).

        Returns (applied per user, dropped records with reasons).
        """
        deltas: dict[int, tuple[int, int, set[str]]] = {}
        applied: list[AppliedUsage] = []
        dropped: list[DroppedRecord] = []
        for record in records:
            key = (record.core_id, record.account_id)
            owner = owners.get(key)
            if owner is None:
                dropped.append(DroppedRecord(
                    record=record,
                    reason=f"no panel user owns {record.core_id}:{record.account_id}",
                ))
                continue
            up, down, cores = deltas.get(owner, (0, 0, set()))
            deltas[owner] = (up + record.uplink_bytes, down + record.downlink_bytes,
                             cores | {record.core_id})

        for user_id, (up, down, cores) in sorted(deltas.items()):
            if up == 0 and down == 0:
                continue  # zero deltas add nothing (and must not touch the store)
            entry = await self._store.add(user_id, up, down)
            limit = self._limits.get(user_id)
            applied.append(AppliedUsage(
                user_id=user_id,
                applied_bytes=up + down,
                new_total_bytes=entry.total_bytes,
                limit_bytes=limit,
                exceeded=limit is not None and entry.total_bytes >= limit,
                cores=cores,
            ))
        return applied, dropped

    async def get_view(self, user_id: int, limit_bytes: int | None = None) -> QuotaView:
        entry = await self._store.get(user_id) or QuotaEntry(user_id=user_id)
        limit = limit_bytes if limit_bytes is not None else self._limits.get(user_id)
        remaining = None if limit is None else max(0, limit - entry.total_bytes)
        return QuotaView(
            user_id=user_id,
            uplink_bytes=entry.uplink_bytes,
            downlink_bytes=entry.downlink_bytes,
            total_bytes=entry.total_bytes,
            limit_bytes=limit,
            remaining_bytes=remaining,
            exceeded=limit is not None and entry.total_bytes >= limit,
        )

    async def reset(self, user_id: int) -> QuotaEntry:
        """Admin action: restart the user's accounting period."""
        await self._store.reset(user_id)
        return (await self._store.get(user_id)) or QuotaEntry(user_id=user_id)
