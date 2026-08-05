"""Unified Session Manager — active sessions + history across every core.

The abstraction above heterogeneous cores:
  * Drivers report *live* sessions uniformly as ``DeviceSession``
    (xray IPs, OpenVPN status rows, WireGuard handshakes, hysteria traffic
    API, sing-box counter-delta).
  * This manager diffs consecutive polls: a session present last poll and
    gone now is **closed** — with a computed duration and final counters —
    and appended to the history store. A session never seen before is
    **opened**.

This is the honest poll-based approach that works for every core without
requiring them to emit lifecycle events; cores that DO have explicit events
(openvpn disconnect hook) already reflect them in their live view.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from app.cores.types import DeviceSession


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def session_key(core_id: str, account_id: str, ip: str | None,
                connected_at: datetime | None) -> str:
    """Stable identity of one live session across polls."""
    stamp = connected_at.isoformat() if connected_at else ""
    return f"{core_id}|{account_id}|{ip or '-'}|{stamp}"


class ActiveSession(BaseModel):
    """One session live right now on some core."""

    key: str
    user_id: int | None = None
    core_id: str
    account_id: str
    ip: str | None = None
    connected_at: datetime | None = None
    first_seen: datetime = Field(default_factory=_utcnow)
    last_activity: datetime = Field(default_factory=_utcnow)
    rx_bytes: int = 0
    tx_bytes: int = 0
    platform: str | None = None
    app_version: str | None = None
    metadata: dict = Field(default_factory=dict)


class SessionRecord(BaseModel):
    """A closed session, archived in history."""

    key: str
    user_id: int | None = None
    core_id: str
    account_id: str
    ip: str | None = None
    started_at: datetime
    ended_at: datetime
    duration_seconds: float
    rx_bytes: int = 0
    tx_bytes: int = 0


@runtime_checkable
class SessionStore(Protocol):
    """Port: session history persistence (SQL adapter in Phase 3)."""

    async def append(self, record: SessionRecord) -> None: ...
    async def history(
        self, *, user_id: int | None = None, account_id: str | None = None,
        limit: int = 100,
    ) -> list[SessionRecord]: ...


class InMemorySessionStore:
    def __init__(self) -> None:
        self._records: list[SessionRecord] = []

    async def append(self, record: SessionRecord) -> None:
        self._records.append(record)

    async def history(
        self, *, user_id: int | None = None, account_id: str | None = None,
        limit: int = 100,
    ) -> list[SessionRecord]:
        rows = [
            r for r in self._records
            if (user_id is None or r.user_id == user_id)
            and (account_id is None or r.account_id == account_id)
        ]
        return list(reversed(rows[-limit:]))


class SessionReport(BaseModel):
    opened: list[ActiveSession] = Field(default_factory=list)
    ongoing: list[ActiveSession] = Field(default_factory=list)
    closed: list[SessionRecord] = Field(default_factory=list)


class SessionManager:
    """Poll-diff session lifecycle tracker over all cores."""

    def __init__(self, store: SessionStore) -> None:
        self._store = store
        self._active: dict[str, ActiveSession] = {}

    async def refresh(
        self,
        sessions: list[DeviceSession],
        owners: dict[tuple[str, str], int] | None = None,
    ) -> SessionReport:
        """Process one poll of live sessions from every core.

        ``owners``: optional ``{(core_id, account_id): user_id}`` attribution.
        """
        now = _utcnow()
        owners = owners or {}
        report = SessionReport()
        seen: set[str] = set()

        for session in sessions:
            meta = session.metadata or {}
            key = session_key(session.core_id, session.account_id,
                              session.ip, session.connected_at)
            seen.add(key)
            rx = int(meta.get("session_rx_bytes") or meta.get("rx_bytes") or 0)
            tx = int(meta.get("session_tx_bytes") or meta.get("tx_bytes") or 0)
            user_id = owners.get((session.core_id, session.account_id))
            existing = self._active.get(key)
            if existing is None:
                existing = ActiveSession(
                    key=key, user_id=user_id, core_id=session.core_id,
                    account_id=session.account_id, ip=session.ip,
                    connected_at=session.connected_at or now,
                    first_seen=now, last_activity=now,
                    rx_bytes=rx, tx_bytes=tx,
                    platform=meta.get("platform"), app_version=meta.get("app_version"),
                    metadata=meta,
                )
                self._active[key] = existing
                report.opened.append(existing)
            else:
                existing.last_activity = now
                existing.user_id = existing.user_id or user_id
                existing.rx_bytes = max(existing.rx_bytes, rx)
                existing.tx_bytes = max(existing.tx_bytes, tx)
                report.ongoing.append(existing)

        for key in sorted(set(self._active) - seen):
            dead = self._active.pop(key)
            started = dead.connected_at or dead.first_seen
            if started.tzinfo is None:  # drivers returning naive times: assume UTC
                started = started.replace(tzinfo=timezone.utc)
            record = SessionRecord(
                key=key, user_id=dead.user_id, core_id=dead.core_id,
                account_id=dead.account_id, ip=dead.ip,
                started_at=started, ended_at=now,
                duration_seconds=max(0.0, (now - started).total_seconds()),
                rx_bytes=dead.rx_bytes, tx_bytes=dead.tx_bytes,
            )
            await self._store.append(record)
            report.closed.append(record)
        return report

    def active(self, *, core_id: str | None = None,
               user_id: int | None = None) -> list[ActiveSession]:
        """Sessions live right now, optionally filtered."""
        return [
            s for s in self._active.values()
            if (core_id is None or s.core_id == core_id)
            and (user_id is None or s.user_id == user_id)
        ]

    async def history(
        self, *, user_id: int | None = None, account_id: str | None = None,
        limit: int = 100,
    ) -> list[SessionRecord]:
        return await self._store.history(
            user_id=user_id, account_id=account_id, limit=limit
        )
