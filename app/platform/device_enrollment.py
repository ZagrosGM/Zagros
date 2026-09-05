"""Strict subscription-device (HWID) enrollment.

This policy is deliberately independent from online source-IP limiting.  A
stable identifier comes only from ``X-Device-ID`` or ``X-HWID``; Zagros never
pretends an IP address or User-Agent is hardware identity.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
from datetime import datetime, timezone
from typing import Mapping

from sqlalchemy import delete, select

from app.persistence.models import SubscriptionDeviceModel, UserModel


class DeviceEnrollmentError(Exception):
    """A subscription/config request failed its device precondition."""


_LOCKS: dict[int, asyncio.Lock] = {}


def _lock(user_id: int) -> asyncio.Lock:
    lock = _LOCKS.get(user_id)
    if lock is None:
        lock = _LOCKS[user_id] = asyncio.Lock()
    return lock


def device_id_from_headers(headers: Mapping[str, str]) -> str | None:
    """Read and validate the two accepted stable-ID headers.

    When both names are present they must agree; accepting conflicting values
    would make enrollment depend on proxy/header ordering.
    """
    first = (headers.get("x-device-id") or "").strip()
    second = (headers.get("x-hwid") or "").strip()
    if first and second and first != second:
        raise DeviceEnrollmentError("X-Device-ID and X-HWID do not match")
    value = first or second
    if not value:
        return None
    if not 8 <= len(value) <= 256:
        raise DeviceEnrollmentError("device ID must be 8 to 256 characters")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in value):
        raise DeviceEnrollmentError("device ID must contain visible ASCII characters only")
    return value


def _digest(value: str) -> str:
    # HMAC prevents low-entropy hardware serials from being reversed from a
    # leaked database. The platform already requires this secret for tokens.
    import config

    secret = str(getattr(config, "ZAGROS_SECRET_KEY", "zagros-device-id"))
    return hmac.new(secret.encode(), b"subscription-device\0" + value.encode(),
                    hashlib.sha256).hexdigest()


def _hint(value: str) -> str:
    if len(value) <= 10:
        return value[:4] + "…"
    return value[:6] + "…" + value[-4:]


def _enroll_sync(runtime, user_id: int, headers: Mapping[str, str],
                 user_agent: str | None, source_ip: str | None) -> dict:
    now = datetime.now(timezone.utc)
    try:
        source_ip = str(ipaddress.ip_address(source_ip)) if source_ip else None
    except ValueError:
        source_ip = None
    with runtime.session_factory() as session:
        user = session.get(UserModel, user_id)
        if user is None:
            raise DeviceEnrollmentError("subscription user not found")
        limit = max(0, int(user.device_limit or 0))
        if limit == 0:
            return {"required": False, "enrolled": False, "limit": 0}
        device_id = device_id_from_headers(headers)
        if not device_id:
            raise DeviceEnrollmentError(
                "this subscription requires X-Device-ID or X-HWID")

        digest = _digest(device_id)
        rows = list(session.execute(
            select(SubscriptionDeviceModel)
            .where(SubscriptionDeviceModel.user_id == user_id)
            .order_by(SubscriptionDeviceModel.first_seen,
                      SubscriptionDeviceModel.id)
        ).scalars())
        for position, row in enumerate(rows):
            if hmac.compare_digest(row.device_hash, digest):
                # Lowering the limit immediately excludes devices beyond the
                # oldest N instead of grandfathering every historical row.
                if position >= limit:
                    raise DeviceEnrollmentError(
                        f"device limit reached ({limit}); ask the administrator to remove an enrolled device")
                row.last_seen = now
                row.user_agent = (user_agent or "")[:512] or None
                row.last_ip = source_ip
                session.commit()
                return {"required": True, "enrolled": False, "limit": limit,
                        "device": row.device_hint}
        if len(rows) >= limit:
            raise DeviceEnrollmentError(
                f"device limit reached ({limit}); ask the administrator to remove an enrolled device")
        row = SubscriptionDeviceModel(
            user_id=user_id, device_hash=digest, device_hint=_hint(device_id),
            first_seen=now, last_seen=now,
            user_agent=(user_agent or "")[:512] or None,
            last_ip=source_ip,
        )
        session.add(row)
        session.commit()
        return {"required": True, "enrolled": True, "limit": limit,
                "device": row.device_hint}


async def enforce(runtime, user_id: int, headers: Mapping[str, str],
                  user_agent: str | None = None,
                  source_ip: str | None = None) -> dict:
    """Require/enroll this stable ID; source IP is metadata, never identity."""
    async with _lock(user_id):
        return await asyncio.to_thread(
            _enroll_sync, runtime, user_id, dict(headers), user_agent,
            source_ip)


def list_devices(runtime, user_id: int) -> list[dict]:
    with runtime.session_factory() as session:
        rows = session.execute(
            select(SubscriptionDeviceModel)
            .where(SubscriptionDeviceModel.user_id == user_id)
            .order_by(SubscriptionDeviceModel.first_seen,
                      SubscriptionDeviceModel.id)
        ).scalars()
        return [{
            "id": row.id,
            "device": row.device_hint,
            "first_seen": row.first_seen.isoformat(),
            "last_seen": row.last_seen.isoformat(),
            "user_agent": row.user_agent,
            "last_ip": row.last_ip,
        } for row in rows]


def remove_device(runtime, user_id: int, device_id: int | None = None) -> int:
    with runtime.session_factory() as session:
        stmt = delete(SubscriptionDeviceModel).where(
            SubscriptionDeviceModel.user_id == user_id)
        if device_id is not None:
            stmt = stmt.where(SubscriptionDeviceModel.id == device_id)
        result = session.execute(stmt)
        session.commit()
        return int(result.rowcount or 0)
