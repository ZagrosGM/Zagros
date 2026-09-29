"""Canonical SQL policy for the one global stable-device limit.

``subscription_devices`` is the only authorization registry. Legacy
subscription rows have no Application binding/status; cryptographic
Application rows occupy a slot only while active. Monitoring ``devices`` and
source-IP tables are intentionally absent from this policy.
"""
from __future__ import annotations

from sqlalchemy import func, or_, select

from app.persistence.models import SubscriptionDeviceModel


def occupying_device_predicate(user_id: int):
    """SQL predicate for rows that consume one global user device slot."""
    return (
        SubscriptionDeviceModel.user_id == user_id,
        or_(
            SubscriptionDeviceModel.device_status.is_(None),
            SubscriptionDeviceModel.device_status == "active",
        ),
    )


def occupying_device_count(session, user_id: int) -> int:
    """Count legacy subscription + active Application devices together."""
    return int(session.scalar(
        select(func.count(SubscriptionDeviceModel.id)).where(
            *occupying_device_predicate(user_id),
        )
    ) or 0)


def occupying_devices(session, user_id: int):
    """Return slot rows in deterministic oldest-first entitlement order."""
    return list(session.execute(
        select(SubscriptionDeviceModel)
        .where(*occupying_device_predicate(user_id))
        .order_by(
            SubscriptionDeviceModel.first_seen,
            SubscriptionDeviceModel.id,
        )
    ).scalars())


def device_within_limit(session, *, user_id: int, device_id: int,
                        device_limit: int | None) -> bool:
    """Whether ``device_id`` is currently entitled under a lowered limit.

    A null/zero limit is unlimited. For a positive limit the oldest N active
    stable-device rows remain entitled, matching subscription delivery's
    existing deterministic behavior. This is checked on every Application
    login/refresh/access/config authority path, not only during enrollment.
    """
    limit = max(0, int(device_limit or 0))
    if limit == 0:
        return True
    allowed = session.scalars(
        select(SubscriptionDeviceModel.id)
        .where(*occupying_device_predicate(user_id))
        .order_by(
            SubscriptionDeviceModel.first_seen,
            SubscriptionDeviceModel.id,
        )
        .limit(limit)
    ).all()
    return int(device_id) in {int(value) for value in allowed}
