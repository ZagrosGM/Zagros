"""Real Monitoring read model fed by the existing five-second IP poll.

No second core/node poll is introduced.  The IP-limit collector publishes its
already authenticated ``DeviceSession`` rows here: live connections stay
in-memory, while source-IP activity is persisted in one batch transaction.
Stable subscription devices are read only from ``subscription_devices``;
source IPs are never presented as HWIDs.
"""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, func, select, tuple_

from app.persistence.models import (
    IPActivityModel,
    IPBanModel,
    NodeModel,
    SubscriptionDeviceModel,
    UserModel,
)


def _aware(value: Any, fallback: datetime) -> datetime:
    if value is None:
        return fallback
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return fallback
    if not isinstance(value, datetime):
        return fallback
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None
            else value.astimezone(timezone.utc))


def _source_key(user_id: int, ip: str, core_id: str,
                node_id: int | None) -> str:
    raw = f"{int(user_id)}|{ip}|{core_id}|{node_id if node_id is not None else 'master'}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _connection_key(row: dict[str, Any], started: datetime) -> str:
    raw = "|".join((
        str(row.get("node_id") if row.get("node_id") is not None else "master"),
        str(row.get("core_id") or ""), str(row.get("account_id") or ""),
        str(row.get("ip") or "-"), started.isoformat(),
    ))
    return hashlib.sha256(raw.encode()).hexdigest()


def _traffic(metadata: dict[str, Any]) -> tuple[int, int]:
    """Return client upload/download only when a driver exposes real counters."""
    try:
        upload = int(metadata.get("uplink_bytes")
                     or metadata.get("session_rx_bytes") or 0)
        download = int(metadata.get("downlink_bytes")
                       or metadata.get("session_tx_bytes") or 0)
    except (TypeError, ValueError):
        return 0, 0
    return max(0, upload), max(0, download)


def _record_poll_sync(runtime, rows: list[dict[str, Any]], now: datetime,
                      reset_after_seconds: int) -> dict[tuple[int, str], datetime]:
    sources: dict[str, dict[str, Any]] = {}
    for row in rows:
        ip = row.get("ip")
        if not ip:
            continue
        key = _source_key(int(row["user_id"]), str(ip), str(row["core_id"]),
                          row.get("node_id"))
        current = sources.get(key)
        connected = _aware(row.get("connected_at"), now)
        if current is None or connected < current["connected_at"]:
            sources[key] = {**row, "source_key": key,
                            "connected_at": connected}
    if not sources:
        return {}

    with runtime.session_factory() as session:
        existing = {
            item.source_key: item for item in session.execute(
                select(IPActivityModel).where(
                    IPActivityModel.source_key.in_(list(sources)))
            ).scalars()
        }
        first_by_ip: dict[tuple[int, str], datetime] = {}
        for key, source in sources.items():
            connected = source["connected_at"]
            item = existing.get(key)
            if item is None:
                item = IPActivityModel(
                    source_key=key, user_id=int(source["user_id"]),
                    ip=str(source["ip"]), core_id=str(source["core_id"]),
                    node_id=source.get("node_id"), first_seen=connected,
                    active_since=connected, last_seen=now,
                )
                session.add(item)
            else:
                prior_seen = _aware(item.last_seen, now)
                if (now - prior_seen).total_seconds() > reset_after_seconds:
                    item.active_since = connected
                else:
                    item.active_since = min(_aware(item.active_since, now), connected)
                item.first_seen = min(_aware(item.first_seen, now), connected)
                item.last_seen = now
                # A deleted/re-created node can make an old FK null; the
                # authenticated current observation is authoritative.
                item.node_id = source.get("node_id")
            active_since = _aware(item.active_since, connected)
            pair = (int(source["user_id"]), str(source["ip"]))
            first_by_ip[pair] = min(first_by_ip.get(pair, active_since), active_since)
        session.commit()
        return first_by_ip


async def publish_poll(runtime, rows: list[dict[str, Any]], *, now: datetime,
                       failed_sources: list[str], probed_sources: int,
                       reset_after_seconds: int) -> dict[tuple[int, str], datetime]:
    """Persist IP activity and atomically publish current connection rows."""
    first_by_ip = await asyncio.to_thread(
        _record_poll_sync, runtime, rows, now, reset_after_seconds)
    connections: list[dict[str, Any]] = []
    for row in rows:
        pair = (int(row["user_id"]), str(row.get("ip") or ""))
        started = _aware(
            row.get("connected_at"),
            first_by_ip.get(pair, now),
        )
        metadata = dict(row.get("metadata") or {})
        upload, download = _traffic(metadata)
        connections.append({
            "key": _connection_key(row, started),
            "user_id": int(row["user_id"]),
            "core_id": str(row.get("core_id") or ""),
            "node_id": row.get("node_id"),
            "ip": row.get("ip"),
            # Standard VPN protocols do not carry a trustworthy HWID. Never
            # promote driver IP-derived metadata to device identity.
            "device": None,
            "started_at": started,
            "last_activity": _aware(row.get("last_activity"), now),
            "upload_bytes": upload,
            "download_bytes": download,
            "status": "active",
        })
    connections.sort(key=lambda item: (item["started_at"], item["key"]))
    runtime.monitoring_snapshot = {
        "generated_at": now,
        "failed_sources": tuple(sorted(set(failed_sources))),
        "probed_sources": max(0, int(probed_sources)),
        "connections": tuple(connections),
    }
    return first_by_ip


def _snapshot(runtime) -> dict[str, Any]:
    return getattr(runtime, "monitoring_snapshot", {
        "generated_at": None, "failed_sources": (), "probed_sources": 0,
        "connections": (),
    })


def live_connections(runtime, *, page: int = 1,
                     page_size: int = 100) -> dict[str, Any]:
    snap = _snapshot(runtime)
    all_rows = list(snap.get("connections") or ())
    total = len(all_rows)
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    start = (page - 1) * page_size
    selected = all_rows[start:start + page_size]
    user_ids = {int(row["user_id"]) for row in selected}
    node_ids = {int(row["node_id"]) for row in selected
                if row.get("node_id") is not None}
    with runtime.session_factory() as session:
        users = dict(session.execute(
            select(UserModel.id, UserModel.username).where(UserModel.id.in_(user_ids))
        ).all()) if user_ids else {}
        nodes = dict(session.execute(
            select(NodeModel.id, NodeModel.name).where(NodeModel.id.in_(node_ids))
        ).all()) if node_ids else {}
    now = datetime.now(timezone.utc)
    result = []
    for row in selected:
        started = _aware(row["started_at"], now)
        node_id = row.get("node_id")
        result.append({
            **row,
            "username": users.get(int(row["user_id"])),
            "node_name": "Master" if node_id is None else nodes.get(int(node_id)),
            "started_at": started.isoformat(),
            "last_activity": _aware(row["last_activity"], now).isoformat(),
            "duration_seconds": max(0, int((now - started).total_seconds())),
            "total_bytes": int(row["upload_bytes"]) + int(row["download_bytes"]),
        })
    generated = snap.get("generated_at")
    return {
        "items": result, "total": total, "page": page,
        "page_size": page_size,
        "generated_at": generated.isoformat() if generated else None,
        "failed_sources": list(snap.get("failed_sources") or ()),
        "probed_sources": int(snap.get("probed_sources") or 0),
    }


def enrolled_devices(runtime, *, page: int = 1,
                     page_size: int = 100) -> dict[str, Any]:
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    with runtime.session_factory() as session:
        total = int(session.scalar(select(func.count(SubscriptionDeviceModel.id))) or 0)
        rows = session.execute(
            select(SubscriptionDeviceModel, UserModel.username)
            .join(UserModel, UserModel.id == SubscriptionDeviceModel.user_id)
            .order_by(desc(SubscriptionDeviceModel.last_seen),
                      SubscriptionDeviceModel.id)
            .offset((page - 1) * page_size).limit(page_size)
        ).all()
        items = [{
            "id": row.SubscriptionDeviceModel.id,
            "user_id": row.SubscriptionDeviceModel.user_id,
            "username": row.username,
            "device": row.SubscriptionDeviceModel.device_hint,
            "last_ip": row.SubscriptionDeviceModel.last_ip,
            "core_id": None,
            "node_id": None,
            "node_name": None,
            "first_seen": row.SubscriptionDeviceModel.first_seen.isoformat(),
            "last_seen": row.SubscriptionDeviceModel.last_seen.isoformat(),
            "status": "enrolled",
            "user_agent": row.SubscriptionDeviceModel.user_agent,
        } for row in rows]
    return {"items": items, "total": total, "page": page,
            "page_size": page_size}


def ip_activity(runtime, *, page: int = 1, page_size: int = 100,
                user_id: int | None = None) -> dict[str, Any]:
    from app.platform.ip_limits import load_settings

    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=max(
        15, int(load_settings(runtime)["review_interval_seconds"]) * 2))
    snap = _snapshot(runtime)
    failed = set(snap.get("failed_sources") or ())
    with runtime.session_factory() as session:
        filters = ([IPActivityModel.user_id == int(user_id)]
                   if user_id is not None else [])
        total = int(session.scalar(
            select(func.count(IPActivityModel.id)).where(*filters)) or 0)
        rows = session.execute(
            select(IPActivityModel, UserModel.username, NodeModel.name.label("node_name"))
            .join(UserModel, UserModel.id == IPActivityModel.user_id)
            .outerjoin(NodeModel, NodeModel.id == IPActivityModel.node_id)
            .where(*filters)
            .order_by(desc(IPActivityModel.last_seen), IPActivityModel.id)
            .offset((page - 1) * page_size).limit(page_size)
        ).all()
        pairs = {(row.IPActivityModel.user_id, row.IPActivityModel.ip)
                 for row in rows}
        bans = set(session.execute(
            select(IPBanModel.user_id, IPBanModel.ip).where(
                IPBanModel.active.is_(True), IPBanModel.expires_at > now,
                tuple_(IPBanModel.user_id, IPBanModel.ip).in_(pairs),
            )
        ).all()) if pairs else set()
        items = []
        for row in rows:
            item = row.IPActivityModel
            source_failed = (item.core_id in failed or
                             (item.node_id is not None and
                              f"node:{row.node_name}" in failed))
            if (item.user_id, item.ip) in bans:
                status = "banned"
            elif source_failed:
                status = "unknown"
            elif item.last_seen >= cutoff:
                status = "active"
            else:
                status = "inactive"
            items.append({
                "id": item.id, "user_id": item.user_id,
                "username": row.username, "ip": item.ip,
                "core_id": item.core_id, "node_id": item.node_id,
                "node_name": "Master" if item.node_id is None else row.node_name,
                "first_seen": item.first_seen.isoformat(),
                "active_since": item.active_since.isoformat(),
                "last_seen": item.last_seen.isoformat(), "status": status,
            })
    return {"items": items, "total": total, "page": page,
            "page_size": page_size, "generated_at": (
                snap["generated_at"].isoformat() if snap.get("generated_at") else None),
            "failed_sources": sorted(failed)}
