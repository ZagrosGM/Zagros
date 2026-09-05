"""Aggregate Statistics over Zagros' one real usage journal.

System cards read cumulative rows maintained atomically by ``SQLUsageJournal``;
system history reads one five-minute row regardless of user count.  A user's
raw journal rows are grouped by SQL only after an admin opens that user's
Statistics drawer.  No endpoint returns or iterates the full user list.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import BigInteger, Integer, cast, func, select

from app.persistence.models import (
    NodeModel,
    SystemUsageBucketModel,
    UsageAggregateModel,
    UsageRecordModel,
    UserModel,
    UserUsageModel,
)

MAX_CUSTOM_DAYS = 366


@dataclass(frozen=True)
class RangeSpec:
    start: datetime
    end: datetime
    bucket_seconds: int
    period: str


def _parse_datetime(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        result = value
    else:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (result.replace(tzinfo=timezone.utc) if result.tzinfo is None
            else result.astimezone(timezone.utc))


def range_spec(period: str, start: str | datetime | None = None,
               end: str | datetime | None = None,
               *, now: datetime | None = None) -> RangeSpec:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    period = str(period or "day").lower()
    presets = {
        "hour": (timedelta(hours=1), 300),
        "day": (timedelta(days=1), 3600),
        "week": (timedelta(days=7), 86_400),
        "month": (timedelta(days=30), 86_400),
    }
    if period in presets:
        duration, bucket = presets[period]
        return RangeSpec(start=now - duration, end=now,
                         bucket_seconds=bucket, period=period)
    if period != "custom":
        raise ValueError("range must be hour, day, week, month, or custom")
    custom_start, custom_end = _parse_datetime(start), _parse_datetime(end)
    if custom_start is None or custom_end is None:
        raise ValueError("custom range requires start and end")
    if custom_start >= custom_end:
        raise ValueError("custom range start must be before end")
    duration = custom_end - custom_start
    if duration > timedelta(days=MAX_CUSTOM_DAYS):
        raise ValueError(f"custom range cannot exceed {MAX_CUSTOM_DAYS} days")
    if duration <= timedelta(hours=6):
        bucket = 300
    elif duration <= timedelta(days=2):
        bucket = 3600
    elif duration <= timedelta(days=60):
        bucket = 86_400
    else:
        bucket = 604_800
    return RangeSpec(start=custom_start, end=custom_end,
                     bucket_seconds=bucket, period=period)


def _floor(value: datetime, seconds: int) -> datetime:
    stamp = int(value.timestamp())
    return datetime.fromtimestamp((stamp // seconds) * seconds,
                                  tz=timezone.utc)


def _aware(value: Any) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None
            else value.astimezone(timezone.utc))


def _core_names(runtime, core_ids: set[str]) -> dict[str, str]:
    names: dict[str, str] = {}
    for core_id in core_ids:
        try:
            metadata = runtime.core_manager.get(core_id).metadata
            names[core_id] = str(metadata.name or core_id)
        except Exception:
            # The journal identity is still real if a previously used core was
            # later removed. Do not invent a catalog entry.
            names[core_id] = core_id
    return names


def overview(runtime) -> dict[str, Any]:
    with runtime.session_factory() as session:
        aggregates = {row.dimension: row for row in session.execute(
            select(UsageAggregateModel).where(
                (UsageAggregateModel.dimension == "system")
                | UsageAggregateModel.dimension.like("core:%")
                | UsageAggregateModel.dimension.like("node:%")
            )
        ).scalars()}
        used_node_ids = {
            int(key[5:]) for key in aggregates
            if key.startswith("node:") and key != "node:master"
        }
        nodes = dict(session.execute(
            select(NodeModel.id, NodeModel.name).where(
                NodeModel.id.in_(used_node_ids))
        ).all()) if used_node_ids else {}
        total_nodes = int(session.scalar(select(func.count(NodeModel.id))) or 0)
    system = aggregates.get("system")
    upload = int(system.uplink_bytes if system else 0)
    download = int(system.downlink_bytes if system else 0)
    core_ids = {key[5:] for key in aggregates if key.startswith("core:")}
    core_names = _core_names(runtime, core_ids)
    by_core = []
    for core_id in sorted(core_ids):
        row = aggregates[f"core:{core_id}"]
        up, down = int(row.uplink_bytes), int(row.downlink_bytes)
        by_core.append({
            "core_id": core_id, "core_name": core_names[core_id],
            "upload_bytes": up, "download_bytes": down,
            "total_bytes": up + down,
        })
    by_node = []
    for key, row in sorted(aggregates.items()):
        if not key.startswith("node:"):
            continue
        identity = key[5:]
        node_id = None if identity == "master" else int(identity)
        up, down = int(row.uplink_bytes), int(row.downlink_bytes)
        by_node.append({
            "node_id": node_id,
            "node_name": "Master" if node_id is None else nodes.get(node_id, identity),
            "upload_bytes": up, "download_bytes": down,
            "total_bytes": up + down,
        })

    from app.platform.monitoring import _snapshot
    live = _snapshot(runtime)
    connections = list(live.get("connections") or ())
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_traffic_bytes": upload + download,
        "upload_bytes": upload, "download_bytes": download,
        "active_users": len({int(row["user_id"]) for row in connections}),
        "active_connections": len(connections),
        "total_nodes": total_nodes,
        "total_cores": len(runtime.core_manager.list_cores()),
        "traffic_by_core": by_core, "traffic_by_node": by_node,
        "monitoring_generated_at": (
            live["generated_at"].isoformat() if live.get("generated_at") else None),
        "monitoring_partial": bool(live.get("failed_sources")),
        "source": "usage_records",
    }


def system_history(runtime, spec: RangeSpec) -> dict[str, Any]:
    # Include the partially overlapping first five-minute source bucket.
    source_start = _floor(spec.start, 300)
    with runtime.session_factory() as session:
        rows = session.execute(
            select(SystemUsageBucketModel)
            .where(SystemUsageBucketModel.bucket_start >= source_start,
                   SystemUsageBucketModel.bucket_start <= spec.end)
            .order_by(SystemUsageBucketModel.bucket_start)
        ).scalars().all()
    grouped: dict[datetime, list[int]] = {}
    for row in rows:
        bucket = _floor(_aware(row.bucket_start), spec.bucket_seconds)
        values = grouped.setdefault(bucket, [0, 0])
        values[0] += int(row.uplink_bytes)
        values[1] += int(row.downlink_bytes)
    points = [{
        "bucket_start": bucket.isoformat(),
        "upload_bytes": values[0], "download_bytes": values[1],
        "total_bytes": values[0] + values[1],
    } for bucket, values in sorted(grouped.items())]
    return {
        "range": spec.period, "start": spec.start.isoformat(),
        "end": spec.end.isoformat(), "bucket_seconds": spec.bucket_seconds,
        "points": points, "source": "system_usage_buckets",
    }


def user_overview(runtime, username: str) -> dict[str, Any] | None:
    with runtime.session_factory() as session:
        row = session.execute(
            select(UserModel, UserUsageModel)
            .outerjoin(UserUsageModel, UserUsageModel.user_id == UserModel.id)
            .where(UserModel.username == username)
        ).one_or_none()
        if row is None:
            return None
        user, usage = row
        upload = int(usage.uplink_bytes if usage else 0)
        download = int(usage.downlink_bytes if usage else 0)
        limit = int(user.data_limit_bytes) if user.data_limit_bytes else None
        used = upload + download
        remaining = None if limit is None else max(0, limit - used)
        percent = None if limit is None else ((used / limit) * 100 if limit else 0)
        return {
            "user_id": int(user.id), "username": user.username,
            "status": user.status, "total_traffic_bytes": used,
            "upload_bytes": upload, "download_bytes": download,
            "data_limit_bytes": limit, "used_bytes": used,
            "remaining_bytes": remaining, "usage_percentage": percent,
            "updated_at": usage.updated_at.isoformat() if usage else None,
            "source": "user_usage",
        }


def _sql_bucket(column, seconds: int, dialect: str):
    if dialect == "sqlite":
        epoch = cast(func.strftime("%s", column), BigInteger)
        floored = cast(epoch / seconds, Integer) * seconds
        return func.datetime(floored, "unixepoch")
    if dialect in {"mysql", "mariadb"}:
        return func.from_unixtime(
            func.floor(func.unix_timestamp(column) / seconds) * seconds)
    if dialect == "postgresql":
        return func.to_timestamp(
            func.floor(func.extract("epoch", column) / seconds) * seconds)
    raise RuntimeError(f"unsupported Statistics database dialect: {dialect}")


def user_traffic(runtime, user_id: int, spec: RangeSpec) -> dict[str, Any]:
    with runtime.session_factory() as session:
        dialect = session.bind.dialect.name
        bucket = _sql_bucket(UsageRecordModel.recorded_at,
                             spec.bucket_seconds, dialect).label("bucket_start")
        criteria = (
            UsageRecordModel.user_id == int(user_id),
            UsageRecordModel.recorded_at >= spec.start,
            UsageRecordModel.recorded_at <= spec.end,
        )
        history_rows = session.execute(
            select(
                bucket,
                func.coalesce(func.sum(UsageRecordModel.uplink_bytes), 0),
                func.coalesce(func.sum(UsageRecordModel.downlink_bytes), 0),
            ).where(*criteria).group_by(bucket).order_by(bucket)
        ).all()
        core_rows = session.execute(
            select(
                UsageRecordModel.core_id,
                func.coalesce(func.sum(UsageRecordModel.uplink_bytes), 0),
                func.coalesce(func.sum(UsageRecordModel.downlink_bytes), 0),
            ).where(*criteria).group_by(UsageRecordModel.core_id)
            .order_by(UsageRecordModel.core_id)
        ).all()
        node_rows = session.execute(
            select(
                UsageRecordModel.node_id,
                func.coalesce(func.sum(UsageRecordModel.uplink_bytes), 0),
                func.coalesce(func.sum(UsageRecordModel.downlink_bytes), 0),
            ).where(*criteria).group_by(UsageRecordModel.node_id)
            .order_by(UsageRecordModel.node_id)
        ).all()
        node_ids = {int(node_id) for node_id, _up, _down in node_rows
                    if node_id is not None}
        nodes = dict(session.execute(
            select(NodeModel.id, NodeModel.name).where(NodeModel.id.in_(node_ids))
        ).all()) if node_ids else {}

    core_ids = {str(core_id) for core_id, _up, _down in core_rows}
    names = _core_names(runtime, core_ids)
    history = [{
        "bucket_start": _aware(bucket_start).isoformat(),
        "upload_bytes": int(up), "download_bytes": int(down),
        "total_bytes": int(up) + int(down),
    } for bucket_start, up, down in history_rows]
    by_core = [{
        "core_id": str(core_id), "core_name": names[str(core_id)],
        "upload_bytes": int(up), "download_bytes": int(down),
        "total_bytes": int(up) + int(down),
    } for core_id, up, down in core_rows]
    by_node = [{
        "node_id": int(node_id) if node_id is not None else None,
        "node_name": ("Master" if node_id is None
                      else nodes.get(int(node_id), str(node_id))),
        "upload_bytes": int(up), "download_bytes": int(down),
        "total_bytes": int(up) + int(down),
    } for node_id, up, down in node_rows]
    upload = sum(item["upload_bytes"] for item in by_core)
    download = sum(item["download_bytes"] for item in by_core)
    return {
        "range": spec.period, "start": spec.start.isoformat(),
        "end": spec.end.isoformat(), "bucket_seconds": spec.bucket_seconds,
        "upload_bytes": upload, "download_bytes": download,
        "total_bytes": upload + download,
        "points": history, "traffic_by_core": by_core,
        "traffic_by_node": by_node, "source": "usage_records",
    }
