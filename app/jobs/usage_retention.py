"""Bounded growth for the usage journal (f-usageretain-1).

Installer report: ``usage_records`` receives one row per active
(core, account, node) every 30 seconds and nothing ever shrank it —
~864,000 rows/day at 300 concurrent sessions, ~100 GB/year, with the
dashboard summing the whole table per poll.

Instead of deleting history (the per-user charts read the raw journal),
this job COLLAPSES old rows in place: every (day, user, core, node)
group older than the horizon becomes ONE row carrying the group's sums.
Long-range statistics keep working unchanged (the chart bucketing is
coarser than a day for big ranges anyway), while the daily row cost drops
from ~2,880/account to 1. Growth becomes bounded by ACTIVE days, not by
panel age.

Env: ``USAGE_RECORDS_COLLAPSE_DAYS`` (default 7; ``0`` disables the job).
"""
from __future__ import annotations

import os
import time

from app import logger, scheduler
from app.persistence.models import UsageRecordModel

_COLLAPSE_DAYS_DEFAULT = 7
_BATCH_GROUPS = 400
_MAX_BATCHES_PER_RUN = 100          # a run is bounded even on a huge backlog
_SWEEP_SECONDS = 6 * 3600


def _collapse_days() -> int:
    raw = str(os.environ.get("USAGE_RECORDS_COLLAPSE_DAYS", "") or "").strip()
    try:
        return int(raw) if raw else _COLLAPSE_DAYS_DEFAULT
    except ValueError:
        return _COLLAPSE_DAYS_DEFAULT


def _day_bucket(column, dialect: str):
    # the shared helper keeps the bucketing identical to the statistics page
    from app.platform.statistics import _sql_bucket

    return _sql_bucket(column, 86400, dialect)


def run_usage_retention(session_factory=None) -> int:
    """Collapse pre-horizon journal rows into daily rows; return row count."""
    from sqlalchemy import func, select

    from app.persistence.models import SystemUsageBucketModel, UsageAggregateModel

    days = _collapse_days()
    if days <= 0:
        return 0
    if session_factory is None:
        from app.db.base import SessionLocal as session_factory
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    collapsed = 0
    started = time.monotonic()
    with session_factory() as s:
        dialect = s.bind.dialect.name
        bucket = _day_bucket(UsageRecordModel.recorded_at, dialect).label("day")
        for _batch in range(_MAX_BATCHES_PER_RUN):
            groups = s.execute(
                select(
                    bucket,
                    UsageRecordModel.user_id,
                    UsageRecordModel.core_id,
                    UsageRecordModel.node_id,
                    func.coalesce(func.sum(UsageRecordModel.uplink_bytes), 0),
                    func.coalesce(func.sum(UsageRecordModel.downlink_bytes), 0),
                    func.count(),
                    func.min(UsageRecordModel.recorded_at),
                    func.max(UsageRecordModel.recorded_at),
                    # f-usagecoeff-2: last factor pair seen in the group —
                    # audit trail survives the collapse (raw sums stay raw)
                    func.max(UsageRecordModel.quota_factor),
                    func.max(UsageRecordModel.billing_factor),
                )
                .where(UsageRecordModel.recorded_at < cutoff)
                .group_by(bucket, UsageRecordModel.user_id,
                          UsageRecordModel.core_id, UsageRecordModel.node_id)
                .having(func.count() > 1)
                .limit(_BATCH_GROUPS)
            ).all()
            if not groups:
                break
            for _day, user_id, core_id, node_id, up, down, _n, first, last, qf, bf in groups:
                key = [UsageRecordModel.recorded_at >= first,
                       UsageRecordModel.recorded_at <= last,
                       UsageRecordModel.core_id == core_id]
                key.append(UsageRecordModel.user_id.is_(None) if user_id is None
                           else UsageRecordModel.user_id == user_id)
                key.append(UsageRecordModel.node_id.is_(None) if node_id is None
                           else UsageRecordModel.node_id == node_id)
                removed = s.query(UsageRecordModel).filter(*key).delete(synchronize_session=False)
                s.add(UsageRecordModel(
                    user_id=user_id, core_id=core_id, node_id=node_id,
                    account_id="",  # collapsed marker: details folded per user
                    uplink_bytes=int(up or 0), downlink_bytes=int(down or 0),
                    recorded_at=first,
                    quota_factor=qf, billing_factor=bf,
                ))
                collapsed += max(removed - 1, 0)
            s.commit()
    if collapsed:
        logger.info("usage retention: collapsed %d journal row(s) older "
                    "than %d day(s) into daily summaries (%.1fs)",
                    collapsed, days, time.monotonic() - started)
    return collapsed


scheduler.add_job(run_usage_retention, 'interval',
                  seconds=_SWEEP_SECONDS,
                  id='usage_records_retention',
                  coalesce=True, max_instances=1)
logger.info("usage journal retention scheduled (%.0fh, horizon %s days)",
            _SWEEP_SECONDS / 3600,
            os.environ.get("USAGE_RECORDS_COLLAPSE_DAYS") or _COLLAPSE_DAYS_DEFAULT)
