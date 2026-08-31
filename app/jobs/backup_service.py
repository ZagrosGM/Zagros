"""Scheduler shim for the scheduled backup service.

A lightweight tick decides *whether* the configured schedule is due — the
archive itself is built by :mod:`app.platform.backup_service`. Presets and
operator-written cron expressions go through the same matcher, so "daily at 3"
and ``0 3 * * *`` are the same thing to us.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app import logger, scheduler
from app.platform.backup_service import cron_matches

_TICK_SECONDS = 60
_GRACE_MINUTES = 5   # a late tick must still fire the due run


def run_scheduled_backup() -> None:
    """Sync entry point — safe no-op without a platform runtime."""
    try:
        import app as _app

        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # noqa: BLE001 — jobs must never crash the scheduler
        runtime = None
    if runtime is None:
        return
    try:
        _tick(runtime)
    except Exception as exc:  # noqa: BLE001
        logger.error(f"backup service tick failed: {exc}")


def _due(settings, now: datetime) -> bool:
    """True when the schedule wants a run in this (or a very recent) minute."""
    if not settings.enabled or not settings.bot_token or not settings.chat_id:
        return False
    expression = settings.cron_expression()
    for offset in range(_GRACE_MINUTES):
        moment = now.replace(second=0, microsecond=0) - \
            __import__("datetime").timedelta(minutes=offset)
        if cron_matches(expression, moment):
            return True
    return False


def _already_ran(state, now: datetime) -> bool:
    """Guard against double-firing within the same minute window."""
    if not state.last_run_at:
        return False
    return (now.timestamp() - state.last_run_at) < _TICK_SECONDS * 2


def _tick(runtime) -> None:
    from app.platform.backup_service import run_once

    store = getattr(runtime, "backup_service", None)
    if store is None:
        return
    settings, state = store.load()
    if not settings.enabled:
        return
    now = datetime.now(timezone.utc)
    if not _due(settings, now) or _already_ran(state, now):
        return
    logger.info("backup service: scheduled run starting")
    result = run_once(runtime)
    logger.info(f"backup service: run finished — {result.get('ok')} "
                f"{result.get('archive', '')} delivered={result.get('delivered')}")


scheduler.add_job(run_scheduled_backup, "interval", seconds=_TICK_SECONDS,
                  coalesce=True, max_instances=1,
                  id="backup_service", replace_existing=True)
