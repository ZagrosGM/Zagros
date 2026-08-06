"""Scheduler shim for the global device-limit / unified-online pass
(app.platform.device_limits).

ONE limit across every core: the 4th device on a 3-device plan is rejected
(user suspends on ALL cores) until the count drops — plus the unified
``online_at`` the dashboard and portal both read. Business logic lives in
the platform service; drivers only report sessions.
"""
from __future__ import annotations

import asyncio

from app import logger, scheduler


def review_device_limits() -> None:
    """Sync entry point — safe no-op without a platform runtime."""
    try:
        import app as _app

        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # noqa: BLE001 — jobs must never crash the scheduler
        runtime = None
    if runtime is None:
        return
    try:
        from app.platform.device_limits import run_once

        asyncio.run(run_once(runtime))
    except Exception as exc:  # noqa: BLE001
        logger.warning("device-limit pass failed: %s", exc)


scheduler.add_job(review_device_limits, 'interval',
                  seconds=30, id='device_limits',
                  coalesce=True, max_instances=1)

logger.info("device-limit reconciler scheduled (30s)")
