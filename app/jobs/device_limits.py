"""Five-second scheduler tick for independent source-IP enforcement.

The service reads the configured review interval and skips intermediate ticks
when an operator chooses a value above five seconds. HWID enrollment is
request-time and therefore needs no polling job.
"""
from __future__ import annotations

import asyncio

from app import logger, scheduler


def review_ip_limits() -> None:
    try:
        import app as _app
        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # jobs must never crash the scheduler
        runtime = None
    if runtime is None:
        return
    try:
        from app.platform.ip_limits import run_once
        asyncio.run(run_once(runtime))
    except Exception as exc:  # noqa: BLE001
        logger.warning("IP-limit pass failed: %s", exc)


# Keep the historical job id so an in-process upgrade replaces rather than
# duplicates it. Minimum supported detection time is five seconds.
scheduler.add_job(review_ip_limits, "interval",
                  seconds=5, id="device_limits", replace_existing=True,
                  coalesce=True, max_instances=1)

logger.info("cross-core IP-limit reconciler scheduled (5s base tick)")
