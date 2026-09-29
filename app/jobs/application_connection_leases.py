"""Short fail-closed reconciliation for Application device leases."""
from __future__ import annotations

import asyncio

from app import logger, scheduler


async def _tick(runtime) -> None:
    removed = await runtime.application_connections.sweep()
    if removed:
        logger.info("Application lease sweep removed %d expired/revoked lease(s)",
                    removed)


def application_connection_lease_sweep() -> None:
    try:
        import app as _app
        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # noqa: BLE001
        runtime = None
    if runtime is None:
        return
    try:
        asyncio.run(_tick(runtime))
    except Exception as exc:  # noqa: BLE001 — scheduler must survive failures
        logger.warning("Application lease sweep failed: %s", type(exc).__name__)


scheduler.add_job(
    application_connection_lease_sweep, "interval", seconds=5,
    id="application_connection_lease_sweep", coalesce=True, max_instances=1,
)
logger.info("Application connection lease sweep scheduled (5s)")
