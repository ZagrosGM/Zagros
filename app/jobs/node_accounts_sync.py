"""Keep every node's account set equal to the panel's.

A node serves the users the panel tells it about, and nobody was telling it
when the list changed: create a user and the node kept serving yesterday's
accounts, so the new config pointed at the node and simply did not connect —
while every pre-existing user worked, which is exactly how this looked like a
node bug rather than a missing push.

Rather than remember to notify a node from every path that can change a user
(creation, edit, deletion, expiry, a device limit cutting someone off, the
periodic review), this sweep asks what the panel has and compares it with what
each node already received: it pushes where they differ and skips where they
do not. A node that was down, or an agent that restarted and lost its state,
converges on the forced cycle.
"""
from __future__ import annotations

import asyncio

from app import logger, scheduler
from app.nodes.service import fanout_accounts

# Short enough that a user created in the dashboard can connect right away,
# long enough that the comparison (a local read, no node traffic) is noise.
_SYNC_SECONDS = 30
# Re-assert even when nothing changed: a node restart wipes its local state
# and the panel has no other way to notice that.
_FORCE_EVERY_CYCLES = 40


async def _tick(runtime, force: bool) -> None:
    result = await fanout_accounts(runtime, force=force)
    pushed = result.get("pushed") or []
    errors = result.get("errors") or []
    if pushed or errors:
        logger.info(
            "node accounts sync: %d node(s) updated%s", len(pushed),
            f", {len(errors)} failed" if errors else "")


def node_accounts_sync() -> None:
    """Scheduler entry point (sync) — no-op without a platform runtime."""
    global _cycles

    try:
        import app as _app

        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # noqa: BLE001 — jobs must never crash the scheduler
        runtime = None
    if runtime is None:
        return
    _cycles += 1
    try:
        asyncio.run(_tick(runtime, force=_cycles % _FORCE_EVERY_CYCLES == 0))
    except Exception as exc:  # noqa: BLE001
        logger.warning("node accounts sync tick failed: %s", exc)


_cycles = 0

scheduler.add_job(node_accounts_sync, "interval", seconds=_SYNC_SECONDS,
                  id="node_accounts_sync", coalesce=True, max_instances=1)
logger.info("node accounts sync scheduled (%ss)", _SYNC_SECONDS)
