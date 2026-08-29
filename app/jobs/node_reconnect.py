"""Keep every node reachable — automatically, and across panel restarts.

Adding a node only records intent: the agent is installed afterwards, by hand,
on a machine this panel cannot see. Nothing then moved the row out of
``pending``, so a node stayed half-added until an operator found the right
button. A panel restart had the same hole from the other side: the pairing
survives in the database, but nothing re-proved it, so every node came back
looking stale until someone touched it.

This job closes both:

* **periodic** — a node that is not connected is retried on a backoff ladder,
  so one that is simply not installed yet is not hammered; connected nodes
  get a heartbeat every few cycles so health and inventory stay honest.
* **on boot** — :func:`boot_reconnect` runs the same pass immediately, which
  is what makes a panel restart a non-event for every paired node.

Failures are recorded on the node row (``last_error``) rather than logged into
oblivion, so the UI can say *why* a node is stuck.
"""
from __future__ import annotations

import asyncio
import threading
import time

from app import logger, scheduler
from app.nodes.service import native_nodes, reconnect

# Short enough that a node finishing its install shows up while the operator is
# still looking at the page; long enough to stay out of the way.
_SWEEP_SECONDS = 45
# Heartbeat healthy nodes on a slower cadence: that is a liveness proof, not a
# poll loop, and every call is a signed round-trip to another machine.
_HEALTH_EVERY_CYCLES = 8
# Backoff for nodes that keep failing: 45s → 90s → 3m → 5m (then 5m).
_BACKOFF = (45.0, 90.0, 180.0, 300.0)

_lock = threading.Lock()
_cycles = 0
_next_due: dict[int, float] = {}
_failures: dict[int, int] = {}


async def _sweep(runtime, *, force: bool = False) -> dict[str, int]:
    global _cycles
    with _lock:
        _cycles += 1
        health_cycle = _cycles % _HEALTH_EVERY_CYCLES == 0

    stats = {"checked": 0, "paired": 0, "healthy": 0, "failed": 0}
    for row in native_nodes(runtime):
        node_id = int(row.id)
        was_connected = row.status == "connected"
        # An unpaired node is the one case where patience costs the most: the
        # operator has just run the installer on it and is watching the page.
        # There is nothing to back off from — no credentials to protect, no
        # socket to spare — so it is retried on every sweep. Only nodes that
        # are genuinely down (they have credentials and stopped answering)
        # earn a backoff.
        paired = bool(row.agent_identity and row.agent_credentials_enc)
        if was_connected and not health_cycle and not force:
            continue

        now = time.monotonic()
        with _lock:
            if paired and not force and now < _next_due.get(node_id, 0.0):
                continue
            _next_due[node_id] = now + _SWEEP_SECONDS
        stats["checked"] += 1

        try:
            view = await reconnect(runtime, node_id)
        except Exception as exc:  # noqa: BLE001 — one node never blocks the rest
            with _lock:
                failures = _failures.get(node_id, 0) + 1
                _failures[node_id] = failures
                _next_due[node_id] = now + _BACKOFF[
                    min(failures - 1, len(_BACKOFF) - 1)]
            stats["failed"] += 1
            # One line when an outage starts, not one per retry: the detail is
            # on the node row (last_error) where the UI can show it.
            if failures == 1 or force:
                logger.warning("node '%s' (%s) is unreachable: %s",
                               row.name, row.address, exc)
            else:
                logger.debug("node %s reconnect failed: %s", row.name, exc)
            continue

        with _lock:
            _failures.pop(node_id, None)
            _next_due.pop(node_id, None)
        if was_connected:
            stats["healthy"] += 1
        else:
            stats["paired"] += 1
            logger.info("node '%s' is now %s (%s)", view.name, view.status,
                        view.address)
    return stats


def node_reconnect() -> None:
    """Scheduler entry point (sync) — no-op without a platform runtime."""
    try:
        import app as _app

        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # noqa: BLE001 — jobs must never crash the scheduler
        runtime = None
    if runtime is None:
        return
    try:
        stats = asyncio.run(_sweep(runtime))
    except Exception as exc:  # noqa: BLE001
        logger.warning("node reconnect sweep failed: %s", exc)
        return
    if stats["failed"]:
        logger.info("node reconnect: %d node(s) paired, %d healthy, %d failing",
                    stats["paired"], stats["healthy"], stats["failed"])


async def boot_reconnect(runtime) -> None:
    """One pass right after boot, so a restart never leaves nodes stale."""
    try:
        stats = await _sweep(runtime, force=True)
    except Exception as exc:  # noqa: BLE001 — boot must not fail over a node
        logger.warning("node reconnect at boot failed: %s", exc)
        return
    logger.info("node reconnect at boot: %d node(s) checked — %d reachable, "
                "%d failing", stats["checked"],
                stats["paired"] + stats["healthy"], stats["failed"])


scheduler.add_job(node_reconnect, "interval", seconds=_SWEEP_SECONDS,
                  id="node_reconnect", coalesce=True, max_instances=1)
logger.info("node reconnect sweep scheduled (%ss)", _SWEEP_SECONDS)
