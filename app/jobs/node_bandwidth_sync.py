"""Push per-user speed limits to every paired node.

Shaping is host-local, so a limit the panel computed is only real on a node
once the node has installed it. This job keeps every node's ruleset equal to
the panel's intent: it fires on change (a limit was edited, a user was added
or removed) and periodically regardless, so a node that was down — or an
agent that restarted — converges on its own without operator action.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading

from app import logger, scheduler
from app.nodes.service import bandwidth_limits_payload, sync_bandwidth_limits

# A minute is well inside "the user noticed the limit is missing" and far
# outside "the panel is hammering its nodes".
_SYNC_SECONDS = 60
# Even with no change, re-assert occasionally: a node restart clears its
# local state and the panel has no other trigger to notice that.
_FORCE_EVERY_CYCLES = 15

_lock = threading.Lock()
_last_digest: str | None = None
_cycles = 0


def _digest(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


async def _tick(runtime) -> None:
    global _last_digest, _cycles
    payload = await asyncio.to_thread(bandwidth_limits_payload, runtime)
    digest = _digest(payload)
    with _lock:
        _cycles += 1
        unchanged = digest == _last_digest
        forced = _cycles % _FORCE_EVERY_CYCLES == 0
        _last_digest = digest
        if unchanged and not forced:
            return
        reason = "forced" if forced else "changed"
    result = await sync_bandwidth_limits(runtime)
    pushed = result.get("pushed") or []
    if pushed or result.get("errors"):
        logger.info("node bandwidth sync (%s): %d node(s) updated%s", reason,
                    len(pushed),
                    f", {len(result.get('errors') or [])} failed"
                    if result.get("errors") else "")


def node_bandwidth_sync() -> None:
    """Scheduler entry point (sync) — no-op without a platform runtime."""
    try:
        import app as _app

        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # noqa: BLE001 — jobs must never crash the scheduler
        runtime = None
    if runtime is None:
        return
    try:
        asyncio.run(_tick(runtime))
    except Exception as exc:  # noqa: BLE001
        logger.warning("node bandwidth sync tick failed: %s", exc)


scheduler.add_job(node_bandwidth_sync, "interval", seconds=_SYNC_SECONDS,
                  id="node_bandwidth_sync", coalesce=True, max_instances=1)
logger.info("node bandwidth sync scheduled (%ss)", _SYNC_SECONDS)
