"""Scheduler shim for the cross-core usage recorder (app.platform.usage_recorder).

Folds every configured core's per-account usage deltas into the ONE shared
quota the user actually has: legacy ``used_traffic`` (the master counter all
review/quota flows enforce) + the platform quota/journal. Business logic
lives in the recorder service; drivers only report counters.
"""
from __future__ import annotations

from app import logger, scheduler
from app.platform.usage_recorder import record_core_usages

# Provider counters are cumulative and restart-safe; a 30-second sweep loses
# no bytes. Keeping SoftEther management sampling away from a 10-second hot
# loop is important for long-lived SSTP data streams on small VPS instances.
_USAGE_SWEEP_SECONDS = 30
scheduler.add_job(record_core_usages, 'interval',
                  seconds=_USAGE_SWEEP_SECONDS,
                  id='core_usage_recorder',
                  coalesce=True, max_instances=1)

logger.info("unified all-core usage recorder scheduled (%ss)",
            _USAGE_SWEEP_SECONDS)
