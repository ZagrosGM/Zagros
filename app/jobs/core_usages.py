"""Scheduler shim for the cross-core usage recorder (app.platform.usage_recorder).

Folds every configured core's per-account usage deltas into the ONE shared
quota the user actually has: legacy ``used_traffic`` (the master counter all
review/quota flows enforce) + the platform quota/journal. Business logic
lives in the recorder service; drivers only report counters.
"""
from __future__ import annotations

from app import logger, scheduler
from app.platform.usage_recorder import record_core_usages

scheduler.add_job(record_core_usages, 'interval',
                  seconds=30, id='core_usage_recorder',
                  coalesce=True, max_instances=1)

logger.info("core usage recorder scheduled (30s)")
