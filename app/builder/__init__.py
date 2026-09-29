"""White-label build system (panel side).

SQLAlchemy rows (``app.persistence.models``) are the durable source of
truth; Redis/RQ is dispatch transport plus ephemeral live-log streams.
The code that *executes* builds lives in the separate
``Zagros-VPN-Builder`` repository — this package never imports it. The two
sides meet only through the versioned RQ job payload (``JOB_CONTRACT_VERSION``)
and the worker HTTP API (``app.builder.worker_router``).
"""
from __future__ import annotations

# v2 (Phase 14): the job document gained a pinned ``sdk_source`` next to
# ``source`` so lone checkouts resolve the SDK sibling. Bump together
# with ``Zagros-VPN-Builder`` — a v1 worker must never silently build a
# v2 job (and vice versa) without the SDK it cannot resolve.
JOB_CONTRACT_VERSION = 2
# RQ entry point. Referenced BY STRING from the panel so the panel never
# imports builder code; resolved inside the worker process at runtime.
WORKER_JOB_FUNCTION = "zagros_builder.worker.run_build"
