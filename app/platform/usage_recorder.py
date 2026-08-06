"""Cross-core usage recorder — the shared-quota pipeline ("P4 recorder").

ONE counter set rules them all: every configured core reports per-account
deltas (drivers convert raw/persistent counters into non-negative deltas via
their in-process trackers), and this module folds each delta into:

* the **legacy master counter** (``users.used_traffic``) — the number every
  review/quota/admin-cap flow already enforces on, so a user over limit via
  Hysteria2 + WireGuard + PPTP traffic suspends exactly like xray traffic;
* the **platform quota store** — the portal reads this view;
* the **usage journal** (analytics, per-core totals);
* the **persistent baseline store** — handed back to driver trackers at boot
  so a panel restart never re-reports a whole counter (exactly-once).

Driver contracts stay untouched (business logic lives here, not in drivers):
a core missing USAGE_ACCOUNTING is skipped quietly; a core that errors on a
single tick is logged and skipped — one bad core never blocks the others.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import update

logger = logging.getLogger(__name__)


def _baseline_key(core_id: str, account_id: str) -> str:
    return f"{core_id}:{account_id}"


async def restore_baselines(runtime) -> None:
    """Boot-time: hand persisted cumulative baselines back to driver trackers."""
    owners = await asyncio.to_thread(runtime.users.account_owners)
    by_core: dict[str, dict[str, tuple[int, int]]] = {}
    for (core_id, account_id) in owners:
        by_core.setdefault(core_id, {})[account_id] = (0, 0)
    for core_id, accounts in by_core.items():
        keys = [_baseline_key(core_id, a) for a in accounts]
        try:
            stored = await runtime.baselines.get_many(keys)
        except Exception as exc:  # noqa: BLE001 — never block boot on baselines
            logger.warning("baseline restore read failed for core %s: %s", core_id, exc)
            continue
        if not stored:
            continue
        ready = {key.split(":", 1)[1]: totals for key, totals in stored.items()}
        try:
            runtime.core_manager.get(core_id).restore_usage_baselines(ready)
        except Exception as exc:  # noqa: BLE001
            logger.warning("baseline restore failed for core %s: %s", core_id, exc)


async def record_once(runtime) -> int:
    """One recorder pass across all enabled cores; returns applied delta rows."""
    from app.cores.manager import BUILTIN_CORE_IDS
    from app.cores.types import Capability

    manager = runtime.core_manager
    owners = await asyncio.to_thread(runtime.users.account_owners)
    applied: list = []
    per_user: dict[int, list[int]] = {}

    for core_id in manager.list_cores():
        if not manager.is_enabled(core_id):
            continue
        if core_id in BUILTIN_CORE_IDS:
            # Double-count guard: built-in engines (xray) are metered by the
            # legacy stack into users.used_traffic already; folding their
            # deltas again here would burn quota at twice the real rate.
            continue
        try:
            driver = manager.get(core_id)
        except Exception:  # noqa: BLE001 — not loaded right now: skip honestly
            continue
        if Capability.USAGE_ACCOUNTING not in driver.metadata.capabilities:
            continue
        account_ids = [a for (cid, a) in owners if cid == core_id]
        if not account_ids:
            continue
        try:
            records = await driver.get_usage(account_ids=account_ids)
        except Exception as exc:  # noqa: BLE001 — isolate a broken tick
            logger.warning("usage read failed for core %s (tick skipped): %s", core_id, exc)
            continue
        records = [r for r in (records or []) if r.uplink_bytes or r.downlink_bytes]

        # persist the tracker's cumulative baseline AFTER the read so the next
        # boot resumes from exactly this point
        try:
            snapshot = driver.usage_tracker_snapshot(account_ids)
        except Exception:  # noqa: BLE001
            snapshot = {}
        if snapshot:
            await runtime.baselines.set_many({
                _baseline_key(core_id, account_id): totals
                for account_id, totals in snapshot.items()
            })

        for r in records:
            owner = owners.get((r.core_id, r.account_id))
            if owner is None:
                continue  # account revoked after the read — honest drop + log
            totals = per_user.setdefault(owner, [0, 0])
            totals[0] += r.uplink_bytes
            totals[1] += r.downlink_bytes
            applied.append(r)

    if not applied:
        return 0

    await runtime.usage_journal.append(applied, owners)
    for user_id, (up, down) in per_user.items():
        await runtime.quota.add(user_id, up, down)

    # fold into the legacy master counter — uses the legacy ORM directly
    try:
        from app.db import GetDB
        from app.db.models import User as LegacyUser

        with GetDB() as db:
            for user_id, (up, down) in per_user.items():
                row = await asyncio.to_thread(runtime.users.get_user, user_id)
                if row is None:
                    continue
                db.execute(
                    update(LegacyUser)
                    .where(LegacyUser.username == row.username)
                    .values(used_traffic=LegacyUser.used_traffic + up + down)
                )
            db.commit()
    except Exception as exc:  # noqa: BLE001 — legacy side is optional in tests
        logger.warning("legacy used_traffic fold failed (quota still applied): %s", exc)

    logger.info("core usage recorder applied %d deltas across %d users",
                len(applied), len(per_user))
    return len(applied)


def record_core_usages() -> None:
    """Scheduler entry point (sync) — safe no-op without a platform runtime."""
    try:
        import app as _app

        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # noqa: BLE001 — jobs must never crash the scheduler
        runtime = None
    if runtime is None:
        return
    try:
        asyncio.run(record_once(runtime))
    except Exception as exc:  # noqa: BLE001
        logger.warning("core usage recorder tick failed: %s", exc)
