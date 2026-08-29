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
import threading

from sqlalchemy import update

logger = logging.getLogger(__name__)
_pass_lock = threading.Lock()


def _baseline_key(core_id: str, account_id: str) -> str:
    return f"{core_id}:{account_id}"


_XRAY_PROTOCOL_SUFFIXES = frozenset({"vmess", "vless", "trojan", "shadowsocks"})


def _provider_owner_aliases(
    owners: dict[tuple[str, str], int],
) -> dict[tuple[str, str], int]:
    """Add provider-native identities to the platform attribution map.

    Legacy Xray emits one stats identity ``<legacy-id>.<username>`` shared by
    every Xray protocol, while delivery rows are
    ``<legacy-id>.<username>.<protocol>``.  Requiring an exact row match made
    every Xray UsageRecord ownerless.  Alias only known protocol suffixes and
    only when every matching row belongs to the same user, so malformed or
    cross-user identities fail closed rather than leaking usage.
    """
    expanded = dict(owners)
    candidates: dict[tuple[str, str], set[int]] = {}
    for (core_id, account_id), user_id in owners.items():
        if core_id != "xray":
            continue
        prefix, dot, protocol = account_id.rpartition(".")
        if dot and prefix and protocol in _XRAY_PROTOCOL_SUFFIXES:
            candidates.setdefault((core_id, prefix), set()).add(user_id)
    for key, user_ids in candidates.items():
        if len(user_ids) == 1:
            expanded[key] = next(iter(user_ids))
    return expanded


def _account_ids_for_core(
    owners: dict[tuple[str, str], int], core_id: str,
) -> list[str]:
    return sorted({account_id for cid, account_id in owners if cid == core_id})


async def restore_baselines(runtime) -> None:
    """Boot-time: hand persisted cumulative baselines back to driver trackers."""
    owners = _provider_owner_aliases(
        await asyncio.to_thread(runtime.users.account_owners)
    )
    by_core: dict[str, dict[str, tuple[int, int]]] = {}
    for (core_id, account_id) in owners:
        by_core.setdefault(core_id, {})[account_id] = (0, 0)
    for core_id, accounts in by_core.items():
        keys = [_baseline_key(core_id, a) for a in accounts]
        try:
            prefix_reader = getattr(runtime.baselines, "get_prefix", None)
            if callable(prefix_reader):
                all_core = await prefix_reader(f"{core_id}:")
                stored = {
                    key: totals for key, totals in all_core.items()
                    if any(
                        key == _baseline_key(core_id, account_id)
                        or key.startswith(
                            _baseline_key(core_id, account_id) + "::"
                        )
                        for account_id in accounts
                    )
                }
            else:
                stored = await runtime.baselines.get_many(keys)
        except Exception as exc:  # noqa: BLE001 — never block boot on baselines
            logger.warning("baseline restore read failed for core %s: %s", core_id, exc)
            continue
        # These managed local providers are torn down and recreated during a
        # graceful panel/container replacement, so their cumulative counters
        # begin a new generation at zero. Restoring the old cursor can lose an
        # entire first transfer when it happens to reach the same value. Xray
        # native-node sub-cursors are external and remain restoreable.
        if core_id in {"xray", "sing-box", "wireguard"}:
            stored = ({key: value for key, value in stored.items()
                       if core_id == "xray" and "::node::" in key})
        if not stored:
            continue
        ready = {key.split(":", 1)[1]: totals for key, totals in stored.items()}
        try:
            runtime.core_manager.get(core_id).restore_usage_baselines(ready)
        except Exception as exc:  # noqa: BLE001
            logger.warning("baseline restore failed for core %s: %s", core_id, exc)


async def record_once(runtime) -> int:
    """One recorder pass across all enabled cores; returns applied delta rows.

    This is the sole per-user counter consumer, including built-in Xray. The
    former legacy Xray scheduler called the same provider with ``reset=True``
    while this recorder sampled cumulative counters, leaving the platform
    quota/journal empty and making ownership impossible to prove. One reader
    and one fold path removes that split-brain/double-count race.
    """
    from app.cores.types import Capability

    manager = runtime.core_manager
    owners = _provider_owner_aliases(
        await asyncio.to_thread(runtime.users.account_owners)
    )
    applied: list = []
    per_user: dict[int, list[int]] = {}
    pending_baselines: dict[str, tuple[int, int]] = {}

    for core_id in manager.list_cores():
        if not manager.is_enabled(core_id):
            continue
        try:
            driver = manager.get(core_id)
        except Exception:  # noqa: BLE001 — not loaded right now: skip honestly
            continue
        if Capability.USAGE_ACCOUNTING not in driver.metadata.capabilities:
            continue
        account_ids = _account_ids_for_core(owners, core_id)
        if not account_ids:
            continue
        try:
            records = await driver.get_usage(account_ids=account_ids)
        except Exception as exc:  # noqa: BLE001 — isolate a broken tick
            logger.warning("usage read failed for core %s (tick skipped): %s", core_id, exc)
            continue
        records = [r for r in (records or []) if r.uplink_bytes or r.downlink_bytes]

        # Capture the cursor after the read, but do not persist it until the
        # corresponding deltas have reached the journal/quota. Persisting the
        # baseline first created a crash window that permanently lost bytes.
        try:
            snapshot = driver.usage_tracker_snapshot(account_ids)
        except Exception:  # noqa: BLE001
            snapshot = {}
        pending_baselines.update({
            _baseline_key(core_id, str(account_id)): (int(totals[0]), int(totals[1]))
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

    # Nodes hold their own cumulative counters and their own baselines, so
    # their deltas are a separate provider: folding them here is what makes a
    # user's quota follow them to whatever server they connect through.
    # They are kept out of ``applied`` until they are durable on purpose: a
    # node-side failure (agent unreachable, node row deleted mid-tick) must
    # never take the local cores' accounting down with it.
    node_applied: list = []
    node_per_user: dict[int, list[int]] = {}
    try:
        from app.nodes.service import collect_node_usage

        for r in await collect_node_usage(runtime):
            owner = owners.get((r.core_id, r.account_id))
            if owner is None:
                continue
            totals = node_per_user.setdefault(owner, [0, 0])
            totals[0] += r.uplink_bytes
            totals[1] += r.downlink_bytes
            node_applied.append(r)
    except Exception as exc:  # noqa: BLE001 — never break the local fold
        logger.warning("node usage collection failed (tick continues): %s", exc)
        node_applied, node_per_user = [], {}

    if not applied and not node_applied:
        if pending_baselines:
            await runtime.baselines.set_many(pending_baselines)
        return 0

    if applied:
        await runtime.usage_journal.append(applied, owners)
        for user_id, (up, down) in per_user.items():
            await runtime.quota.add(user_id, up, down)

    if node_applied:
        try:
            await runtime.usage_journal.append(node_applied, owners)
            for user_id, (up, down) in node_per_user.items():
                await runtime.quota.add(user_id, up, down)
        except Exception as exc:  # noqa: BLE001 — local bytes are already safe
            logger.warning("node usage could not be recorded this tick: %s", exc)
            node_applied, node_per_user = [], {}
        else:
            for user_id, (up, down) in node_per_user.items():
                totals = per_user.setdefault(user_id, [0, 0])
                totals[0] += up
                totals[1] += down
            applied.extend(node_applied)

    # Fold into the legacy master/admin counters in one transaction.  This is
    # still the quota/review API's compatibility view, but it no longer owns a
    # second provider read. ``online_at`` follows real attributed growth.
    try:
        from datetime import datetime

        from app.db import GetDB
        from app.db.models import Admin as LegacyAdmin
        from app.db.models import User as LegacyUser

        with GetDB() as db:
            for user_id, (up, down) in per_user.items():
                row = await asyncio.to_thread(runtime.users.get_user, user_id)
                if row is None:
                    continue
                amount = int(up) + int(down)
                legacy = db.query(LegacyUser).filter(
                    LegacyUser.username == row.username
                ).one_or_none()
                if legacy is None:
                    continue
                db.execute(
                    update(LegacyUser)
                    .where(LegacyUser.id == legacy.id)
                    .values(
                        used_traffic=LegacyUser.used_traffic + amount,
                        online_at=datetime.utcnow(),
                    )
                )
                if legacy.admin_id is not None:
                    db.execute(
                        update(LegacyAdmin)
                        .where(LegacyAdmin.id == legacy.admin_id)
                        .values(users_usage=LegacyAdmin.users_usage + amount)
                    )
            db.commit()
    except Exception as exc:  # noqa: BLE001 — legacy side is optional in tests
        logger.warning("legacy counter fold failed (platform quota still applied): %s", exc)

    # Platform quota/journal accepted the batch: its provider cursors may now
    # advance. A restart before this write can replay (over-count) but can no
    # longer skip bytes; durable idempotent batches are the next schema-level
    # hardening step.
    if pending_baselines:
        await runtime.baselines.set_many(pending_baselines)

    logger.info("core usage recorder applied %d deltas across %d users",
                len(applied), len(per_user))
    return len(applied)


def record_core_usages() -> None:
    """Scheduler entry point (sync) — safe no-op without a platform runtime."""
    if not _pass_lock.acquire(blocking=False):
        return
    try:
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
    finally:
        _pass_lock.release()


async def flush_before_shutdown(runtime) -> int:
    """Serialize one final provider read before managed cores are stopped."""
    await asyncio.to_thread(_pass_lock.acquire)
    try:
        return await record_once(runtime)
    finally:
        _pass_lock.release()
