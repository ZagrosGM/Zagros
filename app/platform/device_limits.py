"""Global device limit + unified online status — ONE pass, all cores.

Device Limit (global, spec §3): a user's devices are the UNION of every
core's view —
  * cores with per-IP session data (softether, wireguard, openvpn, …)
    contribute their distinct IPs (one phone running three protocols from
    the same address is ONE device, not three);
  * cores whose stats answer only "is this account online" (xray's stats
    API has no per-user IP table) contribute ONE presence per online
    account — an honest lower bound, never an invention.
When the union exceeds the user's ``device_limit`` the FOURTH device is
rejected the only way a VPN platform can: the user is suspended (legacy
``limited`` + suspend on every driver) until the count drops back. Only
users Zagros itself limited (``device_limit_disabled`` flag) are revived —
quota-limited/expired/hand-disabled users are never resurrected by this
pass (same contract as the admin consumption cap).

Unified online (spec §4): any core reporting the user online touches
``online_at`` — on the legacy row (what the dashboard shows) AND the
platform projection (what the portal shows). Additive only; nothing here
ever marks a user offline.

Drivers only REPORT (get_online_devices); all decisions live here.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_REVIVE_GUARD_QUOTA = True  # documented constant: revival checks quota+expiry


async def collect_devices_diag(runtime) -> tuple[dict[int, set[str]], list[str]]:
    """collect_devices + which cores FAILED their online read this pass —
    the 'unknown' state of the dashboard indicator (item 14): a user with no
    fresh session is OFFLINE only when every online-capable core answered;
    when some core's API was unreachable their state is honestly UNKNOWN."""
    from app.cores.types import Capability

    manager = runtime.core_manager
    owners = await asyncio.to_thread(runtime.users.account_owners)
    devices: dict[int, set[str]] = {}
    failed: list[str] = []
    if not owners:
        return devices, failed

    for core_id in manager.list_cores():
        if not manager.is_enabled(core_id):
            continue
        try:
            driver = manager.get(core_id)
        except Exception:  # noqa: BLE001 — not loaded: skip honestly
            continue
        if Capability.ONLINE_TRACKING not in driver.metadata.capabilities:
            continue
        try:
            sessions = await driver.get_online_devices(account_ids=None)
        except Exception as exc:  # noqa: BLE001 — one bad core never blocks the pass
            logger.warning("online devices read failed for core %s (pass continues): %s",
                           core_id, exc)
            failed.append(core_id)
            continue
        for sess in sessions or []:
            owner = owners.get((sess.core_id, sess.account_id))
            if owner is None and core_id == "xray":
                owner = await _xray_owner_id(runtime, sess.account_id)
            if owner is None:
                continue  # revoked after the read — honest drop + log elsewhere
            key = str(sess.ip) if sess.ip else f"presence:{sess.core_id}:{sess.account_id}"
            devices.setdefault(owner, set()).add(key)
    return devices, sorted(failed)


async def collect_devices(runtime) -> dict[int, set[str]]:
    """{platform_user_id: {device keys}} across ALL enabled cores.

    Device key = client IP when the core sees one, else one presence per
    online account (honest lower bound for IP-blind cores).
    """
    devices, _failed = await collect_devices_diag(runtime)
    return devices


async def _xray_owner_id(runtime, email: str) -> int | None:
    """Legacy xray emails are ``{legacy_id}.{username}`` — resolve to the
    platform user id via the username suffix (account_owners only knows the
    mirror ids, which append the protocol)."""
    try:
        _legacy_id, username = str(email).split(".", 1)
    except ValueError:
        return None
    row = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    return None if row is None else row.id


async def run_once(runtime) -> dict[str, int]:
    """One enforcement pass; returns counters for logs/tests."""
    from app.db import GetDB
    from app.db.models import User as LegacyUser
    from app.models.user import UserStatus

    devices_by_user, failed_cores = await collect_devices_diag(runtime)
    stats = {"online": 0, "limited": 0, "revived": 0}
    now_ts = datetime.now(timezone.utc).timestamp()
    # item 14: publish the raw material of the dashboard's online indicator —
    # the freshest collect result + which cores were unreachable while taking it
    try:
        await runtime.kv.set_value("online.last_collect", {
            "ts": now_ts,
            "failed_cores": failed_cores,
            "online_user_ids": sorted(pid for pid, keys in devices_by_user.items() if keys),
        })
    except Exception as exc:  # noqa: BLE001 — indicator degrades, never blocks enforcement
        logger.debug("online snapshot persist failed: %s", exc)

    with GetDB() as db:
        rows = db.query(LegacyUser).all()
        for row in rows:
            platform_row = await asyncio.to_thread(
                runtime.users.get_user_by_username, row.username)
            if platform_row is None:
                continue  # projection pending: bridge sync will create it
            devices = devices_by_user.get(platform_row.id, set())

            # unified online (additive only)
            if devices:
                _touch_online(db, row)
                _touch_platform_online(runtime, platform_row.id)
                stats["online"] += 1

            limit = int(getattr(row, "device_limit", None) or 0)
            if limit <= 0:
                continue  # unlimited: nothing to enforce
            count = len(devices)

            if (row.status == UserStatus.active and count > limit
                    and not getattr(row, "device_limit_disabled", False)):
                await _limit_user(db, row, runtime, count, limit)
                stats["limited"] += 1
            elif (row.status == UserStatus.limited
                    and getattr(row, "device_limit_disabled", False)
                    and count <= limit
                    and _revivable(row, now_ts)):
                await _revive_user(db, row, runtime, count, limit)
                stats["revived"] += 1
        db.commit()
    if any(stats.values()):
        logger.info("device-limit pass: %d online, %d limited, %d revived",
                    stats["online"], stats["limited"], stats["revived"])
    return stats


def _revivable(row: Any, now_ts: float) -> bool:
    """Never resurrect a user who is ALSO out of quota or past expiry."""
    if _REVIVE_GUARD_QUOTA:
        if row.data_limit and (row.used_traffic or 0) >= row.data_limit:
            return False
    if row.expire and row.expire <= now_ts:
        return False
    return True


def _touch_online(db, row: Any) -> None:
    row.online_at = datetime.utcnow()


def _touch_platform_online(runtime, platform_id: int) -> None:
    try:
        from sqlalchemy import update

        from app.persistence.models import UserModel

        with runtime.session_factory() as s:
            s.execute(
                update(UserModel)
                .where(UserModel.id == platform_id)
                .values(online_at=datetime.now(timezone.utc))
            )
            s.commit()
    except Exception as exc:  # noqa: BLE001 — portal freshness is best-effort
        logger.warning("platform online touch failed for %s: %s", platform_id, exc)


async def _limit_user(db, row: Any, runtime, count: int, limit: int) -> None:
    from app import xray
    from app.db import update_user_status
    from app.models.user import UserStatus

    row.device_limit_disabled = True
    db.flush()
    try:
        xray.operations.remove_user(row)  # cut the built-in core too
    except Exception as exc:  # noqa: BLE001 — xray down: DB truth still leads
        logger.warning("xray removal for device-limited %s failed: %s",
                       row.username, exc)
    update_user_status(db, row, UserStatus.limited)
    await _sync_bridge(runtime, row)
    logger.info('User "%s" limited — %d devices online (global device limit=%d)',
                row.username, count, limit)


async def _revive_user(db, row: Any, runtime, count: int, limit: int) -> None:
    from app import xray
    from app.db import update_user_status
    from app.models.user import UserStatus

    row.device_limit_disabled = False
    db.flush()
    try:
        xray.operations.update_user(row)  # put the built-in core back
    except Exception as exc:  # noqa: BLE001
        logger.warning("xray re-add for revived %s failed: %s", row.username, exc)
    update_user_status(db, row, UserStatus.active)
    await _sync_bridge(runtime, row)
    logger.info('User "%s" revived — back under device limit (%d<=%d)',
                row.username, count, limit)


async def _sync_bridge(runtime, row: Any) -> None:
    try:
        from app.platform import provisioning

        await provisioning.sync_user(runtime, row, None)
    except Exception as exc:  # noqa: BLE001 — never fail the pass
        logger.warning("device-limit bridge sync failed for %s: %s",
                       row.username, exc)
