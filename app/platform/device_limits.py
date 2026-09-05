"""Unified online collection plus a v1.0.3 compatibility entry point.

v1.0.4 deliberately separates the concepts previously conflated here:
``app.platform.ip_limits`` handles online source IPs without suspending an
account, while ``app.platform.device_enrollment`` handles stable subscription
HWIDs. The collection helpers remain for dashboard presence compatibility.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
logger = logging.getLogger(__name__)


async def collect_devices_diag(runtime) -> tuple[dict[int, set[str]], list[str], int]:
    """collect_devices + pass diagnostics for the dashboard indicator:

    RETURNS ``(devices, failed_cores, probed_core_count)``.

    * ``failed_cores`` — cores that CLAIMED online tracking but whose read
      failed this pass (their absence of evidence is honestly UNKNOWN);
    * ``probed_core_count`` — online-capable cores that answered. When
      ZERO, the panel simply has no online API on this deployment (every
      enabled core lacks the capability) and presence must be reported as
      UNKNOWN, never as a fake OFFLINE.
    """
    from app.cores.types import Capability

    manager = runtime.core_manager
    owners = await asyncio.to_thread(runtime.users.account_owners)
    devices: dict[int, set[str]] = {}
    failed: list[str] = []
    probed = 0
    if not owners:
        return devices, failed, probed

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
        probed += 1
        for sess in sessions or []:
            owner = owners.get((sess.core_id, sess.account_id))
            if owner is None and core_id == "xray":
                owner = await _xray_owner_id(runtime, sess.account_id)
            if owner is None:
                continue  # revoked after the read — honest drop + log elsewhere
            key = str(sess.ip) if sess.ip else f"presence:{sess.core_id}:{sess.account_id}"
            devices.setdefault(owner, set()).add(key)

    # Nodes: a user connected through a node is just as online as one on this
    # host, and the session material is identical (drivers report it; the
    # panel only attributes it).
    try:
        from app.nodes.service import collect_node_devices

        node_sessions, node_failed = await collect_node_devices(runtime)
    except Exception as exc:  # noqa: BLE001 — never break local collection
        logger.debug("node device collection unavailable: %s", exc)
        node_sessions, node_failed = [], []
    if node_sessions:
        for item in node_sessions:
            owner = owners.get((item.get("core_id"), item.get("account_id")))
            if owner is None and item.get("core_id") == "xray":
                owner = await _xray_owner_id(runtime, str(item.get("account_id")))
            if owner is None:
                continue
            key = (str(item.get("ip")) if item.get("ip")
                   else f"presence:node{item.get('node_id')}:"
                        f"{item.get('core_id')}:{item.get('account_id')}")
            devices.setdefault(owner, set()).add(key)
        probed += 1
    failed.extend(f"node:{name}" for name in node_failed)
    return devices, sorted(failed), probed


async def collect_devices(runtime) -> dict[int, set[str]]:
    """{platform_user_id: {device keys}} across ALL enabled cores.

    Device key = client IP when the core sees one, else one presence per
    online account (honest lower bound for IP-blind cores).
    """
    devices, _failed, _probed = await collect_devices_diag(runtime)
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


async def publish_online_snapshot(runtime, online_user_ids: set[int],
                                  failed_cores: list[str] | None = None,
                                  probed_cores: int = 0) -> None:
    """Publish/touch unified online state without enforcing either limit."""
    from app.db import GetDB
    from app.db.models import User as LegacyUser
    from sqlalchemy import select
    from app.persistence.models import UserModel

    now = datetime.now(timezone.utc)
    ids = {int(value) for value in online_user_ids}
    names: set[str] = set()
    with runtime.session_factory() as session:
        if ids:
            rows = session.execute(
                select(UserModel).where(UserModel.id.in_(ids))
            ).scalars()
            for row in rows:
                row.online_at = now
                names.add(row.username)
        session.commit()
    if names:
        with GetDB() as db:
            db.query(LegacyUser).filter(LegacyUser.username.in_(names)).update(
                {LegacyUser.online_at: now.replace(tzinfo=None)},
                synchronize_session=False,
            )
            db.commit()
    await runtime.kv.set_value("online.last_collect", {
        "ts": now.timestamp(),
        "failed_cores": sorted(failed_cores or []),
        "probed_cores": max(0, int(probed_cores)),
        "online_user_ids": sorted(ids),
    })


async def run_once(runtime) -> dict[str, int]:
    """Compatibility entry point: v1.0.4 enforces the separate IP policy."""
    from app.platform.ip_limits import run_once as run_ip_limits

    return await run_ip_limits(runtime, force=True)
