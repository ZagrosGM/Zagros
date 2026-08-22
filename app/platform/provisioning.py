"""Legacy↔Platform user bridge + multi-core grant provisioning.

This module is the single writer that keeps a **legacy dashboard user**
(the Marzban-parity master entity: quota, expiry, admin governance, CLI)
and its **platform projection** (portal user + per-core accounts) in sync.

Design rules (contract with the sprint spec):

* One dashboard user may hold accounts on MANY cores — "Marzban inbound
  selection, but multi-core". The xray core stays special: it consumes the
  legacy database directly (``include_db_users``), so for xray we only
  mirror *delivery descriptors* (account rows) into the platform store so
  the Subscription Portal can render xray sections next to the others.
* Drivers stay business-logic-free: this service computes WHAT must exist
  (desired accounts per core/protocol), drivers only provision/suspend/
  resume/delete and may generate credentials into ``account.settings``
  which we then persist (encrypted at rest by the repository layer).
* Everything here is **idempotent** — re-syncing converges, never
  duplicates — and every driver call is best-effort-isolated: one failing
  core raises an error that names the core, never wedges the user.
* Quota stays singular: the legacy ``used_traffic`` counter is the master
  number; we mirror its baseline into the platform quota store so the
  portal shows the SAME figure (per-core usage deltas land in the same
  counters — see ``app/jobs`` review pipeline).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Iterable

from app.cores.types import UserAccount
from app.platform.inbounds import catalog as build_inbound_catalog

logger = logging.getLogger(__name__)

LEGACY_CORE_ID = "xray"


class GrantError(RuntimeError):
    """A driver or catalog rejected a grant — message must name the core."""


async def _drop_usage_baseline(runtime, core_id: str, account_id: str) -> None:
    key = f"{core_id}:{account_id}"
    drop_prefix = getattr(runtime.baselines, "drop_prefix", None)
    if callable(drop_prefix):
        await drop_prefix(key)
    else:
        await runtime.baselines.drop(key)


def platform_account_id(user_id: int, username: str, protocol: str) -> str:
    """Same convention as the Marzban migration importer (§delivery matrix)."""
    return f"{user_id}.{username}.{protocol}"


def _legacy_status(value: Any) -> str:
    return getattr(value, "value", value) or "active"


def _legacy_expire_dt(user: Any) -> datetime | None:
    expire = getattr(user, "expire", None)
    if not expire:
        return None
    try:
        return datetime.fromtimestamp(int(expire), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _legacy_used_bytes(user: Any) -> int:
    used = getattr(user, "used_traffic", None)
    try:
        return max(0, int(used or 0))
    except (TypeError, ValueError):
        return 0


def _platform_admin_id(runtime, user: Any) -> int | None:
    """Map the legacy owner admin to the platform admin row BY USERNAME.

    Legacy admin ids are meaningless on the platform engine (separate
    tables/sequences) — copying them blindly would violate the FK. When the
    platform has no such admin yet, ownership stays NULL (honest unknown);
    the admin-management bridge can backfill it later.
    """
    admin = getattr(user, "admin", None)
    username = getattr(admin, "username", None)
    if not username:
        return None
    from sqlalchemy import select

    from app.persistence.models import AdminModel

    with runtime.session_factory() as s:
        return s.execute(
            select(AdminModel.id).where(AdminModel.username == username)
        ).scalar_one_or_none()


async def sync_platform_user(runtime, user: Any) -> int:
    """Upsert the platform projection of a legacy user; returns platform id.

    ``user`` is the legacy ORM row (``app.db.models.User``). The upsert keeps
    platform-specific fields (app credentials, device limit, auth mode) —
    only mirrored fields are written.
    """
    device_limit = int(getattr(user, "device_limit", 0) or 0) or None
    platform_id = await asyncio.to_thread(
        runtime.users.upsert_user,
        username=user.username,
        status=_legacy_status(user.status),
        data_limit_bytes=(int(getattr(user, "data_limit", 0) or 0) or None),
        expire_at=_legacy_expire_dt(user),
        device_limit=device_limit,
        download_limit_mbps=max(0, int(
            getattr(user, "download_limit_mbps", 0) or 0)),
        upload_limit_mbps=max(0, int(
            getattr(user, "upload_limit_mbps", 0) or 0)),
        admin_id=await asyncio.to_thread(_platform_admin_id, runtime, user),
        note=getattr(user, "note", None),
    )
    # upsert keeps None optional fields by design — but a CLEARED legacy
    # limit must clear the mirror too, so reconcile the exact value:
    await asyncio.to_thread(_reconcile_device_limit, runtime, platform_id,
                            device_limit)
    # Upgrade/bootstrap mirror: never reset an already-live unified quota on
    # every User Edit.  The old reset-then-add sequence raced the recorder and
    # could erase a concurrent core delta.  Bring a missing/older platform row
    # up to the legacy compatibility total, but never move a counter backwards.
    try:
        used = _legacy_used_bytes(user)
        entry = await runtime.quota.get(platform_id)
        current = entry.total_bytes if entry else 0
        if used > current:
            await runtime.quota.add(platform_id, 0, used - current)
    except Exception as exc:  # noqa: BLE001 — quota mirror must not break sync
        logger.warning("quota baseline bootstrap failed for %s: %s", user.username, exc)
    return platform_id


def _reconcile_device_limit(runtime, platform_id: int, value: int | None) -> None:
    """Write the mirrored device_limit verbatim (incl. NULL for "unlimited").

    Separate from upsert_user because its keep-None contract exists to
    protect platform-local fields — the legacy column is the master here.
    """
    from sqlalchemy import update

    from app.persistence.models import UserModel

    with runtime.session_factory() as s:
        s.execute(
            update(UserModel)
            .where(UserModel.id == platform_id)
            .values(device_limit=value)
        )
        s.commit()


def _proxy_rows(user: Any) -> Iterable[tuple[str, dict[str, Any], list[str]]]:
    """(protocol, settings, excluded_tags) from the legacy proxy records."""
    rows: list[tuple[str, dict[str, Any], list[str]]] = []
    for proxy in getattr(user, "proxies", []) or []:
        protocol = getattr(proxy, "type", None)
        protocol = getattr(protocol, "value", protocol)  # enums → plain string
        if not protocol:
            continue
        settings = dict(getattr(proxy, "settings", None) or {})
        excluded = [i.tag for i in getattr(proxy, "excluded_inbounds", []) or []]
        rows.append((protocol, settings, excluded))
    return rows


async def sync_legacy_accounts(runtime, user: Any, platform_id: int) -> None:
    """Mirror the legacy xray proxies as platform delivery accounts.

    No driver calls are made for xray here — the legacy stack already pushes
    users into the xray config; these rows exist so the portal/delivery layer
    renders the xray protocols alongside the other cores.
     Removed proxies are dropped from the mirror (the legacy stack removes
    them from the xray config itself).
    """
    enabled = _legacy_status(user.status) == "active"
    wanted: set[str] = set()
    for protocol, settings, excluded in _proxy_rows(user):
        account_id = platform_account_id(user.id, user.username, protocol)
        wanted.add(account_id)
        body = dict(settings)
        if excluded:
            body["excluded_inbounds"] = excluded
        await asyncio.to_thread(
            runtime.users.upsert_core_account,
            user_id=platform_id, core_id=LEGACY_CORE_ID, account_id=account_id,
            protocol=protocol, enabled=enabled, settings=body,
        )
    current = [a for a in await asyncio.to_thread(
        runtime.users.accounts_of, platform_id, decrypt=False)
        if a["core_id"] == LEGACY_CORE_ID]
    for acc in current:
        if acc["account_id"] not in wanted:
            await asyncio.to_thread(
                runtime.users.delete_account,
                user_id=platform_id, core_id=LEGACY_CORE_ID, account_id=acc["account_id"])
        elif acc["enabled"] != enabled:
            await asyncio.to_thread(
                runtime.users.set_account_enabled,
                user_id=platform_id, core_id=LEGACY_CORE_ID,
                account_id=acc["account_id"], enabled=enabled)


async def _catalog_map(runtime):
    groups = await build_inbound_catalog(runtime)
    return {g.core_id: g for g in groups}


def _resolve_tag_protocols(core_id: str, tags: list[str],
                           catalog: dict[str, Any],
                           *, repair: bool = False) -> dict[str, list[str]]:
    """Map selected inbound tags → {protocol: [tags]} using the live catalog.

    Raises GrantError naming the core when a tag does not exist — the admin
    must never get a silently-empty account. With ``repair=True`` (item 6,
    case B) unknown tags are instead skipped with a logged warning: a grant
    that went STALE (its inbound was deleted) must not 500/422 an unrelated
    User Edit/Save — it self-heals here AND at the source (the studio
    cascade). A payload that was *never valid* still fails loudly at the
    API boundary (repair=False for fresh create/modify validation).
    """
    group = catalog.get(core_id)
    if group is None:
        raise GrantError(f"core '{core_id}' is not available (not installed/enabled)")
    known = {i.tag: i.protocol for i in group.inbounds}
    out: dict[str, list[str]] = {}
    for tag in tags:
        if tag not in known:
            if repair:
                logger.warning("grant repair: dropping dangling inbound tag "
                               "'%s' for core '%s' (valid: %s)",
                               tag, core_id, sorted(known) or "— none configured")
                continue
            raise GrantError(
                f"core '{core_id}' has no inbound '{tag}' "
                f"(valid: {sorted(known) or '— none configured'})")
        out.setdefault(known[tag], []).append(tag)
    return out


async def apply_grants(runtime, user: Any, platform_id: int,
                       grants: dict[str, list[str]], *,
                       repair: bool = False) -> None:
    """Converge the per-core accounts to exactly ``grants`` (non-xray cores).

    ``grants`` maps core_id → selected inbound tags. cores absent from the
    mapping keep their current accounts (PATCH semantics); an explicit empty
    list revokes that core's accounts. ``repair=True`` (storage-healing
    paths only — never the strict fresh-payload validation) drops dangling
    tags instead of raising, per item 6B.
    """
    catalog = await _catalog_map(runtime)
    active = _legacy_status(user.status) == "active"
    current = await asyncio.to_thread(runtime.users.accounts_of, platform_id)

    for core_id, tags in grants.items():
        if core_id == LEGACY_CORE_ID:
            continue  # xray is governed by legacy proxies, not grants
        if core_id not in catalog:
            raise GrantError(f"core '{core_id}' is not available (not installed/enabled)")
        existing = [a for a in current if a["core_id"] == core_id]
        wanted = _resolve_tag_protocols(core_id, list(tags or []), catalog,
                                        repair=repair) if tags else {}
        if repair and tags and not wanted:
            logger.warning("grant for core '%s' contained only dangling tags "
                           "(%s) — leaving its accounts untouched; re-save "
                           "with a valid selection to change them", core_id, tags)
            continue

        if core_id == "softether":
            # Four compatibility transports are four account identities, but
            # provisioning them through create_account opened ~12 rapid
            # localhost vpncmd logins and tripped SoftEther's management DoS
            # guard. Reconcile the complete desired set in ONE authenticated
            # PTY; sync_accounts mints credentials in place for persistence.
            desired_accounts: list[UserAccount] = []
            for protocol, proto_tags in wanted.items():
                account_id = platform_account_id(user.id, user.username, protocol)
                all_proto_tags = [i.tag for i in catalog[core_id].inbounds
                                  if i.protocol == protocol]
                excluded = sorted(set(all_proto_tags) - set(proto_tags))
                previous = next(
                    (a for a in existing
                     if a["protocol"] == protocol and a["account_id"] == account_id),
                    None,
                )
                settings = dict(previous["settings"] if previous else {})
                settings["inbound_tags"] = list(proto_tags)
                if excluded:
                    settings["excluded_inbounds"] = excluded
                else:
                    settings.pop("excluded_inbounds", None)
                desired_accounts.append(UserAccount(
                    user_id=platform_id, username=user.username,
                    account_id=account_id, protocol=protocol,
                    enabled=active, settings=settings,
                ))
            try:
                driver = runtime.core_manager.get(core_id)
                await driver.sync_accounts(desired_accounts)
            except Exception as exc:  # noqa: BLE001
                raise GrantError(
                    f"core '{core_id}' failed to batch-provision accounts: {exc}") from exc
            desired_ids = {account.account_id for account in desired_accounts}
            for acc in existing:
                if acc["account_id"] not in desired_ids:
                    await asyncio.to_thread(
                        runtime.users.delete_account,
                        user_id=platform_id, core_id=core_id,
                        account_id=acc["account_id"])
                    await _drop_usage_baseline(runtime, core_id, acc["account_id"])
            for account in desired_accounts:
                await asyncio.to_thread(
                    runtime.users.upsert_core_account,
                    user_id=platform_id, core_id=core_id,
                    account_id=account.account_id, protocol=account.protocol,
                    enabled=active, settings=dict(account.settings),
                )
            continue

        # revoke what is no longer selected
        for acc in existing:
            protocol = acc["protocol"]
            if protocol not in wanted:
                try:
                    await runtime.core_manager.get(core_id).delete_account(acc["account_id"])
                except Exception as exc:  # noqa: BLE001 — keep converging others
                    raise GrantError(f"core '{core_id}' failed to delete account: {exc}") from exc
                await asyncio.to_thread(
                    runtime.users.delete_account,
                    user_id=platform_id, core_id=core_id, account_id=acc["account_id"])
                await _drop_usage_baseline(runtime, core_id, acc["account_id"])

        # provision / update what is selected
        for protocol, proto_tags in wanted.items():
            account_id = platform_account_id(user.id, user.username, protocol)
            all_proto_tags = [i.tag for i in catalog[core_id].inbounds
                              if i.protocol == protocol]
            excluded = sorted(set(all_proto_tags) - set(proto_tags))
            previous = next(
                (a for a in existing
                 if a["protocol"] == protocol and a["account_id"] == account_id),
                None,
            )
            # Inbound selection is metadata, not credentials. Alpha.7.8 rebuilt
            # settings from tags on every Edit User and silently rotated/lost
            # WireGuard keys, OpenVPN/SSH passwords and sing-box UUIDs. Preserve
            # the encrypted desired state and replace only grant-derived keys.
            settings: dict[str, Any] = dict(previous["settings"] if previous else {})
            settings["inbound_tags"] = list(proto_tags)
            if excluded:
                settings["excluded_inbounds"] = excluded
            else:
                settings.pop("excluded_inbounds", None)
            account = UserAccount(
                user_id=platform_id, username=user.username, account_id=account_id,
                protocol=protocol, enabled=active, settings=settings,
            )
            try:
                driver = runtime.core_manager.get(core_id)
                if previous:
                    await driver.update_account(account)
                else:
                    await driver.create_account(account)
            except Exception as exc:  # noqa: BLE001 — name the failing core
                raise GrantError(f"core '{core_id}' failed to provision account: {exc}") from exc
            await asyncio.to_thread(
                runtime.users.upsert_core_account,
                user_id=platform_id, core_id=core_id, account_id=account_id,
                protocol=protocol, enabled=active, settings=dict(account.settings),
            )


async def sync_grants_enabled(runtime, user: Any, platform_id: int) -> None:
    """Push the legacy active/disabled state onto every platform account."""
    active = _legacy_status(user.status) == "active"
    accounts = await asyncio.to_thread(runtime.users.accounts_of, platform_id, decrypt=False)
    for acc in accounts:
        if acc["enabled"] == active:
            continue
        if acc["core_id"] != LEGACY_CORE_ID:
            try:
                driver = runtime.core_manager.get(acc["core_id"])
                if active:
                    await driver.resume_account(UserAccount(
                        user_id=platform_id, username=user.username,
                        account_id=acc["account_id"], protocol=acc["protocol"],
                        enabled=True, settings={},
                    ))
                else:
                    await driver.suspend_account(acc["account_id"])
            except Exception as exc:  # noqa: BLE001 — row state still converges
                logger.warning("core %s suspend/resume failed for %s: %s",
                               acc["core_id"], user.username, exc)
        await asyncio.to_thread(
            runtime.users.set_account_enabled,
            user_id=platform_id, core_id=acc["core_id"],
            account_id=acc["account_id"], enabled=active)


async def sync_user(runtime, user: Any,
                    grants: dict[str, list[str]] | None = None) -> int:
    """Full convergence: projection + xray mirror + grant diff + status.

    ``grants=None`` keeps current grants (used by status/limit paths);
    an explicit mapping applies the diff (used by create/modify).
    """
    platform_id = await sync_platform_user(runtime, user)
    await sync_legacy_accounts(runtime, user, platform_id)
    if grants is not None:
        # repair=True: Edit/Save re-sends the STORED selection — a grant that
        # dangled since (inbound deleted) must self-heal, not 422 (item 6B).
        await apply_grants(runtime, user, platform_id, grants, repair=True)
    await sync_grants_enabled(runtime, user, platform_id)
    return platform_id


async def remove_user(runtime, username: str) -> None:
    """Delete every core account + the platform projection (best-effort)."""
    row = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        return
    platform_id = row.id
    accounts = await asyncio.to_thread(runtime.users.accounts_of, platform_id, decrypt=False)
    for acc in accounts:
        if acc["core_id"] == LEGACY_CORE_ID:
            continue
        try:
            await runtime.core_manager.get(acc["core_id"]).delete_account(acc["account_id"])
        except Exception as exc:  # noqa: BLE001 — local rows are removed anyway
            logger.warning("core %s delete_account failed for %s: %s",
                           acc["core_id"], username, exc)
        await _drop_usage_baseline(runtime, acc["core_id"], acc["account_id"])
    await asyncio.to_thread(runtime.users.delete_user, platform_id)


async def grants_of(runtime, username: str) -> dict[str, list[str]]:
    """Current grants as core_id → inbound tags (for API responses/UI)."""
    row = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        return {}
    out: dict[str, list[str]] = {}
    for acc in await asyncio.to_thread(runtime.users.accounts_of, row.id):
        if acc["core_id"] == LEGACY_CORE_ID:
            continue  # xray proxies are governed on the legacy side, not grants
        tags = acc["settings"].get("inbound_tags")
        if not tags:
            continue
        out.setdefault(acc["core_id"], [])
        out[acc["core_id"]].extend(t for t in tags if t not in out[acc["core_id"]])
    return out


async def reconcile_accounts_after_inbound_change(runtime, core_id: str) -> dict:
    """Grant cascade when a core's inbound set CHANGED (studio apply /
    wizard — item 6, case A): a grant materialized into an account whose
    ``inbound_tags`` no longer exist must never strand the user.

    * tags still valid → account settings pruned in place (store + driver);
    * NOTHING left → the account is revoked (driver + store), honestly;
    * callers get a small report; failures on one account never abort the
      sweep for the others (logged, counted).
    """
    from collections import Counter
    import copy

    groups = await build_inbound_catalog(runtime)
    group = next((g for g in groups if g.core_id == core_id), None)
    known = {i.tag: i.protocol for i in group.inbounds} if group else {}
    report = Counter()
    try:
        accounts = await asyncio.to_thread(runtime.users.accounts_of_core, core_id)
    except AttributeError:
        return {"skipped": "store cannot list core accounts"}
    for acc in accounts:
        settings = dict(acc.get("settings") or {})
        before = copy.deepcopy(settings)
        current_tags = list(settings.get("inbound_tags") or [])
        kept = [tag for tag in current_tags if tag in known]
        try:
            if current_tags and not kept:
                try:
                    await runtime.core_manager.get(core_id).delete_account(acc["account_id"])
                except Exception as exc:  # noqa: BLE001 — store row still heals
                    logger.warning("inbound cascade: driver delete failed for %s on %s: %s",
                                   acc["account_id"], core_id, exc)
                await asyncio.to_thread(
                    runtime.users.delete_account,
                    user_id=acc["user_id"], core_id=core_id,
                    account_id=acc["account_id"])
                await _drop_usage_baseline(runtime, core_id, acc["account_id"])
                report["revoked"] += 1
                logger.info("inbound cascade: revoked %s on %s — its last "
                            "inbound %s is gone", acc["account_id"], core_id,
                            current_tags)
                continue

            if current_tags and kept != current_tags:
                proto = acc["protocol"]
                all_proto = sorted(tag for tag, protocol in known.items()
                                   if protocol == proto)
                settings["inbound_tags"] = kept
                settings["excluded_inbounds"] = sorted(set(all_proto) - set(kept))
                report["pruned"] += 1
                logger.info("inbound cascade: pruned dangling tags for %s on %s "
                            "(%s → %s)", acc["account_id"], core_id,
                            current_tags, kept)

            # Reconcile every surviving account, including whole-core grants.
            # Adding a WireGuard inbound creates a new per-inbound tunnel
            # address in account.settings; persisting the driver's in-place
            # mutation here is what makes the second profile survive reboot.
            model = UserAccount(
                user_id=acc["user_id"], username="",
                account_id=acc["account_id"], protocol=acc["protocol"],
                enabled=acc["enabled"], settings=settings,
            )
            await runtime.core_manager.get(core_id).update_account(model)
            if model.settings != before:
                await asyncio.to_thread(
                    runtime.users.upsert_core_account,
                    user_id=acc["user_id"], core_id=core_id,
                    account_id=acc["account_id"], protocol=acc["protocol"],
                    enabled=acc["enabled"], settings=model.settings)
                if kept == current_tags:
                    report["hydrated"] += 1
        except Exception as exc:  # noqa: BLE001 — one row must not block the sweep
            report["errors"] += 1
            logger.warning("inbound cascade failed for %s on %s: %s",
                           acc["account_id"], core_id, exc)
    return dict(report)
