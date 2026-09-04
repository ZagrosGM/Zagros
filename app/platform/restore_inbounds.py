"""Materialize the LISTENERS a foreign backup carries (3x-ui keeps its
inbounds in the database) on the built-in xray core, then converge the
imported users onto them.

Why a separate step: ``restore_service`` is a synchronous, thread-run
importer that only talks to databases. Creating an inbound is a studio
transaction (stage → materialize on the core → persist, under the per-core
lock) that lives in the async runtime — so the API layer runs the row
import first and this module second, and the report tells the operator
exactly what happened to each listener.

Honesty rules:
* an inbound whose tag already exists is left alone (idempotent re-import);
* a listener the core refuses (port clash, untranslatable combo) is
  reported by tag with the core's own message — never a silent skip;
* nothing here touches the imported users' credentials: legacy proxies
  serve every inbound of their protocol (no ``excluded_inbounds``), so once
  the listener exists the user is on it; the platform mirror is refreshed
  so the portal/subscription reflects it immediately.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

XRAY_CORE_ID = "xray"


def _hosts_by_tag(snapshot_hosts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for host in snapshot_hosts or []:
        tag = str(host.get("inbound_tag") or "").strip()
        if tag:
            grouped.setdefault(tag, []).append(host)
    return grouped


def _write_legacy_hosts(tag: str, hosts: list[dict[str, Any]]) -> int:
    """Replace the panel default host row of a freshly created inbound with
    the entry points the source advertised (CDN front / real port / path).
    The legacy ``hosts`` table is what the xray subscription generator reads
    (Marzban parity) — the platform ``core_hosts`` table is skipped for xray
    by design. Returns the number of rows written."""
    from app.db import GetDB, crud
    from app.models.proxy import ProxyHost as ProxyHostModify

    models = []
    for host in hosts:
        if host.get("is_disabled"):
            continue
        data = {
            "remark": str(host.get("remark") or tag)[:256],
            "address": str(host.get("address") or "{SERVER_IP}")[:256],
            "port": host.get("port"),
            "sni": host.get("sni"),
            "host": host.get("host"),
            "path": host.get("path"),
            "security": host.get("security") or "inbound_default",
            "allowinsecure": bool(host.get("allowinsecure")),
            "is_disabled": False,
        }
        fp = host.get("fingerprint")
        if fp:
            data["fingerprint"] = fp
        try:
            models.append(ProxyHostModify(**data))
        except Exception as exc:  # noqa: BLE001 — one bad row must not kill the tag
            logger.warning("restore: host row for %s dropped (%s): %s", tag, exc, data)
    if not models:
        return 0
    with GetDB() as db:
        crud.update_hosts(db, tag, models)
    try:
        from app import xray as _xray

        _xray.hosts.update()
    except Exception:  # noqa: BLE001 — rows are persisted; cache refreshes on reload
        pass
    return len(models)


async def materialize_imported_inbounds(runtime, snapshot, report: dict[str, Any],
                                        *, usernames: list[str] | None = None) -> dict[str, Any]:
    """Create ``snapshot.inbounds`` on the xray core and converge users.

    ``report`` is the ``RestoreReport.to_dict()`` payload; counts/steps/
    warnings are appended in place and the same dict is returned.
    """
    from app.studio.service import InboundSpec, StudioConflictError, StudioError

    specs = list(getattr(snapshot, "inbounds", None) or [])
    counts = report.setdefault("counts", {})
    steps = report.setdefault("steps", [])
    warnings = report.setdefault("warnings", [])
    counts.setdefault("inbounds_found", len(specs))
    counts.setdefault("inbounds_created", 0)
    counts.setdefault("inbounds_existing", 0)
    counts.setdefault("inbounds_failed", 0)
    counts.setdefault("hosts_written", 0)
    if not specs:
        return report

    try:
        driver = runtime.core_manager.get(XRAY_CORE_ID)
    except Exception as exc:  # noqa: BLE001
        warnings.append(
            f"{len(specs)} inbound(s) found in the backup but the xray core is not "
            f"available here ({exc.__class__.__name__}) — create them in Inbounds → "
            "Add inbound; the imported users will pick them up automatically.")
        counts["inbounds_failed"] = len(specs)
        return report

    from app.platform.routers import _cascade_grants, _materialize_hook

    hosts_by_tag = _hosts_by_tag(getattr(snapshot, "hosts", None) or [])
    created: list[str] = []
    for spec in specs:
        tag = str(spec.get("tag") or "").strip()
        if not tag:
            continue
        if not spec.get("enabled", True):
            warnings.append(f"inbound '{tag}' is disabled in the source — not created")
            continue
        settings = dict(spec.get("settings") or {})
        try:
            inbound = InboundSpec(tag=tag, protocol=str(spec["protocol"]),
                                  port=int(spec["port"]), listen=spec.get("listen"),
                                  settings=settings)
        except Exception as exc:  # noqa: BLE001 — pydantic message names the field
            counts["inbounds_failed"] += 1
            warnings.append(f"inbound '{tag}' could not be described: {exc}")
            continue
        try:
            result = await runtime.studio.wizard_create(
                driver, inbound, _materialize_hook(runtime, XRAY_CORE_ID, driver))
        except StudioConflictError:
            # same tag, different settings: the operator's listener wins —
            # the imported users are already served by whatever is there
            counts["inbounds_existing"] += 1
            warnings.append(
                f"inbound '{tag}' already exists with different settings — kept as is")
            continue
        except StudioError as exc:
            counts["inbounds_failed"] += 1
            warnings.append(f"inbound '{tag}' was refused: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001 — HTTPException(422) from the hook
            detail = getattr(exc, "detail", None) or str(exc)
            counts["inbounds_failed"] += 1
            warnings.append(f"inbound '{tag}' (port {spec.get('port')}) was not created: {detail}")
            continue
        if not result.valid:
            counts["inbounds_failed"] += 1
            warnings.append(f"inbound '{tag}' is invalid for xray: {'; '.join(result.errors[:3])}")
            continue
        if not result.changed:
            counts["inbounds_existing"] += 1
            continue
        counts["inbounds_created"] += 1
        created.append(tag)
        try:
            await _cascade_grants(runtime, XRAY_CORE_ID)
        except Exception:  # noqa: BLE001 — cascade is best-effort by contract
            pass
        for note in spec.get("notes") or []:
            warnings.append(f"inbound '{tag}': {note}")
        rows = hosts_by_tag.get(tag) or []
        if rows:
            try:
                counts["hosts_written"] += await asyncio.to_thread(
                    _write_legacy_hosts, tag, rows)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"inbound '{tag}': host entries were not written: {exc}")

    if created:
        steps.append(
            f"{len(created)} inbound(s) created on the xray core: {', '.join(created)}")
    if counts["inbounds_existing"]:
        steps.append(f"{counts['inbounds_existing']} inbound(s) already existed")

    # converge the imported users: the legacy xray path attaches every user
    # to the inbounds of its protocol on restart, the platform mirror needs
    # an explicit sync so the portal/subscription shows the new listeners now
    names = list(usernames or [])
    if names and created:
        synced = await _sync_users(runtime, names)
        counts["users_synced"] = synced
        steps.append(f"{synced} imported user(s) attached to the new inbound(s)")
    return report


async def _sync_users(runtime, usernames: list[str]) -> int:
    from app.db import GetDB, crud
    from app.platform import provisioning

    def _load(name: str):
        with GetDB() as db:
            row = crud.get_user(db, name)
            if row is None:
                return None
            for proxy in row.proxies:
                _ = [i.tag for i in proxy.excluded_inbounds]
            _ = getattr(row.admin, "username", None)
            db.expunge(row)
            return row

    synced = 0
    for name in usernames:
        row = await asyncio.to_thread(_load, name)
        if row is None:
            continue
        try:
            await provisioning.sync_user(runtime, row, None)
            synced += 1
        except Exception as exc:  # noqa: BLE001 — keep converging the rest
            logger.warning("restore: platform sync failed for %s: %s", name, exc)
    return synced
