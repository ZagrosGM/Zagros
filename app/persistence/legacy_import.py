"""Write imported users into the store the panel actually manages.

The migration pipeline imported users into the *platform* database, reported
``users_migrated: 338``, and the operator saw an unchanged user list. Both
sides were telling the truth: the rows existed — just not in the database the
panel's user management runs on.

The panel still keeps users where Marzban kept them (``app.db``: ``users`` +
``proxies``, the tables behind ``/api/users``, subscriptions and config
generation). An import that only writes the platform side produces a user that
cannot be listed, edited, delivered or billed — a success that yields nothing.

So this module writes that half. It is deliberately separate from the
platform-side migration: two stores, two shapes, one snapshot feeding both.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.proxy import ProxyTypes
from app.models.user import UserStatus

logger = logging.getLogger(__name__)

# Protocols the legacy store can represent. A Marzban/3x-ui client on anything
# else (hysteria2, tuic, …) cannot be turned into a proxy row here, and saying
# so is better than dropping it silently.
SUPPORTED_PROTOCOLS: frozenset[str] = frozenset(p.value for p in ProxyTypes)


def _as_settings(value: Any) -> dict[str, Any]:
    """Proxy settings as a mapping.

    Marzban (and 3x-ui) keep settings in a JSON *text* column, so the reader
    hands back a string. Stored as a string, the panel's response model
    rejects the row and ``/api/users`` answers 500 — the import looks fine and
    the user list is simply unreachable.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def protocol_supported(name: Any) -> bool:
    return str(name or "").strip().lower() in SUPPORTED_PROTOCOLS


def _coerce_status(raw: Any) -> UserStatus:
    try:
        return UserStatus(str(raw or "active").strip().lower())
    except ValueError:
        return UserStatus.active


VALID_RESET_STRATEGIES = frozenset({"no_reset", "day", "week", "month", "year"})


def _coerce_strategy(raw: Any) -> str:
    """An unrecognised reset strategy must not become a failed INSERT."""
    value = str(raw or "no_reset").strip().lower()
    return value if value in VALID_RESET_STRATEGIES else "no_reset"


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def import_users(snapshot: Any, session_factory, *, admin_id: int | None = None,
                 dry_run: bool = False) -> dict[str, Any]:
    """Create one panel user per imported user, carrying its proxies over.

    Idempotent by username: importing the same archive twice must not create
    duplicates. Returns counts plus the warnings the operator needs — most
    importantly which protocols could not be represented.
    """
    from app.db.models import Proxy, User  # legacy store

    report: dict[str, Any] = {
        "created": 0, "skipped_existing": 0, "proxies_created": 0,
        "proxies_unsupported": 0, "unsupported_protocols": [], "conflicts": [],
        "warnings": [],
    }
    proxy_types = {p.value: p for p in ProxyTypes}

    with session_factory() as session:
        # The username column is NOCASE-unique, so "Admin" and "admin" are the
        # same name here. Comparing case-sensitively let a 3x-ui "admin" through
        # on top of a Marzban "Admin" and the INSERT failed with a UNIQUE
        # violation — which aborted the whole import with a 500.
        existing = {str(name).lower() for (name,)
                    in session.execute(select(User.username)).all()}
        for entry in snapshot.users:
            username = str(entry.get("username") or "").strip()
            if not username:
                continue
            if username.lower() in existing:
                report["skipped_existing"] += 1
                continue

            proxies = [p for p in (snapshot.proxies or [])
                       if str(p.get("user_id")) == str(entry.get("id"))]
            usable = [p for p in proxies if protocol_supported(p.get("type"))]
            for skipped in (p for p in proxies if not protocol_supported(p.get("type"))):
                report["proxies_unsupported"] += 1
                name = str(skipped.get("type") or "unknown")
                if name not in report["unsupported_protocols"]:
                    report["unsupported_protocols"].append(name)

            if dry_run:
                report["created"] += 1
                report["proxies_created"] += len(usable)
                existing.add(username.lower())
                continue

            user = User(
                username=username,
                status=_coerce_status(entry.get("status")),
                used_traffic=_as_int(entry.get("used_traffic")) or 0,
                data_limit=_as_int(entry.get("data_limit")),
                data_limit_reset_strategy=_coerce_strategy(
                    entry.get("data_limit_reset_strategy")),
                expire=_as_int(entry.get("expire")),
                device_limit=_as_int(entry.get("device_limit")),
                download_limit_mbps=_as_int(entry.get("download_limit_mbps")) or 0,
                upload_limit_mbps=_as_int(entry.get("upload_limit_mbps")) or 0,
                note=(entry.get("note") or "")[:500] or None,
                admin_id=admin_id,
            )
            for proxy in usable:
                user.proxies.append(Proxy(
                    type=proxy_types[str(proxy.get("type")).strip().lower()],
                    settings=_as_settings(proxy.get("settings")),
                ))
                report["proxies_created"] += 1
            session.add(user)
            try:
                # One row per commit: a single rejected username must not take
                # the other three hundred down with it.
                session.commit()
                existing.add(username.lower())
                report["created"] += 1
            except IntegrityError:
                session.rollback()
                report["skipped_existing"] += 1
                report["conflicts"].append(username)

    if report["proxies_unsupported"]:
        report["warnings"].append(
            f"{report['proxies_unsupported']} client(s) used protocols this panel "
            f"cannot store ({', '.join(report['unsupported_protocols'][:6])}); those "
            "users were imported without a proxy.")
    if report["skipped_existing"]:
        report["warnings"].append(
            f"{report['skipped_existing']} user(s) already existed and were left alone.")
    if report["conflicts"]:
        report["warnings"].append(
            f"{len(report['conflicts'])} user(s) could not be stored "
            f"({', '.join(report['conflicts'][:6])}) — the rest were imported.")
    logger.info("legacy import: %s", {k: v for k, v in report.items() if isinstance(v, int)})
    return report
