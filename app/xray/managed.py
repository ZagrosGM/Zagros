"""Durable panel-managed xray state (f-routingfix-3).

The Routing and Outbounds pages deploy NATIVE artifacts into the running
legacy Xray config through ``LegacyXrayBackend``: data-plane routing rules
and managed outbounds (admin profiles plus the ``zg-direct``/``zg-block``/
``zg-dns`` action targets). Those mutations lived only in the in-memory
``app.xray.config`` dict — and EVERY ordinary restart rebuilds the config
from the database (``xray.config.include_db_users()``), so the first user
edit / suspend / core-restart silently wiped the deployed routing. Routing
looked deployed, worked for a moment, then "randomly" stopped.

This module is the missing half: the native form of whatever the cores
layer last deployed, persisted next to the core's data dir and merged back
into every rebuilt config. It stores ONLY the already-translated native
dicts (no credentials beyond what a native outbound itself carries — the
same bytes already sit in the running config and are never logged).
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("zagros.xray.managed")

#: Default lives with the rest of the mutable panel state; tests override it.
DEFAULT_STATE_PATH = "/var/lib/zagros/xray-managed.json"


def state_path() -> Path:
    raw = os.environ.get("ZAGROS_XRAY_MANAGED_STATE", "").strip()
    return Path(raw or DEFAULT_STATE_PATH)


def load() -> dict[str, Any]:
    """The persisted managed state, or an empty document.

    A missing/corrupt file degrades to stock behaviour (no managed rules),
    exactly like a panel that never deployed routing — never a crash.
    """
    path = state_path()
    try:
        document = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:  # noqa: BLE001 - degrade, never block
        logger.warning("xray managed state unreadable (%s); ignoring it", exc)
        return {}
    if not isinstance(document, dict):
        return {}
    return {
        "rules": [r for r in (document.get("rules") or []) if isinstance(r, dict)],
        "outbounds": [o for o in (document.get("outbounds") or [])
                      if isinstance(o, dict)],
    }


def save(*, rules: list[dict[str, Any]] | None = None,
         outbounds: list[dict[str, Any]] | None = None) -> None:
    """Merge-save one artifact list; ``None`` keeps the other untouched.

    An EMPTY list is meaningful (the operator deployed zero rules) and is
    persisted as such — passing ``[]`` clears, passing ``None`` preserves.
    """
    document = load()
    if rules is not None:
        document["rules"] = list(rules)
    if outbounds is not None:
        document["outbounds"] = list(outbounds)
    path = state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent),
                                        prefix=".xray-managed-", suffix=".tmp")
        with os.fdopen(fd, "w") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=1)
            handle.write("\n")
        os.replace(tmp_name, path)
    except OSError as exc:  # noqa: BLE001 - deploy must not die on persist
        logger.error("cannot persist xray managed state (%s) — routing will "
                     "vanish on the next core restart", exc)


def clear() -> None:
    try:
        state_path().unlink(missing_ok=True)
    except OSError as exc:  # noqa: BLE001
        logger.warning("cannot remove xray managed state: %s", exc)
