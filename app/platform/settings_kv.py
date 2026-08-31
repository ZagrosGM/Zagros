"""Tiny key/value helpers over the shared settings table.

Used for panel-wide overrides that would otherwise need an ``.env`` edit and a
restart (token lifetime, for example). Deliberately synchronous and dependency
free so any layer — router, job, service — can read it.
"""
from __future__ import annotations

from typing import Any


def load(session_factory, key: str, default: Any = None) -> Any:
    """Read one settings row's JSON value (or *default*)."""
    from app.persistence.models import SettingModel

    try:
        with session_factory() as session:
            row = session.get(SettingModel, key)
            if row is None:
                return default
            return row.value_json if row.value_json is not None else default
    except Exception:  # noqa: BLE001 - settings must never break a request
        return default


def save(session_factory, key: str, value: Any) -> Any:
    """Write one settings row (upsert) and return what was stored."""
    from app.persistence.models import SettingModel

    with session_factory() as session:
        row = session.get(SettingModel, key)
        if row is None:
            session.add(SettingModel(key=key, value_json=value))
        else:
            row.value_json = value
        session.commit()
    return value
