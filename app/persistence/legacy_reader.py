"""Read a legacy Marzban (v0.8.x) database into plain dicts.

Implemented against the DB-API directly (sqlite3) so the reader itself is
dependency-free and testable; the returned :class:`LegacySnapshot` is the
*only* thing the migration mapper consumes (Open/Closed: other dialects
can produce the same snapshot via SQLAlchemy without touching the mapper).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class LegacySnapshot:
    users: list[dict[str, Any]] = field(default_factory=list)
    proxies: list[dict[str, Any]] = field(default_factory=list)
    excluded_inbounds: list[dict[str, Any]] = field(default_factory=list)
    hosts: list[dict[str, Any]] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    admins: list[dict[str, Any]] = field(default_factory=list)
    usage_reset_logs: list[dict[str, Any]] = field(default_factory=list)
    node_user_usages: list[dict[str, Any]] = field(default_factory=list)
    system: dict[str, Any] | None = None
    #: listener definitions a source carries IN its database (3x-ui keeps
    #: every inbound there; Marzban keeps them in xray_config.json, so this
    #: stays empty for Marzban-shaped panels). Each entry is a wizard-shaped
    #: spec: {tag, protocol, port, listen, settings{transport, security,
    #: path, host, service_name, sni, ...}, remark, enabled, notes[]}.
    inbounds: list[dict[str, Any]] = field(default_factory=list)


_TABLES: dict[str, str] = {
    "users": "SELECT * FROM users",
    "proxies": "SELECT * FROM proxies",
    "excluded_inbounds": "SELECT * FROM exclude_inbounds_association",
    "hosts": "SELECT * FROM hosts",
    "nodes": "SELECT * FROM nodes",
    "admins": "SELECT * FROM admins",
    "usage_reset_logs": "SELECT * FROM user_usage_logs",
    "node_user_usages": "SELECT * FROM node_user_usages",
}


def read_legacy_sqlite(path: str | Path) -> LegacySnapshot:
    """Read every migration-relevant table; missing tables yield empty lists
    (older Marzban versions had fewer tables — the mapper decides what
    matters, not the reader)."""
    snapshot = LegacySnapshot()
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        existing = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for attr, sql in _TABLES.items():
            table = sql.rsplit(" ", 1)[-1]
            if table not in existing:
                continue
            rows = [dict(r) for r in conn.execute(sql)]
            setattr(snapshot, attr, rows)
        if "system" in existing:
            row = conn.execute("SELECT * FROM system LIMIT 1").fetchone()
            snapshot.system = dict(row) if row else None
    finally:
        conn.close()
    return snapshot
