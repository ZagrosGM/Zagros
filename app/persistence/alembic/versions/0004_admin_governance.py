"""Admin governance columns on the LEGACY schema (separate engine).

Revision ID: 0004_admin_governance
Revises: 0003_core_host_extras

Alpha.7 introduces four governance caps on legacy ``admins``
(``max_users``, ``expire_at``, ``traffic_alloc_limit``,
``traffic_consume_limit``) plus the suspension marker on legacy
``users`` (``admin_limit_disabled``).

Same splitting contract as ``0002_legacy_schema``: the legacy stack lives
on ``SQLALCHEMY_DATABASE_URL`` (NOT the Alembic P3 bind), so this revision
applies idempotent ``ALTER TABLE ... ADD COLUMN`` statements on the
legacy engine. Idempotency is mandatory: ``0002`` still calls
``create_all(checkfirst=True)``, which creates the CURRENT metadata
(models already carry these columns) on fresh installs — so on fresh
databases every column already exists and this revision must be a no-op.

Downgrade drops the added columns (best-effort) — the data they hold is
derived from panel configuration, not user traffic, so losing it is safe
and reversible (re-set the limits after re-upgrading).
"""
from __future__ import annotations

import os

from alembic import op  # noqa: F401  (kept for tooling parity; P3 bind unused)

revision = "0004_admin_governance"
down_revision = "0003_core_host_extras"
branch_labels = None
depends_on = None

_LEGACY_URL_FALLBACK = "sqlite:///db.sqlite3"  # identical to config.py

_ADMIN_COLUMNS = (
    ("max_users", "INTEGER"),
    ("expire_at", "DATETIME"),
    ("traffic_alloc_limit", "BIGINT"),
    ("traffic_consume_limit", "BIGINT"),
)
_USER_COLUMNS = (
    ("admin_limit_disabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
)
_MYSQL_DEFAULT_FIX = (
    # MySQL has no native BOOLEAN DEFAULT FALSE in some legacy modes
    ("admin_limit_disabled", "TINYINT(1) NOT NULL DEFAULT 0"),
)


def _legacy_url() -> str:
    return os.environ.get("SQLALCHEMY_DATABASE_URL") or _LEGACY_URL_FALLBACK


def _existing_columns(conn, table: str) -> set[str]:
    from sqlalchemy import inspect

    return {c["name"] for c in inspect(conn).get_columns(table)}


def _add_columns(conn, table: str, columns, *, mysql: bool) -> list[str]:
    from sqlalchemy import text as _text

    added: list[str] = []
    existing = _existing_columns(conn, table)
    for name, ddl in columns:
        if name in existing:
            continue  # fresh create_all already shipped the column
        if mysql and table == "users":
            ddl = dict(_MYSQL_DEFAULT_FIX).get(name, ddl)
        conn.execute(_text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        added.append(f"{table}.{name}")
    return added


def upgrade() -> None:
    from sqlalchemy import create_engine

    engine = create_engine(_legacy_url())
    mysql = engine.dialect.name in ("mysql", "mariadb")
    try:
        with engine.begin() as conn:
            added = _add_columns(conn, "admins", _ADMIN_COLUMNS, mysql=mysql)
            added += _add_columns(conn, "users", _USER_COLUMNS, mysql=mysql)
            if added:
                print(f"admin governance columns added: {', '.join(added)}")
    finally:
        engine.dispose()


def downgrade() -> None:
    from sqlalchemy import create_engine

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            existing_admins = _existing_columns(conn, "admins")
            existing_users = _existing_columns(conn, "users")
            from sqlalchemy import text as _text

            for name, _ddl in _ADMIN_COLUMNS:
                if name in existing_admins:
                    conn.execute(_text(f"ALTER TABLE admins DROP COLUMN {name}"))
            for name, _ddl in _USER_COLUMNS:
                if name in existing_users:
                    conn.execute(_text(f"ALTER TABLE users DROP COLUMN {name}"))
    finally:
        engine.dispose()
