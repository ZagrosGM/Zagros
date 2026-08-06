"""Global device limit on the LEGACY schema (separate engine).

Revision ID: 0006_device_limit
Revises: 0005_template_core_access

``users.device_limit`` — max distinct simultaneous devices across ALL
cores (NULL = unlimited), and ``users.device_limit_disabled`` — the
auto-revive marker for users Zagros limited because of device overflow
(same contract as ``admin_limit_disabled``).

Same idempotency contract as ``0004``/``0005``: fresh installs already own
these columns via ``0002_legacy_schema``'s ``create_all(checkfirst=True)``
with current metadata; on pre-existing databases this applies the ALTERs
on the legacy engine (SQLALCHEMY_DATABASE_URL), never the platform bind.
"""
from __future__ import annotations

import os

from alembic import op  # noqa: F401  (kept for tooling parity; P3 bind unused)

revision = "0006_device_limit"
down_revision = "0005_template_core_access"
branch_labels = None
depends_on = None

_LEGACY_URL_FALLBACK = "sqlite:///db.sqlite3"  # identical to config.py

_COLUMNS = (
    ("device_limit", "INTEGER"),
    ("device_limit_disabled", "BOOLEAN NOT NULL DEFAULT 0"),
)


def _legacy_url() -> str:
    return os.environ.get("SQLALCHEMY_DATABASE_URL") or _LEGACY_URL_FALLBACK


def _existing_columns(conn, table: str) -> set[str]:
    from sqlalchemy import inspect

    return {c["name"] for c in inspect(conn).get_columns(table)}


def upgrade() -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            existing = _existing_columns(conn, "users")
            for name, ddl in _COLUMNS:
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))
                    print(f"device limit column added: users.{name}")
    finally:
        engine.dispose()


def downgrade() -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            existing = _existing_columns(conn, "users")
            for name, _ddl in _COLUMNS:
                if name in existing:
                    conn.execute(text(f"ALTER TABLE users DROP COLUMN {name}"))
    finally:
        engine.dispose()
