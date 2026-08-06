"""Multi-core template grants on the LEGACY schema (separate engine).

Revision ID: 0005_template_core_access
Revises: 0004_admin_governance

User Templates become multi-core: ``user_templates.core_access`` holds the
grant mapping ``{core_id: [inbound tags]}`` so a template can mix inbounds
from xray, sing-box, wireguard, openvpn, ... — the same mapping a user's
``core_access`` carries at creation time.

Same idempotency contract as ``0004``: ``0002_legacy_schema`` still calls
``create_all(checkfirst=True)`` with CURRENT metadata (which already owns
this column), so on fresh installs this revision must be a no-op; on
pre-existing databases it applies the ALTER on the legacy engine
(SQLALCHEMY_DATABASE_URL), never on the platform bind.
"""
from __future__ import annotations

import os

from alembic import op  # noqa: F401  (kept for tooling parity; P3 bind unused)

revision = "0005_template_core_access"
down_revision = "0004_admin_governance"
branch_labels = None
depends_on = None

_LEGACY_URL_FALLBACK = "sqlite:///db.sqlite3"  # identical to config.py

_COLUMN = ("core_access", "JSON")


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
            name, ddl = _COLUMN
            if name not in _existing_columns(conn, "user_templates"):
                conn.execute(text(f"ALTER TABLE user_templates ADD COLUMN {name} {ddl}"))
                print("template core_access column added: user_templates.core_access")
    finally:
        engine.dispose()


def downgrade() -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            name, _ddl = _COLUMN
            if name in _existing_columns(conn, "user_templates"):
                conn.execute(text(f"ALTER TABLE user_templates DROP COLUMN {name}"))
    finally:
        engine.dispose()
