"""Admin permission matrix column on the LEGACY schema (separate engine).

Revision ID: 0022_admin_permissions
Revises: 0021_build_artifact

f-panel-5: ``admins.permissions`` (TEXT NULL) stores the per-admin panel
permission document ({"v":1,"sections":{...},"inbounds":[...]|null}).
NULL = the historical default: a non-sudo admin may use every section
except sudo-only admin management; sudo admins bypass the matrix entirely.

Same splitting contract as 0004_admin_governance: the legacy stack lives on
``SQLALCHEMY_DATABASE_URL`` (NOT the Alembic P3 bind), so this revision
applies an idempotent ``ALTER TABLE ... ADD COLUMN`` on the legacy engine.
Fresh installs already carry the column through ``create_all``.
"""
from __future__ import annotations

import os

from alembic import op  # noqa: F401  (kept for tooling parity; P3 bind unused)

revision = "0022_admin_permissions"
down_revision = "0021_build_artifact"
branch_labels = None
depends_on = None

_LEGACY_URL_FALLBACK = "sqlite:///db.sqlite3"  # identical to config.py


def _legacy_url() -> str:
    return os.environ.get("SQLALCHEMY_DATABASE_URL") or _LEGACY_URL_FALLBACK


def upgrade() -> None:
    from sqlalchemy import create_engine, inspect, text

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            existing = {c["name"] for c in inspect(conn).get_columns("admins")}
            if "permissions" in existing:
                return  # fresh create_all already shipped the column
            conn.execute(text(
                "ALTER TABLE admins ADD COLUMN permissions TEXT NULL"))
            print("admins.permissions column added")
    finally:
        engine.dispose()


def downgrade() -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE admins DROP COLUMN permissions"))
    except Exception:  # noqa: BLE001 — best-effort reverse
        pass
    finally:
        engine.dispose()
