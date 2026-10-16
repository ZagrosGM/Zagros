"""Reseller creation policy on the LEGACY admins table.

Revision ID: 0026_reseller_policy
Revises: 0025_usage_indexes

f-reseller-policy-1 (installer FR): three optional creation-side policy
columns for non-sudo admins —

  * allowed_template_ids    TEXT    JSON list of user_template ids; when
                                    set the admin may ONLY create users
                                    from these templates (server-enforced).
  * max_user_duration_days  BIGINT  no user may expire further than this
                                    many days from now.
  * clamp_user_expiry       BOOLEAN clamp a user's expiry to the admin's
                                    own expire_at instead of rejecting.

All three are NULL on every existing row = policy disabled, so the upgrade
changes no behaviour until an operator sets them. Same splitting contract
as 0004: idempotent ADD COLUMN on the legacy engine (fresh installs get
the columns from create_all and this revision is a no-op).
"""
from __future__ import annotations

from alembic import op  # noqa: F401  (kept for tooling parity; P3 bind unused)

revision = "0026_reseller_policy"
down_revision = "0025_usage_indexes"
branch_labels = None
depends_on = None

_ADMIN_COLUMNS = (
    ("allowed_template_ids", "TEXT"),
    ("max_user_duration_days", "BIGINT"),
    ("clamp_user_expiry", "BOOLEAN"),
)


def _legacy_url() -> str:
    from app.persistence.alembic._legacy import legacy_url as _shared
    return _shared()


def _existing_columns(conn, table: str) -> set[str]:
    from sqlalchemy import inspect

    return {c["name"] for c in inspect(conn).get_columns(table)}


def _add_columns(conn, table: str, columns) -> list[str]:
    from sqlalchemy import text as _text

    added: list[str] = []
    existing = _existing_columns(conn, table)
    for name, ddl in columns:
        if name in existing:
            continue  # fresh create_all already shipped the column
        conn.execute(_text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        added.append(f"{table}.{name}")
    return added


def upgrade() -> None:
    from sqlalchemy import create_engine

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            from app.persistence.alembic._legacy import table as _t
            added = _add_columns(conn, _t("admins"), _ADMIN_COLUMNS)
            if added:
                print(f"reseller policy columns added: {', '.join(added)}")
    finally:
        engine.dispose()


def downgrade() -> None:
    from sqlalchemy import create_engine

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            from app.persistence.alembic._legacy import table as _t
            existing = _existing_columns(conn, _t("admins"))
            from sqlalchemy import text as _text

            for name, _ddl in _ADMIN_COLUMNS:
                if name in existing:
                    conn.execute(
                        _text(f"ALTER TABLE {_t('admins')} DROP COLUMN {name}"))
    finally:
        engine.dispose()
