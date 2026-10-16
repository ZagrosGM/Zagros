"""Template link on the LEGACY users table.

Revision ID: 0027_template_link
Revises: 0026_reseller_policy

f-templink-1 (installer FR): users remember the template they were created
from (``users.template_id``). A plain indexed INTEGER, deliberately WITHOUT
a foreign key — deleting a template must never cascade into users; a stale
id simply means "that template was removed". NULL = created without a
template (manual or API), which stays the default on every upgraded row.
"""
from __future__ import annotations

from alembic import op  # noqa: F401  (kept for tooling parity; P3 bind unused)

revision = "0027_template_link"
down_revision = "0026_reseller_policy"
branch_labels = None
depends_on = None

_USER_COLUMNS = (
    ("template_id", "INTEGER"),
)
_INDEX = "ix_users_template_id"


def _legacy_url() -> str:
    from app.persistence.alembic._legacy import legacy_url as _shared
    return _shared()


def _existing_columns(conn, table: str) -> set[str]:
    from sqlalchemy import inspect

    return {c["name"] for c in inspect(conn).get_columns(table)}


def upgrade() -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(_legacy_url())
    tname = "users"
    try:
        with engine.begin() as conn:
            from app.persistence.alembic._legacy import table as _t
            existing = _existing_columns(conn, _t(tname))
            if "template_id" not in existing:
                conn.execute(text(
                    f"ALTER TABLE {_t(tname)} ADD COLUMN template_id INTEGER"))
                print(f"{tname}.template_id added")
            idx = {i["name"] for i in __import__("sqlalchemy").inspect(
                conn).get_indexes(_t(tname))}
            if _INDEX not in idx:
                try:
                    conn.execute(text(
                        f"CREATE INDEX {_INDEX} ON {_t(tname)} (template_id)"))
                except Exception:  # noqa: BLE001 — index is an optimization
                    pass
    finally:
        engine.dispose()


def downgrade() -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(_legacy_url())
    try:
        with engine.begin() as conn:
            from app.persistence.alembic._legacy import table as _t
            existing = _existing_columns(conn, _t(tname))
            if "template_id" in existing:
                try:
                    conn.execute(text(f"DROP INDEX {_INDEX}"))
                except Exception:  # noqa: BLE001
                    pass
                conn.execute(text(
                    f"ALTER TABLE {_t(tname)} DROP COLUMN template_id"))
    finally:
        engine.dispose()
