"""Per-user aggregate upload/download bandwidth limits.

Revision ID: 0011_user_bandwidth_limits
Revises: 0010_native_node_agent

Both platform and legacy user projections receive non-null integer Mbps fields.
Zero is unlimited, preserving every upgraded user's current behavior.
"""
from __future__ import annotations

import os

from alembic import op
import sqlalchemy as sa

revision = "0011_user_bandwidth_limits"
down_revision = "0010_native_node_agent"
branch_labels = None
depends_on = None

_COLUMNS = ("download_limit_mbps", "upload_limit_mbps")
_LEGACY_URL_FALLBACK = "sqlite:///db.sqlite3"


def _existing(bind, table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def _legacy_url() -> str:
    return os.environ.get("SQLALCHEMY_DATABASE_URL") or _LEGACY_URL_FALLBACK


def upgrade() -> None:
    bind = op.get_bind()
    current = _existing(bind, "users")
    for name in _COLUMNS:
        if name not in current:
            op.add_column(
                "users",
                sa.Column(name, sa.Integer(), nullable=False, server_default="0"),
            )

    legacy = sa.create_engine(_legacy_url())
    try:
        with legacy.begin() as connection:
            current = _existing(connection, "users")
            for name in _COLUMNS:
                if name not in current:
                    connection.execute(sa.text(
                        f"ALTER TABLE users ADD COLUMN {name} "
                        "INTEGER NOT NULL DEFAULT 0"
                    ))
    finally:
        legacy.dispose()


def downgrade() -> None:
    bind = op.get_bind()
    current = _existing(bind, "users")
    for name in reversed(_COLUMNS):
        if name in current:
            op.drop_column("users", name)

    legacy = sa.create_engine(_legacy_url())
    try:
        with legacy.begin() as connection:
            current = _existing(connection, "users")
            for name in reversed(_COLUMNS):
                if name in current:
                    connection.execute(sa.text(
                        f"ALTER TABLE users DROP COLUMN {name}"
                    ))
    finally:
        legacy.dispose()
