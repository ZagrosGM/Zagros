"""Pinned SDK source on builds (Phase 14).

Revision ID: 0020_build_sdk_source
Revises: 0019_build_system
Create Date: 2026-09-08

Additive only: ``sdk_source_repo``/``sdk_source_revision`` on
``app_builds``. Nullable on purpose — pre-Phase-14 rows predate SDK
pinning and stay readable; the service requires both pins for every new
build and the v2 worker refuses job documents without them.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_build_sdk_source"
down_revision = "0019_build_system"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {str(col["name"])
            for col in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if "app_builds" not in _tables():
        return
    have = _columns("app_builds")
    if "sdk_source_repo" not in have:
        op.add_column("app_builds",
                      sa.Column("sdk_source_repo", sa.String(length=512),
                                nullable=True))
    if "sdk_source_revision" not in have:
        op.add_column("app_builds",
                      sa.Column("sdk_source_revision", sa.String(length=64),
                                nullable=True))


def downgrade() -> None:
    if "app_builds" not in _tables():
        return
    have = _columns("app_builds")
    if "sdk_source_revision" in have:
        op.drop_column("app_builds", "sdk_source_revision")
    if "sdk_source_repo" in have:
        op.drop_column("app_builds", "sdk_source_repo")
