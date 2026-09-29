"""Per-target artifact kind (Phase 17).

Revision ID: 0021_build_artifact
Revises: 0020_build_sdk_source
Create Date: 2026-09-09

``artifact`` (``apk``|``aab``, default ``apk``) on ``build_platform_jobs``
and ``app_build_artifacts``; the job uniqueness widens from
(build, platform, arch) to (build, platform, arch, artifact) so one
build can carry APK and AAB siblings for the same target. The
server default backfills pre-Phase-17 rows as ``apk`` — old jobs keep
working byte-for-byte. The artifacts table keeps its
(build, platform, arch, filename) key: sibling filenames always differ
(``.apk`` vs ``.aab``), so the key stays unique without a rebuild.

Downgrade caveat: restoring the 3-column key fails while sibling rows
exist — delete the ``aab`` jobs first.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021_build_artifact"
down_revision = "0020_build_sdk_source"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {str(col["name"])
            for col in sa.inspect(op.get_bind()).get_columns(table)}


def _job_unique_columns() -> list[str] | None:
    for constraint in sa.inspect(op.get_bind()).get_unique_constraints(
            "build_platform_jobs"):
        if constraint["name"] == "uq_build_jobs_build_target":
            return [str(col) for col in constraint["column_names"]]
    return None


def upgrade() -> None:
    if "build_platform_jobs" in _tables():
        have = _columns("build_platform_jobs")
        key_cols = _job_unique_columns()
        with op.batch_alter_table("build_platform_jobs") as batch:
            if "artifact" not in have:
                batch.add_column(
                    sa.Column("artifact", sa.String(length=16),
                                nullable=False, server_default="apk"))
            if key_cols == ["build_id", "platform", "arch"]:
                batch.drop_constraint("uq_build_jobs_build_target",
                                      type_="unique")
                batch.create_unique_constraint(
                    "uq_build_jobs_build_target",
                    ["build_id", "platform", "arch", "artifact"])
    if "app_build_artifacts" in _tables():
        if "artifact" not in _columns("app_build_artifacts"):
            with op.batch_alter_table("app_build_artifacts") as batch:
                batch.add_column(
                    sa.Column("artifact", sa.String(length=16),
                                nullable=False, server_default="apk"))


def downgrade() -> None:
    if "app_build_artifacts" in _tables():
        if "artifact" in _columns("app_build_artifacts"):
            with op.batch_alter_table("app_build_artifacts") as batch:
                batch.drop_column("artifact")
    if "build_platform_jobs" in _tables():
        have = _columns("build_platform_jobs")
        key_cols = _job_unique_columns()
        with op.batch_alter_table("build_platform_jobs") as batch:
            if key_cols == ["build_id", "platform", "arch", "artifact"]:
                batch.drop_constraint("uq_build_jobs_build_target",
                                      type_="unique")
                batch.create_unique_constraint(
                    "uq_build_jobs_build_target",
                    ["build_id", "platform", "arch"])
            if "artifact" in have:
                batch.drop_column("artifact")
