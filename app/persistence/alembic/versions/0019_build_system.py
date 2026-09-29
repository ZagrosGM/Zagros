"""White-label build system tables (Phase 12).

Revision ID: 0019_build_system
Revises: 0018_application_connection_leases
Create Date: 2026-09-08

Additive only: ``app_builds`` + per-platform jobs, immutable artifact
records, worker identities and encrypted build credentials. SQL is the
durable source of truth; Redis/RQ stays transport + ephemeral state.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_build_system"
down_revision = "0018_application_connection_leases"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _indexes(table: str) -> set[str]:
    return {str(row["name"]) for row in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    tables = _tables()

    if "app_builds" not in tables:
        op.create_table(
            "app_builds",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("public_id", sa.String(length=36), nullable=False),
            sa.Column("application_id", sa.Integer(), nullable=False),
            sa.Column("owner_admin_id", sa.Integer(), nullable=False),
            sa.Column("version", sa.String(length=32), nullable=False),
            sa.Column("build_number", sa.Integer(), nullable=False),
            sa.Column("source_repo", sa.String(length=512), nullable=False),
            sa.Column("source_revision", sa.String(length=64), nullable=False),
            sa.Column("build_config", sa.JSON(), nullable=False),
            sa.Column("config_digest", sa.String(length=64), nullable=False),
            sa.Column("requested_platforms", sa.JSON(), nullable=False),
            sa.Column("credential_ids", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False,
                      server_default="queued"),
            sa.Column("progress", sa.Integer(), nullable=False,
                      server_default="0"),
            sa.Column("failure_code", sa.String(length=64), nullable=True),
            sa.Column("failure_message", sa.String(length=500), nullable=True),
            sa.Column("log_ref", sa.String(length=1024), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["application_id"], ["applications.id"],
                                    ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["owner_admin_id"], ["admins.id"],
                                    ondelete="RESTRICT"),
            sa.UniqueConstraint("public_id"),
            sa.UniqueConstraint("application_id", "build_number",
                                name="uq_app_builds_app_number"),
        )
        op.create_index("ix_app_builds_application_status", "app_builds",
                        ["application_id", "status"])
        op.create_index("ix_app_builds_owner_status", "app_builds",
                        ["owner_admin_id", "status"])

    if "build_platform_jobs" not in tables:
        op.create_table(
            "build_platform_jobs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("build_id", sa.Integer(), nullable=False),
            sa.Column("platform", sa.String(length=32), nullable=False),
            sa.Column("arch", sa.String(length=32), nullable=False),
            sa.Column("queue_name", sa.String(length=64), nullable=False),
            sa.Column("queue_job_id", sa.String(length=128), nullable=True),
            sa.Column("job_token_hash", sa.String(length=64), nullable=True),
            sa.Column("job_token_valid", sa.Boolean(), nullable=False,
                      server_default="1"),
            sa.Column("status", sa.String(length=20), nullable=False,
                      server_default="queued"),
            sa.Column("worker_id", sa.String(length=128), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("failure_code", sa.String(length=64), nullable=True),
            sa.Column("failure_message", sa.String(length=500), nullable=True),
            sa.Column("log_ref", sa.String(length=1024), nullable=True),
            sa.ForeignKeyConstraint(["build_id"], ["app_builds.id"],
                                    ondelete="CASCADE"),
            sa.UniqueConstraint("build_id", "platform", "arch",
                                name="uq_build_jobs_build_target"),
        )
        op.create_index("ix_build_jobs_build_status", "build_platform_jobs",
                        ["build_id", "status"])
        op.create_index("ix_build_jobs_queue", "build_platform_jobs",
                        ["queue_job_id"])

    if "app_build_artifacts" not in tables:
        op.create_table(
            "app_build_artifacts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("build_id", sa.Integer(), nullable=False),
            sa.Column("platform", sa.String(length=32), nullable=False),
            sa.Column("arch", sa.String(length=32), nullable=False),
            sa.Column("filename", sa.String(length=256), nullable=False),
            sa.Column("rel_path", sa.String(length=1024), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("size_bytes", sa.BigInteger(), nullable=False),
            sa.Column("signature_ref", sa.String(length=1024), nullable=True),
            sa.Column("sbom_ref", sa.String(length=1024), nullable=True),
            sa.Column("provenance", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["build_id"], ["app_builds.id"],
                                    ondelete="CASCADE"),
            sa.UniqueConstraint("build_id", "platform", "arch", "filename",
                                name="uq_build_artifacts_target_file"),
        )
        op.create_index("ix_build_artifacts_build", "app_build_artifacts",
                        ["build_id"])

    if "build_workers" not in tables:
        op.create_table(
            "build_workers",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("worker_id", sa.String(length=128), nullable=False),
            sa.Column("display_name", sa.String(length=128), nullable=False),
            sa.Column("platform_labels", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False,
                      server_default="pending"),
            sa.Column("api_token_hash", sa.String(length=64), nullable=True),
            sa.Column("register_token_hash", sa.String(length=64),
                      nullable=True),
            sa.Column("register_token_expires_at",
                      sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True),
                      nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("worker_id"),
        )
        op.create_index("ix_build_workers_status", "build_workers",
                        ["status"])

    if "build_credentials" not in tables:
        op.create_table(
            "build_credentials",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("public_id", sa.String(length=36), nullable=False),
            sa.Column("scope", sa.String(length=20), nullable=False),
            sa.Column("owner_ref", sa.String(length=128), nullable=False),
            sa.Column("kind", sa.String(length=32), nullable=False),
            sa.Column("label", sa.String(length=128), nullable=False),
            sa.Column("encrypted_material", sa.Text(), nullable=False),
            sa.Column("envelope_digest", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked", sa.Boolean(), nullable=False,
                      server_default="0"),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("public_id"),
        )
        op.create_index("ix_build_credentials_scope_owner",
                        "build_credentials",
                        ["scope", "owner_ref", "revoked"])


def downgrade() -> None:
    tables = _tables()
    for table in ("build_credentials", "build_workers",
                  "app_build_artifacts", "build_platform_jobs",
                  "app_builds"):
        if table in tables:
            op.drop_table(table)
