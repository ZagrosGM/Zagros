"""Zagros initial schema (P3).

Revision ID: 0001_zagros_initial
Revises: —
Create Date: 2026-08-05

The first revision materializes the complete ``app.persistence`` schema on
empty databases. Upgrades FROM legacy Zagros are handled by the separate,
idempotent data importer (``app.persistence.migration``) which runs on top
of this schema — mixing schema creation and data moves in one revision
makes rollbacks unsafe, so they stay separate by design.
"""
from __future__ import annotations

from alembic import op

revision = "0001_zagros_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    import app.persistence.models  # noqa: F401 — register all models
    from app.persistence.base import Base

    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    import app.persistence.models  # noqa: F401
    from app.persistence.base import Base

    Base.metadata.drop_all(bind=op.get_bind())
