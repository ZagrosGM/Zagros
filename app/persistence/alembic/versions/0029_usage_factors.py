"""Applied usage-coefficient factors on journal rows (audit trail).

Revision ID: 0029_usage_factors
Revises: 0028_template_inbounds_json

f-usagecoeff-2 (v1.1.3): the FR asks the applied factors to be stored "with
each record (or with the daily rollup) for auditability". The journal keeps
RAW bytes (statistics stay physical); these two nullable columns carry the
quota/billing factors that were applied to each delta when it was folded
into the user's quota and the reseller's invoice. NULL = recorded before
this revision or read straight from a driver without coefficients.
The daily collapse (usage_retention) carries the last known pair forward.
"""
from __future__ import annotations

from alembic import op  # noqa: F401  (kept for tooling parity)
import sqlalchemy as sa  # noqa: F401

revision = "0029_usage_factors"
down_revision = "0028_template_inbounds_json"
branch_labels = None
depends_on = None

_TABLE = "usage_records"
_COLUMNS = (("quota_factor", "FLOAT"), ("billing_factor", "FLOAT"))


def _existing_columns(conn, table: str) -> set[str]:
    from sqlalchemy import inspect

    return {c["name"] for c in inspect(conn).get_columns(table)}


def upgrade() -> None:
    conn = op.get_bind()
    existing = _existing_columns(conn, _TABLE)
    for name, decl in _COLUMNS:
        if name in existing:
            continue
        # NULL = "no coefficient was applied / unknown" — never 0, which
        # would read as "this traffic was free".
        conn.execute(sa.text(
            f"ALTER TABLE {_TABLE} ADD COLUMN {name} {decl}"))


def downgrade() -> None:
    conn = op.get_bind()
    existing = _existing_columns(conn, _TABLE)
    for name, _decl in _COLUMNS:
        if name in existing:
            conn.execute(sa.text(f"ALTER TABLE {_TABLE} DROP COLUMN {name}"))
