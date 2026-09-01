"""native Zagros node identity and encrypted signing credentials.

Revision ID: 0010_native_node_agent
Revises: 0009_policy_routing_domains
Create Date: 2026-08-15

0001 intentionally materializes current metadata on a brand-new database, so
this revision is column-idempotent: upgrades add the fields;
fresh installs already have them before Alembic reaches 0010.
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_native_node_agent"
down_revision = "0009_policy_routing_domains"
branch_labels = None
depends_on = None

_COLUMNS = {
    "agent_type": sa.Column("agent_type", sa.String(32), nullable=False,
                            server_default="legacy_xray"),
    "agent_identity": sa.Column("agent_identity", sa.String(128), nullable=True),
    "certificate_fingerprint": sa.Column("certificate_fingerprint", sa.String(128), nullable=True),
    "agent_credentials_enc": sa.Column("agent_credentials_enc", sa.Text(), nullable=True),
}


def _existing() -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns("nodes")}


def upgrade() -> None:
    existing = _existing()
    missing = [name for name in _COLUMNS if name not in existing]
    if not missing:
        return
    with op.batch_alter_table("nodes") as batch:
        for name in missing:
            batch.add_column(_COLUMNS[name])


def downgrade() -> None:
    existing = _existing()
    present = [name for name in reversed(_COLUMNS) if name in existing]
    if not present:
        return
    with op.batch_alter_table("nodes") as batch:
        for name in present:
            batch.drop_column(name)
