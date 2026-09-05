"""real monitoring activity and low-cost usage statistics rollups.

Revision ID: 0014_monitoring_statistics
Revises: 0013_split_ip_device_limits
Create Date: 2026-09-05

The append-only usage journal remains the single accounting source.  This
revision adds small cumulative/system-time rollups maintained in the same
transaction as each journal append, plus indexes for on-demand single-user
aggregation.  No user list is materialized for system Statistics.
"""
from __future__ import annotations

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0014_monitoring_statistics"
down_revision = "0013_split_ip_device_limits"
branch_labels = None
depends_on = None


def _utc(value) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
        timezone.utc).replace(tzinfo=None)


def _bucket_query(dialect: str) -> str:
    if dialect == "sqlite":
        bucket = "datetime((CAST(strftime('%s', recorded_at) AS INTEGER) / 300) * 300, 'unixepoch')"
    elif dialect in {"mysql", "mariadb"}:
        bucket = "FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(recorded_at) / 300) * 300)"
    elif dialect == "postgresql":
        bucket = "TO_TIMESTAMP(FLOOR(EXTRACT(EPOCH FROM recorded_at) / 300) * 300)"
    else:  # Zagros officially supports the three dialects above.
        raise RuntimeError(f"unsupported Statistics migration dialect: {dialect}")
    return (
        f"SELECT {bucket} AS bucket_start, "
        "COALESCE(SUM(uplink_bytes), 0) AS uplink_bytes, "
        "COALESCE(SUM(downlink_bytes), 0) AS downlink_bytes "
        f"FROM usage_records GROUP BY {bucket} ORDER BY {bucket}"
    )


def _backfill(conn) -> None:
    if "usage_records" not in sa.inspect(conn).get_table_names():
        return
    aggregate = sa.table(
        "usage_aggregates",
        sa.column("dimension", sa.String(190)),
        sa.column("uplink_bytes", sa.BigInteger()),
        sa.column("downlink_bytes", sa.BigInteger()),
        sa.column("updated_at", sa.DateTime()),
    )
    buckets = sa.table(
        "system_usage_buckets",
        sa.column("bucket_start", sa.DateTime()),
        sa.column("uplink_bytes", sa.BigInteger()),
        sa.column("downlink_bytes", sa.BigInteger()),
    )
    if conn.scalar(sa.text("SELECT COUNT(*) FROM usage_aggregates")):
        return

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    dimensions: list[dict] = []
    up, down = conn.execute(sa.text(
        "SELECT COALESCE(SUM(uplink_bytes), 0), "
        "COALESCE(SUM(downlink_bytes), 0) FROM usage_records"
    )).one()
    dimensions.append({"dimension": "system", "uplink_bytes": int(up or 0),
                       "downlink_bytes": int(down or 0), "updated_at": now})
    for core_id, core_up, core_down in conn.execute(sa.text(
        "SELECT core_id, COALESCE(SUM(uplink_bytes), 0), "
        "COALESCE(SUM(downlink_bytes), 0) FROM usage_records GROUP BY core_id"
    )):
        dimensions.append({"dimension": f"core:{core_id}",
                           "uplink_bytes": int(core_up or 0),
                           "downlink_bytes": int(core_down or 0),
                           "updated_at": now})
    for node_id, node_up, node_down in conn.execute(sa.text(
        "SELECT node_id, COALESCE(SUM(uplink_bytes), 0), "
        "COALESCE(SUM(downlink_bytes), 0) FROM usage_records GROUP BY node_id"
    )):
        key = "master" if node_id is None else str(int(node_id))
        dimensions.append({"dimension": f"node:{key}",
                           "uplink_bytes": int(node_up or 0),
                           "downlink_bytes": int(node_down or 0),
                           "updated_at": now})
    conn.execute(aggregate.insert(), dimensions)

    rows = [{"bucket_start": _utc(bucket), "uplink_bytes": int(bucket_up or 0),
             "downlink_bytes": int(bucket_down or 0)}
            for bucket, bucket_up, bucket_down in conn.execute(
                sa.text(_bucket_query(conn.dialect.name)))]
    if rows:
        conn.execute(buckets.insert(), rows)


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = set(inspector.get_table_names())

    if "usage_aggregates" not in tables:
        op.create_table(
            "usage_aggregates",
            sa.Column("dimension", sa.String(length=190), primary_key=True),
            sa.Column("uplink_bytes", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("downlink_bytes", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "system_usage_buckets" not in tables:
        op.create_table(
            "system_usage_buckets",
            sa.Column("bucket_start", sa.DateTime(timezone=True), primary_key=True),
            sa.Column("uplink_bytes", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("downlink_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        )
    if "ip_activity" not in tables:
        op.create_table(
            "ip_activity",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("source_key", sa.String(length=64), nullable=False, unique=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("ip", sa.String(length=45), nullable=False),
            sa.Column("core_id", sa.String(length=32), nullable=False),
            sa.Column("node_id", sa.Integer(), nullable=True),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("active_since", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["node_id"], ["nodes.id"], ondelete="SET NULL"),
        )
        op.create_index("ix_ip_activity_last_seen", "ip_activity", ["last_seen"])
        op.create_index("ix_ip_activity_user_last", "ip_activity", ["user_id", "last_seen"])
        op.create_index("ix_ip_activity_core_last", "ip_activity", ["core_id", "last_seen"])
        op.create_index("ix_ip_activity_node_last", "ip_activity", ["node_id", "last_seen"])

    columns = {column["name"] for column in sa.inspect(conn).get_columns(
        "subscription_devices")}
    if "last_ip" not in columns:
        with op.batch_alter_table("subscription_devices") as batch:
            batch.add_column(sa.Column("last_ip", sa.String(length=45), nullable=True))

    existing_indexes = {item["name"] for item in sa.inspect(conn).get_indexes(
        "usage_records")}
    for name, columns in (
        ("ix_usage_owner_time", ["user_id", "recorded_at"]),
        ("ix_usage_recorded_at", ["recorded_at"]),
        ("ix_usage_core_time", ["core_id", "recorded_at"]),
        ("ix_usage_node_time", ["node_id", "recorded_at"]),
    ):
        if name not in existing_indexes:
            op.create_index(name, "usage_records", columns)

    _backfill(conn)


def downgrade() -> None:
    # Monitoring history and accounting rollups are intentionally retained.
    # Dropping them would destroy real operational/accounting data.
    pass
