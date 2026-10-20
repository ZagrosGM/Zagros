from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]


def test_0014_backfills_real_journal_and_query_indexes(tmp_path):
    database = tmp_path / "upgrade.db"
    url = f"sqlite:///{database}"
    env = {**os.environ, "ZAGROS_DATABASE_URL": url}

    def upgrade(target: str) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
             "upgrade", target], cwd=ROOT, env=env, capture_output=True,
            text=True, timeout=300, check=False,
        )
        assert result.returncode == 0, result.stderr

    upgrade("0013_split_ip_device_limits")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO usage_records "
            "(user_id, core_id, account_id, node_id, uplink_bytes, "
            "downlink_bytes, recorded_at) VALUES "
            "(NULL, 'xray', 'a', NULL, 11, 19, '2026-09-05 10:01:00'), "
            "(NULL, 'sing-box', 'b', NULL, 7, 13, '2026-09-05 10:04:00')"
        ))
    upgrade("head")

    inspector = inspect(engine)
    assert {"usage_aggregates", "system_usage_buckets", "ip_activity"} <= set(
        inspector.get_table_names())
    assert "last_ip" in {column["name"] for column in
                         inspector.get_columns("subscription_devices")}
    indexes = {index["name"] for index in inspector.get_indexes("usage_records")}
    assert {"ix_usage_owner_time", "ix_usage_recorded_at",
            "ix_usage_core_time", "ix_usage_node_time"} <= indexes
    with engine.connect() as connection:
        rows = dict(connection.execute(text(
            "SELECT dimension, uplink_bytes + downlink_bytes "
            "FROM usage_aggregates"
        )).all())
        assert rows["system"] == 50
        assert rows["core:xray"] == 30 and rows["core:sing-box"] == 20
        assert rows["node:master"] == 50
        buckets = connection.execute(text(
            "SELECT uplink_bytes, downlink_bytes FROM system_usage_buckets"
        )).all()
        assert buckets == [(18, 32)]
