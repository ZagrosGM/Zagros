from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select

from app.cores.types import UsageRecord
from app.persistence.base import Base, create_session_factory
from app.persistence.models import (
    CoreModel, NodeModel, SubscriptionDeviceModel,
    SystemUsageBucketModel, UsageAggregateModel, UsageRecordModel,
    UserModel, UserUsageModel,
)
from app.persistence.repositories import SQLUsageJournal
from app.platform.monitoring import (
    enrolled_devices, ip_activity, live_connections, publish_poll,
)
from app.platform.statistics import (
    overview, range_spec, system_history, user_overview, user_traffic,
)


@pytest.fixture()
def runtime(tmp_path):
    sf = create_session_factory(f"sqlite:///{tmp_path / 'monitoring-statistics.db'}")
    Base.metadata.create_all(sf.kw["bind"])
    with sf() as s:
        s.add_all([
            UserModel(id=1, username="alice", status="active", data_limit_bytes=1_000),
            UserModel(id=2, username="bob", status="disabled"),
            NodeModel(id=7, name="edge-a", address="edge.invalid"),
            CoreModel(core_id="xray", enabled=True),
            CoreModel(core_id="sing-box", enabled=True),
        ])
        s.commit()
    class CoreManager:
        def list_cores(self): return ["xray", "sing-box"]
        def get(self, core_id):
            return SimpleNamespace(metadata=SimpleNamespace(name=core_id.title()))
    return SimpleNamespace(session_factory=sf, core_manager=CoreManager())


def test_journal_rollups_and_system_aggregate_consistency(runtime):
    records = [
        UsageRecord(core_id="xray", account_id="a", uplink_bytes=13, downlink_bytes=21),
        UsageRecord(core_id="sing-box", account_id="b", node_id=7,
                    uplink_bytes=5, downlink_bytes=8),
    ]
    asyncio.run(SQLUsageJournal(runtime.session_factory).append(
        records, {("xray", "a"): 1, ("sing-box", "b"): 2}))
    with runtime.session_factory() as s:
        s.add(UserUsageModel(user_id=1, uplink_bytes=13, downlink_bytes=21))
        s.add(UserUsageModel(user_id=2, uplink_bytes=5, downlink_bytes=8))
        s.commit()
        raw = s.execute(select(UsageRecordModel)).scalars().all()
        system = s.get(UsageAggregateModel, "system")
        buckets = s.execute(select(SystemUsageBucketModel)).scalars().all()
        assert sum(row.uplink_bytes for row in raw) == system.uplink_bytes == 18
        assert sum(row.downlink_bytes for row in raw) == system.downlink_bytes == 29
        assert sum(row.uplink_bytes for row in buckets) == 18
        assert sum(row.downlink_bytes for row in buckets) == 29

    asyncio.run(publish_poll(runtime, [{
        "user_id": 1, "core_id": "xray", "account_id": "a",
        "node_id": None, "ip": "198.51.100.1", "metadata": {},
    }], now=datetime.now(timezone.utc), failed_sources=[], probed_sources=2,
       reset_after_seconds=15))
    result = overview(runtime)
    assert result["upload_bytes"] == 18
    assert result["download_bytes"] == 29
    assert result["total_traffic_bytes"] == 47
    assert result["active_users"] == result["active_connections"] == 1
    assert result["total_nodes"] == 1 and result["total_cores"] == 2
    assert {row["core_id"] for row in result["traffic_by_core"]} == {"xray", "sing-box"}
    by_node = {row["node_id"]: row for row in result["traffic_by_node"]}
    assert by_node[None] == {
        "node_id": None, "node_name": "Master", "upload_bytes": 13,
        "download_bytes": 21, "total_bytes": 34,
    }
    assert by_node[7] == {
        "node_id": 7, "node_name": "edge-a", "upload_bytes": 5,
        "download_bytes": 8, "total_bytes": 13,
    }


def test_monitoring_pagination_and_hwid_ip_separation(runtime):
    now = datetime.now(timezone.utc)
    rows = [{
        "user_id": 1 if i < 4 else 2, "core_id": "xray",
        "account_id": f"a{i}", "node_id": None,
        "ip": f"198.51.100.{i}",
        "connected_at": now - timedelta(minutes=i), "metadata": {},
    } for i in range(1, 6)]
    asyncio.run(publish_poll(runtime, rows, now=now, failed_sources=[],
                             probed_sources=2, reset_after_seconds=15))
    with runtime.session_factory() as s:
        s.add_all([
            SubscriptionDeviceModel(user_id=1, device_hash="h" * 64,
                                    device_hint="stable-a", last_ip="203.0.113.9"),
            SubscriptionDeviceModel(user_id=2, device_hash="j" * 64,
                                    device_hint="stable-b", last_ip="203.0.113.10"),
        ])
        s.commit()

    page = live_connections(runtime, page=2, page_size=2)
    assert page["total"] == 5 and len(page["items"]) == 2
    devices = enrolled_devices(runtime, page=1, page_size=20)
    ips = ip_activity(runtime, page=1, page_size=20)
    assert devices["total"] == 2 and ips["total"] == 5
    assert {row["device"] for row in devices["items"]} == {"stable-a", "stable-b"}
    assert {row["ip"] for row in ips["items"]} == {
        f"198.51.100.{i}" for i in range(1, 6)
    }
    assert all("device_id" not in row and "device" not in row for row in ips["items"])
    assert all(row["core_id"] is None and row["node_id"] is None
               for row in devices["items"])


def test_user_statistics_is_selected_and_range_filtered(runtime):
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    with runtime.session_factory() as s:
        s.add_all([
            UsageRecordModel(user_id=1, core_id="xray", account_id="a", node_id=None,
                             uplink_bytes=10, downlink_bytes=20,
                             recorded_at=now - timedelta(minutes=20)),
            UsageRecordModel(user_id=1, core_id="sing-box", account_id="a", node_id=7,
                             uplink_bytes=30, downlink_bytes=40,
                             recorded_at=now - timedelta(minutes=10)),
            UsageRecordModel(user_id=2, core_id="xray", account_id="b", node_id=None,
                             uplink_bytes=900, downlink_bytes=900,
                             recorded_at=now - timedelta(minutes=10)),
            UserUsageModel(user_id=1, uplink_bytes=50, downlink_bytes=150),
        ])
        s.commit()

    statements: list[str] = []
    engine = runtime.session_factory.kw["bind"]
    event.listen(engine, "before_cursor_execute",
                 lambda _c, _cur, statement, _p, _ctx, _many: statements.append(statement))
    selected_overview = user_overview(runtime, "alice")
    assert selected_overview is not None
    spec = range_spec("custom", now - timedelta(minutes=30), now, now=now)
    result = user_traffic(runtime, selected_overview["user_id"], spec)
    assert selected_overview["username"] == "alice"
    assert selected_overview["total_traffic_bytes"] == 200
    assert selected_overview["used_bytes"] == 200
    assert selected_overview["remaining_bytes"] == 800
    assert result["upload_bytes"] == 40 and result["download_bytes"] == 60
    assert {row["core_id"] for row in result["traffic_by_core"]} == {"xray", "sing-box"}
    assert sum(row["total_bytes"] for row in result["traffic_by_node"]) == 100
    assert not any("FROM users" in sql and "WHERE" not in sql for sql in statements)


def test_system_history_honors_preset_and_custom_ranges(runtime):
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    with runtime.session_factory() as session:
        session.add_all([
            SystemUsageBucketModel(bucket_start=now - timedelta(minutes=30),
                                   uplink_bytes=4, downlink_bytes=6),
            SystemUsageBucketModel(bucket_start=now - timedelta(days=2),
                                   uplink_bytes=90, downlink_bytes=90),
        ])
        session.commit()
    hour = system_history(runtime, range_spec("hour", now=now))
    assert sum(point["total_bytes"] for point in hour["points"]) == 10
    custom = system_history(runtime, range_spec(
        "custom", now - timedelta(days=3), now, now=now))
    assert sum(point["total_bytes"] for point in custom["points"]) == 190
    assert custom["bucket_seconds"] == 86_400


def test_range_validation_is_bounded():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="requires start and end"):
        range_spec("custom", None, now)
    with pytest.raises(ValueError, match="cannot exceed"):
        range_spec("custom", now - timedelta(days=367), now)
    with pytest.raises(ValueError, match="must be before"):
        range_spec("custom", now, now - timedelta(seconds=1))


def test_system_statistics_stays_fast_with_large_user_table(runtime):
    with runtime.session_factory() as s:
        s.add_all([UserModel(username=f"bulk-{i}", status="active") for i in range(10_000)])
        s.add(UsageAggregateModel(dimension="system", uplink_bytes=1, downlink_bytes=2))
        s.commit()
    statements: list[str] = []
    engine = runtime.session_factory.kw["bind"]
    event.listen(engine, "before_cursor_execute",
                 lambda _c, _cur, statement, _p, _ctx, _many: statements.append(statement))
    started = time.perf_counter()
    result = overview(runtime)
    elapsed = time.perf_counter() - started
    assert result["total_traffic_bytes"] == 3
    assert elapsed < 1.0
    assert len(statements) <= 5
    assert not any("FROM users" in sql for sql in statements)
