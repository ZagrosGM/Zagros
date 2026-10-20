"""Monitoring/Statistics contracts through the authenticated HTTP stack."""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
_TMP = Path(tempfile.mkdtemp(prefix="zg-monitoring-statistics-api-"))
os.environ.setdefault("SQLALCHEMY_DATABASE_URL", f"sqlite:///{_TMP}/legacy.db")
os.environ.setdefault("ZAGROS_DATABASE_URL", f"sqlite:///{_TMP}/platform.db")
os.environ.setdefault("ZAGROS_SECRET_KEY", "monitoring-statistics-api-test-key")
os.environ.setdefault("ZAGROS_ALEMBIC_INI", str(ROOT / "alembic.ini"))

migration = subprocess.run(
    [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
     "upgrade", "head"], cwd=ROOT, env=os.environ.copy(), capture_output=True,
    text=True, timeout=300, check=False,
)
assert migration.returncode == 0, migration.stderr

import app as panel  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.db import GetDB, crud  # noqa: E402
from app.db.base import Base as LegacyBase, engine as legacy_engine  # noqa: E402
from app.db.models import JWT as JWTModel  # noqa: E402
from app.models.admin import AdminCreate  # noqa: E402
from app.persistence.models import (  # noqa: E402
    SubscriptionDeviceModel, SystemUsageBucketModel, UsageAggregateModel,
    UsageRecordModel, UserModel, UserUsageModel,
)
from app.platform.monitoring import publish_poll  # noqa: E402
from app.utils.jwt import create_admin_token  # noqa: E402

LegacyBase.metadata.create_all(legacy_engine)
if getattr(panel.app.state, "zagros", None) is None:
    from app.platform.runtime import PlatformRuntime
    runtime = PlatformRuntime.from_env()
    runtime.verify_schema()
    panel.app.state.zagros = runtime
with GetDB() as db:
    if db.query(JWTModel).first() is None:
        db.add(JWTModel(id=1, secret_key="cd" * 32))
        db.commit()

client = TestClient(panel.app)


def _token() -> str:
    username = f"stat-admin-{uuid.uuid4().hex[:10]}"
    with GetDB() as db:
        crud.create_admin(db, AdminCreate(username=username, password="pass-123456",
                                          is_sudo=True))
    return create_admin_token(username, is_sudo=True)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_system_and_selected_user_statistics_http_contracts():
    token = _token()
    runtime = panel.app.state.zagros
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    username = f"stats-{uuid.uuid4().hex[:10]}"
    with runtime.session_factory() as session:
        user = UserModel(username=username, status="active", data_limit_bytes=10_000)
        session.add(user)
        session.flush()
        session.add(UserUsageModel(user_id=user.id, uplink_bytes=300, downlink_bytes=700))
        session.add(UsageRecordModel(
            user_id=user.id, core_id="api-real-core", account_id="acct",
            node_id=None, uplink_bytes=30, downlink_bytes=70,
            recorded_at=now - timedelta(minutes=5)))
        current = session.get(UsageAggregateModel, "system")
        if current is None:
            session.add(UsageAggregateModel(
                dimension="system", uplink_bytes=30, downlink_bytes=70))
        else:
            current.uplink_bytes += 30
            current.downlink_bytes += 70
        session.add(UsageAggregateModel(
            dimension=f"core:api-{uuid.uuid4().hex[:8]}",
            uplink_bytes=30, downlink_bytes=70))
        bucket = session.get(SystemUsageBucketModel, now - timedelta(minutes=5))
        if bucket is None:
            session.add(SystemUsageBucketModel(
                bucket_start=now - timedelta(minutes=5),
                uplink_bytes=30, downlink_bytes=70))
        session.commit()

    unauthenticated = client.get("/api/zagros/statistics/overview")
    assert unauthenticated.status_code in (401, 403)

    system = client.get("/api/zagros/statistics/overview", headers=_auth(token))
    assert system.status_code == 200, system.text
    body = system.json()
    assert body["source"] == "usage_records"
    assert body["total_traffic_bytes"] >= 100
    assert "users" not in body

    history = client.get(
        "/api/zagros/statistics/traffic-history",
        params={"range": "custom",
                "start": (now - timedelta(hours=1)).isoformat(),
                "end": now.isoformat()}, headers=_auth(token))
    assert history.status_code == 200, history.text
    assert history.json()["source"] == "system_usage_buckets"
    assert sum(point["total_bytes"] for point in history.json()["points"]) >= 100

    selected = client.get(
        f"/api/zagros/statistics/users/by-username/{username}", headers=_auth(token))
    assert selected.status_code == 200, selected.text
    assert selected.json()["used_bytes"] == 1_000
    traffic = client.get(
        f"/api/zagros/statistics/users/by-username/{username}/traffic",
        params={"range": "custom",
                "start": (now - timedelta(hours=1)).isoformat(),
                "end": now.isoformat()}, headers=_auth(token))
    assert traffic.status_code == 200, traffic.text
    assert traffic.json()["total_bytes"] == 100
    assert traffic.json()["traffic_by_core"][0]["core_id"] == "api-real-core"
    assert client.get(
        "/api/zagros/statistics/users/by-username/not-a-real-user",
        headers=_auth(token)).status_code == 404
    assert client.get(
        "/api/zagros/statistics/traffic-history",
        params={"range": "custom"}, headers=_auth(token)).status_code == 422


def test_monitoring_http_pagination_and_separate_device_ip_rows():
    token = _token()
    runtime = panel.app.state.zagros
    now = datetime.now(timezone.utc)
    username = f"monitor-{uuid.uuid4().hex[:10]}"
    with runtime.session_factory() as session:
        user = UserModel(username=username, status="active")
        session.add(user)
        session.flush()
        user_id = user.id
        session.add(SubscriptionDeviceModel(
            user_id=user_id, device_hash=uuid.uuid4().hex * 2,
            device_hint="stable-test-hwid", last_ip="203.0.113.99"))
        session.commit()
    asyncio.run(publish_poll(runtime, [{
        "user_id": user_id, "core_id": "xray", "account_id": "real-account",
        "node_id": None, "ip": "198.51.100.77",
        "connected_at": now - timedelta(seconds=30),
        "metadata": {"uplink_bytes": 11, "downlink_bytes": 19},
    }], now=now, failed_sources=[], probed_sources=1, reset_after_seconds=15))

    live = client.get("/api/zagros/monitoring/live-connections",
                      params={"page": 1, "page_size": 1}, headers=_auth(token))
    assert live.status_code == 200, live.text
    assert live.json()["total"] == 1 and len(live.json()["items"]) == 1
    assert live.json()["items"][0]["ip"] == "198.51.100.77"

    devices = client.get("/api/zagros/monitoring/devices",
                         params={"page": 1, "page_size": 200}, headers=_auth(token))
    ips = client.get("/api/zagros/monitoring/ip-activity",
                     params={"page": 1, "page_size": 200}, headers=_auth(token))
    assert devices.status_code == ips.status_code == 200
    device = next(row for row in devices.json()["items"] if row["user_id"] == user_id)
    ip = next(row for row in ips.json()["items"] if row["user_id"] == user_id)
    assert device["device"] == "stable-test-hwid"
    assert device["last_ip"] == "203.0.113.99"
    assert ip["ip"] == "198.51.100.77" and "device" not in ip
    assert device["core_id"] is None and device["node_id"] is None
