"""Snapshot/PanelInfo contract tests — the SPA↔backend agreement.

Regression for the alpha.5 white-screen blocker: the dashboard SPA read
``snapshot.totals.online_users`` from a ``Snapshot`` type that INVENTED a
``totals`` block the backend never emitted. The real payload has flat
``users_total/users_online/users_active`` keys. The TypeError during render,
with no error boundary, unmounted the whole React tree (UI flashed ~300 ms
then went white on every refresh).

These tests pin BOTH sides of the contract:

* HTTP level  — the live router stack emits every top-level key the SPA
  consumes (and ``panel/info`` carries ``version`` + ``uptime_seconds``),
* model level — every item-shape field the SPA reads exists on the real
  Pydantic models (catches renames even for lists that are empty here).

If you change adminapi/dashboard.py, update app/dashboard/src/lib/types.ts
in the same commit.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

_NEED = ("sqlalchemy", "fastapi", "httpx", "cryptography")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")

# Top-level keys the SPA reads off /api/zagros/dashboard/snapshot
# (app/dashboard/src/lib/types.ts::Snapshot + Overview.tsx usage).
SNAPSHOT_TOP_KEYS = {
    "generated_at", "users_total", "users_online", "users_active",
    "usage_total_bytes", "usage_by_core", "cores", "nodes",
    "devices_active", "sessions_active",
    "routing_status", "outbound_status", "alerts",
}
DEPLOYMENT_STATUS_KEYS = {"deployed_at_available", "per_core", "unsupported_total"}
PANEL_INFO_KEYS = {"version", "uptime_seconds", "domain", "client_auth_mode"}
# Item-level keys the SPA reads from list elements.
CORE_HEALTH_KEYS = {
    "core_id", "name", "state", "health", "enabled", "version",
    "uptime_seconds", "active_accounts", "active_sessions", "message",
}
LIVE_USAGE_KEYS = {"core_id", "uplink_bytes", "downlink_bytes"}
ALERT_KEYS = {"severity", "code", "message", "target"}
NODE_HEALTH_KEYS = {"node_id", "name", "address", "status", "last_seen"}


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """Real router stack over a real runtime (same wiring as test_admin_api)."""
    from tests.platform.test_admin_api import _env_for, _migrate

    db = tmp_path_factory.mktemp("snapshot-contract") / "platform.db"
    env = _env_for(db)
    import os
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT"):
        os.environ[var] = env[var]
    _migrate(env)

    import sys
    if not hasattr(sys.modules.get("app"), "app"):
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            sys.modules.pop(name, None)
    import app as _app_warm

    _app_warm.app  # noqa: B018 - force warm-up of the legacy import chain

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.models.admin import Admin
    from app.platform import admin_api  # noqa: F401 - registers endpoints
    from app.platform.routers import zagros_admin_router
    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()
    app = FastAPI()
    app.state.zagros = rt
    app.dependency_overrides[Admin.check_sudo_admin] = lambda: {"username": "test"}
    app.include_router(zagros_admin_router)
    with TestClient(app) as c:
        yield c


def test_snapshot_emits_spa_consumed_keys(client) -> None:
    body = client.get("/api/zagros/dashboard/snapshot")
    assert body.status_code == 200, body.text
    payload = body.json()
    missing = SNAPSHOT_TOP_KEYS - payload.keys()
    assert not missing, f"snapshot lost SPA-consumed keys: {sorted(missing)}"
    for section in ("routing_status", "outbound_status"):
        missing = DEPLOYMENT_STATUS_KEYS - payload[section].keys()
        assert not missing, f"{section} lost keys: {sorted(missing)}"
    # The alpha.5 bug, spelled out so it can never come back quietly:
    assert "totals" not in payload, (
        "reintroducing a nested totals block would silently re-break the SPA"
    )


def test_panel_info_carries_version_and_uptime(client) -> None:
    body = client.get("/api/zagros/panel/info")
    assert body.status_code == 200, body.text
    payload = body.json()
    missing = PANEL_INFO_KEYS - payload.keys()
    assert not missing, f"panel/info lost keys the SPA reads: {sorted(missing)}"
    assert isinstance(payload["version"], str) and payload["version"]


def test_item_models_cover_spa_fields() -> None:
    """Static half of the contract: item-level fields must exist on the models
    even though every list is empty on a fresh install."""
    from app.adminapi.dashboard import (
        Alert,
        CoreHealthView,
        DashboardSnapshot,
        DeploymentStatusView,
        LiveUsageGauge,
        NodeHealthView,
    )

    assert SNAPSHOT_TOP_KEYS <= DashboardSnapshot.model_fields.keys()
    assert DEPLOYMENT_STATUS_KEYS <= DeploymentStatusView.model_fields.keys()
    assert CORE_HEALTH_KEYS <= CoreHealthView.model_fields.keys()
    assert LIVE_USAGE_KEYS <= LiveUsageGauge.model_fields.keys()
    assert ALERT_KEYS <= Alert.model_fields.keys()
    assert NODE_HEALTH_KEYS <= NodeHealthView.model_fields.keys()
