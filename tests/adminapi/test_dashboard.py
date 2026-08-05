"""Dashboard aggregation tests — snapshot assembly, alerts, ordering.

Run: pytest tests/adminapi/test_dashboard.py -v  OR  python tests/adminapi/test_dashboard.py
"""
from __future__ import annotations

import asyncio
import sys
import traceback
import types as _types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.adminapi.dashboard import (  # noqa: E402
    Alert,
    AlertSeverity,
    DashboardService,
    NodeHealthView,
)
from app.cores.types import (  # noqa: E402
    CoreMetrics,
    CoreState,
    CoreStatus,
    HealthStatus,
)


class _FakeCoreManager:
    async def status_all(self):
        return [
            CoreStatus(core_id="xray", state=CoreState.RUNNING, health=HealthStatus.HEALTHY,
                       core_version="1.8.23", uptime_seconds=123.0,
                       metrics=CoreMetrics(active_accounts=41, active_sessions=9)),
            CoreStatus(core_id="sing-box", state=CoreState.RUNNING,
                       health=HealthStatus.DEGRADED, message="stats api unreachable",
                       metrics=CoreMetrics(active_accounts=10)),
            CoreStatus(core_id="wireguard", state=CoreState.RUNNING,
                       health=HealthStatus.UNHEALTHY, enabled=True),
            CoreStatus(core_id="openvpn", state=CoreState.ERROR,
                       health=HealthStatus.UNKNOWN, enabled=True),
        ]


class _FakeUserStats:
    async def user_totals(self):
        return {"total": 120, "active": 100, "online": 23}

    async def quota_alerts(self, *, ratio: float, limit: int) -> list[Alert]:
        assert ratio == 0.9 and limit == 10
        return [Alert(severity=AlertSeverity.WARNING, code="quota.nearly_full",
                      target="bob", message="bob used 93% of quota")]


class _FakeUsageProvider:
    async def usage_by_core(self):
        return {"xray": (1_000, 9_000), "wireguard": (2_000, 18_000)}


class _FakeNodeProvider:
    async def node_states(self):
        return [
            NodeHealthView(node_id=1, name="node-de", address="10.0.0.5", status="connected",
                           last_seen=datetime.now(timezone.utc)),
            NodeHealthView(node_id=2, name="node-fr", address="10.0.0.6", status="connecting"),
        ]


class _FakeDevices:
    async def all(self):
        return [SimpleNamespace(current_core="xray"),
                SimpleNamespace(current_core=None),
                SimpleNamespace(current_core="wireguard")]


class _FakeSessions:
    def active(self, **kwargs):
        return [object()] * 7


def _deployment_report(per_core: dict[str, tuple[int, int]]):
    results = {
        cid: SimpleNamespace(
            applied=[object()] * a,
            unsupported=[SimpleNamespace(rule=f"r{i}", reason="x") for i in range(u)],
        )
        for cid, (a, u) in per_core.items()
    }
    return SimpleNamespace(results=results)


def test_snapshot_aggregates_everything() -> None:
    routing = SimpleNamespace(last_report=_deployment_report({"xray": (5, 1), "wireguard": (0, 5)}))
    outbounds = SimpleNamespace(last_report=_deployment_report({"xray": (3, 0)}))
    service = DashboardService(
        core_manager=_FakeCoreManager(),  # type: ignore[arg-type]
        user_stats=_FakeUserStats(),
        usage_provider=_FakeUsageProvider(),
        node_provider=_FakeNodeProvider(),
        routing_engine=routing,
        outbound_manager=outbounds,
        device_store=_FakeDevices(),
        session_manager=_FakeSessions(),
    )
    snap = asyncio.run(service.snapshot())

    assert snap.users_total == 120 and snap.users_online == 23 and snap.users_active == 100
    assert snap.usage_total_bytes == 30_000
    gauges = {g.core_id: g for g in snap.usage_by_core}
    assert gauges["xray"].total_bytes == 10_000 and gauges["wireguard"].total_bytes == 20_000

    cores = {c.core_id: c for c in snap.cores}
    assert cores["xray"].metrics_account_count if False else cores["xray"].active_accounts == 41
    assert cores["sing-box"].health == "degraded" and cores["sing-box"].message

    assert snap.devices_active == 2 and snap.sessions_active == 7
    assert {n.name for n in snap.nodes} == {"node-de", "node-fr"}

    assert snap.routing_status.deployed_at_available
    assert snap.routing_status.unsupported_total == 6
    assert snap.routing_status.per_core["wireguard"] == {"applied": 0, "unsupported": 5}
    assert snap.outbound_status.unsupported_total == 0

    # alerts: critical first (wg unhealthy + openvpn error), then warnings
    codes = [a.code for a in snap.alerts]
    assert codes[:2] == ["core.unhealthy", "core.error"]
    assert "core.degraded" in codes and "node.offline" in codes
    assert "quota.nearly_full" in codes
    assert snap.alerts[0].severity is AlertSeverity.CRITICAL


def test_snapshot_without_optional_providers() -> None:
    service = DashboardService(
        core_manager=_FakeCoreManager(),  # type: ignore[arg-type]
        user_stats=_FakeUserStats(),
        usage_provider=_FakeUsageProvider(),
        node_provider=None,
    )
    snap = asyncio.run(service.snapshot())
    assert snap.nodes == []
    assert snap.routing_status.deployed_at_available is False
    assert snap.outbound_status.deployed_at_available is False
    assert snap.devices_active == 0 and snap.sessions_active == 0


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
