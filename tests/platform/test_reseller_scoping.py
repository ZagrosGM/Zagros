"""f-reseller-1 / f-reseller-2 / f-allocgap-1 — reseller governance.

Installer report: a reseller (users:edit, inbounds/cores hidden) could not
grant any protocol (catalog 403) while a template silently still could;
the Overview snapshot handed out node IPs and panel-wide totals; and an
allocation budget was bypassed by unlimited users.
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app.adminapi.dashboard import (  # noqa: E402
    Alert, AlertSeverity, CoreHealthView, DashboardSnapshot, LiveUsageGauge,
    NodeHealthView,
)
from app.platform import admin_api  # noqa: E402
from app.platform.routers import _current_admin, dashboard_snapshot  # noqa: E402


def _full_snapshot() -> DashboardSnapshot:
    return DashboardSnapshot(
        generated_at=datetime.now(timezone.utc),
        users_total=7, users_online=3, users_active=5,
        usage_total_bytes=999_999,
        usage_by_core=[LiveUsageGauge(core_id="xray", uplink_bytes=1,
                                      downlink_bytes=2)],
        cores=[CoreHealthView(core_id="xray", state="running",
                              health="healthy")],
        nodes=[NodeHealthView(node_id=1, name="de-1", address="203.0.113.77",
                              status="connected")],
        devices_active=4, sessions_active=2,
        alerts=[
            Alert(severity=AlertSeverity.WARNING, code="quota.nearly_full",
                  target="mine-alice", message="x"),
            Alert(severity=AlertSeverity.WARNING, code="quota.nearly_full",
                  target="other-bob", message="x"),
            Alert(severity=AlertSeverity.CRITICAL, code="node.offline",
                  target="de-1", message="x"),
        ],
    )


def _runtime(tmp_path):
    """runtime stub: real SQL session factory over a temp platform schema."""
    from app.persistence.base import Base, create_session_factory
    import app.persistence.models  # noqa: F401

    url = f"sqlite:///{tmp_path}/platform.db"
    factory = create_session_factory(url)
    Base.metadata.create_all(factory.kw["bind"])
    with factory() as s:
        from app.persistence.models import AdminModel, UserModel, UserUsageModel
        s.add(AdminModel(id=7, username="reseller-1", password_hash="x"))
        s.add(AdminModel(id=8, username="reseller-2", password_hash="x"))
        s.add(UserModel(id=1, username="mine-alice", status="active",
                        admin_id=7, online_at=datetime.now(timezone.utc)))
        s.add(UserModel(id=2, username="other-bob", status="active",
                        admin_id=8))
        s.add(UserUsageModel(user_id=1, uplink_bytes=30, downlink_bytes=50))
        s.commit()

    async def _snapshot():
        return _full_snapshot()

    return SimpleNamespace(dashboard=SimpleNamespace(snapshot=_snapshot),
                           session_factory=factory)


def test_reseller_snapshot_is_scoped_to_own_data(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    _current_admin.set(SimpleNamespace(is_sudo=False, id=7))
    try:
        out = asyncio.run(dashboard_snapshot(runtime=runtime))
    finally:
        _current_admin.set(None)
    assert (out.users_total, out.users_active, out.users_online) == (1, 1, 1)
    assert out.usage_total_bytes == 80, "own users' usage only"
    assert out.cores == [] and out.nodes == [], "infrastructure never leaves"
    assert out.usage_by_core == []
    assert not out.routing_status.deployed_at_available
    assert [a.target for a in out.alerts] == ["mine-alice"], \
        "other admins' usernames must not leak through alerts"
    assert "203.0.113.77" not in out.model_dump_json()


def test_sudo_snapshot_is_untouched(tmp_path):
    runtime = _runtime(tmp_path)
    _current_admin.set(SimpleNamespace(is_sudo=True, id=1))
    try:
        out = asyncio.run(dashboard_snapshot(runtime=runtime))
    finally:
        _current_admin.set(None)
    assert out.users_total == 7
    assert len(out.nodes) == 1 and out.nodes[0].address == "203.0.113.77"


def test_access_catalog_is_minimal_and_allowlist_filtered(monkeypatch):
    class Group:
        def __init__(self, d):
            self._d = d

        def as_dict(self):
            import copy
            return copy.deepcopy(self._d)

    fake_groups = [
        Group({"core_id": "xray", "name": "Xray", "enabled": True,
               "inbounds": [
                   {"tag": "VLESS-TLS", "protocol": "vless", "port": 443,
                    "network": "tcp", "security_class": "secure"},
                   {"tag": "SECRET-TAG", "protocol": "vmess", "port": 1234},
               ]}),
        Group({"core_id": "wireguard", "name": "WireGuard", "enabled": True,
               "inbounds": [{"tag": "wg-in", "protocol": "wireguard",
                             "port": 51820}]}),
    ]
    import app.platform.inbounds as inbounds_mod

    async def _fake_catalog(runtime):
        return fake_groups
    monkeypatch.setattr(inbounds_mod, "catalog", _fake_catalog)
    # restricted admin: allow-list with one xray tag
    monkeypatch.setattr(
        admin_api._ap, "allowed_inbounds",
        lambda raw: ["VLESS-TLS"], raising=False)
    out = asyncio.run(admin_api.access_picker_catalog(
        runtime=SimpleNamespace(),
        admin=SimpleNamespace(is_sudo=False, permissions={"x": 1})))
    assert out["restricted"] is True
    tags = [i["tag"] for g in out["groups"] for i in g["inbounds"]]
    assert tags == ["VLESS-TLS"], "allow-list + other cores' tags excluded"
    entry = out["groups"][0]["inbounds"][0]
    assert "port" not in entry and "network" not in entry, \
        "server configuration must not leak through the picker catalog"

    # sudo: unrestricted, but STILL minimal fields
    monkeypatch.setattr(admin_api._ap, "allowed_inbounds",
                        lambda raw: None, raising=False)
    out = asyncio.run(admin_api.access_picker_catalog(
        runtime=SimpleNamespace(),
        admin=SimpleNamespace(is_sudo=True, permissions=None)))
    assert out["restricted"] is False
    assert {i["tag"] for g in out["groups"] for i in g["inbounds"]} == {
        "VLESS-TLS", "SECRET-TAG", "wg-in"}
    assert all("port" not in i for g in out["groups"] for i in g["inbounds"])
