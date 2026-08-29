"""Node telemetry: presence, quota and shaping for traffic a node serves.

The panel derives presence (device limits), usage (quota) and shaping
(bandwidth limits) from its own local cores, so a user connected through a
node used to look offline, consume nothing and never be limited. These tests
pin the three bridges that fix that:

*   ``collect_node_devices`` → ``collect_devices_diag`` (presence)
*   ``collect_node_usage``   → ``record_once``           (quota)
*   ``push_bandwidth_limits``                            (shaping)

Every node call is faked at the client boundary, so the tests run without a
live agent while still exercising the real fan-out, attribution and
coefficient logic.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "fastapi")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")

if _HAS:
    from app.cores.types import UsageRecord


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


@pytest.fixture(scope="module")
def env_runtime(tmp_path_factory):
    db = tmp_path_factory.mktemp("node-telemetry") / "zagros.db"
    env = {
        **os.environ,
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db}",
        "ZAGROS_SECRET_KEY": "node-telemetry-test-key-0123456789",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    }
    # module-scoped, so it cannot request the function-scoped fixture
    with pytest.MonkeyPatch.context() as mp:
        for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                    "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
            mp.setenv(var, env[var])
        _migrate(env)

        from app.platform.runtime import PlatformRuntime

        rt = PlatformRuntime.from_env()
        rt.verify_schema()
    return rt


# --------------------------------------------------------------------------- #
# fakes                                                                        #
# --------------------------------------------------------------------------- #

class FakeClient:
    """Stands in for ZagrosNodeClient: canned telemetry, recorded pushes."""

    def __init__(self, *, devices=(), usage=(), push_result=None, exc=None):
        self._devices = list(devices)
        self._usage = list(usage)
        self._push_result = push_result if push_result is not None else {
            "ok": True, "limited_users": len(devices)}
        self._exc = exc
        self.pushed: list[dict] = []

    def runtime_devices(self):
        if self._exc:
            raise self._exc
        return {"devices": list(self._devices), "failed_cores": []}

    def runtime_usage(self):
        if self._exc:
            raise self._exc
        return {"usage": list(self._usage)}

    def push_bandwidth_limits(self, payload):
        if self._exc:
            raise self._exc
        self.pushed.append(payload)
        return dict(self._push_result)


def _node_row(node_id=7, name="n7", coefficient=1.0):
    return types.SimpleNamespace(id=node_id, name=name,
                                 usage_coefficient=coefficient)


def _patch_nodes(monkeypatch, module, clients: dict[int, FakeClient],
                 rows=None, paired=None):
    """Route ``module``'s node fan-out at the given fake clients."""
    rows = rows if rows is not None else [_node_row(i) for i in clients]
    monkeypatch.setattr(module, "paired_nodes", lambda runtime: rows)
    monkeypatch.setattr(module, "_client", lambda runtime, row: clients[row.id])


def _node(runtime, node_id: int, name: str, coefficient: float = 1.0) -> int:
    """A real node row — ``usage_records.node_id`` is a foreign key, so the
    fold path can only be exercised against a node the database knows."""
    from app.persistence.models import NodeModel

    def mutate(session):
        session.merge(NodeModel(
            id=node_id, name=name, address="198.51.100.7", port=62050,
            api_port=62051, status="connected", usage_coefficient=coefficient,
            agent_type="zagros_native", agent_credentials_enc="cipher:test"))
        return node_id

    with runtime.session_factory() as session:
        result = mutate(session)
        session.commit()
    return result


def _project(runtime, username: str, accounts=()) -> int:
    pid = runtime.users.upsert_user(username=username, status="active",
                                    upload_limit_mbps=5, download_limit_mbps=10)
    for core_id, account_id in accounts:
        runtime.users.upsert_core_account(
            user_id=pid, core_id=core_id, account_id=account_id,
            protocol="wireguard", enabled=True, settings={})
    return pid


# --------------------------------------------------------------------------- #
# 1 — presence: a node session marks the user online                          #
# --------------------------------------------------------------------------- #

def test_node_session_marks_user_online(env_runtime, monkeypatch):
    from app.nodes import service
    from app.platform import device_limits

    rt = env_runtime
    pid = _project(rt, "nt_online", accounts=(("openvpn", "1.nt.ovpn"),))
    client = FakeClient(devices=[{"core_id": "openvpn",
                                  "account_id": "1.nt.ovpn",
                                  "ip": "203.0.113.9"}])
    _patch_nodes(monkeypatch, service, {7: client})

    devices, failed, _probed = asyncio.run(device_limits.collect_devices_diag(rt))

    assert devices.get(pid) == {"203.0.113.9"}
    assert failed == []


def test_node_session_without_ip_still_counts_as_a_device(env_runtime, monkeypatch):
    """A core that reports no client IP (openvpn status, accel-ppp) must still
    make the user online — keyed per node so two nodes never collide."""
    from app.nodes import service
    from app.platform import device_limits

    rt = env_runtime
    pid = _project(rt, "nt_noip", accounts=(("openvpn", "1.nt.noip"),))
    client = FakeClient(devices=[{"core_id": "openvpn",
                                  "account_id": "1.nt.noip",
                                  "ip": None}])
    _patch_nodes(monkeypatch, service, {7: client})

    devices, _failed, _probed = asyncio.run(device_limits.collect_devices_diag(rt))

    assert devices.get(pid) == {"presence:node7:openvpn:1.nt.noip"}


def test_unreachable_node_is_reported_and_never_breaks_presence(env_runtime,
                                                                monkeypatch):
    from app.nodes import service
    from app.platform import device_limits

    rt = env_runtime
    _project(rt, "nt_down", accounts=(("pptp", "1.nt.pptp"),))
    _patch_nodes(monkeypatch, service,
                 {7: FakeClient(exc=RuntimeError("connection refused"))})

    sessions, failed = asyncio.run(service.collect_node_devices(rt))
    devices, diag_failed, _probed = asyncio.run(device_limits.collect_devices_diag(rt))

    assert sessions == []
    assert failed == ["n7"]
    assert "node:n7" in diag_failed
    assert devices == {}


# --------------------------------------------------------------------------- #
# 2 — quota: node deltas reach the user's usage                                #
# --------------------------------------------------------------------------- #

def test_node_usage_is_recorded_with_node_id_and_coefficient(env_runtime,
                                                             monkeypatch):
    from app.nodes import service

    rt = env_runtime
    _project(rt, "nt_quota", accounts=(("wireguard", "1.nt.wg"),))
    client = FakeClient(usage=[
        {"core_id": "wireguard", "account_id": "1.nt.wg",
         "uplink_bytes": 1000, "downlink_bytes": 4000},
        # a zero delta is not traffic: never inflate the user's usage
        {"core_id": "wireguard", "account_id": "1.nt.wg",
         "uplink_bytes": 0, "downlink_bytes": 0},
    ])
    _patch_nodes(monkeypatch, service, {7: client},
                 rows=[_node_row(7, coefficient=2.0)])

    records = asyncio.run(service.collect_node_usage(rt))

    assert len(records) == 1
    rec = records[0]
    assert (rec.core_id, rec.account_id) == ("wireguard", "1.nt.wg")
    assert rec.node_id == 7
    # the node's usage_coefficient is applied exactly like a local core's
    assert (rec.uplink_bytes, rec.downlink_bytes) == (2000, 8000)


def test_record_once_folds_node_usage_into_the_quota(env_runtime, monkeypatch):
    """The end-to-end quota path: a node-only user's traffic is counted."""
    from app.cores.types import UsageRecord as _UR  # noqa: F401
    from app.nodes import service
    from app.platform import usage_recorder

    rt = env_runtime
    node_id = _node(rt, 7, "nt-fold-node")
    pid = _project(rt, "nt_fold", accounts=(("wireguard", "1.nt.fold"),))

    async def fake_collect(runtime):
        return [_UR(core_id="wireguard", account_id="1.nt.fold",
                    node_id=node_id, uplink_bytes=2048, downlink_bytes=8192)]

    monkeypatch.setattr(service, "collect_node_usage", fake_collect)

    before = asyncio.run(rt.quota.get(pid))
    written = asyncio.run(usage_recorder.record_once(rt))
    after = asyncio.run(rt.quota.get(pid))

    assert written >= 1
    base_up = int(getattr(before, "uplink_bytes", 0) or 0)
    base_down = int(getattr(before, "downlink_bytes", 0) or 0)
    assert int(after.uplink_bytes) - base_up == 2048
    assert int(after.downlink_bytes) - base_down == 8192


# --------------------------------------------------------------------------- #
# 3 — shaping: the decision is handed to the node that carries the traffic     #
# --------------------------------------------------------------------------- #

def test_bandwidth_limits_payload_groups_accounts_per_user(env_runtime):
    from app.nodes import service

    rt = env_runtime
    pid = _project(rt, "nt_shape", accounts=(("wireguard", "1.nt.wg"),
                                             ("openvpn", "1.nt.ovpn")))
    payload = service.bandwidth_limits_payload(rt)
    row = payload[str(pid)]

    assert row["username"] == "nt_shape"
    assert (row["upload_mbps"], row["download_mbps"]) == (5, 10)
    assert row["accounts"] == {"wireguard": ["1.nt.wg"], "openvpn": ["1.nt.ovpn"]}


def test_bandwidth_limits_are_pushed_to_every_node(env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    _project(rt, "nt_push", accounts=(("wireguard", "1.nt.push"),))
    good, bad = FakeClient(push_result={"ok": True, "limited_users": 3}), FakeClient(
        exc=RuntimeError("TLS handshake failed"))
    _patch_nodes(monkeypatch, service, {7: good, 8: bad},
                 rows=[_node_row(7), _node_row(8, name="n8")])

    report = asyncio.run(service.sync_bandwidth_limits(rt))

    assert {"node_id": 7, "limited_users": 3, "ok": True} in report["pushed"]
    assert len(report["errors"]) == 1
    assert "node 8" in report["errors"][0]
    # the good node received the full decision, not a summary
    assert good.pushed and str(1) in good.pushed[0]
    assert bad.pushed == []
