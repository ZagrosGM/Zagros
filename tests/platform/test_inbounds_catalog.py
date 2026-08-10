"""Tests for app.platform.inbounds — the unified multi-core inbound catalog.

Runs against a real PlatformRuntime (Alembic-created SQLite) and the real
CoreManager: studio cores contribute config inbounds, service cores derive
entries from their real settings, and the built-in legacy xray core merges
from its running config (same source as the legacy /api/inbounds endpoint).
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "fastapi")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    db = tmp_path / "platform.db"
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "catalog-test-key-0123456789",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        monkeypatch.setenv(var, env[var])
    _migrate(env)

    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()
    yield rt
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        monkeypatch.delenv(var, raising=False)


def test_service_core_entries_come_from_real_settings(runtime):
    from app.cores.base import BaseCoreDriver
    from app.cores.types import CoreMetadata, CoreState, CoreStatus, HealthStatus
    from app.platform import inbounds as cat

    class FakeWG(BaseCoreDriver):
        metadata = CoreMetadata(id="wgprobe", name="WireGuard",
                                protocols=["wireguard"], capabilities=set())

        def __init__(self, settings=None):
            super().__init__(settings or {"port": 51820})

        async def start(self): pass
        async def stop(self): pass

        async def status(self):
            return CoreStatus(core_id="wireguard", state=CoreState.RUNNING,
                              health=HealthStatus.HEALTHY, core_version="1.0")

        async def get_logs(self, tail=200):
            yield "wg"

        async def create_account(self, account): pass
        async def update_account(self, account): pass
        async def delete_account(self, account_id): pass
        async def build_client_config(self, account, node=None): return "wg://x"
        async def sync_accounts(self, accounts): pass

    # attached AS core "wireguard" (the service-derivation key); the driver's
    # own registry id stays unique to avoid colliding with the real driver.
    runtime.core_manager.attach("wireguard", FakeWG(), enabled=True)
    groups = asyncio.run(cat.catalog(runtime))
    wg = next((g for g in groups if g.core_id == "wireguard"), None)
    assert wg is not None, "attached enabled core missing from catalog"
    assert [(i.tag, i.protocol, i.port) for i in wg.inbounds] == [
        ("wireguard", "wireguard", 51820)]


def test_disabled_core_yields_no_entries(runtime):
    from app.platform import inbounds as cat

    runtime.core_manager.attach("wireguard", type("D", (), {
        "metadata": type("M", (), {"name": "WG", "protocols": ["wireguard"]})(),
        "settings": {},
    })(), enabled=False)
    # attach() with a duck-typed object only works if manager.get passes it
    # through; either way the disabled flag must exclude it.
    groups = asyncio.run(cat.catalog(runtime))
    assert all(g.core_id != "wireguard" for g in groups)


def test_softether_catalog_is_enabled_capability_aware():
    from app.platform.inbounds import _service_inbounds

    assert _service_inbounds("softether", {}) == []
    settings = {
        "feature_softether": True, "native_port": 5555,
        "feature_l2tp": True, "feature_l2tp_raw": True,
        "feature_etherip": True, "feature_sstp": True,
        "feature_ovpn": True,
    }
    entries = _service_inbounds("softether", settings)
    assert [(e.tag, e.protocol) for e in entries] == [
        ("softether", "softether"), ("l2tp", "l2tp"),
        ("l2tp-raw", "l2tp_raw"), ("etherip", "etherip"),
        ("sstp", "sstp"), ("softether-openvpn", "ovpn")]
    assert all(e.protocol != "pptp" for e in entries)


def test_legacy_xray_group_merges_running_config(runtime, monkeypatch):
    from app.platform import inbounds as cat

    fake = type("X", (), {"config": type("C", (), {
        "inbounds_by_protocol": {
            "vless": [{"tag": "VLESS Reality", "port": 443}],
            "shadowsocks": [{"tag": "Shadowsocks TCP", "port": 1080}],
        }
    })()})
    monkeypatch.setitem(sys.modules, "app.xray", fake)
    # the builder imports `from app import xray` — patch the attribute chain
    import app as _pkg
    monkeypatch.setattr(_pkg, "xray", fake, raising=False)

    groups = asyncio.run(cat.catalog(runtime))
    xray_group = next((g for g in groups if g.core_id == "xray"), None)
    assert xray_group is not None, "built-in xray missing from catalog"
    tags = {i.tag: (i.protocol, i.port) for i in xray_group.inbounds}
    assert tags["VLESS Reality"] == ("vless", 443)
    assert tags["Shadowsocks TCP"] == ("shadowsocks", 1080)
