"""Built-in xray attach — the panel's own engine as a protected platform core.

Why this file exists: the legacy bridge mirrors every user's xray proxies
into ``user_core_accounts`` (core_id="xray"), but the platform CoreManager
only knew operator-installed cores — so every mirror row was discarded at
materialization time and the multi-core portal/subscription came out EMPTY
for the most common protocols. ``boot_cores`` now attaches the real
XrayDriver (legacy backend) automatically, protected by manager-level
guards, skipped by the usage recorder (the legacy stack already accounts
xray traffic — folding again would double-count) and de-duplicated in the
inbound catalog.
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
        "ZAGROS_SECRET_KEY": "builtin-xray-test-key-0123456",
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


if _HAS:
    from app.cores.base import BaseCoreDriver
    from app.cores.types import (
        Capability,
        CoreMetadata,
        CoreState,
        CoreStatus,
        HealthStatus,
        UsageRecord,
    )

    class _FakeAccountingDriver(BaseCoreDriver):
        """Usage-capable double attached UNDER the id 'xray' — the recorder's
        built-in skip must discard its deltas purely by identity."""

        metadata = CoreMetadata(
            id="xrayprobe", name="fake-xray", protocols=["shadowsocks"],
            capabilities={Capability.USER_MANAGEMENT, Capability.USAGE_ACCOUNTING})

        async def start(self): pass
        async def stop(self): pass

        async def status(self):
            return CoreStatus(core_id="xrayprobe", state=CoreState.RUNNING,
                              health=HealthStatus.HEALTHY)

        async def get_logs(self, tail=200):
            yield "x"

        async def create_account(self, account): pass
        async def update_account(self, account): pass
        async def delete_account(self, account_id): pass
        async def build_client_config(self, account, node=None): return None
        async def sync_accounts(self, accounts): pass

        async def get_usage(self, account_ids=None, since=None):
            return [UsageRecord(core_id="xray", account_id=a,
                                uplink_bytes=10_000, downlink_bytes=10_000)
                    for a in (account_ids or [])]

        def usage_tracker_snapshot(self, account_ids):
            return {a: (10_000, 10_000) for a in account_ids}


def test_boot_cores_attaches_builtin_xray_and_materializes_mirror_rows(runtime):
    """Without the attach, xray mirror rows never reach the portal."""
    pid = runtime.users.upsert_user(username="mirror01", status="active")
    runtime.users.upsert_core_account(
        user_id=pid, core_id="xray", account_id="1.mirror01.shadowsocks",
        protocol="shadowsocks", enabled=True,
        settings={"method": "chacha20-ietf-poly1305", "password": "pw"})

    # before boot: xray unknown to the platform — the materialization gap
    pairs = asyncio.run(runtime.portal._provider.get_core_accounts(pid))
    assert pairs == []

    asyncio.run(runtime.boot_cores())

    assert "xray" in runtime.core_manager.list_cores()
    assert runtime.core_manager.is_enabled("xray")

    pairs = asyncio.run(runtime.portal._provider.get_core_accounts(pid))
    assert len(pairs) == 1
    driver, account = pairs[0]
    assert driver.metadata.id == "xray"
    assert account.protocol == "shadowsocks"
    assert account.settings["password"] == "pw"  # decrypted round-trip

    # idempotent: a second boot does not duplicate or raise
    asyncio.run(runtime.boot_cores())
    assert runtime.core_manager.list_cores().count("xray") == 1


def test_catalog_lists_xray_exactly_once(runtime):
    from app.platform.inbounds import catalog

    asyncio.run(runtime.boot_cores())
    groups = asyncio.run(catalog(runtime))
    xray_groups = [g for g in groups if g.core_id == "xray"]
    # legacy group owns the xray view (running config is the truth); the
    # manager-attached core must never add a second, studio-derived group.
    assert len(xray_groups) <= 1


def test_manager_refuses_uninstall_and_disable_for_builtin(runtime):
    from app.cores.exceptions import CoreStateError

    runtime.core_manager.attach("xray", _FakeAccountingDriver(), enabled=True)

    with pytest.raises(CoreStateError):
        asyncio.run(runtime.core_manager.uninstall_core("xray", purge=True, force=True))
    with pytest.raises(CoreStateError):
        asyncio.run(runtime.core_manager.disable_core("xray"))

    # still attached & enabled afterwards — the guard is not a state change
    assert runtime.core_manager.is_enabled("xray")
    assert "xray" in runtime.core_manager.list_cores()


def test_recorder_never_double_counts_builtin_xray(runtime):
    """xray traffic is metered by the legacy stack already; the cross-core
    recorder must skip built-in ids even when the driver is usage-capable."""
    from app.platform import usage_recorder

    runtime.core_manager.attach("xray", _FakeAccountingDriver(), enabled=True)
    pid = runtime.users.upsert_user(username="nomix01", status="active")
    runtime.users.upsert_core_account(
        user_id=pid, core_id="xray", account_id="1.nomix01.shadowsocks",
        protocol="shadowsocks", enabled=True, settings={})

    applied = asyncio.run(usage_recorder.record_once(runtime))
    assert applied == 0
    entry = asyncio.run(runtime.quota.get(pid))
    assert entry is None or entry.total_bytes == 0


def test_core_view_marks_builtin(runtime):
    from app.platform.admin_api import _core_view

    runtime.core_manager.attach("xray", _FakeAccountingDriver(), enabled=True)
    view = asyncio.run(_core_view(runtime, "xray", {}))
    assert view["builtin"] is True

    # operator cores stay un-flagged
    class _OtherDriver(_FakeAccountingDriver):
        metadata = CoreMetadata(
            id="wg-op", name="wg", protocols=["wireguard"],
            capabilities={Capability.USER_MANAGEMENT})

    runtime.core_manager.attach("wg-op", _OtherDriver(), enabled=True)
    view = asyncio.run(_core_view(runtime, "wg-op", {}))
    assert view["builtin"] is False
