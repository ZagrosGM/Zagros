"""Global device limit + unified online status (spec §3/§4/§5).

Runs the REAL enforcement pass (app.platform.device_limits.run_once) over a
real PlatformRuntime + real legacy rows: devices are the IP-union of every
core's view; crossing the limit suspends the user on EVERY core (bridge),
dropping back under it revives only users Zagros itself limited, and any
core reporting the user online touches online_at on both stores.
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


if _HAS:
    from app.cores.base import BaseCoreDriver
    from app.cores.types import (
        Capability,
        CoreMetadata,
        CoreState,
        CoreStatus,
        DeviceSession,
        HealthStatus,
    )

    class OnlineDriver(BaseCoreDriver):
        """Reports canned sessions; records suspend/resume calls."""

        metadata = CoreMetadata(
            id="onde1", name="online-fake", protocols=["wireguard"],
            capabilities={Capability.USER_MANAGEMENT,
                          Capability.ONLINE_TRACKING,
                          Capability.SUSPEND_RESUME})

        def __init__(self, settings=None, *, sessions=()):
            super().__init__(settings)
            self.sessions = list(sessions)
            self.suspend_calls: list[str] = []
            self.resume_calls: list[str] = []

        async def start(self): pass
        async def stop(self): pass

        async def status(self):
            return CoreStatus(core_id=self.metadata.id, state=CoreState.RUNNING,
                              health=HealthStatus.HEALTHY)

        async def get_logs(self, tail=200):
            yield "on"

        async def create_account(self, account): pass
        async def update_account(self, account): pass
        async def delete_account(self, account_id): pass
        async def build_client_config(self, account, node=None): return None
        async def sync_accounts(self, accounts): pass

        async def get_online_devices(self, account_ids=None):
            return [s for s in self.sessions
                    if account_ids is None or s.account_id in account_ids]

        async def suspend_account(self, account_id):
            self.suspend_calls.append(account_id)

        async def resume_account(self, account):
            self.resume_calls.append(account.account_id)


@pytest.fixture()
def env_runtime(tmp_path, monkeypatch):
    db = tmp_path / "platform.db"
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        # legacy engine is process-global (warmed by earlier suites) — the
        # job's GetDB writes land there; legacy rows use unique 'dl*' names
        # and the fixture cleans them up.
        "SQLALCHEMY_DATABASE_URL": env.get(
            "SQLALCHEMY_DATABASE_URL", f"sqlite:///{db.parent / 'legacy.db'}"),
        "ZAGROS_SECRET_KEY": "device-limit-test-key-01234",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        monkeypatch.setenv(var, env[var])
    _migrate(env)

    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()

    # The legacy engine is process-global: depending on collection order it
    # may bind the CWD default (db.sqlite3) — which an ABORTED earlier run
    # can leave littered with this suite's dl_* rows (observed: UNIQUE
    # constraint on the first insert, order-dependent). Treat setup like
    # teardown: ensure the schema exists and sweep any leftover dl_* rows
    # BEFORE the test, identically to the post-test sweep. Deterministic
    # regardless of warm-up order.
    from app.db import GetDB
    from app.db.base import Base as _LegacyBase, engine as _legacy_engine
    from app.db.models import User as LegacyUser

    _LegacyBase.metadata.create_all(_legacy_engine)
    with GetDB() as db:
        db.query(LegacyUser).filter(LegacyUser.username.like("dl\\_%")).delete(
            synchronize_session=False)
        db.commit()

    yield rt

    with GetDB() as db:
        db.query(LegacyUser).filter(LegacyUser.username.like("dl\\_%")).delete(
            synchronize_session=False)
        db.commit()


def _legacy_user(username: str, *, status="active", device_limit=None,
                 data_limit=None, used_traffic=0, id_override=None):
    from app.db import GetDB
    from app.db.models import User as LegacyUser
    from app.models.user import UserStatus

    with GetDB() as db:
        row = LegacyUser(
            username=username, status=UserStatus(status),
            device_limit=device_limit, data_limit=data_limit,
            used_traffic=used_traffic,
        )
        if id_override is not None:
            row.id = id_override
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id


def _project(runtime, username: str, *, status="active",
             accounts: tuple[tuple[str, str], ...] = ()) -> int:
    pid = runtime.users.upsert_user(username=username, status=status)
    for core_id, account_id in accounts:
        runtime.users.upsert_core_account(
            user_id=pid, core_id=core_id, account_id=account_id,
            protocol="wireguard", enabled=True, settings={})
    return pid


def _attach(runtime, core_id: str, sessions):
    driver = OnlineDriver(sessions=sessions)
    runtime.core_manager.attach(core_id, driver, enabled=True)
    return driver


def _legacy_row(username: str):
    from app.db import GetDB
    from app.db.models import User as LegacyUser

    with GetDB() as db:
        row = db.query(LegacyUser).filter(LegacyUser.username == username).first()
        if row is not None:
            db.expunge(row)
        return row


def test_ip_union_dedup_and_unified_online_touch(env_runtime):
    from app.platform import device_limits

    rt = env_runtime
    _legacy_user("dl_union", device_limit=None)
    pid = _project(rt, "dl_union", accounts=(("net1", "a1"), ("net2", "b1")))
    _attach(rt, "net1", [DeviceSession(core_id="net1", account_id="a1", ip="1.1.1.1")])
    _attach(rt, "net2", [DeviceSession(core_id="net2", account_id="b1", ip="1.1.1.1"),
                         DeviceSession(core_id="net2", account_id="b1", ip="2.2.2.2")])

    stats = asyncio.run(device_limits.run_once(rt))
    assert stats["online"] >= 1
    # 2 distinct IPs across the two cores, not 3 session rows
    devices = asyncio.run(device_limits.collect_devices(rt))
    assert devices[pid] == {"1.1.1.1", "2.2.2.2"}

    row = _legacy_row("dl_union")
    assert row.online_at is not None  # legacy surface
    assert row.status.value == "active"  # no limit -> never suspended
    assert rt.users.get_user(pid).online_at is not None  # platform surface


def test_fourth_device_is_rejected_everywhere_then_revived(env_runtime):
    from app.platform import device_limits

    rt = env_runtime
    _legacy_user("dl_gate", device_limit=1)
    pid = _project(rt, "dl_gate", accounts=(("net1", "c1"), ("net2", "d1")))
    d1 = _attach(rt, "net1", [DeviceSession(core_id="net1", account_id="c1", ip="10.0.0.1")])
    d2 = _attach(rt, "net2", [DeviceSession(core_id="net2", account_id="d1", ip="10.0.0.2")])

    stats = asyncio.run(device_limits.run_once(rt))
    assert stats["limited"] >= 1

    row = _legacy_row("dl_gate")
    assert row.status.value == "limited"
    assert row.device_limit_disabled is True
    # unified suspend: EVERY platform account carried over to disabled AND
    # the drivers themselves got suspend_account
    assert d1.suspend_calls == ["c1"] and d2.suspend_calls == ["d1"]
    accs = rt.users.accounts_of(pid, decrypt=False)
    assert all(not a["enabled"] for a in accs)

    # the extra device disconnects -> back under the limit -> revive
    d2.sessions = []
    stats = asyncio.run(device_limits.run_once(rt))
    assert stats["revived"] >= 1
    row = _legacy_row("dl_gate")
    assert row.status.value == "active"
    assert row.device_limit_disabled is False
    assert d1.resume_calls and d2.resume_calls
    accs = rt.users.accounts_of(pid, decrypt=False)
    assert all(a["enabled"] for a in accs)


def test_revival_never_resurrects_quota_or_expired(env_runtime):
    from app.platform import device_limits

    rt = env_runtime
    _legacy_user("dl_block", device_limit=1, data_limit=100, used_traffic=0)
    pid = _project(rt, "dl_block", accounts=(("net1", "e1"),))
    drv = _attach(rt, "net1", [
        DeviceSession(core_id="net1", account_id="e1", ip="1.1.1.1"),
        DeviceSession(core_id="net1", account_id="e1", ip="2.2.2.2"),
    ])
    asyncio.run(device_limits.run_once(rt))
    assert _legacy_row("dl_block").status.value == "limited"

    # burn the quota while limited, then drop the extra device
    from app.db import GetDB
    from app.db.models import User as LegacyUser
    with GetDB() as db:
        db.query(LegacyUser).filter(LegacyUser.username == "dl_block").update(
            {"used_traffic": 500})
        db.commit()
    drv.sessions = [DeviceSession(core_id="net1", account_id="e1", ip="1.1.1.1")]
    stats = asyncio.run(device_limits.run_once(rt))
    assert stats["revived"] == 0
    assert _legacy_row("dl_block").status.value == "limited"
    assert _legacy_row("dl_block").device_limit_disabled is True


def test_xray_presence_counts_as_one_device_and_maps_by_email(env_runtime):
    from app.platform import device_limits

    rt = env_runtime
    legacy_id = _legacy_user("dl_xray", device_limit=1)
    pid = _project(rt, "dl_xray", accounts=(("net1", "x1"),))
    # the built-in xray core reports the legacy email (no IP available)
    _attach(rt, "xray", [
        DeviceSession(core_id="xray", account_id=f"{legacy_id}.dl_xray", ip=None)])
    _attach(rt, "net1", [DeviceSession(core_id="net1", account_id="x1", ip="9.9.9.9")])

    devices = asyncio.run(device_limits.collect_devices(rt))
    assert devices[pid] == {f"presence:xray:{legacy_id}.dl_xray", "9.9.9.9"}

    stats = asyncio.run(device_limits.run_once(rt))
    assert stats["limited"] >= 1  # 2 devices > limit 1
    assert _legacy_row("dl_xray").status.value == "limited"
