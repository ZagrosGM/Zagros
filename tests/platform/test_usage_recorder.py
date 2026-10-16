"""Tests for app.platform.usage_recorder — the shared-quota pipeline.

One counter set for every core: recorder passes fold driver-reported deltas
into the platform quota + journal + persistent baselines, and restore at
"restart" resumes accounting exactly-once (never re-reports whole counters).
Runs on real PlatformRuntime + Alembic schema with recording driver doubles
attached through the real CoreManager.
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
    from app.cores.stats import DeltaTracker
    from app.cores.types import (
        Capability,
        CoreMetadata,
        CoreState,
        CoreStatus,
        HealthStatus,
        UsageRecord,
    )

    class CumulativeDriver(BaseCoreDriver):
        """A usage-accounting core whose backend reports CUMULATIVE counters
        (like hysteria2/softether); instance state simulates process restarts."""

        metadata = CoreMetadata(
            id="cum-core", name="Cumulative", protocols=["wireguard"],
            capabilities={Capability.USER_MANAGEMENT, Capability.USAGE_ACCOUNTING})

        backend_counters: dict[str, tuple[int, int]] = {}

        def __init__(self, settings=None):
            super().__init__(settings)
            self._usage = DeltaTracker()  # fresh memory per "process"

        async def start(self): pass
        async def stop(self): pass

        async def status(self):
            return CoreStatus(core_id=self.metadata.id, state=CoreState.RUNNING,
                              health=HealthStatus.HEALTHY, core_version="1.0")

        async def get_logs(self, tail=200):
            yield "cum"

        async def create_account(self, account): pass
        async def update_account(self, account): pass
        async def delete_account(self, account_id): pass
        async def build_client_config(self, account, node=None): return "wg://x"

        async def sync_accounts(self, accounts): pass

        async def get_usage(self, account_ids=None, since=None):
            out = []
            for account_id, (up, down) in self.backend_counters.items():
                if account_ids is not None and account_id not in account_ids:
                    continue
                du, dd = self._usage.observe(account_id, up, down)
                out.append(UsageRecord(core_id=self.metadata.id, account_id=account_id,
                                       uplink_bytes=du, downlink_bytes=dd))
            return out

    class NoAccountingDriver(CumulativeDriver):
        metadata = CoreMetadata(id="quiet-core", name="Quiet", protocols=["ssh"],
                                capabilities={Capability.USER_MANAGEMENT})


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    db = tmp_path / "platform.db"
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "recorder-test-key-0123456789",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        monkeypatch.setenv(var, env[var])
    _migrate(env)

    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()
    CumulativeDriver.backend_counters.clear()
    yield rt
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        monkeypatch.delenv(var, raising=False)


_legacy_counter = {"n": 0}


def crud_admin_create(username):
    from app.models.admin import AdminCreate
    _legacy_counter["n"] += 1
    return AdminCreate(username=username, password="x".join(["pw12345"] * 3),
                       is_sudo=False)


def crud_user_create(username):
    from app.models.user import UserCreate
    _legacy_counter["n"] += 1
    return UserCreate(username=username, proxies={"vless": {}})


def _mk_account(runtime, username="rec01", core_id="cum-core", account_id="acct-1"):
    pid = runtime.users.upsert_user(username=username, status="active")
    runtime.users.upsert_core_account(
        user_id=pid, core_id=core_id, account_id=account_id,
        protocol="wireguard", enabled=True, settings={})
    return pid


def test_recorder_folds_deltas_into_quota_journal_and_baselines(runtime):
    from app.platform import usage_recorder

    driver = CumulativeDriver()
    runtime.core_manager.attach("cum-core", driver, enabled=True)
    pid = _mk_account(runtime)

    CumulativeDriver.backend_counters["acct-1"] = (1000, 2000)
    applied = asyncio.run(usage_recorder.record_once(runtime))
    assert applied == 1

    entry = asyncio.run(runtime.quota.get(pid))
    assert entry is not None and (entry.total_bytes, )[0] == 3000
    snap = asyncio.run(runtime.baselines.get_many(["cum-core:acct-1"]))
    assert snap["cum-core:acct-1"] == (1000, 2000)

    # next tick with MORE traffic: only the delta folds
    # (up 1000→1500 adds 500; down 2000→2600 adds 600 → total 4100, not 7100)
    CumulativeDriver.backend_counters["acct-1"] = (1500, 2600)
    asyncio.run(usage_recorder.record_once(runtime))
    entry = asyncio.run(runtime.quota.get(pid))
    assert entry.total_bytes == 4100


def test_restart_never_re_reports_counters(runtime):
    """The killer scenario: panel restart resets driver memory; persisted
    baselines must make the same cumulative value a NO-OP (exactly-once)."""
    from app.platform import usage_recorder

    driver = CumulativeDriver()
    runtime.core_manager.attach("cum-core", driver, enabled=True)
    pid = _mk_account(runtime)

    CumulativeDriver.backend_counters["acct-1"] = (5000, 5000)
    asyncio.run(usage_recorder.record_once(runtime))
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 10000

    # --- process restart: fresh driver instance with EMPTY tracker memory ---
    runtime.core_manager.attach("cum-core", CumulativeDriver(), enabled=True)
    asyncio.run(usage_recorder.restore_baselines(runtime))

    applied = asyncio.run(usage_recorder.record_once(runtime))
    assert applied == 0, "restart re-reported counters — double count!"
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 10000

    # and when real traffic arrives post-restart, only THAT delta counts
    CumulativeDriver.backend_counters["acct-1"] = (5300, 5200)
    asyncio.run(usage_recorder.record_once(runtime))
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 10500


def test_builtin_xray_provider_identity_is_attributed_once(runtime):
    from app.platform import usage_recorder

    driver = CumulativeDriver()
    # Instance metadata avoids registering a second global driver under the
    # built-in id during test collection.
    driver.metadata = CoreMetadata(
        id="xray", name="Xray", protocols=["shadowsocks"],
        capabilities={Capability.USER_MANAGEMENT, Capability.USAGE_ACCOUNTING},
    )
    runtime.core_manager.attach("xray", driver, enabled=True)
    pid = _mk_account(
        runtime, username="xray-owner", core_id="xray",
        account_id="42.xray-owner.shadowsocks",
    )
    CumulativeDriver.backend_counters["42.xray-owner"] = (100, 2900)
    assert asyncio.run(usage_recorder.record_once(runtime)) == 1
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 3000
    # A flat cumulative read cannot be folded a second time.
    assert asyncio.run(usage_recorder.record_once(runtime)) == 0
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 3000
    totals = asyncio.run(runtime.usage_journal.totals_by_core())
    assert totals["xray"] == (100, 2900)


def test_managed_resetting_core_does_not_restore_stale_generation(runtime):
    from app.platform import usage_recorder

    driver = CumulativeDriver()
    driver.metadata = CoreMetadata(
        id="sing-box", name="sing-box", protocols=["hysteria2"],
        capabilities={Capability.USER_MANAGEMENT, Capability.USAGE_ACCOUNTING},
    )
    runtime.core_manager.attach("sing-box", driver, enabled=True)
    pid = _mk_account(runtime, username="new-generation", core_id="sing-box",
                      account_id="acct-reset")
    asyncio.run(runtime.baselines.set_many({"sing-box:acct-reset": (5000, 6000)}))
    asyncio.run(usage_recorder.restore_baselines(runtime))
    assert driver.usage_tracker_snapshot(["acct-reset"]) == {}

    # New process generation reaches the same raw values: all bytes count.
    CumulativeDriver.backend_counters["acct-reset"] = (5000, 6000)
    asyncio.run(usage_recorder.record_once(runtime))
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 11000


def test_cores_without_accounting_capability_are_skipped(runtime):
    from app.platform import usage_recorder

    runtime.core_manager.attach("quiet-core", NoAccountingDriver(), enabled=True)
    _mk_account(runtime, username="rec02", core_id="quiet-core", account_id="a-q")
    assert asyncio.run(usage_recorder.record_once(runtime)) == 0


def test_broken_core_is_isolated_and_tick_continues(runtime):
    from app.platform import usage_recorder

    class BrokenDriver(CumulativeDriver):
        metadata = CoreMetadata(
            id="broken-core", name="Broken", protocols=["wireguard"],
            capabilities={Capability.USER_MANAGEMENT, Capability.USAGE_ACCOUNTING})

        async def get_usage(self, account_ids=None, since=None):
            raise RuntimeError("backend exploded")

    runtime.core_manager.attach("broken-core", BrokenDriver(), enabled=True)
    runtime.core_manager.attach("cum-core", CumulativeDriver(), enabled=True)
    pid = _mk_account(runtime, username="rec03", core_id="cum-core", account_id="acct-ok")
    _mk_account(runtime, username="rec04", core_id="broken-core", account_id="acct-bad")

    CumulativeDriver.backend_counters["acct-ok"] = (700, 300)
    applied = asyncio.run(usage_recorder.record_once(runtime))
    assert applied == 1  # healthy core billed despite the broken one
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 1000


def test_concurrent_passes_bill_exactly_once(runtime):
    """Race-condition contract (spec §11): two recorder passes racing in the
    same process must fold each byte EXACTLY once — the shared quota may
    never inflate under parallelism, and the journal sees one delta set."""
    from app.platform import usage_recorder

    driver = CumulativeDriver()
    runtime.core_manager.attach("cum-core", driver, enabled=True)
    pid = _mk_account(runtime, username="rec05", core_id="cum-core", account_id="acct-race")

    CumulativeDriver.backend_counters["acct-race"] = (1000, 2000)

    async def race():
        return await asyncio.gather(
            usage_recorder.record_once(runtime),
            usage_recorder.record_once(runtime),
        )

    applied_a, applied_b = asyncio.run(race())
    # both passes may see the same counter snapshot, but the in-memory delta
    # tracker serializes: one pass bills 3000, the other bills nothing —
    # total applied must equal ONE fold.
    assert applied_a + applied_b == 1
    entry = asyncio.run(runtime.quota.get(pid))
    assert entry.total_bytes == 3000

    # and the NEXT real traffic still folds exactly once after the race
    CumulativeDriver.backend_counters["acct-race"] = (1500, 2600)
    asyncio.run(usage_recorder.record_once(runtime))
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 4100


# --------------------------------------------------------------------- #
# f-usagecoeff-1: usage coefficients — quota vs billing split, raw journal
# --------------------------------------------------------------------- #

def test_usage_coefficients_scale_quota_billing_split(runtime):
    from datetime import datetime, timezone

    from app.platform import settings_kv, usage_recorder

    driver = CumulativeDriver()
    runtime.core_manager.attach("cum-core", driver, enabled=True)
    pid = _mk_account(runtime, username="coeff01", account_id="acct-coeff")
    # account carries its inbound tag — per-inbound pricing source
    runtime.users.upsert_core_account(
        user_id=pid, core_id="cum-core", account_id="acct-coeff",
        protocol="wireguard", enabled=True,
        settings={"inbound_tags": ["wg-tr"]})

    sf = runtime.session_factory
    settings_kv.save(sf, "usage_coefficient_master", 2.0)
    settings_kv.save(sf, "usage_coefficient_quota", 1.0)
    settings_kv.save(sf, "usage_coefficient_billing", 1.5)
    settings_kv.save(sf, "usage_coefficient_inbounds", {"wg-tr": 3.0})

    # a matching legacy user+admin so the billing fold has a destination
    from app.db import GetDB, crud
    from app.db.base import Base as LegacyBase, engine as legacy_engine
    from app.db.models import Admin as LegacyAdmin, User as LegacyUser
    LegacyBase.metadata.create_all(legacy_engine)
    with GetDB() as db:
        admin = crud.create_admin(db, crud_admin_create("coeff-boss"))
        crud.create_user(
            db, crud_user_create("coeff01"), admin=admin)
        admin_id = admin.id

    CumulativeDriver.backend_counters["acct-coeff"] = (100, 200)
    assert asyncio.run(usage_recorder.record_once(runtime)) == 1

    # QUOTA: 300 raw × master 2 × inbound 3 × quota_mult 1 = 1800
    entry = asyncio.run(runtime.quota.get(pid))
    assert entry.total_bytes == 1800, "quota side carries master×inbound×quota"
    # JOURNAL: stays RAW (statistics are physical)
    totals = asyncio.run(runtime.usage_journal.totals_by_core())
    assert totals.get("cum-core") == (100, 200), "journal keeps RAW bytes"
    # BILLING: legacy users_usage = 300 × 2 × 3 × 1.5 = 2700
    with GetDB() as db:
        row = db.query(LegacyAdmin).get(admin_id)
        assert row.users_usage == 2700, "billing side carries its own factor"
        luser = db.query(LegacyUser).filter(
            LegacyUser.username == "coeff01").one()
        assert luser.used_traffic == 1800, "used_traffic follows the QUOTA side"


def test_usage_coefficient_defaults_change_nothing(runtime):
    """1.0 everywhere must reproduce the legacy fold exactly."""
    from app.platform import usage_recorder

    driver = CumulativeDriver()
    runtime.core_manager.attach("cum-core", driver, enabled=True)
    pid = _mk_account(runtime, username="coeff10", account_id="acct-dflt")
    CumulativeDriver.backend_counters["acct-dflt"] = (700, 800)
    assert asyncio.run(usage_recorder.record_once(runtime)) == 1
    assert asyncio.run(runtime.quota.get(pid)).total_bytes == 1500
