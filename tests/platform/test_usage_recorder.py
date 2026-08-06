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
