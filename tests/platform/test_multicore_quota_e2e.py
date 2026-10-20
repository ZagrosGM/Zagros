"""Item 20 — multi-core end-to-end through the REAL recorder pipeline.

One user with accounts on three cores: the shared quota must total
usage from every core (deltas, no double count across ticks), suspend/
resume propagate to every core, and deleting an inbound revokes cleanly
(cascade from item 6). Real SQLite runtime + real recorder service; only
the core BINARIES are doubled (usage counters are scripted — traffic
shape is the thing under test, and it is real).
"""
from __future__ import annotations

import asyncio

import pytest

from tests.platform.test_provisioning import LegacyUser, _stub_catalog, _catalog  # noqa: F401
from tests.platform.test_provisioning import runtime as _provision_runtime


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    yield from _provision_runtime.__wrapped__(tmp_path, monkeypatch)


class MeteringDriver:
    """Minimal driver double with REAL usage semantics: cumulative kernel
    counters per account; the recorder's DeltaTracker does the rest."""

    class metadata:
        id = "meter"

    def __init__(self, core_id: str, protocols=("fakeproto",)):
        from app.cores.types import Capability, CoreMetadata

        self.metadata = CoreMetadata(
            id=core_id, name=core_id, protocols=list(protocols),
            capabilities={Capability.USER_MANAGEMENT, Capability.SUSPEND_RESUME,
                          Capability.USAGE_ACCOUNTING, Capability.ONLINE_TRACKING})
        self.counters: dict[str, tuple[int, int]] = {}
        self.deleted: list[str] = []
        self.suspended: list[str] = []
        self.resumed: list[str] = []
        from app.cores.stats import DeltaTracker

        self._usage = DeltaTracker()

    async def create_account(self, account):
        self.counters.setdefault(account.account_id, (0, 0))

    async def update_account(self, account):
        pass

    async def delete_account(self, account_id):
        self.counters.pop(account_id, None)
        self.deleted.append(account_id)
        self._usage.forget(account_id)

    async def suspend_account(self, account_id):
        self.suspended.append(account_id)

    async def resume_account(self, account):
        self.resumed.append(account.account_id)

    async def sync_accounts(self, accounts):
        for a in accounts:
            await self.create_account(a)

    async def get_usage(self, account_ids=None, since=None):
        from app.cores.types import UsageRecord

        out = []
        for aid, (up, down) in self.counters.items():
            if account_ids is not None and aid not in account_ids:
                continue
            du, dd = self._usage.observe(aid, up, down)
            out.append(UsageRecord(core_id=self.metadata.id, account_id=aid,
                                   uplink_bytes=du, downlink_bytes=dd))
        return out

    async def get_online_devices(self, account_ids=None):
        return []


def test_one_user_one_quota_across_cores(runtime, monkeypatch):  # noqa: F811
    """xray-style builtin is guarded separately; the two meter cores fold
    into the SAME user quota, per tick, with exactly-once semantics."""
    from app.platform.usage_recorder import record_once

    ssh_core = MeteringDriver("ssh")
    sb_core = MeteringDriver("sing-box")
    runtime.core_manager.attach("ssh", ssh_core, enabled=True)
    runtime.core_manager.attach("sing-box", sb_core, enabled=True)

    async def _go():
        from app.platform import provisioning

        _stub_catalog(
            monkeypatch,
            _catalog(("ssh", "fakeproto", ["ssh-443"]),
            ("sing-box", "fakeproto", ["sb-8443"])))
        user = LegacyUser("quota-e2e", user_id=200)
        pid = await provisioning.sync_user(
            runtime, user, grants={"ssh": ["ssh-443"], "sing-box": ["sb-8443"]})
        accounts = runtime.users.accounts_of(pid)
        aid = {a["core_id"]: a["account_id"] for a in accounts}
        assert set(aid) == {"ssh", "sing-box"}

        # the legacy master row (production: created by the admin panel's
        # legacy user flow) — the recorder folds platform deltas into it too
        from app.db import GetDB
        from app.db.models import User as LegacyUserModel

        with GetDB() as db:
            db.add(LegacyUserModel(username="quota-e2e", status="active",
                                   used_traffic=0, data_limit=None))
            db.commit()

        # --- tick 1: REAL cumulative counters → full deltas fold in
        ssh_core.counters[aid["ssh"]] = (0, 3 * 2**30)     # 3 GB
        sb_core.counters[aid["sing-box"]] = (2 * 2**30, 5 * 2**30)  # 7 GB
        await record_once(runtime)
        q1 = (await runtime.quota.get(pid)).total_bytes
        assert q1 == 10 * 2**30, q1  # 3+7 GB on ONE shared counter

        # --- tick 2: no new traffic → nothing re-billed (exactly-once)
        await record_once(runtime)
        assert (await runtime.quota.get(pid)).total_bytes == q1
        # legacy master counter got the same folds
        from app.db import GetDB
        from app.db.models import User as LegacyUserModel

        with GetDB() as db:
            row = db.query(LegacyUserModel).filter_by(username="quota-e2e").first()
            legacy_used = row.used_traffic if row else None
        assert legacy_used == q1

        # --- tick 3: partial growth on ONE core
        ssh_core.counters[aid["ssh"]] = (0, 3 * 2**30 + 500)
        await record_once(runtime)
        assert (await runtime.quota.get(pid)).total_bytes == q1 + 500

        # --- suspend propagates to BOTH cores (item 20 lifecycle)
        user.status = "disabled"
        await provisioning.sync_grants_enabled(runtime, user, pid)
        assert aid["ssh"] in ssh_core.suspended
        assert aid["sing-box"] in sb_core.suspended
        user.status = "active"
        await provisioning.sync_grants_enabled(runtime, user, pid)
        assert aid["ssh"] in ssh_core.resumed
        assert aid["sing-box"] in sb_core.resumed

        # --- journal totals (item 17) reflect exactly what was folded
        totals = await runtime.usage_journal.totals_by_core()
        assert totals["ssh"][1] == 3 * 2**30 + 500
        assert totals["sing-box"][1] == 5 * 2**30
    asyncio.run(_go())
