"""Part 13 — ONE user across MANY cores: cross-core consistency pins.

The neighbouring files already prove the big pieces (shared quota totals,
suspend/resume fan-out, inbound-delete cascade). This file pins what was
left:

* identity is SHARED and STABLE — the same ``{uid}.{username}.{protocol}``
  account id on every core, unchanged by re-syncs and grant expansion;
* revoking ONE core never disturbs the others;
* deleting a core's persisted state row never corrupts the other cores'
  rows (scoped DELETE, idempotent on replay);
* historical usage journal rows survive a core's removal — accounting
  stays attributable and the shared quota is untouched.

Real SQLite runtime, real repositories/stores, recording driver doubles
attached through the real manager path.
"""
from __future__ import annotations

import asyncio

import pytest

from tests.platform.test_provisioning import (  # noqa: F401
    LegacyUser,
    RecordingDriver,
    SecondRecorder,
    _catalog,
    _stub_catalog,
)
from tests.platform.test_provisioning import runtime as _provision_runtime


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    yield from _provision_runtime.__wrapped__(tmp_path, monkeypatch)


def test_identity_is_shared_and_stable_across_cores_and_resyncs(runtime, monkeypatch):
    """One username, one deterministic account id per core — and the ids
    must NOT fork or rename when grants are re-applied or expanded."""
    async def _go():
        from tests.platform.test_provisioning import _stub_catalog as stub

        stub(monkeypatch, _catalog(
            ("rec-one", "wireguard", ["wg0", "wg1"]),
            ("rec-two", "hysteria2", ["hy2"]),
        ))
        from app.platform import provisioning

        user = LegacyUser("shared-id", user_id=301)
        pid = await provisioning.sync_user(
            runtime, user, grants={"rec-one": ["wg0"], "rec-two": ["hy2"]})

        acc_one = "301.shared-id.wireguard"
        acc_two = "301.shared-id.hysteria2"
        assert runtime.rec_one.created == [acc_one]
        assert runtime.rec_two.created == [acc_two]

        rows = {a["core_id"]: a for a in runtime.users.accounts_of(pid)
                if a["core_id"] != "xray"}
        # identity is literally the same string on both cores — provisioner
        # derives it from (user_id, username, protocol), never per-core renames
        assert rows["rec-one"]["account_id"] == acc_one
        assert rows["rec-two"]["account_id"] == acc_two
        assert rows["rec-one"]["account_id"].split(".")[1] == \
            rows["rec-two"]["account_id"].split(".")[1] == "shared-id"

        # re-sync with an EXPANDED grant: same identity via update path,
        # exactly one row per core (no twin), tags converge
        await provisioning.sync_user(
            runtime, user,
            grants={"rec-one": ["wg0", "wg1"], "rec-two": ["hy2"]})
        rows_after = {a["core_id"]: a for a in runtime.users.accounts_of(pid)
                      if a["core_id"] != "xray"}
        assert rows_after["rec-one"]["account_id"] == acc_one
        assert rows_after["rec-two"]["account_id"] == acc_two
        assert sorted(rows_after["rec-one"]["settings"]["inbound_tags"]) == ["wg0", "wg1"]
        per_core = {}
        for a in runtime.users.accounts_of(pid):
            per_core.setdefault(a["core_id"], []).append(a["account_id"])
        assert len(per_core["rec-one"]) == 1
        assert len(per_core["rec-two"]) == 1
    asyncio.run(_go())


def test_revoking_one_core_never_disturbs_the_other(runtime, monkeypatch):
    """Un-granting core A must delete ONLY core A's account: the account
    row and the driver state of core B stay byte-identical."""
    async def _go():
        _stub_catalog(monkeypatch, _catalog(
            ("rec-one", "wireguard", ["wg0"]),
            ("rec-two", "hysteria2", ["hy2"]),
        ))
        from app.platform import provisioning

        user = LegacyUser("partial-revoke", user_id=302)
        pid = await provisioning.sync_user(
            runtime, user, grants={"rec-one": ["wg0"], "rec-two": ["hy2"]})

        await provisioning.sync_user(runtime, user, grants={"rec-one": []})

        assert runtime.rec_one.deleted == ["302.partial-revoke.wireguard"]
        assert runtime.rec_two.deleted == [], "untargeted core must hear nothing"
        rows = {a["core_id"]: a for a in runtime.users.accounts_of(pid)
                if a["core_id"] != "xray"}
        assert "rec-one" not in rows
        assert rows["rec-two"]["account_id"] == "302.partial-revoke.hysteria2"
        assert rows["rec-two"]["enabled"] is True
        assert rows["rec-two"]["settings"]["inbound_tags"] == ["hy2"]
        # and core B keeps serving: a fresh usage/grant sync touches only B now
        assert runtime.rec_two.created == ["302.partial-revoke.hysteria2"]
    asyncio.run(_go())


def test_removing_core_state_row_is_scoped_and_idempotent(runtime):
    """Deleting one core's persisted state row leaves every other core's
    row byte-identical; replaying the delete is a harmless no-op."""
    async def _go():
        from app.cores.types import CoreState

        store = runtime.core_state
        await store.save_state("rec-one", state=CoreState.RUNNING, enabled=True,
                               settings={"port": 51820})
        await store.save_state("rec-two", state=CoreState.STOPPED, enabled=False,
                               settings={"port": 443})

        await store.remove("rec-two")
        loaded = await store.load()
        assert sorted(loaded) == ["rec-one"]
        # not just 'present' — byte-identical (no cascades, no bleed-over)
        assert loaded["rec-one"] == {
            "state": CoreState.RUNNING.value, "enabled": True,
            "settings": {"port": 51820}}

        # idempotent replay: deleting a missing row must not explode
        await store.remove("rec-two")
        loaded = await store.load()
        assert sorted(loaded) == ["rec-one"]

        # and the surviving core keeps accepting state writes
        await store.save_state("rec-one", state=CoreState.STOPPED, enabled=True,
                               settings=None)
        loaded = await store.load()
        assert loaded["rec-one"]["state"] == CoreState.STOPPED.value
        assert loaded["rec-one"]["settings"] == {"port": 51820}  # None = keep
    asyncio.run(_go())


def test_usage_journal_and_quota_survive_core_removal(runtime, monkeypatch):
    """After journal entries exist for cores A and B, removing B's state
    row must NOT cascade into accounting: totals stay attributable and
    the shared quota keeps its value (history is honest, never rewritten)."""
    from tests.platform.test_multicore_quota_e2e import MeteringDriver

    meter_a = MeteringDriver("ssh")
    meter_b = MeteringDriver("sing-box")
    runtime.core_manager.attach("ssh", meter_a, enabled=True)
    runtime.core_manager.attach("sing-box", meter_b, enabled=True)

    async def _go():
        from app.platform import provisioning
        from app.platform.usage_recorder import record_once

        _stub_catalog(monkeypatch, _catalog(
            ("ssh", "fakeproto", ["ssh-443"]),
            ("sing-box", "fakeproto", ["sb-8443"])))
        user = LegacyUser("journal-keep", user_id=303)
        pid = await provisioning.sync_user(
            runtime, user, grants={"ssh": ["ssh-443"], "sing-box": ["sb-8443"]})
        aid = {a["core_id"]: a["account_id"] for a in runtime.users.accounts_of(pid)}

        meter_a.counters[aid["ssh"]] = (0, 1 * 2**30)
        meter_b.counters[aid["sing-box"]] = (0, 2 * 2**30)
        await record_once(runtime)
        quota_before = (await runtime.quota.get(pid)).total_bytes
        assert quota_before == 3 * 2**30
        totals_before = await runtime.usage_journal.totals_by_core()
        assert totals_before["ssh"][1] == 1 * 2**30
        assert totals_before["sing-box"][1] == 2 * 2**30

        # core removed from the persisted registry (the 'حذف core' case)
        await runtime.core_state.remove("sing-box")
        loaded = await runtime.core_state.load()
        assert "sing-box" not in loaded

        # accounting history is NOT rewritten: journal rows stay attributable
        totals_after = await runtime.usage_journal.totals_by_core()
        assert totals_after == totals_before
        # shared quota untouched by the removal
        assert (await runtime.quota.get(pid)).total_bytes == quota_before
    asyncio.run(_go())
