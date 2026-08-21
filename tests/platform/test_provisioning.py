"""Tests for app.platform.provisioning — the legacy↔platform bridge that makes
ONE dashboard user hold accounts on MANY cores ("Marzban inbounds, multi-core").

Everything below runs against REAL infrastructure: a real PlatformRuntime on a
real Alembic-created SQLite schema and the real CoreManager with recording
test-double drivers attached through the real attach path. Only the inbound
CATALOG view is stubbed per test (it is a pure read model over live core
configs; its own renderer is covered by the /inbounds endpoint tests).
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "fastapi", "pydantic")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")


def _env_for(db_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db_path}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db_path.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "test-secret-0123456789abcdef",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    return env


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


class _LegacyProxy:
    def __init__(self, protocol, settings, excluded=()):
        self.type = protocol
        self.settings = settings
        self.excluded_inbounds = [type("Inb", (), {"tag": t})() for t in excluded]


class LegacyUser:
    """Attribute-level stand-in for app.db.models.User (provisioning only
    reads attributes — the ORM itself is covered by the API-level tests)."""

    def __init__(self, username, *, status="active", data_limit=0, expire=None,
                 admin_id=1, note=None, user_id=7, proxies=(), used_traffic=0):
        self.id = user_id
        self.username = username
        self.status = status
        self.data_limit = data_limit
        self.expire = expire
        self.admin_id = admin_id
        self.note = note
        self.used_traffic = used_traffic
        self.proxies = list(proxies)


if _HAS:
    from app.cores.base import BaseCoreDriver
    from app.cores.types import (
        Capability,
        CoreMetadata,
        CoreState,
        CoreStatus,
        HealthStatus,
    )
    from app.platform.inbounds import CatalogGroup, CatalogInbound

    class RecordingDriver(BaseCoreDriver):
        """Real BaseCoreDriver subclass that records every provisioning call
        and generates a credential (exercising the persist-back contract)."""

        metadata = CoreMetadata(
            id="rec-one", name="Recorder One", protocols=["wireguard"],
            capabilities={Capability.USER_MANAGEMENT, Capability.SUSPEND_RESUME})

        def __init__(self, settings=None):
            super().__init__(settings)
            self.created: list[str] = []
            self.deleted: list[str] = []
            self.suspended: list[str] = []
            self.resumed: list[str] = []

        async def start(self): pass
        async def stop(self): pass
        async def status(self):
            return CoreStatus(core_id=self.metadata.id, state=CoreState.RUNNING,
                              health=HealthStatus.HEALTHY, core_version="1.0")

        async def get_logs(self, tail=200):
            yield "recorder log"

        async def create_account(self, account) -> None:
            if account.settings.get("boom"):
                raise RuntimeError("simulated backend refusal")
            account.settings.setdefault("private_key", f"gen-{account.account_id}")
            self.created.append(account.account_id)

        async def update_account(self, account) -> None:
            await self.create_account(account)

        async def delete_account(self, account_id: str) -> None:
            self.deleted.append(account_id)

        async def suspend_account(self, account_id: str) -> None:
            self.suspended.append(account_id)

        async def resume_account(self, account) -> None:
            self.resumed.append(account.account_id)

        async def build_client_config(self, account, node=None):
            return "wg://config"

        async def sync_accounts(self, accounts): pass

    class SecondRecorder(RecordingDriver):
        metadata = CoreMetadata(
            id="rec-two", name="Recorder Two", protocols=["hysteria2"],
            capabilities={Capability.USER_MANAGEMENT, Capability.SUSPEND_RESUME})


def _catalog(*entries: tuple[str, str, list[str]]):
    """(core_id, protocol, tags) → CatalogGroup list for the read-model stub."""
    groups: list[CatalogGroup] = []
    per_core: dict[str, CatalogGroup] = {}
    for core_id, protocol, tags in entries:
        group = per_core.setdefault(
            core_id, CatalogGroup(core_id=core_id, name=core_id, enabled=True))
        group.inbounds.extend(CatalogInbound(tag=t, protocol=protocol) for t in tags)
        if group not in groups:
            groups.append(group)
    return groups


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    db = tmp_path / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        monkeypatch.setenv(var, env[var])
    _migrate(env)

    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()
    one, two = RecordingDriver(), SecondRecorder()
    rt.core_manager.attach("rec-one", one, enabled=True)
    rt.core_manager.attach("rec-two", two, enabled=True)
    rt.rec_one = one
    rt.rec_two = two
    yield rt
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        monkeypatch.delenv(var, raising=False)


def _stub_catalog(monkeypatch, groups):
    from app.platform import provisioning

    async def _fake(runtime):
        return groups

    monkeypatch.setattr(provisioning, "build_inbound_catalog", _fake)

def test_sync_platform_user_mirrors_limits_expire_admin_and_quota(runtime):
    async def _go():
        from app.platform import provisioning

        expire = int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp())
        user = LegacyUser("bridge01", data_limit=5 * 1024**3, expire=expire,
                          admin_id=3, note="vip", used_traffic=123456)
        pid = await provisioning.sync_platform_user(runtime, user)
        row = runtime.users.get_user(pid)
        assert row.username == "bridge01"
        assert row.status == "active"
        assert row.data_limit_bytes == 5 * 1024**3
        assert row.expire_at is not None and abs(row.expire_at.timestamp() - expire) < 5
        # legacy admin ids never leak across engines: unmapped owner → NULL (honest)
        assert row.admin_id is None
        entry = await runtime.quota.get(pid)
        assert entry is not None and entry.total_bytes == 123456
        # A stale/lower legacy snapshot must never move the live unified quota
        # backwards (User Edit used to reset it and race recorder deltas).
        user.used_traffic = 50
        await provisioning.sync_platform_user(runtime, user)
        entry = await runtime.quota.get(pid)
        assert entry.total_bytes == 123456
        # Upgrade/bootstrap can still catch an older platform row up safely.
        user.used_traffic = 200000
        await provisioning.sync_platform_user(runtime, user)
        entry = await runtime.quota.get(pid)
        assert entry.total_bytes == 200000


    asyncio.run(_go())
def test_sync_legacy_accounts_mirrors_proxies_and_prunes(runtime):
    async def _go():
        from app.platform import provisioning

        user = LegacyUser("bridge02", proxies=[
            _LegacyProxy("vless", {"id": "uuid-1"}, excluded=["VLESS OLD"]),
            _LegacyProxy("shadowsocks", {"password": "pw"}),
        ], user_id=8)
        pid = await provisioning.sync_platform_user(runtime, user)
        await provisioning.sync_legacy_accounts(runtime, user, pid)
        rows = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "xray"]
        assert {a["protocol"] for a in rows} == {"vless", "shadowsocks"}
        vless = next(a for a in rows if a["protocol"] == "vless")
        assert vless["account_id"] == "8.bridge02.vless"
        assert vless["settings"]["id"] == "uuid-1"
        assert vless["settings"]["excluded_inbounds"] == ["VLESS OLD"]
        # dropping a proxy prunes the mirror honestly
        user.proxies = [p for p in user.proxies if p.type != "shadowsocks"]
        await provisioning.sync_legacy_accounts(runtime, user, pid)
        rows = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "xray"]
        assert {a["protocol"] for a in rows} == {"vless"}
        # disabled user disables the xray mirror rows too
        user.status = "disabled"
        await provisioning.sync_legacy_accounts(runtime, user, pid)
        rows = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "xray"]
        assert all(not a["enabled"] for a in rows)


    asyncio.run(_go())
def test_softether_multi_protocol_grant_uses_one_batch_reconcile(runtime, monkeypatch):
    async def _go():
        from app.cores.types import Capability, CoreMetadata
        from app.platform import provisioning

        driver = RecordingDriver()
        driver.metadata = CoreMetadata(
            id="softether", name="SoftEther",
            protocols=["softether", "sstp"],
            capabilities={Capability.USER_MANAGEMENT, Capability.SUSPEND_RESUME},
        )
        batches = []

        async def sync_accounts(accounts):
            batches.append([account.account_id for account in accounts])
            for account in accounts:
                account.settings.setdefault("password", "batch-generated")

        driver.sync_accounts = sync_accounts
        runtime.core_manager.attach("softether", driver, enabled=True)
        _stub_catalog(monkeypatch, _catalog(
            ("softether", "softether", ["native"]),
            ("softether", "sstp", ["sstp"]),
        ))
        user = LegacyUser("batch-se", user_id=81)
        pid = await provisioning.sync_user(runtime, user, grants={
            "softether": ["native", "sstp"],
        })
        assert len(batches) == 1
        assert set(batches[0]) == {
            "81.batch-se.softether", "81.batch-se.sstp",
        }
        rows = [row for row in runtime.users.accounts_of(pid)
                if row["core_id"] == "softether"]
        assert len(rows) == 2
        assert all(row["settings"]["password"] == "batch-generated" for row in rows)

    asyncio.run(_go())


def test_apply_grants_creates_accounts_on_both_cores(runtime, monkeypatch):
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(
            ("rec-one", "wireguard", ["wg0", "wg1"]),
            ("rec-two", "hysteria2", ["hy2"]),
        ))
        user = LegacyUser("bridge03", user_id=9)
        pid = await provisioning.sync_user(runtime, user, grants={
            "rec-one": ["wg0"], "rec-two": ["hy2"]})
        acc_one = "9.bridge03.wireguard"
        acc_two = "9.bridge03.hysteria2"
        assert runtime.rec_one.created == [acc_one]
        assert runtime.rec_two.created == [acc_two]
        rows = {a["core_id"]: a for a in runtime.users.accounts_of(pid)
                if a["core_id"] != "xray"}
        assert rows["rec-one"]["settings"]["private_key"] == f"gen-{acc_one}"  # persist-back
        assert rows["rec-one"]["settings"]["inbound_tags"] == ["wg0"]
        assert rows["rec-one"]["settings"]["excluded_inbounds"] == ["wg1"]  # subset select
        assert rows["rec-two"]["settings"]["inbound_tags"] == ["hy2"]
        # Idempotent metadata edits preserve generated credentials byte-for-byte.
        private_before = rows["rec-one"]["settings"]["private_key"]
        await provisioning.sync_user(runtime, user, grants={
            "rec-one": ["wg1"], "rec-two": ["hy2"]})
        counts = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"]
        assert len(counts) == 1
        assert counts[0]["settings"]["private_key"] == private_before
        assert counts[0]["settings"]["inbound_tags"] == ["wg1"]
        assert counts[0]["settings"]["excluded_inbounds"] == ["wg0"]


    asyncio.run(_go())


def test_softether_user_before_l2tp_reconciles_existing_account_and_replay(
    runtime, monkeypatch,
):
    """Regression for the real error-66 lifecycle report.

    A user first owns the native SoftEther grant while no L2TP inbound exists.
    After L2TP appears, saving both grants must update the existing live user,
    create only the genuinely missing L2TP identity, survive duplicate Save and
    replay, rotate a password, and remove only the revoked L2TP account.
    """
    async def _go():
        from app.cores.drivers.softether.driver import SoftEtherDriver
        from app.cores.exceptions import CoreError
        from app.cores.types import CoreState, UserAccount
        from app.platform import provisioning
        from tests.cores.fakes import FakeSEBackend

        class StrictSEBackend(FakeSEBackend):
            def __init__(self):
                super().__init__()
                self.create_calls: list[str] = []
                self.delete_calls: list[str] = []

            def user_create(self, username, note=""):
                self.create_calls.append(username)
                if username in self.users:
                    raise CoreError("UserCreate failed (error code 66)")
                self.users[username] = ""

            def user_delete(self, username):
                self.delete_calls.append(username)
                super().user_delete(username)

        backend = StrictSEBackend()
        settings = {
            "ipsec_psk": "unit-psk", "feature_softether": True,
            "feature_l2tp": False,
            "feature_tags": {"softether": "native-test"},
        }
        first = SoftEtherDriver(settings, backend=backend)
        runtime.core_manager.attach(
            "softether", first, enabled=True, state=CoreState.RUNNING)
        _stub_catalog(monkeypatch, _catalog(
            ("softether", "softether", ["native-test"]),
        ))
        user = LegacyUser("se-lifecycle", user_id=91)

        # User exists before any L2TP inbound.
        pid = await provisioning.sync_user(
            runtime, user, grants={"softether": ["native-test"]})
        native_id = "91.se-lifecycle.softether"
        l2tp_id = "91.se-lifecycle.l2tp"
        assert backend.create_calls == [native_id]
        assert native_id in backend.users and l2tp_id not in backend.users

        # L2TP is created later and the in-memory driver is fresh, matching a
        # container restart/account-replay gap. The native user must be found,
        # not created again; only the missing L2TP user is created.
        settings.update({
            "feature_l2tp": True,
            "feature_tags": {"softether": "native-test", "l2tp": "l2tp-new"},
        })
        fresh = SoftEtherDriver(settings, backend=backend)
        runtime.core_manager.attach(
            "softether", fresh, enabled=True, state=CoreState.RUNNING)
        _stub_catalog(monkeypatch, _catalog(
            ("softether", "softether", ["native-test"]),
            ("softether", "l2tp", ["l2tp-new"]),
        ))
        await provisioning.sync_user(runtime, user, grants={
            "softether": ["native-test", "l2tp-new"]})
        assert backend.create_calls == [native_id, l2tp_id]
        rows = [a for a in runtime.users.accounts_of(pid)
                if a["core_id"] == "softether"]
        assert {a["protocol"] for a in rows} == {"softether", "l2tp"}

        # Duplicate Save is idempotent.
        await provisioning.sync_user(runtime, user, grants={
            "softether": ["native-test", "l2tp-new"]})
        assert backend.create_calls == [native_id, l2tp_id]

        # Password rotation updates the existing live identity without create.
        l2tp_row = next(a for a in rows if a["protocol"] == "l2tp")
        rotated_settings = dict(l2tp_row["settings"])
        rotated_settings["password"] = "rotated-unit-password"
        await fresh.update_account(UserAccount(
            user_id=pid, username=user.username, account_id=l2tp_id,
            protocol="l2tp", enabled=True, settings=rotated_settings))
        assert backend.create_calls == [native_id, l2tp_id]
        assert backend.users[l2tp_id] == "rotated-unit-password"

        # Container recreation/account replay discovers both users and emits
        # no UserCreate. Persist the rotation first, then replay real SQL rows.
        runtime.users.upsert_core_account(
            user_id=pid, core_id="softether", account_id=l2tp_id,
            protocol="l2tp", enabled=True, settings=rotated_settings)
        replayed = SoftEtherDriver(settings, backend=backend)
        runtime.core_manager.attach(
            "softether", replayed, enabled=True, state=CoreState.RUNNING)
        deferred = await runtime._restore_core_accounts({"softether"})
        assert deferred == set()
        assert backend.create_calls == [native_id, l2tp_id]

        # Removing L2TP revokes only that account; native remains untouched.
        await provisioning.sync_user(
            runtime, user, grants={"softether": ["native-test"]})
        assert l2tp_id in backend.delete_calls
        assert native_id in backend.users and l2tp_id not in backend.users
        remaining = [a for a in runtime.users.accounts_of(pid)
                     if a["core_id"] == "softether"]
        assert [a["protocol"] for a in remaining] == ["softether"]

    asyncio.run(_go())


def test_apply_grants_revokes_unselected_and_names_unknowns(runtime, monkeypatch):
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg0"])))
        user = LegacyUser("bridge04", user_id=10)
        pid = await provisioning.sync_user(runtime, user, grants={"rec-one": ["wg0"]})
        # revoke by explicit empty list
        await provisioning.sync_user(runtime, user, grants={"rec-one": []})
        assert runtime.rec_one.deleted == ["10.bridge04.wireguard"]
        assert [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"] == []
        # unknown tag names the core AND the tag
        with pytest.raises(provisioning.GrantError) as ei:
            await provisioning.apply_grants(runtime, user, pid, {"rec-one": ["nope"]})
        assert "rec-one" in str(ei.value) and "nope" in str(ei.value)
        # unknown core names the core
        with pytest.raises(provisioning.GrantError) as ei:
            await provisioning.apply_grants(runtime, user, pid, {"ghost-core": ["x"]})
        assert "ghost-core" in str(ei.value)


    asyncio.run(_go())
def test_driver_failure_raises_named_core_and_persists_nothing(runtime, monkeypatch):
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg0"])))
        user = LegacyUser("bridge05", user_id=11)
        pid = await provisioning.sync_platform_user(runtime, user)

        original = runtime.rec_one.create_account

        async def _boom(account):
            await original(account.model_copy(update={
                "settings": {**account.settings, "boom": True}}))

        runtime.rec_one.create_account = _boom
        with pytest.raises(provisioning.GrantError) as ei:
            await provisioning.apply_grants(runtime, user, pid, {"rec-one": ["wg0"]})
        assert "rec-one" in str(ei.value)
        assert [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"] == []


    asyncio.run(_go())
def test_suspend_resume_follows_legacy_status(runtime, monkeypatch):
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg0"])))
        user = LegacyUser("bridge06", user_id=12)
        pid = await provisioning.sync_user(runtime, user, grants={"rec-one": ["wg0"]})
        acc = "12.bridge06.wireguard"
        user.status = "disabled"
        await provisioning.sync_user(runtime, user)
        assert acc in runtime.rec_one.suspended
        rows = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"]
        assert rows[0]["enabled"] is False
        user.status = "active"
        await provisioning.sync_user(runtime, user)
        assert acc in runtime.rec_one.resumed
        rows = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"]
        assert rows[0]["enabled"] is True


    asyncio.run(_go())
def test_remove_user_deletes_accounts_and_projection(runtime, monkeypatch):
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg0"])))
        user = LegacyUser("bridge07", user_id=13, proxies=[
            _LegacyProxy("vless", {"id": "uuid-7"})])
        pid = await provisioning.sync_user(runtime, user, grants={"rec-one": ["wg0"]})
        assert runtime.users.accounts_of(pid)
        await provisioning.remove_user(runtime, "bridge07")
        assert "13.bridge07.wireguard" in runtime.rec_one.deleted
        assert runtime.users.get_user_by_username("bridge07") is None
        assert runtime.users.accounts_of(pid) == []


    asyncio.run(_go())
def test_grants_of_reports_selection(runtime, monkeypatch):
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(
            ("rec-one", "wireguard", ["wg0"]), ("rec-two", "hysteria2", ["hy2"])))
        user = LegacyUser("bridge08", user_id=14)
        await provisioning.sync_user(runtime, user, grants={
            "rec-one": ["wg0"], "rec-two": ["hy2"]})
        grants = await provisioning.grants_of(runtime, "bridge08")
        assert grants == {"rec-one": ["wg0"], "rec-two": ["hy2"]}

    asyncio.run(_go())


def test_deleted_inbound_cascades_revoke_and_prune(runtime, monkeypatch):
    """Item 6A: deleting an inbounds through the studio must cascade into
    materialized grants — full revocation when the last tag is gone, in-place
    pruning when some remain. A later User Edit must never meet a ghost tag."""
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg-a", "wg-b"])))
        user = LegacyUser("cascade01", user_id=71)
        pid = await provisioning.sync_user(runtime, user,
                                           grants={"rec-one": ["wg-a", "wg-b"]})
        accounts = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"]
        assert len(accounts) == 1
        assert set(accounts[0]["settings"]["inbound_tags"]) == {"wg-a", "wg-b"}

        # wg-b deleted → pruned to wg-a, excluded recomputed from the live set
        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg-a"])))
        report = await provisioning.reconcile_accounts_after_inbound_change(runtime, "rec-one")
        assert report.get("pruned") == 1 and not report.get("revoked")
        acc = runtime.users.accounts_of(pid)[0]
        assert acc["settings"]["inbound_tags"] == ["wg-a"]
        assert acc["settings"]["excluded_inbounds"] == []

        # wg-a also deleted → account revoked on driver + store
        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg-c"])))
        report = await provisioning.reconcile_accounts_after_inbound_change(runtime, "rec-one")
        assert report.get("revoked") == 1
        assert [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"] == []
        assert runtime.rec_one.deleted, "driver must hear the revocation"
    asyncio.run(_go())


def test_added_inbound_persists_driver_generated_per_inbound_credentials(runtime, monkeypatch):
    """alpha.7.9: adding an inbound must persist credentials/addresses that
    update_account generates in place; otherwise profile two dies on reboot."""
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg-a"])))
        user = LegacyUser("cascade-hydrate", user_id=73)
        pid = await provisioning.sync_user(
            runtime, user, grants={"rec-one": ["wg-a"]})

        original_update = runtime.rec_one.update_account

        async def _hydrate(account):
            await original_update(account)
            account.settings.setdefault("inbound_addresses", {})["wg-b"] = "10.91.0.2/32"

        runtime.rec_one.update_account = _hydrate
        _stub_catalog(monkeypatch, _catalog(
            ("rec-one", "wireguard", ["wg-a", "wg-b"])))
        report = await provisioning.reconcile_accounts_after_inbound_change(
            runtime, "rec-one")
        assert report.get("hydrated") == 1
        stored = [account for account in runtime.users.accounts_of(pid)
                  if account["core_id"] == "rec-one"][0]
        assert stored["settings"]["inbound_addresses"]["wg-b"] == "10.91.0.2/32"
        assert stored["settings"]["inbound_tags"] == ["wg-a"]

    asyncio.run(_go())


def test_grant_save_with_dangling_tags_repairs_instead_of_422(runtime, monkeypatch):
    """Item 6B: a grant set carrying ONLY ghosts (e.g. written before the
    inbound was deleted) must not explode an unrelated Edit/Save — it is
    skipped with a logged warning and the user's accounts stay untouched."""
    async def _go():
        from app.platform import provisioning

        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg-a"])))
        user = LegacyUser("cascade02", user_id=72)
        pid = await provisioning.sync_user(runtime, user, grants={"rec-one": ["wg-a"]})
        assert len([a for a in runtime.users.accounts_of(pid)
                    if a["core_id"] == "rec-one"]) == 1

        _stub_catalog(monkeypatch, _catalog(("rec-one", "wireguard", ["wg-a", "wg-new"])))
        # ghost + valid mix: converges to the valid part (repair, no 422)
        await provisioning.sync_user(runtime, user,
                                     grants={"rec-one": ["wg-ghost", "wg-new"]})
        acc = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"][0]
        assert acc["settings"]["inbound_tags"] == ["wg-new"]

        # ghost ONLY: nothing valid to converge — accounts untouched, no exception
        await provisioning.sync_user(runtime, user, grants={"rec-one": ["wg-ghost"]})
        acc = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"][0]
        assert acc["settings"]["inbound_tags"] == ["wg-new"]
    asyncio.run(_go())
