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
        # re-sync converges to the new snapshot instead of accumulating
        user.used_traffic = 50
        await provisioning.sync_platform_user(runtime, user)
        entry = await runtime.quota.get(pid)
        assert entry.total_bytes == 50


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
        # idempotent: full re-sync provisions nothing twice
        await provisioning.sync_user(runtime, user, grants={"rec-one": ["wg0"], "rec-two": ["hy2"]})
        assert runtime.rec_one.created.count(acc_one) >= 1  # upsert path re-runs create
        counts = [a for a in runtime.users.accounts_of(pid) if a["core_id"] == "rec-one"]
        assert len(counts) == 1


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
