from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.cores.base import BaseCoreDriver
from app.cores.devices import InMemoryDeviceStore
from app.cores.types import (
    Capability, CoreMetadata, CoreStatus, CoreState, DeviceSession,
    HealthStatus, ListenerClaim,
)
from app.persistence.base import Base, create_session_factory
from app.persistence.models import (
    IPActivityModel, IPBanModel, SubscriptionDeviceModel, UserModel,
)
from app.platform import device_enrollment, ip_limits, monitoring


class Driver(BaseCoreDriver):
    metadata = CoreMetadata(
        id="fake-ip", name="fake", protocols=["fake"],
        capabilities={Capability.ONLINE_TRACKING},
    )

    def __init__(self):
        super().__init__({})
        self.sessions = [DeviceSession(core_id="fake-ip", account_id="acct", ip="198.51.100.1")]
        self.closed: list[str] = []

    async def start(self): pass
    async def stop(self): pass
    async def create_account(self, account): pass
    async def update_account(self, account): pass
    async def delete_account(self, account_id): pass
    async def build_client_config(self, account): raise NotImplementedError

    async def status(self):
        return CoreStatus(core_id="fake-ip", state=CoreState.RUNNING,
                          health=HealthStatus.HEALTHY)

    async def get_online_devices(self, account_ids=None):
        return list(self.sessions)

    async def listener_claims(self):
        return [
            ListenerClaim(core_id="fake-ip", protocol="fake", transport="tcp",
                          port=2443, label="vpn"),
            ListenerClaim(core_id="fake-ip", protocol="admin", transport="tcp",
                          address="127.0.0.1", port=8000, label="private"),
        ]

    async def terminate_source_ip(self, ip):
        self.closed.append(ip)
        return 1


class Users:
    def account_owners(self):
        return {("fake-ip", "acct"): 1}

    def get_user_by_username(self, username):
        return None


class Manager:
    def __init__(self, driver): self.driver = driver
    def list_cores(self): return ["fake-ip"]
    def is_enabled(self, core_id): return True
    def get(self, core_id): return self.driver


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    sf = create_session_factory(f"sqlite:///{tmp_path / 'platform.db'}")
    Base.metadata.create_all(sf.kw["bind"])
    with sf() as s:
        s.add(UserModel(id=1, username="alice", status="active", ip_limit=1,
                        device_limit=1))
        s.commit()
    driver = Driver()
    rt = SimpleNamespace(session_factory=sf, users=Users(),
                         core_manager=Manager(driver),
                         devices=InMemoryDeviceStore())
    monkeypatch.setattr(ip_limits, "apply_firewall", lambda *a, **k: True)
    monkeypatch.setattr(ip_limits, "_push_node_bans", lambda *a, **k: _zero())
    from app.platform import device_limits
    monkeypatch.setattr(device_limits, "publish_online_snapshot", _noop)
    ip_limits._LAST_RUN = 0
    return rt, driver


async def _zero(): return 0
async def _noop(*args, **kwargs): return None


@pytest.mark.asyncio
async def test_newest_ip_only_is_timed_banned_and_account_stays_active(runtime):
    rt, driver = runtime
    first = await ip_limits.run_once(rt, force=True)
    assert first["banned"] == 0

    driver.sessions.append(DeviceSession(
        core_id="fake-ip", account_id="acct", ip="198.51.100.2"))
    second = await ip_limits.run_once(rt, force=True)
    assert second["banned"] == 1
    assert driver.closed == ["198.51.100.2"]
    with rt.session_factory() as s:
        user = s.get(UserModel, 1)
        ban = s.execute(select(IPBanModel)).scalar_one()
        assert user.status == "active"
        assert ban.ip == "198.51.100.2" and ban.active
        assert timedelta(minutes=14) < ban.expires_at - datetime.now(timezone.utc) <= timedelta(minutes=15)
        original_expiry = ban.expires_at

    again = await ip_limits.run_once(rt, force=True)
    assert again["banned"] == 0
    with rt.session_factory() as s:
        assert s.execute(select(IPBanModel)).scalar_one().expires_at == original_expiry


@pytest.mark.asyncio
async def test_firewall_scope_contains_only_managed_public_vpn_ports(runtime):
    rt, _driver = runtime
    tcp, udp = await ip_limits.managed_ports(rt)
    assert tcp == {2443}
    assert udp == set()
    now = datetime.now(timezone.utc)
    ban = IPBanModel(user_id=1, ip="198.51.100.2", banned_at=now,
                     expires_at=now + timedelta(minutes=15),
                     reason="test", active=True)
    script = ip_limits._nft_script([ban], tcp, udp, now)
    assert "198.51.100.2 timeout 900s" in script
    assert "2443" in script
    assert "8000" not in script
    assert "elements = {  }" not in script


@pytest.mark.asyncio
async def test_scheduler_guard_skips_overlapping_pass(runtime, monkeypatch):
    rt, _driver = runtime
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_collect(_runtime):
        entered.set()
        await release.wait()
        return {}, set(), [], 1

    monkeypatch.setattr(ip_limits, "collect_observations", slow_collect)
    first_task = asyncio.create_task(ip_limits.run_once(rt, force=True))
    await entered.wait()
    overlapping = await ip_limits.run_once(rt, force=True)
    assert overlapping["skipped"] == 1
    release.set()
    completed = await first_task
    assert completed["skipped"] == 0


@pytest.mark.asyncio
async def test_expired_ban_is_deactivated_after_source_disconnects(runtime):
    rt, driver = runtime
    await ip_limits.run_once(rt, force=True)
    driver.sessions.append(DeviceSession(
        core_id="fake-ip", account_id="acct", ip="198.51.100.2"))
    await ip_limits.run_once(rt, force=True)
    with rt.session_factory() as s:
        ban = s.execute(select(IPBanModel)).scalar_one()
        ban.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        s.commit()
    driver.sessions = driver.sessions[:1]
    result = await ip_limits.run_once(rt, force=True)
    assert result["expired"] == 1
    assert ip_limits.list_bans(rt, active_only=True) == []


@pytest.mark.asyncio
async def test_device_limit_requires_header_and_enrolls_stable_ids(runtime):
    rt, _driver = runtime
    with pytest.raises(device_enrollment.DeviceEnrollmentError, match="requires"):
        await device_enrollment.enforce(rt, 1, {}, "client")

    first = "install-550e8400-e29b-41d4-a716-446655440000"
    result = await device_enrollment.enforce(rt, 1, {"x-device-id": first}, "app/1")
    assert result["enrolled"] is True
    repeat = await device_enrollment.enforce(rt, 1, {"x-hwid": first}, "app/2")
    assert repeat["enrolled"] is False
    with pytest.raises(device_enrollment.DeviceEnrollmentError, match="limit reached"):
        await device_enrollment.enforce(rt, 1, {"x-device-id": "different-install-id"})

    with rt.session_factory() as s:
        row = s.execute(select(SubscriptionDeviceModel)).scalar_one()
        assert row.device_hash != first and first not in row.device_hint
        enrolled_id = row.id
    assert device_enrollment.remove_device(rt, 1, enrolled_id) == 1
    allowed = await device_enrollment.enforce(
        rt, 1, {"x-device-id": "different-install-id"})
    assert allowed["enrolled"] is True


@pytest.mark.asyncio
async def test_one_poll_feeds_live_and_ip_activity_without_creating_devices(runtime):
    rt, driver = runtime
    await ip_limits.run_once(rt, force=True)
    live = monitoring.live_connections(rt, page=1, page_size=10)
    ips = monitoring.ip_activity(rt, page=1, page_size=10)
    assert live["total"] == ips["total"] == 1
    assert live["items"][0]["ip"] == ips["items"][0]["ip"] == "198.51.100.1"
    assert await rt.devices.all() == []  # source IP is never promoted to HWID
    with rt.session_factory() as s:
        persisted = s.execute(select(IPActivityModel)).scalar_one()
        assert persisted.user_id == 1 and persisted.ip == "198.51.100.1"

    await device_enrollment.enforce(
        rt, 1, {"x-device-id": "persistent-hwid"}, "app", "203.0.113.5")
    driver.sessions = []
    await ip_limits.run_once(rt, force=True)
    assert monitoring.live_connections(rt)["total"] == 0
    devices = monitoring.enrolled_devices(rt)
    assert devices["total"] == 1
    assert "203.0.113.5" not in devices["items"][0]["device"]
    assert devices["items"][0]["last_ip"] == "203.0.113.5"


@pytest.mark.asyncio
async def test_ip_and_hwid_limits_are_independent(runtime):
    rt, driver = runtime
    await device_enrollment.enforce(rt, 1, {"x-device-id": "device-install-one"})
    driver.sessions.append(DeviceSession(
        core_id="fake-ip", account_id="acct", ip="198.51.100.9"))
    result = await ip_limits.run_once(rt, force=True)
    assert result["banned"] == 1
    with rt.session_factory() as s:
        assert s.scalar(select(UserModel.device_limit).where(UserModel.id == 1)) == 1
        assert s.scalar(select(UserModel.ip_limit).where(UserModel.id == 1)) == 1
        assert s.scalar(select(UserModel.status).where(UserModel.id == 1)) == "active"
