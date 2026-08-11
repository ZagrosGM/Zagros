"""Upgrade/restart recovery regressions for persisted core desired state.

These tests reproduce the alpha.7.7 architecture defect: SQL retained users,
credentials, Studio documents and core settings, but a recreated panel process
constructed empty driver account maps. No operator action had changed, yet
OpenVPN auth failed and config-render cores omitted old users/listeners.
"""
from __future__ import annotations

import asyncio
import copy
from types import SimpleNamespace

from app.cores.delivery import ArtifactKind, DeliveryContext
from app.cores.drivers.openvpn import OpenVPNDriver
from app.cores.drivers.singbox import SingBoxDriver
from app.cores.drivers.wireguard import WireGuardDriver
from app.cores.manager import CoreManager
from app.cores.types import CoreState
from app.platform.runtime import PlatformRuntime
from tests.cores.fakes import (
    FakeOpenVPNBackend,
    FakeSingBoxBackend,
    FakeV2RayStats,
    FakeWireGuardBackend,
)


class _Store:
    async def load(self): return {}
    async def save_state(self, core_id, *, state, enabled, settings=None): pass
    async def remove(self, core_id): pass


class _Users:
    def __init__(self, rows: list[dict], *, username: str = "upgrade-user"):
        self.rows = copy.deepcopy(rows)
        self.owner = SimpleNamespace(id=1, username=username, status="active")
        self.upserts: list[dict] = []

    def accounts_of_core(self, core_id: str, *, decrypt: bool = True):
        return [copy.deepcopy(r) for r in self.rows if r["core_id"] == core_id]

    def get_user(self, user_id: int):
        return self.owner if user_id == self.owner.id else None

    def upsert_core_account(self, **kwargs):
        self.upserts.append(copy.deepcopy(kwargs))
        for row in self.rows:
            if (row["core_id"], row["account_id"]) == (
                    kwargs["core_id"], kwargs["account_id"]):
                row["settings"] = copy.deepcopy(kwargs["settings"])


def _runtime(driver, core_id: str, rows: list[dict]):
    manager = CoreManager(_Store())
    manager.attach(core_id, driver, enabled=True, state=CoreState.STOPPED)
    runtime = SimpleNamespace(core_manager=manager, users=_Users(rows))
    restore = PlatformRuntime._restore_core_accounts.__get__(runtime, type(runtime))
    return runtime, restore


def _links(profile) -> list[str]:
    return [
        artifact.content
        for section in profile.sections
        for artifact in section.artifacts
        if artifact.kind is ArtifactKind.LINK and artifact.content
    ]


def test_singbox_subscription_is_byte_identical_after_process_upgrade(tmp_path) -> None:
    async def run() -> None:
        settings = {
            "work_dir": str(tmp_path),
            "cert_dir": str(tmp_path / "certs"),
            "advertise_host": "vpn.example.test",
            "stats_enabled": False,
        }
        document = {"inbounds": [{
            "tag": "hy-old", "protocol": "hysteria2",
            "listen": "0.0.0.0", "port": 38473,
            "transport": "quic", "security": "tls",
        }]}
        row = {
            "user_id": 1, "core_id": "sing-box",
            "account_id": "1.upgrade.hy", "protocol": "hysteria2",
            "enabled": True,
            "settings": {
                "password": "persisted-hy-password",
                "inbound_tags": ["hy-old"],
            },
        }
        context = DeliveryContext(public_host="vpn.example.test")

        old = SingBoxDriver(settings, backend=FakeSingBoxBackend(running=False),
                            stats=FakeV2RayStats())
        await old.apply_studio_document(document)
        from app.cores.types import UserAccount
        account = UserAccount(
            user_id=1, username="upgrade-user", account_id=row["account_id"],
            protocol=row["protocol"], enabled=True,
            settings=copy.deepcopy(row["settings"]),
        )
        await old.create_account(account)
        before = _links(await old.describe_delivery(account, context))

        # What an image upgrade does: a new driver object with the same SQL
        # and mounted files, but no in-memory accounts.
        new_backend = FakeSingBoxBackend(running=False)
        new = SingBoxDriver(settings, backend=new_backend, stats=FakeV2RayStats())
        await new.apply_studio_document(document)
        runtime, restore = _runtime(new, "sing-box", [row])
        assert await restore() == set()
        restored = new._accounts[row["account_id"]]
        after = _links(await new.describe_delivery(restored, context))

        assert after == before
        inbound = next(i for i in new_backend.configs[-1]["inbounds"]
                       if i["tag"] == "hy-old")
        assert inbound["listen"] == "0.0.0.0"
        assert inbound["listen_port"] == 38473
        assert inbound["users"] == [{
            "name": row["account_id"], "password": "persisted-hy-password",
        }]
        assert inbound["tls"]["enabled"] is True
        assert runtime.users.upserts == []  # byte-identical credentials: no churn

    asyncio.run(run())


def test_real_encrypted_sql_account_rehydrates_after_upgrade(tmp_path) -> None:
    from sqlalchemy import select

    from app.persistence.base import Base, create_session_factory
    from app.persistence.models import UserCoreAccountModel
    from app.persistence.repositories import SecretsCipher, UserRepository

    database = f"sqlite:///{tmp_path / 'upgrade.db'}"
    sf = create_session_factory(database)
    Base.metadata.create_all(sf.kw["bind"])
    users = UserRepository(
        sf, SecretsCipher.from_master_secret("upgrade-secret-0123456789"))
    user_id = users.upsert_user(username="sql-upgrade", status="active")
    password = "sql-persisted-openvpn-password"
    users.upsert_core_account(
        user_id=user_id, core_id="openvpn", account_id="71.sql.ovpn",
        protocol="ovpn", enabled=True,
        settings={"password": password, "inbound_tags": ["openvpn"]},
    )
    with sf() as session:
        encrypted = session.execute(
            select(UserCoreAccountModel.credentials_enc)
        ).scalar_one()
    assert password not in str(encrypted)

    backend = FakeOpenVPNBackend()
    backend.running = False
    driver = OpenVPNDriver(backend=backend)
    manager = CoreManager(_Store())
    manager.attach("openvpn", driver, enabled=True, state=CoreState.STOPPED)
    runtime = SimpleNamespace(core_manager=manager, users=users)
    restore = PlatformRuntime._restore_core_accounts.__get__(runtime, type(runtime))
    assert asyncio.run(restore()) == set()
    assert driver._authorize("71.sql.ovpn", password, {})


def test_openvpn_persisted_account_is_authorizable_before_listener_start() -> None:
    async def run() -> None:
        backend = FakeOpenVPNBackend()
        backend.running = False
        driver = OpenVPNDriver(backend=backend)
        row = {
            "user_id": 1, "core_id": "openvpn",
            "account_id": "1.upgrade.ovpn", "protocol": "ovpn",
            "enabled": True,
            "settings": {"password": "persisted-ovpn-password",
                         "inbound_tags": ["openvpn"]},
        }
        _runtime_obj, restore = _runtime(driver, "openvpn", [row])
        assert await restore() == set()
        assert driver._authorize("1.upgrade.ovpn", "persisted-ovpn-password", {})
        assert not driver._authorize("1.upgrade.ovpn", "wrong", {})

    asyncio.run(run())


def test_openvpn_upgrade_repairs_and_persists_old_missing_password() -> None:
    async def run() -> None:
        backend = FakeOpenVPNBackend()
        backend.running = False
        driver = OpenVPNDriver(backend=backend)
        row = {
            "user_id": 1, "core_id": "openvpn",
            "account_id": "1.upgrade.ovpn", "protocol": "ovpn",
            "enabled": True, "settings": {"inbound_tags": ["openvpn"]},
        }
        runtime, restore = _runtime(driver, "openvpn", [row])
        assert await restore() == set()
        assert len(runtime.users.upserts) == 1
        repaired = runtime.users.upserts[0]["settings"]["password"]
        assert repaired and driver._authorize("1.upgrade.ovpn", repaired, {})

    asyncio.run(run())


def test_wireguard_upgrade_restores_peer_before_interface_up(tmp_path) -> None:
    async def run() -> None:
        backend = FakeWireGuardBackend()
        backend.running = False
        driver = WireGuardDriver({
            "work_dir": str(tmp_path), "enable_nat": False,
            "advertise_host": "vpn.example.test",
        }, backend=backend)
        row = {
            "user_id": 1, "core_id": "wireguard",
            "account_id": "1.upgrade.wg", "protocol": "wireguard",
            "enabled": True,
            "settings": {
                "private_key": "client-private",
                "public_key": "A" * 43 + "=",
                "preshared_key": "B" * 43 + "=",
                "address": "10.66.66.2/32",
                "inbound_tags": ["wireguard"],
            },
        }
        _runtime_obj, restore = _runtime(driver, "wireguard", [row])
        assert await restore() == set()
        assert backend.synced == []  # offline restore must not fake liveness
        await driver.start()
        config = backend.synced[-1]
        assert "ListenPort = 51820" in config
        assert f"PublicKey = {'A' * 43}=" in config
        assert "AllowedIPs = 10.66.66.2/32" in config

    asyncio.run(run())
