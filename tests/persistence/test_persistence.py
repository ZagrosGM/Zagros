"""Persistence layer tests — SQL adapters for every hexagonal port.

Requires SQLAlchemy (declared in requirements); skipped cleanly when the
package is unavailable so the dependency-free suites stay green.

Run: pytest tests/persistence/test_persistence.py -v
  OR python tests/persistence/test_persistence.py
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import traceback
import types as _types
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

try:
    import sqlalchemy  # noqa: F401
    _HAS_SA = True
except ModuleNotFoundError:
    _HAS_SA = False

import pytest  # noqa: E402

pytestmark = pytest.mark.skipif(not _HAS_SA, reason="sqlalchemy not installed")


def _factory(tmp_name: str):
    from app.persistence import create_schema, create_session_factory

    path = Path(tempfile.mkdtemp(prefix="zgpersist-")) / tmp_name
    sf = create_session_factory(f"sqlite:///{path}")
    create_schema(sf)
    return sf


# ---------------------------------------------------------------------- #
# cipher
# ---------------------------------------------------------------------- #

def test_cipher_roundtrip_and_aad_binding() -> None:
    from app.persistence.cipher import CipherError, SecretsCipher

    cipher = SecretsCipher.from_master_secret("unit-test-master-secret-32b!")
    blob = cipher.encrypt_json({"uuid": "u-1", "password": "p"}, aad="7:xray:7.alice")
    assert blob.startswith("v1:")
    assert cipher.decrypt_json(blob, aad="7:xray:7.alice") == {"uuid": "u-1", "password": "p"}
    # swapped AAD (ciphertext moved to another row) must fail
    try:
        cipher.decrypt_json(blob, aad="8:xray:8.bob")
        raise AssertionError("ciphertext accepted under another row's AAD")
    except CipherError:
        pass
    # tampering must fail
    pos = len(blob) // 2
    raw = blob[:pos] + ("A" if blob[pos] != "A" else "B") + blob[pos + 1:]
    try:
        cipher.decrypt_json(raw, aad="7:xray:7.alice")
        raise AssertionError("tampered ciphertext accepted")
    except CipherError:
        pass
    try:
        SecretsCipher.from_master_secret("short")
        raise AssertionError("short master secret accepted")
    except CipherError:
        pass


# ---------------------------------------------------------------------- #
# core state store
# ---------------------------------------------------------------------- #

def test_core_state_store_roundtrip_and_merge() -> None:
    from app.cores.types import CoreState
    from app.persistence.repositories import SQLCoreStateStore

    store = SQLCoreStateStore(_factory("cores.db"))

    async def run():
        assert await store.load() == {}
        await store.save_state("wireguard", state=CoreState.RUNNING, enabled=True,
                               settings={"port": 51820, "nested": {"a": 1}})
        await store.save_state("xray", state=CoreState.STOPPED, enabled=False)
        loaded = await store.load()
        assert loaded["wireguard"]["state"] == CoreState.RUNNING.value
        assert loaded["wireguard"]["settings"]["port"] == 51820
        assert loaded["xray"]["enabled"] is False
        # settings merge semantics: None keeps existing, dict merges
        await store.save_state("wireguard", state=CoreState.STOPPED, enabled=False,
                               settings={"dns": ["1.1.1.1"]})
        loaded = await store.load()
        assert loaded["wireguard"]["settings"]["port"] == 51820
        assert loaded["wireguard"]["settings"]["dns"] == ["1.1.1.1"]
        await store.remove("xray")
        assert "xray" not in await store.load()

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# quota / baselines / journal
# ---------------------------------------------------------------------- #

def test_quota_store_ledger_semantics() -> None:
    from app.persistence.repositories import SQLQuotaStore, UserRepository

    sf = _factory("quota.db")
    uid = UserRepository(sf).upsert_user(username="alice")
    store = SQLQuotaStore(sf)

    async def run():
        assert await store.get(uid) is None
        e = await store.add(uid, 10, 100)
        assert (e.uplink_bytes, e.downlink_bytes) == (10, 100)
        e = await store.add(uid, 5, 50)
        assert e.total_bytes == 165
        all_entries = {x.user_id: x for x in await store.all()}
        assert all_entries[uid].total_bytes == 165
        await store.reset(uid)
        assert (await store.get(uid)).total_bytes == 0

    asyncio.run(run())


def test_baseline_store_persists_deltas() -> None:
    from app.persistence.repositories import SQLBaselineStore

    sf = _factory("baselines.db")
    store = SQLBaselineStore(sf)

    async def run():
        await store.set_many({"xray:1.alice": (10, 100), "wireguard:peer1": (3, 30)})
        # a "restart": a brand-new store instance on the same DB
        store2 = SQLBaselineStore(sf)
        got = await store2.get_many(["xray:1.alice", "wireguard:peer1", "missing"])
        assert got == {"xray:1.alice": (10, 100), "wireguard:peer1": (3, 30)}
        await store2.set_many({"xray:1.alice": (15, 150)})
        assert (await store2.get_many(["xray:1.alice"]))["xray:1.alice"] == (15, 150)
        await store2.drop("wireguard:peer1")
        assert "wireguard:peer1" not in await store2.get_many(["wireguard:peer1"])

    asyncio.run(run())


def test_usage_journal_appends_with_attribution() -> None:
    from app.cores.types import UsageRecord
    from app.persistence.repositories import SQLUsageJournal, UserRepository

    sf = _factory("journal.db")
    repo = UserRepository(sf)
    repo.upsert_user(username="alice")  # FK target for attributed records
    journal = SQLUsageJournal(sf)
    records = [
        UsageRecord(core_id="xray", account_id="7.alice", uplink_bytes=1, downlink_bytes=10),
        UsageRecord(core_id="wg", account_id="peer-1", uplink_bytes=2, downlink_bytes=20),
    ]

    async def run():
        user = repo.get_user_by_username("alice")
        n = await journal.append(records, {("xray", "7.alice"): user.id})
        assert n == 2
    asyncio.run(run())


def test_usage_journal_totals_by_core() -> None:
    """Item 17: per-core totals = exact GROUP-BY sum of journaled deltas."""
    from app.cores.types import UsageRecord
    from app.persistence.repositories import SQLUsageJournal, UserRepository

    sf = _factory("journal-totals.db")
    repo = UserRepository(sf)
    repo.upsert_user(username="alice")
    journal = SQLUsageJournal(sf)

    async def run():
        user = repo.get_user_by_username("alice")
        owners = {("sing-box", "7.alice"): user.id, ("wg", "p1"): user.id}
        for batch in (
            [UsageRecord(core_id="sing-box", account_id="7.alice",
                         uplink_bytes=5, downlink_bytes=100),
             UsageRecord(core_id="wg", account_id="p1", uplink_bytes=3, downlink_bytes=30)],
            [UsageRecord(core_id="sing-box", account_id="7.alice",
                         uplink_bytes=5, downlink_bytes=50)],
        ):
            await journal.append(batch, owners)
        totals = await journal.totals_by_core()
        assert totals == {"sing-box": (10, 150), "wg": (3, 30)}
    asyncio.run(run())


# ---------------------------------------------------------------------- #
# devices & sessions
# ---------------------------------------------------------------------- #

def test_device_store_crud_and_set_field() -> None:
    from app.cores.devices import DeviceInfo
    from app.persistence.repositories import SQLDeviceStore, UserRepository

    sf = _factory("devices.db")
    UserRepository(sf).upsert_user(username="alice")  # FK target
    alice = UserRepository(sf).get_user_by_username("alice")
    store = SQLDeviceStore(sf)
    device = DeviceInfo(device_id="d-1", user_id=alice.id, platform="android",
                        app_version="1.0", last_ip="10.0.0.2",
                        current_core="xray", cores={"xray", "wireguard"})

    async def run():
        await store.upsert(device)
        got = await store.get("d-1")
        assert got is not None and got.cores == {"xray", "wireguard"}
        assert got.first_seen.tzinfo is not None  # UtcDateTime contract
        device.platform = "ios"
        device.cores.add("openvpn")
        await store.upsert(device)
        assert (await store.get("d-1")).cores == {"xray", "wireguard", "openvpn"}
        assert len(await store.for_user(alice.id)) == 1
        assert len(await store.all()) == 1

    asyncio.run(run())


def test_session_store_history_filters_and_order() -> None:
    from app.cores.sessions import SessionRecord
    from app.persistence.repositories import SQLSessionStore, UserRepository

    sf = _factory("sessions.db")
    repo = UserRepository(sf)
    u7 = repo.upsert_user(username="alice")   # FK targets
    u9 = repo.upsert_user(username="bob")
    store = SQLSessionStore(sf)
    now = datetime.now(timezone.utc)
    records = [
        SessionRecord(key="k1", user_id=u7, core_id="xray", account_id="7.alice",
                      ip="1.1.1.1", started_at=now - timedelta(hours=3),
                      ended_at=now - timedelta(hours=2), duration_seconds=3600,
                      rx_bytes=1, tx_bytes=2),
        SessionRecord(key="k2", user_id=u7, core_id="wg", account_id="peer-1",
                      ip="1.1.1.2", started_at=now - timedelta(hours=1),
                      ended_at=now, duration_seconds=3200, rx_bytes=3, tx_bytes=4),
        SessionRecord(key="k3", user_id=u9, core_id="xray", account_id="9.bob",
                      started_at=now - timedelta(minutes=30), ended_at=now,
                      duration_seconds=100),
    ]

    async def run():
        for r in records:
            await store.append(r)
        hist7 = await store.history(user_id=u7)
        assert [h.key for h in hist7] == ["k2", "k1"]  # newest ended first
        assert len(await store.history(account_id="9.bob")) == 1
        assert len(await store.history(limit=2)) == 2
        assert hist7[0].rx_bytes == 3

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# portal settings & refresh tokens
# ---------------------------------------------------------------------- #

def test_portal_settings_sql_roundtrip() -> None:
    from app.portal.models import ClientAuthMode, PortalSettings
    from app.persistence.repositories import SQLPortalSettingsStore

    store = SQLPortalSettingsStore(_factory("settings.db"))

    async def run():
        assert (await store.get_portal_settings()).brand == "Zagros"
        new = PortalSettings(client_auth_mode=ClientAuthMode.APPLICATION_LOGIN,
                             brand="Zagros Panel", default_lang="en")
        await store.save_portal_settings(new)
        got = await store.get_portal_settings()
        assert got.client_auth_mode is ClientAuthMode.APPLICATION_LOGIN
        assert got.brand == "Zagros Panel" and got.default_lang == "en"

    asyncio.run(run())


def test_refresh_token_store_lifecycle() -> None:
    from app.persistence.repositories import SQLRefreshTokenStore, UserRepository

    sf = _factory("tokens.db")
    uid7 = UserRepository(sf).upsert_user(username="alice")  # FK target
    store = SQLRefreshTokenStore(sf)
    exp = datetime.now(timezone.utc) + timedelta(days=30)

    async def run():
        await store.save(uid7, "hash-1", exp)
        row = await store.get("hash-1")
        assert row is not None and row.user_id == uid7 and not row.revoked
        assert row.expires_at.tzinfo is not None
        await store.revoke("hash-1", rotated_to="hash-2")
        row = await store.get("hash-1")
        assert row.revoked and row.rotated_to == "hash-2"
        await store.save(uid7, "hash-3", exp)
        await store.revoke_all_for_user(uid7)
        assert (await store.get("hash-3")).revoked

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# user repository: users + encrypted core accounts
# ---------------------------------------------------------------------- #

def test_user_repository_idempotency_and_credentials() -> None:
    from app.persistence.cipher import SecretsCipher
    from app.persistence.repositories import UserRepository

    cipher = SecretsCipher.from_master_secret("unit-test-master-secret-32b!")
    repo = UserRepository(_factory("users.db"), cipher)

    uid1 = repo.upsert_user(username="alice", data_limit_bytes=10_000_000_000,
                            expire_at=datetime(2026, 9, 1, tzinfo=timezone.utc))
    uid2 = repo.upsert_user(username="alice", status="limited")  # idempotent
    assert uid1 == uid2
    user = repo.get_user(uid1)
    assert user.status == "limited" and user.data_limit_bytes == 10_000_000_000
    assert user.expire_at.tzinfo is not None

    acc_id1 = repo.upsert_core_account(
        user_id=uid1, core_id="wireguard", account_id=f"{uid1}.alice",
        protocol="wireguard", settings={"private_key": "K" * 44, "address": "10.9.0.2/32"},
    )
    acc_id2 = repo.upsert_core_account(
        user_id=uid1, core_id="wireguard", account_id=f"{uid1}.alice",
        protocol="wireguard", settings={"private_key": "L" * 44, "address": "10.9.0.2/32"},
    )
    assert acc_id1 == acc_id2  # no duplicates on re-run
    accounts = repo.accounts_of(uid1)
    assert len(accounts) == 1
    assert accounts[0]["settings"]["private_key"] == "L" * 44  # latest wins

    # ciphertext is actually at rest (not plaintext JSON in the DB)
    from sqlalchemy import select

    from app.persistence.models import UserCoreAccountModel
    with repo._sf() as s:
        row = s.execute(select(UserCoreAccountModel)).scalar_one()
        assert row.credentials_enc.startswith("v1:")
        assert "L" * 44 not in row.credentials_enc

    repo.set_account_enabled(user_id=uid1, core_id="wireguard",
                             account_id=f"{uid1}.alice", enabled=False)
    assert repo.accounts_of(uid1)[0]["enabled"] is False
    owners = repo.account_owners()
    assert owners == {("wireguard", f"{uid1}.alice"): uid1}

    repo.delete_account(user_id=uid1, core_id="wireguard", account_id=f"{uid1}.alice")
    repo.delete_user(uid2 := uid1)
    assert repo.get_user(uid2) is None


def test_repository_rejects_credentials_without_cipher() -> None:
    from app.persistence.repositories import UserRepository

    repo = UserRepository(_factory("nocipher.db"), cipher=None)
    uid = repo.upsert_user(username="bob")
    try:
        repo.upsert_core_account(user_id=uid, core_id="xray", account_id="1.b",
                                 protocol="vless", settings={"id": "x"})
        raise AssertionError("stored credentials without cipher")
    except ValueError:
        pass


if __name__ == "__main__":
    if not _HAS_SA:
        print("SKIPPED — sqlalchemy not installed (pip install -r requirements.txt)")
        sys.exit(0)
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
