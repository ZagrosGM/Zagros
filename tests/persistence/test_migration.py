"""Zagros → Zagros migration tests against a real legacy v0.8.4-shaped DB.

The fixture database is created with raw sqlite3 using the actual legacy
column layout (users/proxies/hosts/nodes/admins/...), proving the importer
works on real exported Zagros databases without the legacy stack.

Run: pytest tests/persistence/test_migration.py -v  OR  python tests/persistence/test_migration.py
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import traceback
import types as _types
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


# ---------------------------------------------------------------------- #
# legacy fixture DB (Zagros v0.8.4 table shapes)
# ---------------------------------------------------------------------- #

def _create_legacy_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE admins (
        id INTEGER PRIMARY KEY, username VARCHAR(34) UNIQUE, hashed_password VARCHAR(128),
        created_at DATETIME, is_sudo BOOLEAN DEFAULT 0, password_reset_at DATETIME,
        telegram_id BIGINT, discord_webhook VARCHAR(1024), users_usage BIGINT DEFAULT 0);
    CREATE TABLE users (
        id INTEGER PRIMARY KEY, username VARCHAR(34) UNIQUE, status VARCHAR(20),
        used_traffic BIGINT DEFAULT 0, data_limit BIGINT, data_limit_reset_strategy VARCHAR(20),
        expire INTEGER, admin_id INTEGER, sub_revoked_at DATETIME, sub_updated_at DATETIME,
        sub_last_user_agent VARCHAR(512), created_at DATETIME, note VARCHAR(500),
        online_at DATETIME, on_hold_expire_duration BIGINT, on_hold_timeout DATETIME,
        auto_delete_in_days INTEGER, edit_at DATETIME, last_status_change DATETIME);
    CREATE TABLE proxies (id INTEGER PRIMARY KEY, user_id INTEGER, type VARCHAR(20), settings JSON);
    CREATE TABLE inbounds (id INTEGER PRIMARY KEY, tag VARCHAR(256) UNIQUE);
    CREATE TABLE exclude_inbounds_association (proxy_id INTEGER, inbound_tag VARCHAR(256));
    CREATE TABLE hosts (
        id INTEGER PRIMARY KEY, remark VARCHAR(256), address VARCHAR(256), port INTEGER,
        path VARCHAR(256), sni VARCHAR(1000), host VARCHAR(1000),
        security VARCHAR(20), alpn VARCHAR(20), fingerprint VARCHAR(20),
        inbound_tag VARCHAR(256), allowinsecure BOOLEAN, is_disabled BOOLEAN,
        mux_enable BOOLEAN, fragment_setting VARCHAR(100), noise_setting VARCHAR(2000),
        random_user_agent BOOLEAN, use_sni_as_host BOOLEAN);
    CREATE TABLE system (id INTEGER PRIMARY KEY, uplink BIGINT, downlink BIGINT);
    CREATE TABLE jwt (id INTEGER PRIMARY KEY, secret_key VARCHAR(64));
    CREATE TABLE nodes (
        id INTEGER PRIMARY KEY, name VARCHAR(256) UNIQUE, address VARCHAR(256), port INTEGER,
        api_port INTEGER, xray_version VARCHAR(32), status VARCHAR(20),
        last_status_change DATETIME, message VARCHAR(1024), created_at DATETIME,
        uplink BIGINT, downlink BIGINT, usage_coefficient FLOAT);
    CREATE TABLE user_usage_logs (
        id INTEGER PRIMARY KEY, user_id INTEGER, used_traffic_at_reset BIGINT, reset_at DATETIME);
    CREATE TABLE node_user_usages (
        id INTEGER PRIMARY KEY, created_at DATETIME, user_id INTEGER, node_id INTEGER,
        used_traffic BIGINT);
    """)
    c.execute("INSERT INTO admins VALUES (1, 'boss', '$2b$12$hashhash', '2024-01-01', 1, NULL, 4242, NULL, 0)")
    c.execute("INSERT INTO users VALUES (1, 'alice', 'active', 3221225472, 10737418240, "
              "'no_reset', 1757000000, 1, NULL, NULL, 'v2rayNG/1.8', '2024-05-01', 'vip', "
              "'2026-08-01', NULL, NULL, NULL, NULL, NULL)")
    c.execute("INSERT INTO users VALUES (2, 'bob', 'expired', 1073741824, 5368709120, "
              "'monthly', 1700000000, 1, NULL, NULL, NULL, '2024-06-01', NULL, NULL, "
              "NULL, NULL, NULL, NULL, NULL)")
    c.execute("INSERT INTO proxies VALUES (1, 1, 'vmess', '{\"id\": \"uuid-alice-vmess\"}')")
    c.execute("INSERT INTO proxies VALUES (2, 1, 'vless', '{\"id\": \"uuid-alice-vless\", \"flow\": \"\"}')")
    c.execute("INSERT INTO proxies VALUES (3, 1, 'trojan', '{\"password\": \"tr0jan!\"}')")
    c.execute("INSERT INTO proxies VALUES (4, 1, 'shadowsocks', '{\"password\": \"ss-pass\", \"method\": \"aes-128-gcm\"}')")
    c.execute("INSERT INTO proxies VALUES (5, 2, 'vless', '{\"id\": \"uuid-bob-vless\"}')")
    c.execute("INSERT INTO inbounds VALUES (1, 'VLESS_TCP_REALITY')")
    c.execute("INSERT INTO inbounds VALUES (2, 'VMESS_WS')")
    c.execute("INSERT INTO exclude_inbounds_association VALUES (2, 'VMESS_WS')")
    c.execute("INSERT INTO hosts VALUES (1, 'DE Reality', 'de.example.com', 443, NULL, "
              "'www.microsoft.com', NULL, 'reality', 'h2', 'chrome', 'VLESS_TCP_REALITY', "
              "0, 0, 0, NULL, NULL, 0, 0)")
    c.execute("INSERT INTO hosts VALUES (2, 'CDN', 'cdn.example.com', 2083, '/ws', "
              "'cdn.example.com', 'cdn.example.com', 'inbound_default', 'none', 'none', "
              "'VMESS_WS', 0, 1, 0, NULL, NULL, 0, 0)")
    c.execute("INSERT INTO system VALUES (1, 999, 888)")
    c.execute("INSERT INTO jwt VALUES (1, 'legacy-jwt-secret')")
    c.execute("INSERT INTO nodes VALUES (1, 'node-de', '10.0.0.5', 443, 62050, '1.8.6', "
              "'connected', '2026-08-01', NULL, '2025-01-01', 1000, 2000, 2.0)")
    c.execute("INSERT INTO user_usage_logs VALUES (1, 1, 5000000000, '2026-01-01')")
    c.execute("INSERT INTO node_user_usages VALUES (1, '2026-08-01 10:00', 1, 1, 12345)")
    conn.commit()
    conn.close()


def _fixture(tmp: str = "legacy.db") -> Path:
    path = Path(tempfile.mkdtemp(prefix="zglegacy-")) / tmp
    _create_legacy_db(path)
    return path


# ---------------------------------------------------------------------- #
# reader + pure plan
# ---------------------------------------------------------------------- #

def test_legacy_reader_reads_all_tables() -> None:
    from app.persistence.legacy_reader import read_legacy_sqlite

    snap = read_legacy_sqlite(_fixture())
    assert len(snap.users) == 2 and len(snap.proxies) == 5
    assert len(snap.hosts) == 2 and len(snap.nodes) == 1
    assert snap.system == {"id": 1, "uplink": 999, "downlink": 888}
    assert len(snap.usage_reset_logs) == 1


def test_plan_maps_users_accounts_hosts() -> None:
    import datetime

    from app.persistence.legacy_reader import read_legacy_sqlite
    from app.persistence.migration import build_migration_plan

    plan = build_migration_plan(read_legacy_sqlite(_fixture()))
    report = plan.report
    assert report.users_migrated == 2 and report.accounts_migrated == 5
    assert report.hosts_migrated == 2 and report.nodes_migrated == 1
    assert report.admins_migrated == 1

    alice = next(u for u in plan.users if u["username"] == "alice")
    assert alice["status"] == "active"
    assert alice["data_limit_bytes"] == 10737418240
    assert alice["expire_at"] == datetime.datetime.fromtimestamp(
        1757000000, tz=datetime.timezone.utc)
    usage = next(u for u in plan.usage if u["username"] == "alice")
    assert usage["used_bytes"] == 3221225472

    vless = next(a for a in plan.accounts if a["protocol"] == "vless"
                 and a["username"] == "alice")
    assert vless["account_id"] == "1.alice.vless"
    assert vless["settings"]["id"] == "uuid-alice-vless"
    assert vless["settings"]["excluded_inbounds"] == ["VMESS_WS"]  # assoc honored
    cdn = next(h for h in plan.hosts if h["remark"] == "CDN")
    assert cdn["security"] is None               # inbound_default normalized
    assert cdn["extras"]["is_disabled"] is True  # kept non-destructively
    # no data loss: legacy-only fields archived in audit
    assert any(a["action"] == "legacy.usage_reset" for a in plan.audit)
    assert any("inbound" in w.lower() for w in report.warnings)


# ---------------------------------------------------------------------- #
# apply + idempotency on the real Zagros schema
# ---------------------------------------------------------------------- #

def _target_factory():
    from app.persistence import create_schema, create_session_factory

    path = Path(tempfile.mkdtemp(prefix="zgtarget-")) / "zagros.db"
    sf = create_session_factory(f"sqlite:///{path}")
    create_schema(sf)
    return sf


def test_import_dry_run_then_apply_then_reapply_idempotent() -> None:
    from app.persistence.cipher import SecretsCipher
    from app.persistence.legacy_reader import read_legacy_sqlite
    from app.persistence.migration import LegacyImportService
    from app.persistence.models import UserModel, UserCoreAccountModel, CoreHostModel
    from app.persistence.repositories import SQLQuotaStore, UserRepository

    sf = _target_factory()
    repo = UserRepository(sf, SecretsCipher.from_master_secret("migration-test-key-32bytes!"))
    service = LegacyImportService(sf, repo, repo._cipher)
    snapshot = read_legacy_sqlite(_fixture())

    dry = service.migrate(snapshot, dry_run=True)
    assert dry.dry_run and dry.users_migrated == 2
    with sf() as s:  # dry run wrote nothing
        assert s.query(UserModel).count() == 0

    report1 = service.migrate(snapshot, dry_run=False)
    assert not report1.dry_run
    with sf() as s:
        assert s.query(UserModel).count() == 2
        assert s.query(UserCoreAccountModel).count() == 5
        assert s.query(CoreHostModel).count() == 2
        # marzban-era host attributes survive the migration (extras column)
        hosts = {h.remark: h for h in s.query(CoreHostModel)}
        assert hosts["CDN"].extras["is_disabled"] is True
        assert hosts["CDN"].extras["mux_enable"] is False
        assert hosts["CDN"].extras["inbound_tag"] == "VMESS_WS"
        assert hosts["DE Reality"].extras["inbound_tag"] == "VLESS_TCP_REALITY"

    # unified quota ledger got the legacy counters
    import asyncio
    entry = asyncio.run(SQLQuotaStore(sf).get(1))
    assert entry is not None and entry.total_bytes == 3221225472

    # accounts decrypt through the repository with row-bound AAD
    accounts = repo.accounts_of(1)
    assert len(accounts) == 4
    trojan = next(a for a in accounts if a["protocol"] == "trojan")
    assert trojan["settings"]["password"] == "tr0jan!"

    # SECOND run: everything converges, nothing duplicates
    report2 = service.migrate(snapshot, dry_run=False)
    with sf() as s:
        assert s.query(UserModel).count() == 2
        assert s.query(UserCoreAccountModel).count() == 5
        assert s.query(CoreHostModel).count() == 2
    assert report2.idempotent and report2.users_migrated == 2


def test_migration_status_and_disable_semantics() -> None:
    from app.persistence.cipher import SecretsCipher
    from app.persistence.legacy_reader import read_legacy_sqlite
    from app.persistence.migration import LegacyImportService
    from app.persistence.repositories import UserRepository

    sf = _target_factory()
    cipher = SecretsCipher.from_master_secret("migration-test-key-32bytes!")
    repo = UserRepository(sf, cipher)
    service = LegacyImportService(sf, repo, cipher)
    service.migrate(read_legacy_sqlite(_fixture()), dry_run=False)

    bob = repo.get_user_by_username("bob")
    assert bob.status == "expired"
    # expired user's accounts imported disabled -> not provisioned until resumed
    bob_accounts = repo.accounts_of(bob.id)
    assert bob_accounts and all(a["enabled"] is False for a in bob_accounts)
    alice_accounts = repo.accounts_of(1)
    assert all(a["enabled"] is True for a in alice_accounts)


if __name__ == "__main__":
    if not _HAS_SA:
        print("SKIPPED — sqlalchemy not installed")
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
