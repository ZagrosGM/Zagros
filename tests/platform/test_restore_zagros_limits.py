"""f-backlimit-1 (v1.1.3 bugfix 4) — restoring a Zagros database keeps every
user's quota, expiry and proxy credentials.

The old ``read_zagros_platform`` treated the ``users`` table as PLATFORM rows
unconditionally:
* a pre-dbmerge ``zagros.db`` (legacy Marzban schema) read
  ``data_limit_bytes``/``expire_at`` columns that do not exist there — every
  row mapped to NULL and the row-level import re-created EVERY USER
  UNLIMITED and never-expiring;
* a merged single-file database imported the platform rows but ignored the
  legacy layer (``legacy_users`` + ``proxies``) — the actual panel user list
  with credentials.
"""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy",)
pytestmark = pytest.mark.skipif(
    not all(importlib.util.find_spec(m) for m in _NEED),
    reason="sqlalchemy not installed")

_EXPIRE = 1893456000          # 2030-01-01 epoch
_LIMIT = 1073741824           # 1 GiB


def _legacy_schema(db_path: Path) -> None:
    """A pre-merge zagros.db: the LEGACY Marzban layout (the merge renamed
    these tables later; pre-merge files keep the original names)."""
    con = sqlite3.connect(db_path)
    con.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, username VARCHAR(64), status VARCHAR(20),
            used_traffic BIGINT, data_limit BIGINT, expire INTEGER,
            data_limit_reset_strategy VARCHAR(32), note VARCHAR(1024),
            admin_id INTEGER, created_at DATETIME);
        CREATE TABLE proxies (
            id INTEGER PRIMARY KEY, user_id INTEGER, type VARCHAR(32),
            settings VARCHAR(1024));
        CREATE TABLE admins (
            id INTEGER PRIMARY KEY, username VARCHAR(64),
            hashed_password VARCHAR(256), is_sudo BOOLEAN);
        INSERT INTO users VALUES
            (11, 'alice', 'active', 123, 1073741824, 1893456000,
             'no_reset', NULL, 1, '2026-01-01 00:00:00'),
            (12, 'bob', 'active', 0, NULL, NULL, 'no_reset', 'unlimited is deliberate',
             1, '2026-01-02 00:00:00');
        INSERT INTO proxies VALUES (1, 11, 'vless', '{"id":"u1"}'),
                                   (2, 12, 'vmess', '{"id":"u2"}');
        INSERT INTO admins VALUES (1, 'root', '$2b$12$' || 'x' || 'placeholder', 1);
    """)
    con.commit()
    con.close()


def _merged_schema(db_path: Path) -> None:
    """A merged single-file database: platform ``users``/``admins`` PLUS the
    renamed legacy layer (``legacy_users``/``legacy_admins``/``proxies``)."""
    con = sqlite3.connect(db_path)
    con.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, username VARCHAR(64), status VARCHAR(20),
            note VARCHAR(500), data_limit_bytes BIGINT,
            data_limit_reset_strategy VARCHAR(20), expire_at DATETIME,
            ip_limit INTEGER, device_limit INTEGER,
            download_limit_mbps INTEGER DEFAULT 0, upload_limit_mbps INTEGER DEFAULT 0,
            admin_id INTEGER, created_at DATETIME, online_at DATETIME,
            access_mode VARCHAR(32), client_auth_mode VARCHAR(32),
            app_username VARCHAR(64), app_password_hash VARCHAR(256));
        CREATE TABLE legacy_users (
            id INTEGER PRIMARY KEY, username VARCHAR(64), status VARCHAR(20),
            used_traffic BIGINT, data_limit BIGINT, expire INTEGER,
            data_limit_reset_strategy VARCHAR(32), note VARCHAR(1024),
            admin_id INTEGER, created_at DATETIME,
            ip_limit INTEGER, device_limit INTEGER,
            download_limit_mbps INTEGER DEFAULT 0, upload_limit_mbps INTEGER DEFAULT 0,
            on_hold_timeout DATETIME, on_hold_expire_duration BIGINT,
            auto_delete_in_days INTEGER, telegram_id BIGINT,
            next_plan_id INTEGER);
        CREATE TABLE proxies (
            id INTEGER PRIMARY KEY, user_id INTEGER, type VARCHAR(32),
            settings VARCHAR(1024));
        CREATE TABLE admins (
            id INTEGER PRIMARY KEY, username VARCHAR(64),
            password_hash VARCHAR(256), is_sudo BOOLEAN, created_at DATETIME,
            telegram_id BIGINT);
        CREATE TABLE legacy_admins (
            id INTEGER PRIMARY KEY, username VARCHAR(64),
            hashed_password VARCHAR(256), is_sudo BOOLEAN,
            password_reset_at DATETIME, telegram_id BIGINT,
            discord_webhook VARCHAR(1024), permissions VARCHAR(4000),
            users_usage BIGINT, created_at DATETIME);
        CREATE TABLE user_usage (
            user_id INTEGER, uplink_bytes BIGINT, downlink_bytes BIGINT);
        -- platform-only user: never had a legacy twin
        INSERT INTO users VALUES
            (5, 'carol', 'active', NULL, 999, 'no_reset', '2031-06-01 00:00:00',
             NULL, NULL, 0, 0, 1, '2026-02-01 00:00:00', NULL, NULL, NULL,
             NULL, NULL);
        -- legacy layer: quota/expiry/proxies live HERE
        INSERT INTO legacy_users VALUES
            (11, 'alice', 'active', 123, 1073741824, 1893456000, 'no_reset',
             NULL, 1, '2026-01-01 00:00:00', 3, 2, 0, 0, NULL, 0, 0, NULL, NULL),
            (12, 'bob', 'active', 0, NULL, NULL, 'no_reset', NULL, 1,
             '2026-01-02 00:00:00', NULL, NULL, 0, 0, NULL, 0, 0, NULL, NULL);
        INSERT INTO proxies VALUES (1, 11, 'vless', '{"id":"u1"}'),
                                   (2, 12, 'vmess', '{"id":"u2"}');
        INSERT INTO admins VALUES (2, 'platadmin', 'x-nonverifiable', 0,
                                   '2026-02-01 00:00:00', NULL);
        INSERT INTO legacy_admins VALUES (1, 'root',
            '$2b$12$abcdefghijklmnopqrstuv', 1, NULL, NULL, NULL, NULL, 0,
            '2026-01-01 00:00:00');
    """)
    con.commit()
    con.close()


def test_pre_merge_database_keeps_quota_expiry_proxies(tmp_path):
    """THE production report: pre-merge zagros.db imported → every user came
    back unlimited. Now the legacy schema is recognized and quota/expiry and
    the proxy credentials survive."""
    from app.platform.restore_sources import read_zagros_platform

    db = tmp_path / "legacy-zagros.db"
    _legacy_schema(db)
    snapshot, notes = read_zagros_platform(db)
    assert notes.get("schema") == "legacy (pre-merge)"
    users = {u["username"]: u for u in snapshot.users}
    alice = users["alice"]
    assert alice["data_limit"] == _LIMIT, "quota preserved — not NULL/unlimited"
    assert alice["expire"] == _EXPIRE, "expiry preserved — not NULL/never"
    bob = users["bob"]
    assert bob["data_limit"] is None, "a deliberately unlimited user stays unlimited"
    assert bob["note"] == "unlimited is deliberate"
    by_user = {p["user_id"]: p for p in snapshot.proxies}
    assert by_user[11]["type"] == "vless", "proxy credentials carried over"
    assert len(snapshot.admins) == 1
    assert snapshot.admins[0]["username"] == "root"


def test_merged_database_prefers_legacy_layer(tmp_path):
    """Merged single file: the legacy layer (quota/expiry/proxies) feeds the
    panel user list; platform-only users still import; no duplicates."""
    from app.platform.restore_sources import read_zagros_platform

    db = tmp_path / "merged.db"
    _merged_schema(db)
    snapshot, notes = read_zagros_platform(db)
    assert notes.get("schema") == "merged"
    names = [u["username"] for u in snapshot.users]
    assert sorted(names) == ["alice", "bob", "carol"], "no duplicate usernames"
    users = {u["username"]: u for u in snapshot.users}
    alice = users["alice"]
    assert alice["data_limit"] == _LIMIT
    assert alice["expire"] == _EXPIRE
    assert alice["ip_limit"] == 3 and alice["device_limit"] == 2
    bob = users["bob"]
    assert bob["data_limit"] is None and bob["expire"] is None
    carol = users["carol"]
    assert carol["data_limit"] == 999, "platform-only user carried by its own row"
    assert carol["expire"] is not None
    by_user = {p["user_id"]: p for p in snapshot.proxies}
    assert by_user[11]["type"] == "vless" and by_user[12]["type"] == "vmess"
    # admins: legacy hashes preferred, platform-only admin appended
    admin_names = {a["username"] for a in snapshot.admins}
    assert admin_names == {"root", "platadmin"}
    root = next(a for a in snapshot.admins if a["username"] == "root")
    assert root["hashed_password"].startswith("$2b$12$")


def test_merged_import_writes_limited_legacy_user(tmp_path):
    """End-to-end through the row-level importer: the snapshot a merged file
    produces re-creates a user WITH its data limit (the bug made everyone
    unlimited)."""
    import app.db.models  # noqa: F401 — warm the graph first (legacy_import
    # pulls app.models.user → app.xray; importing the legacy models first
    # breaks that cycle, same as tests/persistence/test_legacy_import.py)
    from app.platform.restore_sources import read_zagros_platform
    from app.persistence.legacy_import import import_users
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models import Base as LegacyBase

    db = tmp_path / "merged.db"
    _merged_schema(db)
    snapshot, _notes = read_zagros_platform(db)

    target = tmp_path / "panel.db"
    engine = create_engine(f"sqlite:///{target}")
    # enable FK pragma like the panel harness
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _fk(dbapi_con, _rec):
        cur = dbapi_con.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    LegacyBase.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    report = import_users(snapshot, session_factory)
    assert report["created"] >= 3, f"users imported: {report}"
    from app.db.models import User

    with session_factory() as s:
        alice = s.query(User).filter(User.username == "alice").one()
        assert alice.data_limit == _LIMIT, (
            "the panel user list carries the ORIGINAL quota — not unlimited")
        assert alice.expire == _EXPIRE
        assert len(alice.proxies) == 1
        bob = s.query(User).filter(User.username == "bob").one()
        assert bob.data_limit is None
