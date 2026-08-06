"""Real Alembic-revision tests: 0002 legacy seeds + 0003 core_hosts.extras.

Covers the exact defects found by the live boot smoke:
  * fresh legacy schema must seed the upstream singleton rows
    (system / tls / jwt) or the API auth chain 500s at first login;
  * re-seeding must never rotate the jwt key or overwrite the tls pair;
  * databases created before ``core_hosts.extras`` existed get the column
    via 0003 (incl. ``{}`` backfill), and fresh ones already have it.

Migrations run in a REAL subprocess (like the hostctl tests) so the legacy
``app`` package resolves normally — in-process import-context shims make
the legacy tree un-warmable by design.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

try:
    import sqlalchemy  # noqa: F401
    import alembic  # noqa: F401
    _HAS = True
except ModuleNotFoundError:
    _HAS = False

import pytest  # noqa: E402

pytestmark = pytest.mark.skipif(not _HAS, reason="sqlalchemy/alembic not installed")


def _upgrade(platform_url: str, legacy_url: str, target: str = "head") -> None:
    env = dict(os.environ)
    env.update({
        "ZAGROS_DATABASE_URL": platform_url,
        "SQLALCHEMY_DATABASE_URL": legacy_url,
        "ZAGROS_SECRET_KEY": "alembic-test-key-0123456789abcd",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", target],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, (
        f"alembic upgrade {target} failed:\n{proc.stdout[-800:]}\n{proc.stderr[-1500:]}")


def _load_revision_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "rev0002", ROOT / "app" / "persistence" / "alembic" / "versions" / "0002_legacy_schema.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_0002_seeds_required_singletons() -> None:
    import sqlite3

    base = Path(tempfile.mkdtemp(prefix="zgalembic-"))
    _upgrade(f"sqlite:///{base}/zagros.db", f"sqlite:///{base}/legacy.db")

    with sqlite3.connect(base / "legacy.db") as legacy:
        for table in ("system", "tls", "jwt"):
            (count,) = legacy.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            assert count == 1, f"{table} must be seeded with exactly one row"
        (key,) = legacy.execute("SELECT secret_key FROM jwt WHERE id = 1").fetchone()
        assert len(key) == 64 and int(key, 16) != 0  # 64-hex random per deployment
        (cert,) = legacy.execute("SELECT certificate FROM tls WHERE id = 1").fetchone()
        assert cert.startswith("-----BEGIN CERTIFICATE-----")
        (uplink,) = legacy.execute("SELECT uplink FROM system WHERE id = 1").fetchone()
        assert uplink == 0
        (head,) = sqlite3.connect(base / "zagros.db").execute(
            "SELECT version_num FROM alembic_version").fetchone()
        assert head == "0006_device_limit"


def test_0002_reseed_never_rotates_keys() -> None:
    import sqlite3

    base = Path(tempfile.mkdtemp(prefix="zgalembic-"))
    legacy_url = f"sqlite:///{base}/legacy.db"
    _upgrade(f"sqlite:///{base}/zagros.db", legacy_url)

    def _row():
        with sqlite3.connect(base / "legacy.db") as db:
            return (db.execute("SELECT secret_key FROM jwt").fetchone()[0],
                    db.execute("SELECT key FROM tls").fetchone()[0])

    jwt_before, tls_before = _row()

    from sqlalchemy import create_engine

    mod = _load_revision_module()
    engine = create_engine(legacy_url)
    try:
        mod._seed_singletons(engine)  # direct re-run (alembic replays skip it)
    finally:
        engine.dispose()
    jwt_after, tls_after = _row()
    assert jwt_after == jwt_before, "jwt key must never rotate on re-seed"
    assert tls_after == tls_before, "tls pair must never be overwritten"


def test_0003_adds_extras_to_preexisting_databases() -> None:
    import sqlite3

    base = Path(tempfile.mkdtemp(prefix="zgalembic-"))
    platform_url = f"sqlite:///{base}/zagros.db"
    _upgrade(platform_url, f"sqlite:///{base}/legacy.db")

    # fresh databases get the column from the 0001 metadata path already
    cols = {r[1] for r in sqlite3.connect(base / "zagros.db")
            .execute("PRAGMA table_info(core_hosts)")}
    assert "extras" in cols

    # emulate a database created BEFORE the column existed, stamped at 0002
    with sqlite3.connect(base / "zagros.db") as db:
        db.execute("ALTER TABLE core_hosts DROP COLUMN extras")
        db.execute("INSERT INTO core_hosts (core_id, remark, address, sort) "
                   "VALUES ('xray', 'old', 'old.example.com', 0)")
        db.execute("UPDATE alembic_version SET version_num = '0002_legacy_schema'")
        db.commit()
    cols = {r[1] for r in sqlite3.connect(base / "zagros.db")
            .execute("PRAGMA table_info(core_hosts)")}
    assert "extras" not in cols

    _upgrade(platform_url, f"sqlite:///{base}/legacy.db")
    with sqlite3.connect(base / "zagros.db") as db:
        cols = {r[1] for r in db.execute("PRAGMA table_info(core_hosts)")}
        assert "extras" in cols
        (extras_val,) = db.execute(
            "SELECT extras FROM core_hosts WHERE remark = 'old'").fetchone()
        assert extras_val == "{}", "old rows must be backfilled to {}"
        (head,) = db.execute("SELECT version_num FROM alembic_version").fetchone()
        assert head == "0006_device_limit"


def test_0004_adds_governance_columns_to_preexisting_databases() -> None:
    """Pre-alpha.7 legacy databases must gain the five governance columns
    via 0004 (their admins rows untouched), while fresh installs already
    have them from create_all and the revision must simply no-op."""
    import sqlite3

    base = Path(tempfile.mkdtemp(prefix="zggov0004-"))
    legacy_path = base / "legacy.db"
    with sqlite3.connect(legacy_path) as legacy:
        legacy.executescript("""
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY,
                username VARCHAR(34) UNIQUE,
                hashed_password VARCHAR(128),
                created_at DATETIME,
                is_sudo BOOLEAN,
                users_usage BIGINT NOT NULL DEFAULT 0
            );
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username VARCHAR(34) UNIQUE,
                status VARCHAR(16),
                admin_id INTEGER
            );
            INSERT INTO admins (id, username, hashed_password, is_sudo, users_usage)
              VALUES (1, 'oldboss', 'hash', 0, 7);
        """)
    _upgrade(f"sqlite:///{base}/zagros.db", f"sqlite:///{legacy_path}")

    with sqlite3.connect(legacy_path) as legacy:
        admin_cols = {r[1] for r in legacy.execute("PRAGMA table_info(admins)")}
        for col in ("max_users", "expire_at", "traffic_alloc_limit", "traffic_consume_limit"):
            assert col in admin_cols, f"admins.{col} missing after 0004"
        user_cols = {r[1] for r in legacy.execute("PRAGMA table_info(users)")}
        assert "admin_limit_disabled" in user_cols, "users.admin_limit_disabled missing"
        row = legacy.execute(
            "SELECT username, users_usage, max_users FROM admins WHERE id = 1").fetchone()
        assert row == ("oldboss", 7, None), "pre-existing admin row must not be touched"


def test_0005_adds_template_core_access_to_preexisting_databases() -> None:
    """Pre-existing legacy databases must gain user_templates.core_access
    via 0005 (rows untouched), while fresh installs already have it from
    create_all and the revision must no-op."""
    import sqlite3

    base = Path(tempfile.mkdtemp(prefix="zgtpl0005-"))
    legacy_path = base / "legacy.db"
    with sqlite3.connect(legacy_path) as legacy:
        legacy.executescript("""
            CREATE TABLE user_templates (
                id INTEGER PRIMARY KEY,
                name VARCHAR(64) NOT NULL,
                data_limit BIGINT,
                expire_duration BIGINT,
                username_prefix VARCHAR(20),
                username_suffix VARCHAR(20)
            );
            INSERT INTO user_templates (id, name, data_limit, expire_duration)
              VALUES (1, 'old-plan', 1024, 86400);
        """)
    _upgrade(f"sqlite:///{base}/zagros.db", f"sqlite:///{legacy_path}")

    with sqlite3.connect(legacy_path) as legacy:
        cols = {r[1] for r in legacy.execute("PRAGMA table_info(user_templates)")}
        assert "core_access" in cols, "user_templates.core_access missing after 0005"
        row = legacy.execute(
            "SELECT name, data_limit, core_access FROM user_templates WHERE id = 1"
        ).fetchone()
        assert row == ("old-plan", 1024, None), "pre-existing template row must not be touched"


def test_0006_adds_device_limit_to_preexisting_databases() -> None:
    """Pre-existing legacy databases must gain users.device_limit(+_disabled)
    via 0006 (rows untouched), while fresh installs already have both from
    create_all and the revision must no-op."""
    import sqlite3

    base = Path(tempfile.mkdtemp(prefix="zgdev0006-"))
    legacy_path = base / "legacy.db"
    with sqlite3.connect(legacy_path) as legacy:
        legacy.executescript("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username VARCHAR(34) NOT NULL,
                status VARCHAR(20),
                used_traffic BIGINT
            );
            INSERT INTO users (id, username, status, used_traffic)
              VALUES (1, 'old-user', 'active', 7);
        """)
    _upgrade(f"sqlite:///{base}/zagros.db", f"sqlite:///{legacy_path}")

    with sqlite3.connect(legacy_path) as legacy:
        cols = {r[1] for r in legacy.execute("PRAGMA table_info(users)")}
        assert "device_limit" in cols, "users.device_limit missing after 0006"
        assert "device_limit_disabled" in cols, "users.device_limit_disabled missing after 0006"
        row = legacy.execute(
            "SELECT username, device_limit, device_limit_disabled FROM users WHERE id = 1"
        ).fetchone()
        assert row == ("old-user", None, 0), "pre-existing user row must not be touched"
