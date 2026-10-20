"""f-dbmerge-5 regression: the REAL fresh-install boot order.

The container boot runs ``python3 -m app.dbmerge`` (single-database
consolidation) BEFORE ``alembic upgrade head``. On an empty data dir the
fresh path provisions the legacy schema under ``legacy_*`` names inside the
MAIN database and writes the merge marker — after which the runtime legacy
engine (``app.db.base``) serves the MAIN database. The migrations used to
resolve their engine from the RAW ``SQLALCHEMY_DATABASE_URL`` instead, so
``0002`` created a brand-new legacy file with renamed tables while ``0004``
looked for plain ``admins`` → ``NoSuchTableError`` → every fresh install
rolled back (observed on v1.1.1). Both steps replay here exactly as the
image CMD runs them: separate processes, same environment.
"""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _alembic(env: dict, *args: str) -> subprocess.CompletedProcess:
    e = dict(env)
    e["ZAGROS_ALEMBIC_INI"] = str(ROOT / "alembic.ini")
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT, env=e, capture_output=True, text=True, timeout=300)


def test_fresh_install_boot_dbmerge_then_alembic_converges(tmp_path) -> None:
    main_db = tmp_path / "zagros.db"
    legacy_db = tmp_path / "legacy.db"
    env = dict(os.environ)
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{main_db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{legacy_db}",
        "ZAGROS_SECRET_KEY": "alembic-test-key-0123456789abcd",
    })

    # boot step 1 — dbmerge fresh path: provision legacy into MAIN + marker
    merge = subprocess.run(
        [sys.executable, "-m", "app.dbmerge"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    assert merge.returncode == 0, (
        f"dbmerge failed:\n{merge.stdout[-800:]}\n{merge.stderr[-1500:]}")
    assert not legacy_db.exists(), (
        "fresh install must never create a second (legacy) database")

    # boot step 2 — alembic upgrade head (the step that used to crash at 0004)
    proc = _alembic(env, "upgrade", "head")
    assert proc.returncode == 0, (
        f"alembic upgrade head failed:\n{proc.stdout[-800:]}\n{proc.stderr[-1500:]}")

    # converged: head stamped, single database, legacy tables live in MAIN
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    head = str(ScriptDirectory.from_config(
        Config(str(ROOT / "alembic.ini"))).get_current_head())
    db = sqlite3.connect(main_db)
    try:
        assert db.execute(
            "SELECT version_num FROM alembic_version").fetchone()[0] == head
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        db.close()
    assert "settings" in tables           # P3 marker store
    assert "legacy_admins" in tables      # renamed legacy schema in the MAIN db
    assert not legacy_db.exists(), "the upgrade must not create legacy.db"


def test_unmerged_upgrade_keeps_plain_legacy_names(tmp_path) -> None:
    """Without dbmerge (no marker) the raw URL and PLAIN names are kept —
    the pre-consolidation behaviour must remain byte-for-byte."""
    main_db = tmp_path / "zagros.db"
    legacy_db = tmp_path / "legacy.db"
    env = dict(os.environ)
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{main_db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{legacy_db}",
        "ZAGROS_SECRET_KEY": "alembic-test-key-0123456789abcd",
    })
    proc = _alembic(env, "upgrade", "head")
    assert proc.returncode == 0, (
        f"alembic upgrade head failed:\n{proc.stdout[-800:]}\n{proc.stderr[-1500:]}")
    legacy = sqlite3.connect(legacy_db)
    try:
        tables = {r[0] for r in legacy.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        legacy.close()
    assert {"admins", "users", "nodes"} <= tables
