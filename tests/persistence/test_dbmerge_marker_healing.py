"""f-dbmerge-7 regression — marker versioning heals the PostgreSQL drift.

v1.1.1 wrote "v": 1 markers but never READ them on PostgreSQL (the MySQL-
quoted first attempt aborted the transaction and the corrected second
attempt died inside it), so those installs kept living in the legacy
database while the main copy froze as a boot-time snapshot. The fixed
code must:

* trust only CURRENT-version markers (a v1 marker re-runs the merge once,
  so the fresh legacy rows win, then upgrades the marker to v2);
* honour a v2 marker immediately (no re-merge on the next boot);
* keep the legacy engine un-redirected while the marker is v1 — even if
  dbmerge failed — because the main copy is stale.

Replayed here on sqlite with the REAL boot entrypoint (`python -m
app.dbmerge`) in separate processes.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _dbmerge(main_db: Path, legacy_db: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{main_db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{legacy_db}",
        "ZAGROS_SECRET_KEY": "dbmerge-test-key-0123456789abcd",
    })
    return subprocess.run(
        [sys.executable, "-m", "app.dbmerge"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300)


def _marker(main_db: Path) -> dict | None:
    row = sqlite3.connect(main_db).execute(
        "SELECT value_json FROM settings WHERE key='dbmerge'").fetchone()
    return json.loads(row[0]) if row and row[0] else None


def _legacy_users(legacy_db: Path) -> set[str]:
    return {r[0] for r in sqlite3.connect(legacy_db).execute(
        "SELECT username FROM legacy_users")}


def test_v1_marker_heals_once_and_switches(tmp_path):
    main_db, legacy_db = tmp_path / "zagros.db", tmp_path / "legacy.db"
    # install-time state: merge ran, marker v1 written, legacy retired
    r1 = _dbmerge(main_db, legacy_db)
    assert r1.returncode == 0, r1.stderr[-500:]
    assert (_marker(main_db) or {}).get("v") == 2, "fresh installs write v2"
    assert not legacy_db.exists()

    # ── simulate the PostgreSQL drift exactly as v1.1.1 left it: the MAIN
    # database's marker is v1 (written but never honoured), the panel kept
    # living in the legacy database — original tablenames, no marker — and
    # a fresh user was created THERE after the boot-time snapshot was taken.
    legacy_db2 = tmp_path / "legacy2.db"
    legacy_db2.write_bytes(main_db.read_bytes())
    with sqlite3.connect(legacy_db2) as db:
        for old_name, new_name in (("legacy_users", "users"),
                                   ("legacy_admins", "admins"),
                                   ("legacy_nodes", "nodes"),
                                   ("legacy_next_plans", "next_plans")):
            db.execute(f"ALTER TABLE {old_name} RENAME TO {new_name}")
        db.execute("DELETE FROM settings WHERE key='dbmerge'")
        db.execute("INSERT INTO users (username, status, "
                   "data_limit_reset_strategy, admin_limit_disabled, device_limit_disabled) "
                   "VALUES ('fresh-operator-user', 'active', 'no_reset', 0, 0)")
        db.commit()
    with sqlite3.connect(main_db) as db:
        db.execute("UPDATE settings SET value_json = json_set(value_json, "
                   "'$.v', 1) WHERE key='dbmerge'")
    r2 = _dbmerge(main_db, legacy_db2)
    assert r2.returncode == 0, r2.stderr[-500:]
    # healing merge ran: the fresh user must exist in the MAIN copy…
    assert "fresh-operator-user" in _legacy_users(main_db)
    # …the marker was upgraded, and the legacy file was retired again.
    assert (_marker(main_db) or {}).get("v") == 2
    assert not legacy_db2.exists()

    # second boot with a v2 marker: merged() is True — no third merge pass
    r3 = _dbmerge(main_db, legacy_db2)
    assert r3.returncode == 0
    assert "marker present" in r3.stdout

    # the legacy engine must now serve the MAIN database (renames active)
    env = dict(os.environ)
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{main_db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{legacy_db2}",
    })
    probe = subprocess.run(
        [sys.executable, "-c", """
import os
from app.env_loader import load_zagros_env; load_zagros_env()
import app as _a; getattr(_a, 'app')
from app.db.base import SQLALCHEMY_DATABASE_URL as eff, _marker_present
main = os.environ['ZAGROS_DATABASE_URL']
assert _marker_present(main) is True, 'v2 marker must redirect the engine'
assert eff == main, f'engine must serve main, got {eff}'
print('engine-switch-ok')
"""], cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    assert probe.returncode == 0, probe.stderr[-800:]
    assert "engine-switch-ok" in probe.stdout


def test_v1_marker_keeps_engine_unredirected(tmp_path):
    """dbmerge FAILED on a v1 install → the engine must stay on the legacy
    database (the main copy is a stale snapshot; switching loses data)."""
    main_db, legacy_db = tmp_path / "zagros.db", tmp_path / "legacy.db"
    assert _dbmerge(main_db, legacy_db).returncode == 0
    legacy_db2 = tmp_path / "legacy2.db"
    legacy_db2.write_bytes(main_db.read_bytes())
    with sqlite3.connect(main_db) as db:
        db.execute("UPDATE settings SET value_json = json_set(value_json, "
                   "'$.v', 1) WHERE key='dbmerge'")
    env = dict(os.environ)
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{main_db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{legacy_db2}",
    })
    probe = subprocess.run(
        [sys.executable, "-c", """
from app.env_loader import load_zagros_env; load_zagros_env()
import app as _a; getattr(_a, 'app')
from app.db.base import _marker_present
assert _marker_present(__import__('os').environ['ZAGROS_DATABASE_URL']) is False, (
    'a v1 marker must NOT redirect the engine')
print('stay-legacy-ok')
"""], cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    assert probe.returncode == 0, probe.stderr[-800:]
    assert "stay-legacy-ok" in probe.stdout
