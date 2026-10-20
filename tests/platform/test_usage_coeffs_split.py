"""f-usagecoeff-2 (v1.1.3) — the master/node coefficient decision.

DECISION (the F3 open question): the master coefficient applies ONLY to
master-served traffic. Node deltas were already multiplied by their node's
own ``usage_coefficient`` in collect_node_usage; compounding the master
factor on top priced node traffic twice when an operator raised both.
Per-inbound factors and the quota/billing split apply on BOTH paths.

The applied factor pair is stamped onto every journal row (audit trail);
raw bytes stay raw.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def test_master_factor_applies_on_master_path_only():
    from app.platform.usage_coeffs import Coeffs

    c = Coeffs(master=2.0, quota_mult=1.0, billing_mult=1.5,
               inbounds={"de1": 3.0})
    # master-served record on inbound de1: 2 × 3
    q, b = c.factors_for_tags(["de1"])
    assert q == pytest.approx(6.0)
    assert b == pytest.approx(9.0)
    # node-served record (node factor already inside the bytes):
    # NO master factor — 1 × 3
    q, b = c.factors_for_tags(["de1"], with_master=False)
    assert q == pytest.approx(3.0)
    assert b == pytest.approx(4.5)
    # unmapped inbound: server factor only
    q, b = c.factors_for_tags(None, with_master=False)
    assert (q, b) == (1.0, 1.5)


def test_node_recorder_pass_skips_master_factor():
    """The node fold inside record_once must call with_master=False —
    proven by reading the recorder source (the behaviour is otherwise
    only reachable with a full core driver rig)."""
    src = (ROOT / "app" / "platform" / "usage_recorder.py").read_text()
    assert "factors_for_tags(tags, with_master=False)" in src, (
        "node deltas must not compound the master coefficient")
    assert src.count("factors_for_tags(tags)") == 1, (
        "exactly the master path keeps the master factor")


def test_usage_record_carries_factor_columns():
    from app.cores.types import UsageRecord

    r = UsageRecord(core_id="wg", account_id="a1", node_id=3,
                    uplink_bytes=10, downlink_bytes=0,
                    quota_factor=2.5, billing_factor=2.5)
    assert r.quota_factor == 2.5 and r.billing_factor == 2.5
    # defaults stay None (pre-coefficient readers)
    plain = UsageRecord(core_id="wg", account_id="a1")
    assert plain.quota_factor is None and plain.billing_factor is None


def test_model_and_migration_columns_exist():
    from app.persistence.models import UsageRecordModel

    cols = UsageRecordModel.__table__.columns
    assert "quota_factor" in cols and "billing_factor" in cols
    # and the migration creates them on a real database
    import os
    import subprocess
    from pathlib import Path as _P

    db = _P(os.environ.get("ZAGROS_DB_PATH") or "/tmp/coeff-mig-test.db")
    if db.exists():
        db.unlink()
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db.parent / 'l.db'}",
    })
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c",
         str(ROOT / "alembic.ini"), "upgrade", "head"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    import sqlite3

    con = sqlite3.connect(db)
    names = {row[1] for row in con.execute("PRAGMA table_info(usage_records)")}
    con.close()
    assert {"quota_factor", "billing_factor"} <= names
    db.unlink(missing_ok=True)


def test_retention_collapse_carries_factors_forward(tmp_path):
    """The daily collapse must not erase the audit trail: the surviving
    daily row keeps the group's last known factor pair."""
    import os

    os.environ.setdefault("ZAGROS_DATABASE_URL", f"sqlite:///{tmp_path}/p.db")
    os.environ.setdefault("SQLALCHEMY_DATABASE_URL",
                          f"sqlite:///{tmp_path}/l.db")
    src = (ROOT / "app" / "jobs" / "usage_retention.py").read_text()
    assert "func.max(UsageRecordModel.quota_factor)" in src
    assert "quota_factor=qf, billing_factor=bf" in src
