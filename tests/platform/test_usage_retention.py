"""f-usageretain-1 / f-backprune-1 / f-usagesum-1 — bounded journal growth.

Installer report: usage_records grew forever (~100 GB/year at 300
sessions), backup pruning silently stopped above a 50 MB archive, and the
dashboard summed the entire journal every 8 seconds per open tab.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "pydantic")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="panel requirements not installed")


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
    r = subprocess_run = __import__("subprocess").run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


@pytest.fixture(scope="module")
def db_session(tmp_path_factory):
    db = tmp_path_factory.mktemp("usageret") / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        os.environ[var] = env[var]
    _migrate(env)
    if not hasattr(sys.modules.get("app"), "app"):
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            sys.modules.pop(name, None)
    import app as _app_warm
    _app_warm.app  # noqa: B018

    # the platform tables live on their OWN Declarative base and engine
    from app.persistence.base import Base as PBase, create_session_factory

    import app.persistence.models  # noqa: F401 — register ALL platform tables
    factory = create_session_factory(env["ZAGROS_DATABASE_URL"])
    PBase.metadata.create_all(factory.kw["bind"])

    session = factory()
    yield session
    session.close()


def _seed(session, rows: int, *, days_old: float, user_id=None, core="xray",
          node=None, account="1.alice"):
    from app.persistence.models import UsageRecordModel

    base = datetime.now(timezone.utc) - timedelta(days=days_old)
    for i in range(rows):
        session.add(UsageRecordModel(
            user_id=user_id, core_id=core, account_id=account, node_id=node,
            uplink_bytes=100, downlink_bytes=200,
            recorded_at=base + timedelta(seconds=30 * i)))
    session.commit()


class TestCollapse:
    def test_old_rows_collapse_to_one_daily_row(self, db_session):
        from app.persistence.models import UsageRecordModel
        from app.jobs.usage_retention import run_usage_retention

        _seed(db_session, 300, days_old=30)     # 2.5 hours of sweeps
        _seed(db_session, 10, days_old=0.05)    # fresh rows must survive
        before = db_session.query(UsageRecordModel).count()

        from sqlalchemy.orm import sessionmaker

        collapsed = run_usage_retention(
            sessionmaker(bind=db_session.get_bind()))
        assert collapsed > 0
        db_session.expire_all()
        old = db_session.query(UsageRecordModel).filter(
            UsageRecordModel.account_id == "1.alice").count()
        fresh = db_session.query(UsageRecordModel).filter(
            UsageRecordModel.account_id != "").count()
        assert fresh == 10, "fresh rows must never be collapsed"
        rows = db_session.query(UsageRecordModel).filter(
            UsageRecordModel.account_id == "").all()
        assert len(rows) <= 2, "one row per (day, user, core, node) group"
        totals = sum(r.uplink_bytes + r.downlink_bytes for r in rows)
        assert totals == 300 * 300, "collapsed rows must carry the exact sums"

    def test_totals_read_from_aggregates_not_journal(self, db_session):
        from sqlalchemy.orm import sessionmaker
        from app.persistence.models import UsageAggregateModel, UsageRecordModel
        from app.persistence.repositories import SQLUsageJournal

        db_session.merge(UsageAggregateModel(
            dimension="core:xray", uplink_bytes=11, downlink_bytes=22))
        db_session.commit()
        repo = SQLUsageJournal(
            sessionmaker(bind=db_session.get_bind()))
        totals = asyncio.run(repo.totals_by_core())
        assert totals.get("xray") == (11, 22),             "aggregate rows must answer without scanning the journal"

        # fallback: no aggregates at all → journal sum (legacy databases)
        db_session.query(UsageAggregateModel).delete()
        _seed(db_session, 3, days_old=0.001, core="wg")
        db_session.commit()
        totals = asyncio.run(repo.totals_by_core())
        assert totals.get("wg") == (300, 600)

    def test_runtime_usage_by_core_prefers_aggregates(self, db_session):
        from sqlalchemy.orm import sessionmaker
        from app.persistence.models import UsageAggregateModel
        from app.platform.runtime import _RuntimeUsageByCore

        db_session.merge(UsageAggregateModel(
            dimension="core:wg", uplink_bytes=5, downlink_bytes=7))
        db_session.commit()
        provider = _RuntimeUsageByCore(
            sessionmaker(bind=db_session.get_bind()))
        out = asyncio.run(provider.usage_by_core())
        assert out.get("wg") == (5, 7)
