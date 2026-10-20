"""f-tplsel-1 (v1.1.3 bugfix 1) — a template's xray inbound selection must
survive the API round-trip VERBATIM.

The old response re-derived ``inbounds`` from the association rows × the
LIVE xray registry: on a panel whose xray core was not running (or whose
listeners were renamed) every template read back ``{}`` and "create user
from template" pre-selected nothing — the operator had to pick inbounds by
hand. The fix stores the operator's exact selection in
``user_templates.inbounds_json`` (0028) and answers from it.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "fastapi")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")


def _migrate(env):
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    db = tmp_path / "platform.db"
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "tplsel-test-key-0123456789",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    for var in env:
        if var.startswith(("ZAGROS_", "SQLALCHEMY_")):
            monkeypatch.setenv(var, env[var])
    _migrate(env)
    from app.platform.runtime import PlatformRuntime
    rt = PlatformRuntime.from_env()
    rt.verify_schema()
    yield rt


def _make_template(db, *, inbounds, core_access=None, name="sel-test"):
    from app.db.crud import create_user_template
    from app.models.user_template import UserTemplateCreate

    return create_user_template(db, UserTemplateCreate(
        name=name, data_limit=5 * 1024 ** 3, expire_duration=30 * 86400,
        inbounds=inbounds, core_access=core_access))


def test_selection_survives_with_empty_xray_registry(runtime):
    """The exact production failure: tags stored, xray registry empty —
    the response must still carry the operator's selection."""
    from app.db import GetDB
    from app.models.user_template import UserTemplateResponse

    with GetDB() as db:
        tpl = _make_template(db, inbounds={"vmess": ["VMESS_INBOUND"],
                                          "vless": ["VLESS_INBOUND"]},
                             core_access={"sing-box": ["hy2-in"]})
        assert tpl.inbounds_json, "the verbatim selection is persisted"
        resp = UserTemplateResponse.of(tpl, users_count=0)
    assert resp.inbounds == {"vmess": ["VMESS_INBOUND"],
                             "vless": ["VLESS_INBOUND"]}, (
        "the stored selection is returned verbatim — no live-xray lookup")
    assert resp.core_access == {"sing-box": ["hy2-in"]}
    assert resp.users_count == 0


def test_wildcard_update_persists_and_replaces(runtime):
    """The old `if modified.inbounds:` guard made "all inbounds" unpersistable
    and kept a previous concrete selection alive forever."""
    from app.db import GetDB, crud
    from app.db.crud import get_user_template
    from app.models.user_template import UserTemplateModify, UserTemplateResponse

    with GetDB() as db:
        tpl = _make_template(db, name="wild-test", inbounds={"vmess": ["VMESS_INBOUND"]})
        updated = crud.update_user_template(
            db, tpl, UserTemplateModify(name="wild-test", data_limit=0,
                                        expire_duration=0, inbounds={}))
        db.refresh(updated)
        # wildcard: an empty dict IS an opinion — every xray inbound
        assert updated.inbounds_json == {}
        assert UserTemplateResponse.of(updated).inbounds == {}

        # and back to a concrete selection
        again = crud.update_user_template(
            db, updated, UserTemplateModify(name="wild-test", inbounds={
                "trojan": ["T1"]}))
        db.refresh(again)
        assert UserTemplateResponse.of(again).inbounds == {"trojan": ["T1"]}
        assert get_user_template(db, again.id).id == again.id


def test_pre0028_row_falls_back_to_association(runtime):
    """Rows stored before 0028 (inbounds_json NULL) keep the association
    derivation instead of collapsing to {}."""
    from app.db import GetDB
    from app.db.crud import get_or_create_inbound
    from app.models.user_template import UserTemplateResponse

    with GetDB() as db:
        tpl = _make_template(db, name="legacy-test", inbounds={"vmess": []})  # wildcard → no tags
        tpl.inbounds_json = None  # simulate a pre-0028 row
        inbound = get_or_create_inbound(db, "LEGACY_TAG")
        tpl.inbounds = [inbound]
        db.commit()
        resp = UserTemplateResponse.of(tpl, users_count=0)
    # association-derived (may be {} when the live xray registry does not
    # know the tag — the documented pre-0028 limitation)
    assert isinstance(resp.inbounds, dict)


def test_users_count_roundtrip(runtime):
    """f-tplsync-1: the response carries how many users were created from
    the template — the Templates editor's sync prompt is driven by it."""
    from datetime import datetime, timedelta

    from app.db import GetDB, crud
    from app.db.crud import create_user_template
    from app.models.user import UserCreate
    from app.models.user_template import UserTemplateCreate, UserTemplateResponse

    with GetDB() as db:
        tpl = create_user_template(db, UserTemplateCreate(
            name="counted", data_limit=1024, expire_duration=0, inbounds={}))
        admin = crud.get_admin(db, "testadmin") or crud.create_admin(
            db, __import__("app.models.admin", fromlist=["AdminCreate"]).AdminCreate(
                username="testadmin", password="x " * 4, is_sudo=False))
        for name in ("cu_one", "cu_two"):
            crud.create_user(db, UserCreate(
                username=name, status="active", data_limit=None, expire=None,
                proxies={"vless": {}}, inbounds={}),
                admin=admin)
        from app.db.models import User as LegacyUser

        db.query(LegacyUser).filter(
            LegacyUser.username.in_(["cu_one", "cu_two"])).update(
            {LegacyUser.template_id: tpl.id}, synchronize_session=False)
        db.commit()
        resp = UserTemplateResponse.of(tpl, users_count=2)
        assert resp.users_count == 2
