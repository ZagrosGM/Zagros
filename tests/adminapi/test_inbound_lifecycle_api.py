"""Inbound lifecycle over the REAL HTTP stack (alpha.7.5 items 5 & 14).

Same harness family as test_user_core_access.py: the app warms against
throwaway SQLite files; recording drivers attach to the LIVE CoreManager.
Pins the routed behavior:

* POST wizard/inbound twice (double submit) → second is an idempotent
  replay, the document carries exactly ONE entry;
* same tag + different settings → 409 (never a silent twin);
* DELETE by tag removes exactly the addressed inbound (API level);
* DELETE of a ghost → 404 (not a success);
* a driver refusing the candidate → 422 AND the studio store unchanged;
* deleted-inbound grant cascade → GET user shows no dangling reference and
  a PUT replaying the STALE selection answers 200 (item 14 regression).

Run: pytest tests/adminapi/test_inbound_lifecycle_api.py -q
"""
from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_TMP = Path(tempfile.mkdtemp(prefix="zglife-"))
os.environ.setdefault("SQLALCHEMY_DATABASE_URL", f"sqlite:///{_TMP}/legacy.db")
os.environ.setdefault("ZAGROS_DATABASE_URL", f"sqlite:///{_TMP}/platform.db")
os.environ.setdefault("ZAGROS_SECRET_KEY", "inbound-lifecycle-key-0123456789")
os.environ.setdefault("ZAGROS_ALEMBIC_INI", str(ROOT / "alembic.ini"))

import asyncio  # noqa: E402
import subprocess  # noqa: E402

_r = subprocess.run(
    [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
     "upgrade", "head"], cwd=ROOT, env=os.environ.copy(),
    capture_output=True, text=True, timeout=300, check=False)
assert _r.returncode == 0, f"alembic upgrade failed:\n{_r.stderr}"

try:
    import sqlalchemy  # noqa: F401
    import pytest
    _HAS = True
except ModuleNotFoundError:  # pragma: no cover
    _HAS = False
    import pytest

import app as _app_warm  # noqa: E402
_app_warm.app  # noqa: B018

from fastapi.testclient import TestClient  # noqa: E402

from app.db import GetDB, crud  # noqa: E402
from app.db.base import Base, engine  # noqa: E402
from app.models.admin import AdminCreate  # noqa: E402
from app.utils.jwt import create_admin_token  # noqa: E402

Base.metadata.create_all(engine)

if getattr(_app_warm.app.state, "zagros", None) is None:  # noqa: SIM102
    from app.platform.runtime import PlatformRuntime as _PRT

    _rt = _PRT.from_env()
    _rt.verify_schema()
    _app_warm.app.state.zagros = _rt

from app.db.models import JWT as _JWTModel  # noqa: E402

with GetDB() as _db:
    if _db.query(_JWTModel).first() is None:
        _db.add(_JWTModel(id=1, secret_key="ab" * 32))
        _db.commit()

pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")

_client = TestClient(_app_warm.app)
_counter = 0


def _sudo_token() -> str:
    global _counter
    _counter += 1
    name = f"lifesudo{_counter}"
    with GetDB() as db:
        crud.create_admin(db, AdminCreate(username=name, password="secret-pass-1",
                                          is_sudo=True))
    return create_admin_token(name, is_sudo=True)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _runtime():
    return _app_warm.app.state.zagros


def _studio_driver(core_id: str, *, reject: bool = False):
    """Recording driver WITH a studio contract (inbounds path + materialize
    hook); attach to the live manager; returns the driver."""
    from app.cores.base import BaseCoreDriver
    from app.cores.exceptions import CoreError
    from app.cores.types import (
        Capability,
        CoreMetadata,
        CoreState,
        CoreStatus,
        HealthStatus,
    )

    class StudioRec(BaseCoreDriver):
        metadata = CoreMetadata(
            id=core_id, name=core_id, protocols=["vless"],
            capabilities={Capability.USER_MANAGEMENT, Capability.SUSPEND_RESUME},
            config_schema={},
            studio_inbounds_path="/inbounds",
        )

        def __init__(self, settings=None):
            super().__init__(settings)
            self.docs: list[dict] = []
            self.created: list[str] = []
            self.deleted: list[str] = []

        async def start(self): pass
        async def stop(self): pass

        async def status(self):
            return CoreStatus(core_id=core_id, state=CoreState.RUNNING,
                              health=HealthStatus.HEALTHY, core_version="1.0")

        async def get_logs(self, tail=200):
            yield "rec"

        async def apply_studio_document(self, doc) -> None:
            if reject:
                raise CoreError("engine rejected the candidate document")
            self.docs.append(doc)

        async def create_account(self, account) -> None:
            account.settings.setdefault("secret", f"gen-{account.account_id}")
            self.created.append(account.account_id)

        async def update_account(self, account) -> None:
            await self.create_account(account)

        async def delete_account(self, account_id: str) -> None:
            self.deleted.append(account_id)

        async def suspend_account(self, account_id: str) -> None: pass
        async def resume_account(self, account) -> None: pass

        async def build_client_config(self, account, node=None):
            return "x://config"

        async def sync_accounts(self, accounts): pass

    driver = StudioRec()
    _runtime().core_manager.attach(core_id, driver, enabled=True)
    return driver


def _wizard_body(tag: str, port: int, **settings) -> dict:
    s = {"transport": "tcp", "security": "none"}
    s.update(settings)
    return {"tag": tag, "protocol": "vless", "listen": "0.0.0.0",
            "port": port, "settings": s}


def _studio_doc(core_id: str) -> dict:
    return asyncio.run(_runtime().studio_store.get_document(core_id)) or {}


# --------------------------------------------------------------------- #
# item 5 — duplicates / idempotency / conflict / ghost delete (API level)
# --------------------------------------------------------------------- #

def test_double_submit_creates_exactly_one_inbound():
    core_id = f"life-{uuid.uuid4().hex[:6]}"
    token = _sudo_token()
    _studio_driver(core_id)
    body = _wizard_body("vless-a", 11001)

    r1 = _client.post(f"/api/zagros/studio/{core_id}/wizard/inbound",
                      headers=_auth(token), json=body)
    assert r1.status_code == 200, r1.text
    assert r1.json()["changed"] is True

    r2 = _client.post(f"/api/zagros/studio/{core_id}/wizard/inbound",
                      headers=_auth(token), json=body)
    assert r2.status_code == 200, r2.text
    assert r2.json()["changed"] is False  # idempotent replay, no twin

    inbounds = _studio_doc(core_id)["inbounds"]
    assert [e["tag"] for e in inbounds] == ["vless-a"]


def test_same_tag_different_settings_is_409_not_a_twin():
    core_id = f"life-{uuid.uuid4().hex[:6]}"
    token = _sudo_token()
    _studio_driver(core_id)

    r1 = _client.post(f"/api/zagros/studio/{core_id}/wizard/inbound",
                      headers=_auth(token), json=_wizard_body("vless-b", 11002))
    assert r1.status_code == 200, r1.text

    r2 = _client.post(f"/api/zagros/studio/{core_id}/wizard/inbound",
                      headers=_auth(token), json=_wizard_body("vless-b", 22002))
    assert r2.status_code == 409, r2.text
    assert "DIFFERENT settings" in r2.json()["detail"]

    inbounds = _studio_doc(core_id)["inbounds"]
    assert [e["tag"] for e in inbounds] == ["vless-b"]
    assert inbounds[0]["port"] == 11002  # the refusal forked nothing


def test_engine_refusal_is_422_and_persists_nothing():
    core_id = f"life-{uuid.uuid4().hex[:6]}"
    token = _sudo_token()
    _studio_driver(core_id, reject=True)

    r = _client.post(f"/api/zagros/studio/{core_id}/wizard/inbound",
                     headers=_auth(token), json=_wizard_body("vless-c", 11003))
    assert r.status_code == 422, r.text
    assert "rejected the candidate" in r.json()["detail"]
    # THE atomicity guarantee: no half-created inbound in the store
    assert "inbounds" not in _studio_doc(core_id)


def test_delete_by_tag_removes_exactly_one_ghost_is_404():
    core_id = f"life-{uuid.uuid4().hex[:6]}"
    token = _sudo_token()
    _studio_driver(core_id)
    for tag, port in (("keep-x", 11011), ("drop-x", 11012), ("keep-y", 11013)):
        r = _client.post(f"/api/zagros/studio/{core_id}/wizard/inbound",
                         headers=_auth(token), json=_wizard_body(tag, port))
        assert r.status_code == 200, r.text

    ghost = _client.delete(
        f"/api/zagros/studio/{core_id}/wizard/inbound/ghost-z",
        headers=_auth(token))
    assert ghost.status_code == 404, ghost.text  # not a success

    r = _client.delete(f"/api/zagros/studio/{core_id}/wizard/inbound/drop-x",
                       headers=_auth(token))
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True and r.json()["deleted"] == "drop-x"

    assert [e["tag"] for e in _studio_doc(core_id)["inbounds"]] == ["keep-x", "keep-y"]


# --------------------------------------------------------------------- #
# item 14 — deleted inbound must not strand user grants
# --------------------------------------------------------------------- #

def test_deleted_inbound_cleans_user_grants_and_save_stays_200():
    core_id = f"life-{uuid.uuid4().hex[:6]}"
    token = _sudo_token()
    driver = _studio_driver(core_id)
    name = f"lifeusr{uuid.uuid4().hex[:10]}"

    # 1) inbound exists
    r = _client.post(f"/api/zagros/studio/{core_id}/wizard/inbound",
                     headers=_auth(token), json=_wizard_body("in-a", 11021))
    assert r.status_code == 200, r.text

    # 2) user granted on it
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
        "core_access": {core_id: ["in-a"]},
    })
    assert r.status_code == 200, r.text
    assert driver.created, "the grant never reached the core"

    g = _client.get(f"/api/user/{name}", headers=_auth(token))
    assert g.status_code == 200
    assert g.json().get("core_access", {}).get(core_id) == ["in-a"]

    # 3) the inbound is deleted — grants must cascade
    r = _client.delete(f"/api/zagros/studio/{core_id}/wizard/inbound/in-a",
                       headers=_auth(token))
    assert r.status_code == 200, r.text
    assert driver.deleted, "the revoked account never reached the core"

    # 4) GET user: no dangling reference
    g = _client.get(f"/api/user/{name}", headers=_auth(token))
    assert g.status_code == 200
    core_access = g.json().get("core_access") or {}
    assert core_access.get(core_id) in (None, []), \
        f"dangling grant on a deleted inbound: {core_access}"

    # 5) PUT replaying the STALE selection (what a stale frontend sends after
    #    a delete-on-another-tab): must be a clean 200, never a 500/422
    put = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "note": "edited after inbound deletion",
        "core_access": {core_id: ["in-a"]},
    })
    assert put.status_code == 200, put.text
    body_access = put.json().get("core_access") or {}
    assert body_access.get(core_id) in (None, [])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
