"""User core_access API — multi-core grants through the REAL HTTP stack.

The app warms with env pinned to throwaway SQLite files (same pattern as the
governance tests). Recording test-double drivers attach to the LIVE runtime
CoreManager through its real attach path; only the catalog read-model is
stubbed per test (its renderer is covered by the /zagros/inbounds tests).
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_TMP = Path(tempfile.mkdtemp(prefix="zgcore-"))
os.environ.setdefault("SQLALCHEMY_DATABASE_URL", f"sqlite:///{_TMP}/legacy.db")
os.environ.setdefault("ZAGROS_DATABASE_URL", f"sqlite:///{_TMP}/platform.db")
os.environ.setdefault("ZAGROS_SECRET_KEY", "core-access-test-key-0123456789")
os.environ.setdefault("ZAGROS_ALEMBIC_INI", str(ROOT / "alembic.ini"))

import subprocess  # noqa: E402

# The platform runtime only attaches when its schema verifies — migrate the
# pinned databases BEFORE the app imports (same contract as the real panel).
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
_app_warm.app  # noqa: B018 - force warm-up of the legacy import chain

from fastapi.testclient import TestClient  # noqa: E402

from app.db import GetDB, crud  # noqa: E402
from app.db.base import Base, engine  # noqa: E402
from app.models.admin import AdminCreate  # noqa: E402
from app.utils.jwt import create_admin_token  # noqa: E402

Base.metadata.create_all(engine)

# The app may have been warmed earlier by another adminapi module (imports
# are process-wide): if the platform runtime did not attach back then
# (unverified schema), attach one now — the databases above are migrated.
if getattr(_app_warm.app.state, "zagros", None) is None:  # noqa: SIM102
    from app.platform.runtime import PlatformRuntime as _PRT

    _rt = _PRT.from_env()
    _rt.verify_schema()
    _app_warm.app.state.zagros = _rt

# Seed the legacy singletons exactly like the panel's lifespan does
# (JWT secret, system rows) — TestClient only runs startup inside a `with`
# block, and these tests keep an eager client for simplicity.
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
    name = f"coresudo{_counter}"
    with GetDB() as db:
        crud.create_admin(db, AdminCreate(username=name, password="secret-pass-1",
                                          is_sudo=True))
    return create_admin_token(name, is_sudo=True)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _runtime():
    return _app_warm.app.state.zagros


def _recording_driver(core_id: str, protocol: str):
    """Attach a recording driver to the live manager; returns the driver."""
    from app.cores.base import BaseCoreDriver
    from app.cores.types import (
        Capability,
        CoreMetadata,
        CoreState,
        CoreStatus,
        HealthStatus,
    )

    class Recording(BaseCoreDriver):
        metadata = CoreMetadata(
            id=core_id, name=core_id, protocols=[protocol],
            capabilities={Capability.USER_MANAGEMENT, Capability.SUSPEND_RESUME})

        def __init__(self, settings=None):
            super().__init__(settings)
            self.created: list[str] = []
            self.deleted: list[str] = []

        async def start(self): pass
        async def stop(self): pass

        async def status(self):
            return CoreStatus(core_id=core_id, state=CoreState.RUNNING,
                              health=HealthStatus.HEALTHY, core_version="1.0")

        async def get_logs(self, tail=200):
            yield "rec"

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

    driver = Recording()
    rt = _runtime()
    rt.core_manager.attach(core_id, driver, enabled=True)
    return driver


def _stub_catalog(monkeypatch, core_id: str, protocol: str, tags: list[str]):
    from app.platform import provisioning
    from app.platform.inbounds import CatalogGroup, CatalogInbound

    group = CatalogGroup(core_id=core_id, name=core_id, enabled=True,
                         inbounds=[CatalogInbound(tag=t, protocol=protocol) for t in tags])

    async def _fake(runtime):
        from app.platform.inbounds import catalog as real
        groups = await real(runtime)
        # Recording cores have no studio doc — inject/replace their entries.
        for g in groups:
            if g.core_id == core_id:
                g.inbounds = group.inbounds
                break
        else:
            groups.append(group)
        return groups

    monkeypatch.setattr(provisioning, "build_inbound_catalog", _fake)


def test_create_user_with_core_access_provisions_on_the_core(monkeypatch):
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    _recording_driver(core_id, "wireguard")
    _stub_catalog(monkeypatch, core_id, "wireguard", ["wg0"])
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"

    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
        "core_access": {core_id: ["wg0"]},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["core_access"] == {core_id: ["wg0"]}

    rt = _runtime()
    row = rt.users.get_user_by_username(name)
    assert row is not None, "platform projection missing"
    accounts = rt.users.accounts_of(row.id)
    on_core = [a for a in accounts if a["core_id"] == core_id]
    assert len(on_core) == 1
    assert on_core[0]["settings"]["secret"].startswith("gen-")  # driver creds persisted
    assert on_core[0]["settings"]["inbound_tags"] == ["wg0"]
    # the xray mirror row exists too (portal renders legacy protocols as well)
    assert any(a["core_id"] == "xray" and a["protocol"] == "shadowsocks" for a in accounts)


def test_create_user_unknown_core_rolls_back_legacy_row():
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
        "core_access": {"ghost-core-xyz": ["wg0"]},
    })
    assert r.status_code == 502, r.text
    assert "ghost-core-xyz" in r.json()["detail"]
    # no half-created user — the legacy row was rolled back too
    r2 = _client.get(f"/api/user/{name}", headers=_auth(token))
    assert r2.status_code == 404


def test_modify_user_applies_grant_diff(monkeypatch):
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    driver = _recording_driver(core_id, "hysteria2")
    _stub_catalog(monkeypatch, core_id, "hysteria2", ["hy2"])
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
    })
    assert r.status_code == 200, r.text
    r = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "core_access": {core_id: ["hy2"]},
    })
    assert r.status_code == 200, r.text
    assert r.json()["core_access"] == {core_id: ["hy2"]}
    assert driver.created, "driver never received the account"
    # revoke via explicit empty list
    r = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "core_access": {core_id: []},
    })
    assert r.status_code == 200, r.text
    assert driver.deleted, "driver account was not revoked"
    rt = _runtime()
    row = rt.users.get_user_by_username(name)
    assert [a for a in rt.users.accounts_of(row.id) if a["core_id"] == core_id] == []


def test_delete_user_cleans_core_accounts(monkeypatch):
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    driver = _recording_driver(core_id, "wireguard")
    _stub_catalog(monkeypatch, core_id, "wireguard", ["wg0"])
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
        "core_access": {core_id: ["wg0"]},
    })
    assert r.status_code == 200, r.text
    r = _client.delete(f"/api/user/{name}", headers=_auth(token))
    assert r.status_code == 200, r.text
    assert driver.deleted, "core account survived user deletion"
    rt = _runtime()
    assert rt.users.get_user_by_username(name) is None


def test_core_access_shape_is_validated():
    token = _sudo_token()
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": f"cx{uuid.uuid4().hex[:10]}", "proxies": {"shadowsocks": {}},
        "core_access": {"wireguard": "not-a-list"},
    })
    assert r.status_code == 422, r.text


def test_template_core_access_roundtrip():
    token = _sudo_token()
    name = f"tpl-{uuid.uuid4().hex[:8]}"
    r = _client.post("/api/user_template", headers=_auth(token), json={
        "name": name, "data_limit": 1073741824, "expire_duration": 86400,
        "core_access": {"sing-box": ["hy2-in"], "wireguard": ["wg0"]},
    })
    assert r.status_code == 200, r.text
    tpl_id = r.json()["id"]
    assert r.json()["core_access"] == {"sing-box": ["hy2-in"], "wireguard": ["wg0"]}
    r = _client.get("/api/user_template", headers=_auth(token))
    found = [t for t in r.json() if t["id"] == tpl_id]
    assert found and found[0]["core_access"]["wireguard"] == ["wg0"]


# --------------------------------------------------------------------- #
# multi-core subscription: token by-username + UA-aware link merge
# --------------------------------------------------------------------- #

def _user_with_grants(monkeypatch, *, protocol="wireguard"):
    """Create a dashboard user with a grant on a fresh recording core."""
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    _recording_driver(core_id, protocol)
    _stub_catalog(monkeypatch, core_id, protocol, ["wg0"])
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
        "core_access": {core_id: ["wg0"]},
    })
    assert r.status_code == 200, r.text
    return token, name, core_id


def test_issue_portal_token_by_username_and_404():
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}}})
    assert r.status_code == 200, r.text
    r = _client.post(f"/api/zagros/users/by-username/{name}/subscription-token",
                     headers=_auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["path"].startswith("/zagros/sub/") and body["token"] in body["path"]
    r = _client.post("/api/zagros/users/by-username/nobody-here/subscription-token",
                     headers=_auth(token))
    assert r.status_code == 404


def test_portal_rotation_invalidates_old_link():
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}}})
    assert r.status_code == 200, r.text
    p1 = _client.post(f"/api/zagros/users/by-username/{name}/subscription-token",
                      headers=_auth(token)).json()["path"]
    p2 = _client.post(f"/api/zagros/users/by-username/{name}/subscription-token",
                      headers=_auth(token)).json()["path"]
    assert p1 != p2
    # "path" is already the full PUBLIC mount path (/zagros/sub/...) — the
    # portal router is mounted without the /api prefix (unversioned public
    # link, Marzban /sub/ convention).
    r = _client.get(p1, headers={"accept": "text/html",
                                 "user-agent": "Mozilla/5.0"})
    assert r.status_code == 404  # rotated away (fail-closed)
    r = _client.get(p2, headers={"accept": "text/html",
                                 "user-agent": "Mozilla/5.0"})
    assert r.status_code == 200 and "<html" in r.text.lower()

    # same token with a CLIENT user-agent → base64 link bundle instead of HTML
    r = _client.get(p2, headers={"accept": "*/*",
                                 "user-agent": "v2rayNG/1.8.5"})
    assert r.status_code == 200
    import base64 as _b64
    decoded = _b64.b64decode(r.text).decode()
    assert "<html" not in decoded  # never ship the page to subscription clients


# --------------------------------------------------------------------- #
# built-in xray in the multi-core portal (the xray-only Marzban user)
# --------------------------------------------------------------------- #

def test_builtin_xray_renders_in_portal_and_link_bundle():
    """An xray-only legacy user MUST get a working multi-core portal.

    Before the built-in attach, the bridge's xray mirror rows were dropped
    at materialization time (CoreManager did not know "xray") and BOTH the
    HTML portal and the client link bundle came out empty for exactly the
    protocols most users have. The panel lifespan runs ``boot_cores()``;
    this test reproduces that and asserts real delivery through HTTP.
    """
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}}})
    assert r.status_code == 200, r.text

    asyncio.run(_runtime().boot_cores())  # what the panel startup performs

    path = _client.post(
        f"/api/zagros/users/by-username/{name}/subscription-token",
        headers=_auth(token)).json()["path"]

    r = _client.get(path, headers={"accept": "text/html",
                                   "user-agent": "Mozilla/5.0"})
    assert r.status_code == 200, r.text[:400]
    assert "shadowsocks" in r.text.lower()  # xray delivery section rendered

    r = _client.get(path, headers={"accept": "*/*",
                                   "user-agent": "v2rayNG/1.8.5"})
    assert r.status_code == 200
    import base64 as _b64
    decoded = _b64.b64decode(r.text).decode()
    assert "ss://" in decoded  # the share link a subscription client needs


# --------------------------------------------------------------------- #
# global device limit through the REAL HTTP stack (spec §3)
# --------------------------------------------------------------------- #

def test_device_limit_roundtrip_and_platform_mirror():
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}}, "device_limit": 3})
    assert r.status_code == 200, r.text
    assert r.json()["device_limit"] == 3

    platform = _runtime().users.get_user_by_username(name)
    assert platform is not None and platform.device_limit == 3

    # edit down, then clear (0 = explicit unlimited) — the mirror must
    # follow EXACTLY, including the clear (no stale keep-None residue).
    r = _client.put(f"/api/user/{name}", headers=_auth(token),
                    json={"device_limit": 1})
    assert r.status_code == 200, r.text
    assert r.json()["device_limit"] == 1
    assert _runtime().users.get_user_by_username(name).device_limit == 1

    r = _client.put(f"/api/user/{name}", headers=_auth(token),
                    json={"device_limit": 0})
    assert r.status_code == 200, r.text
    assert r.json()["device_limit"] in (None, 0)
    assert _runtime().users.get_user_by_username(name).device_limit is None

    # invalid values rejected by the schema itself
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": f"cx{uuid.uuid4().hex[:10]}",
        "proxies": {"shadowsocks": {}}, "device_limit": -2})
    assert r.status_code == 422


# --------------------------------------------------------------------- #
# multi-format subscription dispatch (spec §7/§8) through REAL HTTP
# --------------------------------------------------------------------- #

def _issued_path(name: str, token: str) -> str:
    return _client.post(f"/api/zagros/users/by-username/{name}/subscription-token",
                        headers=_auth(token)).json()["path"]


def test_subscription_formats_dispatch_by_ua_and_override():
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}}})
    assert r.status_code == 200, r.text
    asyncio.run(_runtime().boot_cores())  # attach the built-in xray
    path = _issued_path(name, token)

    # clash UA -> mihomo YAML with the user's protocol as a proxy
    r = _client.get(path, headers={"accept": "*/*", "user-agent": "clash-verge/2.0"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/yaml")
    import yaml as _yaml
    doc = _yaml.safe_load(r.text)
    assert any(p["type"] == "ss" and p["name"] for p in doc["proxies"])
    assert doc["rules"] == ["MATCH,PROXY"]

    # sing-box UA -> complete JSON config
    r = _client.get(path, headers={"accept": "*/*", "user-agent": "SFI/1.10"})
    assert r.status_code == 200
    doc = r.json()
    kinds = [o.get("type") for o in doc["outbounds"]]
    assert "shadowsocks" in kinds and "selector" in kinds

    # explicit ?format= wins over a browser UA
    r = _client.get(f"{path}?format=clash-meta",
                    headers={"accept": "text/html", "user-agent": "Mozilla/5.0"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/yaml")

    # link-list clients keep the Marzban base64 contract, deduped
    r = _client.get(path, headers={"accept": "*/*", "user-agent": "v2rayNG/1.8.5"})
    import base64 as _b64
    decoded = _b64.b64decode(r.text).decode()
    links = [ln for ln in decoded.splitlines() if "://" in ln]
    assert links and len(links) == len(set(links))  # بدون تکرار
    assert all(ln.startswith("ss://") for ln in links)
