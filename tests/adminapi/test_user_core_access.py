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


def test_bandwidth_limits_create_update_get_and_validation(monkeypatch):
    runtime = _runtime()
    applied = []
    monkeypatch.setattr(runtime.bandwidth, "reconcile",
                        lambda: applied.append(True) or {"ok": True})
    # This API contract test has no real Xray process; immutable-route refresh
    # has its own production/e2e coverage and must not download a core here.
    monkeypatch.setattr(
        "app.routers.user._ensure_xray_bandwidth_identity",
        lambda _user, **_kwargs: None)
    token = _sudo_token()
    name = f"bw{uuid.uuid4().hex[:10]}"
    created = _client.post("/api/user", headers=_auth(token), json={
        "username": name,
        "proxies": {"shadowsocks": {}},
        "download_limit_mbps": 100,
        "upload_limit_mbps": 20,
    })
    assert created.status_code == 200, created.text
    assert created.json()["download_limit_mbps"] == 100
    assert created.json()["upload_limit_mbps"] == 20
    platform = runtime.users.get_user_by_username(name)
    assert platform.download_limit_mbps == 100
    assert platform.upload_limit_mbps == 20
    assert applied

    changed = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "download_limit_mbps": 50,
        "upload_limit_mbps": 10,
    })
    assert changed.status_code == 200, changed.text
    assert changed.json()["download_limit_mbps"] == 50
    assert changed.json()["upload_limit_mbps"] == 10
    fetched = _client.get(f"/api/user/{name}", headers=_auth(token))
    assert fetched.json()["download_limit_mbps"] == 50
    assert fetched.json()["upload_limit_mbps"] == 10

    unlimited = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "download_limit_mbps": 0, "upload_limit_mbps": 0,
    })
    assert unlimited.status_code == 200
    assert unlimited.json()["download_limit_mbps"] == 0
    assert unlimited.json()["upload_limit_mbps"] == 0

    for invalid in (-1, 100001, 1.5, "10", True, "NaN"):
        response = _client.put(f"/api/user/{name}", headers=_auth(token), json={
            "download_limit_mbps": invalid,
        })
        assert response.status_code == 422, (invalid, response.text)


def test_create_template_style_user_without_xray_proxy(monkeypatch):
    """From Template may grant only a non-Xray inbound. The real HTTP/schema/
    legacy DB/platform DB flow must accept it instead of failing Pydantic 422."""
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    driver = _recording_driver(core_id, "wireguard")
    _stub_catalog(monkeypatch, core_id, "wireguard", ["wg-template"])
    token = _sudo_token()
    name = f"tpl{uuid.uuid4().hex[:10]}"

    payload = {
        "username": name,
        "proxies": {},
        "inbounds": {},
        "core_access": {core_id: ["wg-template"]},
        "data_limit_reset_strategy": "no_reset",
    }
    response = _client.post("/api/user", headers=_auth(token), json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["core_access"] == payload["core_access"]
    assert driver.created, "template grant never reached the core provisioner"

    # Both databases contain one coherent user; no phantom Xray proxy was
    # invented merely to satisfy the old schema.
    with GetDB() as db:
        legacy = crud.get_user(db, name)
        assert legacy is not None and list(legacy.proxies) == []
    runtime = _runtime()
    platform = runtime.users.get_user_by_username(name)
    assert platform is not None
    accounts = runtime.users.accounts_of(platform.id)
    assert [(row["core_id"], row["protocol"], row["settings"]["inbound_tags"])
            for row in accounts] == [(core_id, "wireguard", ["wg-template"])]


def test_create_rejects_user_without_any_access():
    token = _sudo_token()
    response = _client.post("/api/user", headers=_auth(token), json={
        "username": f"empty{uuid.uuid4().hex[:8]}",
        "proxies": {}, "inbounds": {}, "core_access": {},
    })
    assert response.status_code == 422
    assert "proxy or one core_access" in response.text


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
    # an EXPLICIT empty mapping: xray only, no panel defaults (a create
    # without the key gets Settings → API defaults — see
    # test_create_without_core_access_gets_the_panel_defaults)
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}}, "core_access": {},
    })
    assert r.status_code == 200, r.text
    assert r.json()["core_access"] == {}
    assert not driver.created, "an explicit {} must not provision anything"
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
    generated = r.json()["subscription_url"]
    assert "/sub/" in generated and "/zagros/sub/" not in generated
    r = _client.post(f"/api/zagros/users/by-username/{name}/subscription-token",
                     headers=_auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    # the issued link is the CANONICAL /sub/<token>
    assert body["path"].startswith("/sub/") and body["token"] in body["path"]
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
    # "path" is already the full PUBLIC mount path (/sub/<token> canonical;
    # /zagros/sub/<token> remains a forever-alias) — the portal router is
    # mounted without the /api prefix (unversioned public link).
    r = _client.get(p1, headers={"accept": "text/html",
                                 "user-agent": "Mozilla/5.0"})
    assert r.status_code == 404  # rotated away (fail-closed)
    r = _client.get(p2, headers={"accept": "text/html",
                                 "user-agent": "Mozilla/5.0"})
    assert r.status_code == 200 and "<html" in r.text.lower()

    # the pre-7.4 URL shape keeps serving the same token
    alias = p2.replace("/sub/", "/zagros/sub/", 1)
    assert alias != p2
    r = _client.get(alias, headers={"accept": "text/html",
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

def test_existing_user_gets_new_xray_vless_ws_tls_in_portal(monkeypatch):
    """Regression for v1.0.5 field report: the dashboard's canonical empty
    tag list means ALL inbounds of that protocol, including a newly-created
    VLESS WS TLS listener. UserModify previously inverted it to exclude all,
    leaving VLESS and the pre-existing Shadowsocks section unavailable."""
    from app import xray

    token = _sudo_token()
    name = f"xv{uuid.uuid4().hex[:10]}"
    created = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}}})
    assert created.status_code == 200, created.text
    # Attach the built-in delivery driver without booting/downloading the Xray
    # process; this test exercises account projection + portal composition.
    asyncio.run(_runtime()._attach_builtin_xray())

    tag = f"VLESS WS TLS {uuid.uuid4().hex[:6]}"
    vless = {
        "tag": tag, "protocol": "vless", "port": 443, "network": "ws",
        "tls": "tls", "sni": ["vless.example.test"],
        "host": ["vless.example.test"], "path": "/vless-ws",
        "header_type": "", "is_fallback": False,
    }
    by_tag = dict(xray.config.inbounds_by_tag)
    by_tag[tag] = vless
    by_protocol = {key: list(value)
                   for key, value in xray.config.inbounds_by_protocol.items()}
    by_protocol.setdefault("vless", []).append(vless)
    monkeypatch.setattr(xray.config, "inbounds_by_tag", by_tag)
    monkeypatch.setattr(xray.config, "inbounds_by_protocol", by_protocol)
    # Delivery host lookup is independent of the catalog; no explicit host row
    # means the request host + inbound TLS/SNI facts are used.
    monkeypatch.setattr(xray, "hosts", {})

    current = created.json()["proxies"]["shadowsocks"]
    edited = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "proxies": {"shadowsocks": current, "vless": {}},
        # This is exactly what legacyFromTags() emits when each protocol's
        # complete current tag set is selected in the dashboard tree.
        "inbounds": {"shadowsocks": [], "vless": []},
    })
    assert edited.status_code == 200, edited.text
    assert tag in edited.json()["inbounds"]["vless"]
    assert "Shadowsocks TCP" in edited.json()["inbounds"]["shadowsocks"]

    platform = _runtime().users.get_user_by_username(name)
    accounts = [row for row in _runtime().users.accounts_of(platform.id)
                if row["core_id"] == "xray"]
    assert {row["protocol"] for row in accounts} == {"vless", "shadowsocks"}
    assert all(not row["settings"].get("excluded_inbounds") for row in accounts)

    path = _client.post(
        f"/api/zagros/users/by-username/{name}/subscription-token",
        headers=_auth(token)).json()["path"]
    portal = _client.get(path, headers={"accept": "text/html",
                                        "user-agent": "Mozilla/5.0"})
    assert portal.status_code == 200, portal.text[:400]
    assert "vless://" in portal.text
    assert "ss://" in portal.text
    assert "No inbound is available" not in portal.text


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
# independent IP/HWID limits through the REAL HTTP stack
# --------------------------------------------------------------------- #

def test_device_limit_roundtrip_and_platform_mirror():
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
        "ip_limit": 2, "device_limit": 3})
    assert r.status_code == 200, r.text
    assert r.json()["ip_limit"] == 2
    assert r.json()["device_limit"] == 3

    platform = _runtime().users.get_user_by_username(name)
    assert platform is not None
    assert platform.ip_limit == 2 and platform.device_limit == 3

    # edit down, then clear (0 = explicit unlimited) — the mirror must
    # follow EXACTLY, including the clear (no stale keep-None residue).
    r = _client.put(f"/api/user/{name}", headers=_auth(token),
                    json={"ip_limit": 1, "device_limit": 1})
    assert r.status_code == 200, r.text
    assert r.json()["ip_limit"] == 1
    assert r.json()["device_limit"] == 1
    mirrored = _runtime().users.get_user_by_username(name)
    assert mirrored.ip_limit == 1 and mirrored.device_limit == 1

    r = _client.put(f"/api/user/{name}", headers=_auth(token),
                    json={"ip_limit": 0, "device_limit": 0})
    assert r.status_code == 200, r.text
    assert r.json()["ip_limit"] in (None, 0)
    assert r.json()["device_limit"] in (None, 0)
    mirrored = _runtime().users.get_user_by_username(name)
    assert mirrored.ip_limit is None and mirrored.device_limit is None

    # invalid values rejected by the schema itself
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": f"cx{uuid.uuid4().hex[:10]}",
        "proxies": {"shadowsocks": {}}, "device_limit": -2})
    assert r.status_code == 422


def test_ip_limit_security_settings_and_ban_api_roundtrip():
    token = _sudo_token()
    updated = _client.put(
        "/api/zagros/security/ip-limit", headers=_auth(token),
        json={"ban_duration_minutes": 15, "review_interval_seconds": 5},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["ban_duration_minutes"] == 15
    assert updated.json()["review_interval_seconds"] == 5
    overview = _client.get("/api/zagros/security", headers=_auth(token))
    assert overview.status_code == 200
    assert overview.json()["ip_limit"] == updated.json()
    bans = _client.get("/api/zagros/security/ip-bans", headers=_auth(token))
    assert bans.status_code == 200
    assert isinstance(bans.json()["bans"], list)


def test_subscription_hwid_is_strict_and_independent_from_ip_limit():
    token = _sudo_token()
    name = f"hw{uuid.uuid4().hex[:10]}"
    created = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
        "ip_limit": 9, "device_limit": 1,
    })
    assert created.status_code == 200, created.text
    path = _client.post(
        f"/api/zagros/users/by-username/{name}/subscription-token",
        headers=_auth(token),
    ).json()["path"]
    common = {"accept": "*/*", "user-agent": "v2rayNG/1.8.5"}

    missing = _client.get(path, headers=common)
    assert missing.status_code == 403
    assert "X-Device-ID" in missing.text

    first_id = "install-550e8400-e29b-41d4-a716-446655440000"
    first = _client.get(path, headers={**common, "X-Device-ID": first_id})
    assert first.status_code == 200, first.text
    repeat = _client.get(path, headers={**common, "X-HWID": first_id})
    assert repeat.status_code == 200

    denied = _client.get(
        path, headers={**common, "X-Device-ID": "another-install-identifier"})
    assert denied.status_code == 403
    assert "device limit reached" in denied.text

    # The legacy /client/v1 API is PERMANENTLY CLOSED (410) — official-app
    # enrollment moved to the signed Application API (app.applicationapi),
    # whose login enforces the same device policy over signed requests.
    platform = _runtime().users.get_user_by_username(name)
    credentials = _client.post(
        f"/api/zagros/users/{platform.id}/app-credentials", headers=_auth(token))
    assert credentials.status_code == 200
    login_body = {"username": credentials.json()["username"],
                  "password": credentials.json()["password"]}
    # (The whole successful-login/rejection flow lived on the now-closed
    # /client/v1 API; the signed Application API owns that policy today and
    # enforces the same device rules over signed requests.)

    devices = _client.get(
        f"/api/zagros/users/by-username/{name}/devices", headers=_auth(token))
    assert devices.status_code == 200
    assert len(devices.json()["devices"]) == 1
    device_row = devices.json()["devices"][0]
    assert first_id not in str(device_row)
    removed = _client.delete(
        f"/api/zagros/users/by-username/{name}/devices/{device_row['id']}",
        headers=_auth(token),
    )
    assert removed.status_code == 200
    replacement = _client.get(
        path, headers={**common, "X-Device-ID": "another-install-identifier"})
    assert replacement.status_code == 200


# --------------------------------------------------------------------- #
# multi-format subscription dispatch (spec §7/§8) through REAL HTTP
# --------------------------------------------------------------------- #

def _issued_path(name: str, token: str) -> str:
    return _client.post(f"/api/zagros/users/by-username/{name}/subscription-token",
                        headers=_auth(token)).json()["path"]


def test_subscription_formats_dispatch_by_ua_and_override():
    token = _sudo_token()
    name = f"cx{uuid.uuid4().hex[:10]}"
    # explicitly xray-only: a create WITHOUT core_access would receive the
    # panel's API defaults (every enabled core the suite left attached) and
    # the bundle would rightly carry more than ss:// links
    r = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}}, "core_access": {}})
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


# --------------------------------------------------------------------- #
# Marzban-compatible bots (Mirza & co.): no core_access, relative links
# --------------------------------------------------------------------- #

def _set_api_defaults(token: str, core_access):
    r = _client.put("/api/zagros/settings/api-defaults", headers=_auth(token),
                    json={"core_access": core_access})
    assert r.status_code == 200, r.text
    return r.json()


def _mirza_create(token: str, name: str, **extra):
    """The exact body mirzabot's Marzban.php sends (no ``core_access`` key)."""
    body = {"proxies": {"shadowsocks": {}}, "data_limit": 10737418240, "username": name,
            "note": "", "data_limit_reset_strategy": "no_reset", "expire": 0}
    body.update(extra)
    return _client.post("/api/user", headers=_auth(token), json=body)


def test_create_without_core_access_gets_the_panel_defaults(monkeypatch):
    """Item 4 of the bug list: a Mirza-created user received the xray core
    only. The policy default is ``all`` — every enabled non-xray core."""
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    driver = _recording_driver(core_id, "wireguard")
    _stub_catalog(monkeypatch, core_id, "wireguard", ["wg0", "wg1"])
    token = _sudo_token()
    _set_api_defaults(token, "all")
    name = f"mz{uuid.uuid4().hex[:10]}"

    r = _mirza_create(token, name)
    assert r.status_code == 200, r.text
    assert r.json()["core_access"].get(core_id) == ["wg0", "wg1"]
    assert driver.created, "the default grant never reached the core"
    # and the GET the bot performs afterwards agrees
    r = _client.get(f"/api/user/{name}", headers=_auth(token))
    assert r.json()["core_access"].get(core_id) == ["wg0", "wg1"]
    # the preview endpoint tells the operator what a bot user will get
    r = _client.get("/api/zagros/settings/api-defaults", headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["core_access"] == "all"
    assert r.json()["resolved_core_access"].get(core_id) == ["wg0", "wg1"]


def test_api_defaults_policy_none_keeps_the_legacy_xray_only_behaviour(monkeypatch):
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    driver = _recording_driver(core_id, "wireguard")
    _stub_catalog(monkeypatch, core_id, "wireguard", ["wg0"])
    token = _sudo_token()
    _set_api_defaults(token, "none")
    try:
        r = _mirza_create(token, f"mz{uuid.uuid4().hex[:10]}")
        assert r.status_code == 200, r.text
        assert not (r.json()["core_access"] or {}), r.json()["core_access"]
        assert not driver.created
    finally:
        _set_api_defaults(token, "all")


def test_api_defaults_fixed_mapping_drops_unknown_tags_instead_of_failing(monkeypatch):
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    driver = _recording_driver(core_id, "wireguard")
    _stub_catalog(monkeypatch, core_id, "wireguard", ["wg0", "wg1"])
    token = _sudo_token()
    saved = _set_api_defaults(token, {core_id: ["wg1", "gone-tag"], "ghost-core": ["x"]})
    assert saved["core_access"] == {core_id: ["wg1", "gone-tag"], "ghost-core": ["x"]}
    assert saved["resolved_core_access"] == {core_id: ["wg1"]}
    try:
        r = _mirza_create(token, f"mz{uuid.uuid4().hex[:10]}")
        assert r.status_code == 200, r.text
        assert r.json()["core_access"] == {core_id: ["wg1"]}
        assert driver.created
    finally:
        _set_api_defaults(token, "all")


def test_api_defaults_reject_a_malformed_policy():
    token = _sudo_token()
    for bad in ("sometimes", 7, {"": ["a"]}, {"core": "not-a-list"}):
        r = _client.put("/api/zagros/settings/api-defaults", headers=_auth(token),
                        json={"core_access": bad})
        assert r.status_code == 422, (bad, r.text)


def test_explicit_core_access_always_wins_over_the_defaults(monkeypatch):
    """The dashboard and Zagros-aware clients send the key — even ``{}``."""
    core_id = f"rec-{uuid.uuid4().hex[:6]}"
    driver = _recording_driver(core_id, "wireguard")
    _stub_catalog(monkeypatch, core_id, "wireguard", ["wg0"])
    token = _sudo_token()
    _set_api_defaults(token, "all")
    r = _mirza_create(token, f"mz{uuid.uuid4().hex[:10]}", core_access={})
    assert r.status_code == 200, r.text
    assert r.json()["core_access"] == {}
    assert not driver.created


def test_subscription_url_follows_the_saved_subscription_settings():
    """Item 4b: Mirza shows ``subscription_url`` from the create/get JSON. It
    must carry the public domain/scheme/port/path saved in Settings →
    Subscription, not the panel address the bot happened to call."""
    from app.platform import subscription_links

    token = _sudo_token()
    name = f"mz{uuid.uuid4().hex[:10]}"
    r = _mirza_create(token, name)
    assert r.status_code == 200, r.text
    before = r.json()["subscription_url"]
    assert before.startswith(("/sub/", "http://", "https://"))

    rt = _runtime()
    saved = asyncio.run(rt.portal_settings.get_portal_settings())
    try:
        wanted = saved.model_copy(update={
            "public_domain": "links.example.net", "custom_subdomain": "s",
            "public_scheme": "https", "public_port": 2096,
            "subscription_path": "connect", "listener_mode": "shared",
        })
        asyncio.run(rt.portal_settings.save_portal_settings(wanted))
        subscription_links.invalidate()

        for path in (f"/api/user/{name}", "/api/users"):
            r = _client.get(path, headers=_auth(token))
            assert r.status_code == 200, r.text
            body = r.json()
            user = body if path.endswith(name) else next(
                u for u in body["users"] if u["username"] == name)
            url = user["subscription_url"]
            assert url.startswith("https://s.links.example.net:2096/connect/"), url
            assert "/zagros/sub/" not in url
        # a bot-created user is listed with the very same absolute link
        r = _mirza_create(token, f"mz{uuid.uuid4().hex[:10]}")
        assert r.json()["subscription_url"].startswith(
            "https://s.links.example.net:2096/connect/")
    finally:
        asyncio.run(rt.portal_settings.save_portal_settings(saved))
        subscription_links.invalidate()

    # environment fallback still applies when no public identity is saved
    shape = subscription_links.link_shape(force=True)
    assert shape["source"] in ("environment", "none", "portal")


def test_edit_core_access_is_full_state_and_removals_revoke(monkeypatch):
    """f-panel-6: the dashboard Edit/Save always sends the COMPLETE desired
    core_access mapping. Removing a core — or clearing the mapping — must
    revoke that core's accounts; a green "saved" toast that silently keeps
    them was the bug (a partial mapping from API callers still keeps
    unlisted cores: PATCH semantics stay for callers that omit the key)."""
    core_a = f"rec-{uuid.uuid4().hex[:6]}"
    core_b = f"rec-{uuid.uuid4().hex[:6]}"
    _recording_driver(core_a, "wireguard")
    _recording_driver(core_b, "ssh")
    # one combined stub for BOTH cores — _stub_catalog replaces the catalog
    # attribute, so two calls would clobber each other (only the last wins)
    from app.platform import provisioning as _prov
    from app.platform.inbounds import CatalogGroup, CatalogInbound
    extra_groups = [
        CatalogGroup(core_id=core_a, name=core_a, enabled=True,
                     inbounds=[CatalogInbound(tag="wg0", protocol="wireguard")]),
        CatalogGroup(core_id=core_b, name=core_b, enabled=True,
                     inbounds=[CatalogInbound(tag="ssh", protocol="ssh")]),
    ]

    async def _two_core_catalog(runtime):
        # mirror _stub_catalog: wrap the real builder and inject/replace
        # BOTH recording cores in one pass (a single setattr — two separate
        # _stub_catalog calls would clobber each other)
        groups = await _prov.__dict__["_real_catalog_original"](runtime) \
            if "_real_catalog_original" in _prov.__dict__ \
            else await _orig_build(runtime)
        have = {g.core_id for g in groups}
        for g in extra_groups:
            if g.core_id in have:
                groups = [g if gg.core_id == g.core_id else gg for gg in groups]
            else:
                groups.append(g)
        return groups

    _orig_build = _prov.build_inbound_catalog
    monkeypatch.setattr(_prov, "build_inbound_catalog", _two_core_catalog)
    token = _sudo_token()
    name = f"rx{uuid.uuid4().hex[:10]}"

    created = _client.post("/api/user", headers=_auth(token), json={
        "username": name, "proxies": {"shadowsocks": {}},
        "core_access": {core_a: ["wg0"], core_b: ["ssh"]},
    })
    assert created.status_code == 200, created.text
    rt = _runtime()
    row = rt.users.get_user_by_username(name)
    assert row is not None

    # remove core_b: the UI sends only the kept core — it must be revoked
    print("DBG after create:", [(a["core_id"], a["protocol"], a.get("settings", {}).get("inbound_tags")) for a in rt.users.accounts_of(row.id)])
    kept = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "core_access": {core_a: ["wg0"]},
    })
    assert kept.status_code == 200, kept.text
    accounts = rt.users.accounts_of(row.id)
    print("DBG after keep-PUT:", [(a["core_id"], a["protocol"], a.get("settings", {}).get("inbound_tags")) for a in accounts], "kept.text=", kept.text[:200])
    assert not [a for a in accounts if a["core_id"] == core_b], (
        "un-selected core's account survived a successful save")
    assert [a for a in accounts if a["core_id"] == core_a]

    # clear the mapping entirely: every non-xray core account goes
    cleared = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "core_access": {},
    })
    assert cleared.status_code == 200, cleared.text
    accounts = rt.users.accounts_of(row.id)
    assert not [a for a in accounts if a["core_id"] != "xray"], (
        "clearing core_access must revoke every core account")

    # re-grant, then omit the key entirely: PATCH semantics keep the grants
    re_granted = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "core_access": {core_a: ["wg0"]},
    })
    assert re_granted.status_code == 200, re_granted.text
    omitted = _client.put(f"/api/user/{name}", headers=_auth(token), json={
        "note": "status/limit-style update without core_access",
    })
    assert omitted.status_code == 200, omitted.text
    accounts = rt.users.accounts_of(row.id)
    assert [a for a in accounts if a["core_id"] == core_a], (
        "omitted core_access must keep current grants")
