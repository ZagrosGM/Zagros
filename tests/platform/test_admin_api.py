"""Tests for app.platform.admin_api — the unified-dashboard admin surface.

Everything runs against REAL objects over HTTP (TestClient against the real
router stack): a real PlatformRuntime on a real Alembic-created SQLite
schema, a real CoreManager with a test-double driver registered through the
real registry, real KV persistence, real cryptography for certificates.
Only the sudo-auth dependency is overridden (auth itself is covered by the
real-binary E2E suite).
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

_NEED = ("sqlalchemy", "fastapi", "httpx", "cryptography")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")

if _HAS:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient


def _env_for(db_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db_path}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db_path.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "test-secret-0123456789abcdef",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
        "UVICORN_PORT": "8031",
    })
    return env


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


def _register_fake_drivers() -> tuple[str, str]:
    """Two minimal REAL drivers through the real registry: a plain core and
    one with routing + a pure translator (for dry-preview tests)."""
    from app.cores.base import BaseCoreDriver
    from app.cores.types import (
        Capability,
        CoreMetadata,
        CoreState,
        CoreStatus,
        HealthStatus,
    )

    class FakePlain(BaseCoreDriver):
        metadata = CoreMetadata(id="admapi-fake", name="Admin API Fake",
                                protocols=["fake"], capabilities=set())

        def __init__(self, settings=None):
            super().__init__(settings)
            self.started = False
            self.logs: list[str] = []

        async def start(self) -> None:
            self.started = True
            self.logs.append("fake core started")

        async def stop(self) -> None:
            self.started = False
            self.logs.append("fake core stopped")

        async def status(self) -> CoreStatus:
            return CoreStatus(
                core_id=self.metadata.id,
                state=CoreState.RUNNING if self.started else CoreState.STOPPED,
                health=HealthStatus.HEALTHY if self.started else HealthStatus.UNKNOWN,
                core_version="fake-1.0",
            )

        async def get_logs(self, tail: int = 200):
            for line in (self.logs or ["no logs yet"])[-tail:]:
                yield line

        async def create_account(self, account) -> None: pass
        async def update_account(self, account) -> None: pass
        async def delete_account(self, account_id: str) -> None: pass
        async def build_client_config(self, account, node=None) -> str:
            return "fake://config"
        async def sync_accounts(self, accounts): pass

    class FakeRouting(FakePlain):
        metadata = CoreMetadata(
            id="admapi-router", name="Fake Router", protocols=["fake"],
            capabilities={Capability.ROUTING}, studio_inbounds_path="/inbounds")

        async def translate_routing_rules(self, rules, ctx):
            from app.cores.routing.model import TranslatedRoute

            return TranslatedRoute(
                core_id=self.metadata.id,
                applied=[r.name for r in rules],
                payload={"rules": [r.name for r in rules]})

        async def deploy_routing_rules(self, rules, ctx):
            return await self.translate_routing_rules(rules, ctx)

    return FakePlain.metadata.id, FakeRouting.metadata.id


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    db = tmp_path_factory.mktemp("admapi") / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT"):
        os.environ[var] = env[var]
    _migrate(env)

    # The legacy Admin model sits behind upstream's order-sensitive import
    # chain — warm the REAL app builder first (exactly what the panel and
    # hostctl's legacy path do), then the import resolves cleanly.
    # Note: tests/adminapi installs a bare 'app' package stub into
    # sys.modules and imports app.* submodules under it (their legacy-admin
    # try/except then binds the fails-closed auth stub). Evict every stub-era
    # module so the real package (with FastAPI app + real deps) loads fresh.
    if not hasattr(sys.modules.get("app"), "app"):
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            sys.modules.pop(name, None)
    import app as _app_warm

    _app_warm.app  # noqa: B018 - deliberate attribute touch to force warm-up

    plain_id, routing_id = _register_fake_drivers()

    from app.models.admin import Admin
    from app.platform import admin_api  # noqa: F401 - registers endpoints
    from app.platform.routers import zagros_admin_router
    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()

    app = FastAPI()
    app.state.zagros = rt
    app.dependency_overrides[Admin.check_sudo_admin] = lambda: {"username": "test"}
    app.include_router(zagros_admin_router)

    with TestClient(app) as client:
        yield {"client": client, "rt": rt, "plain": plain_id, "routing": routing_id}
    from app.cores.registry import unregister_driver
    unregister_driver(plain_id)
    unregister_driver(routing_id)


def _rule(name="rule-1", matcher=None, **kw):
    body = {
        "name": name,
        "matcher": matcher or {"inbounds": ["reality-in"], "geoips": ["ir"]},
        "action": "route_to",
        "outbound": "warp-up",
        "priority": 10,
        "enabled": True,
    }
    body.update(kw)
    return body


# --------------------------------------------------------------------- #
# cores lifecycle
# --------------------------------------------------------------------- #

class TestCores:
    def test_registry_lists_catalog(self, stack):
        client, fake = stack["client"], stack["plain"]
        payload = client.get("/api/zagros/cores/registry").json()
        ids = {c["id"] for c in payload["registry"]}
        assert {"xray", "sing-box", fake} <= ids
        meta = next(c for c in payload["registry"] if c["id"] == "xray")
        assert meta["installed"] is False
        assert "vless" in meta["protocols"]

    def test_full_lifecycle_over_http(self, stack):
        client, fake = stack["client"], stack["plain"]
        r = client.post(f"/api/zagros/cores/{fake}/install",
                        json={"settings": {"executable_path": "/bin/fake",
                                           "secret_key": "topsecret"}, "enabled": True})
        assert r.status_code == 200, r.text
        assert client.get("/api/zagros/cores").json()["cores"], "cores must list"

        view = client.get(f"/api/zagros/cores/{fake}").json()
        assert view["state"] == "installed"
        assert view["binary_path"] == "/bin/fake"
        assert view["settings"]["secret_key"] == "set (9 chars)"  # masked
        assert view["settings"]["executable_path"] == "/bin/fake"  # non-secret stays

        r = client.post(f"/api/zagros/cores/{fake}/start")
        assert r.json()["state"] == "running"
        view = client.get(f"/api/zagros/cores/{fake}").json()
        assert view["health"] == "healthy" and view["core_version"] == "fake-1.0"

        logs = client.get(f"/api/zagros/cores/{fake}/logs?lines=50").json()
        assert "fake core started" in logs["lines"]

        # disable auto-stops a running core (manager contract)
        assert client.post(f"/api/zagros/cores/{fake}/disable").json()["enabled"] is False
        assert client.get(f"/api/zagros/cores/{fake}").json()["state"] == "stopped"
        assert client.post(f"/api/zagros/cores/{fake}/enable").json()["enabled"] is True

        r = client.post(f"/api/zagros/cores/{fake}/start")
        assert r.json()["state"] == "running"
        r = client.post(f"/api/zagros/cores/{fake}/stop")
        assert r.json()["state"] == "stopped"

        r = client.post(f"/api/zagros/cores/{fake}/uninstall", json={"purge": False})
        assert r.json()["ok"] is True
        assert client.get(f"/api/zagros/cores/{fake}").status_code in (404, 500)

    def test_reinstall_preserves_settings_and_state(self, stack):
        client, fake = stack["client"], stack["plain"]
        r = client.post(f"/api/zagros/cores/{fake}/install",
                        json={"settings": {"executable_path": "/bin/fake",
                                           "secret_key": "keepme"}, "enabled": True})
        assert r.status_code == 200, r.text
        r = client.post(f"/api/zagros/cores/{fake}/reinstall")
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True
        view = client.get(f"/api/zagros/cores/{fake}").json()
        assert view["settings"]["executable_path"] == "/bin/fake"  # kept
        assert view["settings"]["secret_key"] == "set (6 chars)"  # secret preserved
        client.post(f"/api/zagros/cores/{fake}/uninstall", json={"purge": False})

    def test_lifecycle_unknown_core_404(self, stack):
        client = stack["client"]
        assert client.post("/api/zagros/cores/nope/start").status_code in (404, 400)
        r = client.post("/api/zagros/cores/nope/install", json={})
        assert r.status_code == 404


# --------------------------------------------------------------------- #
# routing rules (persistence + preview coverage + deploy)
# --------------------------------------------------------------------- #

class TestRouting:
    def test_save_validate_and_preview(self, stack):
        client, routing_id, plain_id = stack["client"], stack["routing"], stack["plain"]
        for cid in (routing_id, plain_id):
            client.post(f"/api/zagros/cores/{cid}/install", json={"enabled": True})

        r = client.put("/api/zagros/routing/rules", json={"rules": [_rule()]})
        assert r.status_code == 200, r.text
        assert r.json()["count"] == 1

        listed = client.get("/api/zagros/routing/rules").json()["rules"]
        assert listed[0]["matcher"]["inbounds"] == ["reality-in"]
        assert listed[0]["outbound"] == "warp-up"

        # surrogate outbound so route_to resolves during preview
        client.put("/api/zagros/outbounds", json={"outbounds": [
            {"name": "warp-up", "kind": "socks",
             "settings": {"server": "127.0.0.1", "server_port": 1080}, "enabled": True},
        ]})

        preview = client.post("/api/zagros/routing/preview", json={"rules": [_rule()]})
        assert preview.status_code == 200, preview.text
        results = preview.json()["results"]
        assert "rule-1" in results[routing_id]["applied"]  # pure translator, dry
        plain_gaps = results[plain_id]["unsupported"]
        assert plain_gaps and "no routing support" in plain_gaps[0]["reason"]

    def test_rejects_duplicate_and_empty_matcher(self, stack):
        client = stack["client"]
        r = client.put("/api/zagros/routing/rules",
                       json={"rules": [_rule("dup"), _rule("dup")]})
        assert r.status_code == 422
        bad = _rule("empty")
        bad["matcher"] = {}  # model-level validation: matcher must not be empty
        r = client.put("/api/zagros/routing/rules", json={"rules": [bad]})
        assert r.status_code == 422

    def test_deploy_saves_and_reports(self, stack):
        client = stack["client"]
        r = client.post("/api/zagros/routing/deploy", json={"rules": [_rule("d1")]})
        assert r.status_code == 200, r.text
        assert r.json()["saved"] is True


# --------------------------------------------------------------------- #
# outbounds
# --------------------------------------------------------------------- #

class TestOutbounds:
    def test_registry_roundtrip_and_sync(self, stack):
        client = stack["client"]
        r = client.put("/api/zagros/outbounds", json={"outbounds": [
            {"name": "direct-out", "kind": "direct", "settings": {}, "enabled": True},
            {"name": "up-1080", "kind": "socks",
             "settings": {"server": "127.0.0.1", "server_port": 1080}, "enabled": True},
        ]})
        assert r.status_code == 200, r.text
        listed = {o["name"] for o in client.get("/api/zagros/outbounds").json()["outbounds"]}
        assert listed >= {"direct-out", "up-1080"}
        # the manager registry was reconciled (routing previews see the names)
        assert "direct-out" in [o.name for o in stack["rt"].outbound_manager.list()]

    def test_duplicate_names_rejected(self, stack):
        r = stack["client"].put("/api/zagros/outbounds", json={"outbounds": [
            {"name": "twice", "kind": "direct", "settings": {}},
            {"name": "twice", "kind": "block", "settings": {}},
        ]})
        assert r.status_code == 422

    def test_connection_test_is_real(self, stack):
        client = stack["client"]
        r = client.post("/api/zagros/outbounds/test", json={
            "name": "t-direct", "kind": "direct", "settings": {}})
        assert r.json()["ok"] is True  # no endpoint needed

        r = client.post("/api/zagros/outbounds/test", json={
            "name": "t-socks", "kind": "socks",
            "settings": {"server": "127.0.0.1", "server_port": 9}})  # discard port: closed
        assert r.json()["ok"] is False
        assert "error" in r.json()

        r = client.post("/api/zagros/outbounds/test", json={
            "name": "t-chain", "kind": "core", "settings": {"core_id": "ghost-core"}})
        assert r.json()["ok"] is False
        assert "not installed" in r.json()["error"]


# --------------------------------------------------------------------- #
# sessions / client-sessions / devices
# --------------------------------------------------------------------- #

def _seed_user_and_rows(rt):
    from datetime import datetime, timezone

    from app.persistence.models import DeviceModel, RefreshTokenModel, UserModel

    with rt.session_factory() as s:
        user = UserModel(username="admapi-user", status="active")
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(RefreshTokenModel(token_hash="hash-1", user_id=user.id,
                                expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
                                user_agent="test-agent"))
        s.add(DeviceModel(device_id="dev-1", user_id=user.id, name="Pixel", platform="android"))
        s.commit()
        return user.id


class TestOutboundsAlpha7:
    """alpha.7 outbounds item: case-insensitive names, driver-shaped
    schemas, share-URL import, .ovpn re-export, version picker."""

    def test_uppercase_and_mixed_names_accepted(self, stack):
        r = stack["client"].put("/api/zagros/outbounds", json={"outbounds": [
            {"name": "Warp-EU_2", "kind": "direct", "settings": {}, "enabled": True},
        ]})
        assert r.status_code == 200, r.text

    def test_invalid_names_still_rejected(self, stack):
        r = stack["client"].put("/api/zagros/outbounds", json={"outbounds": [
            {"name": "-bad-start", "kind": "direct", "settings": {}},
        ]})
        assert r.status_code == 422

    def test_schema_covers_every_kind_and_transport(self, stack):
        payload = stack["client"].get("/api/zagros/outbounds/schema").json()
        schemas = payload["schemas"]
        from app.cores.outbounds.model import OutboundKind
        assert set(schemas) == {k.value for k in OutboundKind}
        vless_props = schemas["vless"]["properties"]
        assert set(vless_props["network"]["enum"]) >= {
            "tcp", "ws", "grpc", "http", "kcp", "quic",
            "httpupgrade", "splithttp"}
        assert "reality" in vless_props["security"]["enum"]
        assert {"reality_public_key", "reality_short_id",
                "fingerprint", "sni", "alpn"} <= set(vless_props)
        wg_props = schemas["wireguard"]["properties"]
        assert {"private_key", "peer_public_key", "mtu", "keepalive"} <= set(wg_props)
        ovpn_props = schemas["openvpn"]["properties"]
        assert {"ovpn_content", "username", "password",
                "ca_pem", "cert_pem", "key_pem"} <= set(ovpn_props)

    def test_parse_share_url_endpoint(self, stack):
        r = stack["client"].post("/api/zagros/utils/parse-share-url", json={
            "url": "vless://8f3b6b90-1111-4222-8333-944455556666@cdn.example.com:443"
                   "?security=reality&type=ws&path=%2Fws&pbk=K&sid=01&sni=x.io"
                   "&flow=xtls-rprx-vision#imported"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["kind"] == "vless"
        assert data["settings"]["uuid"].startswith("8f3b")
        assert data["settings"]["network"] == "ws"
        assert data["settings"]["reality_public_key"] == "K"
        assert data["name_hint"] == "imported"
        assert "vless" in data["supported_schemes"]

        bad = stack["client"].post("/api/zagros/utils/parse-share-url",
                                   json={"url": "pptp://nope"})
        assert bad.status_code == 422

    def test_ovpn_export_roundtrip(self, stack):
        client = stack["client"]
        r = client.put("/api/zagros/outbounds", json={"outbounds": [
            {"name": "Office-VPN", "kind": "openvpn", "settings": {
                "server": "vpn.example.com", "server_port": 1194,
                "username": "alice", "password": "s3cret",
                "ca_pem": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
            }, "enabled": True},
        ]})
        assert r.status_code == 200, r.text
        exp = client.get("/api/zagros/outbounds/export?name=Office-VPN")
        assert exp.status_code == 200, exp.text
        body = exp.text
        assert "remote vpn.example.com 1194" in body
        assert "auth-user-pass" in body
        assert "<ca>" in body and "</ca>" in body
        missing = client.get("/api/zagros/outbounds/export?name=ghost")
        assert missing.status_code == 404

    def test_versions_endpoint_uses_driver_repo(self, stack, monkeypatch):
        from app.cores import github_install
        calls = {}

        def fake_fetch(repo, *, limit=10, timeout=20.0):
            calls["repo"] = repo
            return [{"tag": "v1.2.3", "name": "x", "prerelease": False,
                     "published_at": "2026-01-01"}]

        monkeypatch.setattr(github_install, "fetch_recent_releases", fake_fetch)
        from app.platform import admin_api
        admin_api._VERSION_CACHE.clear()
        r = stack["client"].get("/api/zagros/cores/xray/versions")
        assert r.status_code == 200, r.text
        assert calls["repo"] == "XTLS/Xray-core"
        assert r.json()["releases"][0]["tag"] == "v1.2.3"

        # wireguard is OS-package managed → honest 404, not a fake list
        r = stack["client"].get("/api/zagros/cores/wireguard/versions")
        assert r.status_code == 404
        r = stack["client"].get("/api/zagros/cores/ghost/versions")
        assert r.status_code == 404


class TestInventory:
    def test_devices_list_and_remove(self, stack):
        client, rt = stack["client"], stack["rt"]
        _seed_user_and_rows(rt)
        devices = client.get("/api/zagros/devices").json()["devices"]
        row = next(d for d in devices if d["device_id"] == "dev-1")
        assert row["username"] == "admapi-user" and row["platform"] == "android"
        assert client.delete("/api/zagros/devices/dev-1").json()["ok"] is True
        assert client.delete("/api/zagros/devices/dev-1").status_code == 404

    def test_client_sessions_list_and_revoke(self, stack):
        client = stack["client"]
        sessions = client.get("/api/zagros/client-sessions").json()["sessions"]
        row = next(s for s in sessions if s["token_hash"] == "hash-1")
        assert row["username"] == "admapi-user" and row["revoked"] is False
        assert client.delete("/api/zagros/client-sessions/hash-1").json()["ok"] is True
        sessions = client.get("/api/zagros/client-sessions").json()["sessions"]
        row = next(s for s in sessions if s["token_hash"] == "hash-1")
        assert row["revoked"] is True

    def test_sessions_history_empty_state_is_real(self, stack):
        body = stack["client"].get("/api/zagros/sessions").json()
        assert body["sessions"] == []  # no traffic yet — honest empty


# --------------------------------------------------------------------- #
# certificates (real crypto)
# --------------------------------------------------------------------- #

class TestCertificates:
    def test_self_signed_roundtrip(self, stack):
        client = stack["client"]
        r = client.post("/api/zagros/certificates/self-signed", json={
            "name": "lab-cert", "common_name": "lab.example.com", "days": 365})
        assert r.status_code == 200, r.text
        cert = r.json()["certificate"]
        assert cert["self_signed"] is True and cert["has_key"] is True
        assert cert["days_left"] >= 360

        listed = client.get("/api/zagros/certificates").json()
        names = {c["name"] for c in listed["certificates"]}
        assert "lab-cert" in names
        assert listed["acme"]["available"] is False  # honest roadmap label

        r = client.post("/api/zagros/certificates/self-signed", json={
            "name": "lab-cert", "common_name": "dup.example.com"})
        assert r.status_code == 409  # refuses to clobber

        assert client.delete("/api/zagros/certificates/lab-cert").json()["ok"] is True
        assert client.delete("/api/zagros/certificates/lab-cert").status_code == 404

    def test_import_rejects_mismatched_pair(self, stack, tmp_path):
        client = stack["client"]
        from app.platform import certificates

        data = str(tmp_path / "certs-import")
        certificates.self_signed(data, "one", "one.example.com")
        certificates.self_signed(data, "two", "two.example.com")
        cert_one = (tmp_path / "certs-import" / "certs" / "one" / "fullchain.pem").read_text()
        key_two = (tmp_path / "certs-import" / "certs" / "two" / "key.pem").read_text()
        r = client.post("/api/zagros/certificates/import", json={
            "name": "mismatch", "cert_pem": cert_one, "key_pem": key_two})
        assert r.status_code == 422
        assert "do NOT match" in r.json()["detail"]


# --------------------------------------------------------------------- #
# panel info
# --------------------------------------------------------------------- #

def test_panel_info(stack):
    info = stack["client"].get("/api/zagros/panel/info").json()
    assert info["version"].startswith("1.0.0-alpha")
    assert info["client_auth_mode"] == "subscription_link"
    assert info["database_driver"] == "sqlite"
    assert info["uptime_seconds"] >= 0
