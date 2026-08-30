"""Tests for app.platform.admin_api — the unified-dashboard admin surface.

Everything runs against REAL objects over HTTP (TestClient against the real
router stack): a real PlatformRuntime on a real Alembic-created SQLite
schema, a real CoreManager with a test-double driver registered through the
real registry, real KV persistence, real cryptography for certificates.
Only the sudo-auth dependency is overridden (auth itself is covered by the
real-binary E2E suite).
"""
from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
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

        def export_config_document(self):
            return {"inbounds": [{
                "tag": "reality-in", "protocol": "socks", "port": 10080,
            }]}

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


async def _canonical_routing_sources(_runtime):
    """Map the fake translator's test inbound to a production-supported source core."""
    return {"groups": [{
        "core_id": "xray", "name": "Xray", "enabled": True,
        "inbounds": [{
            "tag": "reality-in", "protocol": "socks", "port": 10080,
        }],
    }]}


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

    def test_capability_matrix_is_runtime_refined(self, stack):
        payload = stack["client"].get(
            "/api/zagros/cores/capability-matrix").json()
        assert set(payload["all"]) == {
            "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether", "pptp"}
        assert payload["cores"]["wireguard"]["inbound"]["state"] == "not_installed"
        assert payload["cores"]["softether"]["outbound"]["state"] == "not_installed"
        assert set(payload["routing"]) == {
            "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether", "pptp"}
        assert payload["routing"]["xray"]["ssh"]["state"] in {
            "supported", "not_installed"}
        assert payload["routing"]["wireguard"]["ssh"]["state"] == "unsupported"
        assert set(payload["softether_transports"]) == {
            "native", "l2tp_ipsec", "l2tp_raw", "sstp", "openvpn", "pptp"}
        assert payload["softether_transports"]["pptp"]["server"]["state"] != "supported"
        provider = payload["provider_capabilities"]["pptp"]
        assert provider["engine"] == "accel-ppp"
        assert provider["security_class"] == "legacy_insecure"
        assert provider["state"] == "not_installed"

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

    def test_view_never_shows_error_for_a_live_core(self, stack):
        """alpha.7.2 item 3: a recorded ERROR (start died after the process
        came up) must not paint the healthy, running core as Error — the
        live probe wins in the view layer, the monitor reconciles the row."""
        client, rt, fake = stack["client"], stack["rt"], stack["plain"]
        r = client.post(f"/api/zagros/cores/{fake}/start")
        assert r.json()["state"] == "running"

        from app.cores.types import CoreState

        mgr = rt.core_manager
        mgr._states[fake] = CoreState.ERROR  # simulated stuck record
        stored = mgr._states[fake]
        assert stored == CoreState.ERROR

        view = client.get(f"/api/zagros/cores/{fake}").json()
        assert view["state"] == "running", view
        assert view["health"] == "healthy"

        # one monitor cycle heals the record itself
        import asyncio

        asyncio.run(mgr._health_cycle({}))
        assert mgr._states[fake] == CoreState.RUNNING
        # leave the fixture clean for other tests
        client.post(f"/api/zagros/cores/{fake}/stop")

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
    def test_managed_softether_hub_api_is_secret_free_and_routing_only(self, stack):
        from types import SimpleNamespace

        from app.cores.types import CoreState

        client, rt = stack["client"], stack["rt"]

        class Backend:
            def __init__(self):
                self.live = {"DEFAULT"}

            def hub_list(self):
                return sorted(self.live)

        class Driver:
            metadata = SimpleNamespace(name="SoftEther VPN")

            def __init__(self):
                self.settings = {
                    "hub": "DEFAULT", "feature_tags": {}, "feature_softether": True,
                    "native_port": 5555, "policy_hubs": [],
                }
                self._backend = Backend()

            def routing_source_specs(self):
                specs = [{"id": "hub:DEFAULT", "hub": "DEFAULT", "tags": [],
                          "subnet": "192.168.30.0/24", "managed_by_zagros": False}]
                for item in self.settings["policy_hubs"]:
                    specs.append({
                        "id": f"hub:{item['hub']}", "hub": item["hub"],
                        "tags": [item["inbound_tag"]], "tap_device": item["tap_device"],
                        "subnet": item["subnet"], "gateway": item["gateway"],
                        "username": item["username"], "managed_by_zagros": True,
                    })
                return specs

            def policy_sources(self):
                return []

            def create_policy_hub(self, **kwargs):
                password = kwargs.pop("user_password")
                assert password == "managed-unit-password"
                item = {**kwargs, "managed_by_zagros": True}
                self.settings["policy_hubs"].append(item)
                self._backend.live.add(item["hub"])
                assert password not in repr(self.settings)
                return item

            def delete_policy_hub(self, hub):
                self.settings["policy_hubs"] = [
                    item for item in self.settings["policy_hubs"] if item["hub"] != hub]
                self._backend.live.discard(hub)

            def ensure_policy_source(self, source_id):
                raise AssertionError(f"no rule should activate {source_id}")

            def disable_policy_source(self, source_id):
                raise AssertionError(f"no active source should disable {source_id}")

        from tests.cores.policy_fakes import FakeRunner

        driver = Driver()
        original_runner = rt.policy_router._runner  # noqa: SLF001
        rt.policy_router._runner = FakeRunner()  # noqa: SLF001
        rt.core_manager.attach("softether", driver, state=CoreState.RUNNING)
        try:
            asyncio.run(rt.kv.set_value("admin.routing.rules.v1", []))
            response = client.post("/api/zagros/cores/softether/policy-hubs", json={
                "hub": "ZAGROS-E2E-unit", "inbound_tag": "softether-e2e-unit",
                "tap_device": "zge2eunit", "subnet": "192.168.87.0/24",
                "gateway": "192.168.87.254", "username": "e2e-user",
                "user_password": "managed-unit-password",
            })
            assert response.status_code == 200, response.text
            assert "managed-unit-password" not in response.text
            assert response.json()["credential_stored"] is False

            hubs = client.get("/api/zagros/cores/softether/policy-hubs")
            assert hubs.status_code == 200, hubs.text
            assert hubs.json()["hubs"][0]["hub"] == "ZAGROS-E2E-unit"
            assert "password" not in hubs.text.lower()

            routing = client.get("/api/zagros/routing/sources")
            assert routing.status_code == 200, routing.text
            soft = next(group for group in routing.json()["groups"]
                        if group["core_id"] == "softether")
            managed = next(item for item in soft["inbounds"]
                           if item["tag"] == "softether-e2e-unit")
            assert managed["routing_only"] is True
            assert managed["source_core"] == "softether"
            assert managed["source_id"] == "softether:softether-e2e-unit"
            assert managed["duplicate_tag"] is False
            ordinary = client.get("/api/zagros/inbounds").json()
            assert "softether-e2e-unit" not in repr(ordinary)

            asyncio.run(rt.kv.set_value("admin.routing.rules.v1", [{
                "name": "still-referenced", "priority": 10, "enabled": True,
                "matcher": {"inbounds": ["softether-e2e-unit"]},
                "action": "allow", "outbound": None,
            }]))
            blocked = client.delete(
                "/api/zagros/cores/softether/policy-hubs/ZAGROS-E2E-unit")
            assert blocked.status_code == 409
            assert driver._backend.live == {"DEFAULT", "ZAGROS-E2E-unit"}
            asyncio.run(rt.kv.set_value("admin.routing.rules.v1", []))

            deleted = client.delete(
                "/api/zagros/cores/softether/policy-hubs/ZAGROS-E2E-unit")
            assert deleted.status_code == 200, deleted.text
            assert driver._backend.live == {"DEFAULT"}
            assert driver.settings["policy_hubs"] == []
        finally:
            rt.core_manager._drivers.pop("softether", None)  # noqa: SLF001
            rt.core_manager._states.pop("softether", None)  # noqa: SLF001
            rt.core_manager._enabled.pop("softether", None)  # noqa: SLF001
            rt.policy_router._runner = original_runner  # noqa: SLF001
            rt.policy_router._softether_routed.clear()  # noqa: SLF001
            asyncio.run(rt.core_state.remove("softether"))

    def test_save_validate_and_preview(self, stack, monkeypatch):
        import app.platform.admin_api as admin_api

        monkeypatch.setattr(admin_api, "routing_sources", _canonical_routing_sources)
        client, routing_id, plain_id = stack["client"], stack["routing"], stack["plain"]
        for cid in (routing_id, plain_id):
            client.post(f"/api/zagros/cores/{cid}/install", json={"enabled": True})

        # Enabled rules fail closed until their target exists; saving a typo
        # must never create a graph that can only fail later at Deploy.
        r = client.put("/api/zagros/routing/rules", json={"rules": [_rule()]})
        assert r.status_code == 422

        # surrogate outbound so route_to resolves during save/preview
        client.put("/api/zagros/outbounds", json={"outbounds": [
            {"name": "warp-up", "kind": "socks",
             "settings": {"server": "127.0.0.1", "server_port": 1080}, "enabled": True},
        ]})
        # Test runtimes have no Linux policy domain; this fake router is not a
        # production service core, so name existence is the validation edge.
        r = client.put("/api/zagros/routing/rules", json={"rules": [_rule()]})
        assert r.status_code == 200, r.text
        assert r.json()["count"] == 1

        listed = client.get("/api/zagros/routing/rules").json()["rules"]
        assert listed[0]["matcher"]["inbounds"] == ["reality-in"]
        assert listed[0]["outbound"] == "warp-up"

        preview = client.post("/api/zagros/routing/preview", json={"rules": [_rule()]})
        assert preview.status_code == 200, preview.text
        results = preview.json()["results"]
        assert "rule-1" in results[routing_id]["applied"]  # pure translator, dry
        plain_gaps = results[plain_id]["unsupported"]
        assert plain_gaps and "no routing support" in plain_gaps[0]["reason"]

    def test_target_inventory_advertises_scoped_tcp_ssh_policy_tun(self, stack):
        client = stack["client"]
        original = client.get("/api/zagros/outbounds").json()["outbounds"]
        ssh = {"name": "ssh-app", "kind": "ssh", "settings": {
            "server": "ssh.example.test", "server_port": 22,
            "username": "alice", "password": "dummy-test-value",
        }, "enabled": True}
        r = client.put("/api/zagros/outbounds",
                       json={"outbounds": [*original, ssh]})
        assert r.status_code == 200, r.text
        targets = client.get("/api/zagros/routing/targets")
        assert targets.status_code == 200, targets.text
        target = next(row for row in targets.json()["targets"]
                      if row["name"] == "ssh-app")
        assert target["kind"] == "ssh"
        assert target["state"] in {"supported", "not_installed"}
        assert target["selectable"] is True
        assert target["direction"] == "outbound"
        assert target["dataplane"] == "policy_tun"
        assert target["contexts"] == ["native_application_tcp", "policy_tun"]
        assert target["transports"] == ["tcp"]
        assert target["traffic_networks"] == ["tcp"]
        assert target["source_cores"] == [
            "openvpn", "pptp", "sing-box", "softether", "ssh", "wireguard", "xray",
        ]
        assert target["application_level"] is True
        assert target["tun"] is True
        assert "policy_tun" in target["contexts"]
        restored = client.put("/api/zagros/outbounds",
                              json={"outbounds": original})
        assert restored.status_code == 200, restored.text

    def test_rejects_duplicate_and_empty_matcher(self, stack):
        client = stack["client"]
        r = client.put("/api/zagros/routing/rules",
                       json={"rules": [_rule("dup"), _rule("dup")]})
        assert r.status_code == 422
        bad = _rule("empty")
        bad["matcher"] = {}  # model-level validation: matcher must not be empty
        r = client.put("/api/zagros/routing/rules", json={"rules": [bad]})
        assert r.status_code == 422

    def test_unknown_and_cross_core_duplicate_inbound_tags_fail_closed(
        self, stack, monkeypatch,
    ):
        import app.platform.admin_api as admin_api

        client = stack["client"]
        saved = client.put("/api/zagros/outbounds", json={"outbounds": [{
            "name": "warp-up", "kind": "socks", "enabled": True,
            "settings": {"server": "127.0.0.1", "server_port": 1080},
        }]})
        assert saved.status_code == 200, saved.text
        repeated = _rule("repeated-source")
        repeated["matcher"]["inbounds"] = ["reality-in", "reality-in"]
        response = client.put("/api/zagros/routing/rules", json={"rules": [repeated]})
        assert response.status_code == 422
        assert "duplicate inbound tag" in response.text
        unknown = _rule("unknown-source")
        unknown["matcher"]["inbounds"] = ["deleted-inbound"]
        response = client.put("/api/zagros/routing/rules", json={"rules": [unknown]})
        assert response.status_code == 422
        assert "unknown/deleted inbound" in response.text

        async def duplicate_sources(_runtime):
            return {"groups": [
                {"core_id": "xray", "name": "Xray", "enabled": True,
                 "inbounds": [{"tag": "same-tag", "protocol": "socks", "port": 1001}]},
                {"core_id": "sing-box", "name": "sing-box", "enabled": True,
                 "inbounds": [{"tag": "same-tag", "protocol": "socks", "port": 1002}]},
            ]}

        monkeypatch.setattr(admin_api, "routing_sources", duplicate_sources)
        duplicate = _rule("duplicate-source")
        duplicate["matcher"]["inbounds"] = ["same-tag"]
        response = client.put("/api/zagros/routing/rules", json={"rules": [duplicate]})
        assert response.status_code == 422
        assert "duplicate inbound tag" in response.text

    def test_deploy_saves_and_reports(self, stack, monkeypatch):
        import app.platform.admin_api as admin_api

        monkeypatch.setattr(admin_api, "routing_sources", _canonical_routing_sources)
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

    def test_credentials_are_encrypted_at_rest_redacted_and_preserved(self, stack):
        client, runtime = stack["client"], stack["rt"]
        secret = "phase3-api-secret-never-return"
        response = client.put("/api/zagros/outbounds", json={"outbounds": [{
            "name": "secure-ssh", "kind": "ssh", "enabled": True,
            "settings": {
                "server": "127.0.0.1", "server_port": 9,
                "username": "alice", "password": secret,
            },
        }]})
        assert response.status_code == 200, response.text
        listed = client.get("/api/zagros/outbounds").json()["outbounds"]
        profile = next(item for item in listed if item["name"] == "secure-ssh")
        assert "password" not in profile["settings"]
        assert profile["secret_state"] == {"password": True}
        assert secret not in json.dumps(profile)
        stored = asyncio.run(runtime.kv.get_value("admin.outbounds.v1"))
        assert stored["version"] == 2
        assert secret not in json.dumps(stored)
        assert stored["profiles"][0]["credentials_enc"].startswith("v1:")

        # A GET→PUT round trip intentionally omits the password.  The server
        # retains the existing authenticated ciphertext instead of forcing the
        # browser to receive or round-trip plaintext.
        response = client.put("/api/zagros/outbounds", json={"outbounds": listed})
        assert response.status_code == 200, response.text
        internal = runtime.outbound_manager.get("secure-ssh")
        assert internal.settings["password"] == secret

    def test_validation_errors_never_echo_submitted_credentials(self, stack):
        marker = "SECRET-MARKER-MUST-NOT-ECHO"
        response = stack["client"].put("/api/zagros/outbounds", json={"outbounds": [{
            "name": "invalid-sstp", "kind": "sstp", "enabled": True,
            "settings": {
                "server": "vpn.example.test", "server_port": 443,
                "username": "alice", "password": marker,
                "allow_insecure": True,
            },
        }]})
        assert response.status_code == 422
        assert marker not in response.text
        assert "cannot be bypassed" in response.text

    def test_ppp_test_uses_disposable_domain_samples_network_and_rolls_back(
        self, stack, monkeypatch,
    ):
        from app.cores.outbounds.model import Outbound
        from app.platform import admin_api

        outbound = Outbound(name="test-real-pptp", kind="pptp", settings={
            "server": "vpn.example.test", "server_port": 1723,
            "username": "alice", "password": "test-secret",
            "legacy_risk_ack": True, "test_samples": 24,
            "test_url": "https://probe.example.test/nonce",
        })

        class Domain:
            ready = True

        class Policy:
            def __init__(self):
                self.calls = []
                self.active_name = ""

            def prepare(self, values):
                names = [item.name for item in values]
                self.calls.append(names)
                self.active_name = names[0] if names else ""
                return {self.active_name: Domain()} if names else {}

            def domain_views(self):
                return [{
                    "outbound": self.active_name, "ready": True, "mode": "ppp",
                    "interface": "zgltest", "tunnel_interface": "ppp0",
                    "namespace": "zgntest", "client_address": "10.0.0.2",
                    "client_uplink_bytes": 12, "client_downlink_bytes": 34,
                    "establishment_ms": 901.0, "ppp_ready_ms": 650.0,
                }]

            def measure_ppp(self, domain, measured_outbound):
                assert domain.ready
                assert measured_outbound.settings["test_url"] == (
                    "https://probe.example.test/nonce")
                assert measured_outbound.settings["test_samples"] == 24
                return {
                    "direct_rtt": {
                        "samples": 24, "median_ms": 8.0, "p95_ms": 12.0,
                    },
                    "tunnel_rtt": {
                        "samples": 24, "median_ms": 31.0, "p95_ms": 44.0,
                    },
                    "selected_rtt_ms": 31.0,
                    "direct_https": {
                        "elapsed_ms": 15.0, "nonce": "direct-nonce",
                    },
                    "tunnel_https": {
                        "elapsed_ms": 40.0, "nonce": "tunnel-nonce",
                    },
                    "route": "203.0.113.8 dev ppp0 src 10.0.0.2",
                    "counter_delta": {
                        "uplink_bytes": 123, "downlink_bytes": 456,
                    },
                }

        policy = Policy()
        async def no_stored(_runtime): return []
        monkeypatch.setattr(admin_api, "_load_outbounds", no_stored)
        monkeypatch.setattr(stack["rt"], "policy_router", policy)
        result = asyncio.run(admin_api._test_outbound(stack["rt"], outbound))
        assert result == {"status": "healthy", "rtt_ms": 31.0}
        assert "setup_ms" not in result
        assert "rollback_ms" not in result
        assert "establishment_ms" not in result
        assert "ppp_ready_ms" not in result
        assert "first_packet_ms" not in result
        assert "diagnostics" not in result
        assert "detail" not in result
        disposable_name = policy.calls[0][0]
        assert disposable_name != outbound.name
        assert disposable_name.startswith("zgtest-")
        assert policy.calls == [[disposable_name], []]

    def test_connection_test_is_real(self, stack):
        client = stack["client"]
        r = client.post("/api/zagros/outbounds/test", json={
            "name": "t-direct", "kind": "direct", "settings": {}})
        assert r.json()["status"] == "healthy"  # no endpoint needed

        r = client.post("/api/zagros/outbounds/test", json={
            "name": "t-socks", "kind": "socks",
            "settings": {"server": "127.0.0.1", "server_port": 9}})  # discard port: closed
        assert r.json()["status"] == "unhealthy"
        assert "error" in r.json()

        r = client.post("/api/zagros/outbounds/test", json={
            "name": "t-chain", "kind": "core", "settings": {"core_id": "ghost-core"}})
        assert r.json()["status"] == "unhealthy"
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
        legacy = {
            "softether_l2tp", "softether_l2tp_raw",
            "softether_sstp", "softether_pptp",
        }
        assert set(schemas) == {k.value for k in OutboundKind} - legacy
        assert {"softether_native", "l2tp_ipsec", "l2tp_raw", "sstp", "pptp"} <= set(schemas)
        assert not legacy.intersection(schemas)
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
        for kind in ("l2tp_ipsec", "l2tp_raw", "sstp", "pptp"):
            assert {"test_url", "test_samples"} <= set(schemas[kind]["properties"])
            assert schemas[kind]["properties"]["test_samples"]["minimum"] == 20
            assert schemas[kind]["properties"]["test_samples"]["maximum"] == 30

    @pytest.mark.parametrize("kind", [
        "softether_l2tp", "softether_l2tp_raw",
        "softether_sstp", "softether_pptp",
    ])
    def test_deprecated_softether_aliases_cannot_be_created_or_tested(
        self, stack, kind,
    ):
        payload = {"name": f"legacy-{kind}", "kind": kind, "settings": {}}
        saved = stack["client"].put(
            "/api/zagros/outbounds", json={"outbounds": [payload]})
        assert saved.status_code == 422
        assert "deprecated outbound kind" in saved.text
        tested = stack["client"].post("/api/zagros/outbounds/test", json=payload)
        assert tested.status_code == 422
        assert "deprecated outbound kind" in tested.text

    def test_udp_outbound_tests_are_protocol_aware(self, stack):
        client = stack["client"]
        payloads = [
            {"name": "hy-udp", "kind": "hysteria2", "settings": {
                "server": "127.0.0.1", "server_port": 9, "password": "pw"}},
            {"name": "wg-udp", "kind": "wireguard", "settings": {
                "server": "127.0.0.1", "server_port": 9,
                "private_key": "A", "peer_public_key": "B",
                "local_address": ["10.0.0.2/32"]}},
            {"name": "ovpn-udp", "kind": "openvpn", "settings": {
                "ovpn_content": "client\nproto udp\nremote 127.0.0.1 9\n"}},
        ]
        for payload in payloads:
            result = client.post("/api/zagros/outbounds/test", json=payload)
            assert result.status_code == 200, result.text
            assert result.json()["status"] == "healthy"
            assert "detail" not in result.json()
            assert result.json()["rtt_ms"] is not None

    def test_wireguard_profile_import_endpoint(self, stack):
        key = lambda value: base64.b64encode(bytes([value]) * 32).decode()  # noqa: E731
        content = (
            f"[Interface]\nPrivateKey = {key(1)}\nAddress = 10.77.0.2/32\n"
            "DNS = 1.1.1.1\n"
            f"[Peer]\nPublicKey = {key(2)}\nPresharedKey = {key(3)}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = wg.example.com:51830\n"
            "PersistentKeepalive = 25\n"
        )
        response = stack["client"].post(
            "/api/zagros/utils/parse-wireguard-profile", json={"content": content})
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["kind"] == "wireguard"
        assert data["settings"]["server"] == "wg.example.com"
        assert data["settings"]["server_port"] == 51830
        assert data["settings"]["local_address"] == ["10.77.0.2/32"]
        assert data["settings"]["allowed_ips"] == ["0.0.0.0/0", "::/0"]
        assert "private_key" not in data["settings"]
        assert "preshared_key" not in data["settings"]
        assert data["secret_state"] == {"preshared_key": True, "private_key": True}
        assert data["sealed_credentials"].startswith("v1:")
        assert key(1) not in json.dumps(data) and key(3) not in json.dumps(data)
        saved = stack["client"].put("/api/zagros/outbounds", json={"outbounds": [{
            "name": "imported-wg", "kind": data["kind"],
            "settings": data["settings"], "secret_state": data["secret_state"],
            "sealed_credentials": data["sealed_credentials"], "enabled": True,
        }]})
        assert saved.status_code == 200, saved.text
        internal = stack["rt"].outbound_manager.get("imported-wg")
        assert internal.settings["private_key"] == key(1)
        assert internal.settings["preshared_key"] == key(3)
        bad = stack["client"].post(
            "/api/zagros/utils/parse-wireguard-profile",
            json={"content": "[Interface]\nAddress=bad\n"})
        assert bad.status_code == 422

    def test_parse_share_url_endpoint(self, stack):
        r = stack["client"].post("/api/zagros/utils/parse-share-url", json={
            "url": "vless://8f3b6b90-1111-4222-8333-944455556666@cdn.example.com:443"
                   "?security=reality&type=ws&path=%2Fws&pbk=K&sid=01&sni=x.io"
                   "&flow=xtls-rprx-vision#imported"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["kind"] == "vless"
        assert "uuid" not in data["settings"]
        assert data["secret_state"] == {"uuid": True}
        assert data["sealed_credentials"].startswith("v1:")
        assert "8f3b6b90" not in json.dumps(data)
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
        assert "s3cret" not in body
        assert "<ca>" in body and "</ca>" in body
        missing = client.get("/api/zagros/outbounds/export?name=ghost")
        assert missing.status_code == 404
        private = client.put("/api/zagros/outbounds", json={"outbounds": [{
            "name": "Private-OVPN", "kind": "openvpn", "settings": {
                "server": "vpn.example.com", "server_port": 1194,
                "key_pem": "-----BEGIN PRIVATE KEY-----\nno-echo\n-----END PRIVATE KEY-----",
            }, "enabled": True,
        }]})
        assert private.status_code == 200, private.text
        refused = client.get("/api/zagros/outbounds/export?name=Private-OVPN")
        assert refused.status_code == 409
        assert "no-echo" not in refused.text

    def test_versions_endpoint_uses_driver_repo(self, stack, monkeypatch):
        from app.cores import github_install
        calls = {}

        def fake_fetch(repo, *, limit=10, timeout=20.0):
            calls["repo"] = repo
            return [{"tag": "v1.2.3", "name": "x", "prerelease": False,
                     "published_at": "2026-01-01"}]

        monkeypatch.setattr(github_install, "fetch_recent_releases", fake_fetch)
        from app.platform import admin_api
        from app.cores import releases as releases_mod

        releases_mod.clear_cache()
        r = stack["client"].get("/api/zagros/cores/xray/versions")
        assert r.status_code == 200, r.text
        assert calls["repo"] == "XTLS/Xray-core"
        assert r.json()["releases"][0]["tag"] == "v1.2.3"

        # wireguard is OS-package managed → honest 404, not a fake list
        r = stack["client"].get("/api/zagros/cores/wireguard/versions")
        assert r.status_code == 404
        r = stack["client"].get("/api/zagros/cores/ghost/versions")
        assert r.status_code == 404


class TestSubscriptionCanonicalURL:
    def test_copy_url_uses_sql_subscription_origin_port_and_path(self, stack):
        client, runtime = stack["client"], stack["rt"]
        runtime.users.upsert_user(username="admapi-sub-user")
        saved = client.put("/api/zagros/settings/portal", json={
            "public_domain": "example.test",
            "custom_subdomain": "sub",
            "public_scheme": "https",
            "public_port": 9443,
            "subscription_path": "clients",
            "listener_mode": "external_proxy",
        })
        assert saved.status_code == 200, saved.text
        response = client.get(
            "/api/zagros/users/by-username/admapi-sub-user/subscription-url")
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["url"].startswith(
            "https://sub.example.test:9443/clients/")
        assert "/zagros/" not in payload["url"]
        assert payload["listener_mode"] == "external_proxy"


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
        # Environment-honest: the production image ships certbot, while a
        # minimal unit runner may have no ACME client at all.
        assert listed["acme"]["available"] is bool(listed["acme"]["providers"])
        if listed["acme"]["available"]:
            assert any(p["id"] in ("certbot", "acme.sh", "lego")
                       for p in listed["acme"]["providers"])

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
