"""A node must reach "connected and serving" without an operator clicking twice.

Three gaps are pinned here:

* adding a node left it ``pending`` forever — nothing re-checked the agent
  after the installer had been run on it;
* a panel restart left every node stale — the pairing survives in the database
  but nothing re-proved it;
* installing a core on a node produced a core that could not start, because
  only "sync config" ever handed the node its listeners.

Node I/O is faked at the client boundary; the real service logic (discovery,
pairing, convergence, start) runs untouched.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "fastapi")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


@pytest.fixture(scope="module")
def env_runtime(tmp_path_factory):
    db = tmp_path_factory.mktemp("node-reconnect") / "zagros.db"
    env = {
        **os.environ,
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db}",
        "ZAGROS_SECRET_KEY": "node-reconnect-test-key-0123456789",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    }
    with pytest.MonkeyPatch.context() as mp:
        for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                    "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
            mp.setenv(var, env[var])
        _migrate(env)
        from app.platform.runtime import PlatformRuntime

        rt = PlatformRuntime.from_env()
        rt.verify_schema()
    return rt


# --------------------------------------------------------------------------- #
# fakes                                                                        #
# --------------------------------------------------------------------------- #

class FakeClient:
    def __init__(self, *, cores=None, fail=()):
        self.cores_payload = cores if cores is not None else {
            "installed": {}, "available": ["wireguard"], "preview": {}}
        self.fail = set(fail)
        self.actions: list[tuple[str, str]] = []
        self.sent_settings: list[dict] = []

    def _guard(self, what):
        if what in self.fail:
            raise RuntimeError(f"{what} refused")

    def heartbeat(self):
        self._guard("heartbeat")
        return {"node_id": "abc", "agent_version": "0.3.0"}

    def health(self):
        return {"healthy": True, "uptime_seconds": 12.0}

    def cores(self):
        self._guard("cores")
        return self.cores_payload

    def lifecycle(self, core_id, action, settings=None, purge=False, force=False):
        self._guard("lifecycle")
        self.actions.append((core_id, action))
        self.sent_settings.append(dict(settings or {}))
        return {"core_id": core_id, "state": "running" if action == "start" else action}


def _sealed_credentials(runtime, identity="node-abc"):
    return runtime.cipher.encrypt_json(
        {"signing_key": base64.b64encode(b"\x01" * 32).decode("ascii")},
        aad=f"node-agent:{identity}")


def _node(runtime, name, *, status="pending", paired=True, **extra):
    from app.persistence.models import NodeModel

    with runtime.session_factory() as session:
        session.merge(NodeModel(
            name=name, address="198.51.100.7", port=62050, api_port=62051,
            status=status, agent_type="zagros_native",
            panel_id=f"panel-test-{name}",
            agent_identity="node-abc" if paired else None,
            agent_credentials_enc=(_sealed_credentials(runtime) if paired else None),
            **extra))
        session.commit()
        row = session.query(NodeModel).filter(NodeModel.name == name).one()
        return int(row.id)


def _row(runtime, node_id):
    from app.persistence.models import NodeModel

    with runtime.session_factory() as session:
        row = session.get(NodeModel, node_id)
        session.expunge(row)
        return row


# --------------------------------------------------------------------------- #
# 1 — a paired node only needs a heartbeat                                     #
# --------------------------------------------------------------------------- #

def test_reconnect_revives_a_paired_node_with_a_heartbeat(env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "rr_paired", status="error",
                    last_error="connection refused")
    client = FakeClient()
    monkeypatch.setattr(service, "_client", lambda runtime, row: client)

    view = asyncio.run(service.reconnect(rt, node_id))

    assert view.status == "connected"
    assert view.last_error is None
    assert client.actions == []          # nothing to start: no cores installed


# --------------------------------------------------------------------------- #
# 2 — a pending node is discovered and paired on its own                       #
# --------------------------------------------------------------------------- #

def test_reconnect_pairs_a_pending_node(env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "rr_pending", status="pending", paired=False)
    calls: dict = {}

    async def fake_discover(runtime, nid):
        return service.Discovery(reachable=True, node_id="node-abc",
                                 certificate_sha256="a" * 64,
                                 pending_token=True, registered=False)

    async def fake_pair(runtime, nid, *, certificate_fingerprint,
                        registration_token=None, node_id_hint=None):
        calls.update({"nid": nid, "fingerprint": certificate_fingerprint,
                      "hint": node_id_hint})
        from app.persistence.models import NodeModel

        with runtime.session_factory() as session:
            current = session.get(NodeModel, nid)
            current.status = "connected"
            current.agent_identity = "node-abc"
            current.agent_credentials_enc = _sealed_credentials(runtime)
            session.commit()
            session.refresh(current)
            session.expunge(current)
            return service._view(current)

    converged: list[int] = []

    async def fake_converge(runtime, nid, core_ids=None):
        converged.append(nid)

    monkeypatch.setattr(service, "discover", fake_discover)
    monkeypatch.setattr(service, "pair", fake_pair)
    monkeypatch.setattr(service, "converge_node", fake_converge)

    view = asyncio.run(service.reconnect(rt, node_id))

    assert view.status == "connected"
    # the fingerprint is the one the node published, and the id is cross-checked
    assert calls["fingerprint"] == "a" * 64
    assert calls["hint"] == "node-abc"
    # a node that just came up is configured and started, not left half-done
    assert converged == [node_id]


def test_reconnect_reports_a_node_that_is_not_waiting_for_a_token(env_runtime,
                                                                  monkeypatch):
    from app.nodes import service
    from app.nodes.client import NodeClientError

    rt = env_runtime
    node_id = _node(rt, "rr_spent", status="pending", paired=False)

    async def fake_discover(runtime, nid):
        return service.Discovery(reachable=True, node_id="node-abc",
                                 certificate_sha256="b" * 64,
                                 pending_token=False, registered=True)

    monkeypatch.setattr(service, "discover", fake_discover)

    with pytest.raises(NodeClientError) as excinfo:
        asyncio.run(service.reconnect(rt, node_id))

    assert "installer" in str(excinfo.value).lower()
    assert "installer" in (_row(rt, node_id).last_error or "").lower()


def test_reconnect_names_a_reinstalled_agent(env_runtime, monkeypatch):
    """A node the panel still holds credentials for, whose agent has since been
    reinstalled, must not be told to "re-run the installer" as if the old token
    would work — it is spent, and the node has no token of its own any more."""
    from app.nodes import service
    from app.nodes.client import NodeClientError

    rt = env_runtime
    node_id = _node(rt, "rr_reinstalled", status="error", paired=True)

    async def fake_discover(runtime, nid):
        return service.Discovery(reachable=True, node_id="node-NEW",
                                 certificate_sha256="c" * 64,
                                 pending_token=False, registered=False)

    monkeypatch.setattr(service, "discover", fake_discover)

    with pytest.raises(NodeClientError) as excinfo:
        asyncio.run(service.reconnect(rt, node_id))

    text = str(excinfo.value).lower()
    assert "rotate" in text and "installer" in text
    assert "rotate" in (_row(rt, node_id).last_error or "").lower()
    # the pairing is reported as broken, but it is kept — an unreachable node is
    # not a node to forget
    assert _row(rt, node_id).agent_credentials_enc is not None


def test_reconnect_reports_an_unreachable_node(env_runtime, monkeypatch):
    from app.nodes import service
    from app.nodes.client import NodeClientError

    rt = env_runtime
    node_id = _node(rt, "rr_down", status="pending", paired=False)

    async def fake_discover(runtime, nid):
        return service.Discovery(reachable=False, error="connection refused")

    monkeypatch.setattr(service, "discover", fake_discover)

    with pytest.raises(NodeClientError):
        asyncio.run(service.reconnect(rt, node_id))
    assert "connection refused" in (_row(rt, node_id).last_error or "")


def test_a_token_rotated_before_the_agent_was_reinstalled_still_pairs(
        env_runtime, monkeypatch):
    """The live bug: rotating the token stores it under the identity the panel
    knew *then*. Re-installing the agent changes that identity, and pairing
    must not refuse to find its own token because of it."""
    from app.nodes import service

    rt = env_runtime
    token = "tok-0123456789abcdefghij"
    node_id = _node(
        rt, "rr_identity_drift", status="error", paired=True,
        registration_token_hash=hashlib.sha256(token.encode()).hexdigest(),
        registration_token_enc=rt.cipher.encrypt_json(
            {"registration_token": token}, aad="node-token:node-abc"))

    sent: dict = {}

    class FakeRegistrationClient:
        def __init__(self, *args, **kwargs):
            pass

        def register(self, panel_id, offered):
            sent["token"] = offered
            return {"node_id": "node-reinstalled",
                    "signing_key": base64.b64encode(b"\x02" * 32).decode("ascii")}

    monkeypatch.setattr(service, "fetch_pinned_certificate",
                        lambda address, port, fingerprint: ("CERT", fingerprint))
    monkeypatch.setattr(service, "ZagrosNodeClient", FakeRegistrationClient)

    view = asyncio.run(service.pair(
        rt, node_id, certificate_fingerprint="d" * 64,
        node_id_hint="node-reinstalled"))

    assert sent["token"] == token          # the token was found, not "missing"
    assert view.status == "connected"
    assert view.pending is False


def test_reconnect_all_touches_every_native_node(env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    good = _node(rt, "rr_all_ok", status="connected")
    revived = _node(rt, "rr_all_revive", status="error", last_error="timeout")
    stuck = _node(rt, "rr_all_stuck", status="pending", paired=False)

    async def fake_reconnect(runtime, node_id):
        # Only the rows this test created are given a transport; everything
        # else would reach for a real socket.
        if node_id == stuck:
            raise RuntimeError("node is not waiting for a registration token")
        return await service_reconnect(runtime, node_id)

    service_reconnect = service.reconnect
    monkeypatch.setattr(service, "_client", lambda runtime, row: FakeClient())
    monkeypatch.setattr(service, "reconnect", fake_reconnect)
    monkeypatch.setattr(service, "native_nodes",
                        lambda runtime: [_row(runtime, good),
                                         _row(runtime, revived),
                                         _row(runtime, stuck)])

    report = asyncio.run(service.reconnect_all(rt))

    assert report["checked"] == 3
    assert good in [item["node_id"] for item in report["connected"]]
    # a node that had dropped to error is re-attached, not merely left alone
    assert revived in [item["node_id"] for item in report["paired"]]
    assert "rr_all_stuck" in report["failed"]


# --------------------------------------------------------------------------- #
# 3 — installing a core leaves it configured and running                        #
# --------------------------------------------------------------------------- #

def test_converge_starts_only_cores_the_master_also_runs(env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "rr_converge", status="connected")
    client = FakeClient(cores={"installed": {
        "wireguard": {"core_id": "wireguard", "state": "stopped"},
        "pptp": {"core_id": "pptp", "state": "stopped"},     # not on the master
        "openvpn": {"core_id": "openvpn", "state": "running"},  # already up
    }, "available": [], "preview": {}})
    monkeypatch.setattr(service, "_client", lambda runtime, row: client)
    monkeypatch.setattr(rt.core_manager, "list_cores", lambda: ["wireguard", "openvpn"])
    monkeypatch.setattr(service, "sync_node",
                        lambda runtime, nid, core_ids=None: service.SyncResult(
                            node_id=nid,
                            pushed=[{"core_id": "wireguard", "inbound_count": 1}]))

    report = asyncio.run(service.start_node_cores(rt, node_id))

    assert report["started"] == ["wireguard"]          # stopped + on the master
    assert any("pptp" in item for item in report["skipped"])
    assert ("openvpn", "start") not in client.actions  # already running


def test_installing_a_core_converges_it_immediately(env_runtime, monkeypatch):
    """The bug: 'install' produced a core that could not start until a manual
    sync. Installing must end with a configured, running core."""
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "rr_install", status="connected")
    client = FakeClient()
    monkeypatch.setattr(service, "_client", lambda runtime, row: client)
    monkeypatch.setattr(service, "heartbeat",
                        lambda runtime, nid: service._view(_row(runtime, nid)))

    seen: list = []

    async def fake_converge(runtime, nid, core_ids=None):
        seen.append((nid, tuple(core_ids or ())))

    monkeypatch.setattr(service, "converge_node", fake_converge)

    result = asyncio.run(service.core_lifecycle(
        rt, node_id, "wireguard", action="install"))

    assert seen == [(node_id, ("wireguard",))]
    assert "convergence" in result

    seen.clear()
    asyncio.run(service.core_lifecycle(rt, node_id, "wireguard", action="stop"))
    assert seen == []          # only install/update converge


# --------------------------------------------------------------------------- #
# 4 — pinning a core to a release                                              #
# --------------------------------------------------------------------------- #

def test_install_can_pin_a_release(env_runtime, monkeypatch):
    """Changing a core's version (up or down) is an install/update with a pin,
    not a new protocol: the agent already reads it from the driver settings."""
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "rr_pin", status="connected")
    client = FakeClient()
    monkeypatch.setattr(service, "_client", lambda runtime, row: client)
    monkeypatch.setattr(service, "heartbeat",
                        lambda runtime, nid: service._view(_row(runtime, nid)))

    asyncio.run(service.core_lifecycle(
        rt, node_id, "xray", action="update", version="v25.9.11",
        settings={"keep": True}))

    assert client.actions[-1] == ("xray", "update")
    assert client.sent_settings[-1] == {"keep": True, "release_version": "v25.9.11"}


def test_a_version_cannot_be_pinned_on_an_action_that_installs_nothing(
        env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "rr_pin_bad", status="connected")
    monkeypatch.setattr(service, "_client", lambda runtime, row: FakeClient())

    with pytest.raises(ValueError) as excinfo:
        asyncio.run(service.core_lifecycle(
            rt, node_id, "xray", action="start", version="v25.9.11"))
    assert "does not install anything" in str(excinfo.value)


def test_core_versions_lists_what_the_node_could_install(env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "rr_versions", status="connected")

    async def fake_releases(core_id, limit=10):
        return {"core": core_id, "repo": "XTLS/Xray-core",
                "releases": [{"tag": "v25.9.11", "prerelease": False}]}

    monkeypatch.setattr("app.cores.releases.recent_releases", fake_releases)

    payload = asyncio.run(service.core_versions(rt, node_id, "xray"))

    assert payload["node_id"] == node_id
    assert payload["releases"][0]["tag"] == "v25.9.11"

    # a core the OS installs has no list — say so plainly instead of showing
    # an empty picker
    async def raises(core_id, limit=10):
        from app.cores.releases import NoReleaseFeed

        raise NoReleaseFeed("core 'openvpn' is not GitHub-release managed")

    monkeypatch.setattr("app.cores.releases.recent_releases", raises)
    with pytest.raises(ValueError, match="not GitHub-release managed"):
        asyncio.run(service.core_versions(rt, node_id, "openvpn"))


# --------------------------------------------------------------------------- #
# 5 — the installer lives in zagros-scripts, at a ref that exists             #
# --------------------------------------------------------------------------- #

def test_installer_comes_from_the_scripts_repository(env_runtime, monkeypatch):
    """Installing a node must not depend on the agent repository being
    reachable: the script and the CLI live next to the panel's installer."""
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "rr_installer", status="pending", paired=False)
    monkeypatch.setattr(service, "_ref_cache", None)
    monkeypatch.setenv("ZAGROS_SCRIPTS_REF", "v1.2.3")

    command = service._installer_command(_row(rt, node_id), "tok").command

    assert "zagros-scripts/v1.2.3/install-node.sh" in command
    assert "zagros-node/main/scripts/install.sh" not in command


def test_installer_prefers_a_matching_tag_else_main(env_runtime, monkeypatch):
    """A released panel hands out the installer that shipped with it; a build
    nobody has tagged yet must still hand out one that downloads."""
    from app.nodes import service

    monkeypatch.delenv("ZAGROS_SCRIPTS_REF", raising=False)
    monkeypatch.setattr("app.__version__", "9.9.9")

    monkeypatch.setattr(service, "_ref_cache", None)
    monkeypatch.setattr(service, "_scripts_ref_exists",
                        lambda ref, timeout=4.0: ref == "v9.9.9")
    assert service.installer_scripts_ref() == "v9.9.9"

    monkeypatch.setattr(service, "_ref_cache", None)
    monkeypatch.setattr(service, "_scripts_ref_exists",
                        lambda ref, timeout=4.0: False)
    assert service.installer_scripts_ref() == "main"

    # an explicit override always wins, even over a tag that exists
    monkeypatch.setenv("ZAGROS_SCRIPTS_REF", "hotfix")
    assert service.installer_scripts_ref() == "hotfix"
