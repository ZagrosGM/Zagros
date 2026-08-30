"""A user must reach the nodes without anyone asking for it.

The bug this pins: creating a user changed the panel and the master, and
nothing else. A node kept serving the account list it was given last — so the
new user's config, which points at the node, simply did not connect, while
every pre-existing user kept working. It read like a broken node and was a
missing push.

Node I/O is faked at the client boundary; the service logic (digest, skip,
push, isolation) runs untouched.
"""
from __future__ import annotations

import asyncio
import base64
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


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


@pytest.fixture(scope="module")
def env_runtime(tmp_path_factory):
    db = tmp_path_factory.mktemp("node-accounts") / "zagros.db"
    env = {
        **os.environ,
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db}",
        "ZAGROS_SECRET_KEY": "node-accounts-test-key-0123456789",
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


class FakeClient:
    """Records what the panel tried to hand the node."""

    def __init__(self, *, cores=None, fail=()):
        self.cores_payload = cores if cores is not None else {"installed": {
            "wireguard": {"state": "running", "core_version": "v1"}}}
        self.fail = set(fail)
        self.account_pushes: list[tuple[str, list[dict]]] = []
        self.documents: list[tuple[str, dict]] = []

    def _guard(self, what):
        if what in self.fail:
            raise RuntimeError(f"{what} refused")

    def cores(self):
        self._guard("cores")
        return self.cores_payload

    def apply_accounts(self, core_id, accounts):
        self._guard("apply_accounts")
        self.account_pushes.append((core_id, list(accounts)))
        return {"count": len(accounts)}

    def apply_inbounds(self, core_id, document):
        self._guard("apply_inbounds")
        self.documents.append((core_id, document))
        return {"inbound_count": len((document or {}).get("inbounds") or [])}


def _sealed_credentials(runtime, identity="node-abc"):
    return runtime.cipher.encrypt_json(
        {"signing_key": base64.b64encode(b"\x01" * 32).decode("ascii")},
        aad=f"node-agent:{identity}")


def _node(runtime, name, *, status="connected", paired=True, **extra):
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


def _install(runtime, monkeypatch, clients, *, accounts=(("wireguard", []),),
             cores=("wireguard",), cores_payload=None, failing=()):
    """Fake the node I/O: one client per node row, keyed by id.

    The runtime is module-scoped, so nodes created by an earlier test are
    still paired — every assertion here is about one node id, and the client
    registry keeps them apart.
    """
    from app.nodes import service

    def _make(row):
        key = int(row.id)
        if key not in clients:
            clients[key] = FakeClient(
                cores=cores_payload, fail={"cores"} if key in failing else ())
        return clients[key]

    table = dict(accounts)

    monkeypatch.setattr(service, "_client", lambda rt, row: _make(row))
    monkeypatch.setattr(runtime.core_manager, "list_cores", lambda: list(cores))
    monkeypatch.setattr(service, "_core_accounts",
                        lambda rt, core_id: (list(table.get(core_id))
                                             if core_id in table else None))
    return service


def _pushed_for(result, node_id):
    """The part of a fan-out report that concerns one node."""
    return [p for p in (result.get("pushed") or []) if p["node_id"] == node_id]


# --------------------------------------------------------------------------- #
# the push                                                                     #
# --------------------------------------------------------------------------- #

def test_a_new_user_reaches_the_node(env_runtime, monkeypatch):
    """Create a user, and the node is told about it — no sync button."""
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "acct_new")
    clients: dict = {}
    accounts = [{"user_id": 1, "username": "old", "account_id": "old",
                 "protocol": "wireguard", "enabled": True, "settings": {}},
                {"user_id": 2, "username": "new", "account_id": "new",
                 "protocol": "wireguard", "enabled": True, "settings": {}}]
    _install(rt, monkeypatch, clients, accounts={"wireguard": accounts})

    result = asyncio.run(service.fanout_accounts(rt))
    client = clients[node_id]

    assert [c for c, _ in client.account_pushes] == ["wireguard"]
    assert "new" in [a["username"] for _, pushed in client.account_pushes
                     for a in pushed]


def test_unchanged_accounts_are_not_pushed_again(env_runtime, monkeypatch):
    """The sweep runs every half minute: it must not re-send every time."""
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "acct_skip")
    clients: dict = {}
    accounts = [{"user_id": 1, "username": "steady", "account_id": "steady",
                 "protocol": "wireguard", "enabled": True, "settings": {}}]
    _install(rt, monkeypatch, clients, accounts={"wireguard": accounts})

    asyncio.run(service.fanout_accounts(rt))
    client = clients[node_id]
    assert len(client.account_pushes) == 1

    second = asyncio.run(service.fanout_accounts(rt))
    assert len(client.account_pushes) == 1          # nothing re-sent
    assert _pushed_for(second, node_id) == []       # and nothing claimed pushed

    # …but a change goes straight out
    accounts.append({"user_id": 2, "username": "fresh", "account_id": "fresh",
                     "protocol": "wireguard", "enabled": True, "settings": {}})
    asyncio.run(service.fanout_accounts(rt))
    assert len(client.account_pushes) == 2
    assert any(a["username"] == "fresh"
               for _, pushed in client.account_pushes for a in pushed)


def test_force_reasserts_what_a_node_already_has(env_runtime, monkeypatch):
    """An agent that restarted lost its state; the forced cycle covers it."""
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "acct_force")
    clients: dict = {}
    _install(rt, monkeypatch, clients, accounts={"wireguard": [
        {"user_id": 1, "username": "steady", "account_id": "steady",
         "protocol": "wireguard", "enabled": True, "settings": {}}]})

    asyncio.run(service.fanout_accounts(rt))
    asyncio.run(service.fanout_accounts(rt, force=True))

    assert len(clients[node_id].account_pushes) == 2


def test_xray_accounts_travel_inside_the_document(env_runtime, monkeypatch):
    """xray keeps its users in the config, so pushing them means re-applying it."""
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "acct_xray")
    clients: dict = {}
    document = {"inbounds": [{
        "tag": "Shadowsocks TCP", "protocol": "shadowsocks",
        "settings": {"clients": [{"password": "p", "method": "m"},
                                 {"password": "q", "method": "m"}]}}]}
    _install(rt, monkeypatch, clients, cores=("xray",), cores_payload={
        "installed": {"xray": {"state": "running", "core_version": "26.6.1"}}})
    monkeypatch.setattr(service, "_xray_document_with_accounts",
                        lambda: dict(document))

    result = asyncio.run(service.fanout_accounts(rt))
    client = clients[node_id]

    assert [c for c, _ in client.documents] == ["xray"]
    assert _pushed_for(result, node_id)[0]["pushed"][0]["accounts"] == 2


def test_an_unreadable_account_table_never_revokes_anyone(env_runtime, monkeypatch):
    """A read failure means 'unknown', not 'no users' — nobody gets cut off."""
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "acct_unknown")
    clients: dict = {}
    _install(rt, monkeypatch, clients, accounts={})   # unknown, not empty

    result = asyncio.run(service.fanout_accounts(rt))

    assert clients[node_id].account_pushes == []
    assert any("left untouched" in e for e in result["errors"])


def test_one_broken_node_does_not_stop_the_others(env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    good_id = _node(rt, "acct_good")
    bad_id = _node(rt, "acct_bad")
    clients: dict = {}
    _install(rt, monkeypatch, clients, failing=(bad_id,), accounts={
        "wireguard": [{"user_id": 1, "username": "u", "account_id": "u",
                       "protocol": "wireguard", "enabled": True,
                       "settings": {}}]})

    result = asyncio.run(service.fanout_accounts(rt))

    assert len(clients[good_id].account_pushes) == 1
    assert any(f"node {bad_id}" in e for e in result["errors"])


def test_an_unpaired_node_is_left_alone(env_runtime, monkeypatch):
    from app.nodes import service

    rt = env_runtime
    node_id = _node(rt, "acct_unpaired", paired=False)
    clients: dict = {}
    _install(rt, monkeypatch, clients, accounts={
        "wireguard": [{"user_id": 1, "username": "u", "account_id": "u",
                       "protocol": "wireguard", "enabled": True,
                       "settings": {}}]})

    result = asyncio.run(service.fanout_accounts(rt))

    assert _pushed_for(result, node_id) == []
    assert node_id not in clients
