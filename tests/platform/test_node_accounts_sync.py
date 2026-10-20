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
        self.materials: list[dict[str, str]] = []

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

    def apply_inbounds(self, core_id, document, *, material=None):
        self._guard("apply_inbounds")
        self.documents.append((core_id, document))
        self.materials.append(dict(material or {}))
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
            add_as_new_host=extra.pop("add_as_new_host", True),
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


# --------------------------------------------------------------------------- #
# f-nodetoken-1 / node-host regression (installer report item 2 + 3)
# --------------------------------------------------------------------------- #

def test_sync_registers_the_node_address_as_host(env_runtime, monkeypatch):
    """'add as new host' must create core_hosts rows for the node address.

    Installer report: every sync answered "hosts": [] and no rows appeared.
    The host-add path itself was verified to work; this test locks the full
    sync -> SQL store behaviour so a regression cannot hide again.
    """
    from app.nodes import service as service_mod

    clients: dict[int, FakeClient] = {}
    svc = _install(env_runtime, monkeypatch, clients,
                   cores=("wireguard",),
                   cores_payload={"installed": {
                       "wireguard": {"state": "running", "core_version": "v1"}}})
    node_id = _node(env_runtime, "host-node", add_as_new_host=True)
    # identity federation needs a live master driver — out of scope here
    async def _no_identity(rt, client, core_id, result):
        return None
    monkeypatch.setattr(svc, "_push_identity", _no_identity)
    # a studio document with one inbound tag drives the host registration
    class DocStore:
        async def get_document(self, core_id):
            return {"inbounds": [{"tag": "wg-inbound-1"}]}
    monkeypatch.setattr(env_runtime, "studio_store", DocStore(), raising=False)

    result = asyncio.run(svc.sync_node(env_runtime, node_id))
    assert result.errors == [], result.errors
    assert f"wireguard:wg-inbound-1" in (result.hosts or []), result

    async def _rows():
        return await env_runtime.core_hosts.list_grouped("wireguard")
    grouped = asyncio.run(_rows())
    entries = grouped.get("wg-inbound-1") or []
    assert any(e.address == "198.51.100.7" for e in entries), grouped

    # idempotent: a second sync must not duplicate the host
    result2 = asyncio.run(svc.sync_node(env_runtime, node_id))
    assert result2.hosts == [], result2.hosts
    grouped2 = asyncio.run(_rows())
    assert len(grouped2.get("wg-inbound-1") or []) == 1


def test_sync_explains_when_add_as_host_is_off(env_runtime, monkeypatch):
    """f-nodehosts-1: an empty hosts list must say WHY (installer report:
    "hosts": [] with no clue). With the option off, the result carries a
    note instead of a silent no-op."""
    from app.nodes import service as service_mod

    clients: dict[int, FakeClient] = {}
    svc = _install(env_runtime, monkeypatch, clients,
                   cores=("wireguard",),
                   cores_payload={"installed": {
                       "wireguard": {"state": "running", "core_version": "v1"}}})
    node_id = _node(env_runtime, "nohost-node", add_as_new_host=False)

    async def _no_identity(rt, client, core_id, result):
        return None
    monkeypatch.setattr(svc, "_push_identity", _no_identity)

    result = asyncio.run(svc.sync_node(env_runtime, node_id))
    assert result.hosts == []
    assert any("add-as-new-host" in n for n in result.notes), result.notes


def test_paired_node_installer_command_hides_the_consumed_token(env_runtime):
    """The dialog promises the token is sealed only until pairing completes.

    A connected node's installer command used to hand the (consumed) token
    back — and the dashboard rendered it. Now a paired node gets the command
    shape without any token material.
    """
    import base64 as _b64

    node_id = _node(env_runtime, "token-node")
    # give the row a sealed token so the old code had something to leak
    from app.persistence.models import NodeModel

    token = "one-time-token-abcdef"
    with env_runtime.session_factory() as session:
        row = session.get(NodeModel, node_id)
        row.registration_token_hash = __import__("hashlib").sha256(
            token.encode()).hexdigest()
        row.registration_token_enc = env_runtime.cipher.encrypt_json(
            {"token": token}, aad=f"node-agent:node-abc")
        session.commit()

    from app.nodes import service as node_service
    command = asyncio.run(node_service.installer_command(env_runtime, node_id))
    assert command.registration_token is None, \
        "a paired node must not hand back its consumed token"
    assert token not in command.command


