"""Host Settings admin API (alpha.7.2, item 13) — /api/zagros/cores/{id}/hosts.

Contracts under test: 404 on unknown cores AND unknown inbound tags
(validated against the LIVE catalog, not a guess), bulk-PUT
partial-replace semantics, validation (port / security), and that the
entries the API stores are the entries the engine consumes. App imports
stay inside the fixture (platform-test convention — module-level app
imports trip the legacy circular-import safety on some orders).
"""
from __future__ import annotations

import pytest

FAKE_ID = "hostapi-wg"


@pytest.fixture()
def client(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.persistence.repositories import InMemoryCoreHostStore
    from app.platform import admin_api  # noqa: F401 — registers endpoints
    from app.platform.routers import get_runtime, zagros_admin_router

    class _RuntimeStub:
        def __init__(self):
            self.core_hosts = InMemoryCoreHostStore()

    rt = _RuntimeStub()

    async def fake_known_catalog(runtime):
        from app.platform.inbounds import CatalogGroup, CatalogInbound

        group = CatalogGroup(core_id=FAKE_ID, name="Fake WG", enabled=True,
                             inbounds=[CatalogInbound(tag="wg-main",
                                                      protocol="wireguard",
                                                      port=51820)])
        return {FAKE_ID: group}
    monkeypatch.setattr(admin_api, "_known_catalog", fake_known_catalog)

    app = FastAPI()
    app.state.zagros = rt
    app.dependency_overrides[get_runtime] = lambda: rt
    # override the ACTUAL admin dependency callables — whichever branch
    # (legacy Admin stack / fail-closed fallback) the router resolved at
    # import time
    from app.platform import routers as _routers

    for _dep in _routers._SUDO_DEPS:
        app.dependency_overrides[_dep.dependency] = lambda: {"username": "t"}
    app.include_router(zagros_admin_router)
    with TestClient(app) as c:
        yield c, rt


def test_unknown_core_404(client):
    c, _ = client
    r = c.get("/api/zagros/cores/nope/hosts")
    assert r.status_code == 404


def test_get_empty_initially(client):
    c, _ = client
    r = c.get(f"/api/zagros/cores/{FAKE_ID}/hosts")
    assert r.status_code == 200 and r.json() == {}


def test_put_rejects_unknown_inbound_tag(client):
    c, _ = client
    r = c.put(f"/api/zagros/cores/{FAKE_ID}/hosts",
              json={"hosts": {"ghost-tag": [{"remark": "x", "address": "a.b"}]}})
    assert r.status_code == 404
    assert "ghost-tag" in str(r.json())


def test_put_roundtrip_and_partial_semantics(client):
    c, rt = client
    payload = {"hosts": {"wg-main": [
        {"remark": "DC1-{USERNAME}", "address": "dc1.example.com",
         "port": 51830, "security": "inbound_default"},
        {"remark": "off", "address": "off.example.com", "is_disabled": True},
    ]}}
    r = c.put(f"/api/zagros/cores/{FAKE_ID}/hosts", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    entries = body["wg-main"]
    assert [e["address"] for e in entries] == ["dc1.example.com", "off.example.com"]
    assert entries[1]["is_disabled"] is True

    got = c.get(f"/api/zagros/cores/{FAKE_ID}/hosts").json()
    assert got["wg-main"][0]["port"] == 51830

    # engine-level read: the store hands the portal the engine shape
    import asyncio

    from app.portal.hostengine import HostEntry
    grouped = asyncio.run(rt.core_hosts.list_grouped(FAKE_ID))
    assert isinstance(grouped["wg-main"][0], HostEntry)
    assert grouped["wg-main"][1].is_disabled is True

    # PUT of an unrelated tag-keyed payload does NOT wipe the first tag
    r = c.put(f"/api/zagros/cores/{FAKE_ID}/hosts", json={"hosts": {}})
    assert r.status_code == 200
    got = c.get(f"/api/zagros/cores/{FAKE_ID}/hosts").json()
    assert [e["address"] for e in got["wg-main"]] == \
        ["dc1.example.com", "off.example.com"]

    # explicit empty list DOES clear the tag
    r = c.put(f"/api/zagros/cores/{FAKE_ID}/hosts",
              json={"hosts": {"wg-main": []}})
    assert r.status_code == 200
    got = c.get(f"/api/zagros/cores/{FAKE_ID}/hosts").json()
    assert got.get("wg-main", []) == []


def test_put_validates_port_and_security(client):
    c, _ = client
    r = c.put(f"/api/zagros/cores/{FAKE_ID}/hosts",
              json={"hosts": {"wg-main": [{"address": "a.b", "port": 70000}]}})
    assert r.status_code == 422
    r = c.put(f"/api/zagros/cores/{FAKE_ID}/hosts",
              json={"hosts": {"wg-main": [{"address": "a.b", "security": "garbage"}]}})
    assert r.status_code == 422


def test_put_full_item13_field_set(client):
    c, _ = client
    entry = {"remark": "R", "address": "a.example.com", "port": 443,
             "sni": "a.example.com,b.example.com", "host": "h.example.com",
             "path": "/w", "security": "tls", "alpn": "h2,http/1.1",
             "fingerprint": "chrome", "allowinsecure": False,
             "is_disabled": False, "mux_enable": True,
             "fragment_setting": "10-20,10-20,tlshello",
             "noise_setting": "quic:80-90",
             "random_user_agent": True, "use_sni_as_host": True}
    r = c.put(f"/api/zagros/cores/{FAKE_ID}/hosts",
              json={"hosts": {"wg-main": [entry]}})
    assert r.status_code == 200, r.text
    got = c.get(f"/api/zagros/cores/{FAKE_ID}/hosts").json()["wg-main"][0]
    for key, value in entry.items():
        assert got[key] == value, f"field {key}: {got[key]!r} != {value!r}"
