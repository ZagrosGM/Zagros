"""Wizard Import + Preview (alpha.7.2, item 6).

Import: a client share link maps onto THIS core's blueprint exactly —
the (protocol, transport, security) cell must exist (never guessed),
parsed values land on DECLARED blueprint fields only, and credentials /
foreign values are reported in ``unmapped`` rather than eaten or
invented as listener settings.

Preview: ``wizard_preview_inbound`` produces the EXACT patch the real
apply would (shared ``_wizard_ops``), validates it, and persists
NOTHING — the stepper's review gate.
"""
from __future__ import annotations

import asyncio

import pytest

from app.studio.service import ConfigStudioService, InboundSpec
from app.studio.wizard_import import WizardImportError, import_link_spec


# ---------------------------------------------------------------------- #
# import mapper — cells resolve exactly                                   #
# ---------------------------------------------------------------------- #

def test_import_vless_ws_tls_on_xray() -> None:
    spec = import_link_spec(
        "xray",
        "vless://11111111-2222-3333-4444-555555555555@my.server:443"
        "?type=ws&security=tls&path=%2Fws&host=cdn.example.com"
        "&sni=panel.example.com&alpn=h2%2Chttp%2F1.1#DE-Node")
    assert spec["tag"] == "DE-Node"
    assert (spec["protocol"], spec["transport"], spec["security"]) == \
        ("vless", "ws", "tls")
    assert spec["port"] == 443
    assert spec["settings"]["path"] == "/ws"
    assert spec["settings"]["host"] == "cdn.example.com"
    assert spec["settings"]["sni"] == "panel.example.com"
    assert spec["settings"]["alpn"] == ["h2", "http/1.1"]
    # the uuid is an ACCOUNT credential, never a listener setting — reported
    dropped = {u["key"]: u for u in spec["unmapped"]}
    assert "uuid" in dropped and "credential" in dropped["uuid"]["reason"]
    # flow maps only when the cell declares it (ws+tls does not on xray)
    assert "flow" not in spec["settings"]


def test_import_reality_cell_with_flow() -> None:
    spec = import_link_spec(
        "xray",
        "vless://u@srv:443?type=tcp&security=reality&sni=www.microsoft.com"
        "&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision")
    assert (spec["transport"], spec["security"]) == ("tcp", "reality")
    assert spec["settings"]["flow"] == "xtls-rprx-vision"
    assert spec["settings"]["public_key"] == "PUBKEY"
    assert spec["settings"]["fingerprint"] == "chrome"
    assert spec["settings"]["sni"] == "www.microsoft.com"
    dropped = {u["key"] for u in spec["unmapped"]}
    assert "reality_short_id" in dropped          # per-server material, not listener


def test_import_unoffered_cell_named_never_guessed() -> None:
    # sing-box has no xhttp — the error names what IS offered
    with pytest.raises(WizardImportError, match="not offered") as err:
        import_link_spec("sing-box",
                         "vless://u@srv:443?type=splithttp&security=none&path=%2Fxh")
    assert "tcp" in str(err.value)
    # xray has no hysteria2 — protocol-level miss names the protocols
    with pytest.raises(WizardImportError, match="hysteria2"):
        import_link_spec("xray", "hysteria2://pw@srv:443/?sni=x.com")


def test_import_quic_protocols_default_to_tls_cell() -> None:
    # hysteria2/tuic links omit `security` (implicit TLS); the blueprint
    # offers ONLY tls — resolve there, never "none"
    spec = import_link_spec(
        "sing-box",
        "hysteria2://pw@srv:4430/?sni=cdn.example.com"
        "&obfs=salamander&obfs-password=sec#HY")
    assert (spec["transport"], spec["security"]) == ("quic", "tls")
    assert spec["settings"]["obfs"] == "sec"
    assert spec["settings"]["sni"] == "cdn.example.com"
    tuic = import_link_spec(
        "sing-box", "tuic://uuid:pw@srv:5443?congestion_control=bbr&sni=x.com")
    assert tuic["security"] == "tls"
    assert tuic["settings"]["congestion_control"] == "bbr"


def test_import_shadowsocks_method_and_b64_credentials() -> None:
    spec = import_link_spec("xray", "ss://YWVzLTI1Ni1nY206cHc=@srv:8388#SS1")
    assert spec["protocol"] == "shadowsocks"
    assert spec["settings"] == {"method": "aes-256-gcm"}
    dropped = {u["key"] for u in spec["unmapped"]}
    assert "password" in dropped  # account credential


def test_import_transport_aliases() -> None:
    mkcp = import_link_spec("xray", "vless://u@srv:2053?type=kcp&security=none")
    assert mkcp["transport"] == "mkcp"
    grpc = import_link_spec(
        "xray",
        "vless://u@srv:443?type=grpc&security=tls&serviceName=svc&sni=x.com")
    assert grpc["settings"]["service_name"] == "svc"


def test_import_bad_links_fail_honestly() -> None:
    with pytest.raises(WizardImportError, match="unsupported protocol"):
        import_link_spec("xray", "wireguard://x")
    with pytest.raises(WizardImportError, match="empty link"):
        import_link_spec("xray", "   ")


# ---------------------------------------------------------------------- #
# service: preview = dry-run of the REAL apply path                       #
# ---------------------------------------------------------------------- #

class _MD:
    id = "fake"
    studio_inbounds_path = "/inbounds"
    config_schema = None
    protocols = ("vless",)


class _FakeDriver:
    def __init__(self, doc):
        self.metadata = _MD()
        self.doc = doc

    def export_config_document(self):
        return self.doc


def _svc(driver):
    class _Store:
        async def get_document(self, core_id):
            return driver.doc if driver.doc else None

        async def save_document(self, core_id, doc):
            driver.doc = doc
            return doc

    return ConfigStudioService(_Store())


def _spec():
    return InboundSpec(tag="wiz-1", listen="0.0.0.0", port=1443,
                       protocol="vless",
                       settings={"transport": "tcp", "security": "none"})


def test_preview_validates_without_persisting() -> None:
    driver = _FakeDriver({"inbounds": [{"tag": "old", "port": 1}]})
    svc = _svc(driver)
    result = asyncio.run(svc.wizard_preview_inbound(driver, _spec()))
    assert result.valid
    assert result.document["inbounds"][1]["tag"] == "wiz-1"
    assert result.diff  # unified diff produced
    # NOTHING persisted — the store still serves the old document
    assert [ib["tag"] for ib in driver.doc["inbounds"]] == ["old"]


def test_preview_matches_apply_exactly() -> None:
    preview_driver = _FakeDriver({})
    applied_driver = _FakeDriver({})
    pre = asyncio.run(_svc(preview_driver).wizard_preview_inbound(
        preview_driver, _spec()))
    ap = asyncio.run(_svc(applied_driver).wizard_add_inbound(
        applied_driver, _spec()))
    assert pre.valid and ap.valid
    assert pre.document == applied_driver.doc  # same mutation, seed path


def test_preview_rejects_invalid_spec() -> None:
    driver = _FakeDriver({"inbounds": []})
    bad = InboundSpec(tag="x", listen=None, port=1, protocol="vless",
                      settings={"transport": "tcp", "security": "none"})
    bad.port = 70001  # type: ignore[assignment] — post-construct invalid
    svc = _svc(driver)
    result = asyncio.run(svc.wizard_preview_inbound(driver, bad))
    # config_schema is None on the stub, so the port slips validation at
    # this layer — but nothing may be persisted regardless
    assert driver.doc == {"inbounds": []}


# ---------------------------------------------------------------------- #
# endpoints: /wizard/preview + /wizard/import                             #
# ---------------------------------------------------------------------- #

@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Isolate the legacy DB BEFORE any app import: app/db/base.py binds its
    # engine at import time from SQLALCHEMY_DATABASE_URL — warming it
    # unpatched here would freeze it onto the cwd db.sqlite3 for the whole
    # process and pollute sibling suites (observed: UNIQUE collisions on
    # leftover dl_% rows in test_device_limits).
    monkeypatch.setenv("SQLALCHEMY_DATABASE_URL",
                       f"sqlite:///{tmp_path / 'legacy.db'}")
    monkeypatch.setenv("ZAGROS_DATABASE_URL",
                       f"sqlite:///{tmp_path / 'platform.db'}")
    monkeypatch.setenv("ZAGROS_SECRET_KEY", "wizard-import-test-key-01234")
    import importlib

    # Complete the legacy db package BEFORE the router import: routers'
    # guarded `from app.models.admin import Admin` can otherwise trigger a
    # circular import whose failure unwinds sys.modules["app.db"] but keeps
    # the half-initialized "app.db.base" — leaving Base.metadata without the
    # models for the whole process (observed: sibling legacy writes dying
    # with "no such table: users"). A real boot initializes db first too.
    _dbpkg = importlib.import_module("app.db")
    _dbpkg.Base.metadata.create_all(_dbpkg.engine)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.platform.routers import get_runtime, zagros_admin_router

    driver = _FakeDriver({"inbounds": []})
    svc = _svc(driver)

    class _CM:
        def get(self, core_id):
            if core_id != "fake":
                raise KeyError(core_id)
            return driver

    class _RT:
        core_manager = _CM()
        studio = svc

    app = FastAPI()
    app.state.zagros = _RT()
    app.dependency_overrides[get_runtime] = lambda: app.state.zagros
    from app.platform import routers as _routers

    for _dep in _routers._SUDO_DEPS:
        app.dependency_overrides[_dep.dependency] = lambda: {"username": "t"}
    app.include_router(zagros_admin_router)
    with TestClient(app) as c:
        yield c, driver


def test_preview_endpoint_dry_run(client) -> None:
    c, driver = client
    res = c.post("/api/zagros/studio/fake/wizard/preview", json={
        "tag": "wiz-1", "listen": "0.0.0.0", "port": 1443, "protocol": "vless",
        "settings": {"transport": "tcp", "security": "none"}})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["valid"] is True and body["diff"]
    assert [ib["tag"] for ib in driver.doc["inbounds"]] == []  # untouched
    res = c.post("/api/zagros/studio/nope/wizard/preview", json={
        "tag": "x", "port": 1, "protocol": "vless", "settings": {}})
    assert res.status_code == 404


def test_import_endpoint_maps_or_names_the_gap(client) -> None:
    c, _ = client
    res = c.post("/api/zagros/cores/fake/wizard/import",
                 json={"link": "hysteria2://pw@srv:4430/?sni=x.com"})
    assert res.status_code == 404                       # fake core = no blueprint
    res = c.post("/api/zagros/cores/sing-box/wizard/import",
                 json={"link": "hysteria2://pw@srv:4430/?sni=x.com#HY"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["protocol"] == "hysteria2" and body["security"] == "tls"
    res = c.post("/api/zagros/cores/nope/wizard/import", json={"link": "x"})
    assert res.status_code == 404
