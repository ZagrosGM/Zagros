"""α7.1 studio flow tests: the wizard→real-listener root fixes.

Covers the six defects filed against alpha.7 Studio/User management:

* studio service cardinality (single-listener engines REPLACE, agents append)
* platform boot hydration (persisted doc re-applied — the "wizard listener
  vanishes after a panel restart" report)
* routers CoreError→422 mapping (the "request failed (500)" report)
* xray driver strict translator (protocol/transport/security gates, verified
  live against Xray 26.3.27 in the matrix probe)
* xray backend apply bridge + live catalog reload (the "new inbound does not
  appear in user-creation catalog" report — item 6)
* blueprint matrix shape (browser form contract) and banned-string hygiene
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
import sys
import types
from pathlib import Path

import pytest

# Pre-import the legacy xray facade BEFORE any test patches config.XRAY_JSON:
# importing app.xray runs module-level `XRayConfig(XRAY_JSON, ...)`; if a
# monkeypatch landed first it would point at a tmp file and the package init
# would crash (the exact ordering hazard the backend's lazy import hides).
import app.xray  # noqa: F401

from app.cores.exceptions import CoreError
from app.studio.service import ConfigStudioService, InboundSpec
from app.studio.jsonpatch import PatchOperation


# --------------------------------------------------------------------- #
# service: wizard_add_inbound cardinality
# --------------------------------------------------------------------- #

class _MD:  # minimal metadata, DELIBERATELY without studio_max_inbounds
    id = "fake"
    studio_inbounds_path = "/inbounds"
    config_schema = None
    protocols = ("vless",)


class _FakeDriver:
    """Doc-bearing fake: the store returns THIS doc (like SQLStudioStore)."""

    def __init__(self, doc):
        self.metadata = _MD()
        self.doc = doc

    def export_config_document(self):
        return self.doc


def _svc(driver):
    class _Store:  # in-memory StudioStore port stand-in
        async def get_document(self, core_id):
            return driver.doc if driver.doc else None

        async def save_document(self, core_id, doc):
            driver.doc = doc
            return doc

    return ConfigStudioService(_Store())


def _spec(tag="wiz-1"):
    return InboundSpec(
        tag=tag, listen="0.0.0.0", port=1443, protocol="vless",
        settings={"transport": "tcp", "security": "none"},
    )


def test_wizard_replace_for_single_listener_core():
    driver = _FakeDriver({"inbounds": [{"tag": "old", "port": 1}]})
    # declare the single-listener contract the OS drivers use
    driver.metadata.studio_max_inbounds = 1
    svc = _svc(driver)
    asyncio.run(svc.wizard_add_inbound(driver, _spec()))
    # exactly ONE listener remains, and it is the wizard's
    assert [ib["tag"] for ib in driver.doc["inbounds"]] == ["wiz-1"]
    assert driver.doc["inbounds"][0]["transport"] == "tcp"


def test_wizard_appends_when_cardinality_unlimited():
    driver = _FakeDriver({"inbounds": [{"tag": "old", "port": 1}]})
    driver.metadata.studio_max_inbounds = None
    svc = _svc(driver)
    asyncio.run(svc.wizard_add_inbound(driver, _spec()))
    assert [ib["tag"] for ib in driver.doc["inbounds"]] == ["old", "wiz-1"]


def test_wizard_missing_metadata_attribute_means_unlimited():
    # third-party drivers predate the field — getattr posture, no AttributeError
    driver = _FakeDriver({"inbounds": [{"tag": "old", "port": 1}]})
    assert not hasattr(driver.metadata, "studio_max_inbounds")
    svc = _svc(driver)
    asyncio.run(svc.wizard_add_inbound(driver, _spec()))
    assert [ib["tag"] for ib in driver.doc["inbounds"]] == ["old", "wiz-1"]


def test_wizard_seeds_missing_parent_list():
    driver = _FakeDriver({})  # fresh store — no 'inbounds' key at all
    svc = _svc(driver)
    asyncio.run(svc.wizard_add_inbound(driver, _spec()))
    assert driver.doc["inbounds"][0]["tag"] == "wiz-1"


# --------------------------------------------------------------------- #
# platform hydration: persisted doc re-applied before cores start
# --------------------------------------------------------------------- #

class _HydratableDriver:
    def __init__(self, fail=False):
        self.received: list[dict] = []
        self.fail = fail

    async def apply_studio_document(self, doc):
        if self.fail:
            raise CoreError("stale field from an older engine")
        self.received.append(doc)


class _HydrationRuntime:
    """Duck-typed stand-in: PlatformRuntime._hydrate_studio_documents only
    touches core_manager + studio_store."""

    def __init__(self, cores, docs):
        self.core_manager = types.SimpleNamespace(
            list_cores=lambda: list(cores),
            get=lambda cid: cores[cid],
        )
        self.studio_store = types.SimpleNamespace(
            get_document=None,
        )
        docs_ = docs

        async def _get(core_id):
            return docs_.get(core_id)

        self.studio_store.get_document = _get


class _HydrationSUT:  # bind the unbound method from the real class
    ...


def _bind_hydration(runtime):
    from app.platform.runtime import PlatformRuntime

    return PlatformRuntime._hydrate_studio_documents.__get__(
        runtime, type(runtime))


def test_hydration_reapplies_persisted_documents(caplog):
    good, broken = _HydratableDriver(), _HydratableDriver(fail=True)
    runtime = _HydrationRuntime(
        {"singbox": good, "openvpn": broken},
        {"singbox": {"inbounds": [{"tag": "a"}]},
         "openvpn": {"inbounds": [{"tag": "b"}]}},
    )
    with caplog.at_level(logging.ERROR):
        asyncio.run(_bind_hydration(runtime)())
    assert good.received == [{"inbounds": [{"tag": "a"}]}]
    # a stale document is logged loudly and NEVER aborts boot
    assert "openvpn" in caplog.text and "no longer applies" in caplog.text


def test_hydration_skips_cores_without_documents():
    good = _HydratableDriver()
    runtime = _HydrationRuntime({"singbox": good}, {})
    asyncio.run(_bind_hydration(runtime)())
    assert good.received == []


# --------------------------------------------------------------------- #
# routers: CoreError → 422 (was the opaque 500)
# --------------------------------------------------------------------- #

def test_materialize_studio_maps_core_error_to_422():
    from fastapi import HTTPException

    from app.platform.routers import _materialize_studio

    class _RejectDriver:
        async def apply_studio_document(self, doc):
            raise CoreError("only ONE listener is supported")

    runtime = types.SimpleNamespace(
        studio_store=types.SimpleNamespace(
            get_document=lambda cid: asyncio.sleep(0, result={"inbounds": []}),
        ),
    )
    with pytest.raises(HTTPException) as ei:
        asyncio.run(_materialize_studio(runtime, "tuic", _RejectDriver()))
    assert ei.value.status_code == 422
    assert "tuic:" in str(ei.value.detail)
    assert "ONE listener" in str(ei.value.detail)


def test_materialize_studio_no_hook_returns_notice():
    from app.platform.routers import _materialize_studio

    runtime = types.SimpleNamespace(
        studio_store=types.SimpleNamespace(
            get_document=lambda cid: asyncio.sleep(0, result={"inbounds": []}),
        ),
    )
    notice = asyncio.run(_materialize_studio(runtime, "legacy", object()))
    assert notice is not None and "next start" in notice


# --------------------------------------------------------------------- #
# xray driver: strict studio translator
# --------------------------------------------------------------------- #

from app.cores.drivers.xray.driver import XrayDriver


class _XrayBackendStub:
    def __init__(self):
        self.applied: list[dict] = []

    def apply_config_document(self, document):
        self.applied.append(document)


def _xray_driver(tmp_path) -> XrayDriver:
    d = XrayDriver(settings={"cert_dir": str(tmp_path / "certs")})
    d._backend = _XrayBackendStub()
    return d


def _apply_doc(driver: XrayDriver, inbounds):
    asyncio.run(driver.apply_studio_document({"inbounds": inbounds}))
    return driver._backend.applied[-1]


def test_xray_rejects_empty_inbound_set(tmp_path):
    d = _xray_driver(tmp_path)
    with pytest.raises(CoreError, match="at least ONE inbound"):
        asyncio.run(d.apply_studio_document({"inbounds": []}))
    assert d._backend.applied == []


def test_xray_rejects_duplicate_tags(tmp_path):
    d = _xray_driver(tmp_path)
    entry = {"tag": "dup", "protocol": "vless", "port": 1111,
             "transport": "tcp", "security": "none"}
    with pytest.raises(CoreError, match="unique"):
        asyncio.run(d.apply_studio_document({"inbounds": [entry, dict(entry)]}))
    assert d._backend.applied == []


def test_xray_rejects_unsupported_protocol_with_pointer(tmp_path):
    d = _xray_driver(tmp_path)
    with pytest.raises(CoreError) as ei:
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"tag": "wgd", "protocol": "wireguard", "port": 1111}]}))
    assert "OUTBOUND-only" in str(ei.value)


def test_xray_rejects_unknown_wizard_fields(tmp_path):
    d = _xray_driver(tmp_path)
    with pytest.raises(CoreError) as ei:
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"tag": "x1", "protocol": "vless", "port": 1111,
             "header_type": "http", "seed": "abc"}]}))  # removed mKCP levers
    assert "unknown" in str(ei.value).lower() or "not translatable" in str(ei.value)


def test_xray_rejects_removed_transports(tmp_path):
    d = _xray_driver(tmp_path)
    for transport in ("quic", "http"):
        with pytest.raises(CoreError, match="removed/not available"):
            asyncio.run(d.apply_studio_document({"inbounds": [
                {"tag": "x1", "protocol": "vless", "port": 1111,
                 "transport": transport}]}))


def test_xray_reality_gates(tmp_path):
    d = _xray_driver(tmp_path)
    # vmess + reality: wrong protocol
    with pytest.raises(CoreError, match="VLESS/Trojan over TCP/XHTTP/gRPC"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"tag": "r1", "protocol": "vmess", "port": 1443, "transport": "tcp",
             "security": "reality", "sni": "www.microsoft.com"}]}))
    # vless over ws + reality: wrong transport (binary: RAW/XHTTP/gRPC only)
    with pytest.raises(CoreError, match="VLESS/Trojan over TCP/XHTTP/gRPC"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"tag": "r2", "protocol": "vless", "port": 1443, "transport": "ws",
             "security": "reality", "sni": "www.microsoft.com"}]}))
    # vless+tcp+reality: PASS, keypair materialized, public key echoed back
    doc = _apply_doc(d, [{
        "tag": "rl", "protocol": "vless", "port": 1443, "transport": "tcp",
        "security": "reality", "sni": "www.microsoft.com"}])
    rs = doc["inbounds"][0]["streamSettings"]["realitySettings"]
    assert rs["dest"] == "www.microsoft.com:443"
    assert rs["serverNames"] == ["www.microsoft.com"]
    assert rs["privateKey"] and rs["publicKey"] and rs["shortIds"]


def test_xray_trojan_needs_tls(tmp_path):
    d = _xray_driver(tmp_path)
    with pytest.raises(CoreError, match="Trojan without TLS"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"tag": "tj", "protocol": "trojan", "port": 1443,
             "security": "none"}]}))


def test_xray_ss2022_points_at_singbox(tmp_path):
    d = _xray_driver(tmp_path)
    with pytest.raises(CoreError) as ei:
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"tag": "ss2", "protocol": "shadowsocks", "port": 8388,
             "method": "2022-blake3-aes-128-gcm"}]}))
    assert "sing-box" in str(ei.value)


def test_xray_tls_self_signed_materialization(tmp_path):
    d = _xray_driver(tmp_path)
    doc = _apply_doc(d, [{
        "tag": "tls-1", "protocol": "vless", "port": 1443, "transport": "ws",
        "security": "tls", "sni": "vpn.example.com", "path": "/w"}])
    ss = doc["inbounds"][0]["streamSettings"]
    assert ss["wsSettings"]["path"] == "/w"
    tls = ss["tlsSettings"]
    assert tls["serverName"] == "vpn.example.com"
    cert, key = tls["certificates"][0]["certificateFile"], tls["certificates"][0]["keyFile"]
    assert "BEGIN CERTIFICATE" in Path(cert).read_text()
    key_text = Path(key).read_text()
    assert "PRIVATE KEY" in key_text
    assert oct(Path(key).stat().st_mode & 0o777) == "0o600"
    # idempotent second apply: same files, no rewrite ripple
    mtime = Path(key).stat().st_mtime_ns
    _apply_doc(d, [{
        "tag": "tls-1", "protocol": "vless", "port": 1443, "transport": "ws",
        "security": "tls", "sni": "vpn.example.com"}])
    assert Path(key).stat().st_mtime_ns == mtime


def test_xray_tls_upload_pair_and_half_pair_guard(tmp_path):
    d = _xray_driver(tmp_path)
    with pytest.raises(CoreError, match="certificate AND private key"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"tag": "half", "protocol": "vless", "port": 1443, "security": "tls",
             "sni": "s.example.com", "certificate": "-----BEGIN CERTIFICATE-----"}]}))


def test_xray_native_entries_pass_through_untouched(tmp_path):
    d = _xray_driver(tmp_path)
    native = {"tag": "raw", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
              "settings": {"clients": [], "decryption": "none"},
              "streamSettings": {"network": "tcp", "security": "none"}}
    doc = _apply_doc(d, [native])
    assert doc["inbounds"][0] == native  # byte-identical, Advanced Mode intact


def test_xray_mkcp_renders_new_shape(tmp_path):
    d = _xray_driver(tmp_path)
    doc = _apply_doc(d, [{
        "tag": "kcp1", "protocol": "vless", "port": 9999, "transport": "mkcp",
        "security": "none", "mtu": 1200, "tti": 40, "congestion": True}])
    ss = doc["inbounds"][0]["streamSettings"]
    assert ss["network"] == "mkcp"
    assert ss["kcpSettings"] == {"mtu": 1200, "tti": 40, "congestion": True}


def test_xray_grpc_requires_service_name(tmp_path):
    d = _xray_driver(tmp_path)
    with pytest.raises(CoreError, match="service name"):
        asyncio.run(d.apply_studio_document({"inbounds": [
            {"tag": "g", "protocol": "vless", "port": 2053,
             "transport": "grpc"}]}))


# --------------------------------------------------------------------- #
# xray backend bridge: validate → persist → reload live catalog → restart
# --------------------------------------------------------------------- #

def _valid_doc(pn=12345):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "wiz-ws", "listen": "0.0.0.0", "port": pn, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {"network": "ws", "security": "none",
                               "wsSettings": {"path": "/t"}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                         "routeOnly": True},
        }],
        "outbounds": [{"protocol": "freedom", "tag": "DIRECT"},
                      {"protocol": "blackhole", "tag": "BLOCK"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": []},
    }


class _FakeXrayModule:
    """Stands in for the legacy `app.xray` facade (mod boundary)."""

    def __init__(self):
        self.api_host, self.api_port = "127.0.0.1", 8080

        class _Cfg(dict):
            def include_db_users(self):
                return {"merged": True}

        self.config = _Cfg({"inbounds": []})
        self.config.inbounds = []
        self.config.inbounds_by_protocol = {}
        self.config.inbounds_by_tag = {}
        self.config._fallbacks_inbound = []

        class _Core:
            started = True
            restarts: list = []

            def restart(self, config):
                self.restarts.append(config)

        self.core = _Core()

        class _Hosts(dict):
            cleared = False

            def clear(self):
                self.cleared = True
                super().clear()

        self.hosts = _Hosts()


def _backend_with_mod():
    from app.cores.drivers.xray.backend import LegacyXrayBackend

    b = LegacyXrayBackend({})
    b._mod = _FakeXrayModule()
    return b


def test_apply_config_document_reloads_live_catalog_identity(tmp_path, monkeypatch):
    import config as _host_cfg

    target = tmp_path / "xray_config.json"
    monkeypatch.setattr(_host_cfg, "XRAY_JSON", str(target), raising=False)
    b = _backend_with_mod()
    live = b._mod.config           # the singleton routers hold a reference to
    b.apply_config_document(_valid_doc())

    # 1) identity kept (object never swapped) but catalog reloaded
    assert b._mod.config is live
    assert "vless" in b._mod.config.inbounds_by_protocol
    tags = [ib["tag"] for ib in b._mod.config.inbounds_by_protocol["vless"]]
    assert "wiz-ws" in tags
    # 2) clean document persisted (no injected API inbound leaking to disk)
    on_disk = json.loads(target.read_text())
    assert [ib["tag"] for ib in on_disk["inbounds"]] == ["wiz-ws"]
    # 3) hosts storage invalidated, running core restarted with merged users
    assert b._mod.hosts.cleared
    assert b._mod.core.restarts == [{"merged": True}]


def test_apply_config_document_invalid_doc_touches_nothing(tmp_path, monkeypatch):
    import config as _host_cfg

    monkeypatch.setattr(_host_cfg, "XRAY_JSON", str(tmp_path / "xray_config.json"),
                        raising=False)
    b = _backend_with_mod()
    bad = _valid_doc()
    bad["outbounds"] = []                       # legacy validation rejects it
    with pytest.raises(CoreError, match="nothing was applied"):
        b.apply_config_document(bad)
    assert not (tmp_path / "xray_config.json").exists()
    assert b._mod.core.restarts == []
    assert b._mod.hosts.cleared is False
    assert b._mod.config.inbounds_by_protocol == {}


# --------------------------------------------------------------------- #
# blueprint shapes + banned strings
# --------------------------------------------------------------------- #

from app.studio.wizard import blueprint_for


def _walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def test_every_core_has_a_blueprint():
    for core in ("xray", "singbox", "hysteria2", "tuic", "openvpn",
                 "wireguard", "ssh", "softether"):
        bp = blueprint_for(core)
        assert bp and bp["core_id"] == core and bp["protocols"], core


def test_xray_blueprint_matrix():
    bp = blueprint_for("xray")
    protos = {p["id"]: p for p in bp["protocols"]}
    assert set(protos) == {"vless", "vmess", "trojan", "shadowsocks",
                           "socks", "http", "dokodemo-door"}
    # reality only on vless/trojan and only on tcp/xhttp/grpc
    for name, proto in protos.items():
        for tr in proto["transports"]:
            secs = {s["id"] for s in tr["securities"]}
            if "reality" in secs:
                assert name in ("vless", "trojan"), (name, tr["id"])
                assert tr["id"] in ("tcp", "xhttp", "grpc"), (name, tr["id"])
    # trojan never offers security none
    for tr in protos["trojan"]["transports"]:
        assert all(s["id"] != "none" for s in tr["securities"])
    # shadowsocks classic ciphers only (ss-2022 lives on the sing-box core)
    ss_fields = [f for tr_ in protos["shadowsocks"]["transports"]
                 for s_ in tr_["securities"] for f in s_["fields"]
                 if f["key"] == "method"]
    for f in ss_fields:
        assert not any(o.startswith("2022-") for o in f["options"])
    # no removed transports anywhere in the matrix
    for proto in protos.values():
        for tr in proto["transports"]:
            assert tr["id"] in ("tcp", "ws", "httpupgrade", "grpc", "xhttp", "mkcp")


def test_singbox_and_os_blueprints_shape():
    sb = blueprint_for("singbox")
    protos = {p["id"]: p for p in sb["protocols"]}
    for needed in ("vless", "vmess", "trojan", "shadowsocks", "socks", "http",
                   "mixed", "naive", "anytls", "hysteria2", "tuic"):
        assert needed in protos, needed
    # socks/mixed carry no TLS; naive forced over TLS (pinned against binary)
    for name in ("socks", "mixed"):
        for tr in protos[name]["transports"]:
            assert all(s["id"] != "tls" for s in tr["securities"]), name
    assert any(s["id"] == "tls" for s in protos["naive"]["transports"][0]["securities"])

    wg = blueprint_for("wireguard")
    keys = {f["key"] for n in _walk(wg["protocols"]) if "key" in n for f in [n]}
    for k in ("listen", "private_key", "public_key", "mtu", "dns", "endpoint",
              "allowed_ips", "persistent_keepalive", "preshared_keys", "address"):
        assert k in keys, k

    ovpn = blueprint_for("openvpn")
    keys = {f["key"] for n in _walk(ovpn["protocols"]) if "key" in n for f in [n]}
    for k in ("topology", "cipher", "cipher_fallback", "auth", "compression",
              "ca_certificate", "certificate", "certificate_key",
              "username", "password", "extra_directives", "auth_mode"):
        assert k in keys, k

    ssh = blueprint_for("ssh")
    keys = {f["key"] for n in _walk(ssh["protocols"]) if "key" in n for f in [n]}
    for k in ("banner", "authentication", "password", "public_key", "shell",
              "sftp", "max_sessions"):
        assert k in keys, k


def test_no_banned_user_facing_strings():
    """Wizard must never punt operators at Advanced Mode or opaque 500s."""
    import re

    repo = Path(__file__).resolve().parents[2]
    banned = (
        re.compile(r"use Advanced Mode", re.I),
        re.compile(r"no dynamic wizard blueprint", re.I),
        re.compile(r"request failed \(500\)", re.I),
    )
    for base in (repo / "app",):
        for path in base.rglob("*"):
            if path.suffix not in {".py", ".tsx", ".ts"}:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern in banned:
                assert not pattern.search(text), f"{pattern.pattern} in {path}"
