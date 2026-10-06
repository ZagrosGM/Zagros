"""f-panel-9 — TLS/REALITY + transport actually reach the deployed config.

VLESS/VMess/Trojan outbounds used to render as bare address+port+credential
dicts: a TLS/REALITY upstream closed the raw connection and every routed
user lost internet. These tests pin the full mapping in BOTH runtimes
(Xray streamSettings, sing-box tls/transport) through the real driver
methods, not just the helpers.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "pydantic")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="panel requirements not installed")

if _HAS:
    from app.cores.drivers.singbox.driver import SingBoxDriver
    from app.cores.drivers.xray.driver import XrayDriver
    from app.cores.outbounds.model import Outbound, OutboundKind
    from app.cores.outbounds.stream_render import (
        singbox_tls_and_transport,
        xray_stream_settings,
    )


def _ob(kind: OutboundKind, settings: dict) -> Outbound:
    return Outbound(name="up-1", kind=kind, settings=settings)


_VLESS_TLS_WS = {
    "server": "up.example.com", "server_port": 443, "uuid": "u-1",
    "network": "ws", "path": "/wspath", "host": "cdn.example.com",
    "security": "tls", "sni": "sni.example.com",
    "alpn": "h2,http/1.1", "fingerprint": "chrome",
}
_VLESS_REALITY_TCP = {
    "server": "up.example.com", "server_port": 443, "uuid": "u-1",
    "flow": "xtls-rprx-vision",
    "security": "reality", "sni": "www.microsoft.com",
    "reality_public_key": "pb-key", "reality_short_id": "abcd",
    "fingerprint": "chrome",
}


class TestXrayRendering:
    def test_tls_ws_reaches_stream_settings(self):
        native, gap = XrayDriver._outbound_to_native(
            None, _ob(OutboundKind.VLESS, dict(_VLESS_TLS_WS)))
        assert gap is None
        stream = native["streamSettings"]
        assert stream["network"] == "ws"
        assert stream["wsSettings"] == {"path": "/wspath",
                                        "headers": {"Host": "cdn.example.com"}}
        assert stream["security"] == "tls"
        tls = stream["tlsSettings"]
        assert tls["serverName"] == "sni.example.com"
        assert tls["alpn"] == ["h2", "http/1.1"]
        assert tls["fingerprint"] == "chrome"

    def test_reality_reaches_stream_settings(self):
        native, _ = XrayDriver._outbound_to_native(
            None, _ob(OutboundKind.VLESS, dict(_VLESS_REALITY_TCP)))
        stream = native["streamSettings"]
        assert stream["security"] == "reality"
        reality = stream["realitySettings"]
        assert reality["serverName"] == "www.microsoft.com"
        assert reality["publicKey"] == "pb-key"
        assert reality["shortId"] == "abcd"
        assert reality["fingerprint"] == "chrome"

    def test_trojan_and_vmess_get_stream_too(self):
        trojan = dict(_VLESS_TLS_WS, password="p")
        trojan.pop("uuid")
        native, _ = XrayDriver._outbound_to_native(
            None, _ob(OutboundKind.TROJAN, trojan))
        assert native["streamSettings"]["security"] == "tls"
        native, _ = XrayDriver._outbound_to_native(
            None, _ob(OutboundKind.VMESS, dict(_VLESS_TLS_WS)))
        assert native["streamSettings"]["security"] == "tls"

    def test_grpc_service_name_and_multi(self):
        s = dict(_VLESS_TLS_WS, network="grpc", path=None, host=None,
                 serviceName="Svc", mode="multi")
        stream = xray_stream_settings(s)
        assert stream["grpcSettings"] == {"serviceName": "Svc",
                                          "multiMode": True}

    def test_splithttp_maps_to_xhttp(self):
        stream = xray_stream_settings(dict(
            _VLESS_TLS_WS, network="splithttp"))
        assert stream["network"] == "xhttp"
        assert stream["xhttpSettings"]["path"] == "/wspath"

    def test_plain_tcp_stays_bare(self):
        settings = {"server": "s", "server_port": 443, "uuid": "u"}
        assert xray_stream_settings(settings) is None
        native, _ = XrayDriver._outbound_to_native(
            None, _ob(OutboundKind.VLESS, dict(settings)))
        assert "streamSettings" not in native


class TestSingBoxRendering:
    def test_tls_ws_reaches_tls_and_transport(self):
        native, gap = SingBoxDriver._outbound_to_native(
            None, _ob(OutboundKind.VLESS, dict(_VLESS_TLS_WS)))
        assert gap is None
        assert native["tls"] == {
            "enabled": True, "server_name": "sni.example.com",
            "alpn": ["h2", "http/1.1"],
            "utls": {"enabled": True, "fingerprint": "chrome"}}
        assert native["transport"] == {
            "type": "ws", "path": "/wspath",
            "headers": {"Host": "cdn.example.com"}}

    def test_reality_reaches_tls_block(self):
        native, _ = SingBoxDriver._outbound_to_native(
            None, _ob(OutboundKind.TROJAN,
                      dict(_VLESS_REALITY_TCP, password="p", uuid=None)))
        tls = native["tls"]
        assert tls["reality"] == {"enabled": True, "public_key": "pb-key",
                                  "short_id": "abcd"}
        assert tls["server_name"] == "www.microsoft.com"
        assert "transport" not in native

    def test_allow_insecure_maps_to_insecure(self):
        tls, _ = singbox_tls_and_transport(
            dict(_VLESS_TLS_WS, allow_insecure=True))
        assert tls["insecure"] is True

    def test_plain_tcp_stays_bare(self):
        settings = {"server": "s", "server_port": 443, "uuid": "u"}
        tls, transport = singbox_tls_and_transport(dict(settings))
        assert tls is None and transport is None
        native, _ = SingBoxDriver._outbound_to_native(
            None, _ob(OutboundKind.VLESS, dict(settings)))
        assert "tls" not in native and "transport" not in native
