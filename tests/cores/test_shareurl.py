"""Share-URL parser tests ("Import URL", alpha.7).

Every case uses realistic links as produced by common panels/clients —
vless REALITY with ws/grpc/httpupgrade/splithttp transports, vmess
base64-JSON, trojan, ss2022 + legacy ss, hysteria2 with obfs + port
hopping, tuic.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.cores.outbounds.model import OutboundKind  # noqa: E402
from app.utils.shareurl import ShareURLError, parse_share_url  # noqa: E402


def test_vless_reality_tcp_vision() -> None:
    link = (
        "vless://8f3b6b90-1111-4222-8333-944455556666@cdn.example.com:443"
        "?security=reality&encryption=none&pbk=PUBKEYXYZ&sni=www.microsoft.com"
        "&fp=chrome&sid=ab12cd34&spx=%2F&flow=xtls-rprx-vision&type=tcp#My%20Server"
    )
    parsed = parse_share_url(link)
    assert parsed.kind is OutboundKind.VLESS
    s = parsed.settings
    assert s["server"] == "cdn.example.com" and s["server_port"] == 443
    assert s["uuid"] == "8f3b6b90-1111-4222-8333-944455556666"
    assert s["security"] == "reality"
    assert s["flow"] == "xtls-rprx-vision"
    assert s["reality_public_key"] == "PUBKEYXYZ"
    assert s["reality_short_id"] == "ab12cd34"
    assert s["reality_spider_x"] == "/"
    assert s["sni"] == "www.microsoft.com"
    assert s["fingerprint"] == "chrome"
    assert s["network"] == "tcp"
    assert parsed.name_hint == "My Server"


def test_vless_ws_tls() -> None:
    link = (
        "vless://1aa2bb3c-0000-4000-8000-abcdef012345@example.org:8443"
        "?type=ws&security=tls&path=%2Fws%2Fpath&host=cdn.example.org"
        "&sni=cdn.example.org&alpn=http%2F1.1#ws-node"
    )
    s = parse_share_url(link).settings
    assert s["network"] == "ws"
    assert s["path"] == "/ws/path"
    assert s["host"] == "cdn.example.org"
    assert s["security"] == "tls"
    assert s["alpn"] == "http/1.1"


def test_vless_grpc_and_httpupgrade_and_splithttp() -> None:
    grpc = parse_share_url(
        "vless://1aa2bb3c-0000-4000-8000-abcdef012345@example.org:443"
        "?type=grpc&serviceName=TsService&security=reality&pbk=K&sni=x.io&sid=01"
    ).settings
    assert grpc["network"] == "grpc" and grpc["serviceName"] == "TsService"

    hu = parse_share_url(
        "vless://1aa2bb3c-0000-4000-8000-abcdef012345@example.org:443"
        "?type=httpupgrade&path=%2Fhu&host=h.io&security=tls"
    ).settings
    assert hu["network"] == "httpupgrade" and hu["path"] == "/hu"

    sh = parse_share_url(
        "vless://1aa2bb3c-0000-4000-8000-abcdef012345@example.org:443"
        "?type=splithttp&path=%2Fsh&host=s.io&security=tls"
    ).settings
    assert sh["network"] == "splithttp"

    xh = parse_share_url(
        "vless://1aa2bb3c-0000-4000-8000-abcdef012345@example.org:443"
        "?type=xhttp&security=tls"
    ).settings
    assert xh["network"] == "splithttp"  # xhttp alias


def test_vmess_base64() -> None:
    import base64
    import json
    payload = {
        "v": "2", "ps": "vmess-node", "add": "vm.example.com", "port": "10086",
        "id": "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297", "aid": "0",
        "scy": "auto", "net": "ws", "path": "/vmws", "host": "cdn.vm.com",
        "tls": "tls", "sni": "cdn.vm.com", "type": "none",
    }
    link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
    parsed = parse_share_url(link)
    assert parsed.kind is OutboundKind.VMESS
    s = parsed.settings
    assert s["server"] == "vm.example.com" and s["server_port"] == 10086
    assert s["uuid"] == "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
    assert s["network"] == "ws" and s["path"] == "/vmws"
    assert s["security"] == "tls" and s["sni"] == "cdn.vm.com"
    assert s["cipher"] == "auto"
    assert parsed.name_hint == "vmess-node"


def test_trojan_defaults_tls() -> None:
    s = parse_share_url(
        "trojan://p%40ssw0rd@tj.example.com:443?sni=tj.example.com&allowInsecure=0#tj"
    ).settings
    assert s["password"] == "p@ssw0rd"
    assert s["security"] == "tls"  # trojan implies TLS
    assert s["sni"] == "tj.example.com"
    assert s["allow_insecure"] is False


def test_ss2022_and_legacy_ss() -> None:
    s = parse_share_url(
        "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206cGFzc3dvcmQtaGVyZQ@ss.example.com:8388#ss"
    ).settings
    assert s["method"] == "2022-blake3-aes-256-gcm"
    assert s["password"] == "password-here"
    assert s["server_port"] == 8388

    legacy = parse_share_url(
        "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40OjgzODg#legacy"
    ).settings
    assert legacy["method"] == "aes-256-gcm" and legacy["server"] == "1.2.3.4"


def test_hysteria2_full() -> None:
    s = parse_share_url(
        "hy2://authpass@hy.example.com:443?obfs=salamander&obfs-password=obfspw"
        "&sni=hy.example.com&insecure=1&mport=20000-30000#hy2"
    ).settings
    assert s["password"] == "authpass"
    assert s["obfs"] == "salamander" and s["obfs_password"] == "obfspw"
    assert s["allow_insecure"] is True
    assert s["port_hopping"] == "20000-30000"


def test_tuic_full() -> None:
    s = parse_share_url(
        "tuic://8f3b6b90-1111-4222-8333-944455556666:tuietpass@tuic.example.com:10443"
        "?congestion_control=bbr&alpn=h3&sni=tuic.example.com&udp_relay_mode=native#t"
    ).settings
    assert s["uuid"] == "8f3b6b90-1111-4222-8333-944455556666"
    assert s["password"] == "tuietpass"
    assert s["congestion_control"] == "bbr"
    assert s["alpn"] == "h3"


def test_errors_are_clear() -> None:
    with pytest.raises(ShareURLError):
        parse_share_url("")
    with pytest.raises(ShareURLError) as err:
        parse_share_url("openvpn://x")
    assert "unsupported" in str(err.value).lower()
    with pytest.raises(ShareURLError):
        parse_share_url("vless://@1.2.3.4:443")  # no uuid
    with pytest.raises(ShareURLError):
        parse_share_url("vmess://not-valid-base64!!!")
