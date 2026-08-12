"""Multi-format subscription rendering (spec §7/§8).

ONE merged multi-core link set → clash-meta YAML / sing-box JSON, with the
honesty contract: exact duplicates collapse, names stay unique, and what a
format cannot express is named in notes — never fabricated, never silent.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_HAS = importlib.util.find_spec("yaml") is not None
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")

LINKS = [
    "vless://abcd-1234@de.example.com:443?security=reality&sni=www.microsoft.com"
    "&pbk=PUBKEY-1&sid=ab12&type=tcp&flow=xtls-rprx-vision#VLESS%20DE",
    "vmess://eyJhZGQiOiJ3cy5leGFtcGxlLmNvbSIsInBvcnQiOjQ0MywiaWQiOiJhYmNkLTEyMzQi"
    "LCJhaWQiOjAsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInBhdGgiOiIvd3MiLCJob3N0Ijoid3Mu"
    "ZXhhbXBsZS5jb20iLCJ0bHMiOiJ0bHMiLCJzbmkiOiJ3cy5leGFtcGxlLmNvbSJ9#VMess-WS",
    "trojan://s3cret@tr.example.com:443?sni=tr.example.com#Trojan",
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@ss.example.com:8388#SS",
    "hysteria2://hy2pw@hy.example.com:8443?sni=hy.example.com#HY2",
    "tuic://abcd-1234:tuicpw@tu.example.com:10443?sni=tu.example.com"
    "&congestion_control=bbr#TUIC",
    # exact duplicate (spec: بدون تکرار) + an unparsable one + an unsupported one
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@ss.example.com:8388#SS",
    "wireguard://cGFzczpLRVk@wg.example.com:51820?public_key=PUBK#WG",
    "garbage-not-a-link",
]


def test_dedupe_preserves_order():
    from app.platform.sub_formats import dedupe_links

    assert dedupe_links(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


def test_parse_named_unique_and_honest_skips():
    from app.platform.sub_formats import parse_named

    parsed, notes = parse_named(LINKS)
    names = [n for n, _ in parsed]
    assert len(names) == len(set(names)) == 6  # 7 valid unique links - dup -> 6
    assert names.count("SS") == 1
    assert any("wireguard" in n for n in notes)
    assert any("garbage" in n for n in notes)


def test_clash_meta_yaml_is_valid_and_exact():
    import yaml

    from app.platform.sub_formats import to_clash_meta

    body, notes = to_clash_meta(LINKS, ["portal-note"])
    assert body.startswith("#")  # notes ride as YAML comments
    doc = yaml.safe_load(body)

    proxies = doc["proxies"]
    types = sorted(p["type"] for p in proxies)
    assert types == ["hysteria2", "ss", "trojan", "tuic", "vless", "vmess"]
    names = [p["name"] for p in proxies]
    assert len(names) == len(set(names))

    vless = next(p for p in proxies if p["type"] == "vless")
    assert vless["uuid"] == "abcd-1234"
    assert vless["tls"] is True and vless["client-fingerprint"] == "chrome"
    assert vless["reality-opts"]["public-key"] == "PUBKEY-1"
    assert vless["reality-opts"]["short-id"] == "ab12"
    assert vless["flow"] == "xtls-rprx-vision"

    vmess = next(p for p in proxies if p["type"] == "vmess")
    assert vmess["network"] == "ws"
    assert vmess["ws-opts"]["path"] == "/ws"
    assert vmess["ws-opts"]["headers"]["Host"] == "ws.example.com"
    assert vmess["servername"] == "ws.example.com"

    hy2 = next(p for p in proxies if p["type"] == "hysteria2")
    assert hy2["password"] == "hy2pw" and hy2["sni"] == "hy.example.com"

    group = doc["proxy-groups"][0]
    assert group["type"] == "select" and set(names) <= set(group["proxies"])
    assert doc["rules"] == ["MATCH,PROXY"]
    assert any("garbage" in n for n in notes)


def test_sing_box_json_is_valid_and_exact():
    from app.platform.sub_formats import to_sing_box

    text, notes = to_sing_box(LINKS)
    doc = json.loads(text)

    outbounds = doc["outbounds"]
    selector = outbounds[0]
    assert selector["type"] == "selector" and selector["tag"] == "select"
    # modern shape (sing-box 1.13): only `direct` trails the proxy outbounds —
    # no legacy `block`/`dns` special outbounds (removed upstream)
    proxy_tags = [o["tag"] for o in outbounds[1:-1]]
    assert outbounds[-1]["type"] == "direct"
    assert not any(o.get("type") in ("block", "dns") for o in outbounds)
    assert len(proxy_tags) == len(set(proxy_tags)) == 6
    assert selector["default"] == proxy_tags[0]
    assert set(proxy_tags) <= set(selector["outbounds"])

    vless = next(o for o in outbounds if o.get("type") == "vless")
    assert vless["tls"]["reality"]["public_key"] == "PUBKEY-1"
    assert vless["tls"]["server_name"] == "www.microsoft.com"
    assert vless["flow"] == "xtls-rprx-vision"

    vmess = next(o for o in outbounds if o.get("type") == "vmess")
    assert vmess["transport"] == {"type": "ws", "path": "/ws",
                                  "headers": {"Host": "ws.example.com"}}
    assert vmess["tls"]["enabled"] is True

    ss = next(o for o in outbounds if o.get("type") == "shadowsocks")
    assert ss["method"] == "chacha20-ietf-poly1305" and "tls" not in ss

    tuic = next(o for o in outbounds if o.get("type") == "tuic")
    assert tuic["uuid"] == "abcd-1234" and tuic["congestion_control"] == "bbr"

    assert doc["route"]["final"] == "select"
    assert any("garbage" in n for n in notes)


def test_grpc_service_name_survives_link_to_client_formats():
    link = (
        "vless://00000000-0000-4000-8000-000000000001@vpn.example.com:443"
        "?type=grpc&security=tls&allowInsecure=1&serviceName=p0grpc#grpc"
    )
    from app.platform.sub_formats import to_clash_meta, to_sing_box
    import yaml

    sing = json.loads(to_sing_box([link])[0])
    outbound = next(o for o in sing["outbounds"] if o.get("type") == "vless")
    assert outbound["transport"] == {"type": "grpc", "service_name": "p0grpc"}
    assert outbound["tls"]["insecure"] is True

    clash = yaml.safe_load(to_clash_meta([link])[0])
    proxy = clash["proxies"][0]
    assert proxy["network"] == "grpc"
    assert proxy["grpc-opts"] == {"grpc-service-name": "p0grpc"}


def test_sing_box_quic_protocols_always_emit_tls():
    """hy2/tuic are TLS-mandatory in sing-box — links carry no `security`
    param, yet the rendered outbound MUST still carry a valid tls block
    (verified against the real binary; the old renderer dropped it and
    produced an unbootable config)."""
    from app.platform.sub_formats import to_sing_box

    text, _ = to_sing_box([
        "hysteria2://pw@hy.example.com:8443?sni=hy.example.com&insecure=1#H",
        "hy2://pw@hy2.example.com:443?obfs=salamander&obfs-password=x#H2",
        "tuic://abcd-1234:pw@tu.example.com:10443?sni=tu.example.com"
        "&allow_insecure=1#T",
    ])
    doc = json.loads(text)
    hy2 = next(o for o in doc["outbounds"] if o.get("type") == "hysteria2"
               and o["server"] == "hy.example.com")
    assert hy2["tls"]["enabled"] is True
    assert hy2["tls"]["server_name"] == "hy.example.com"
    assert hy2["tls"]["insecure"] is True
    tuic = next(o for o in doc["outbounds"] if o.get("type") == "tuic")
    assert tuic["tls"]["enabled"] is True
    assert tuic["tls"]["server_name"] == "tu.example.com"
    assert tuic["tls"]["insecure"] is True


_SINGBOX_BIN = os.environ.get("ZAGROS_SINGBOX_BIN") or shutil.which("sing-box") \
    or ("/tmp/sbcheck/sb112" if os.path.exists("/tmp/sbcheck/sb112") else None)


@pytest.mark.skipif(not _SINGBOX_BIN,
                    reason="real sing-box binary unavailable "
                           "(set ZAGROS_SINGBOX_BIN to enable)")
def test_rendered_config_passes_real_binary_check(tmp_path):
    """The subscription sing-box config must be BOOTABLE — validated with
    `sing-box check` on the real binary (the legacy special outbounds that
    1.13 removed used to fail this; never again silently)."""
    import subprocess

    from app.cores.drivers.singbox.driver import _x25519_keypair
    from app.platform.sub_formats import to_sing_box

    # the shared LINKS fixture uses placeholder ids/keys; the real binary
    # fully validates them, so this check runs over structurally REAL links
    # (genuine x25519 reality key + RFC4122 uuids).
    _, real_pub = _x25519_keypair()
    links = [
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@de.example.com:443"
        f"?security=reality&sni=www.microsoft.com&pbk={real_pub}&sid=ab12"
        "&type=tcp&flow=xtls-rprx-vision#VLESS",
        "hysteria2://pw@hy.example.com:8443?sni=hy.example.com&insecure=1#HY2",
        "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@tu.example.com:10443"
        "?sni=tu.example.com&congestion_control=bbr#TUIC",
        "ss://YWVzLTEyOC1nY206cHc@ss.example.com:8388#SS",
    ]
    text, notes = to_sing_box(links, [])
    cfg = tmp_path / "sub.json"
    cfg.write_text(text)
    proc = subprocess.run([_SINGBOX_BIN, "check", "-c", str(cfg)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, (
        f"subscription config failed {_SINGBOX_BIN} check:\n"
        f"{proc.stdout}\n{proc.stderr}\n{text[:1500]}")


def test_empty_set_renders_valid_documents():
    from app.platform.sub_formats import to_clash_meta, to_sing_box

    import yaml

    body, _ = to_clash_meta([], [])
    doc = yaml.safe_load(body)
    assert doc["proxies"] == [] and doc["proxy-groups"][0]["proxies"] == ["DIRECT"]

    text, _ = to_sing_box([], [])
    doc = json.loads(text)
    assert doc["outbounds"][0]["outbounds"] == ["direct"]
