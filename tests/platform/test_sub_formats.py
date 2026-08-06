"""Multi-format subscription rendering (spec §7/§8).

ONE merged multi-core link set → clash-meta YAML / sing-box JSON, with the
honesty contract: exact duplicates collapse, names stay unique, and what a
format cannot express is named in notes — never fabricated, never silent.
"""
from __future__ import annotations

import importlib.util
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
    proxy_tags = [o["tag"] for o in outbounds[1:-3]]
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


def test_empty_set_renders_valid_documents():
    from app.platform.sub_formats import to_clash_meta, to_sing_box

    import yaml

    body, _ = to_clash_meta([], [])
    doc = yaml.safe_load(body)
    assert doc["proxies"] == [] and doc["proxy-groups"][0]["proxies"] == ["DIRECT"]

    text, _ = to_sing_box([], [])
    doc = json.loads(text)
    assert doc["outbounds"][0]["outbounds"] == ["direct"]
