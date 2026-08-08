"""Delivery-descriptor unit tests + all-driver conformance.

Two layers:
* unit tests for the share-link renderer, field masking and the generic
  payload presenter (no drivers involved);
* a conformance suite driving ``describe_delivery`` of all eight built-in
  drivers with fake backends, asserting the shape contract every
  presentation layer (Subscription Portal, bots, ...) relies on.

Run: pytest tests/cores/test_delivery.py -v   OR   python tests/cores/test_delivery.py
"""
from __future__ import annotations

import asyncio
import base64
import json
import sys
import tempfile
import traceback
import types as _types
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores.delivery import (  # noqa: E402
    ArtifactKind,
    DeliveryProfile,
    ShareLinkError,
    fields_from_mapping,
    is_secret_field,
    profile_from_client_config,
    share_url_for_outbound,
)
from app.cores.types import ClientConfig, UserAccount  # noqa: E402

# ---------------------------------------------------------------------- #
# unit: share-link renderer
# ---------------------------------------------------------------------- #

_OUT_VLESS = {
    "type": "vless", "tag": "VLESS_TCP_REALITY",
    "server": "de.example.com", "server_port": 443,
    "uuid": "11111111-2222-3333-4444-555555555555",
    "flow": "xtls-rprx-vision",
    "tls": {
        "enabled": True, "server_name": "www.microsoft.com", "alpn": ["h2"],
        "utls": {"enabled": True, "fingerprint": "chrome"},
        "reality": {"enabled": True, "public_key": "PUB", "short_id": "ab12"},
    },
    "transport": {"type": "tcp"},
}

_OUT_WS = {
    "type": "vless", "tag": "VLESS_WS", "server": "cdn.example.com",
    "server_port": 2083, "uuid": "u-u-i-d",
    "tls": {"enabled": False},
    "transport": {"type": "ws", "path": "/graphql?x=1", "headers": {"Host": "cdn.example.com"}},
}


def test_share_url_vless_reality() -> None:
    url = share_url_for_outbound(_OUT_VLESS, "Reality · DE")
    parts = urlsplit(url)
    assert parts.scheme == "vless"
    assert parts.username == _OUT_VLESS["uuid"]
    assert parts.hostname == "de.example.com" and parts.port == 443
    q = parse_qs(parts.query)
    assert q["security"] == ["reality"] and q["sni"] == ["www.microsoft.com"]
    assert q["pbk"] == ["PUB"] and q["sid"] == ["ab12"]
    assert q["fp"] == ["chrome"] and q["alpn"] == ["h2"]
    assert q["flow"] == ["xtls-rprx-vision"] and q["type"] == ["tcp"]
    assert unquote(parts.fragment) == "Reality · DE"


def test_share_url_vless_ws_no_tls() -> None:
    url = share_url_for_outbound(_OUT_WS, "ws link")
    parts = urlsplit(url)
    q = parse_qs(parts.query)
    assert q["security"] == ["none"] and q["type"] == ["ws"]
    assert q["host"] == ["cdn.example.com"]
    assert q["path"] == ["/graphql?x=1"]  # special chars must survive roundtrip


def test_share_url_vmess_decodes() -> None:
    out = {
        "type": "vmess", "tag": "VMESS_WS", "server": "vm.example.com",
        "server_port": 8443, "uuid": "v-u-i-d",
        "tls": {"enabled": True, "server_name": "sni.example.com", "alpn": ["h2", "http/1.1"],
                "utls": {"enabled": False, "fingerprint": None}},
        "transport": {"type": "ws", "path": "/vm", "headers": {"Host": "vm.example.com"}},
    }
    url = share_url_for_outbound(out, "vmess link")
    assert url.startswith("vmess://")
    doc = json.loads(base64.b64decode(url[len("vmess://"):]).decode("utf-8"))
    assert doc["v"] == "2" and doc["ps"] == "vmess link"
    assert doc["add"] == "vm.example.com" and doc["port"] == "8443"
    assert doc["id"] == "v-u-i-d" and doc["net"] == "ws"
    assert doc["path"] == "/vm" and doc["host"] == "vm.example.com"
    assert doc["tls"] == "tls" and doc["sni"] == "sni.example.com"
    assert doc["alpn"] == "h2,http/1.1"


def test_share_url_trojan_and_shadowsocks() -> None:
    trojan = share_url_for_outbound(
        {"type": "trojan", "server": "t.example.com", "server_port": 443,
         "password": "p@ss/w:d", "tls": {"enabled": True, "server_name": "t.example.com",
         "alpn": None, "utls": {"enabled": False, "fingerprint": None}},
         "transport": {"type": "tcp"}},
        "trojan",
    )
    parts = urlsplit(trojan)
    # trojan URLs carry the password as the whole userinfo (no user: separator)
    assert parts.scheme == "trojan" and unquote(parts.username or "") == "p@ss/w:d"
    assert parse_qs(parts.query)["sni"] == ["t.example.com"]

    ss = share_url_for_outbound(
        {"type": "shadowsocks", "server": "s.example.com", "server_port": 8388,
         "method": "aes-128-gcm", "password": "secret", "tls": {"enabled": False}},
        "ss",
    )
    parts = urlsplit(ss)
    assert parts.scheme == "ss" and parts.hostname == "s.example.com" and parts.port == 8388
    pad = "=" * (-len(parts.username) % 4)
    assert base64.urlsafe_b64decode(parts.username + pad).decode() == "aes-128-gcm:secret"


def test_share_url_errors_are_honest() -> None:
    for bad in (
        {"type": "vless", "server_port": 443},                       # no server
        {"type": "vless", "server": "x", "server_port": 443},        # no uuid
        {"type": "shadowsocks", "server": "x", "server_port": 1, "method": None, "password": "p"},
        {"type": "hysteria2", "server": "x", "server_port": 443},    # not link-encodable here
    ):
        try:
            share_url_for_outbound(bad, "x")
            raise AssertionError(f"accepted invalid outbound: {bad}")
        except ShareLinkError:
            pass


# ---------------------------------------------------------------------- #
# unit: field masking + generic presenter
# ---------------------------------------------------------------------- #


def test_secret_field_rules() -> None:
    assert is_secret_field("password") and is_secret_field("ipsec_psk")
    assert is_secret_field("private_key") and is_secret_field("uuid")
    assert not is_secret_field("public_key") and not is_secret_field("host")
    fields = fields_from_mapping({"host": "h", "password": "p", "profile": "x", "n": None})
    keys = {f.key: f for f in fields}
    assert set(keys) == {"host", "password"}          # profile/None skipped
    assert keys["password"].secret and not keys["host"].secret


def _cfg(payload: dict, protocol: str = "p", engine: str = "e") -> ClientConfig:
    return ClientConfig(core_id="c", protocol=protocol, engine=engine,
                        payload=payload, display_name="disp")


def test_generic_presenter_share_url_and_hint() -> None:
    profile = profile_from_client_config(_cfg({"format": "share-url", "url": "hy2://x"}))
    profile.validate_shape()
    art = profile.sections[0].artifacts[0]
    assert art.kind is ArtifactKind.LINK and art.qr and art.content == "hy2://x"


def test_generic_presenter_file_and_fields() -> None:
    profile = profile_from_client_config(_cfg({"format": "ini", "profile": "[Interface]..."}))
    art = profile.sections[0].artifacts[0]
    assert art.kind is ArtifactKind.FILE and art.filename == "config.conf" and art.qr

    ssh = profile_from_client_config(_cfg(
        {"format": "ssh", "host": "h", "port": 22, "username": "u",
         "password": "p", "hint": "ssh -D 1080"}, protocol="ssh"))
    ssh.validate_shape()
    kinds = [a.kind for a in ssh.sections[0].artifacts]
    assert ArtifactKind.FIELDS in kinds and ArtifactKind.NOTE in kinds


def test_generic_presenter_outbounds_and_fallback_note() -> None:
    profile = profile_from_client_config(_cfg({"outbounds": [_OUT_VLESS]}))
    assert urlsplit(profile.sections[0].artifacts[0].content).scheme == "vless"

    empty = profile_from_client_config(_cfg({"nested": {"opaque": [1, 2]}}))
    empty.validate_shape()
    assert empty.sections[0].artifacts[0].kind is ArtifactKind.NOTE


# ---------------------------------------------------------------------- #
# conformance: describe_delivery across all eight built-in drivers
# ---------------------------------------------------------------------- #

_XRAY_INBOUNDS: dict[str, dict[str, Any]] = {
    "VLESS_TCP_REALITY": {
        "protocol": "vless", "network": "tcp", "tls": "reality", "header_type": "",
        "port": 443, "sni": ["www.microsoft.com"], "pbk": "PUB", "sids": ["ab12"],
    },
    "VLESS_WS": {"protocol": "vless", "network": "ws", "tls": "none", "header_type": "", "port": 2083},
}

_XRAY_HOSTS: dict[str, list[dict[str, Any]]] = {
    "VLESS_TCP_REALITY": [{
        "remark": "Reality · DE", "address": ["de.example.com"], "port": 443,
        "sni": ["www.microsoft.com"], "host": [], "path": None, "alpn": "h2",
        "fingerprint": "chrome", "tls": None,
    }],
    "VLESS_WS": [{
        "remark": "WS · CDN", "address": ["cdn.example.com"], "port": 2083,
        "sni": [], "host": ["cdn.example.com"], "path": "/ws", "alpn": "",
        "fingerprint": "", "tls": None,
    }],
}


class _DeliveryXrayBackend:
    """Minimal backend exposing config shape for delivery tests."""

    def __init__(self) -> None:
        self.running = False

    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): pass
    def is_running(self): return self.running
    def version(self): return "1.8.23"
    def metrics(self):
        from app.cores.types import CoreMetrics
        return CoreMetrics()
    def logs(self, tail: int = 200): return []
    def inbounds(self): return _XRAY_INBOUNDS
    def host_options(self, tag: str): return list(_XRAY_HOSTS.get(tag, []))
    def add_user(self, tag, protocol, email, settings): pass
    def remove_user(self, tag, email): pass
    def usage(self, reset: bool = False): return []
    def online_accounts(self): return []
    def set_routing_rules(self, rules): pass
    def set_outbounds(self, outbounds): pass
    def ensure_listener(self, protocol, port): pass


def _acct(user: int, name: str, protocol: str, settings: dict | None = None) -> UserAccount:
    return UserAccount(
        user_id=user, username=name, account_id=f"{user}.{name}",
        protocol=protocol, settings=settings or {},
    )


async def _xray_profile() -> DeliveryProfile:
    from app.cores.drivers.xray import XrayDriver
    driver = XrayDriver(backend=_DeliveryXrayBackend())
    account = _acct(1, "alice", "vless", {"id": "11111111-2222-3333-4444-555555555555"})
    await driver.create_account(account)
    return await driver.describe_delivery(account)


async def _singbox_profile() -> DeliveryProfile:
    from app.cores.drivers.singbox import SingBoxDriver
    from tests.cores.fakes import FakeSingBoxBackend
    driver = SingBoxDriver(settings={"work_dir": tempfile.mkdtemp(prefix="dlvsb-")},
                           backend=FakeSingBoxBackend())
    account = _acct(1, "alice", "vless", {"id": "uuid-1"})
    await driver.create_account(account)
    return await driver.describe_delivery(account)


async def _wireguard_profile() -> DeliveryProfile:
    from app.cores.drivers.wireguard import WireGuardDriver
    from tests.cores.fakes import FakeWireGuardBackend
    driver = WireGuardDriver({"work_dir": tempfile.mkdtemp(prefix="dlvwg-")},
                             backend=FakeWireGuardBackend())
    await driver.start()
    account = _acct(1, "alice", "wireguard")
    await driver.create_account(account)
    return await driver.describe_delivery(account)


async def _openvpn_profile() -> DeliveryProfile:
    from app.cores.drivers.openvpn import OpenVPNDriver
    from tests.cores.fakes import FakeOpenVPNBackend
    driver = OpenVPNDriver(backend=FakeOpenVPNBackend())
    await driver.start()
    account = _acct(1, "alice", "ovpn", {"password": "pw-alice"})
    await driver.create_account(account)
    return await driver.describe_delivery(account)


async def _hysteria2_profile() -> DeliveryProfile:
    # consolidated (alpha.7.2): hysteria2 is served by the sing-box core
    from app.cores.drivers.singbox import SingBoxDriver
    from tests.cores.fakes import FakeSingBoxBackend, FakeV2RayStats
    driver = SingBoxDriver(
        {"work_dir": tempfile.mkdtemp(prefix="dlvhy-"),
         "advertise_host": "vpn.example.com"},
        backend=FakeSingBoxBackend(), stats=FakeV2RayStats())
    await driver.start()
    account = _acct(1, "alice", "hysteria2", {"password": "secret"})
    await driver.create_account(account)
    return await driver.describe_delivery(account)


async def _tuic_profile() -> DeliveryProfile:
    # consolidated (alpha.7.2): tuic is served by the sing-box core
    from app.cores.drivers.singbox import SingBoxDriver
    from tests.cores.fakes import FakeSingBoxBackend, FakeV2RayStats
    driver = SingBoxDriver(
        {"work_dir": tempfile.mkdtemp(prefix="dlvtuic-"),
         "advertise_host": "vpn.example.com"},
        backend=FakeSingBoxBackend(), stats=FakeV2RayStats())
    await driver.start()
    account = _acct(1, "alice", "tuic")
    await driver.create_account(account)
    return await driver.describe_delivery(account)


async def _ssh_profile() -> DeliveryProfile:
    from app.cores.drivers.ssh import SSHTunnelDriver
    from tests.cores.fakes import FakeSSHBackend
    driver = SSHTunnelDriver(backend=FakeSSHBackend())
    account = _acct(1, "alice", "ssh", {"password": "s3cret"})
    await driver.create_account(account)
    return await driver.describe_delivery(account)


async def _softether_profile() -> DeliveryProfile:
    from app.cores.drivers.softether import SoftEtherDriver
    from tests.cores.fakes import FakeSEBackend
    driver = SoftEtherDriver({"ipsec_psk": "test-psk"}, backend=FakeSEBackend())
    account = _acct(1, "alice", "l2tp", {"password": "pw"})
    await driver.create_account(account)
    return await driver.describe_delivery(account)


# label → (expected profile core_id, builder). The hysteria2/tuic protocols
# are served by the sing-box core since alpha.7.2 (consolidation), so their
# profiles honestly report core_id "sing-box".
_BUILDERS = {
    "xray": ("xray", _xray_profile),
    "sing-box": ("sing-box", _singbox_profile),
    "wireguard": ("wireguard", _wireguard_profile),
    "openvpn": ("openvpn", _openvpn_profile),
    "hysteria2 (via sing-box)": ("sing-box", _hysteria2_profile),
    "tuic (via sing-box)": ("sing-box", _tuic_profile),
    "ssh": ("ssh", _ssh_profile),
    "softether": ("softether", _softether_profile),
}

_ALLOWED_LINK_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"}


def test_all_drivers_describe_delivery_conformance() -> None:
    for label, (core_id, builder) in _BUILDERS.items():
        profile = asyncio.run(builder())
        assert profile.core_id == core_id, f"{label}: wrong profile core id"
        profile.validate_shape()
        for section in profile.sections:
            assert section.protocol, f"{core_id}: empty section protocol"
            assert section.engine, f"{core_id}: empty section engine"
            for artifact in section.artifacts:
                if artifact.kind is ArtifactKind.LINK:
                    scheme = urlsplit(artifact.content).scheme
                    assert scheme in _ALLOWED_LINK_SCHEMES, (
                        f"{core_id}: unexpected link scheme '{scheme}'"
                    )
                if artifact.kind is ArtifactKind.FIELDS:
                    for field in artifact.fields:
                        secretish = any(
                            t in field.key.lower()
                            for t in ("password", "psk", "private")
                        )
                        if secretish and not field.key.startswith("public"):
                            assert field.secret, (
                                f"{core_id}: field '{field.key}' not masked"
                            )


def test_xray_delivery_lists_all_inbounds_with_links() -> None:
    profile = asyncio.run(_xray_profile())
    links = [a for s in profile.sections for a in s.artifacts if a.kind is ArtifactKind.LINK]
    assert len(links) == 2, f"expected 2 links (2 inbounds), got {len(links)}"
    labels = {a.label for a in links}
    assert "Reality · DE" in labels
    urls = [a.content for a in links]
    assert any("pbk=PUB" in u for u in urls)            # reality link
    assert any("security=none" in u for u in urls)      # ws link


def test_wireguard_delivery_has_file_fields_and_qr() -> None:
    profile = asyncio.run(_wireguard_profile())
    section = profile.sections[0]
    arts = section.artifacts
    kinds = [a.kind for a in arts]
    # item 15: field-rich sections — FILE + FIELDS + an honest how-to NOTE,
    # and the section names its inbound for the Host Settings engine.
    assert kinds == [ArtifactKind.FILE, ArtifactKind.FIELDS, ArtifactKind.NOTE]
    assert section.inbound_tag == "wireguard"
    file_art = arts[0]
    assert file_art.qr and file_art.filename.endswith(".conf")
    assert "[Interface]" in file_art.content and "PrivateKey" in file_art.content
    fields = {f.key: f for f in arts[1].fields}
    assert {"address", "public_key", "endpoint", "dns",
            "allowed_ips", "keepalive"} <= set(fields)
    assert not fields["public_key"].secret             # server public key is public
    assert "PrivateKey" not in {f.label for f in arts[1].fields}


def test_openvpn_delivery_has_profile_and_credentials() -> None:
    profile = asyncio.run(_openvpn_profile())
    arts = profile.sections[0].artifacts
    file_art = next(a for a in arts if a.kind is ArtifactKind.FILE)
    assert file_art.filename.endswith(".ovpn")
    fields = {f.key: f for a in arts if a.kind is ArtifactKind.FIELDS for f in a.fields}
    assert fields["username"].value == "1.alice"
    assert fields["password"].secret and fields["password"].value == "pw-alice"


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
