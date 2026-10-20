"""WireGuard outbound .conf import regressions."""
from __future__ import annotations

import base64

import pytest

from app.cores.outbounds.wireguard_profile import (
    WireGuardProfileError,
    parse_wireguard_profile,
)


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode()


def test_wireguard_conf_import_maps_complete_client_profile() -> None:
    profile = f"""\
[Interface]
PrivateKey = {_key(1)}
Address = 10.44.0.2/32, fd44::2/128
DNS = 1.1.1.1, 9.9.9.9
MTU = 1380

[Peer]
PublicKey = {_key(2)}
PresharedKey = {_key(3)}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = wg.example.com:51888
PersistentKeepalive = 19
"""
    settings = parse_wireguard_profile(profile)
    assert settings == {
        "server": "wg.example.com",
        "server_port": 51888,
        "private_key": _key(1),
        "peer_public_key": _key(2),
        "preshared_key": _key(3),
        "local_address": ["10.44.0.2/32", "fd44::2/128"],
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "dns": ["1.1.1.1", "9.9.9.9"],
        "mtu": 1380,
        "keepalive": 19,
    }


def test_wireguard_conf_import_supports_bracketed_ipv6_endpoint_and_defaults() -> None:
    settings = parse_wireguard_profile(f"""\
[Interface]
PrivateKey = {_key(4)}
Address = 10.55.0.2/32
[Peer]
PublicKey = {_key(5)}
Endpoint = [2001:db8::7]:51820
""")
    assert settings["server"] == "2001:db8::7"
    assert settings["server_port"] == 51820
    assert settings["allowed_ips"] == ["0.0.0.0/0", "::/0"]
    assert settings["mtu"] == 1420 and settings["keepalive"] == 25
    assert "preshared_key" not in settings


@pytest.mark.parametrize("profile, message", [
    ("[Interface]\nAddress=10.0.0.2/32\n[Peer]\nEndpoint=x:1\n", "PrivateKey"),
    (f"[Interface]\nPrivateKey={_key(1)}\nAddress=10.0.0.2/32\n", r"exactly one \[Peer\]"),
    (f"[Interface]\nPrivateKey={_key(1)}\nAddress=bad\n[Peer]\nPublicKey={_key(2)}\nEndpoint=x:1\n", "Address"),
    (f"[Interface]\nPrivateKey={_key(1)}\nAddress=10.0.0.2/32\n[Peer]\nPublicKey={_key(2)}\nEndpoint=missing-port\n", "Endpoint"),
])
def test_wireguard_conf_import_rejects_incomplete_or_ambiguous_profiles(
    profile: str, message: str,
) -> None:
    with pytest.raises(WireGuardProfileError, match=message):
        parse_wireguard_profile(profile)
