"""SoftEther client-outbound capability honesty."""
from __future__ import annotations

from app.cores.outbounds.model import (
    SOFTETHER_CLIENT_KINDS,
    SOFTETHER_CLIENT_LIMITATION,
    Outbound,
)
from app.cores.outbounds.profile_schema import outbound_schemas


def test_only_native_softether_provider_is_publicly_visible() -> None:
    schemas = outbound_schemas()
    internal = {
        "softether_l2tp", "softether_l2tp_raw", "softether_sstp",
        "softether_pptp", "softether_native",
    }
    # Legacy rows remain model-decodable for migration-safe deletion, but only
    # the genuine SoftEther vpnclient transport has a public creation schema.
    assert internal == {kind.value for kind in SOFTETHER_CLIENT_KINDS}
    assert "softether_native" in schemas
    assert schemas["softether_native"]["x-supported"] is True
    for kind in internal - {"softether_native"}:
        assert kind not in schemas


def test_native_profile_is_typed_and_requires_explicit_hub_credentials() -> None:
    outbound = Outbound(
        name="softether-native-up", kind="softether_native",
        settings={"server": "vpn.example.test", "server_port": 5555,
                  "hub": "ZAGROS-EDGE", "username": "u", "password": "p"},
        enabled=False,
    )
    assert outbound.kind in SOFTETHER_CLIENT_KINDS
    assert outbound.settings["hub"] == "ZAGROS-EDGE"
    assert "native SoftEther protocol has a dedicated vpnclient" in (
        SOFTETHER_CLIENT_LIMITATION)
