"""SoftEther client-outbound capability honesty."""
from __future__ import annotations

from app.cores.outbounds.model import (
    SOFTETHER_CLIENT_KINDS,
    SOFTETHER_CLIENT_LIMITATION,
    Outbound,
)
from app.cores.outbounds.profile_schema import outbound_schemas


def test_every_requested_softether_client_family_is_visible_but_disabled() -> None:
    schemas = outbound_schemas()
    expected = {
        "softether_l2tp", "softether_l2tp_raw", "softether_sstp",
        "softether_pptp", "softether_native",
    }
    assert expected == {kind.value for kind in SOFTETHER_CLIENT_KINDS}
    for kind in expected:
        assert kind in schemas
        assert schemas[kind]["x-supported"] is False
        assert "client" in schemas[kind]["x-disabled-reason"].lower()


def test_softether_profiles_remain_typed_for_migration_but_carry_no_runtime_claim() -> None:
    outbound = Outbound(
        name="softether-native-up", kind="softether_native",
        settings={"server": "vpn.example.test", "server_port": 5555,
                  "username": "u", "password": "p"},
        enabled=False,
    )
    assert outbound.kind in SOFTETHER_CLIENT_KINDS
    assert "ships no supported client runtime" in SOFTETHER_CLIENT_LIMITATION
