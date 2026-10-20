"""Transport-specific SoftEther runtime capability regressions."""
from __future__ import annotations

from app.cores.drivers.softether.capabilities import (
    apply_softether_wizard_capabilities,
    parse_server_command_inventory,
    softether_transport_capabilities,
)
from app.studio.wizard import blueprint_for


HELP_444 = """
You can use the following 205 commands:
 About                      - Display the version information
 IPsecEnable                - Enable or Disable IPsec VPN Server Function
 IPsecGet                   - Get the Current IPsec VPN Server Settings
 ListenerList               - Get List of TCP Listeners
 OpenVpnEnable              - Enable / Disable OpenVPN Clone Server Function
 OpenVpnGet                 - Get the Current Settings of OpenVPN Clone Server
 ServerInfoGet              - Get server information
 SstpEnable                 - Enable / Disable Microsoft SSTP VPN Clone Server
 SstpGet                    - Get the Current Microsoft SSTP Settings
"""


class Backend:
    def vpncmd_binary(self):
        return "/runtime/vpncmd"

    def server_binary(self):
        return "/runtime/vpnserver"

    def client_binary(self):
        return "/runtime/vpnclient"

    def version(self):
        return "4.44 build 9807"

    def server_command_inventory(self):
        return parse_server_command_inventory(HELP_444)


class Runtime:
    class Manager:
        def get(self, core_id):
            assert core_id == "softether"
            return type("Driver", (), {"_backend": Backend()})()

    core_manager = Manager()


def test_command_inventory_and_pptp_detection_are_live_and_non_mutating() -> None:
    commands = parse_server_command_inventory(HELP_444)
    assert {"IPsecGet", "IPsecEnable", "SstpGet", "SstpEnable"} <= commands
    assert not any("pptp" in command.lower() for command in commands)

    matrix = softether_transport_capabilities(Runtime())
    assert matrix["l2tp_ipsec"]["server"]["state"] == "supported"
    assert matrix["sstp"]["server"]["state"] == "supported"
    pptp = matrix["pptp"]["server"]
    assert pptp["state"] == "unsupported"
    assert pptp["required_commands"] == ["PptpEnable", "PptpGet"]
    assert pptp["observed_commands"] == []
    assert "4.44 build 9807" in pptp["reason"]
    assert "vpncmd server command count=" in " ".join(pptp["evidence"])


def test_softether_client_matrix_is_transport_specific_and_openvpn_is_real() -> None:
    matrix = softether_transport_capabilities(Runtime())
    native = matrix["native"]["client"]
    assert native["state"] in {"supported", "not_installed"}
    assert native["tun"] is True
    assert native["canonical_outbound_kind"] == "softether_native"
    assert native["provider"] == "vpnclient+vpncmd+Virtual-NIC namespace adapter"
    assert "dedicated client service/account/NIC" in " ".join(native["evidence"])
    canonical = {
        "l2tp_ipsec": "l2tp_ipsec",
        "l2tp_raw": "l2tp_raw",
        "sstp": "sstp",
    }
    for transport, kind in canonical.items():
        client = matrix[transport]["client"]
        assert client["state"] in {"supported", "not_installed"}
        assert client["tun"] is True
        assert client["canonical_outbound_kind"] == kind
        assert "canonical independent outbound" in " ".join(client["evidence"])
        assert "SoftEther is only the compatible remote listener" in client["reason"]
    pptp = matrix["pptp"]["client"]
    assert pptp["state"] == "not_applicable"
    assert pptp["tun"] is False
    assert pptp["canonical_outbound_kind"] is None
    assert "independent ACCEL-PPP/pptp-linux" in pptp["reason"]
    openvpn = matrix["openvpn"]["client"]
    # Host package presence can refine supported to not_installed, but the
    # canonical provider must never become a fake SoftEther client kind.
    assert openvpn["state"] in {"supported", "not_installed"}
    assert openvpn["canonical_outbound_kind"] == "openvpn"
    assert openvpn["provider"] == "OpenVPN client"
    assert openvpn["tun"] is True
    assert "canonical client is independent kind=openvpn" in openvpn["reason"]


def test_live_wizard_uses_the_same_pptp_detector() -> None:
    blueprint = apply_softether_wizard_capabilities(
        blueprint_for("softether"), Runtime())
    by_id = {protocol["id"]: protocol for protocol in blueprint["protocols"]}
    assert by_id["l2tp"]["availability"] == "supported"
    assert by_id["sstp"]["availability"] == "supported"
    # PPTP has moved to an independent ACCEL-PPP provider and is not a
    # SoftEther wizard choice. The live SoftEther matrix still reports it.
    assert "pptp" not in by_id
    assert blueprint["transport_capabilities"]["pptp"]["server"]["state"] == "unsupported"
    assert blueprint["transport_capabilities"]["pptp"]["client"]["state"] == "not_applicable"
