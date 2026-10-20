"""Cross-core capability matrix is complete, typed and honest."""
from __future__ import annotations

from app.cores.matrix import FEATURES, capability_matrix, routing_pair_matrix


def test_matrix_has_every_required_feature_for_six_primary_cores() -> None:
    matrix = capability_matrix()
    assert set(matrix) == {
        "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether", "pptp"}
    assert set(FEATURES) == {
        "inbound", "outbound", "routing_source", "routing_destination", "tun",
        "traffic_accounting", "host_settings", "subscription", "tls",
        "version_probe", "node_support",
    }
    allowed = {
        "supported", "unsupported", "environment_limited",
        "not_installed", "not_applicable",
    }
    for core_id, cells in matrix.items():
        assert set(cells) == set(FEATURES), core_id
        for feature, cell in cells.items():
            assert cell["state"] in allowed, (core_id, feature)
            assert cell["detail"], (core_id, feature)


def test_matrix_locks_reported_ssh_softether_and_version_distinctions() -> None:
    matrix = capability_matrix()
    assert matrix["ssh"]["outbound"]["state"] == "supported"
    assert matrix["ssh"]["tun"]["state"] == "unsupported"
    assert matrix["softether"]["inbound"]["state"] == "supported"
    assert matrix["softether"]["outbound"]["state"] == "supported"
    # Native vpnclient is now a real dedicated namespace/Virtual-NIC target;
    # the existing isolated Hub/TAP remains the source dataplane.
    assert matrix["softether"]["routing_source"]["state"] == "supported"
    assert matrix["softether"]["routing_destination"]["state"] == "supported"
    assert matrix["softether"]["tun"]["state"] == "supported"
    assert all(matrix[core]["version_probe"]["state"] == "supported"
               for core in matrix)
    # Native Zagros agent reuses every real CoreManager adapter; legacy Xray
    # transport remains a migration-only path, not the source of this support.
    assert all(matrix[core]["node_support"]["state"] == "supported"
               for core in matrix if core != "pptp")
    assert matrix["pptp"]["node_support"]["state"] == "unsupported"
    assert matrix["pptp"]["routing_source"]["state"] == "supported"
    assert matrix["pptp"]["routing_destination"]["state"] == "supported"
    assert "legacy" in matrix["xray"]["node_support"]["detail"]


def test_runtime_matrix_preserves_not_installed_as_distinct_state() -> None:
    matrix = capability_matrix(installed={"xray"})
    assert matrix["xray"]["inbound"]["state"] == "supported"
    assert matrix["wireguard"]["inbound"]["state"] == "not_installed"
    # Implemented native client support is distinct from runtime installation.
    assert matrix["softether"]["outbound"]["state"] == "not_installed"
    assert matrix["wireguard"]["tls"]["state"] == "not_applicable"


def test_source_target_routing_matrix_preserves_application_vs_tun_boundary() -> None:
    matrix = routing_pair_matrix()
    assert set(matrix) == {
        "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether", "pptp"}
    assert all(set(row) == set(matrix) for row in matrix.values())
    for source in matrix:
        for target in ("xray", "sing-box", "openvpn", "wireguard"):
            assert matrix[source][target]["state"] == "supported"
    assert matrix["xray"]["ssh"]["state"] == "supported"
    assert matrix["sing-box"]["ssh"]["state"] == "supported"
    for source in ("openvpn", "wireguard", "ssh", "softether", "pptp"):
        assert matrix[source]["ssh"]["state"] == "unsupported"
    assert all(matrix[source]["softether"]["state"] == "supported"
               for source in matrix)
    assert all(matrix[source]["pptp"]["state"] == "supported"
               for source in matrix)

    runtime = routing_pair_matrix(installed={"xray", "sing-box"})
    assert runtime["xray"]["ssh"]["state"] == "not_installed"
    assert runtime["xray"]["softether"]["state"] == "not_installed"
