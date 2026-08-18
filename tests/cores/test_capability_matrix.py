"""Cross-core capability matrix is complete, typed and honest."""
from __future__ import annotations

from app.cores.matrix import FEATURES, capability_matrix, routing_pair_matrix


def test_matrix_has_every_required_feature_for_six_primary_cores() -> None:
    matrix = capability_matrix()
    assert set(matrix) == {
        "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether"}
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
    assert matrix["softether"]["outbound"]["state"] == "unsupported"
    # SoftEther VPN Server is a real routed-TAP source, not an outbound. The
    # four source→TUN cells are testable/supported; every →SoftEther cell stays
    # unsupported until a separately managed vpnclient adapter exists.
    assert matrix["softether"]["routing_source"]["state"] == "supported"
    assert matrix["softether"]["routing_destination"]["state"] == "unsupported"
    assert matrix["softether"]["tun"]["state"] == "unsupported"
    assert all(matrix[core]["version_probe"]["state"] == "supported"
               for core in matrix)
    # Native Zagros agent reuses every real CoreManager adapter; legacy Xray
    # transport remains a migration-only path, not the source of this support.
    assert all(matrix[core]["node_support"]["state"] == "supported"
               for core in matrix)
    assert "legacy" in matrix["xray"]["node_support"]["detail"]


def test_runtime_matrix_preserves_not_installed_as_distinct_state() -> None:
    matrix = capability_matrix(installed={"xray"})
    assert matrix["xray"]["inbound"]["state"] == "supported"
    assert matrix["wireguard"]["inbound"]["state"] == "not_installed"
    # Product limitations do not become misleading package problems.
    assert matrix["softether"]["outbound"]["state"] == "unsupported"
    assert matrix["wireguard"]["tls"]["state"] == "not_applicable"


def test_source_target_routing_matrix_preserves_application_vs_tun_boundary() -> None:
    matrix = routing_pair_matrix()
    assert set(matrix) == {"xray", "sing-box", "openvpn", "wireguard", "ssh", "softether"}
    assert all(set(row) == set(matrix) for row in matrix.values())
    for source in matrix:
        for target in ("xray", "sing-box", "openvpn", "wireguard"):
            assert matrix[source][target]["state"] == "supported"
    assert matrix["xray"]["ssh"]["state"] == "supported"
    assert matrix["sing-box"]["ssh"]["state"] == "supported"
    for source in ("openvpn", "wireguard", "ssh", "softether"):
        assert matrix[source]["ssh"]["state"] == "unsupported"
    assert all(matrix[source]["softether"]["state"] == "unsupported"
               for source in matrix)

    runtime = routing_pair_matrix(installed={"xray", "sing-box"})
    assert runtime["xray"]["ssh"]["state"] == "not_installed"
    # Unsupported architecture remains unsupported when absent.
    assert runtime["xray"]["softether"]["state"] == "unsupported"
