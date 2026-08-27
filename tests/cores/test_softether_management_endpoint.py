"""Regression coverage for durable SoftEther management endpoint selection."""
from app.cores.drivers.softether import LocalSoftEtherBackend, SoftEtherDriver


def test_default_management_endpoint_uses_native_listener_not_https_port():
    driver = SoftEtherDriver()
    assert driver.settings["server"] == "localhost:5555"
    assert driver._backend.server == "localhost:5555"


def test_legacy_bare_loopback_endpoint_migrates_to_saved_native_port():
    backend = LocalSoftEtherBackend({
        "server": "localhost", "native_port": 6543, "admin_password": "",
    })
    assert backend.server == "localhost:6543"


def test_explicit_remote_and_explicit_loopback_endpoints_are_preserved():
    assert LocalSoftEtherBackend({"server": "vpn.example:992"}).server == "vpn.example:992"
    assert LocalSoftEtherBackend({"server": "127.0.0.1:5555"}).server == "127.0.0.1:5555"


def test_ipv6_loopback_is_bracketed_before_native_port_is_added():
    assert LocalSoftEtherBackend({"server": "::1", "native_port": 5555}).server == "[::1]:5555"
