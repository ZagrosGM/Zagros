"""Standard CoreAdapter.version() contract across the six product cores."""
from __future__ import annotations

import asyncio

from app.cores.drivers.openvpn import OpenVPNDriver
from app.cores.drivers.singbox import SingBoxDriver
from app.cores.drivers.softether import SoftEtherDriver
from app.cores.drivers.ssh import SSHTunnelDriver
from app.cores.drivers.wireguard import WireGuardDriver
from app.cores.drivers.xray import XrayDriver
from tests.cores.test_openvpn_driver import FakeBackend as FakeOpenVPNBackend
from tests.cores.test_singbox_driver import FakeSingBoxBackend, FakeStatsSource
from tests.cores.test_softether_driver import FakeSEBackend
from tests.cores.test_ssh_driver import FakeSSHBackend
from tests.cores.test_wireguard_driver import FakeWireGuardBackend
from tests.cores.test_xray_driver import FakeBackend as FakeXrayBackend


def test_every_primary_core_has_a_stopped_state_version_probe() -> None:
    xray_backend = FakeXrayBackend()
    sing_backend = FakeSingBoxBackend(running=False)
    openvpn_backend = FakeOpenVPNBackend()
    wireguard_backend = FakeWireGuardBackend()
    ssh_backend = FakeSSHBackend(sshd=False)
    softether_backend = FakeSEBackend()
    ssh_backend.version = lambda: "10.0p2"  # type: ignore[attr-defined]
    softether_backend.version = lambda: "4.44 build 9807"  # type: ignore[attr-defined]

    drivers = [
        (XrayDriver(backend=xray_backend), "1.8.23"),
        (SingBoxDriver(backend=sing_backend, stats=FakeStatsSource()), "1.11.4"),
        (OpenVPNDriver(backend=openvpn_backend), "2.5.9"),
        (WireGuardDriver(backend=wireguard_backend), "v1.0.20210914"),
        (SSHTunnelDriver(backend=ssh_backend), "10.0p2"),
        (SoftEtherDriver(backend=softether_backend), "4.44 build 9807"),
    ]

    async def run() -> None:
        for driver, expected in drivers:
            info = await driver.version()
            assert info.version == expected, driver.metadata.id
            assert info.reason is None

    asyncio.run(run())


def test_unknown_version_always_has_a_reason() -> None:
    backend = FakeSSHBackend(sshd=False)
    driver = SSHTunnelDriver(backend=backend)
    info = asyncio.run(driver.version())
    assert info.version is None
    assert info.display == "unknown"
    assert info.reason and "no version probe" in info.reason


def test_real_adapter_parsers_extract_wireguard_ssh_and_softether_versions(monkeypatch, tmp_path) -> None:
    import subprocess

    from app.cores.drivers.singbox.backend import LocalSingBoxBackend
    from app.cores.drivers.softether.backend import LocalSoftEtherBackend
    from app.cores.drivers.ssh.backend import LocalSystemSSHBackend
    from app.cores.drivers.wireguard.backend import LocalWireGuardBackend

    singbox = LocalSingBoxBackend({
        "work_dir": str(tmp_path / "sing-box"),
        "executable_path": "sing-box",
    })
    monkeypatch.setattr(
        "app.cores.drivers.singbox.backend.subprocess.check_output",
        lambda *a, **k: "sing-box version v1.12.4\n\nEnvironment: go1.23.1 linux/amd64\n",
    )
    assert singbox.version() == "1.12.4"

    wireguard = LocalWireGuardBackend({
        "interface": "wg-test", "work_dir": str(tmp_path / "wireguard")})
    monkeypatch.setattr(
        wireguard, "_run",
        lambda _argv, **_kw: (
            "wireguard-tools v1.0.20210914 - "
            "https://git.zx2c4.com/wireguard-tools/\n"),
    )
    assert wireguard.version() == "v1.0.20210914"

    ssh = LocalSystemSSHBackend({"work_dir": "/tmp/zagros-version-test"})
    monkeypatch.setattr(ssh, "_sshd_bin", lambda: "/usr/sbin/sshd")
    monkeypatch.setattr(
        "app.cores.drivers.ssh.backend.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 0, "", "OpenSSH_10.0p2 Debian-7, OpenSSL 3.5.6"),
    )
    assert ssh.version() == "10.0p2"

    softether = LocalSoftEtherBackend({})
    monkeypatch.setattr(softether, "vpncmd_binary", lambda: "/runtime/vpncmd")
    monkeypatch.setattr(
        "app.cores.drivers.softether.backend.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 0, "Version 4.44 Build 9807   (English)\n", ""),
    )
    assert softether.version() == "4.44 build 9807"
