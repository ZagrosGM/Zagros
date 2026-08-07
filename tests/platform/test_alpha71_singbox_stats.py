"""alpha.7.1 regression tests — sing-box stats root fixes.

Field report: core RUNNING yet status showed the raw socket error
"sing-box stats API unreachable: ... Connection refused" (127.0.0.1:19091).
Root causes pinned here:

a) NO official sing-box build ships the v2ray_api tag (verified upstream
   1.9.7→1.13.16) → the rendered config never carried a listener, yet the
   driver still DIALED 19091 on every usage tick and surfaced the raw error.
   Fix: Zagros-vendored builds (checksum-verified) + stats short-circuit.
b) the raw socket error overwrote the coherent degrade message.
"""
from __future__ import annotations

import hashlib
import io
import tarfile

import pytest

from app.cores.exceptions import CoreError


def _driver(*, probe: bool, failing_stats: bool = False):
    from app.cores.drivers.singbox.driver import SingBoxDriver

    class FakeBackend:
        def probe_v2ray_support(self):
            return probe

    class FakeStats:
        def query_user_counters(self):
            if failing_stats:
                raise OSError("failed to connect to all addresses; last error: "
                              "UNKNOWN: ipv4:127.0.0.1:19091: Connection refused")
            return {}

    return SingBoxDriver(
        {"listen": "0.0.0.0", "ports": {"vless": 443},
         "stats_enabled": True, "stats_api": "127.0.0.1:19091"},
        backend=FakeBackend(), stats=FakeStats(),
    )


def test_stats_shortcircuits_when_build_lacks_api():
    """Diagging a listener that was never rendered must not leak raw socket
    noise; the coherent degrade message set at render survives."""
    import asyncio

    driver = _driver(probe=False)
    driver._accounts["u"] = type("A", (), {
        "protocol": "vless", "account_id": "u", "enabled": True,
        "settings": {"id": "11111111-2222-3333-4444-555555555555"}})()
    driver.render_config()  # sets the honest degrade reason
    records = asyncio.run(driver.get_usage())
    assert records == []
    assert driver._stats_error
    assert "lacks the v2ray_api build tag" in driver._stats_error
    assert "refused" not in driver._stats_error.lower()
    assert "unreachable" not in driver._stats_error.lower()


def test_stats_error_names_listener_and_restart_when_build_supports_api():
    """Probe-positive build whose listener died: the message must name the
    listener address and the remedy (restart), not a bare socket error."""
    import asyncio

    driver = _driver(probe=True, failing_stats=True)
    assert driver._stats_ready() is True
    with pytest.raises(Exception):
        asyncio.run(driver.get_usage())
    assert "stats listener not answering on 127.0.0.1:19091" in driver._stats_error
    assert "restart" in driver._stats_error


def test_stats_ready_false_when_accounting_disabled():
    driver = _driver(probe=True)
    driver.settings["stats_enabled"] = False
    assert driver._stats_ready() is False


# --------------------------------------------------------------------- #
# vendored stats-enabled install path
# --------------------------------------------------------------------- #

def _backend(tmp_path, monkeypatch):
    import app.cores.drivers.singbox.backend as sb_backend

    backend = sb_backend.LocalSingBoxBackend({
        "executable_path": str(tmp_path / "sing-box"),
        "work_dir": str(tmp_path),
        "config_path": str(tmp_path / "sing-box.json"),
        "release_version": "1.12.4",
    })
    captured: dict = {}

    def fake_install(**kw):
        captured.update(kw)
        # simulate a downloaded binary landing on disk
        from app.cores.github_install import _install_bytes
        _install_bytes(b"fake-sing-box-binary", kw["target_executable"])
        return kw["pinned"][0] if kw.get("pinned") else "latest"

    monkeypatch.setattr("app.cores.github_install.install_from_github", fake_install)
    return backend, captured


def test_install_prefers_vendored_stats_build_and_verifies_checksum(tmp_path, monkeypatch):
    import app.cores.drivers.singbox.backend as sb_backend
    from app.cores.github_install import host_arch, host_os

    monkeypatch.setattr(sb_backend, "_vendored_checksum",
                        lambda version, asset: "deadbeef" * 8)
    backend, captured = _backend(tmp_path, monkeypatch)
    monkeypatch.setattr(backend, "probe_v2ray_support", lambda: True)
    backend.install_binary()

    asset = f"sing-box-1.12.4-v2rayapi-{host_os()}-{host_arch()}.tar.gz"
    assert captured["repo"] == "ZagrosGM/Zagros"
    assert captured["pinned"] == ("vendor-singbox-1.12.4", asset)
    assert captured["sha256"] == "deadbeef" * 8


def test_vendored_install_refuses_when_probe_fails(tmp_path, monkeypatch):
    import app.cores.drivers.singbox.backend as sb_backend

    monkeypatch.setattr(sb_backend, "_vendored_checksum", lambda v, a: "ab" * 32)
    backend, _ = _backend(tmp_path, monkeypatch)
    monkeypatch.setattr(backend, "probe_v2ray_support", lambda: False)
    with pytest.raises(CoreError, match="vendor-build bug"):
        backend.install_binary()


def test_install_falls_back_to_official_when_no_vendored_asset(tmp_path, monkeypatch):
    import app.cores.drivers.singbox.backend as sb_backend
    from app.cores.github_install import host_arch, host_os

    monkeypatch.setattr(sb_backend, "_vendored_checksum", lambda v, a: None)
    backend, captured = _backend(tmp_path, monkeypatch)
    backend.install_binary()
    assert captured["repo"] == "SagerNet/sing-box"
    assert captured["pinned"] == ("v1.12.4",
                                  f"sing-box-1.12.4-{host_os()}-{host_arch()}.tar.gz")


def test_vendored_checksum_parses_sha256sums(tmp_path, monkeypatch):
    import app.cores.drivers.singbox.backend as sb_backend

    payload = (f"{'aa'*32}  sing-box-1.12.4-v2rayapi-linux-amd64.tar.gz\n"
               f"{'bb'*32}  sing-box-1.12.4-v2rayapi-linux-arm64.tar.gz\n")

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=0: Resp(payload.encode()))
    got = sb_backend._vendored_checksum("1.12.4", "sing-box-1.12.4-v2rayapi-linux-amd64.tar.gz")
    assert got == "aa" * 32
    assert sb_backend._vendored_checksum("1.12.4", "missing.tar.gz") is None


# --------------------------------------------------------------------- #
# raw download integrity (github_install sha256)
# --------------------------------------------------------------------- #

def _tgz(member: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(member)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_install_from_github_verifies_sha256_of_payload(monkeypatch, tmp_path):
    from app.cores.github_install import install_from_github

    blob = _tgz("pkg/sing-box", b"\x7fELF-fake-binary")

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr("app.cores.github_install._open",
                        lambda url, timeout: Resp(blob))
    target = str(tmp_path / "sing-box")
    ok = install_from_github(
        repo="ZagrosGM/Zagros", target_executable=target,
        asset_match=lambda n: True, member_match=lambda m: m.endswith("sing-box"),
        pinned=("vendor-singbox-1.12.4", "asset.tar.gz"),
        sha256=hashlib.sha256(blob).hexdigest(),
    )
    assert ok == "vendor-singbox-1.12.4"
    assert open(target, "rb").read() == b"\x7fELF-fake-binary"

    with pytest.raises(CoreError, match="checksum mismatch"):
        install_from_github(
            repo="ZagrosGM/Zagros", target_executable=target,
            asset_match=lambda n: True, member_match=lambda m: m.endswith("sing-box"),
            pinned=("vendor-singbox-1.12.4", "asset.tar.gz"),
            sha256="00" * 32,
        )
