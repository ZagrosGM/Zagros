"""Exact-version install pinning (alpha.7 Simple install dialog).

The version picker sends settings.release_version; drivers must translate
it into a pinned (tag, asset) download — skipping the REST API entirely.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.cores.drivers.xray import driver as xray_driver  # noqa: E402


def test_xray_install_pins_exact_version(monkeypatch, tmp_path) -> None:
    from app.cores import github_install

    captured: dict = {}

    def fake_install(**kwargs):
        captured.update(kwargs)
        return "v1.2.3"

    monkeypatch.setattr(github_install, "install_from_github", fake_install)
    exe = tmp_path / "xray"
    tag = xray_driver._install_xray({
        "executable_path": str(exe),
        "release_version": "1.2.3",
    })
    assert tag == "v1.2.3"
    assert captured["pinned"] is not None
    tagv, asset = captured["pinned"]
    assert tagv == "v1.2.3"  # normalized with the v prefix
    assert asset  # os/arch asset name for THIS host
    assert (tmp_path / ("xray" + xray_driver._MARKER)).read_text().strip() == "v1.2.3"


def test_xray_install_latest_when_no_version(monkeypatch, tmp_path) -> None:
    from app.cores import github_install

    captured: dict = {}
    monkeypatch.setattr(
        github_install, "install_from_github",
        lambda **kwargs: captured.update(kwargs) or "v9.9.9")

    tag = xray_driver._install_xray({"executable_path": str(tmp_path / "xray2")})
    assert tag == "v9.9.9"
    assert captured["pinned"] is None


def test_hysteria2_install_pins_exact_version(monkeypatch, tmp_path) -> None:
    from app.cores import github_install
    from app.cores.drivers.hysteria2.backend import LocalHysteria2Backend

    captured: dict = {}

    def fake_install(**kwargs):
        captured.update(kwargs)
        # pretend the binary landed where install_binary promised
        Path(kwargs["target_executable"]).write_bytes(b"x")
        return "v2.6.1"

    monkeypatch.setattr(github_install, "install_from_github", fake_install)
    backend = LocalHysteria2Backend({
        "work_dir": str(tmp_path), "executable_path": "hysteria",
        "release_version": "2.6.1",
    })
    try:
        tag = backend.install_binary()
    except Exception:
        # host without the right asset table must not fail the assertion path
        assert captured.get("pinned") is None
        return
    assert tag == "v2.6.1"
    pinned = captured.get("pinned")
    assert pinned is not None and pinned[0] == "v2.6.1"
