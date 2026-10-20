"""A version chosen at update time must reach the installer.

Every driver installs from a pin held in its settings, except pptp which is
pinned by design and refuses anything else. ``update(version)`` is the one
call that is handed a version at call time — the panel's version picker and
the node's lifecycle both go through it — and two drivers used to drop that
argument on the floor, which made "change version" a button that did nothing.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(
    not importlib.util.find_spec("sqlalchemy"),
    reason="full panel requirements not installed")


def _paths(tmp_path, core):
    """Every path the driver would otherwise default to /var/lib/zagros."""
    base = tmp_path / "cores" / core
    return {
        "executable_path": str(base / "bin" / core),
        "assets_path": str(base / "assets"),
        "config_path": str(base / f"{core}_config.json"),
        "work_dir": str(base),
    }


def _xray_driver(monkeypatch, settings):
    from app.cores.drivers.xray import driver as module

    seen: dict = {}

    def fake_install(target_settings):
        seen["settings"] = dict(target_settings)
        return "v9.9.9"

    monkeypatch.setattr(module, "_install_xray", fake_install)
    return module.XrayDriver(settings), seen


def test_xray_update_pins_the_requested_release(monkeypatch, tmp_path):
    driver, seen = _xray_driver(monkeypatch, _paths(tmp_path, "xray"))

    version = asyncio.run(driver.update("v1.2.3"))

    assert version == "v9.9.9"
    assert seen["settings"].get("release_version") == "v1.2.3"


def test_xray_update_without_a_version_keeps_the_settings_pin(monkeypatch, tmp_path):
    """No argument means 'whatever this core is pinned to' — not 'unpinned'."""
    settings = _paths(tmp_path, "xray")
    settings["release_version"] = "26.3.27"
    driver, seen = _xray_driver(monkeypatch, settings)

    asyncio.run(driver.update())

    assert seen["settings"].get("release_version") == "26.3.27"


def test_xray_update_does_not_mutate_the_driver_settings(monkeypatch, tmp_path):
    """A one-off pin must not leak into the core's stored configuration."""
    driver, seen = _xray_driver(monkeypatch, _paths(tmp_path, "xray"))

    asyncio.run(driver.update("v1.2.3"))

    assert "release_version" not in driver.settings
    assert seen["settings"]["release_version"] == "v1.2.3"


def test_singbox_update_forwards_the_version_to_the_installer(monkeypatch, tmp_path):
    from app.cores.drivers.singbox import driver as module

    seen: dict = {}

    class FakeBackend:
        def __init__(self, settings):
            self.settings = settings

        def install_binary(self, version=None):
            seen["version"] = version
            return "v1.2.3"

        def version(self):
            return "v1.2.3"

    import app.cores.drivers.singbox.backend as backend_module

    monkeypatch.setattr(backend_module, "LocalSingBoxBackend", FakeBackend)
    driver = module.SingBoxDriver(_paths(tmp_path, "singbox"))

    assert asyncio.run(driver.update("1.12.4")) == "v1.2.3"
    assert seen["version"] == "1.12.4"

    asyncio.run(driver.update())
    assert seen["version"] is None


def test_pptp_refuses_a_version_it_is_not_pinned_to(monkeypatch, tmp_path):
    """A driver that cannot honour a pin must say so, not pretend to."""
    from app.cores.drivers.pptp import driver as module

    monkeypatch.setattr(module.PptpDriver, "_backend_for",
                        lambda self: None, raising=False)
    driver = module.PptpDriver(_paths(tmp_path, "pptp"))
    with pytest.raises(Exception, match="pinned"):
        asyncio.run(driver.update("9.9.9"))
