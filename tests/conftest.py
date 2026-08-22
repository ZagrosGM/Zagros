"""Shared fixtures for the suite.

``no_real_core_binary_installs``
--------------------------------
Since alpha.7 the xray driver **self-heals a missing binary on start** (field
feedback: "Start" died with ENOENT on fresh VPS installs). Exactly right in
production — but inside app-booting tests it means any flow that starts the
built-in xray core on a networked machine with a writable target downloads
~30 MB from GitHub and launches a real daemon: flaky (outbound network in
CI), messy (leftover processes), slow.

The fixture is defined here once and applied **autouse only where whole-app
boots happen** (tests/adminapi, tests/platform) via thin wrappers in those
directories' conftest.py. tests/cores keeps the RAW installer on purpose:
``tests/cores/test_release_pinning.py`` verifies the pin resolution logic
with a stubbed network layer and must see the real ``_install_xray``. Real
end-to-end installs stay covered by the real-binary E2E suite; the unit-level
self-heal contract is pinned by tests/platform/test_alpha7_fixes.py, which
monkeypatches ``_install_xray`` itself (its patch applies after this fixture
and therefore wins).
"""
from __future__ import annotations

import os
from pathlib import Path

# Production defaults live on the mounted /var/lib/zagros tree. Unit tests run
# unprivileged and must never seed host state, so bind the legacy singleton to
# the repository fixture before importing any app module.
_ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("XRAY_JSON", str(_ROOT / "xray_config.json"))
os.environ.setdefault("XRAY_EXECUTABLE_PATH", str(_ROOT / ".test-xray"))
os.environ.setdefault("XRAY_ASSETS_PATH", str(_ROOT / ".test-xray-assets"))
# The production limiter persists fail-closed/runtime state under
# /var/lib/zagros. GitHub-hosted pytest runs unprivileged, so give the suite a
# process-unique writable state file before app.platform.bandwidth is imported.
_TEST_BANDWIDTH_STATE = Path("/tmp") / f"zagros-bandwidth-test-{os.getpid()}.json"
os.environ.setdefault("ZAGROS_BANDWIDTH_STATE_PATH", str(_TEST_BANDWIDTH_STATE))

import pytest

from app.cores.exceptions import CoreError


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_bandwidth_state():
    _TEST_BANDWIDTH_STATE.unlink(missing_ok=True)
    try:
        yield
    finally:
        _TEST_BANDWIDTH_STATE.unlink(missing_ok=True)
        _TEST_BANDWIDTH_STATE.with_suffix(".part").unlink(missing_ok=True)


def _blocked_install(settings: dict):  # pragma: no cover - trivial guard
    raise CoreError(
        "real core-binary downloads are blocked in the test suite; "
        "stub _install_xray in the test itself (see test_alpha7_fixes.py)"
    )


@pytest.fixture
def no_real_core_binary_installs(monkeypatch):
    try:
        import app.cores.drivers.xray.driver as xray_driver
    except Exception:  # noqa: BLE001 - module-graph surgery in some tests
        yield
        return
    monkeypatch.setattr(xray_driver, "_install_xray", _blocked_install)
    yield
