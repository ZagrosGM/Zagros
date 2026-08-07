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

import pytest

from app.cores.exceptions import CoreError


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
