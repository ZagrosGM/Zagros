"""adminapi tests boot the full app — keep their core starts offline.

See tests/conftest.py for why real binary downloads are blocked here.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _auto_no_real_core_binary_installs(no_real_core_binary_installs):
    yield
