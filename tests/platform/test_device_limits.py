"""Compatibility guard for the v1.0.4 split limit design.

The detailed IP/HWID behavior lives in test_split_ip_hwid_limits.py. This file
keeps the historical module name while proving the retired account-suspension
entry point now delegates to source-IP enforcement.
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_legacy_entry_point_delegates_without_account_suspension(monkeypatch):
    from app.platform import device_limits, ip_limits

    called = []

    async def fake(runtime, *, force=False):
        called.append((runtime, force))
        return {"banned": 1}

    monkeypatch.setattr(ip_limits, "run_once", fake)
    marker = object()
    assert await device_limits.run_once(marker) == {"banned": 1}
    assert called == [(marker, True)]
