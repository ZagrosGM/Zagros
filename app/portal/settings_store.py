"""Portal settings persistence (port + in-memory implementation).

The SQL-backed implementation lives in ``app.persistence.repositories``
and satisfies the same protocol; the service layer depends only on this
port (Dependency Inversion).
"""
from __future__ import annotations

import asyncio
from typing import Protocol

from app.portal.models import PortalSettings


class SettingsStore(Protocol):
    async def get_portal_settings(self) -> PortalSettings: ...
    async def save_portal_settings(self, settings: PortalSettings) -> PortalSettings: ...


class InMemorySettingsStore:
    """Process-local settings store (tests, single-node dev deployments)."""

    def __init__(self, initial: PortalSettings | None = None) -> None:
        self._settings = initial or PortalSettings()
        self._lock = asyncio.Lock()

    async def get_portal_settings(self) -> PortalSettings:
        async with self._lock:
            return self._settings.model_copy(deep=True)

    async def save_portal_settings(self, settings: PortalSettings) -> PortalSettings:
        async with self._lock:
            self._settings = settings.model_copy(deep=True)
            return self._settings.model_copy(deep=True)
