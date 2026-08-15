"""Atomic, encrypted, root-private CoreStateStore for a standalone node."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from app.cores.types import CoreState
from app.persistence.cipher import SecretsCipher


class NodeCoreStateStore:
    """Persist lifecycle facts while AES-GCM sealing core-specific settings.

    Core settings may contain VPN admin passwords/private keys. File mode 0600
    is necessary but not sufficient; every settings blob is authenticated with
    AAD bound to its core id. The local data key is generated once and kept in a
    separate 0600 file under the node state directory.
    """

    def __init__(self, root: str) -> None:
        self.path = Path(root) / "cores.json"
        self.key_path = Path(root) / "state.key"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        if not self.key_path.exists():
            part = self.key_path.with_suffix(".part")
            part.write_bytes(os.urandom(32))
            os.chmod(part, 0o600)
            os.replace(part, self.key_path)
        key = self.key_path.read_bytes()
        if len(key) != 32:
            raise ValueError("node state.key must contain exactly 32 bytes")
        os.chmod(self.key_path, 0o600)
        self._cipher = SecretsCipher(key)
        self._lock = asyncio.Lock()

    def _read(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text())
        if not isinstance(raw, dict):
            return {}
        value: dict[str, dict[str, Any]] = {}
        for core_id, record in raw.items():
            if not isinstance(record, dict):
                continue
            if record.get("settings_enc"):
                settings = self._cipher.decrypt_json(
                    str(record["settings_enc"]), aad=f"node-core:{core_id}")
            else:
                # One-time compatibility with pre-encryption development state;
                # the next save rewrites it sealed.
                settings = dict(record.get("settings") or {})
            value[str(core_id)] = {
                "state": record.get("state", CoreState.INSTALLED.value),
                "enabled": bool(record.get("enabled", True)),
                "settings": settings,
            }
        return value

    def _write(self, value: dict[str, dict[str, Any]]) -> None:
        sealed = {
            core_id: {
                "state": record.get("state", CoreState.INSTALLED.value),
                "enabled": bool(record.get("enabled", True)),
                "settings_enc": self._cipher.encrypt_json(
                    dict(record.get("settings") or {}),
                    aad=f"node-core:{core_id}"),
            }
            for core_id, record in value.items()
        }
        part = self.path.with_suffix(".part")
        part.write_text(json.dumps(sealed, sort_keys=True) + "\n")
        os.chmod(part, 0o600)
        os.replace(part, self.path)

    def _load_and_migrate(self) -> dict[str, dict[str, Any]]:
        value = self._read()
        if self.path.exists():
            raw = json.loads(self.path.read_text())
            if isinstance(raw, dict) and any(
                isinstance(record, dict)
                and "settings" in record
                and "settings_enc" not in record
                for record in raw.values()
            ):
                # Remove plaintext immediately on first successful load rather
                # than waiting for an unrelated future lifecycle transition.
                self._write(value)
        return value

    async def load(self) -> dict[str, dict[str, Any]]:
        async with self._lock:
            return await asyncio.to_thread(self._load_and_migrate)

    async def save_state(self, core_id: str, *, state: CoreState,
                         enabled: bool, settings: dict | None = None) -> None:
        async with self._lock:
            value = await asyncio.to_thread(self._read)
            previous = value.get(core_id, {})
            value[core_id] = {
                "state": state.value, "enabled": bool(enabled),
                "settings": settings if settings is not None
                else previous.get("settings", {}),
            }
            await asyncio.to_thread(self._write, value)

    async def remove(self, core_id: str) -> None:
        async with self._lock:
            value = await asyncio.to_thread(self._read)
            value.pop(core_id, None)
            await asyncio.to_thread(self._write, value)
