"""Client API persistence ports + in-memory implementations.

* Refresh tokens: opaque, stored SHA-256 hashed, rotatable, revocable.
* Connect tokens: one-time, 30 s TTL; the server ephemeral X25519 private
  key lives ONLY in this store next to the token (never logged, never in the
  audit record). SQL implementations live in ``app.persistence`` — refresh
  tokens survive restarts; connect tokens are in-memory by design because
  they die within 30 s anyway.
"""
from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from app.cores.base import BaseCoreDriver
from app.cores.types import UserAccount


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------- #
# data provider port (users / accounts / quota views)
# --------------------------------------------------------------------- #

class ClientDataProvider(Protocol):
    """Hexagonal port joining the client API with the platform core."""

    async def get_user_record(self, user_id: int) -> dict[str, Any] | None:
        """Identity view: id/username/status/expire_at/app credential fields."""

    async def find_user_by_app_username(self, app_username: str) -> dict[str, Any] | None:
        """Reverse lookup for login (uniform-cost even when missing)."""

    async def save_app_credentials(self, user_id: int, app_username: str,
                                   app_password_hash: str) -> None: ...

    async def get_core_accounts(self, user_id: int) -> list[tuple[BaseCoreDriver, UserAccount]]: ...

    async def get_usage(self, user_id: int) -> tuple[int, int | None]:
        """(used_bytes, data_limit_bytes)."""


# --------------------------------------------------------------------- #
# refresh tokens
# --------------------------------------------------------------------- #

@dataclass
class RefreshTokenRecord:
    user_id: int
    token_hash: str
    expires_at: datetime
    revoked: bool = False
    created_at: datetime = field(default_factory=_utcnow)
    rotated_to: str | None = None


class RefreshTokenStore(Protocol):
    async def save(self, user_id: int, token_hash: str, expires_at: datetime) -> None: ...
    async def get(self, token_hash: str) -> RefreshTokenRecord | None: ...
    async def revoke(self, token_hash: str, *, rotated_to: str | None = None) -> None: ...
    async def revoke_all_for_user(self, user_id: int) -> None: ...


class InMemoryRefreshTokenStore:
    def __init__(self) -> None:
        self._rows: dict[str, RefreshTokenRecord] = {}
        self._lock = asyncio.Lock()

    async def save(self, user_id: int, token_hash: str, expires_at: datetime) -> None:
        async with self._lock:
            self._rows[token_hash] = RefreshTokenRecord(user_id, token_hash, expires_at)

    async def get(self, token_hash: str) -> RefreshTokenRecord | None:
        async with self._lock:
            row = self._rows.get(token_hash)
            return None if row is None else RefreshTokenRecord(**vars(row))

    async def revoke(self, token_hash: str, *, rotated_to: str | None = None) -> None:
        async with self._lock:
            if token_hash in self._rows:
                self._rows[token_hash].revoked = True
                self._rows[token_hash].rotated_to = rotated_to

    async def revoke_all_for_user(self, user_id: int) -> None:
        async with self._lock:
            for row in self._rows.values():
                if row.user_id == user_id:
                    row.revoked = True


# --------------------------------------------------------------------- #
# connect tokens (one-time, short-lived)
# --------------------------------------------------------------------- #

@dataclass
class ConnectTokenRecord:
    user_id: int
    core_id: str
    token_hash: str
    expires_at: datetime
    consumed_at: datetime | None = None

    @property
    def consumed(self) -> bool:
        return self.consumed_at is not None


class ConnectTokenStore(Protocol):
    async def save(self, record: ConnectTokenRecord) -> None: ...
    async def get(self, token_hash: str) -> ConnectTokenRecord | None: ...
    async def mark_consumed(self, token_hash: str, when: datetime) -> bool:
        """Atomically consume; False when already consumed/unknown."""


class InMemoryConnectTokenStore:
    def __init__(self) -> None:
        self._rows: dict[str, ConnectTokenRecord] = {}
        self._lock = asyncio.Lock()

    async def save(self, record: ConnectTokenRecord) -> None:
        async with self._lock:
            self._rows[record.token_hash] = record

    async def get(self, token_hash: str) -> ConnectTokenRecord | None:
        async with self._lock:
            return self._rows.get(token_hash)

    async def mark_consumed(self, token_hash: str, when: datetime) -> bool:
        async with self._lock:
            row = self._rows.get(token_hash)
            if row is None or row.consumed:
                return False
            row.consumed_at = when
            return True


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
