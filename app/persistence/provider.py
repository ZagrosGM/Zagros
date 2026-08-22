"""SQL-backed data providers for the Client API and Subscription Portal.

Bridges the hexagonal ports onto SQLAlchemy repositories + the live
CoreManager. Only accounts of **enabled, loaded** cores are delivered —
a stopped/uninstalled core's material is honestly skipped (the portal
shows the rest; the app simply doesn't list that core).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from app.cores.manager import CoreManager
from app.cores.types import UserAccount
from app.persistence.repositories import SQLQuotaStore, UserRepository
from app.portal.models import PortalUserView
from app.portal.service import SubscriptionContext

_ONLINE_GRACE_SECONDS = 90


def _user_record_view(row, used: int) -> dict[str, Any]:
    online = False
    if row.online_at is not None:
        age = (datetime.now(timezone.utc) - row.online_at).total_seconds()
        online = age < _ONLINE_GRACE_SECONDS
    return {
        "id": row.id,
        "username": row.username,
        "status": row.status,
        "expire_at": row.expire_at,
        "online": online,
        "app_username": row.app_username,
        "app_password_hash": row.app_password_hash,
        "client_auth_mode": row.client_auth_mode,
        "used_bytes": used,
        "data_limit_bytes": row.data_limit_bytes,
        "download_limit_mbps": int(row.download_limit_mbps or 0),
        "upload_limit_mbps": int(row.upload_limit_mbps or 0),
    }


class SQLOnlineDataAdapter:
    """Implements ClientDataProvider + PortalDataProvider against SQL + live cores."""

    def __init__(self, session_factory, users: UserRepository,
                 quota: SQLQuotaStore, core_manager: CoreManager) -> None:
        self._sf = session_factory
        self._users = users
        self._quota = quota
        self._manager = core_manager

    # ---------------- shared identity views ---------------- #
    async def get_user_record(self, user_id: int) -> dict[str, Any] | None:
        def _sync() -> dict[str, Any] | None:
            row = self._users.get_user(user_id)
            return None if row is None else row
        row = await asyncio.to_thread(_sync)
        if row is None:
            return None
        entry = await self._quota.get(user_id)
        return _user_record_view(row, entry.total_bytes if entry else 0)

    async def find_user_by_app_username(self, app_username: str) -> dict[str, Any] | None:
        def _sync():
            from sqlalchemy import select

            from app.persistence.models import UserModel
            with self._sf() as s:
                row = s.execute(
                    select(UserModel).where(UserModel.app_username == app_username)
                ).scalar_one_or_none()
                if row is not None:
                    s.expunge(row)
                return row
        row = await asyncio.to_thread(_sync)
        if row is None:
            return None
        entry = await self._quota.get(row.id)
        return _user_record_view(row, entry.total_bytes if entry else 0)

    async def save_app_credentials(self, user_id: int, app_username: str,
                                   app_password_hash: str) -> None:
        await asyncio.to_thread(
            self._users.set_app_credentials, user_id, app_username, app_password_hash
        )

    async def get_usage(self, user_id: int) -> tuple[int, int | None]:
        def _limit() -> int | None:
            row = self._users.get_user(user_id)
            return None if row is None else row.data_limit_bytes
        entry = await self._quota.get(user_id)
        limit = await asyncio.to_thread(_limit)
        return (entry.total_bytes if entry else 0), limit

    # ---------------- account materialization ---------------- #
    def _materialize(self, user_id: int):
        """(driver, UserAccount) pairs for enabled & live cores only."""
        pairs = []
        rows = self._users.accounts_of(user_id, decrypt=True)
        for row in rows:
            core_id = row["core_id"]
            if not self._manager.is_enabled(core_id):
                continue
            try:
                driver = self._manager.get(core_id)
            except Exception:  # noqa: BLE001 — core not loaded: skip honestly
                continue
            account = UserAccount(
                user_id=user_id,
                username="",
                account_id=row["account_id"],
                protocol=row["protocol"],
                enabled=row["enabled"],
                settings=row["settings"],
            )
            pairs.append((driver, account))
        return pairs

    async def get_core_accounts(self, user_id: int):
        return await asyncio.to_thread(self._materialize, user_id)

    # ---------------- portal ---------------- #
    async def get_subscription_context(self, user_id: int):
        record = await self.get_user_record(user_id)
        if record is None:
            return None
        pairs = await self.get_core_accounts(user_id)
        username = str(record["username"])
        # enrich account identities for display
        for _, account in pairs:
            account.username = username
        view = PortalUserView(
            user_id=user_id,
            username=username,
            status=record["status"],
            used_bytes=record["used_bytes"],
            data_limit_bytes=record["data_limit_bytes"],
            expire_at=record["expire_at"],
            online=record["online"],
            client_auth_mode=record.get("client_auth_mode"),
        )
        return SubscriptionContext(user=view, accounts=pairs)
