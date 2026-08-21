"""SQL repository adapters implementing the platform's hexagonal ports.

Every port from ``app.cores`` (CoreStateStore, QuotaStore, DeviceStore,
SessionStore), ``app.portal`` (SettingsStore) and ``app.clientapi``
(RefreshTokenStore) gets a production SQL implementation here, plus the
admin-facing repositories the Admin API builds on. All adapters are
synchronous SQLAlchemy executed inside ``asyncio.to_thread`` (see
``app.persistence.base`` for the rationale).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Protocol

from sqlalchemy import delete, desc, select, update

from app.cores.devices import DeviceInfo
from app.cores.quota import QuotaEntry
from app.cores.sessions import SessionRecord
from app.cores.types import CoreState, UsageRecord
from app.portal.models import PortalSettings
from app.persistence.cipher import SecretsCipher
from app.persistence.models import (
    CoreHostModel,
    CoreModel,
    DeviceModel,
    DeviceSessionModel,
    RefreshTokenModel,
    SettingModel,
    UsageBaselineModel,
    UsageRecordModel,
    UserCoreAccountModel,
    UserModel,
    UserUsageModel,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------- #
# cores (CoreStateStore port)
# --------------------------------------------------------------------- #

class SQLCoreStateStore:
    """Implements app.cores.manager.CoreStateStore."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    def _load_sync(self) -> dict[str, dict[str, Any]]:
        with self._sf() as s:
            rows = s.execute(select(CoreModel)).scalars().all()
            return {
                r.core_id: {
                    "state": r.state, "enabled": r.enabled,
                    "settings": dict(r.settings_json or {}),
                }
                for r in rows
            }

    async def load(self) -> dict[str, dict[str, Any]]:
        return await asyncio.to_thread(self._load_sync)

    def _save_sync(self, core_id: str, *, state: CoreState, enabled: bool,
                   settings: dict[str, Any] | None) -> None:
        with self._sf() as s:
            row = s.execute(
                select(CoreModel).where(CoreModel.core_id == core_id)
            ).scalar_one_or_none()
            if row is None:
                row = CoreModel(core_id=core_id, state=state.value, enabled=enabled,
                                settings_json=settings or {})
                s.add(row)
            else:
                row.state = state.value
                row.enabled = enabled
                if settings is not None:
                    existing = dict(row.settings_json or {})
                    existing.update(settings)
                    row.settings_json = existing
            s.commit()

    async def save_state(self, core_id: str, *, state: CoreState, enabled: bool,
                         settings: dict[str, Any] | None = None) -> None:
        await asyncio.to_thread(
            self._save_sync, core_id, state=state, enabled=enabled, settings=settings
        )

    async def remove(self, core_id: str) -> None:
        def _sync() -> None:
            with self._sf() as s:
                s.execute(delete(CoreModel).where(CoreModel.core_id == core_id))
                s.commit()
        await asyncio.to_thread(_sync)


# --------------------------------------------------------------------- #
# unified quota (QuotaStore port) + usage journal + baselines
# --------------------------------------------------------------------- #

class SQLQuotaStore:
    """Implements app.cores.quota.QuotaStore on top of ``user_usage``."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def get(self, user_id: int) -> QuotaEntry | None:
        def _sync() -> QuotaEntry | None:
            with self._sf() as s:
                row = s.get(UserUsageModel, user_id)
                if row is None:
                    return None
                return QuotaEntry(user_id=row.user_id, uplink_bytes=row.uplink_bytes,
                                  downlink_bytes=row.downlink_bytes)
        return await asyncio.to_thread(_sync)

    async def add(self, user_id: int, uplink: int, downlink: int) -> QuotaEntry:
        def _sync() -> QuotaEntry:
            # Race-safe: a plain get-then-increment loses concurrent folds
            # (last writer wins). The increment happens IN SQL (single
            # statement, DB write lock) and the create-vs-increment race is
            # resolved by retrying: the loser's INSERT hits the UNIQUE pk and
            # the next attempt takes the UPDATE path. Exactly-once per call.
            from sqlalchemy import update
            from sqlalchemy.exc import IntegrityError

            for _attempt in range(4):
                try:
                    with self._sf() as s:
                        res = s.execute(
                            update(UserUsageModel)
                            .where(UserUsageModel.user_id == user_id)
                            .values(
                                uplink_bytes=UserUsageModel.uplink_bytes + uplink,
                                downlink_bytes=UserUsageModel.downlink_bytes + downlink,
                            )
                        )
                        if res.rowcount == 0:
                            s.add(UserUsageModel(
                                user_id=user_id, uplink_bytes=uplink,
                                downlink_bytes=downlink))
                        s.commit()
                        row = s.get(UserUsageModel, user_id)
                        return QuotaEntry(
                            user_id=row.user_id, uplink_bytes=row.uplink_bytes,
                            downlink_bytes=row.downlink_bytes)
                except IntegrityError:  # concurrent INSERT won — retry as UPDATE
                    continue
            raise RuntimeError("quota add failed repeatedly under contention")  # unreachable-ish
        return await asyncio.to_thread(_sync)

    async def all(self) -> list[QuotaEntry]:
        def _sync() -> list[QuotaEntry]:
            with self._sf() as s:
                return [
                    QuotaEntry(user_id=r.user_id, uplink_bytes=r.uplink_bytes,
                               downlink_bytes=r.downlink_bytes)
                    for r in s.execute(select(UserUsageModel)).scalars().all()
                ]
        return await asyncio.to_thread(_sync)

    async def reset(self, user_id: int) -> None:
        def _sync() -> None:
            with self._sf() as s:
                row = s.get(UserUsageModel, user_id)
                if row is not None:
                    row.uplink_bytes = 0
                    row.downlink_bytes = 0
                s.commit()
        await asyncio.to_thread(_sync)


class BaselineStore(Protocol):
    """Port for persistent driver-counter baselines (exactly-once deltas)."""

    async def get_many(self, keys: list[str]) -> dict[str, tuple[int, int]]: ...
    async def set_many(self, values: dict[str, tuple[int, int]]) -> None: ...
    async def drop(self, key: str) -> None: ...


class SQLBaselineStore:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def get_many(self, keys: list[str]) -> dict[str, tuple[int, int]]:
        if not keys:
            return {}
        def _sync() -> dict[str, tuple[int, int]]:
            with self._sf() as s:
                rows = s.execute(
                    select(UsageBaselineModel).where(UsageBaselineModel.key.in_(keys))
                ).scalars().all()
                return {r.key: (r.uplink_base, r.downlink_base) for r in rows}
        return await asyncio.to_thread(_sync)

    async def get_prefix(self, prefix: str) -> dict[str, tuple[int, int]]:
        """Read provider sub-keys (for example Xray's per-node cursors)."""
        def _sync() -> dict[str, tuple[int, int]]:
            with self._sf() as s:
                rows = s.execute(
                    select(UsageBaselineModel).where(
                        UsageBaselineModel.key.like(prefix + "%")
                    )
                ).scalars().all()
                return {r.key: (r.uplink_base, r.downlink_base) for r in rows}
        return await asyncio.to_thread(_sync)

    async def set_many(self, values: dict[str, tuple[int, int]]) -> None:
        if not values:
            return

        def _sync() -> None:
            # Race-safe per-key upsert: under concurrent passes a naive
            # SELECT→INSERT hits the UNIQUE key; retry then takes the UPDATE
            # branch. Baselines are cumulative snapshots — convergent writes.
            from sqlalchemy.exc import IntegrityError

            for key, (up, down) in values.items():
                for _attempt in range(4):
                    try:
                        with self._sf() as s:
                            row = s.get(UsageBaselineModel, key)
                            if row is None:
                                s.add(UsageBaselineModel(
                                    key=key, uplink_base=up, downlink_base=down))
                            else:
                                row.uplink_base, row.downlink_base = up, down
                            s.commit()
                        break
                    except IntegrityError:
                        continue
                else:
                    raise RuntimeError(  # unreachable-ish under retry
                        f"baseline upsert failed repeatedly for {key}")
        await asyncio.to_thread(_sync)

    async def drop(self, key: str) -> None:
        def _sync() -> None:
            with self._sf() as s:
                s.execute(delete(UsageBaselineModel).where(UsageBaselineModel.key == key))
                s.commit()
        await asyncio.to_thread(_sync)

    async def drop_prefix(self, prefix: str) -> None:
        """Forget one account and any provider-specific sub-cursors."""
        def _sync() -> None:
            with self._sf() as s:
                s.execute(delete(UsageBaselineModel).where(
                    (UsageBaselineModel.key == prefix)
                    | UsageBaselineModel.key.like(prefix + "::%")
                ))
                s.commit()
        await asyncio.to_thread(_sync)


class SQLUsageJournal:
    """Appends usage batches to the journal (P4 recorder's sink)."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def append(self, records: list[UsageRecord],
                     owners: dict[tuple[str, str], int]) -> int:
        """Journal each record with its attributed user; returns row count."""
        def _sync() -> int:
            with self._sf() as s:
                for r in records:
                    s.add(UsageRecordModel(
                        user_id=owners.get((r.core_id, r.account_id)),
                        core_id=r.core_id, account_id=r.account_id,
                        node_id=r.node_id,
                        uplink_bytes=r.uplink_bytes, downlink_bytes=r.downlink_bytes,
                        recorded_at=r.recorded_at,
                    ))
                s.commit()
                return len(records)
        return await asyncio.to_thread(_sync)

    async def totals_by_core(self) -> dict[str, tuple[int, int]]:
        """All-time per-core usage totals from the journal (item 17).

        The journal only ever receives recorder DELTAS (exactly-once), so a
        plain GROUP-BY sum is the real per-core total — immune to core
        restarts/reinstalls and free of the host-interface byte counts the
        old Cores page mistakenly displayed (backend metrics' network_rx/tx
        is the PROCESS/host NIC, not user traffic).
        """
        from sqlalchemy import func

        def _sync() -> dict[str, tuple[int, int]]:
            with self._sf() as s:
                rows = s.execute(
                    select(
                        UsageRecordModel.core_id,
                        func.coalesce(func.sum(UsageRecordModel.uplink_bytes), 0),
                        func.coalesce(func.sum(UsageRecordModel.downlink_bytes), 0),
                    ).group_by(UsageRecordModel.core_id)
                ).all()
                return {core: (int(up), int(down)) for core, up, down in rows}
        return await asyncio.to_thread(_sync)

def _to_info(row: DeviceModel) -> DeviceInfo:
    return DeviceInfo(
        device_id=row.device_id, user_id=row.user_id, name=row.name,
        platform=row.platform, app_version=row.app_version, last_ip=row.last_ip,
        first_seen=row.first_seen, last_seen=row.last_seen,
        current_core=row.current_core, cores=set(row.cores_json or []),
    )


class SQLDeviceStore:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def get(self, device_id: str) -> DeviceInfo | None:
        def _sync() -> DeviceInfo | None:
            with self._sf() as s:
                row = s.execute(
                    select(DeviceModel).where(DeviceModel.device_id == device_id)
                ).scalar_one_or_none()
                return None if row is None else _to_info(row)
        return await asyncio.to_thread(_sync)

    async def upsert(self, device: DeviceInfo) -> None:
        def _sync() -> None:
            with self._sf() as s:
                row = s.execute(
                    select(DeviceModel).where(DeviceModel.device_id == device.device_id)
                ).scalar_one_or_none()
                if row is None:
                    row = DeviceModel(device_id=device.device_id, user_id=device.user_id)
                    s.add(row)
                row.user_id = device.user_id
                row.name = device.name
                row.platform = device.platform
                row.app_version = device.app_version
                row.last_ip = device.last_ip
                row.first_seen = device.first_seen
                row.last_seen = device.last_seen
                row.current_core = device.current_core
                row.cores_json = sorted(device.cores)
                s.commit()
        await asyncio.to_thread(_sync)

    async def for_user(self, user_id: int) -> list[DeviceInfo]:
        def _sync() -> list[DeviceInfo]:
            with self._sf() as s:
                rows = s.execute(
                    select(DeviceModel).where(DeviceModel.user_id == user_id)
                ).scalars().all()
                return [_to_info(r) for r in rows]
        return await asyncio.to_thread(_sync)

    async def all(self) -> list[DeviceInfo]:
        def _sync() -> list[DeviceInfo]:
            with self._sf() as s:
                return [_to_info(r) for r in
                        s.execute(select(DeviceModel)).scalars().all()]
        return await asyncio.to_thread(_sync)


def _to_record(row: DeviceSessionModel) -> SessionRecord:
    return SessionRecord(
        key=row.key, user_id=row.user_id, core_id=row.core_id,
        account_id=row.account_id, ip=row.ip,
        started_at=row.started_at, ended_at=row.ended_at,
        duration_seconds=row.duration_seconds,
        rx_bytes=row.rx_bytes, tx_bytes=row.tx_bytes,
    )


class SQLSessionStore:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def append(self, record: SessionRecord) -> None:
        def _sync() -> None:
            with self._sf() as s:
                s.add(DeviceSessionModel(
                    key=record.key, user_id=record.user_id, core_id=record.core_id,
                    account_id=record.account_id, ip=record.ip,
                    started_at=record.started_at, ended_at=record.ended_at,
                    duration_seconds=record.duration_seconds,
                    rx_bytes=record.rx_bytes, tx_bytes=record.tx_bytes,
                ))
                s.commit()
        await asyncio.to_thread(_sync)

    async def history(self, *, user_id: int | None = None,
                      account_id: str | None = None,
                      limit: int = 100) -> list[SessionRecord]:
        def _sync() -> list[SessionRecord]:
            stmt = select(DeviceSessionModel).order_by(desc(DeviceSessionModel.ended_at))
            if user_id is not None:
                stmt = stmt.where(DeviceSessionModel.user_id == user_id)
            if account_id is not None:
                stmt = stmt.where(DeviceSessionModel.account_id == account_id)
            stmt = stmt.limit(limit)
            with self._sf() as s:
                return [_to_record(r) for r in s.execute(stmt).scalars().all()]
        return await asyncio.to_thread(_sync)


# --------------------------------------------------------------------- #
# studio documents (StudioStore port) — settings KV under "studio.document.*"
# --------------------------------------------------------------------- #

class SQLStudioStore:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    @staticmethod
    def _key(core_id: str) -> str:
        return f"studio.document.{core_id}"

    async def get_document(self, core_id: str) -> dict[str, Any] | None:
        def _sync() -> dict[str, Any] | None:
            with self._sf() as s:
                row = s.get(SettingModel, self._key(core_id))
                return None if row is None else dict(row.value_json or {})
        return await asyncio.to_thread(_sync)

    async def save_document(self, core_id: str, document: dict[str, Any]) -> None:
        def _sync() -> None:
            with self._sf() as s:
                row = s.get(SettingModel, self._key(core_id))
                if row is None:
                    s.add(SettingModel(key=self._key(core_id), value_json=document))
                else:
                    row.value_json = document
                s.commit()
        await asyncio.to_thread(_sync)


# --------------------------------------------------------------------- #
# portal settings (SettingsStore port)
# --------------------------------------------------------------------- #

_PORTAL_SETTINGS_KEY = "portal.settings"


class SQLPortalSettingsStore:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def get_portal_settings(self) -> PortalSettings:
        def _sync() -> PortalSettings:
            with self._sf() as s:
                row = s.get(SettingModel, _PORTAL_SETTINGS_KEY)
                if row is None:
                    return PortalSettings()
                return PortalSettings.model_validate(row.value_json or {})
        return await asyncio.to_thread(_sync)

    async def save_portal_settings(self, settings: PortalSettings) -> PortalSettings:
        # normalize at the persistence edge too so ANY writer (HTTP router,
        # service call, script) stores one canonical shape
        settings = settings.normalize()
        payload = settings.model_dump(mode="json")
        def _sync() -> PortalSettings:
            with self._sf() as s:
                row = s.get(SettingModel, _PORTAL_SETTINGS_KEY)
                if row is None:
                    s.add(SettingModel(key=_PORTAL_SETTINGS_KEY, value_json=payload))
                else:
                    row.value_json = payload
                s.commit()
            return settings
        return await asyncio.to_thread(_sync)


# --------------------------------------------------------------------- #
# refresh tokens (clientapi RefreshTokenStore port)
# --------------------------------------------------------------------- #

class SQLRefreshTokenStore:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def save(self, user_id: int, token_hash: str, expires_at: datetime) -> None:
        def _sync() -> None:
            with self._sf() as s:
                s.add(RefreshTokenModel(token_hash=token_hash, user_id=user_id,
                                        expires_at=expires_at))
                s.commit()
        await asyncio.to_thread(_sync)

    async def get(self, token_hash: str):
        from app.clientapi.stores import RefreshTokenRecord

        def _sync():
            with self._sf() as s:
                row = s.get(RefreshTokenModel, token_hash)
                if row is None:
                    return None
                return RefreshTokenRecord(
                    user_id=row.user_id, token_hash=row.token_hash,
                    expires_at=row.expires_at, revoked=row.revoked,
                    created_at=row.created_at, rotated_to=row.rotated_to,
                )
        return await asyncio.to_thread(_sync)

    async def revoke(self, token_hash: str, *, rotated_to: str | None = None) -> None:
        def _sync() -> None:
            with self._sf() as s:
                s.execute(
                    update(RefreshTokenModel)
                    .where(RefreshTokenModel.token_hash == token_hash)
                    .values(revoked=True, rotated_to=rotated_to)
                )
                s.commit()
        await asyncio.to_thread(_sync)

    async def revoke_all_for_user(self, user_id: int) -> None:
        def _sync() -> None:
            with self._sf() as s:
                s.execute(
                    update(RefreshTokenModel)
                    .where(RefreshTokenModel.user_id == user_id)
                    .values(revoked=True)
                )
                s.commit()
        await asyncio.to_thread(_sync)


# --------------------------------------------------------------------- #
# users + core accounts (admin / migration / provisioning)
# --------------------------------------------------------------------- #

class UserRepository:
    """Admin-facing user CRUD incl. per-core account management.

    Synchronous by design — the Admin API layer wraps it in threads just
    like the store adapters above.
    """

    def __init__(self, session_factory, cipher: SecretsCipher | None = None) -> None:
        self._sf = session_factory
        self._cipher = cipher

    # ---------------- users ---------------- #
    def upsert_user(self, *, username: str, status: str = "active",
                    data_limit_bytes: int | None = None,
                    expire_at: datetime | None = None,
                    device_limit: int | None = None,
                    note: str | None = None,
                    client_auth_mode: str | None = None,
                    admin_id: int | None = None) -> int:
        """Idempotent by username (migration-safe); returns user id.

        Update semantics: ``None`` for an optional field means *keep the
        existing value* — an upsert carrying partial data must never wipe
        limits/expiry. Explicit clearing is a separate admin operation.
        """
        with self._sf() as s:
            row = s.execute(
                select(UserModel).where(UserModel.username == username)
            ).scalar_one_or_none()
            if row is None:
                row = UserModel(username=username)
                s.add(row)
                s.flush()
            row.status = status
            if data_limit_bytes is not None:
                row.data_limit_bytes = data_limit_bytes
            if expire_at is not None:
                row.expire_at = expire_at
            if device_limit is not None:
                row.device_limit = device_limit
            if note is not None:
                row.note = note
            if client_auth_mode is not None:
                row.client_auth_mode = client_auth_mode
            if admin_id is not None:
                row.admin_id = admin_id
            s.commit()
            return row.id

    def get_user(self, user_id: int) -> UserModel | None:
        with self._sf() as s:
            row = s.get(UserModel, user_id)
            if row is not None:
                s.expunge(row)
            return row

    def get_user_by_username(self, username: str) -> UserModel | None:
        with self._sf() as s:
            row = s.execute(
                select(UserModel).where(UserModel.username == username)
            ).scalar_one_or_none()
            if row is not None:
                s.expunge(row)
            return row

    def list_users(self, *, limit: int = 200, offset: int = 0) -> list[UserModel]:
        with self._sf() as s:
            rows = s.execute(
                select(UserModel).order_by(UserModel.id).limit(limit).offset(offset)
            ).scalars().all()
            for row in rows:
                s.expunge(row)
            return rows

    def set_status(self, user_id: int, status: str) -> None:
        with self._sf() as s:
            s.execute(update(UserModel).where(UserModel.id == user_id)
                      .values(status=status))
            s.commit()

    def set_app_credentials(self, user_id: int, app_username: str,
                            app_password_hash: str) -> None:
        with self._sf() as s:
            s.execute(
                update(UserModel).where(UserModel.id == user_id).values(
                    app_username=app_username, app_password_hash=app_password_hash,
                )
            )
            s.commit()

    def delete_user(self, user_id: int) -> None:
        with self._sf() as s:
            s.execute(delete(UserCoreAccountModel)
                      .where(UserCoreAccountModel.user_id == user_id))
            s.execute(delete(UserModel).where(UserModel.id == user_id))
            s.commit()

    # ---------------- core accounts ---------------- #
    def upsert_core_account(self, *, user_id: int, core_id: str, account_id: str,
                            protocol: str, enabled: bool = True,
                            settings: dict[str, Any] | None = None) -> int:
        """Idempotent by (user_id, core_id, account_id); settings encrypted."""
        enc = None
        if settings is not None:
            if self._cipher is None:
                raise ValueError("a SecretsCipher is required to store credentials")
            aad = f"{user_id}:{core_id}:{account_id}"
            enc = self._cipher.encrypt_json(settings, aad=aad)
        with self._sf() as s:
            row = s.execute(
                select(UserCoreAccountModel).where(
                    UserCoreAccountModel.user_id == user_id,
                    UserCoreAccountModel.core_id == core_id,
                    UserCoreAccountModel.account_id == account_id,
                )
            ).scalar_one_or_none()
            if row is None:
                row = UserCoreAccountModel(user_id=user_id, core_id=core_id,
                                           account_id=account_id)
                s.add(row)
            row.protocol = protocol
            row.enabled = enabled
            if enc is not None:
                row.credentials_enc = enc
            s.commit()
            return row.id

    def set_account_enabled(self, *, user_id: int, core_id: str,
                            account_id: str, enabled: bool) -> None:
        with self._sf() as s:
            s.execute(
                update(UserCoreAccountModel)
                .where(UserCoreAccountModel.user_id == user_id,
                       UserCoreAccountModel.core_id == core_id,
                       UserCoreAccountModel.account_id == account_id)
                .values(enabled=enabled)
            )
            s.commit()

    def accounts_of(self, user_id: int, *, decrypt: bool = True) -> list[dict[str, Any]]:
        """Decrypted account view for provisioning/portal (secrets stay server-side)."""
        with self._sf() as s:
            rows = s.execute(
                select(UserCoreAccountModel)
                .where(UserCoreAccountModel.user_id == user_id)
                .where(UserCoreAccountModel.revoked_at.is_(None))
            ).scalars().all()
            out: list[dict[str, Any]] = []
            for row in rows:
                settings: dict[str, Any] = {}
                if decrypt and row.credentials_enc:
                    if self._cipher is None:
                        raise ValueError("a SecretsCipher is required to read credentials")
                    aad = f"{row.user_id}:{row.core_id}:{row.account_id}"
                    settings = self._cipher.decrypt_json(row.credentials_enc, aad=aad)
                out.append({
                    "user_id": row.user_id, "core_id": row.core_id,
                    "account_id": row.account_id, "protocol": row.protocol,
                    "enabled": row.enabled, "settings": settings,
                })
            return out

    def accounts_of_core(self, core_id: str, *, decrypt: bool = True) -> list[dict[str, Any]]:
        """Every LIVE account of one core across all users (grant-cascade
        reconciler: prune/revoke accounts whose inbound tags vanished)."""
        with self._sf() as s:
            rows = s.execute(
                select(UserCoreAccountModel)
                .where(UserCoreAccountModel.core_id == core_id)
                .where(UserCoreAccountModel.revoked_at.is_(None))
            ).scalars().all()
            out: list[dict[str, Any]] = []
            for row in rows:
                settings: dict[str, Any] = {}
                if decrypt and row.credentials_enc:
                    if self._cipher is None:
                        raise ValueError("a SecretsCipher is required to read credentials")
                    aad = f"{row.user_id}:{row.core_id}:{row.account_id}"
                    settings = self._cipher.decrypt_json(row.credentials_enc, aad=aad)
                out.append({
                    "user_id": row.user_id, "core_id": row.core_id,
                    "account_id": row.account_id, "protocol": row.protocol,
                    "enabled": row.enabled, "settings": settings,
                })
            return out

    def delete_account(self, *, user_id: int, core_id: str, account_id: str) -> None:
        with self._sf() as s:
            s.execute(
                delete(UserCoreAccountModel)
                .where(UserCoreAccountModel.user_id == user_id,
                       UserCoreAccountModel.core_id == core_id,
                       UserCoreAccountModel.account_id == account_id)
            )
            s.commit()

    def account_owners(self) -> dict[tuple[str, str], int]:
        """The {(core_id, account_id): user_id} attribution map for quota folds."""
        with self._sf() as s:
            rows = s.execute(
                select(UserCoreAccountModel.core_id, UserCoreAccountModel.account_id,
                       UserCoreAccountModel.user_id)
                .where(UserCoreAccountModel.revoked_at.is_(None))
            ).all()
            return {(core_id, account_id): user_id for core_id, account_id, user_id in rows}


class SQLSettingsKV:
    """Generic typed key-value access on the ``settings`` table.

    Used for small platform markers that are not full settings documents —
    e.g. the current subscription-token jti per user (rotation invalidates
    older portal URLs immediately). JSON-serializable values only.
    """

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def get_value(self, key: str) -> Any:
        def _sync() -> Any:
            with self._sf() as s:
                row = s.get(SettingModel, key)
                return None if row is None else row.value_json
        return await asyncio.to_thread(_sync)

    async def set_value(self, key: str, value: Any) -> None:
        def _sync() -> None:
            # Retry-on-conflict upsert (same discipline as the baseline store)
            # — concurrent token rotations must never crash on the UNIQUE pk.
            from sqlalchemy.exc import IntegrityError

            for _attempt in range(4):
                try:
                    with self._sf() as s:
                        row = s.get(SettingModel, key)
                        if row is None:
                            s.add(SettingModel(key=key, value_json=value))
                        else:
                            row.value_json = value
                        s.commit()
                    return
                except IntegrityError:
                    continue
        return await asyncio.to_thread(_sync)


class InMemorySettingsKV:
    """Non-persistent counterpart used by tests and dev boots."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    async def get_value(self, key: str) -> Any:
        return self._data.get(key)

    async def set_value(self, key: str, value: Any) -> None:
        self._data[key] = value


# --------------------------------------------------------------------- #
# core host settings (delivery-layer "Host Settings" engine entries)
# --------------------------------------------------------------------- #

class SQLCoreHostStore:
    """Admin Host-Settings entries keyed by ``(core_id, inbound_tag)``.

    Rows live in the P3 ``core_hosts`` table.  The engine consumes
    :class:`app.portal.hostengine.HostEntry` objects; this adapter owns the
    model ↔ row mapping both ways.  ``sort`` persists **priority** — the
    position of an entry inside its tag's list (item 13) — so the API's
    list order IS the expansion order.
    """

    #: (core_id, tag) → known extras keys promoted onto HostEntry fields;
    #: every OTHER extras key round-trips through HostEntry.extras verbatim
    #: (marzban-era attributes we do not interpret stay preserved).
    _KNOWN_EXTRAS = ("mux_enable", "fragment_setting", "noise_setting",
                     "random_user_agent", "use_sni_as_host")

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    # ---- mapping helpers -------------------------------------------- #
    @staticmethod
    def _to_entry(row) -> "HostEntry":
        from app.portal.hostengine import HostEntry

        extras = dict(row.extras or {})
        known = {k: extras.pop(k) for k in SQLCoreHostStore._KNOWN_EXTRAS
                 if k in extras}
        return HostEntry(
            remark=row.remark or "",
            address=row.address or "",
            port=row.port,
            sni=row.sni,
            host=row.host_header,
            path=row.path,
            security=row.security,
            alpn=row.alpn,
            fingerprint=row.fingerprint,
            allowinsecure=extras.pop("allowinsecure", None),
            is_disabled=bool(extras.pop("is_disabled", False)),
            mux_enable=bool(known.get("mux_enable", False)),
            fragment_setting=known.get("fragment_setting"),
            noise_setting=known.get("noise_setting"),
            random_user_agent=bool(known.get("random_user_agent", False)),
            use_sni_as_host=bool(known.get("use_sni_as_host", False)),
            extras=extras,
        )

    @staticmethod
    def _to_row(core_id: str, tag: str, sort: int, entry: "HostEntry") -> "CoreHostModel":
        extras = dict(entry.extras or {})
        if entry.allowinsecure is not None:
            extras["allowinsecure"] = bool(entry.allowinsecure)
        if entry.is_disabled:
            extras["is_disabled"] = True
        for key in SQLCoreHostStore._KNOWN_EXTRAS:
            value = getattr(entry, key)
            if value not in (None, False, ""):
                extras[key] = value
        return CoreHostModel(
            core_id=core_id, inbound_tag=tag, sort=sort,
            remark=entry.remark, address=entry.address, port=entry.port,
            sni=entry.sni, host_header=entry.host, path=entry.path,
            security=entry.security, alpn=entry.alpn,
            fingerprint=entry.fingerprint, extras=extras,
        )

    # ---- port ------------------------------------------------------- #
    async def list_grouped(self, core_id: str) -> dict[str, list["HostEntry"]]:
        """``{inbound_tag: [entries in priority order]}`` for one core."""
        def _sync():
            with self._sf() as s:
                rows = (s.query(CoreHostModel)
                        .filter(CoreHostModel.core_id == core_id)
                        .order_by(CoreHostModel.inbound_tag,
                                  CoreHostModel.sort, CoreHostModel.id)
                        .all())
                grouped: dict[str, list] = {}
                for row in rows:
                    grouped.setdefault(row.inbound_tag, []).append(self._to_entry(row))
                return grouped
        return await asyncio.to_thread(_sync)

    async def replace_tags(self, core_id: str,
                           tags: dict[str, list["HostEntry"]]) -> None:
        """Replace ONLY the listed tags' rows (item 13 bulk PUT semantics):
        a tag absent from ``tags`` keeps its rows untouched; a tag mapped
        to ``[]`` is cleared; list order is persisted as priority (sort).
        """
        def _sync() -> None:
            with self._sf() as s:
                for tag, entries in tags.items():
                    (s.query(CoreHostModel)
                     .filter(CoreHostModel.core_id == core_id,
                             CoreHostModel.inbound_tag == tag)
                     .delete(synchronize_session=False))
                    for sort, entry in enumerate(entries):
                        s.add(self._to_row(core_id, tag, sort, entry))
                s.commit()
        return await asyncio.to_thread(_sync)


class InMemoryCoreHostStore:
    """Non-persistent counterpart (unit tests + dev boots)."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, list]] = {}

    async def list_grouped(self, core_id: str) -> dict[str, list]:
        return {tag: list(entries)
                for tag, entries in self._data.get(core_id, {}).items()}

    async def replace_tags(self, core_id: str, tags: dict[str, list]) -> None:
        grouped = self._data.setdefault(core_id, {})
        for tag, entries in tags.items():
            if entries:
                grouped[tag] = list(entries)
            else:
                grouped.pop(tag, None)
