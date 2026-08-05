"""Zagros persistence layer (Phase P3).

* ``base`` — engine/session factory + timezone-safe DateTime.
* ``models`` — the relational schema (see doc §15.6).
* ``cipher`` — AES-256-GCM encryption-at-rest for credentials.
* ``repositories`` — SQL adapters for every hexagonal port.
* ``provider`` — SQL data providers for the Client API & portal.
* ``migration`` + ``legacy_reader`` — idempotent Marzban → Zagros import.
"""
from app.persistence.base import Base, UtcDateTime, create_schema, create_session_factory
from app.persistence.cipher import CipherError, SecretsCipher, derive_key
from app.persistence.provider import SQLOnlineDataAdapter
from app.persistence.repositories import (
    BaselineStore,
    SQLBaselineStore,
    SQLCoreStateStore,
    SQLDeviceStore,
    SQLPortalSettingsStore,
    SQLQuotaStore,
    SQLRefreshTokenStore,
    SQLSessionStore,
    SQLStudioStore,
    SQLUsageJournal,
    UserRepository,
)

__all__ = [
    "Base",
    "UtcDateTime",
    "create_schema",
    "create_session_factory",
    "CipherError",
    "SecretsCipher",
    "derive_key",
    "SQLOnlineDataAdapter",
    "BaselineStore",
    "SQLBaselineStore",
    "SQLCoreStateStore",
    "SQLDeviceStore",
    "SQLPortalSettingsStore",
    "SQLQuotaStore",
    "SQLRefreshTokenStore",
    "SQLSessionStore",
    "SQLStudioStore",
    "SQLUsageJournal",
    "UserRepository",
]
