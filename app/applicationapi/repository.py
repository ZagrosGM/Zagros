"""Transactional SQL operations for Application authentication.

This repository owns the security-critical row locks and cross-worker durable
state: ticket consumption, replay nonces, throttle buckets, global device-slot
allocation and refresh-family rotation.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from app.applicationapi.errors import (
    ActivationTicketInvalid,
    ApplicationAuthFailed,
    ApplicationForbidden,
    ApplicationGrantNotFound,
    ApplicationKeyNotFound,
    ApplicationNotFound,
    ApplicationRateLimited,
    ConfigGrantConsumed,
    ConfigGrantExpired,
    ConfigGrantInvalid,
    ConnectionFailed,
    ConnectionNotFound,
    ConnectionRequired,
    DeviceLimitReached,
    DeviceNotFound,
    EnrollmentRequired,
    ReplayRejected,
)
from app.applicationapi.security import b64url_decode, b64url_encode
from app.persistence.cipher import SecretsCipher
from app.persistence.device_authority import (
    device_within_limit,
    occupying_device_count,
)
from app.persistence.models import (
    AdminModel,
    ApplicationActivationTicketModel,
    ApplicationAuthThrottleModel,
    ApplicationConfigGrantModel,
    ApplicationConnectionLeaseModel,
    ApplicationConnectionModel,
    ApplicationKeyModel,
    ApplicationModel,
    ApplicationRequestNonceModel,
    ApplicationUserGrantModel,
    AuditLogModel,
    NodeModel,
    RefreshTokenModel,
    SubscriptionDeviceModel,
    UsageRecordModel,
    UserModel,
    UserUsageModel,
)

_ACTIVE = "active"
try:
    from app.persistence.models import SettingModel as _PortalSettingModel
except Exception:  # pragma: no cover — standalone test contexts
    _PortalSettingModel = None

_PORTAL_SETTINGS_KEY = "portal.settings"


def _portal_default_access_mode(session) -> str:
    """Panel-wide delivery default ('application' | 'subscription').

    Reads the portal settings row through the SAME session/DB as the
    users table so a NULL per-user access_mode resolves LIVE —
    panel-default users follow the Subscriptions setting without any
    per-user write (f-panel-4).
    """
    if _PortalSettingModel is None:
        return "subscription"
    try:
        row = session.get(_PortalSettingModel, _PORTAL_SETTINGS_KEY)
        raw = ""
        if row is not None:
            raw = (row.value_json or {}).get("client_auth_mode") or ""
    except Exception:  # noqa: BLE001 — settings must never break auth lookup
        return "subscription"
    return "application" if raw == "application_login" else "subscription"


_APPLICATION_MODE = "application"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RequestKeyContext:
    application_db_id: int
    application_public_id: str
    application_status: str
    key_db_id: int
    key_id: str
    key_status: str
    private_key: bytes = field(repr=False)
    # f-panel-7: the application's user access mode ('all_users' default /
    # 'bound_only') — decides whether an ACTIVE grant is required to sign in.
    application_access_mode: str = "all_users"
    device_db_id: int | None = None
    device_key_id: str | None = None
    device_public_key: bytes | None = None
    device_status: str | None = None
    user_id: int | None = None


@dataclass(frozen=True, slots=True)
class UserAuthContext:
    application_db_id: int
    application_public_id: str
    application_status: str
    application_key_db_id: int
    application_key_id: str
    application_key_status: str
    user_id: int
    app_username: str | None
    password_hash: str | None = field(repr=False)
    user_status: str
    access_mode: str | None
    expire_at: datetime | None
    data_limit_bytes: int | None
    used_bytes: int
    device_limit: int | None
    grant_id: int | None
    grant_status: str | None
    # f-panel-7: carried so validation can require the grant only when the
    # application is in 'bound_only' mode.
    application_access_mode: str = "all_users"
    device_db_id: int | None = None
    device_key_id: str | None = None
    device_status: str | None = None
    token_family_id: str | None = None
    device_within_limit: bool = True


@dataclass(frozen=True, slots=True)
class RefreshIssue:
    secret: str = field(repr=False)
    token_hash: str
    family_id: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ConfigGrantContext:
    public_id: str
    core_id: str
    protocol: str | None
    source_account_id: str | None = field(repr=False)
    connection_id: str | None
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ConnectionLeaseContext:
    connection_db_id: int
    connection_id: str
    lease_id: str
    application_id: int
    user_id: int
    device_id: int
    core_id: str
    protocol: str
    node_id: int | None
    target_kind: str
    account_id: str
    status: str
    observed_status: str
    teardown_capability: str
    not_after: datetime
    renewed_at: datetime | None
    observed_at: datetime | None
    last_error: str | None
    settings: dict = field(default_factory=dict, repr=False)
    created: bool = False


@dataclass(frozen=True, slots=True)
class ConfigDeliveryMaterial(ConfigGrantContext):
    application_public_id: str
    config_key_id: str
    config_private_key: bytes = field(repr=False)
    signing_key_id: str
    signing_private_key: bytes = field(repr=False)
    device_key_id: str
    device_public_key: bytes


class ApplicationAuthRepository:
    def __init__(self, session_factory, key_cipher: SecretsCipher,
                 identifier_key: bytes,
                 lease_cipher: SecretsCipher | None = None) -> None:
        if len(identifier_key) != 32:
            raise ValueError("identifier key must be 32 bytes")
        self._sf = session_factory
        self._cipher = key_cipher
        # Lease credentials use a separately derived runtime key in production.
        # The fallback preserves dependency-injected unit repositories.
        self._lease_cipher = lease_cipher or key_cipher
        self._identifier_key = identifier_key

    # ------------------------------------------------------------------
    # low-level safe helpers
    # ------------------------------------------------------------------
    def identifier_hash(self, kind: str, value: str) -> str:
        normalized = value.strip().lower() if kind == "username" else value.strip()
        return hmac.new(
            self._identifier_key,
            f"{kind}\0{normalized}".encode(), hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def safe_source_ip(value: str | None) -> str:
        try:
            return str(ipaddress.ip_address(value or ""))
        except ValueError:
            return "unknown"

    @staticmethod
    def _audit(session, action: str, *, application_id: int | None = None,
               user_id: int | None = None, device_id: int | None = None,
               source_ip_hash: str | None = None,
               result: str = "ok", reason: str | None = None,
               detail: dict | None = None, actor: str = "application-api") -> None:
        extra_detail = detail
        detail = {
            "application_id": application_id,
            "user_id": user_id,
            "device_id": device_id,
            "source_ip_hash": source_ip_hash,
            "result": result,
        }
        if reason:
            detail["reason"] = reason[:64]
        # Explicit allow-list prevents future callers from putting raw configs,
        # credentials, tokens, or key material in an audit record.
        safe_extra = {}
        for key in ("count", "core_id", "from", "to"):
            value = ((extra_detail or {}).get(key)
                     if isinstance(extra_detail, dict) else None)
            if isinstance(value, str):
                safe_extra[key] = value[:64]
            elif isinstance(value, int):
                safe_extra[key] = value
        detail.update(safe_extra)
        session.add(AuditLogModel(
            actor=actor[:64], action=action[:64],
            target=(f"application:{application_id}" if application_id else "application:unknown"),
            detail_json={key: value for key, value in detail.items() if value is not None},
        ))

    def audit(self, action: str, **kwargs) -> None:
        with self._sf() as session:
            self._audit(session, action, **kwargs)
            session.commit()

    def _key_aad(self, public_id: str, kid: str, purpose: str) -> str:
        return f"application-key:{public_id}:{kid}:{purpose}"

    def _encrypt_private(self, private_key: bytes, *, public_id: str,
                         kid: str, purpose: str) -> str:
        return self._cipher.encrypt_json(
            {"private_key": b64url_encode(private_key)},
            aad=self._key_aad(public_id, kid, purpose),
        )

    def _decrypt_private(self, row: ApplicationKeyModel,
                         public_id: str) -> bytes:
        value = self._cipher.decrypt_json(
            row.private_key_encrypted,
            aad=self._key_aad(public_id, row.kid, row.purpose),
        ).get("private_key", "")
        return b64url_decode(str(value), expected_length=32)

    # ------------------------------------------------------------------
    # administrative bootstrap, grant and one-time ticket issuance
    # ------------------------------------------------------------------
    def create_application(self, *, owner_admin_id: int, name: str,
                           api_base_url: str, default_lang: str,
                           branding: dict,
                           user_access_mode: str = "all_users") -> dict:
        if user_access_mode not in ("all_users", "bound_only"):
            raise ApplicationForbidden("user access mode is invalid")
        public_id = str(uuid4())
        signing_kid = "sig-" + secrets.token_hex(8)
        config_kid = "cfg-" + secrets.token_hex(8)

        signing_private_obj = Ed25519PrivateKey.generate()
        signing_private = signing_private_obj.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        signing_public = signing_private_obj.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        config_private_obj = X25519PrivateKey.generate()
        config_private = config_private_obj.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        config_public = config_private_obj.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        with self._sf() as session:
            if session.get(AdminModel, owner_admin_id) is None:
                raise ApplicationForbidden("Application owner does not exist")
            app = ApplicationModel(
                public_id=public_id, owner_admin_id=owner_admin_id,
                name=name.strip(), status=_ACTIVE,
                api_base_url=api_base_url.strip(), default_lang=default_lang.strip(),
                branding=dict(branding or {}),
                user_access_mode=user_access_mode,
                active_signing_kid=signing_kid,
                active_config_kid=config_kid,
            )
            session.add(app)
            session.flush()
            signing = ApplicationKeyModel(
                application_id=app.id, kid=signing_kid, purpose="signing",
                algorithm="ed25519", public_key=b64url_encode(signing_public),
                private_key_encrypted=self._encrypt_private(
                    signing_private, public_id=public_id, kid=signing_kid,
                    purpose="signing"),
                encryption_key_id="application-keys-v1", status=_ACTIVE,
            )
            config = ApplicationKeyModel(
                application_id=app.id, kid=config_kid,
                purpose="config_encryption", algorithm="x25519",
                public_key=b64url_encode(config_public),
                private_key_encrypted=self._encrypt_private(
                    config_private, public_id=public_id, kid=config_kid,
                    purpose="config_encryption"),
                encryption_key_id="application-keys-v1", status=_ACTIVE,
            )
            session.add_all([signing, config])
            self._audit(session, "application.created", application_id=app.id)
            session.commit()
        return {
            "application_id": public_id,
            "name": name.strip(), "status": _ACTIVE,
            "user_access_mode": user_access_mode,
            "signing_key_id": signing_kid,
            "signing_public_key": b64url_encode(signing_public),
            "config_key_id": config_kid,
            "config_public_key": b64url_encode(config_public),
        }

    def set_user_access_mode(self, *, application_public_id: str,
                             user_access_mode: str) -> dict:
        """f-panel-7: switch who may sign in ('all_users' | 'bound_only')."""
        if user_access_mode not in ("all_users", "bound_only"):
            raise ApplicationForbidden("user access mode is invalid")
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == application_public_id,
            )).scalar_one_or_none()
            if app is None:
                raise ApplicationForbidden("Application does not exist")
            previous = app.user_access_mode or "all_users"
            app.user_access_mode = user_access_mode
            self._audit(session, "application.access_mode.changed",
                        application_id=app.id,
                        detail={"from": previous, "to": user_access_mode})
            session.commit()
            return {
                "application_id": app.public_id, "name": app.name,
                "user_access_mode": app.user_access_mode,
            }

    def active_signing_seed(self, *, application_public_id: str) -> str | None:
        """b64url Ed25519 seed of the application's ACTIVE signing key.

        f-panel-8: serves ONLY the white-label build pipeline — the panel
        attaches it to a job-token-authenticated worker fetch so an
        official build can attest enrollments. Never returned by any
        admin API and never persisted outside the encrypted column.
        """
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == application_public_id,
            )).scalar_one_or_none()
            if (app is None or app.status != _ACTIVE
                    or not app.active_signing_kid):
                return None
            key = session.execute(select(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == app.id,
                ApplicationKeyModel.kid == app.active_signing_kid,
                ApplicationKeyModel.purpose == "signing",
            )).scalar_one_or_none()
            if key is None or key.status != _ACTIVE:
                return None
            return b64url_encode(self._decrypt_private(key, app.public_id))

    def grant_user(self, *, application_public_id: str, user_id: int) -> dict:
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == application_public_id)).scalar_one_or_none()
            user = session.get(UserModel, user_id)
            if app is None or user is None or app.status != _ACTIVE:
                raise ApplicationForbidden("Application grant cannot be created")
            grant = session.execute(select(ApplicationUserGrantModel).where(
                ApplicationUserGrantModel.application_id == app.id,
                ApplicationUserGrantModel.user_id == user_id,
            )).scalar_one_or_none()
            if grant is None:
                grant = ApplicationUserGrantModel(
                    application_id=app.id, user_id=user_id, status=_ACTIVE)
                session.add(grant)
                session.flush()
            else:
                grant.status = _ACTIVE
                grant.revoked_at = None
                grant.revoked_reason = None
            self._audit(session, "application.grant.created",
                        application_id=app.id, user_id=user_id)
            session.commit()
            return {
                "grant_id": grant.id, "application_id": app.public_id,
                "user_id": user_id, "status": grant.status,
            }

    def list_applications(self) -> list[dict]:
        """Safe admin projection of every Application (no key material)."""
        with self._sf() as session:
            rows = list(session.scalars(
                select(ApplicationModel).order_by(ApplicationModel.id.asc())))
            return [{
                "id": app.id, "public_id": app.public_id,
                "owner_admin_id": app.owner_admin_id, "name": app.name,
                "status": app.status, "api_base_url": app.api_base_url,
                "default_lang": app.default_lang,
                "user_access_mode": app.user_access_mode or "all_users",
                "active_signing_kid": app.active_signing_kid,
                "active_config_kid": app.active_config_kid,
            } for app in rows]

    def user_grants(self, *, user_id: int) -> list[dict]:
        """Active application grants for one user (joined app identity)."""
        with self._sf() as session:
            rows = list(session.execute(
                select(ApplicationUserGrantModel, ApplicationModel).join(
                    ApplicationModel,
                    ApplicationUserGrantModel.application_id == ApplicationModel.id,
                ).where(
                    ApplicationUserGrantModel.user_id == user_id,
                    ApplicationUserGrantModel.status == _ACTIVE,
                ).order_by(ApplicationModel.id.asc())))
            return [{
                "application_id": app.public_id, "name": app.name,
                "status": app.status,
            } for _, app in rows]

    def get_application(self, public_id: str) -> dict | None:
        """Full safe admin projection (list fields + branding, no keys)."""
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == public_id,
            )).scalar_one_or_none()
            if app is None:
                return None
            return {
                "id": app.id, "public_id": app.public_id,
                "owner_admin_id": app.owner_admin_id, "name": app.name,
                "status": app.status, "api_base_url": app.api_base_url,
                "default_lang": app.default_lang,
                "user_access_mode": app.user_access_mode or "all_users",
                "active_signing_kid": app.active_signing_kid,
                "active_config_kid": app.active_config_kid,
                "branding": dict(app.branding or {}),
            }

    def application_grants(self, public_id: str) -> list[dict]:
        """Active grants for one application (joined usernames)."""
        with self._sf() as session:
            rows = list(session.execute(
                select(ApplicationUserGrantModel, UserModel).join(
                    UserModel,
                    ApplicationUserGrantModel.user_id == UserModel.id,
                ).join(
                    ApplicationModel,
                    (ApplicationUserGrantModel.application_id
                     == ApplicationModel.id),
                ).where(
                    ApplicationModel.public_id == public_id,
                    ApplicationUserGrantModel.status == _ACTIVE,
                ).order_by(UserModel.username.asc())))
            return [{
                "user_id": user.id, "username": user.username,
                "status": grant.status, "granted_at": grant.granted_at,
            } for grant, user in rows]

    def application_public_keys(self, public_id: str) -> dict:
        """Active PUBLIC keys (b64url) for the build-config prefill.

        The private envelopes are never selected here — only ``kid`` and
        the already-public ``public_key`` column.
        """
        empty: dict[str, dict | None] = {"signing": None, "config": None}
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == public_id,
            )).scalar_one_or_none()
            if app is None:
                return empty
            for slot, kid in (
                    ("signing", app.active_signing_kid),
                    ("config", app.active_config_kid)):
                if not kid:
                    continue
                row = session.execute(select(ApplicationKeyModel).where(
                    ApplicationKeyModel.application_id == app.id,
                    ApplicationKeyModel.kid == kid,
                    ApplicationKeyModel.status == _ACTIVE,
                )).scalar_one_or_none()
                if row is not None:
                    empty[slot] = {"kid": row.kid,
                                   "public_key": row.public_key}
            return empty

    def set_application_icon(self, public_id: str,
                             meta: dict | None) -> dict | None:
        """Attach (or, with None, detach) the icon document in branding."""
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == public_id,
            )).scalar_one_or_none()
            if app is None:
                return None
            branding = dict(app.branding or {})
            if meta is None:
                branding.pop("icon", None)
            else:
                branding["icon"] = dict(meta)
            app.branding = branding
            session.commit()
            return {"public_id": app.public_id, "icon": branding.get("icon")}

    def revoke_application(self, *, application_public_id: str,
                           now: datetime | None = None) -> dict:
        """Revoke an Application first, then idempotently cascade authorities.

        The Application status commits before broad child updates. This keeps
        enrollment's user→grant→Application lock order deadlock-safe: even if a
        later cascade must be retried, every public authorization already fails
        closed on the revoked parent.
        """
        now = now or _utcnow()
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == application_public_id,
            ).with_for_update()).scalar_one_or_none()
            if app is None:
                raise ApplicationNotFound("Application not found")
            app_id = app.id
            if app.status != "revoked":
                app.status = "revoked"
                app.revoked_at = now
                app.revoked_reason = "administrator"
                self._audit(
                    session, "application.revoked",
                    application_id=app.id, actor="admin")
            session.commit()

        with self._sf() as session:
            session.execute(update(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == app_id,
                ApplicationKeyModel.status != "revoked",
            ).values(
                status="revoked", revoked_at=now,
                revoked_reason="application_revoked"))
            session.execute(update(ApplicationUserGrantModel).where(
                ApplicationUserGrantModel.application_id == app_id,
                ApplicationUserGrantModel.status != "revoked",
            ).values(
                status="revoked", revoked_at=now,
                revoked_reason="application_revoked"))
            session.execute(update(SubscriptionDeviceModel).where(
                SubscriptionDeviceModel.application_id == app_id,
                SubscriptionDeviceModel.device_status == _ACTIVE,
            ).values(
                device_status="revoked", revoked_at=now,
                revoked_reason="application_revoked"))
            session.execute(update(RefreshTokenModel).where(
                RefreshTokenModel.application_id == app_id,
                RefreshTokenModel.revoked.is_(False),
            ).values(
                revoked=True, revoked_at=now,
                revoked_reason="application_revoked"))
            session.execute(update(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.application_id == app_id,
                ApplicationConfigGrantModel.consumed_at.is_(None),
                ApplicationConfigGrantModel.revoked_at.is_(None),
            ).values(
                revoked_at=now, revoked_reason="application_revoked"))
            session.execute(update(ApplicationActivationTicketModel).where(
                ApplicationActivationTicketModel.application_id == app_id,
                ApplicationActivationTicketModel.consumed_at.is_(None),
                ApplicationActivationTicketModel.revoked_at.is_(None),
            ).values(
                revoked_at=now, revoked_reason="application_revoked"))
            session.commit()
        return {
            "resource": "application", "resource_id": application_public_id,
            "status": "revoked",
        }

    def revoke_user_grant(self, *, application_public_id: str, user_id: int,
                          now: datetime | None = None) -> dict:
        """Revoke one Application/user authority while preserving the device."""
        now = now or _utcnow()
        with self._sf() as session:
            app_id = session.scalar(select(ApplicationModel.id).where(
                ApplicationModel.public_id == application_public_id))
            if app_id is None:
                raise ApplicationGrantNotFound("Application grant not found")
            grant = session.execute(select(ApplicationUserGrantModel).where(
                ApplicationUserGrantModel.application_id == app_id,
                ApplicationUserGrantModel.user_id == user_id,
            ).with_for_update()).scalar_one_or_none()
            if grant is None:
                raise ApplicationGrantNotFound("Application grant not found")
            if grant.status != "revoked":
                grant.status = "revoked"
                grant.revoked_at = now
                grant.revoked_reason = "administrator"
                self._audit(
                    session, "application.grant.revoked",
                    application_id=app_id, user_id=user_id, actor="admin")
            session.commit()

        with self._sf() as session:
            session.execute(update(RefreshTokenModel).where(
                RefreshTokenModel.application_id == app_id,
                RefreshTokenModel.user_id == user_id,
                RefreshTokenModel.revoked.is_(False),
            ).values(
                revoked=True, revoked_at=now,
                revoked_reason="grant_revoked"))
            session.execute(update(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.application_id == app_id,
                ApplicationConfigGrantModel.user_id == user_id,
                ApplicationConfigGrantModel.consumed_at.is_(None),
                ApplicationConfigGrantModel.revoked_at.is_(None),
            ).values(revoked_at=now, revoked_reason="grant_revoked"))
            session.execute(update(ApplicationActivationTicketModel).where(
                ApplicationActivationTicketModel.application_id == app_id,
                ApplicationActivationTicketModel.user_id == user_id,
                ApplicationActivationTicketModel.consumed_at.is_(None),
                ApplicationActivationTicketModel.revoked_at.is_(None),
            ).values(revoked_at=now, revoked_reason="grant_revoked"))
            session.commit()
        return {
            "resource": "grant",
            "resource_id": f"{application_public_id}:{user_id}",
            "status": "revoked",
        }

    def revoke_application_key(self, *, application_public_id: str,
                               key_id: str,
                               now: datetime | None = None) -> dict:
        """Revoke one purpose-separated key and its dependent authorities."""
        now = now or _utcnow()
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == application_public_id,
            )).scalar_one_or_none()
            if app is None:
                raise ApplicationKeyNotFound("Application key not found")
            app_id = app.id
            key = session.execute(select(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == app_id,
                ApplicationKeyModel.kid == key_id,
            ).with_for_update()).scalar_one_or_none()
            if key is None:
                raise ApplicationKeyNotFound("Application key not found")
            key_db_id = key.id
            purpose = key.purpose
            active_signing = app.active_signing_kid == key.kid
            if key.status != "revoked":
                key.status = "revoked"
                key.revoked_at = now
                key.revoked_reason = "administrator"
                self._audit(
                    session, "application.key.revoked",
                    application_id=app_id, actor="admin")
            session.commit()

        with self._sf() as session:
            if purpose == "config_encryption":
                session.execute(update(RefreshTokenModel).where(
                    RefreshTokenModel.application_id == app_id,
                    RefreshTokenModel.application_key_id == key_db_id,
                    RefreshTokenModel.revoked.is_(False),
                ).values(
                    revoked=True, revoked_at=now,
                    revoked_reason="application_key_revoked"))
            if purpose == "config_encryption" or active_signing:
                config_scope = (
                    ApplicationConfigGrantModel.application_key_id == key_db_id
                    if purpose == "config_encryption"
                    else ApplicationConfigGrantModel.application_id == app_id
                )
                session.execute(update(ApplicationConfigGrantModel).where(
                    config_scope,
                    ApplicationConfigGrantModel.consumed_at.is_(None),
                    ApplicationConfigGrantModel.revoked_at.is_(None),
                ).values(
                    revoked_at=now,
                    revoked_reason="application_key_revoked"))
            session.execute(update(ApplicationActivationTicketModel).where(
                ApplicationActivationTicketModel.application_id == app_id,
                ApplicationActivationTicketModel.application_key_id == key_db_id,
                ApplicationActivationTicketModel.consumed_at.is_(None),
                ApplicationActivationTicketModel.revoked_at.is_(None),
            ).values(
                revoked_at=now, revoked_reason="application_key_revoked"))
            session.commit()
        return {
            "resource": "application_key",
            "resource_id": key_id,
            "status": "revoked",
        }

    def issue_activation_ticket(self, *, application_public_id: str,
                                user_id: int, ttl_seconds: int,
                                intended_device_public_key: str | None = None,
                                now: datetime | None = None) -> dict:
        now = now or _utcnow()
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == application_public_id
            ).with_for_update()).scalar_one_or_none()
            if app is None or app.status != _ACTIVE or not app.active_signing_kid:
                raise ApplicationForbidden("Application is not active")
            user = session.get(UserModel, user_id)
            grant = session.execute(select(ApplicationUserGrantModel).where(
                ApplicationUserGrantModel.application_id == app.id,
                ApplicationUserGrantModel.user_id == user_id,
            ).with_for_update()).scalar_one_or_none()
            key = session.execute(select(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == app.id,
                ApplicationKeyModel.kid == app.active_signing_kid,
                ApplicationKeyModel.purpose == "signing",
            )).scalar_one_or_none()
            user_mode = None if user is None else (
                (user.access_mode or user.client_auth_mode)
                or _portal_default_access_mode(session))
            if (user is None or user_mode != _APPLICATION_MODE
                    or grant is None or grant.status != _ACTIVE
                    or key is None or key.status != _ACTIVE):
                raise ApplicationForbidden("Activation ticket cannot be issued")
            intended_hash = None
            if intended_device_public_key:
                raw = b64url_decode(intended_device_public_key, expected_length=32)
                intended_hash = hashlib.sha256(raw).hexdigest()
            expires = now + timedelta(seconds=int(ttl_seconds))
            jti = secrets.token_hex(24)
            payload = {
                "v": 1, "jti": jti, "aid": app.public_id,
                "uid": user.id, "gid": grant.id, "kid": key.kid,
                "iat": int(now.timestamp()), "exp": int(expires.timestamp()),
                "dkh": intended_hash,
            }
            encoded = b64url_encode(json.dumps(
                payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            signing_input = f"zgat1.{encoded}".encode("ascii")
            private = Ed25519PrivateKey.from_private_bytes(
                self._decrypt_private(key, app.public_id))
            signature = private.sign(signing_input)
            token = f"zgat1.{encoded}.{b64url_encode(signature)}"
            session.add(ApplicationActivationTicketModel(
                application_id=app.id, application_key_id=key.id,
                user_id=user.id, application_user_grant_id=grant.id,
                ticket_hash=_token_hash(token), jti=jti,
                intended_device_key_hash=intended_hash,
                issued_at=now, expires_at=expires,
            ))
            self._audit(session, "application.activation.issued",
                        application_id=app.id, user_id=user.id)
            session.commit()
            return {
                "activation_ticket": token, "expires_at": expires,
                "application_id": app.public_id, "user_id": user.id,
            }

    def get_activation_preview(self, token: str,
                               now: datetime | None = None) -> dict:
        """Read-only activation-ticket check for the QR enrollment page.

        Verifies the Ed25519 signature, the expiry, and the single-use
        row — WITHOUT consuming anything, so page views never spend the
        ticket (only ``consume_ticket_and_enroll`` does). Raises
        :class:`ActivationTicketExpired` for past-expiry rows (the page
        renders 410) and :class:`ActivationTicketInvalid` for everything
        else (malformed/forged/consumed/revoked → 404, no oracle)."""
        from app.applicationapi.errors import ActivationTicketExpired
        now = now or _utcnow()
        try:
            head, encoded, signature_text = (token or "").split(".")
            if head != "zgat1":
                raise ValueError
            payload = json.loads(b64url_decode(encoded).decode("utf-8"))
            signature = b64url_decode(signature_text, expected_length=64)
        except Exception as exc:
            raise ActivationTicketInvalid(
                "activation ticket is invalid") from exc
        if (payload.get("v") != 1
                or int(payload.get("exp", 0)) <= int(now.timestamp())
                or int(payload.get("iat", 0)) > int(now.timestamp()) + 30):
            # Expired payloads report 410 only when the row agrees they
            # were once real (a forged-but-expired token stays a 404).
            row_hint = self._activation_row_by_hash(_token_hash(token or ""))
            if row_hint is not None:
                raise ActivationTicketExpired("activation ticket expired")
            raise ActivationTicketInvalid("activation ticket is invalid")
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == payload.get("aid"),
            )).scalar_one_or_none()
            key = session.execute(select(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == (
                    app.id if app is not None else -1),
                ApplicationKeyModel.kid == payload.get("kid"),
                ApplicationKeyModel.purpose == "signing",
            )).scalar_one_or_none()
            if app is None or key is None or key.status != _ACTIVE:
                raise ActivationTicketInvalid("activation ticket is invalid")
            try:
                Ed25519PublicKey.from_public_bytes(
                    b64url_decode(key.public_key, expected_length=32)
                ).verify(signature, f"zgat1.{encoded}".encode("ascii"))
            except (InvalidSignature, ValueError) as exc:
                raise ActivationTicketInvalid(
                    "activation ticket is invalid") from exc
            row = session.execute(select(ApplicationActivationTicketModel).where(
                ApplicationActivationTicketModel.ticket_hash == _token_hash(token),
            )).scalar_one_or_none()
            if row is None or row.revoked_at is not None \
                    or row.consumed_at is not None:
                raise ActivationTicketInvalid("activation ticket is invalid")
            row_expires = row.expires_at
            if row_expires.tzinfo is None:
                row_expires = row_expires.replace(tzinfo=timezone.utc)
            if row_expires <= now:
                raise ActivationTicketExpired("activation ticket expired")
            return {
                "application_public_id": app.public_id,
                "application_name": app.name,
                "user_id": row.user_id,
                "grant_id": row.application_user_grant_id,
                "expires_at": row_expires,
            }

    def _activation_row_by_hash(self, ticket_hash: str):
        with self._sf() as session:
            return session.execute(select(ApplicationActivationTicketModel).where(
                ApplicationActivationTicketModel.ticket_hash == ticket_hash,
            )).scalar_one_or_none()

    # ------------------------------------------------------------------
    # request key lookup and durable anti-replay
    # ------------------------------------------------------------------
    def enrollment_request_key(self, application_public_id: str,
                               key_id: str) -> RequestKeyContext:
        with self._sf() as session:
            pair = session.execute(
                select(ApplicationModel, ApplicationKeyModel)
                .join(ApplicationKeyModel,
                      ApplicationKeyModel.application_id == ApplicationModel.id)
                .where(ApplicationModel.public_id == application_public_id,
                       ApplicationKeyModel.kid == key_id,
                       ApplicationKeyModel.purpose == "config_encryption")
            ).one_or_none()
            if pair is None:
                raise ApplicationAuthFailed("request authentication failed")
            app, key = pair
            return RequestKeyContext(
                application_db_id=app.id, application_public_id=app.public_id,
                application_status=app.status, key_db_id=key.id,
                key_id=key.kid, key_status=key.status,
                private_key=self._decrypt_private(key, app.public_id),
                application_access_mode=app.user_access_mode or "all_users",
            )

    def device_request_key(self, application_public_id: str, key_id: str,
                           device_key_id: str) -> RequestKeyContext:
        with self._sf() as session:
            row = session.execute(
                select(ApplicationModel, ApplicationKeyModel, SubscriptionDeviceModel)
                .join(ApplicationKeyModel,
                      ApplicationKeyModel.application_id == ApplicationModel.id)
                .join(SubscriptionDeviceModel,
                      SubscriptionDeviceModel.application_id == ApplicationModel.id)
                .where(ApplicationModel.public_id == application_public_id,
                       ApplicationKeyModel.kid == key_id,
                       ApplicationKeyModel.purpose == "config_encryption",
                       SubscriptionDeviceModel.device_key_id == device_key_id)
            ).one_or_none()
            if row is None:
                raise EnrollmentRequired("device enrollment required")
            app, key, device = row
            try:
                public_key = b64url_decode(
                    device.device_public_key or "", expected_length=32)
            except ValueError as exc:
                raise ApplicationAuthFailed("request authentication failed") from exc
            return RequestKeyContext(
                application_db_id=app.id, application_public_id=app.public_id,
                application_status=app.status, key_db_id=key.id,
                key_id=key.kid, key_status=key.status,
                private_key=self._decrypt_private(key, app.public_id),
                application_access_mode=app.user_access_mode or "all_users",
                device_db_id=device.id, device_key_id=device.device_key_id,
                device_public_key=public_key, device_status=device.device_status,
                user_id=device.user_id,
            )

    def consume_nonce(self, *, context: RequestKeyContext, nonce: str,
                      request_timestamp: datetime, expires_at: datetime) -> None:
        nonce_hash = self.identifier_hash("nonce", nonce)
        try:
            with self._sf() as session:
                # Opportunistic bounded-state cleanup keeps a public endpoint
                # from growing the replay ledger forever if no scheduler runs.
                session.execute(delete(ApplicationRequestNonceModel).where(
                    ApplicationRequestNonceModel.expires_at < _utcnow()))
                session.add(ApplicationRequestNonceModel(
                    application_id=context.application_db_id,
                    device_id=context.device_db_id,
                    application_key_id=context.key_db_id,
                    nonce_hash=nonce_hash,
                    request_timestamp=request_timestamp,
                    expires_at=expires_at,
                ))
                session.commit()
        except IntegrityError as exc:
            raise ReplayRejected("signed request was already used") from exc

    def purge_expired_nonces(self, before: datetime) -> int:
        with self._sf() as session:
            result = session.execute(delete(ApplicationRequestNonceModel).where(
                ApplicationRequestNonceModel.expires_at < before))
            session.commit()
            return int(result.rowcount or 0)

    # ------------------------------------------------------------------
    # durable IP + username throttle buckets
    # ------------------------------------------------------------------
    def assert_not_throttled(self, *, application_id: int,
                             username: str, source_ip: str,
                             now: datetime) -> None:
        keys = (
            ("username", self.identifier_hash("username", username)),
            ("ip", self.identifier_hash("ip", self.safe_source_ip(source_ip))),
        )
        with self._sf() as session:
            rows = session.execute(select(ApplicationAuthThrottleModel).where(
                ApplicationAuthThrottleModel.application_id == application_id,
                or_(*[
                    (ApplicationAuthThrottleModel.bucket_type == kind)
                    & (ApplicationAuthThrottleModel.bucket_hash == digest)
                    for kind, digest in keys
                ]),
            )).scalars().all()
            if any(_aware(row.blocked_until) and _aware(row.blocked_until) > now
                   for row in rows):
                raise ApplicationRateLimited("too many authentication attempts")

    def record_auth_failure(self, *, application_id: int, username: str,
                            source_ip: str, now: datetime,
                            max_failures: int, window_seconds: int,
                            block_seconds: int) -> None:
        keys = (
            ("username", self.identifier_hash("username", username)),
            ("ip", self.identifier_hash("ip", self.safe_source_ip(source_ip))),
        )
        for kind, digest in keys:
            for attempt in range(3):
                try:
                    with self._sf() as session:
                        row = session.execute(select(ApplicationAuthThrottleModel).where(
                            ApplicationAuthThrottleModel.application_id == application_id,
                            ApplicationAuthThrottleModel.bucket_type == kind,
                            ApplicationAuthThrottleModel.bucket_hash == digest,
                        ).with_for_update()).scalar_one_or_none()
                        if row is None:
                            row = ApplicationAuthThrottleModel(
                                application_id=application_id, bucket_type=kind,
                                bucket_hash=digest, failure_count=0,
                                window_started_at=now, updated_at=now)
                            session.add(row)
                        window_start = _aware(row.window_started_at) or now
                        if now - window_start >= timedelta(seconds=window_seconds):
                            row.window_started_at = now
                            row.failure_count = 0
                            row.blocked_until = None
                        row.failure_count += 1
                        row.updated_at = now
                        if row.failure_count >= max_failures:
                            row.blocked_until = now + timedelta(seconds=block_seconds)
                        session.commit()
                    break
                except IntegrityError:
                    if attempt == 2:
                        raise
        self.audit(
            "application.auth.failure", application_id=application_id,
            source_ip_hash=self.identifier_hash(
                "ip", self.safe_source_ip(source_ip)),
            result="denied", reason="invalid_credentials")

    def clear_auth_failures(self, *, application_id: int, username: str,
                            source_ip: str) -> None:
        keys = (
            ("username", self.identifier_hash("username", username)),
            ("ip", self.identifier_hash("ip", self.safe_source_ip(source_ip))),
        )
        with self._sf() as session:
            session.execute(delete(ApplicationAuthThrottleModel).where(
                ApplicationAuthThrottleModel.application_id == application_id,
                or_(*[
                    (ApplicationAuthThrottleModel.bucket_type == kind)
                    & (ApplicationAuthThrottleModel.bucket_hash == digest)
                    for kind, digest in keys
                ]),
            ))
            session.commit()

    # ------------------------------------------------------------------
    # user/grant/device status context
    # ------------------------------------------------------------------
    def enrollment_user_context(self, *, context: RequestKeyContext,
                                username: str) -> UserAuthContext | None:
        with self._sf() as session:
            row = session.execute(
                select(UserModel, ApplicationUserGrantModel,
                       func.coalesce(UserUsageModel.uplink_bytes, 0),
                       func.coalesce(UserUsageModel.downlink_bytes, 0))
                .outerjoin(ApplicationUserGrantModel,
                    (ApplicationUserGrantModel.user_id == UserModel.id)
                    & (ApplicationUserGrantModel.application_id
                       == context.application_db_id))
                .outerjoin(UserUsageModel, UserUsageModel.user_id == UserModel.id)
                .where(UserModel.app_username == username)
            ).one_or_none()
            if row is None:
                return None
            user, grant, up, down = row
            app = session.get(ApplicationModel, context.application_db_id)
            return UserAuthContext(
                application_db_id=context.application_db_id,
                application_public_id=context.application_public_id,
                application_status=context.application_status,
                application_key_db_id=context.key_db_id,
                application_key_id=context.key_id,
                application_key_status=context.key_status,
                user_id=user.id, app_username=user.app_username,
                password_hash=user.app_password_hash, user_status=user.status,
                access_mode=((user.access_mode or user.client_auth_mode)
                             or _portal_default_access_mode(session)),
                expire_at=_aware(user.expire_at),
                data_limit_bytes=user.data_limit_bytes,
                used_bytes=int(up or 0) + int(down or 0),
                device_limit=user.device_limit,
                grant_id=(grant.id if grant else None),
                grant_status=(grant.status if grant else None),
                application_access_mode=(
                    app.user_access_mode if app else "all_users") or "all_users",
            )

    def device_user_context(self, *, context: RequestKeyContext,
                            username: str | None = None) -> UserAuthContext | None:
        if context.user_id is None:
            return None
        with self._sf() as session:
            statement = (
                select(UserModel, ApplicationUserGrantModel,
                       func.coalesce(UserUsageModel.uplink_bytes, 0),
                       func.coalesce(UserUsageModel.downlink_bytes, 0))
                .outerjoin(ApplicationUserGrantModel,
                    (ApplicationUserGrantModel.user_id == UserModel.id)
                    & (ApplicationUserGrantModel.application_id
                       == context.application_db_id))
                .outerjoin(UserUsageModel, UserUsageModel.user_id == UserModel.id)
                .where(UserModel.id == context.user_id)
            )
            if username is not None:
                statement = statement.where(UserModel.app_username == username)
            row = session.execute(statement).one_or_none()
            if row is None:
                return None
            user, grant, up, down = row
            app = session.get(ApplicationModel, context.application_db_id)
            return UserAuthContext(
                application_db_id=context.application_db_id,
                application_public_id=context.application_public_id,
                application_status=context.application_status,
                application_key_db_id=context.key_db_id,
                application_key_id=context.key_id,
                application_key_status=context.key_status,
                user_id=user.id, app_username=user.app_username,
                password_hash=user.app_password_hash, user_status=user.status,
                access_mode=((user.access_mode or user.client_auth_mode)
                             or _portal_default_access_mode(session)),
                expire_at=_aware(user.expire_at),
                data_limit_bytes=user.data_limit_bytes,
                used_bytes=int(up or 0) + int(down or 0),
                device_limit=user.device_limit,
                grant_id=(grant.id if grant else None),
                grant_status=(grant.status if grant else None),
                application_access_mode=(
                    app.user_access_mode if app else "all_users") or "all_users",
                device_db_id=context.device_db_id,
                device_key_id=context.device_key_id,
                device_status=context.device_status,
                device_within_limit=(
                    context.device_db_id is not None
                    and device_within_limit(
                        session, user_id=user.id,
                        device_id=context.device_db_id,
                        device_limit=user.device_limit)),
            )

    def access_user_context(self, *, application_id: int,
                            application_public_id: str, user_id: int,
                            device_id: int, device_key_id: str,
                            application_key_id: int,
                            token_family_id: str,
                            now: datetime | None = None) -> UserAuthContext | None:
        """Reload every revocable authority for a bearer-token request."""
        now = now or _utcnow()
        with self._sf() as session:
            app = session.get(ApplicationModel, application_id)
            user = session.get(UserModel, user_id)
            device = session.get(SubscriptionDeviceModel, device_id)
            key = session.get(ApplicationKeyModel, application_key_id)
            grant = session.execute(select(ApplicationUserGrantModel).where(
                ApplicationUserGrantModel.application_id == application_id,
                ApplicationUserGrantModel.user_id == user_id,
            )).scalar_one_or_none()
            active_family = session.scalar(select(func.count(RefreshTokenModel.token_hash)).where(
                RefreshTokenModel.token_family_id == token_family_id,
                RefreshTokenModel.application_id == application_id,
                RefreshTokenModel.user_id == user_id,
                RefreshTokenModel.device_id == device_id,
                RefreshTokenModel.application_key_id == application_key_id,
                RefreshTokenModel.expires_at > now,
                RefreshTokenModel.revoked.is_(False),
            ))
            usage = session.get(UserUsageModel, user_id)
            # f-panel-7: a missing grant only disqualifies the context when
            # the application actually requires bound users; in the default
            # 'all_users' mode the grant row is optional bookkeeping.
            grant_required = (
                (app.user_access_mode if app else "all_users") or "all_users"
            ) == "bound_only"
            if (app is None or user is None or device is None or key is None
                    or (grant is None and grant_required) or not active_family
                    or app.public_id != application_public_id
                    or device.application_id != application_id
                    or device.user_id != user_id
                    or device.device_key_id != device_key_id
                    or key.application_id != application_id):
                if app is not None:
                    self._audit(
                        session, "application.access.denied",
                        application_id=app.id,
                        user_id=(user.id if user is not None else None),
                        device_id=(device.id if device is not None else None),
                        result="denied", reason="binding_or_family")
                    session.commit()
                return None
            return UserAuthContext(
                application_db_id=app.id,
                application_public_id=app.public_id,
                application_status=app.status,
                application_key_db_id=key.id,
                application_key_id=key.kid,
                application_key_status=key.status,
                user_id=user.id, app_username=user.app_username,
                password_hash=user.app_password_hash,
                user_status=user.status, access_mode=user.access_mode,
                expire_at=_aware(user.expire_at),
                data_limit_bytes=user.data_limit_bytes,
                used_bytes=((usage.uplink_bytes + usage.downlink_bytes) if usage else 0),
                device_limit=user.device_limit,
                grant_id=grant.id, grant_status=grant.status,
                application_access_mode=(
                    app.user_access_mode or "all_users"),
                device_db_id=device.id, device_key_id=device.device_key_id,
                device_status=device.device_status,
                token_family_id=token_family_id,
                device_within_limit=device_within_limit(
                    session, user_id=user.id, device_id=device.id,
                    device_limit=user.device_limit),
            )

    # ------------------------------------------------------------------
    # signed ticket verification + globally shared device-slot enrollment
    # ------------------------------------------------------------------
    def verify_ticket(self, token: str, *, context: UserAuthContext,
                      device_public_key: bytes, now: datetime) -> dict:
        try:
            prefix, encoded, signature_text = token.split(".")
            if prefix != "zgat1":
                raise ValueError
            payload = json.loads(b64url_decode(encoded).decode("utf-8"))
            signature = b64url_decode(signature_text, expected_length=64)
        except Exception as exc:
            raise ActivationTicketInvalid("activation ticket is invalid") from exc
        if (payload.get("v") != 1
                or payload.get("aid") != context.application_public_id
                or int(payload.get("uid", -1)) != context.user_id
                or int(payload.get("gid", -1)) != int(context.grant_id or -2)
                or int(payload.get("exp", 0)) <= int(now.timestamp())
                or int(payload.get("iat", 0)) > int(now.timestamp()) + 30):
            raise ActivationTicketInvalid("activation ticket is invalid")
        intended = payload.get("dkh")
        fingerprint = hashlib.sha256(device_public_key).hexdigest()
        if intended and not hmac.compare_digest(str(intended), fingerprint):
            raise ActivationTicketInvalid("activation ticket is invalid")

        with self._sf() as session:
            app = session.get(ApplicationModel, context.application_db_id)
            key = session.execute(select(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == context.application_db_id,
                ApplicationKeyModel.kid == payload.get("kid"),
                ApplicationKeyModel.purpose == "signing",
            )).scalar_one_or_none()
            if app is None or key is None or key.status != _ACTIVE:
                raise ActivationTicketInvalid("activation ticket is invalid")
            try:
                Ed25519PublicKey.from_public_bytes(
                    b64url_decode(key.public_key, expected_length=32)
                ).verify(signature, f"zgat1.{encoded}".encode("ascii"))
            except (InvalidSignature, ValueError) as exc:
                raise ActivationTicketInvalid("activation ticket is invalid") from exc
        payload["ticket_hash"] = _token_hash(token)
        payload["fingerprint"] = fingerprint
        payload["signing_key_db_id"] = key.id
        return payload

    def consume_ticket_and_enroll(self, *, context: UserAuthContext,
                                  ticket: dict, device_public_key: bytes,
                                  device_name: str | None, platform: str | None,
                                  app_version: str | None, source_ip: str,
                                  user_agent: str | None,
                                  now: datetime) -> SubscriptionDeviceModel:
        fingerprint = hashlib.sha256(device_public_key).hexdigest()
        public_text = b64url_encode(device_public_key)
        with self._sf() as session:
            # SQLite ignores FOR UPDATE. BEGIN IMMEDIATE takes its database
            # write reservation before count+insert, while MySQL/PostgreSQL
            # use the user-row FOR UPDATE below. This keeps one shared global
            # slot decision across simultaneous subscription/app enrollments.
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            user = session.execute(select(UserModel).where(
                UserModel.id == context.user_id).with_for_update()).scalar_one_or_none()
            grant = session.execute(select(ApplicationUserGrantModel).where(
                ApplicationUserGrantModel.id == context.grant_id).with_for_update()
            ).scalar_one_or_none()
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.id == context.application_db_id).with_for_update()
            ).scalar_one_or_none()
            ticket_row = session.execute(select(ApplicationActivationTicketModel).where(
                ApplicationActivationTicketModel.ticket_hash == ticket["ticket_hash"]
            ).with_for_update()).scalar_one_or_none()
            if (user is None or grant is None or app is None or ticket_row is None
                    or app.status != _ACTIVE or grant.status != _ACTIVE
                    or user.status != _ACTIVE or user.access_mode != _APPLICATION_MODE
                    or ticket_row.application_id != app.id
                    or ticket_row.user_id != user.id
                    or ticket_row.application_user_grant_id != grant.id
                    or ticket_row.application_key_id != ticket["signing_key_db_id"]
                    or ticket_row.jti != ticket.get("jti")
                    or ticket_row.consumed_at is not None
                    or ticket_row.revoked_at is not None
                    or (_aware(ticket_row.expires_at) or now) <= now):
                raise ActivationTicketInvalid("activation ticket is invalid")
            if ticket_row.intended_device_key_hash and not hmac.compare_digest(
                    ticket_row.intended_device_key_hash, fingerprint):
                raise ActivationTicketInvalid("activation ticket is invalid")

            existing = session.execute(select(SubscriptionDeviceModel).where(
                SubscriptionDeviceModel.user_id == user.id,
                SubscriptionDeviceModel.application_id == app.id,
                SubscriptionDeviceModel.device_key_fingerprint == fingerprint,
            )).scalar_one_or_none()
            if existing is not None:
                raise ActivationTicketInvalid("activation ticket is invalid")

            limit = max(0, int(user.device_limit or 0))
            if limit and occupying_device_count(session, user.id) >= limit:
                raise DeviceLimitReached("global device limit reached")

            device_key_id = "dev-" + secrets.token_hex(16)
            device = SubscriptionDeviceModel(
                user_id=user.id, application_id=app.id,
                device_hash=hashlib.sha256(
                    b"zagros-application-device-v1\0"
                    + str(app.id).encode("ascii") + b"\0"
                    + device_public_key).hexdigest(),
                device_hint=fingerprint[:8] + "…" + fingerprint[-6:],
                device_public_key=public_text,
                device_key_fingerprint=fingerprint,
                device_key_id=device_key_id, device_status=_ACTIVE,
                name=(device_name or "").strip()[:128] or None,
                platform=(platform or "").strip()[:32] or None,
                app_version=(app_version or "").strip()[:64] or None,
                first_seen=now, last_seen=now, last_authenticated_at=now,
                user_agent=(user_agent or "")[:512] or None,
                last_ip=self.safe_source_ip(source_ip),
            )
            session.add(device)
            session.flush()
            ticket_row.consumed_at = now
            self._audit(session, "application.device.enrolled",
                        application_id=app.id, user_id=user.id,
                        device_id=device.id,
                        source_ip_hash=self.identifier_hash(
                            "ip", self.safe_source_ip(source_ip)))
            session.commit()
            session.expunge(device)
            return device

    @staticmethod
    def app_attestation_message(*, application_public_id: str, app_kid: str,
                                username: str, device_public_key: bytes) -> bytes:
        """Canonical bytes the build-embedded app signing key must sign."""
        return ("\n".join([
            "ZAGROS-APP-ATTEST-V1",
            application_public_id,
            app_kid,
            username,
            b64url_encode(device_public_key),
        ]) + "\n").encode("utf-8")

    def verify_app_attestation(self, *, application_public_id: str,
                               app_kid: str, message: bytes,
                               signature_text: str) -> None:
        """Verify an enroll attestation from the app's embedded signing key.

        Only the application's ACTIVE signing key is accepted, so rotating or
        revoking it in the panel instantly retires older builds (kill switch).
        Failure maps to ApplicationAuthFailed (401) — never an oracle."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from app.applicationapi.errors import ApplicationAuthFailed
        allowed = set("abcdefghijklmnopqrstuvwxyz"
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not app_kid or len(app_kid) > 64 or not set(app_kid) <= allowed:
            raise ApplicationAuthFailed("app attestation is invalid")
        with self._sf() as session:
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.public_id == application_public_id
            )).scalar_one_or_none()
            if (app is None or app.status != _ACTIVE
                    or not app.active_signing_kid
                    or app_kid != app.active_signing_kid):
                raise ApplicationAuthFailed("app attestation is invalid")
            key = session.execute(select(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == app.id,
                ApplicationKeyModel.kid == app_kid,
                ApplicationKeyModel.purpose == "signing",
            )).scalar_one_or_none()
            if key is None or key.status != _ACTIVE:
                raise ApplicationAuthFailed("app attestation is invalid")
            try:
                public = Ed25519PublicKey.from_public_bytes(
                    b64url_decode(key.public_key, expected_length=32))
                public.verify(
                    b64url_decode(signature_text, expected_length=64), message)
            except (ValueError, InvalidSignature):
                raise ApplicationAuthFailed("app attestation is invalid")

    def enroll_attested_device(self, *, context: UserAuthContext,
                               device_public_key: bytes,
                               device_name: str | None, platform: str | None,
                               app_version: str | None, source_ip: str,
                               user_agent: str | None,
                               now: datetime) -> SubscriptionDeviceModel:
        """Device enrollment authorized by app attestation (no ticket row).

        Mirrors consume_ticket_and_enroll minus the ticket checks: same lock
        order (user -> grant -> app), same device-limit accounting, same
        audit action."""
        from app.applicationapi.errors import ApplicationAuthFailed
        fingerprint = hashlib.sha256(device_public_key).hexdigest()
        public_text = b64url_encode(device_public_key)
        with self._sf() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            user = session.execute(select(UserModel).where(
                UserModel.id == context.user_id).with_for_update()).scalar_one_or_none()
            grant = session.execute(select(ApplicationUserGrantModel).where(
                ApplicationUserGrantModel.id == context.grant_id).with_for_update()
            ).scalar_one_or_none()
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.id == context.application_db_id).with_for_update()
            ).scalar_one_or_none()
            if (user is None or grant is None or app is None
                    or app.status != _ACTIVE or grant.status != _ACTIVE
                    or user.status != _ACTIVE
                    or user.access_mode != _APPLICATION_MODE):
                raise ApplicationAuthFailed("enrollment request is invalid")
            existing = session.execute(select(SubscriptionDeviceModel).where(
                SubscriptionDeviceModel.user_id == user.id,
                SubscriptionDeviceModel.application_id == app.id,
                SubscriptionDeviceModel.device_key_fingerprint == fingerprint,
            )).scalar_one_or_none()
            if existing is not None:
                raise ApplicationAuthFailed("device already enrolled")
            limit = max(0, int(user.device_limit or 0))
            if limit and occupying_device_count(session, user.id) >= limit:
                raise DeviceLimitReached("global device limit reached")
            device_key_id = "dev-" + secrets.token_hex(16)
            device = SubscriptionDeviceModel(
                user_id=user.id, application_id=app.id,
                device_hash=hashlib.sha256(
                    b"zagros-application-device-v1\0"
                    + str(app.id).encode("ascii") + b"\0"
                    + device_public_key).hexdigest(),
                device_hint=fingerprint[:8] + "…" + fingerprint[-6:],
                device_public_key=public_text,
                device_key_fingerprint=fingerprint,
                device_key_id=device_key_id, device_status=_ACTIVE,
                name=(device_name or "").strip()[:128] or None,
                platform=(platform or "").strip()[:32] or None,
                app_version=(app_version or "").strip()[:64] or None,
                first_seen=now, last_seen=now, last_authenticated_at=now,
                user_agent=(user_agent or "")[:512] or None,
                last_ip=self.safe_source_ip(source_ip),
            )
            session.add(device)
            session.flush()
            self._audit(session, "application.device.enrolled",
                        application_id=app.id, user_id=user.id,
                        device_id=device.id,
                        source_ip_hash=self.identifier_hash(
                            "ip", self.safe_source_ip(source_ip)))
            session.commit()
            session.expunge(device)
            return device

    # ------------------------------------------------------------------
    # protected profile/device/config resources
    # ------------------------------------------------------------------
    def _assert_resource_authority(self, session, *, context: UserAuthContext,
                                   now: datetime, lock: bool = False):
        def _query(model, identity):
            statement = select(model).where(model.id == identity)
            return session.execute(
                statement.with_for_update() if lock else statement
            ).scalar_one_or_none()

        # Keep the same lock order as enrollment: user → grant → Application.
        # A single order avoids cross-feature deadlocks under MariaDB/PostgreSQL.
        user = _query(UserModel, context.user_id)
        grant = _query(ApplicationUserGrantModel, context.grant_id)
        app = _query(ApplicationModel, context.application_db_id)
        device = _query(SubscriptionDeviceModel, context.device_db_id)
        key = _query(ApplicationKeyModel, context.application_key_db_id)
        usage = session.get(UserUsageModel, context.user_id)
        active_family = session.scalar(select(func.count(
            RefreshTokenModel.token_hash)).where(
                RefreshTokenModel.token_family_id == context.token_family_id,
                RefreshTokenModel.application_id == context.application_db_id,
                RefreshTokenModel.user_id == context.user_id,
                RefreshTokenModel.device_id == context.device_db_id,
                RefreshTokenModel.application_key_id == (
                    context.application_key_db_id),
                RefreshTokenModel.expires_at > now,
                RefreshTokenModel.revoked.is_(False),
            ))
        used = (usage.uplink_bytes + usage.downlink_bytes) if usage else 0
        if (app is None or user is None or device is None or key is None
                or grant is None or not context.token_family_id or not active_family
                or app.id != context.application_db_id
                or app.public_id != context.application_public_id
                or app.status != _ACTIVE
                or user.status != _ACTIVE
                or user.access_mode != _APPLICATION_MODE
                or device.user_id != user.id
                or device.application_id != app.id
                or device.device_key_id != context.device_key_id
                or device.device_status != _ACTIVE
                or not device_within_limit(
                    session, user_id=user.id, device_id=device.id,
                    device_limit=user.device_limit)
                or key.application_id != app.id
                or key.id != context.application_key_db_id
                or key.kid != context.application_key_id
                or key.purpose != "config_encryption"
                or key.status != _ACTIVE
                or grant.application_id != app.id
                or grant.user_id != user.id
                or grant.status != _ACTIVE
                or (_aware(user.expire_at) is not None
                    and _aware(user.expire_at) <= now)
                or (user.data_limit_bytes is not None
                    and used >= user.data_limit_bytes)
                or (_aware(key.not_before) is not None
                    and _aware(key.not_before) > now)
                or (_aware(key.not_after) is not None
                    and _aware(key.not_after) <= now)):
            raise ApplicationForbidden("Application access denied")
        return app, user, device, key, grant, used

    def application_profile(self, *, context: UserAuthContext,
                            now: datetime) -> dict:
        with self._sf() as session:
            app, user, _device, _key, _grant, used = (
                self._assert_resource_authority(
                    session, context=context, now=now))
            online_at = _aware(user.online_at)
            remaining = (None if user.data_limit_bytes is None else
                         max(0, int(user.data_limit_bytes) - int(used)))
            return {
                "username": user.app_username or "",
                "status": user.status,
                "online": bool(
                    online_at and now - online_at < timedelta(seconds=90)),
                "used_bytes": int(used),
                "data_limit_bytes": user.data_limit_bytes,
                "remaining_bytes": remaining,
                "expire_at": _aware(user.expire_at),
                "application": {
                    "application_id": app.public_id,
                    "name": app.name,
                    "default_lang": app.default_lang,
                    "branding": dict(app.branding or {}),
                },
            }

    def application_devices(self, *, context: UserAuthContext,
                            now: datetime) -> list[dict]:
        with self._sf() as session:
            self._assert_resource_authority(
                session, context=context, now=now)
            rows = session.execute(select(SubscriptionDeviceModel).where(
                SubscriptionDeviceModel.application_id == context.application_db_id,
                SubscriptionDeviceModel.user_id == context.user_id,
                SubscriptionDeviceModel.device_key_id.isnot(None),
            ).order_by(
                SubscriptionDeviceModel.first_seen,
                SubscriptionDeviceModel.id,
            )).scalars().all()
            return [{
                "device_id": row.device_key_id or "",
                "key_fingerprint": row.device_key_fingerprint or "",
                "name": row.name,
                "platform": row.platform,
                "app_version": row.app_version,
                "status": row.device_status or "revoked",
                "is_current": row.id == context.device_db_id,
                "first_seen": _aware(row.first_seen),
                "last_seen": _aware(row.last_seen),
                "last_authenticated_at": _aware(row.last_authenticated_at),
                "revoked_at": _aware(row.revoked_at),
            } for row in rows]

    @staticmethod
    def _revoke_device_rows(session, *, device: SubscriptionDeviceModel,
                            now: datetime, reason: str) -> None:
        device.device_status = "revoked"
        device.revoked_at = now
        device.revoked_reason = reason
        session.execute(update(RefreshTokenModel).where(
            RefreshTokenModel.device_id == device.id,
            RefreshTokenModel.revoked.is_(False),
        ).values(
            revoked=True, revoked_at=now, revoked_reason="device_revoked"))
        session.execute(update(ApplicationConfigGrantModel).where(
            ApplicationConfigGrantModel.device_id == device.id,
            ApplicationConfigGrantModel.consumed_at.is_(None),
            ApplicationConfigGrantModel.revoked_at.is_(None),
        ).values(revoked_at=now, revoked_reason="device_revoked"))

    def revoke_application_device(self, *, context: UserAuthContext,
                                  target_device_key_id: str,
                                  source_ip: str, now: datetime) -> dict:
        with self._sf() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            self._assert_resource_authority(
                session, context=context, now=now, lock=True)
            target = session.execute(select(SubscriptionDeviceModel).where(
                SubscriptionDeviceModel.application_id == context.application_db_id,
                SubscriptionDeviceModel.user_id == context.user_id,
                SubscriptionDeviceModel.device_key_id == target_device_key_id,
            ).with_for_update()).scalar_one_or_none()
            if target is None:
                raise DeviceNotFound("device not found")
            if target.device_status != "revoked":
                self._revoke_device_rows(
                    session, device=target, now=now, reason="self_service")
                self._audit(
                    session, "application.device.revoked",
                    application_id=context.application_db_id,
                    user_id=context.user_id, device_id=target.id,
                    source_ip_hash=self.identifier_hash(
                        "ip", self.safe_source_ip(source_ip)))
                session.commit()
            return {"device_id": target_device_key_id, "status": "revoked"}

    def admin_revoke_application_device(self, *, application_public_id: str,
                                        target_device_key_id: str,
                                        now: datetime | None = None) -> dict:
        now = now or _utcnow()
        with self._sf() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            row = session.execute(
                select(ApplicationModel.id, SubscriptionDeviceModel.id,
                       SubscriptionDeviceModel.user_id)
                .join(SubscriptionDeviceModel,
                      SubscriptionDeviceModel.application_id == ApplicationModel.id)
                .where(
                    ApplicationModel.public_id == application_public_id,
                    SubscriptionDeviceModel.device_key_id == target_device_key_id,
                )
            ).one_or_none()
            if row is None:
                raise DeviceNotFound("device not found")
            app_id, target_id, user_id = row
            # Revocation frees a slot, so serialize it on the same user-row
            # allocation lock used by both enrollment modes.
            session.execute(select(UserModel).where(
                UserModel.id == user_id).with_for_update()).scalar_one()
            app = session.execute(select(ApplicationModel).where(
                ApplicationModel.id == app_id).with_for_update()).scalar_one()
            target = session.execute(select(SubscriptionDeviceModel).where(
                SubscriptionDeviceModel.id == target_id,
                SubscriptionDeviceModel.application_id == app.id,
                SubscriptionDeviceModel.user_id == user_id,
            ).with_for_update()).scalar_one_or_none()
            if target is None:
                raise DeviceNotFound("device not found")
            if target.device_status != "revoked":
                self._revoke_device_rows(
                    session, device=target, now=now, reason="administrator")
                self._audit(
                    session, "application.device.revoked",
                    application_id=app.id, user_id=target.user_id,
                    device_id=target.id, actor="admin")
                session.commit()
            return {"device_id": target_device_key_id, "status": "revoked"}

    def issue_config_grants(self, *, context: UserAuthContext,
                            core_ids: list[str] | None = None,
                            selectors: list[dict] | None = None,
                            now: datetime,
                            expires_at: datetime) -> list[ConfigGrantContext]:
        requested = selectors or [
            {"core_id": core_id, "protocol": None, "source_account_id": None}
            for core_id in (core_ids or [])
        ]
        unique: list[dict] = []
        seen: set[tuple[str, str | None, str | None]] = set()
        for raw in requested:
            item = {
                "core_id": str(raw.get("core_id") or "")[:32],
                "protocol": (str(raw.get("protocol"))[:32]
                             if raw.get("protocol") else None),
                "source_account_id": (str(raw.get("source_account_id"))[:190]
                                      if raw.get("source_account_id") else None),
            }
            key = (item["core_id"], item["protocol"], item["source_account_id"])
            if item["core_id"] and key not in seen:
                seen.add(key)
                unique.append(item)
        if not unique or expires_at <= now:
            return []
        with self._sf() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            app, _user, _device, _config_key, _grant, _used = (
                self._assert_resource_authority(
                    session, context=context, now=now, lock=True))
            signing_key = session.execute(select(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == app.id,
                ApplicationKeyModel.kid == app.active_signing_kid,
                ApplicationKeyModel.purpose == "signing",
            )).scalar_one_or_none()
            if (signing_key is None or signing_key.status != _ACTIVE
                    or (_aware(signing_key.not_before) is not None
                        and _aware(signing_key.not_before) > now)
                    or (_aware(signing_key.not_after) is not None
                        and _aware(signing_key.not_after) <= now)):
                raise ApplicationForbidden("Application access denied")
            session.execute(update(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.application_id == context.application_db_id,
                ApplicationConfigGrantModel.user_id == context.user_id,
                ApplicationConfigGrantModel.device_id == context.device_db_id,
                ApplicationConfigGrantModel.consumed_at.is_(None),
                ApplicationConfigGrantModel.revoked_at.is_(None),
            ).values(revoked_at=now, revoked_reason="superseded"))
            rows = []
            for selector in unique:
                row = ApplicationConfigGrantModel(
                    public_id=str(uuid4()),
                    application_id=context.application_db_id,
                    user_id=context.user_id,
                    device_id=context.device_db_id,
                    application_key_id=context.application_key_db_id,
                    token_family_id=context.token_family_id or "",
                    core_id=selector["core_id"],
                    protocol=selector["protocol"],
                    source_account_id=selector["source_account_id"],
                    issued_at=now, expires_at=expires_at,
                )
                session.add(row)
                rows.append(row)
            session.flush()
            self._audit(
                session, "application.config.grants_issued",
                application_id=context.application_db_id,
                user_id=context.user_id, device_id=context.device_db_id,
                detail={"count": len(rows)})
            session.commit()
            return [ConfigGrantContext(
                public_id=row.public_id, core_id=row.core_id,
                protocol=row.protocol, source_account_id=row.source_account_id,
                connection_id=row.connection_id,
                expires_at=_aware(row.expires_at) or expires_at,
            ) for row in rows]

    def inspect_config_grant(self, *, context: UserAuthContext,
                             public_id: str, now: datetime) -> ConfigGrantContext:
        with self._sf() as session:
            self._assert_resource_authority(
                session, context=context, now=now)
            row = session.execute(select(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.public_id == public_id,
                ApplicationConfigGrantModel.application_id == context.application_db_id,
                ApplicationConfigGrantModel.user_id == context.user_id,
                ApplicationConfigGrantModel.device_id == context.device_db_id,
                ApplicationConfigGrantModel.application_key_id == (
                    context.application_key_db_id),
                ApplicationConfigGrantModel.token_family_id == (
                    context.token_family_id),
            )).scalar_one_or_none()
            if row is None or row.revoked_at is not None:
                raise ConfigGrantInvalid("config grant is invalid")
            if row.consumed_at is not None:
                raise ConfigGrantConsumed("config grant was already consumed")
            if (_aware(row.expires_at) or now) <= now:
                raise ConfigGrantExpired("config grant expired")
            return ConfigGrantContext(
                public_id=row.public_id, core_id=row.core_id,
                protocol=row.protocol, source_account_id=row.source_account_id,
                connection_id=row.connection_id,
                expires_at=_aware(row.expires_at) or now)

    def consume_config_grant(self, *, context: UserAuthContext,
                             public_id: str,
                             now: datetime) -> ConfigDeliveryMaterial:
        with self._sf() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            app, user, device, config_key, _grant, _used = (
                self._assert_resource_authority(
                    session, context=context, now=now, lock=True))
            row = session.execute(select(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.public_id == public_id,
                ApplicationConfigGrantModel.application_id == app.id,
                ApplicationConfigGrantModel.user_id == user.id,
                ApplicationConfigGrantModel.device_id == device.id,
                ApplicationConfigGrantModel.application_key_id == config_key.id,
                ApplicationConfigGrantModel.token_family_id == (
                    context.token_family_id),
            ).with_for_update()).scalar_one_or_none()
            if row is None or row.revoked_at is not None:
                raise ConfigGrantInvalid("config grant is invalid")
            if row.consumed_at is not None:
                raise ConfigGrantConsumed("config grant was already consumed")
            expires_at = _aware(row.expires_at) or now
            if expires_at <= now:
                row.revoked_at = now
                row.revoked_reason = "expired"
                self._audit(
                    session, "application.config.denied",
                    application_id=app.id, user_id=user.id,
                    device_id=device.id, result="denied", reason="expired")
                session.commit()
                raise ConfigGrantExpired("config grant expired")
            if not row.connection_id:
                raise ConnectionRequired("start a connection before consuming its config")
            connection = session.execute(select(ApplicationConnectionModel).where(
                ApplicationConnectionModel.public_id == row.connection_id,
                ApplicationConnectionModel.application_id == app.id,
                ApplicationConnectionModel.user_id == user.id,
                ApplicationConnectionModel.device_id == device.id,
            ).with_for_update()).scalar_one_or_none()
            lease = (session.execute(select(ApplicationConnectionLeaseModel).where(
                ApplicationConnectionLeaseModel.connection_id == connection.id,
            ).with_for_update()).scalar_one_or_none() if connection is not None else None)
            if (connection is None or lease is None
                    or connection.status != "active" or lease.status != "active"
                    or (_aware(lease.not_after) or now) <= now):
                raise ConnectionRequired("connection lease is not active")

            claimed = session.execute(update(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.id == row.id,
                ApplicationConfigGrantModel.consumed_at.is_(None),
                ApplicationConfigGrantModel.revoked_at.is_(None),
            ).values(consumed_at=now))
            if claimed.rowcount != 1:
                session.rollback()
                raise ConfigGrantConsumed("config grant was already consumed")

            signing_key = session.execute(select(ApplicationKeyModel).where(
                ApplicationKeyModel.application_id == app.id,
                ApplicationKeyModel.kid == app.active_signing_kid,
                ApplicationKeyModel.purpose == "signing",
            )).scalar_one_or_none()
            if (signing_key is None or signing_key.status != _ACTIVE
                    or (_aware(signing_key.not_before) is not None
                        and _aware(signing_key.not_before) > now)
                    or (_aware(signing_key.not_after) is not None
                        and _aware(signing_key.not_after) <= now)):
                session.rollback()
                raise ApplicationForbidden("Application access denied")
            try:
                device_public_key = b64url_decode(
                    device.device_public_key or "", expected_length=32)
                config_private = self._decrypt_private(config_key, app.public_id)
                signing_private = self._decrypt_private(signing_key, app.public_id)
            except ValueError as exc:
                session.rollback()
                raise ApplicationAuthFailed("config delivery failed") from exc
            self._audit(
                session, "application.config.grant_consumed",
                application_id=app.id, user_id=user.id,
                device_id=device.id, detail={"core_id": row.core_id})
            session.commit()
            return ConfigDeliveryMaterial(
                public_id=row.public_id, core_id=row.core_id,
                protocol=row.protocol, source_account_id=row.source_account_id,
                connection_id=row.connection_id, expires_at=expires_at,
                application_public_id=app.public_id,
                config_key_id=config_key.kid,
                config_private_key=config_private,
                signing_key_id=signing_key.kid,
                signing_private_key=signing_private,
                device_key_id=device.device_key_id or "",
                device_public_key=device_public_key,
            )

    # ------------------------------------------------------------------
    # refresh token issuance / rotation / family replay revocation
    # ------------------------------------------------------------------
    @staticmethod
    def new_refresh(*, ttl_seconds: int, now: datetime,
                    family_id: str | None = None) -> RefreshIssue:
        secret = secrets.token_urlsafe(32)
        return RefreshIssue(
            secret=secret, token_hash=_token_hash(secret),
            family_id=family_id or secrets.token_hex(24),
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

    def save_initial_refresh(self, *, context: UserAuthContext,
                             device_id: int, issue: RefreshIssue,
                             now: datetime, user_agent: str | None) -> None:
        with self._sf() as session:
            session.add(RefreshTokenModel(
                token_hash=issue.token_hash, user_id=context.user_id,
                application_id=context.application_db_id, device_id=device_id,
                application_key_id=context.application_key_db_id,
                token_family_id=issue.family_id, expires_at=issue.expires_at,
                revoked=False, created_at=now,
                user_agent=(user_agent or "")[:256] or None,
            ))
            self._audit(session, "application.auth.success",
                        application_id=context.application_db_id,
                        user_id=context.user_id, device_id=device_id)
            session.commit()

    def rotate_refresh(self, *, refresh_secret: str,
                       request_context: RequestKeyContext,
                       ttl_seconds: int, now: datetime,
                       user_agent: str | None) -> tuple[UserAuthContext, RefreshIssue]:
        token_hash = _token_hash(refresh_secret)
        with self._sf() as session:
            old = session.execute(select(RefreshTokenModel).where(
                RefreshTokenModel.token_hash == token_hash
            ).with_for_update()).scalar_one_or_none()
            if old is None:
                raise ApplicationAuthFailed("refresh token is invalid")
            if old.revoked:
                if old.token_family_id:
                    session.execute(update(RefreshTokenModel).where(
                        RefreshTokenModel.token_family_id == old.token_family_id
                    ).values(revoked=True, revoked_at=now,
                             revoked_reason="refresh_reuse"))
                    session.execute(update(ApplicationConfigGrantModel).where(
                        ApplicationConfigGrantModel.token_family_id == (
                            old.token_family_id),
                        ApplicationConfigGrantModel.consumed_at.is_(None),
                        ApplicationConfigGrantModel.revoked_at.is_(None),
                    ).values(revoked_at=now, revoked_reason="refresh_reuse"))
                    self._audit(session, "application.refresh.replay",
                                application_id=old.application_id,
                                user_id=old.user_id, device_id=old.device_id,
                                result="denied", reason="refresh_reuse")
                    session.commit()
                raise ApplicationAuthFailed("refresh token is invalid")
            if (_aware(old.expires_at) or now) <= now:
                old.revoked = True
                old.revoked_at = now
                old.revoked_reason = "expired"
                if old.token_family_id:
                    session.execute(update(ApplicationConfigGrantModel).where(
                        ApplicationConfigGrantModel.token_family_id == (
                            old.token_family_id),
                        ApplicationConfigGrantModel.consumed_at.is_(None),
                        ApplicationConfigGrantModel.revoked_at.is_(None),
                    ).values(revoked_at=now, revoked_reason="refresh_expired"))
                session.commit()
                raise ApplicationAuthFailed("refresh token is invalid")
            if (old.application_id != request_context.application_db_id
                    or old.device_id != request_context.device_db_id
                    or old.application_key_id != request_context.key_db_id
                    or not old.token_family_id):
                raise ApplicationAuthFailed("refresh token is invalid")

            app = session.get(ApplicationModel, old.application_id)
            device = session.get(SubscriptionDeviceModel, old.device_id)
            user = session.get(UserModel, old.user_id)
            grant = session.execute(select(ApplicationUserGrantModel).where(
                ApplicationUserGrantModel.application_id == old.application_id,
                ApplicationUserGrantModel.user_id == old.user_id,
            )).scalar_one_or_none()
            key = session.get(ApplicationKeyModel, old.application_key_id)
            usage = session.get(UserUsageModel, old.user_id)
            if (app is None or device is None or user is None or grant is None
                    or key is None):
                raise ApplicationAuthFailed("refresh token is invalid")
            context = UserAuthContext(
                application_db_id=app.id,
                application_public_id=app.public_id,
                application_status=app.status,
                application_key_db_id=key.id,
                application_key_id=key.kid,
                application_key_status=key.status,
                user_id=user.id, app_username=user.app_username,
                password_hash=user.app_password_hash,
                user_status=user.status, access_mode=user.access_mode,
                expire_at=_aware(user.expire_at),
                data_limit_bytes=user.data_limit_bytes,
                used_bytes=((usage.uplink_bytes + usage.downlink_bytes) if usage else 0),
                device_limit=user.device_limit,
                grant_id=grant.id, grant_status=grant.status,
                device_db_id=device.id, device_key_id=device.device_key_id,
                device_status=device.device_status,
                device_within_limit=device_within_limit(
                    session, user_id=user.id, device_id=device.id,
                    device_limit=user.device_limit),
            )
            issue = self.new_refresh(
                ttl_seconds=ttl_seconds, now=now,
                family_id=old.token_family_id)
            # Conditional claim is the cross-dialect race guard. Even where
            # SELECT FOR UPDATE is ignored (SQLite), only one worker can flip
            # this exact unrevoked row; a loser treats the request as replay.
            claimed = session.execute(update(RefreshTokenModel).where(
                RefreshTokenModel.token_hash == old.token_hash,
                RefreshTokenModel.revoked.is_(False),
            ).values(
                revoked=True, rotated_to=issue.token_hash,
                last_used_at=now, revoked_at=now, revoked_reason="rotated",
            ))
            if claimed.rowcount != 1:
                session.execute(update(RefreshTokenModel).where(
                    RefreshTokenModel.token_family_id == old.token_family_id
                ).values(revoked=True, revoked_at=now,
                         revoked_reason="refresh_reuse"))
                session.execute(update(ApplicationConfigGrantModel).where(
                    ApplicationConfigGrantModel.token_family_id == (
                        old.token_family_id),
                    ApplicationConfigGrantModel.consumed_at.is_(None),
                    ApplicationConfigGrantModel.revoked_at.is_(None),
                ).values(revoked_at=now, revoked_reason="refresh_reuse"))
                self._audit(session, "application.refresh.replay",
                            application_id=old.application_id,
                            user_id=old.user_id, device_id=old.device_id,
                            result="denied", reason="refresh_reuse")
                session.commit()
                raise ApplicationAuthFailed("refresh token is invalid")
            session.add(RefreshTokenModel(
                token_hash=issue.token_hash, user_id=user.id,
                application_id=app.id, device_id=device.id,
                application_key_id=key.id,
                token_family_id=issue.family_id,
                parent_token_hash=old.token_hash,
                expires_at=issue.expires_at, revoked=False,
                created_at=now, user_agent=(user_agent or "")[:256] or None,
            ))
            device.last_seen = now
            device.last_authenticated_at = now
            self._audit(session, "application.refresh.rotated",
                        application_id=app.id, user_id=user.id,
                        device_id=device.id)
            session.commit()
            return context, issue

    def revoke_refresh_family(self, *, refresh_secret: str,
                              request_context: RequestKeyContext,
                              now: datetime) -> None:
        token_hash = _token_hash(refresh_secret)
        with self._sf() as session:
            row = session.get(RefreshTokenModel, token_hash)
            # Logout is idempotent and deliberately returns no token oracle.
            if (row is not None
                    and row.application_id == request_context.application_db_id
                    and row.device_id == request_context.device_db_id
                    and row.token_family_id):
                session.execute(update(RefreshTokenModel).where(
                    RefreshTokenModel.token_family_id == row.token_family_id
                ).values(revoked=True, revoked_at=now,
                         revoked_reason="logout"))
                session.execute(update(ApplicationConfigGrantModel).where(
                    ApplicationConfigGrantModel.token_family_id == (
                        row.token_family_id),
                    ApplicationConfigGrantModel.consumed_at.is_(None),
                    ApplicationConfigGrantModel.revoked_at.is_(None),
                ).values(revoked_at=now, revoked_reason="logout"))
                self._audit(session, "application.auth.logout",
                            application_id=row.application_id,
                            user_id=row.user_id, device_id=row.device_id)
                session.commit()

    def mark_login_success(self, *, device_id: int, now: datetime,
                           source_ip: str, user_agent: str | None) -> None:
        with self._sf() as session:
            device = session.get(SubscriptionDeviceModel, device_id)
            if device is not None:
                device.last_seen = now
                device.last_authenticated_at = now
                device.last_ip = self.safe_source_ip(source_ip)
                device.user_agent = (user_agent or "")[:512] or None
                session.commit()

    # ------------------------------------------------------------------
    # device-scoped connection leases
    # ------------------------------------------------------------------
    @staticmethod
    def _lease_aad(public_id: str, account_id: str) -> str:
        return f"application-lease:{public_id}:{account_id}"

    def _lease_settings(self, row: ApplicationConnectionLeaseModel) -> dict:
        if not row.credentials_enc:
            return {}
        return self._lease_cipher.decrypt_json(
            row.credentials_enc, aad=self._lease_aad(row.public_id, row.account_id))

    @staticmethod
    def _connection_active_key(context: UserAuthContext, core_id: str,
                               protocol: str) -> str:
        return (f"{context.application_db_id}:{context.device_db_id}:"
                f"{core_id}:{protocol}")

    def _lease_context(self, connection: ApplicationConnectionModel,
                       lease: ApplicationConnectionLeaseModel, *,
                       created: bool = False, decrypt: bool = False,
                       settings: dict | None = None) -> ConnectionLeaseContext:
        return ConnectionLeaseContext(
            connection_db_id=connection.id,
            connection_id=connection.public_id,
            lease_id=lease.public_id,
            application_id=connection.application_id,
            user_id=connection.user_id,
            device_id=connection.device_id,
            core_id=connection.core_id,
            protocol=connection.protocol,
            node_id=connection.node_id,
            target_kind=connection.target_kind,
            account_id=lease.account_id,
            status=connection.status,
            observed_status=connection.observed_status,
            teardown_capability=connection.teardown_capability,
            not_after=_aware(lease.not_after) or _utcnow(),
            renewed_at=_aware(connection.renewed_at),
            observed_at=_aware(connection.observed_at),
            last_error=connection.last_error,
            settings=(settings if settings is not None else
                      self._lease_settings(lease) if decrypt else {}),
            created=created,
        )

    def reserve_connection(self, *, context: UserAuthContext,
                           config_id: str, node_id: int | None,
                           not_after: datetime, now: datetime) -> ConnectionLeaseContext:
        """Claim one list selector and create/renew exactly one active lease."""
        with self._sf() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            app, user, device, _key, _grant, _used = self._assert_resource_authority(
                session, context=context, now=now, lock=True)
            selector = session.execute(select(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.public_id == config_id,
                ApplicationConfigGrantModel.application_id == app.id,
                ApplicationConfigGrantModel.user_id == user.id,
                ApplicationConfigGrantModel.device_id == device.id,
                ApplicationConfigGrantModel.application_key_id == (
                    context.application_key_db_id),
                ApplicationConfigGrantModel.token_family_id == context.token_family_id,
            ).with_for_update()).scalar_one_or_none()
            if selector is None or selector.revoked_at is not None:
                raise ConfigGrantInvalid("config grant is invalid")
            if selector.consumed_at is not None:
                raise ConfigGrantConsumed("config grant was already consumed")
            if (_aware(selector.expires_at) or now) <= now:
                selector.revoked_at = now
                selector.revoked_reason = "expired"
                session.commit()
                raise ConfigGrantExpired("config grant expired")
            if not selector.protocol or not selector.source_account_id:
                raise ConnectionRequired("request a fresh connection-scoped config list")
            active_key = self._connection_active_key(
                context, selector.core_id, selector.protocol)
            connection = session.execute(select(ApplicationConnectionModel).where(
                ApplicationConnectionModel.active_key == active_key
            ).with_for_update()).scalar_one_or_none()
            created = False
            if connection is None:
                connection = ApplicationConnectionModel(
                    public_id=str(uuid4()), application_id=app.id, user_id=user.id,
                    device_id=device.id,
                    application_key_id=context.application_key_db_id,
                    token_family_id=context.token_family_id or "",
                    core_id=selector.core_id, protocol=selector.protocol,
                    node_id=node_id, target_kind=("node" if node_id else "local"),
                    active_key=active_key, status="pending",
                    observed_status="unknown", requested_at=now,
                    not_after=not_after, updated_at=now,
                )
                session.add(connection)
                session.flush()
                lease = ApplicationConnectionLeaseModel(
                    public_id=str(uuid4()), connection_id=connection.id,
                    application_id=app.id, user_id=user.id, device_id=device.id,
                    core_id=selector.core_id, protocol=selector.protocol,
                    node_id=node_id, target_kind=("node" if node_id else "local"),
                    account_id="zgl-" + secrets.token_hex(12),
                    status="pending", issued_at=now, not_after=not_after,
                )
                session.add(lease)
                session.flush()
                created = True
            else:
                lease = session.execute(select(ApplicationConnectionLeaseModel).where(
                    ApplicationConnectionLeaseModel.connection_id == connection.id
                ).with_for_update()).scalar_one_or_none()
                if lease is None:
                    raise ConnectionFailed("connection lease is unavailable")
                connection.application_key_id = context.application_key_db_id
                connection.token_family_id = context.token_family_id or ""
                connection.not_after = not_after
                connection.renewed_at = now
                connection.updated_at = now
                lease.not_after = not_after
                lease.renewed_at = now
                if connection.status in {"error", "pending"}:
                    connection.status = "pending"
                    lease.status = "pending"
            # The same selector becomes the one-time delivery authority. It is
            # not consumed here; configs/{id} performs the final atomic claim.
            selector.connection_id = connection.public_id
            self._audit(
                session, "application.connection.reserved",
                application_id=app.id, user_id=user.id, device_id=device.id,
                detail={"core_id": connection.core_id})
            session.commit()
            return self._lease_context(
                connection, lease, created=created, decrypt=not created)

    def complete_connection(self, *, connection_id: str, settings: dict,
                            teardown_capability: str,
                            not_after: datetime, now: datetime) -> ConnectionLeaseContext:
        with self._sf() as session:
            connection = session.execute(select(ApplicationConnectionModel).where(
                ApplicationConnectionModel.public_id == connection_id
            ).with_for_update()).scalar_one_or_none()
            if connection is None:
                raise ConnectionNotFound("connection not found")
            lease = session.execute(select(ApplicationConnectionLeaseModel).where(
                ApplicationConnectionLeaseModel.connection_id == connection.id
            ).with_for_update()).scalar_one()
            lease.credentials_enc = self._lease_cipher.encrypt_json(
                dict(settings), aad=self._lease_aad(lease.public_id, lease.account_id))
            lease.status = "active"
            lease.applied_at = now
            lease.not_after = not_after
            lease.last_error = None
            connection.status = "active"
            connection.activated_at = connection.activated_at or now
            connection.renewed_at = now
            connection.not_after = not_after
            connection.updated_at = now
            connection.last_error = None
            connection.teardown_capability = teardown_capability[:32]
            self._audit(
                session, "application.connection.active",
                application_id=connection.application_id, user_id=connection.user_id,
                device_id=connection.device_id,
                detail={"core_id": connection.core_id})
            session.commit()
            return self._lease_context(
                connection, lease, decrypt=False, settings=dict(settings))

    def fail_connection(self, *, connection_id: str, now: datetime,
                        reason: str = "provision_failed") -> None:
        with self._sf() as session:
            connection = session.execute(select(ApplicationConnectionModel).where(
                ApplicationConnectionModel.public_id == connection_id
            ).with_for_update()).scalar_one_or_none()
            if connection is None:
                return
            lease = session.execute(select(ApplicationConnectionLeaseModel).where(
                ApplicationConnectionLeaseModel.connection_id == connection.id
            ).with_for_update()).scalar_one_or_none()
            connection.status = "error"
            connection.active_key = None
            connection.last_error = reason[:1000]
            connection.updated_at = now
            connection.stopped_at = now
            if lease is not None:
                lease.status = "error"
                lease.revoke_requested_at = now
                lease.revoke_reason = reason[:500]
                lease.last_error = reason[:1000]
            session.execute(update(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.connection_id == connection.public_id,
                ApplicationConfigGrantModel.consumed_at.is_(None),
                ApplicationConfigGrantModel.revoked_at.is_(None),
            ).values(revoked_at=now, revoked_reason=reason[:500]))
            session.commit()

    def connection_for_config(self, *, context: UserAuthContext,
                              config_id: str, now: datetime) -> ConnectionLeaseContext:
        """Recheck authority and load only the bound temporary account."""
        with self._sf() as session:
            self._assert_resource_authority(session, context=context, now=now)
            grant = session.execute(select(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.public_id == config_id,
                ApplicationConfigGrantModel.application_id == context.application_db_id,
                ApplicationConfigGrantModel.user_id == context.user_id,
                ApplicationConfigGrantModel.device_id == context.device_db_id,
            )).scalar_one_or_none()
            if grant is None or not grant.connection_id:
                raise ConnectionRequired("start a connection before consuming its config")
            connection = session.execute(select(ApplicationConnectionModel).where(
                ApplicationConnectionModel.public_id == grant.connection_id,
                ApplicationConnectionModel.application_id == context.application_db_id,
                ApplicationConnectionModel.user_id == context.user_id,
                ApplicationConnectionModel.device_id == context.device_db_id,
            )).scalar_one_or_none()
            lease = (session.execute(select(ApplicationConnectionLeaseModel).where(
                ApplicationConnectionLeaseModel.connection_id == connection.id
            )).scalar_one_or_none() if connection is not None else None)
            if (connection is None or lease is None
                    or connection.status != "active" or lease.status != "active"
                    or (_aware(lease.not_after) or now) <= now):
                raise ConnectionRequired("connection lease is not active")
            return self._lease_context(connection, lease, decrypt=True)

    def request_connection_stop(self, *, context: UserAuthContext,
                                connection_id: str, now: datetime,
                                reason: str = "client_stop") -> ConnectionLeaseContext:
        with self._sf() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            self._assert_resource_authority(
                session, context=context, now=now, lock=True)
            connection = session.execute(select(ApplicationConnectionModel).where(
                ApplicationConnectionModel.public_id == connection_id,
                ApplicationConnectionModel.application_id == context.application_db_id,
                ApplicationConnectionModel.user_id == context.user_id,
                ApplicationConnectionModel.device_id == context.device_db_id,
            ).with_for_update()).scalar_one_or_none()
            if connection is None:
                raise ConnectionNotFound("connection not found")
            lease = session.execute(select(ApplicationConnectionLeaseModel).where(
                ApplicationConnectionLeaseModel.connection_id == connection.id
            ).with_for_update()).scalar_one()
            if connection.status not in {"stopped", "expired", "revoked"}:
                connection.status = "revoke_pending"
                connection.active_key = None
                connection.stop_reason = reason[:500]
                connection.stopped_at = now
                connection.updated_at = now
                lease.status = "revoke_pending"
                lease.revoke_requested_at = now
                lease.revoke_reason = reason[:500]
            session.execute(update(ApplicationConfigGrantModel).where(
                ApplicationConfigGrantModel.connection_id == connection.public_id,
                ApplicationConfigGrantModel.consumed_at.is_(None),
                ApplicationConfigGrantModel.revoked_at.is_(None),
            ).values(revoked_at=now, revoked_reason=reason[:500]))
            session.commit()
            return self._lease_context(connection, lease, decrypt=True)

    def connection_statuses(self, *, context: UserAuthContext,
                            now: datetime,
                            connection_id: str | None = None) -> list[ConnectionLeaseContext]:
        with self._sf() as session:
            self._assert_resource_authority(session, context=context, now=now)
            statement = select(
                ApplicationConnectionModel, ApplicationConnectionLeaseModel
            ).join(
                ApplicationConnectionLeaseModel,
                ApplicationConnectionLeaseModel.connection_id == ApplicationConnectionModel.id,
            ).where(
                ApplicationConnectionModel.application_id == context.application_db_id,
                ApplicationConnectionModel.user_id == context.user_id,
                ApplicationConnectionModel.device_id == context.device_db_id,
            )
            if connection_id:
                statement = statement.where(
                    ApplicationConnectionModel.public_id == connection_id)
            rows = session.execute(statement.order_by(
                ApplicationConnectionModel.requested_at.desc(),
                ApplicationConnectionModel.id.desc(),
            )).all()
            return [self._lease_context(connection, lease) for connection, lease in rows]

    def renew_connection(self, *, context: UserAuthContext,
                         connection_id: str, not_after: datetime,
                         now: datetime) -> ConnectionLeaseContext:
        with self._sf() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            self._assert_resource_authority(
                session, context=context, now=now, lock=True)
            connection = session.execute(select(ApplicationConnectionModel).where(
                ApplicationConnectionModel.public_id == connection_id,
                ApplicationConnectionModel.application_id == context.application_db_id,
                ApplicationConnectionModel.user_id == context.user_id,
                ApplicationConnectionModel.device_id == context.device_db_id,
                ApplicationConnectionModel.status == "active",
            ).with_for_update()).scalar_one_or_none()
            if connection is None:
                raise ConnectionNotFound("active connection not found")
            lease = session.execute(select(ApplicationConnectionLeaseModel).where(
                ApplicationConnectionLeaseModel.connection_id == connection.id,
                ApplicationConnectionLeaseModel.status == "active",
            ).with_for_update()).scalar_one_or_none()
            if lease is None or (_aware(lease.not_after) or now) <= now:
                raise ConnectionFailed("connection lease expired")
            connection.not_after = not_after
            connection.renewed_at = now
            connection.updated_at = now
            lease.not_after = not_after
            lease.renewed_at = now
            session.commit()
            return self._lease_context(connection, lease, decrypt=True)

    def update_connection_observation(self, *, connection_id: str,
                                      observed_status: str, now: datetime,
                                      error: str | None = None) -> None:
        with self._sf() as session:
            session.execute(update(ApplicationConnectionModel).where(
                ApplicationConnectionModel.public_id == connection_id
            ).values(
                observed_status=observed_status[:24], observed_at=now,
                updated_at=now, last_error=(error or "")[:1000] or None,
            ))
            session.commit()

    def due_connection_leases(self, *, now: datetime) -> list[ConnectionLeaseContext]:
        """Find expired/revoked leases and detect every lost SQL authority.

        This periodic reconciliation is intentionally independent of the many
        admin/user mutation paths: a crash after any revocation still converges
        local and node enforcement on the next short tick.
        """
        with self._sf() as session:
            rows = session.execute(select(
                ApplicationConnectionModel, ApplicationConnectionLeaseModel,
                ApplicationModel, UserModel, SubscriptionDeviceModel,
                ApplicationKeyModel, ApplicationUserGrantModel, UserUsageModel,
            ).join(
                ApplicationConnectionLeaseModel,
                ApplicationConnectionLeaseModel.connection_id == ApplicationConnectionModel.id,
            ).join(ApplicationModel,
                   ApplicationModel.id == ApplicationConnectionModel.application_id)
             .join(UserModel, UserModel.id == ApplicationConnectionModel.user_id)
             .join(SubscriptionDeviceModel,
                   SubscriptionDeviceModel.id == ApplicationConnectionModel.device_id)
             .join(ApplicationKeyModel,
                   ApplicationKeyModel.id == ApplicationConnectionModel.application_key_id)
             .outerjoin(ApplicationUserGrantModel,
                        (ApplicationUserGrantModel.application_id ==
                         ApplicationConnectionModel.application_id)
                        & (ApplicationUserGrantModel.user_id ==
                           ApplicationConnectionModel.user_id))
             .outerjoin(UserUsageModel,
                        UserUsageModel.user_id == ApplicationConnectionModel.user_id)
             .where(ApplicationConnectionLeaseModel.removed_at.is_(None))
             .order_by(ApplicationConnectionLeaseModel.not_after)).all()
            due: list[ConnectionLeaseContext] = []
            changed = False
            for connection, lease, app, user, device, key, grant, usage in rows:
                expires = (_aware(lease.not_after) or now) <= now
                used = ((usage.uplink_bytes + usage.downlink_bytes) if usage else 0)
                active_family = session.scalar(select(func.count(
                    RefreshTokenModel.token_hash)).where(
                        RefreshTokenModel.token_family_id == connection.token_family_id,
                        RefreshTokenModel.application_id == connection.application_id,
                        RefreshTokenModel.user_id == connection.user_id,
                        RefreshTokenModel.device_id == connection.device_id,
                        RefreshTokenModel.revoked.is_(False),
                        RefreshTokenModel.expires_at > now,
                    ))
                authority_lost = (
                    app.status != _ACTIVE or user.status != _ACTIVE
                    or user.access_mode != _APPLICATION_MODE
                    or device.device_status != _ACTIVE
                    or device.application_id != app.id or device.user_id != user.id
                    or not device_within_limit(
                        session, user_id=user.id, device_id=device.id,
                        device_limit=user.device_limit)
                    or key.status != _ACTIVE or key.application_id != app.id
                    or (_aware(key.not_before) is not None
                        and _aware(key.not_before) > now)
                    or (_aware(key.not_after) is not None
                        and _aware(key.not_after) <= now)
                    or grant is None or grant.status != _ACTIVE
                    or (_aware(user.expire_at) is not None
                        and _aware(user.expire_at) <= now)
                    or (user.data_limit_bytes is not None
                        and used >= user.data_limit_bytes)
                    or not active_family
                )
                requested = lease.status == "revoke_pending"
                if not (expires or authority_lost or requested):
                    continue
                if lease.status != "revoke_pending":
                    lease.status = "revoke_pending"
                    lease.revoke_requested_at = now
                    lease.revoke_reason = (
                        "expired" if expires else "authority_revoked")
                    connection.status = "revoke_pending"
                    connection.active_key = None
                    connection.stop_reason = lease.revoke_reason
                    connection.stopped_at = connection.stopped_at or now
                    connection.updated_at = now
                    changed = True
                due.append(self._lease_context(connection, lease, decrypt=True))
            if changed:
                session.commit()
            return due

    def mark_connection_removed(self, *, connection_id: str, now: datetime,
                                expired: bool, error: str | None = None) -> None:
        with self._sf() as session:
            connection = session.execute(select(ApplicationConnectionModel).where(
                ApplicationConnectionModel.public_id == connection_id
            ).with_for_update()).scalar_one_or_none()
            if connection is None:
                return
            lease = session.execute(select(ApplicationConnectionLeaseModel).where(
                ApplicationConnectionLeaseModel.connection_id == connection.id
            ).with_for_update()).scalar_one_or_none()
            terminal = "expired" if expired else "stopped"
            connection.status = terminal if error is None else "revoke_pending"
            connection.active_key = None
            connection.observed_status = "offline" if error is None else "unknown"
            connection.observed_at = now
            connection.updated_at = now
            connection.stopped_at = connection.stopped_at or now
            connection.last_error = (error or "")[:1000] or None
            if lease is not None:
                if error is None:
                    lease.status = terminal
                    lease.revoked_at = now
                    lease.removed_at = now
                    lease.last_error = None
                else:
                    lease.status = "revoke_pending"
                    lease.last_error = error[:1000]
            session.commit()

    def lease_account_owners(self) -> dict[tuple[str, str], int]:
        """Retain historical mappings so delayed disconnect counters still fold."""
        with self._sf() as session:
            rows = session.execute(select(
                ApplicationConnectionLeaseModel.core_id,
                ApplicationConnectionLeaseModel.account_id,
                ApplicationConnectionLeaseModel.user_id,
            )).all()
            return {(core_id, account_id): int(user_id)
                    for core_id, account_id, user_id in rows}

    def connection_node_address(self, node_id: int) -> str | None:
        with self._sf() as session:
            row = session.get(NodeModel, node_id)
            if row is None or row.status != "connected":
                return None
            return str(row.address or "").strip() or None

    def eligible_connection_node(self, core_id: str) -> int | None:
        """Choose a paired serving node from its last signed inventory."""
        with self._sf() as session:
            rows = session.execute(select(NodeModel).where(
                NodeModel.status == "connected",
                NodeModel.agent_type == "zagros_native",
                NodeModel.agent_identity.isnot(None),
                NodeModel.agent_credentials_enc.isnot(None),
            ).order_by(NodeModel.id)).scalars().all()
            for row in rows:
                cores = (row.settings_json or {}).get("cores") or {}
                if not ((cores.get("features") or {}).get("connection_leases")):
                    continue
                installed = dict(cores.get("installed") or {})
                core = installed.get(core_id)
                state = str((core or {}).get("state") or "").lower()
                if core is not None and state in {"running", "started", "healthy"}:
                    return int(row.id)
        return None

    def active_lease_accounts(self, *, core_id: str,
                              node_id: int | None = None,
                              now: datetime | None = None) -> list[ConnectionLeaseContext]:
        now = now or _utcnow()
        with self._sf() as session:
            statement = select(
                ApplicationConnectionModel, ApplicationConnectionLeaseModel
            ).join(
                ApplicationConnectionLeaseModel,
                ApplicationConnectionLeaseModel.connection_id == ApplicationConnectionModel.id,
            ).where(
                ApplicationConnectionLeaseModel.core_id == core_id,
                ApplicationConnectionLeaseModel.node_id.is_(node_id),
                ApplicationConnectionLeaseModel.status.in_(("active", "pending")),
                ApplicationConnectionLeaseModel.not_after > now,
                ApplicationConnectionLeaseModel.removed_at.is_(None),
            )
            rows = session.execute(statement).all()
            return [self._lease_context(c, l, decrypt=True) for c, l in rows]

    def usage_summary(self, *, context: UserAuthContext, now: datetime) -> dict:
        with self._sf() as session:
            _app, user, _device, _key, _grant, used = self._assert_resource_authority(
                session, context=context, now=now)
            usage = session.get(UserUsageModel, user.id)
            uplink = int(usage.uplink_bytes) if usage else 0
            downlink = int(usage.downlink_bytes) if usage else 0
            active = int(session.scalar(select(func.count(
                ApplicationConnectionModel.id)).where(
                    ApplicationConnectionModel.application_id == context.application_db_id,
                    ApplicationConnectionModel.user_id == context.user_id,
                    ApplicationConnectionModel.status == "active",
                    ApplicationConnectionModel.not_after > now,
                )) or 0)
            remaining = (None if user.data_limit_bytes is None else
                         max(0, int(user.data_limit_bytes) - int(used)))
            return {
                "used_bytes": int(used), "uplink_bytes": uplink,
                "downlink_bytes": downlink,
                "data_limit_bytes": user.data_limit_bytes,
                "remaining_bytes": remaining,
                "expire_at": _aware(user.expire_at),
                "active_connections": active, "as_of": now,
            }

    def usage_records(self, *, context: UserAuthContext, start: datetime,
                      end: datetime, now: datetime) -> list[tuple]:
        with self._sf() as session:
            self._assert_resource_authority(session, context=context, now=now)
            return list(session.execute(select(
                UsageRecordModel.recorded_at,
                UsageRecordModel.uplink_bytes,
                UsageRecordModel.downlink_bytes,
            ).where(
                UsageRecordModel.user_id == context.user_id,
                UsageRecordModel.recorded_at >= start,
                UsageRecordModel.recorded_at < end,
            ).order_by(UsageRecordModel.recorded_at)).all())
