"""ClientApiService — application-facing use-cases (Clean Architecture).

The routers stay thin: every rule (uniform-cost auth, refresh rotation,
one-time connect tokens, sealed delivery, safe profile views) lives here
and is covered by executable tests.
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from app.clientapi.errors import (
    AuthFailedError,
    ClientApiError,
    ConnectTokenError,
    RateLimitedError,
    UserSuspendedError,
)
from app.clientapi.models import (
    AppCredentials,
    AuthTokens,
    ClientProfile,
    ConnectOffer,
    CorePublicView,
)
from app.clientapi.stores import (
    ClientDataProvider,
    ConnectTokenRecord,
    ConnectTokenStore,
    RefreshTokenStore,
    hash_token,
)
from app.clientapi.tokens import SignedTokenService, TokenError
from app.crypto.passwords import PasswordHasher
from app.crypto.seal import SealedEnvelope, seal
from app.crypto.x25519 import X25519_KEY_SIZE

_SUSPENDED_STATUSES = {"disabled", "expired", "limited"}


def _epoch_to_dt(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


class ClientApiService:
    def __init__(
        self,
        provider: ClientDataProvider,
        refresh_store: RefreshTokenStore,
        connect_store: ConnectTokenStore,
        tokens: SignedTokenService,
        *,
        hasher: PasswordHasher | None = None,
        refresh_ttl_seconds: int = 30 * 24 * 3600,
        connect_ttl_seconds: int = 30,
        max_auth_failures: int = 5,
        auth_window_seconds: int = 60,
        now: Callable[[], float] = time.time,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._provider = provider
        self._refresh = refresh_store
        self._connect = connect_store
        self._tokens = tokens
        self._hasher = hasher or PasswordHasher()
        self.refresh_ttl = refresh_ttl_seconds
        self.connect_ttl = connect_ttl_seconds
        self._max_fail = max_auth_failures
        self._window = auth_window_seconds
        self._now = now
        self._emit = on_event or (lambda name, data: None)
        # a real scrypt hash so unknown-usernames pay the same verification cost
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(18))
        self._fail_log: dict[str, list[float]] = {}

    # ------------------------------------------------------------------ #
    # credentials & authentication
    # ------------------------------------------------------------------ #
    async def issue_app_credentials(self, user_id: int) -> AppCredentials:
        """Generate (or rotate) the app's dedicated username/password.

        The plaintext password is returned ONCE; only its scrypt hash is
        persisted. Rotating invalidates previous app logins immediately.
        """
        user = await self._provider.get_user_record(user_id)
        if user is None:
            raise ClientApiError("user not found")
        app_username = f"u{user_id}.{secrets.token_urlsafe(6).lower()}"
        app_password = secrets.token_urlsafe(15)
        await self._provider.save_app_credentials(
            user_id, app_username, self._hasher.hash(app_password)
        )
        await self._refresh.revoke_all_for_user(user_id)
        self._emit("credentials.issued", {"user_id": user_id})
        return AppCredentials(username=app_username, password=app_password)

    def _check_rate_limit(self, key: str) -> None:
        now = self._now()
        window = [t for t in self._fail_log.get(key, []) if now - t < self._window]
        self._fail_log[key] = window
        if len(window) >= self._max_fail:
            raise RateLimitedError("too many failed attempts; try again later")

    def _record_failure(self, key: str) -> None:
        self._fail_log.setdefault(key, []).append(self._now())

    async def authenticate(self, app_username: str, password: str) -> AuthTokens:
        self._check_rate_limit(app_username)
        user = await self._provider.find_user_by_app_username(app_username)
        stored_hash = (user or {}).get("app_password_hash") or self._dummy_hash
        if not self._hasher.verify(password, stored_hash) or user is None:
            self._record_failure(app_username)
            self._emit("auth.failure", {"app_username": app_username})
            raise AuthFailedError("invalid username or password")
        if user.get("status") in _SUSPENDED_STATUSES:
            self._emit("auth.rejected", {"user_id": user["id"], "status": user.get("status")})
            raise UserSuspendedError(f"subscription is {user.get('status')}")
        self._emit("auth.success", {"user_id": user["id"]})
        return await self._issue_tokens(int(user["id"]))

    async def _issue_tokens(self, user_id: int) -> AuthTokens:
        access, access_exp = self._tokens.issue(
            user_id, ttl_seconds=self._tokens.ttl_seconds
        )
        refresh_secret = secrets.token_urlsafe(32)
        refresh_exp = self._now() + self.refresh_ttl
        await self._refresh.save(user_id, hash_token(refresh_secret), _epoch_to_dt(refresh_exp))
        return AuthTokens(
            access_token=access,
            access_expires_at=_epoch_to_dt(access_exp),
            refresh_token=refresh_secret,
            refresh_expires_at=_epoch_to_dt(refresh_exp),
        )

    async def refresh(self, refresh_token: str) -> AuthTokens:
        row = await self._refresh.get(hash_token(refresh_token))
        now = _epoch_to_dt(self._now())
        if row is None or row.revoked or row.expires_at < now:
            raise AuthFailedError("refresh token invalid")
        new = await self._issue_tokens(row.user_id)
        await self._refresh.revoke(row.token_hash, rotated_to=hash_token(new.refresh_token))
        self._emit("token.rotated", {"user_id": row.user_id})
        return new

    async def logout(self, refresh_token: str) -> None:
        await self._refresh.revoke(hash_token(refresh_token))
        self._emit("auth.logout", {})

    async def refresh_owner(self, refresh_token: str) -> int | None:
        """Resolve a refresh token for route-level HWID enforcement."""
        row = await self._refresh.get(hash_token(refresh_token))
        now = _epoch_to_dt(self._now())
        return (None if row is None or row.revoked or row.expires_at < now
                else int(row.user_id))

    async def connect_owner(self, connect_token: str) -> int | None:
        """Resolve a one-time connect token without consuming it."""
        row = await self._connect.get(hash_token(connect_token))
        now = _epoch_to_dt(self._now())
        return (None if row is None or row.consumed or row.expires_at < now
                else int(row.user_id))

    def verify_access(self, access_token: str) -> int:
        """AuthZ guard for routers; returns user_id or raises AuthFailed."""
        try:
            payload = self._tokens.verify(access_token)
        except TokenError as exc:
            raise AuthFailedError(str(exc)) from exc
        return int(payload["sub"])

    # ------------------------------------------------------------------ #
    # profile (secret-free)
    # ------------------------------------------------------------------ #
    async def get_profile(self, user_id: int) -> ClientProfile:
        user = await self._provider.get_user_record(user_id)
        if user is None:
            raise ClientApiError("user not found")
        used, limit = await self._provider.get_usage(user_id)
        cores: list[CorePublicView] = []
        for driver, account in await self._provider.get_core_accounts(user_id):
            status = "active" if account.enabled else "suspended"
            engine = ""
            display = f"{account.protocol} · {driver.metadata.name}"
            try:
                config = await driver.build_client_config(account)
                display = config.display_name or display
                engine = config.engine
            except Exception:  # noqa: BLE001 — view stays honest, not broken
                status = "unavailable"
            cores.append(CorePublicView(
                core_id=driver.metadata.id,
                protocol=account.protocol,
                engine=engine,
                display_name=display,
                status=status,
            ))
        return ClientProfile(
            user_id=user_id,
            username=str(user.get("username", "")),
            status=str(user.get("status", "active")),
            online=bool(user.get("online", False)),
            used_bytes=used,
            data_limit_bytes=limit,
            expire_at=user.get("expire_at"),
            cores=cores,
        )

    # ------------------------------------------------------------------ #
    # sealed connection delivery
    # ------------------------------------------------------------------ #
    async def request_connect(self, user_id: int, core_id: str) -> ConnectOffer:
        user = await self._provider.get_user_record(user_id)
        if user is None:
            raise ClientApiError("user not found")
        if user.get("status") in _SUSPENDED_STATUSES:
            raise UserSuspendedError(f"subscription is {user.get('status')}")
        accounts = {
            driver.metadata.id: (driver, account)
            for driver, account in await self._provider.get_core_accounts(user_id)
        }
        if core_id not in accounts:
            raise ClientApiError(f"core '{core_id}' is not available for this user")
        token = secrets.token_urlsafe(24)
        expires = self._now() + self.connect_ttl
        await self._connect.save(ConnectTokenRecord(
            user_id=user_id, core_id=core_id,
            token_hash=hash_token(token),
            expires_at=_epoch_to_dt(expires),
        ))
        self._emit("connect.issued", {"user_id": user_id, "core_id": core_id})
        return ConnectOffer(connect_token=token, expires_at=_epoch_to_dt(expires),
                            ttl_seconds=self.connect_ttl)

    async def deliver_config(self, connect_token: str,
                             client_eph_public_b64: str,
                             delivery_context=None) -> SealedEnvelope:
        """Consume the one-time token and seal the connection payload.

        The app generates an ephemeral X25519 keypair, sends the public key
        here, and opens the returned envelope entirely in memory.
        """
        token_hash = hash_token(connect_token)
        record = await self._connect.get(token_hash)
        now = _epoch_to_dt(self._now())
        if record is None or record.expires_at < now or record.consumed:
            # uniform by design — no oracle about which condition failed
            raise ConnectTokenError("connect token invalid")
        consumed = await self._connect.mark_consumed(token_hash, now)
        if not consumed:
            raise ConnectTokenError("connect token invalid")
        try:
            client_eph_public = base64.urlsafe_b64decode(
                client_eph_public_b64 + "=" * (-len(client_eph_public_b64) % 4)
            )
        except Exception as exc:  # noqa: BLE001
            raise ConnectTokenError("bad client key") from exc
        if len(client_eph_public) != X25519_KEY_SIZE:
            raise ConnectTokenError("bad client key")

        accounts = {
            driver.metadata.id: (driver, account)
            for driver, account in await self._provider.get_core_accounts(record.user_id)
        }
        if record.core_id not in accounts:
            raise ClientApiError(f"core '{record.core_id}' is not available")
        driver, account = accounts[record.core_id]
        if delivery_context is None:
            config = await driver.build_client_config(account)
        else:
            config = await driver.build_client_config(account, delivery_context)
        document = json.dumps({
            "v": 1,
            "issued_at": now.isoformat(),
            "config": {
                "core_id": config.core_id,
                "protocol": config.protocol,
                "engine": config.engine,
                "display_name": config.display_name,
                "payload": config.payload,
            },
        }, ensure_ascii=False).encode("utf-8")
        envelope = seal(document, client_eph_public)
        self._emit("config.delivered", {"user_id": record.user_id, "core_id": record.core_id})
        return envelope
