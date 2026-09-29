"""Application activation/login/refresh state machine."""
from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from app.applicationapi.auth_models import ApplicationAuthTokens, EnrollResult
from app.applicationapi.errors import (
    ActivationTicketInvalid,
    ApplicationAuthFailed,
    ApplicationForbidden,
    ApplicationRateLimited,
    DeviceLimitReached,
)
from app.applicationapi.repository import (
    ApplicationAuthRepository,
    RequestKeyContext,
    UserAuthContext,
)
from app.applicationapi.security import (
    SignedRequest,
    b64url_decode,
    derive_request_mac_key,
    verify_request_signature,
)
from app.applicationapi.tokens import (
    ApplicationAccessTokenService,
    ApplicationTokenError,
)
from app.crypto.passwords import PasswordHasher


class ApplicationAuthService:
    def __init__(self, repository: ApplicationAuthRepository,
                 tokens: ApplicationAccessTokenService, *,
                 hasher: PasswordHasher | None = None,
                 request_window_seconds: int = 300,
                 refresh_ttl_seconds: int = 30 * 24 * 3600,
                 max_auth_failures: int = 5,
                 auth_window_seconds: int = 60,
                 auth_block_seconds: int = 300,
                 now: Callable[[], float] = time.time) -> None:
        self.repository = repository
        self.tokens = tokens
        self.hasher = hasher or PasswordHasher()
        self.request_window_seconds = int(request_window_seconds)
        self.refresh_ttl_seconds = int(refresh_ttl_seconds)
        self.max_auth_failures = int(max_auth_failures)
        self.auth_window_seconds = int(auth_window_seconds)
        self.auth_block_seconds = int(auth_block_seconds)
        self._now = now
        # Unknown/mismatched usernames still pay one real scrypt verification.
        self._dummy_hash = self.hasher.hash(secrets.token_urlsafe(24))

    def _datetime(self) -> datetime:
        return datetime.fromtimestamp(self._now(), tz=timezone.utc)

    def _check_timestamp(self, signed: SignedRequest, now: datetime) -> None:
        if abs(int(now.timestamp()) - int(signed.timestamp)) > self.request_window_seconds:
            raise ApplicationAuthFailed("signed request is invalid")

    @staticmethod
    def _validate_request_context(context: RequestKeyContext) -> None:
        if context.application_status != "active" or context.key_status != "active":
            raise ApplicationForbidden("Application access denied")
        if context.device_db_id is not None and context.device_status != "active":
            raise ApplicationForbidden("Application access denied")

    @staticmethod
    def _validate_user_context(context: UserAuthContext, now: datetime) -> None:
        if (context.application_status != "active"
                or context.application_key_status != "active"
                or context.user_status != "active"
                or context.access_mode != "application"
                or context.grant_id is None
                or context.grant_status != "active"
                or (context.device_db_id is not None
                    and (context.device_status != "active"
                         or not context.device_within_limit))):
            raise ApplicationForbidden("Application access denied")
        if context.expire_at is not None and context.expire_at <= now:
            raise ApplicationForbidden("Application access denied")
        if (context.data_limit_bytes is not None
                and context.used_bytes >= context.data_limit_bytes):
            raise ApplicationForbidden("Application access denied")

    async def _authenticate_enrollment_request(
        self, signed: SignedRequest, device_public_key: bytes,
    ) -> RequestKeyContext:
        now = self._datetime()
        self._check_timestamp(signed, now)
        if signed.device_id is not None:
            raise ApplicationAuthFailed("signed request is invalid")
        context = await asyncio.to_thread(
            self.repository.enrollment_request_key,
            signed.application_id, signed.application_key_id)
        try:
            mac_key = derive_request_mac_key(
                private_key=context.private_key,
                peer_public_key=device_public_key,
                application_id=context.application_public_id,
                application_key_id=context.key_id,
                device_key_id=None,
            )
        except ValueError as exc:
            raise ApplicationAuthFailed("signed request is invalid") from exc
        if not verify_request_signature(mac_key, signed.canonical(), signed.signature):
            await asyncio.to_thread(
                self.repository.audit, "application.request.signature_failed",
                application_id=context.application_db_id,
                result="denied", reason="signature")
            raise ApplicationAuthFailed("signed request is invalid")
        try:
            self._validate_request_context(context)
        except ApplicationForbidden:
            await asyncio.to_thread(
                self.repository.audit, "application.request.denied",
                application_id=context.application_db_id,
                result="denied", reason="revoked_context")
            raise
        await asyncio.to_thread(
            self.repository.consume_nonce,
            context=context, nonce=signed.nonce,
            request_timestamp=datetime.fromtimestamp(
                signed.timestamp, tz=timezone.utc),
            expires_at=now + timedelta(seconds=self.request_window_seconds),
        )
        return context

    async def _authenticate_device_request(
        self, signed: SignedRequest,
    ) -> RequestKeyContext:
        now = self._datetime()
        self._check_timestamp(signed, now)
        if not signed.device_id:
            raise ApplicationAuthFailed("signed request is invalid")
        context = await asyncio.to_thread(
            self.repository.device_request_key,
            signed.application_id, signed.application_key_id,
            signed.device_id)
        try:
            mac_key = derive_request_mac_key(
                private_key=context.private_key,
                peer_public_key=context.device_public_key or b"",
                application_id=context.application_public_id,
                application_key_id=context.key_id,
                device_key_id=context.device_key_id,
            )
        except ValueError as exc:
            raise ApplicationAuthFailed("signed request is invalid") from exc
        if not verify_request_signature(mac_key, signed.canonical(), signed.signature):
            await asyncio.to_thread(
                self.repository.audit, "application.request.signature_failed",
                application_id=context.application_db_id,
                device_id=context.device_db_id,
                result="denied", reason="signature")
            raise ApplicationAuthFailed("signed request is invalid")
        try:
            self._validate_request_context(context)
        except ApplicationForbidden:
            await asyncio.to_thread(
                self.repository.audit, "application.request.denied",
                application_id=context.application_db_id,
                device_id=context.device_db_id,
                result="denied", reason="revoked_context")
            raise
        await asyncio.to_thread(
            self.repository.consume_nonce,
            context=context, nonce=signed.nonce,
            request_timestamp=datetime.fromtimestamp(
                signed.timestamp, tz=timezone.utc),
            expires_at=now + timedelta(seconds=self.request_window_seconds),
        )
        return context

    async def _password_auth(self, *, context: RequestKeyContext,
                             username: str, password: str,
                             source_ip: str, device_bound: bool,
                             now: datetime) -> UserAuthContext:
        try:
            await asyncio.to_thread(
                self.repository.assert_not_throttled,
                application_id=context.application_db_id,
                username=username, source_ip=source_ip, now=now)
        except ApplicationRateLimited:
            await asyncio.to_thread(
                self.repository.audit, "application.auth.throttled",
                application_id=context.application_db_id,
                device_id=context.device_db_id,
                source_ip_hash=self.repository.identifier_hash(
                    "ip", self.repository.safe_source_ip(source_ip)),
                result="denied", reason="throttled")
            raise

        if device_bound:
            user = await asyncio.to_thread(
                self.repository.device_user_context,
                context=context, username=username)
        else:
            user = await asyncio.to_thread(
                self.repository.enrollment_user_context,
                context=context, username=username)
        stored_hash = user.password_hash if user and user.password_hash else self._dummy_hash
        valid = self.hasher.verify(password, stored_hash)
        if not valid or user is None:
            await asyncio.to_thread(
                self.repository.record_auth_failure,
                application_id=context.application_db_id,
                username=username, source_ip=source_ip, now=now,
                max_failures=self.max_auth_failures,
                window_seconds=self.auth_window_seconds,
                block_seconds=self.auth_block_seconds)
            raise ApplicationAuthFailed("invalid username or password")
        try:
            self._validate_user_context(user, now)
        except ApplicationForbidden:
            await asyncio.to_thread(
                self.repository.audit, "application.auth.denied",
                application_id=context.application_db_id,
                user_id=user.user_id, device_id=context.device_db_id,
                source_ip_hash=self.repository.identifier_hash(
                    "ip", self.repository.safe_source_ip(source_ip)),
                result="denied", reason="policy")
            raise
        return user

    def _token_result(self, *, context: UserAuthContext, device_id: int,
                      device_key_id: str, refresh_issue) -> ApplicationAuthTokens:
        access, access_exp = self.tokens.issue(
            user_id=context.user_id,
            application_id=context.application_db_id,
            application_public_id=context.application_public_id,
            device_id=device_id, device_key_id=device_key_id,
            application_key_id=context.application_key_db_id,
            token_family_id=refresh_issue.family_id,
        )
        return ApplicationAuthTokens(
            access_token=access,
            access_expires_at=datetime.fromtimestamp(access_exp, tz=timezone.utc),
            refresh_token=refresh_issue.secret,
            refresh_expires_at=refresh_issue.expires_at,
        )

    async def enroll(self, *, signed: SignedRequest, username: str,
                     password: str, activation_ticket: str | None,
                     app_signature: str | None, app_kid: str | None,
                     device_public_key_text: str,
                     device_name: str | None, platform: str | None,
                     app_version: str | None, source_ip: str,
                     user_agent: str | None) -> EnrollResult:
        now = self._datetime()
        try:
            device_public_key = b64url_decode(
                device_public_key_text, expected_length=32)
        except ValueError as exc:
            raise ApplicationAuthFailed("signed request is invalid") from exc
        request_context = await self._authenticate_enrollment_request(
            signed, device_public_key)
        user = await self._password_auth(
            context=request_context, username=username, password=password,
            source_ip=source_ip, device_bound=False, now=now)
        if activation_ticket:
            try:
                ticket = await asyncio.to_thread(
                    self.repository.verify_ticket, activation_ticket,
                    context=user, device_public_key=device_public_key, now=now)
                device = await asyncio.to_thread(
                    self.repository.consume_ticket_and_enroll,
                    context=user, ticket=ticket,
                    device_public_key=device_public_key,
                    device_name=device_name, platform=platform,
                    app_version=app_version, source_ip=source_ip,
                    user_agent=user_agent, now=now)
            except ActivationTicketInvalid:
                await asyncio.to_thread(
                    self.repository.record_auth_failure,
                    application_id=user.application_db_id,
                    username=username, source_ip=source_ip, now=now,
                    max_failures=self.max_auth_failures,
                    window_seconds=self.auth_window_seconds,
                    block_seconds=self.auth_block_seconds)
                await asyncio.to_thread(
                    self.repository.audit, "application.activation.denied",
                    application_id=user.application_db_id, user_id=user.user_id,
                    result="denied", reason="invalid_ticket")
                raise
            except DeviceLimitReached:
                await asyncio.to_thread(
                    self.repository.audit, "application.device.enrollment_denied",
                    application_id=user.application_db_id, user_id=user.user_id,
                    result="denied", reason="device_limit")
                raise
        else:
            # App-build attestation path: the private half of the application
            # signing key exists only inside an official build. This replaces
            # user-facing activation codes entirely; rotating or revoking the
            # signing key in the panel retires every older build at once.
            if not app_signature or not app_kid:
                await asyncio.to_thread(
                    self.repository.audit, "application.device.enrollment_denied",
                    application_id=user.application_db_id, user_id=user.user_id,
                    result="denied", reason="app_attestation_missing")
                raise ApplicationAuthFailed("app attestation is required")
            message = self.repository.app_attestation_message(
                application_public_id=request_context.application_public_id,
                app_kid=app_kid, username=username,
                device_public_key=device_public_key)
            try:
                await asyncio.to_thread(
                    self.repository.verify_app_attestation,
                    application_public_id=request_context.application_public_id,
                    app_kid=app_kid, message=message,
                    signature_text=app_signature)
            except ApplicationAuthFailed:
                await asyncio.to_thread(
                    self.repository.audit, "application.device.enrollment_denied",
                    application_id=user.application_db_id, user_id=user.user_id,
                    result="denied", reason="app_attestation_invalid")
                raise
            try:
                device = await asyncio.to_thread(
                    self.repository.enroll_attested_device,
                    context=user, device_public_key=device_public_key,
                    device_name=device_name, platform=platform,
                    app_version=app_version, source_ip=source_ip,
                    user_agent=user_agent, now=now)
            except DeviceLimitReached:
                await asyncio.to_thread(
                    self.repository.audit, "application.device.enrollment_denied",
                    application_id=user.application_db_id, user_id=user.user_id,
                    result="denied", reason="device_limit")
                raise
        await asyncio.to_thread(
            self.repository.clear_auth_failures,
            application_id=user.application_db_id,
            username=username, source_ip=source_ip)
        refresh = self.repository.new_refresh(
            ttl_seconds=self.refresh_ttl_seconds, now=now)
        await asyncio.to_thread(
            self.repository.save_initial_refresh,
            context=user, device_id=device.id, issue=refresh,
            now=now, user_agent=user_agent)
        tokens = self._token_result(
            context=user, device_id=device.id,
            device_key_id=device.device_key_id or "", refresh_issue=refresh)
        return EnrollResult(
            device_id=device.device_key_id or "",
            device_key_fingerprint=device.device_key_fingerprint or "",
            tokens=tokens,
        )

    async def login(self, *, signed: SignedRequest, username: str,
                    password: str, source_ip: str,
                    user_agent: str | None) -> ApplicationAuthTokens:
        now = self._datetime()
        request_context = await self._authenticate_device_request(signed)
        user = await self._password_auth(
            context=request_context, username=username, password=password,
            source_ip=source_ip, device_bound=True, now=now)
        await asyncio.to_thread(
            self.repository.clear_auth_failures,
            application_id=user.application_db_id,
            username=username, source_ip=source_ip)
        refresh = self.repository.new_refresh(
            ttl_seconds=self.refresh_ttl_seconds, now=now)
        await asyncio.to_thread(
            self.repository.save_initial_refresh,
            context=user, device_id=request_context.device_db_id,
            issue=refresh, now=now, user_agent=user_agent)
        await asyncio.to_thread(
            self.repository.mark_login_success,
            device_id=request_context.device_db_id, now=now,
            source_ip=source_ip, user_agent=user_agent)
        return self._token_result(
            context=user, device_id=request_context.device_db_id,
            device_key_id=request_context.device_key_id or "",
            refresh_issue=refresh)

    async def refresh(self, *, signed: SignedRequest, refresh_token: str,
                      user_agent: str | None) -> ApplicationAuthTokens:
        now = self._datetime()
        request_context = await self._authenticate_device_request(signed)
        try:
            current = await asyncio.to_thread(
                self.repository.device_user_context, context=request_context)
            if current is None:
                raise ApplicationAuthFailed("refresh token is invalid")
            self._validate_user_context(current, now)
            context, refresh = await asyncio.to_thread(
                self.repository.rotate_refresh,
                refresh_secret=refresh_token,
                request_context=request_context,
                ttl_seconds=self.refresh_ttl_seconds,
                now=now, user_agent=user_agent)
            self._validate_user_context(context, now)
        except ApplicationForbidden:
            await asyncio.to_thread(
                self.repository.audit, "application.refresh.denied",
                application_id=request_context.application_db_id,
                device_id=request_context.device_db_id,
                result="denied", reason="policy")
            raise
        except ApplicationAuthFailed:
            await asyncio.to_thread(
                self.repository.audit, "application.refresh.denied",
                application_id=request_context.application_db_id,
                device_id=request_context.device_db_id,
                result="denied", reason="invalid_refresh")
            raise
        return self._token_result(
            context=context, device_id=request_context.device_db_id,
            device_key_id=request_context.device_key_id or "",
            refresh_issue=refresh)

    async def logout(self, *, signed: SignedRequest,
                     refresh_token: str) -> None:
        now = self._datetime()
        request_context = await self._authenticate_device_request(signed)
        await asyncio.to_thread(
            self.repository.revoke_refresh_family,
            refresh_secret=refresh_token,
            request_context=request_context, now=now)

    async def authorize_protected(self, *, signed: SignedRequest,
                                  access_token: str) -> UserAuthContext:
        """Bind a bearer token to the same freshly signed device request."""
        request_context = await self._authenticate_device_request(signed)
        access_context = await self.authorize_access(access_token)
        if (request_context.application_db_id != access_context.application_db_id
                or request_context.key_db_id != (
                    access_context.application_key_db_id)
                or request_context.device_db_id != access_context.device_db_id
                or request_context.device_key_id != access_context.device_key_id
                or request_context.user_id != access_context.user_id):
            await asyncio.to_thread(
                self.repository.audit, "application.access.denied",
                application_id=request_context.application_db_id,
                device_id=request_context.device_db_id,
                result="denied", reason="request_token_binding")
            raise ApplicationAuthFailed("access token is invalid")
        return access_context

    async def reauthenticate(self, *, context: UserAuthContext,
                             password: str, source_ip: str) -> None:
        """Password re-authentication for destructive device operations."""
        now = self._datetime()
        username = context.app_username or ""
        try:
            await asyncio.to_thread(
                self.repository.assert_not_throttled,
                application_id=context.application_db_id,
                username=username, source_ip=source_ip, now=now)
        except ApplicationRateLimited:
            await asyncio.to_thread(
                self.repository.audit, "application.auth.throttled",
                application_id=context.application_db_id,
                user_id=context.user_id, device_id=context.device_db_id,
                result="denied", reason="device_reauth")
            raise
        stored_hash = context.password_hash or self._dummy_hash
        if not self.hasher.verify(password, stored_hash):
            await asyncio.to_thread(
                self.repository.record_auth_failure,
                application_id=context.application_db_id,
                username=username, source_ip=source_ip, now=now,
                max_failures=self.max_auth_failures,
                window_seconds=self.auth_window_seconds,
                block_seconds=self.auth_block_seconds)
            raise ApplicationAuthFailed("invalid username or password")
        await asyncio.to_thread(
            self.repository.clear_auth_failures,
            application_id=context.application_db_id,
            username=username, source_ip=source_ip)

    async def authorize_access(self, token: str) -> UserAuthContext:
        """Verify token binding and re-read every revocable SQL authority."""
        try:
            payload = self.tokens.verify(token)
            context = await asyncio.to_thread(
                self.repository.access_user_context,
                application_id=int(payload["app"]),
                application_public_id=str(payload["aid"]),
                user_id=int(payload["sub"]),
                device_id=int(payload["dev"]),
                device_key_id=str(payload["dkid"]),
                application_key_id=int(payload["akid"]),
                token_family_id=str(payload["fam"]),
                now=self._datetime(),
            )
        except (ApplicationTokenError, KeyError, TypeError, ValueError) as exc:
            raise ApplicationAuthFailed("access token is invalid") from exc
        if context is None:
            raise ApplicationAuthFailed("access token is invalid")
        try:
            self._validate_user_context(context, self._datetime())
        except ApplicationForbidden:
            await asyncio.to_thread(
                self.repository.audit, "application.access.denied",
                application_id=context.application_db_id,
                user_id=context.user_id, device_id=context.device_db_id,
                result="denied", reason="policy")
            raise
        return context
