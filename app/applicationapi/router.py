"""HTTP adapter for the signed Application authentication API."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.applicationapi.auth_models import (
    ApplicationAuthTokens,
    EnrollBody,
    EnrollResult,
    LoginBody,
    LogoutBody,
    RefreshBody,
)
from app.applicationapi.config_crypto import ApplicationConfigEnvelope
from app.applicationapi.connection_models import (
    ConnectionStartBody,
    ConnectionStatusList,
    ConnectionView,
    UsageHistoryPage,
    UsageSummary,
)
from app.applicationapi.errors import ApplicationApiError, ApplicationRateLimited
from app.applicationapi.resource_models import (
    ApplicationConfigList,
    ApplicationDeviceList,
    ApplicationProfile,
    DeviceRevokeBody,
    DeviceRevokeResult,
)
from app.applicationapi.security import SignedRequest

router = APIRouter(prefix="/api/application/v1", tags=["Application API"])


async def get_runtime(request: Request):
    # Import lazily to avoid a second composition root.
    from app.platform.routers import get_runtime as platform_runtime

    return await platform_runtime(request)


def _error(exc: ApplicationApiError) -> HTTPException:
    headers = ({"Retry-After": "300"}
               if isinstance(exc, ApplicationRateLimited) else None)
    return HTTPException(
        status_code=exc.status_code,
        detail={"error": exc.error_code, "message": str(exc)},
        headers=headers,
    )


def _require_https(request: Request) -> None:
    if request.url.scheme == "https":
        return
    host = request.client.host if request.client else ""
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        if host == "localhost":
            return
    from app.applicationapi.errors import SecureTransportRequired

    raise _error(SecureTransportRequired("HTTPS is required"))


async def _signed_request(request: Request) -> SignedRequest:
    _require_https(request)
    headers = request.headers
    try:
        timestamp = int(headers.get("x-zagros-timestamp", ""))
        application_id = headers["x-zagros-application-id"].strip()
        key_id = headers["x-zagros-application-key-id"].strip()
        raw_device_id = headers.get("x-zagros-device-id", "-").strip()
        nonce = headers["x-zagros-nonce"].strip()
        signature = headers["x-zagros-signature"].strip()
        if not application_id or not key_id or not nonce or not signature:
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        from app.applicationapi.errors import ApplicationAuthFailed

        raise _error(ApplicationAuthFailed("signed request is invalid")) from exc
    raw_path = request.scope.get("raw_path") or request.url.path.encode("ascii")
    try:
        path = raw_path.decode("ascii")
        raw_query = (request.scope.get("query_string") or b"").decode("ascii")
    except UnicodeDecodeError as exc:
        from app.applicationapi.errors import ApplicationAuthFailed

        raise _error(ApplicationAuthFailed("signed request is invalid")) from exc
    signed = SignedRequest(
        method=request.method, path=path, raw_query=raw_query,
        body=await request.body(), application_id=application_id,
        application_key_id=key_id,
        device_id=(None if raw_device_id in {"", "-"} else raw_device_id),
        timestamp=timestamp, nonce=nonce, signature=signature,
    )
    try:
        signed.canonical()  # validates nonce/field grammar before service use
    except ValueError as exc:
        from app.applicationapi.errors import ApplicationAuthFailed

        raise _error(ApplicationAuthFailed("signed request is invalid")) from exc
    return signed


def _source_ip(request: Request) -> str:
    # Starlette/Uvicorn may already replace request.client using its explicit
    # trusted-proxy configuration. Never trust a raw X-Forwarded-For header here.
    return request.client.host if request.client else "unknown"


def _access_token(request: Request) -> str:
    value = request.headers.get("authorization", "")
    if (not value.startswith("Bearer ") or len(value) > 4096
            or not value[7:] or " " in value[7:]):
        from app.applicationapi.errors import ApplicationAuthFailed

        raise ApplicationAuthFailed("access token is invalid")
    return value[7:]


@router.post("/devices/enroll", response_model=EnrollResult)
async def enroll_device(body: EnrollBody, request: Request,
                        runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_auth.enroll(
            signed=signed, username=body.username,
            password=body.password.get_secret_value(),
            activation_ticket=(body.activation_ticket.get_secret_value()
                               if body.activation_ticket is not None else None),
            app_kid=body.app_kid,
            app_signature=body.app_signature,
            device_public_key_text=body.device_public_key,
            device_name=body.device_name, platform=body.platform,
            app_version=body.app_version, source_ip=_source_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.post("/auth/login", response_model=ApplicationAuthTokens)
async def login(body: LoginBody, request: Request,
                runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_auth.login(
            signed=signed, username=body.username,
            password=body.password.get_secret_value(),
            source_ip=_source_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.post("/auth/refresh", response_model=ApplicationAuthTokens)
async def refresh(body: RefreshBody, request: Request,
                  runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_auth.refresh(
            signed=signed,
            refresh_token=body.refresh_token.get_secret_value(),
            user_agent=request.headers.get("user-agent"),
        )
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.post("/auth/logout")
async def logout(body: LogoutBody, request: Request,
                 runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        await runtime.application_auth.logout(
            signed=signed,
            refresh_token=body.refresh_token.get_secret_value(),
        )
        return {"ok": True}
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.get("/user/profile", response_model=ApplicationProfile)
async def user_profile(request: Request, runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_resources.profile(
            signed=signed, access_token=_access_token(request))
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.get("/devices", response_model=ApplicationDeviceList)
async def list_devices(request: Request, runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_resources.devices(
            signed=signed, access_token=_access_token(request))
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.post(
    "/devices/{device_id}/revoke", response_model=DeviceRevokeResult)
async def revoke_device(device_id: str, body: DeviceRevokeBody,
                        request: Request, runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_resources.revoke_device(
            signed=signed, access_token=_access_token(request),
            target_device_id=device_id,
            password=body.password.get_secret_value(),
            source_ip=_source_ip(request))
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.get("/configs", response_model=ApplicationConfigList)
async def list_configs(request: Request, runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_resources.list_configs(
            signed=signed, access_token=_access_token(request))
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.get(
    "/configs/{config_id}", response_model=ApplicationConfigEnvelope)
async def deliver_config(config_id: str, request: Request,
                         runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        settings = await runtime.portal_settings.get_portal_settings()
        delivery_context = runtime.portal.delivery_context(
            settings, request.url.hostname)
        return await runtime.application_resources.deliver_config(
            signed=signed, access_token=_access_token(request),
            config_id=config_id, delivery_context=delivery_context)
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.post("/connections/start", response_model=ConnectionView)
async def start_connection(body: ConnectionStartBody, request: Request,
                           runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_connections.start(
            signed=signed, access_token=_access_token(request),
            config_id=body.config_id)
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.post("/connections/{connection_id}/stop", response_model=ConnectionView)
async def stop_connection(connection_id: str, request: Request,
                          runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_connections.stop(
            signed=signed, access_token=_access_token(request),
            connection_id=connection_id)
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.get("/connections/status", response_model=ConnectionStatusList)
async def connection_status(request: Request,
                            connection_id: str | None = Query(default=None),
                            renew: bool = Query(default=False),
                            runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_connections.statuses(
            signed=signed, access_token=_access_token(request),
            connection_id=connection_id, renew=renew)
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.get("/usage/summary", response_model=UsageSummary)
async def usage_summary(request: Request, runtime=Depends(get_runtime)):
    try:
        signed = await _signed_request(request)
        return await runtime.application_connections.usage_summary(
            signed=signed, access_token=_access_token(request))
    except ApplicationApiError as exc:
        raise _error(exc) from exc


@router.get("/usage/history", response_model=UsageHistoryPage)
async def usage_history(
    request: Request,
    from_time: datetime | None = Query(default=None, alias="from"),
    to_time: datetime | None = Query(default=None, alias="to"),
    granularity: Literal["hour", "day"] = Query(default="day"),
    limit: int = Query(default=30, ge=1, le=100),
    cursor: str | None = Query(default=None, min_length=4, max_length=256),
    runtime=Depends(get_runtime),
):
    now = datetime.now(timezone.utc)
    end = to_time or now
    start = from_time or (end - timedelta(
        days=7 if granularity == "hour" else 30))
    try:
        signed = await _signed_request(request)
        return await runtime.application_connections.usage_history(
            signed=signed, access_token=_access_token(request),
            start=start, end=end, granularity=granularity,
            limit=limit, cursor=cursor)
    except ApplicationApiError as exc:
        raise _error(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={
            "error": "invalid_usage_range", "message": str(exc)}) from exc
