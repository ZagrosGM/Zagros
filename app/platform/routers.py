"""Zagros HTTP routers — thin adapters over the tested service layer.

Mount under the FastAPI app (the lazy ``app`` builder includes this router
when the platform runtime is available):

    Client API:  /client/v1/...        (official Zagros app)
    Portal:      /zagros/sub/{token}   (driver-agnostic subscription page)
    Admin API:   /api/zagros/...       (dashboard, studio, settings, migration)
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
import base64 as _base64

from app.clientapi.errors import ClientApiError
from app.clientapi.models import AppCredentials, AuthTokens, ConnectOffer
from app.clientapi.tokens import TokenError
from app.portal.models import PortalSettings
from app.portal.render import render_page_html
from app.studio.jsonpatch import PatchOperation
from app.studio.service import InboundSpec, StudioError

zagros_router = APIRouter(tags=["Zagros"])


# ---------------------------------------------------------------------- #
# auth plumbing: admin endpoints ride the legacy OAuth2/JWT stack and are
# restricted to sudo admins. If the legacy stack is not importable (bare
# test shims), the dependency FAILS CLOSED — never open-by-default.
# ---------------------------------------------------------------------- #
try:
    from app.models.admin import Admin as _LegacyAdmin

    _SUDO_DEPS = [Depends(_LegacyAdmin.check_sudo_admin)]
except Exception:  # pragma: no cover - import-time safety net
    async def _no_admin_stack() -> None:
        raise HTTPException(503, "admin authentication stack unavailable")

    _SUDO_DEPS = [Depends(_no_admin_stack)]

zagros_admin_router = APIRouter(
    prefix="/api/zagros", tags=["Zagros Admin"], dependencies=_SUDO_DEPS)


# ---------------------------------------------------------------------- #
# plumbing
# ---------------------------------------------------------------------- #

def get_runtime(request: Request):
    runtime = getattr(request.app.state, "zagros", None)
    if runtime is None:
        raise HTTPException(503, "Zagros platform runtime is not initialized")
    return runtime


def _client_error(exc: Exception) -> HTTPException:
    code = getattr(exc, "status_code", 400)
    return HTTPException(code, {"error": getattr(exc, "error_code", "error"),
                                "message": str(exc)})


def _bearer(authorization: str | None, runtime) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    try:
        return runtime.client_api.verify_access(authorization[7:])
    except ClientApiError as exc:
        raise _client_error(exc) from exc


# ---------------------------------------------------------------------- #
# Client API (/client/v1)
# ---------------------------------------------------------------------- #

class LoginBody(BaseModel):
    username: str
    password: str


class RefreshBody(BaseModel):
    refresh_token: str


class ConfigBody(BaseModel):
    connect_token: str
    client_public_key: str  # base64url X25519 ephemeral public key


@zagros_router.post("/client/v1/auth/login", response_model=AuthTokens)
async def client_login(body: LoginBody, runtime=Depends(get_runtime)):
    try:
        return await runtime.client_api.authenticate(body.username, body.password)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


@zagros_router.post("/client/v1/auth/refresh", response_model=AuthTokens)
async def client_refresh(body: RefreshBody, runtime=Depends(get_runtime)):
    try:
        return await runtime.client_api.refresh(body.refresh_token)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


@zagros_router.post("/client/v1/auth/logout")
async def client_logout(body: RefreshBody, runtime=Depends(get_runtime)):
    await runtime.client_api.logout(body.refresh_token)
    return {"ok": True}


@zagros_router.get("/client/v1/profile")
async def client_profile(authorization: str | None = Header(default=None),
                         runtime=Depends(get_runtime)):
    user_id = _bearer(authorization, runtime)
    return await runtime.client_api.get_profile(user_id)


@zagros_router.post("/client/v1/connect/{core_id}", response_model=ConnectOffer)
async def client_connect(core_id: str,
                         authorization: str | None = Header(default=None),
                         runtime=Depends(get_runtime)):
    user_id = _bearer(authorization, runtime)
    try:
        return await runtime.client_api.request_connect(user_id, core_id)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


@zagros_router.post("/client/v1/config")
async def client_config(body: ConfigBody, runtime=Depends(get_runtime)):
    try:
        envelope = await runtime.client_api.deliver_config(
            body.connect_token, body.client_public_key
        )
    except ClientApiError as exc:
        raise _client_error(exc) from exc
    return envelope


# ---------------------------------------------------------------------- #
# Subscription portal (/zagros/sub/{token})
# ---------------------------------------------------------------------- #

@zagros_router.get("/zagros/sub/{token}", response_class=HTMLResponse)
async def subscription_portal(token: str, request: Request,
                              runtime=Depends(get_runtime),
                              accept_language: str | None = Header(default=None),
                              user_agent: str | None = Header(default=None)):
    try:
        payload = runtime.tokens.verify(token, expected_type="sub")
    except TokenError as exc:
        raise HTTPException(404, "subscription not found") from exc
    user_id = int(payload["sub"])
    # rotation invalidates older portal URLs immediately (fail-closed)
    current_jti = await runtime.kv.get_value(f"portal.sub_jti.{user_id}")
    if current_jti is None or payload.get("jti") != current_jti:
        raise HTTPException(404, "subscription not found")

    # Content negotiation: subscription CLIENTS (v2rayNG, Streisand, sing-box,
    # Nekoray...) fetch the link list (base64 body, Marzban convention);
    # BROWSERS get the rich multi-core portal page.
    accept = request.headers.get("accept", "")
    ua = (user_agent or "").lower()
    # explicit ?format= always wins (browser may fetch clash/sing-box configs)
    explicit_fmt = (request.query_params.get("format") or "").lower().strip()
    is_browser = (not explicit_fmt) and "text/html" in accept and any(
        k in ua for k in ("mozilla", "chrome", "safari", "firefox", "edge"))
    lang = None
    if accept_language:
        lang = accept_language.split(",")[0].strip()[:5]

    if is_browser:
        page = await runtime.portal.build_page(user_id, lang=lang)
        if page is None:
            raise HTTPException(404, "subscription not found")
        return HTMLResponse(render_page_html(page))

    bundle = await runtime.portal.build_links(user_id)
    if bundle is None:
        raise HTTPException(404, "subscription not found")
    links, notes = bundle

    # Client-specific formats (spec §8): ONE merged multi-core link set,
    # rendered for whatever is fetching. ``?format=`` overrides UA sniffing.
    from app.platform.sub_formats import dedupe_links, to_clash_meta, to_sing_box

    fmt = explicit_fmt or _format_for_ua(ua)
    if fmt in ("clash", "clash-meta", "meta", "stash", "yaml"):
        body, _fmt_notes = to_clash_meta(links, notes)
        return PlainTextResponse(
            body, media_type="text/yaml; charset=utf-8",
            headers={
                "profile-update-interval": "6",
                "content-disposition": "attachment; filename=\"zagros.yaml\"",
            },
        )
    if fmt in ("sing-box", "singbox", "json"):
        body, _fmt_notes = to_sing_box(links, notes)
        return PlainTextResponse(
            body, media_type="application/json; charset=utf-8",
            headers={
                "profile-update-interval": "6",
                "content-disposition": "attachment; filename=\"zagros.json\"",
            },
        )

    links = dedupe_links(links)
    body_lines = [f"# {n}" for n in notes] + links
    encoded = _base64.b64encode("\n".join(body_lines).encode()).decode()
    return PlainTextResponse(
        encoded,
        headers={
            "subscription-userinfo": "",
            "profile-update-interval": "6",
            "content-disposition": "attachment; filename=\"zagros-subscription\"",
        },
    )


def _format_for_ua(ua: str) -> str:
    """User-Agent → subscription format (Marzban-style sniffing, multi-core)."""
    if any(k in ua for k in ("clash", "mihomo", "flclash", "stash")):
        return "clash-meta"
    if any(k in ua for k in ("sing-box", "singbox", "sfa", "sfi", "sfm")):
        return "sing-box"
    return ""


@zagros_admin_router.post("/users/{user_id}/subscription-token")
async def issue_subscription_token(user_id: int, runtime=Depends(get_runtime)):
    """Issue (rotate) the user's portal URL token; older links die at once."""
    token, _ = runtime.tokens.issue(user_id, ttl_seconds=10 * 365 * 24 * 3600,
                                    token_type="sub")
    payload = runtime.tokens.verify(token, expected_type="sub")
    await runtime.kv.set_value(f"portal.sub_jti.{user_id}", payload["jti"])
    return {"token": token, "path": f"/zagros/sub/{token}"}


@zagros_admin_router.post("/users/by-username/{username}/subscription-token")
async def issue_subscription_token_by_username(username: str, runtime=Depends(get_runtime)):
    """Same as by-id, for the dashboard which identifies users by username."""
    import asyncio as _asyncio

    row = await _asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        raise HTTPException(404, f"user '{username}' not found")
    return await issue_subscription_token(row.id, runtime)


# ---------------------------------------------------------------------- #
# Admin: dashboard / studio / settings / migration
# ---------------------------------------------------------------------- #

@zagros_admin_router.get("/dashboard/snapshot")
async def dashboard_snapshot(runtime=Depends(get_runtime)):
    snapshot = await runtime.dashboard.snapshot()
    return snapshot


@zagros_admin_router.get("/studio/{core_id}/raw")
async def studio_raw(core_id: str, runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    return {"core_id": core_id, "json": await runtime.studio.raw_text(core_id, driver)}


@zagros_admin_router.get("/cores/{core_id}/wizard-schema")
async def core_wizard_schema(core_id: str):
    """Dynamic inbound-wizard blueprint (protocols × transports × securities
    × fields) for THIS engine — the dashboard stepper renders it verbatim."""
    from app.studio.wizard import blueprint_for

    try:
        return blueprint_for(core_id)
    except KeyError:
        raise HTTPException(404, f"no inbound-wizard blueprint for core '{core_id}'") from None


class StudioPatchBody(BaseModel):
    operations: list[PatchOperation]


@zagros_admin_router.post("/studio/{core_id}/preview")
async def studio_preview(core_id: str, body: StudioPatchBody,
                         runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    return await runtime.studio.preview(driver, body.operations)


async def _materialize_studio(runtime, core_id: str, driver) -> str | None:
    """Push the freshly-applied studio document INTO the core (sing-box,
    tuic, … implement apply_studio_document). Engines without a hook keep
    the document-only surface (alpha.6 semantic) — returned as a warning so
    the operator isn't told the core changed when it did not."""
    doc = await runtime.studio_store.get_document(core_id)
    hook = getattr(driver, "apply_studio_document", None)
    if hook is None or doc is None:
        return ("document saved; this engine applies it on next start "
                "(no live studio→core bridge for this driver)")
    await hook(doc)
    return None


@zagros_admin_router.post("/studio/{core_id}/apply")
async def studio_apply(core_id: str, body: StudioPatchBody,
                       runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    result = await runtime.studio.apply(driver, body.operations)
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    warning = await _materialize_studio(runtime, core_id, driver)
    return {**result.model_dump(), "materialized": warning is None, "notice": warning}


@zagros_admin_router.post("/studio/{core_id}/wizard/inbound")
async def studio_wizard_inbound(core_id: str, spec: InboundSpec,
                                runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    try:
        result = await runtime.studio.wizard_add_inbound(driver, spec)
    except StudioError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    warning = await _materialize_studio(runtime, core_id, driver)
    return {**result.model_dump(), "materialized": warning is None, "notice": warning}


def _driver_or_404(runtime, core_id: str):
    try:
        return runtime.core_manager.get(core_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(404, f"core '{core_id}' is not installed") from exc


@zagros_admin_router.get("/settings/portal", response_model=PortalSettings)
async def get_portal_settings(runtime=Depends(get_runtime)):
    return await runtime.portal_settings.get_portal_settings()


@zagros_admin_router.put("/settings/portal", response_model=PortalSettings)
async def put_portal_settings(settings: PortalSettings,
                              runtime=Depends(get_runtime)):
    return await runtime.portal_settings.save_portal_settings(settings)


@zagros_admin_router.post("/users/{user_id}/app-credentials",
                    response_model=AppCredentials)
async def issue_app_credentials(user_id: int, runtime=Depends(get_runtime)):
    try:
        return await runtime.client_api.issue_app_credentials(user_id)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


class MigrationBody(BaseModel):
    legacy_path: str = Field(description="Filesystem path to the Marzban sqlite DB")
    dry_run: bool = True


@zagros_admin_router.post("/migrate/legacy")
async def migrate_legacy(body: MigrationBody, runtime=Depends(get_runtime)):
    import asyncio

    from app.persistence.legacy_reader import read_legacy_sqlite
    from app.persistence.migration import LegacyImportService

    path = Path(body.legacy_path)
    if not path.is_file():
        raise HTTPException(404, f"legacy database not found: {body.legacy_path}")
    service = LegacyImportService(runtime.session_factory, runtime.users,
                                  runtime.cipher)
    snapshot = await asyncio.to_thread(read_legacy_sqlite, path)
    report = await asyncio.to_thread(service.migrate, snapshot, dry_run=body.dry_run)
    return report.as_dict()
