"""Zagros HTTP routers — thin adapters over the tested service layer.

Mount under the FastAPI app (the lazy ``app`` builder includes this router
when the platform runtime is available):

    Application: /api/application/v1  (signed app/device activation + auth)
    Legacy API:  /client/v1/...        (permanently closed with HTTP 410)
    Portal:      /zagros/sub/{token}   (driver-agnostic subscription page;
                 the path segment is customizable via portal settings —
                 /zagros/{subscription_path}/{token} — with /zagros/sub/...
                 kept as the canonical alias so existing links never die)
    Admin API:   /api/zagros/...       (dashboard, studio, settings, migration)
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastapi import (
    APIRouter, Depends, File, Header, HTTPException, Request, UploadFile,
)
from fastapi.responses import (
    FileResponse, HTMLResponse, PlainTextResponse, Response,
)
from pydantic import BaseModel, Field
import base64 as _base64

from app.applicationapi.auth_models import (
    AccessModeBody,
    AccessModeResult,
    ActivationTicketIssueBody,
    ActivationTicketResult,
    ApplicationBootstrap,
    ApplicationCreateBody,
    ApplicationDetail,
    ApplicationGrantBody,
    ApplicationGrantListItem,
    ApplicationGrantResult,
    ApplicationIconMeta,
    ApplicationListItem,
    ApplicationPublicKeys,
    UserApplicationOverview,
)
from app.applicationapi.errors import ApplicationApiError
from app.applicationapi.resource_models import (
    AuthorityRevokeResult,
    DeviceRevokeResult,
)
from app.clientapi.errors import ClientApiError
from app.clientapi.models import AppCredentials
from app.clientapi.tokens import TokenError
from app.cores.exceptions import CoreError
from app.portal.models import PortalSettings
from app.portal.render import render_page_html
from app.studio.jsonpatch import PatchOperation
from app.studio.service import (
    InboundSpec,
    StudioConflictError,
    StudioError,
    StudioNotFoundError,
)

logger = logging.getLogger(__name__)

zagros_router = APIRouter(tags=["Zagros"])


# ---------------------------------------------------------------------- #
# auth plumbing: admin endpoints ride the legacy OAuth2/JWT stack and are
# restricted to sudo admins. If the legacy stack is not importable (bare
# test shims), the dependency FAILS CLOSED — never open-by-default.
# ---------------------------------------------------------------------- #
def _resolve_sudo_deps():
    """Resolve the sudo dependency WITHOUT depending on import order.

    ``app.models.admin`` and ``app.db`` import each other, so the model is
    only importable once the DB package has been initialised — importing it
    first raises a circular ImportError. That exception used to be swallowed
    here, which silently bound EVERY admin endpoint to a 503 dependency:
    the whole admin API went dead with no log line, purely because some
    other module happened to be imported first (a test file's order is
    enough). Importing the DB package first always breaks the cycle.
    """
    try:
        import app.db  # noqa: F401  — must precede the model import
    except Exception as exc:  # noqa: BLE001 — surfaced by the caller
        logger.warning("admin auth stack: app.db failed to import (%s: %s)",
                       type(exc).__name__, exc)
    from app.models.admin import Admin

    from app import admin_permissions as _perms

    async def _admin_guard(request: Request,
                           admin: Admin = Depends(Admin.get_current)):
        """Authenticated access to /api/zagros + permission enforcement.

        f-panel-5: this used to be ``check_sudo_admin`` router-wide, which
        locked non-sudo admins out of EVERYTHING under /api/zagros (even
        copying their own users' subscription URL). Now: sudo bypasses,
        everyone else needs (section, level) from the permission matrix
        (NULL document = the historical default: all sections). Unmapped
        paths stay authenticated-only (fail-open for forward compat, every
        current route IS mapped).
        """
        if admin.is_sudo:
            return admin
        section, need = _perms.classify_request(request.url.path, request.method)
        if section is None:
            return admin
        if not _perms.allows(admin.permissions, section, need):
            raise HTTPException(403, "You're not allowed")
        return admin

    return [Depends(_admin_guard)]


try:
    _SUDO_DEPS = _resolve_sudo_deps()
except Exception as exc:  # pragma: no cover - import-time safety net
    # Failing CLOSED is the right direction; failing SILENTLY is not: the
    # reason has to be in the log, or the next incident starts blind.
    logger.warning("admin authentication stack unavailable — admin endpoints "
                   "will fail closed with 503 (%s: %s)", type(exc).__name__, exc)

    async def _no_admin_stack() -> None:
        raise HTTPException(503, "admin authentication stack unavailable")

    _SUDO_DEPS = [Depends(_no_admin_stack)]

zagros_admin_router = APIRouter(
    prefix="/api/zagros", tags=["Zagros Admin"], dependencies=_SUDO_DEPS)


# ---------------------------------------------------------------------- #
# plumbing
# ---------------------------------------------------------------------- #

async def get_runtime(request: Request):
    runtime = getattr(request.app.state, "zagros", None)
    if runtime is not None:
        return runtime

    # The runtime is built at boot, which can land before a managed
    # MySQL/MariaDB container accepts connections. Rather than staying
    # disabled until someone restarts the panel, retry once per request so
    # the platform layer heals as soon as the database is reachable.
    builder = getattr(request.app.state, "zagros_builder", None)
    if builder is not None:
        runtime, exc = builder()
        if runtime is not None:
            request.app.state.zagros = runtime
            logging.getLogger("uvicorn.error").info(
                "Zagros platform runtime recovered")
            # The startup event already ran (and did nothing, because there
            # was no runtime yet), so run its work here or the panel serves
            # requests with no cores attached.
            if not getattr(request.app.state, "zagros_booted", False):
                request.app.state.zagros_booted = True
                boot = getattr(request.app.state, "zagros_boot_sequence", None)
                if boot is not None:
                    try:
                        await boot(runtime)
                    except Exception:  # noqa: BLE001 - serve the request anyway
                        logging.getLogger("uvicorn.error").exception(
                            "Zagros boot sequence after recovery failed")
            return runtime
        raise HTTPException(
            503, f"Zagros platform runtime is not initialized: {exc}")

    raise HTTPException(503, "Zagros platform runtime is not initialized")


def _client_error(exc: Exception) -> HTTPException:
    code = getattr(exc, "status_code", 400)
    return HTTPException(code, {"error": getattr(exc, "error_code", "error"),
                                "message": str(exc)})


# ---------------------------------------------------------------------- #
# Retired legacy Client API (/client/v1)
# ---------------------------------------------------------------------- #
# SECURITY DECISION (Phase 3): this credential-only surface is closed, not
# left running beside the signed Application API. Legacy clients receive 410
# and must migrate to /api/application/v1; no auth/config route can bypass
# Application + grant + device proof + nonce/timestamp policy.
@zagros_router.api_route(
    "/client/v1", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
@zagros_router.api_route(
    "/client/v1/{legacy_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
async def legacy_client_api_gone(legacy_path: str = ""):
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=410,
        content={
            "error": "legacy_client_api_gone",
            "message": "The legacy Client API is permanently closed; use the signed Application API.",
            "replacement": "/api/application/v1/",
        },
        headers={
            "Cache-Control": "no-store",
            "Deprecation": "true",
            "Link": '</api/application/v1/>; rel="successor-version"',
        },
    )


# ---------------------------------------------------------------------- #
# Public transition readiness (cross-origin image probe, no credentials)
# ---------------------------------------------------------------------- #

@zagros_router.get("/api/zagros/network-transition/{operation_id}.svg",
                   include_in_schema=False)
async def panel_network_transition_probe(operation_id: str):
    """Return an image only after host apply and new-origin health succeeded.

    A page loaded from the old origin cannot read the new origin's authenticated
    API because of same-origin policy. Image loading is intentionally
    credential-free and still enforces browser DNS/TLS verification; non-success
    states return a non-image 503 so ``img.onerror`` keeps polling.
    """
    import re

    from app.platform.network_settings import HostNetworkRequest

    if not re.fullmatch(r"[0-9a-f]{32,128}", operation_id):
        return PlainTextResponse("not ready", status_code=503)
    result = HostNetworkRequest().status(operation_id)
    if result.get("status") != "success":
        return PlainTextResponse("not ready", status_code=503,
                                 headers={"Cache-Control": "no-store"})
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'>"
           "<rect width='1' height='1' fill='#16a34a'/></svg>")
    return Response(svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------------- #
# Subscription portal (/zagros/sub/{token})
# ---------------------------------------------------------------------- #

async def _legacy_sub_user_id(token: str, runtime=None) -> int | None:
    """Validate a LEGACY username token (pre-
    `create_subscription_token`) under the legacy rules (issued before the
    user's created_at is invalid; `sub_revoked_at` revokes). Returns the
    **platform** user id, or None when the token is not a valid legacy token.

    This is the migration bridge: the legacy /sub/ endpoint is GONE, but
    already-issued URLs (telegram bot messages, admin notes) must keep
    working — they land on the one multi-core portal now.

    The token names the user by USERNAME. The portal, however, is keyed by
    the platform ``users.id`` — a different table with its own sequence.
    Returning the legacy row id here only worked while both stores had been
    filled in lock-step; a 3x-ui/Marzban import (which writes the two stores
    independently), a deleted-and-recreated user, or a panel restored from a
    backup makes the sequences diverge — and a legacy link then served
    ANOTHER user's subscription (same number, different table) or a bare
    ``subscription not found``. Resolve by username on BOTH sides instead,
    and heal a missing platform projection on the spot (a legacy row that
    never got mirrored is still a real user with a real link)."""
    import asyncio as _asyncio

    from app.utils.jwt import get_subscription_payload

    sub = get_subscription_payload(token)
    if not sub:
        return None

    def _legacy_row():
        from app.db import crud
        from app.db.base import SessionLocal

        db = SessionLocal()
        try:
            dbuser = crud.get_user(db, sub["username"])
            if not dbuser or dbuser.created_at > sub["created_at"]:
                return None
            if dbuser.sub_revoked_at and dbuser.sub_revoked_at > sub["created_at"]:
                return None
            # the self-heal below reads these relationships AFTER the
            # session is gone — load them now (detached rows only answer
            # for what was loaded while attached)
            for proxy in dbuser.proxies:
                _ = [i.tag for i in proxy.excluded_inbounds]
            _ = getattr(dbuser.admin, "username", None)
            return dbuser
        finally:
            db.close()

    dbuser = await _asyncio.to_thread(_legacy_row)
    if dbuser is None:
        return None
    if runtime is None:
        return int(dbuser.id)  # no platform store to map into (bare legacy stack)
    row = await _asyncio.to_thread(runtime.users.get_user_by_username, dbuser.username)
    if row is not None:
        return int(row.id)
    # the legacy row exists but was never projected: converge it now (the
    # same path User Edit takes) so the link works instead of 404-ing.
    try:
        from app.platform import provisioning

        return int(await provisioning.sync_user(runtime, dbuser, None))
    except Exception as exc:  # noqa: BLE001 — honest miss, never a 500
        logger.warning("legacy subscription token for %r: platform projection "
                       "missing and self-heal failed: %s", dbuser.username, exc)
        return None


async def _resolve_sub_user_id(token: str, runtime) -> int | None:
    """Bearer subscription token → user id (None = unknown/revoked).

    Shared by the portal and the per-file download endpoint: one trust
    rule (current-jti match, legacy fallback) in exactly one place.
    """
    user_id: int | None = None
    try:
        payload = runtime.tokens.verify(token, expected_type="sub")
    except TokenError:
        payload = None
    if payload is not None:
        candidate = int(payload["sub"])
        # rotation invalidates older portal URLs immediately (fail-closed)
        current_jti = await runtime.kv.get_value(f"portal.sub_jti.{candidate}")
        if current_jti is not None and payload.get("jti") == current_jti:
            user_id = candidate
    if user_id is None:
        # legacy username token (issued pre-) — same portal, one
        # multi-core subscription surface, legacy revocation rules honored
        user_id = await _legacy_sub_user_id(token, runtime)
    return user_id


async def _verify_and_serve(token, request, runtime,
                            accept_language, user_agent):
    user_id = await _resolve_sub_user_id(token, runtime)
    if user_id is None:
        raise HTTPException(404, "subscription not found")
    return await _serve_subscription(runtime, user_id, request,
                                     accept_language, user_agent,
                                     token=token)


async def _reissue_and_serve(token, request, runtime,
                             accept_language, user_agent):
    """Subscriber-side self-service: rotate the app login credentials.

    The subscription URL is the bearer secret; its holder is the
    subscriber, so rotating from this page is self-service recovery —
    old app logins die immediately, the new pair is shown once.
    """
    user_id = await _resolve_sub_user_id(token, runtime)
    if user_id is None:
        raise HTTPException(404, "subscription not found")
    creds = await runtime.client_api.issue_app_credentials(user_id)
    return await _serve_subscription(
        runtime, user_id, request, accept_language, user_agent,
        token=token, reissued_credentials=(creds.username, creds.password))


@zagros_router.post("/sub/{token}/reissue-app",
                    response_class=HTMLResponse)
async def reissue_canonical(token: str, request: Request,
                            runtime=Depends(get_runtime),
                            accept_language: str | None = Header(default=None),
                            user_agent: str | None = Header(default=None)):
    return await _reissue_and_serve(token, request, runtime,
                                    accept_language, user_agent)


@zagros_router.post("/zagros/sub/{token}/reissue-app",
                    response_class=HTMLResponse)
async def reissue_legacy(token: str, request: Request,
                         runtime=Depends(get_runtime),
                         accept_language: str | None = Header(default=None),
                         user_agent: str | None = Header(default=None)):
    return await _reissue_and_serve(token, request, runtime,
                                    accept_language, user_agent)


@zagros_router.post("/{sub_path:path}/{token}/reissue-app",
                    response_class=HTMLResponse)
async def reissue_configured(sub_path: str, token: str, request: Request,
                             runtime=Depends(get_runtime),
                             accept_language: str | None = Header(default=None),
                             user_agent: str | None = Header(default=None)):
    settings = await runtime.portal_settings.get_portal_settings()
    if sub_path != settings.subscription_path:
        raise HTTPException(404, "subscription not found")
    return await _reissue_and_serve(token, request, runtime,
                                    accept_language, user_agent)


@zagros_router.get("/sub/{token}", response_class=HTMLResponse)
async def subscription_portal_canonical(token: str, request: Request,
                                        runtime=Depends(get_runtime),
                                        accept_language: str | None = Header(default=None),
                                        user_agent: str | None = Header(default=None)):
    """Canonical multi-core subscription URL — /sub/<token> (item
    12). One user → one link → every core."""
    return await _verify_and_serve(token, request, runtime,
                                   accept_language, user_agent)


@zagros_router.get("/zagros/sub/{token}", response_class=HTMLResponse)
async def subscription_portal(token: str, request: Request,
                              runtime=Depends(get_runtime),
                              accept_language: str | None = Header(default=None),
                              user_agent: str | None = Header(default=None)):
    """Legacy alias of the canonical /sub/<token> — already-issued links
    keep working forever (no redirect, identical payload)."""
    return await _verify_and_serve(token, request, runtime,
                                   accept_language, user_agent)


@zagros_router.get("/sub/file/{token}/{core_id}/{tag}")
async def subscription_file_download(token: str, core_id: str, tag: str,
                                     request: Request,
                                     runtime=Depends(get_runtime)):
    """Serve one FILE artifact (OpenVPN/WireGuard profile) by bearer token.

    The link-list ``zagros-file:`` markers point here; the trust rule is
    exactly the portal's (current token, rotation-aware). Unknown token /
    core / tag — or a core with no FILE artifact for the tag — all answer
    plain 404 so delivery shape is not oracle-able.
    """
    user_id = await _resolve_sub_user_id(token, runtime)
    if user_id is None:
        raise HTTPException(404, "subscription not found")
    found = await runtime.portal.describe_file(
        user_id, core_id, tag, public_host=request.url.hostname)
    if found is None:
        raise HTTPException(404, "subscription not found")
    content, filename, mime = found
    safe_name = str(filename).replace('"', "").replace("\n", "") or "config.bin"
    return PlainTextResponse(
        content, media_type=f"{mime}; charset=utf-8",
        headers={"content-disposition":
                 f'attachment; filename="{safe_name}"'},
    )


@zagros_router.get("/zagros/activate/{ticket}", response_class=HTMLResponse)
async def activation_enrollment_page(ticket: str, request: Request,
                                     runtime=Depends(get_runtime),
                                     accept_language: str | None = Header(default=None)):
    """QR enrollment page for one activation ticket (item 4).

    External-app onboarding without client changes: the reseller's QR
    encodes this URL, and any browser shows the subscription link plus
    every share-link as scannable QRs. Viewing NEVER consumes the
    ticket (only the app enroll API does) — the page is an idempotent
    delivery vehicle bounded by the ticket TTL. Expired → 410 page,
    forged/consumed/revoked/unknown → plain 404 (no oracle).
    """
    import asyncio as _asyncio

    from app.applicationapi.errors import (
        ActivationTicketExpired, ActivationTicketInvalid,
    )
    from app.platform.subscription_links import (
        subscription_url as canonical_subscription_url,
    )
    from app.portal.render import (
        activation_quarantine_note, render_activation_expired_html,
        render_activation_html,
    )
    from app.utils.jwt import create_subscription_token

    lang = (accept_language or "fa").split(",")[0].strip()[:5] or "fa"
    try:
        preview = await _asyncio.to_thread(
            runtime.application_auth_repository.get_activation_preview,
            ticket)
    except ActivationTicketExpired:
        return HTMLResponse(
            render_activation_expired_html(lang=lang), status_code=410)
    except ActivationTicketInvalid:
        raise HTTPException(404, "activation not found")
    user = await _asyncio.to_thread(
        runtime.users.get_user, preview["user_id"])
    if user is None or not getattr(user, "username", ""):
        raise HTTPException(404, "activation not found")
    settings = await runtime.portal_settings.get_portal_settings()
    sub_token = create_subscription_token(user.username)
    shaped = canonical_subscription_url(sub_token)
    if "://" in shaped:
        sub_url = shaped
    else:
        # No public identity configured: absolutize against the address
        # the reseller's browser actually reached.
        sub_url = f"{str(request.base_url).rstrip('/')}{shaped}"
    built = await runtime.portal.build_links(
        preview["user_id"], public_host=request.url.hostname,
        token=sub_token, bypass_mode_gate=True)
    links, notes = built if built is not None else ([], [])
    if _effective_access_mode(user, settings) == "application":
        # The ticket page delivers explicitly, but the bare subscription
        # link stays quarantined (app-download) — say so on the page.
        notes = [activation_quarantine_note(lang=lang), *notes]
    return HTMLResponse(render_activation_html(
        app_name=preview["application_name"], username=user.username,
        subscription_url=sub_url, links=links, notes=notes,
        expires_at=preview["expires_at"].isoformat(timespec="minutes"),
        brand=settings.brand or "Zagros", lang=lang))


@zagros_router.get("/zagros/{sub_path:path}/{token}", response_class=HTMLResponse)
async def subscription_portal_custom_path(sub_path: str, token: str,
                                          request: Request,
                                          runtime=Depends(get_runtime),
                                          accept_language: str | None = Header(default=None),
                                          user_agent: str | None = Header(default=None)):
    """Settings-driven subscription path. Fail closed: any path other than
    the currently configured one is indistinguishable from a bad token (404),
    never a redirect that would leak the configured path.

    This route must precede the generic root catch-all: ``:path`` deliberately
    accepts namespaced values such as ``sub/test``.
    """
    settings = await runtime.portal_settings.get_portal_settings()
    if sub_path != settings.subscription_path:
        raise HTTPException(404, "subscription not found")
    return await _verify_and_serve(token, request, runtime,
                                   accept_language, user_agent)


@zagros_router.get("/{sub_path:path}/{token}", response_class=HTMLResponse)
async def subscription_portal_configured_path(
    sub_path: str, token: str, request: Request,
    runtime=Depends(get_runtime),
    accept_language: str | None = Header(default=None),
    user_agent: str | None = Header(default=None),
):
    """Canonical configurable root path, e.g. /sub/test/<token>."""
    settings = await runtime.portal_settings.get_portal_settings()
    if sub_path != settings.subscription_path:
        raise HTTPException(404, "subscription not found")
    return await _verify_and_serve(token, request, runtime,
                                   accept_language, user_agent)


def _legacy_user_snapshot(username: str):
    """(used_traffic, data_limit, expire) from the legacy users row — the
    single master counters (quota is singular by design), for the
    `subscription-userinfo` response header the legacy endpoint sent."""
    from app.db import crud
    from app.db.base import SessionLocal

    db = SessionLocal()
    try:
        dbuser = crud.get_user(db, username)
        if dbuser is None:
            return None
        return (int(dbuser.used_traffic or 0),
                int(dbuser.data_limit or 0),
                int(dbuser.expire or 0))
    finally:
        db.close()


def _track_subscription_fetch(username: str, user_agent: str) -> None:
    """Keep `sub_updated_at` / `sub_last_user_agent` alive — the legacy
    endpoint bumped them on every GET; the admin Users page shows them."""
    from app.db import crud
    from app.db.base import SessionLocal

    db = SessionLocal()
    try:
        dbuser = crud.get_user(db, username)
        if dbuser is not None:
            crud.update_user_sub(db, dbuser, user_agent or "")
    finally:
        db.close()


async def _serve_subscription(runtime, user_id: int, request: Request,
                              accept_language: str | None,
                              user_agent: str | None,
                              token: str | None = None,
                              reissued_credentials: tuple[str, str] | None = None):
    # Content negotiation: subscription CLIENTS (v2rayNG, Streisand, sing-box,
    # Nekoray...) fetch the link list (base64 body, Marzban convention);
    # BROWSERS get the rich multi-core portal page.
    import asyncio as _asyncio

    accept = request.headers.get("accept", "")
    ua = (user_agent or "").lower()
    # explicit ?format= always wins (browser may fetch clash/sing-box configs)
    explicit_fmt = (request.query_params.get("format") or "").lower().strip()
    is_browser = (not explicit_fmt) and "text/html" in accept and any(
        k in ua for k in ("mozilla", "chrome", "safari", "firefox", "edge"))
    lang = None
    if accept_language:
        lang = accept_language.split(",")[0].strip()[:5]

    # legacy-continuity bookkeeping: the removed /sub/
    # endpoint tracked every fetch and sent real quota headers — the portal
    # is THE subscription surface now, so it owns the same duties.
    username: str | None = None
    userinfo_header = ""
    try:
        row = await _asyncio.to_thread(runtime.users.get_user, user_id)
        username = row.username if row is not None else None
    except Exception:  # noqa: BLE001 — bookkeeping must never kill delivery
        username = None
    if username:
        # Strict HWID enrollment happens before any portal/config metadata is
        # returned. IP and User-Agent are intentionally never fallback IDs.
        from app.platform.device_enrollment import DeviceEnrollmentError, enforce
        try:
            await enforce(
                runtime, user_id, request.headers, user_agent,
                request.client.host if request.client else None,
            )
        except DeviceEnrollmentError as exc:
            raise HTTPException(403, str(exc)) from exc
        try:
            await _asyncio.to_thread(
                _track_subscription_fetch, username, user_agent or "")
        except Exception:  # noqa: BLE001 — never break a fetch on tracking
            pass
        try:
            snapshot = await _asyncio.to_thread(_legacy_user_snapshot, username)
            if snapshot is not None:
                used, total, expire = snapshot
                userinfo_header = (
                    f"upload=0; download={used}; total={total}; expire={expire}")
        except Exception:  # noqa: BLE001
            userinfo_header = ""

    if is_browser:
        page = await runtime.portal.build_page(
            user_id, lang=lang, public_host=request.url.hostname)
        if page is None:
            raise HTTPException(404, "subscription not found")
        if reissued_credentials is not None:
            page.reissued_credentials = reissued_credentials
        # the URL this page was fetched from, as the subscriber's browser
        # sees it (operator templates print/QR it — Marzban's
        # ``user.subscription_url``); the ?format= variants derive from it
        page.subscription_url = _public_request_url(request)
        # an operator may have picked an uploaded page
        # template. A missing/broken one serves the built-in page, so a
        # subscriber is never the one who pays for an operator's typo.
        template_name: str | None = None
        templates_dir: str | None = None
        try:
            settings = await runtime.portal_settings.get_portal_settings()
            template_name = getattr(settings, "subscription_template", None) or None
            if template_name:
                from app.portal.templates_store import data_dir_for

                templates_dir = data_dir_for(runtime)
        except Exception:  # noqa: BLE001 — settings read must not break delivery
            template_name, templates_dir = None, None
        return HTMLResponse(render_page_html(page, template_name,
                                             templates_dir=templates_dir))

    bundle = await runtime.portal.build_links(
        user_id, public_host=request.url.hostname, token=token)
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
                "subscription-userinfo": userinfo_header,
                "content-disposition": "attachment; filename=\"zagros.yaml\"",
            },
        )
    if fmt in ("sing-box", "singbox", "json"):
        body, _fmt_notes = to_sing_box(links, notes)
        return PlainTextResponse(
            body, media_type="application/json; charset=utf-8",
            headers={
                "profile-update-interval": "6",
                "subscription-userinfo": userinfo_header,
                "content-disposition": "attachment; filename=\"zagros.json\"",
            },
        )

    links = dedupe_links(links)
    body_lines = [f"# {n}" for n in notes] + links
    encoded = _base64.b64encode("\n".join(body_lines).encode()).decode()
    return PlainTextResponse(
        encoded,
        headers={
            "subscription-userinfo": userinfo_header,
            "profile-update-interval": "6",
            "content-disposition": "attachment; filename=\"zagros-subscription\"",
        },
    )


def _public_request_url(request: Request) -> str:
    """The request URL as the subscriber's browser sees it, without the
    query string (the canonical link is the bare token URL).

    Behind a reverse proxy the scheme/host are already the public ones:
    uvicorn rewrites them from ``X-Forwarded-*`` — but only for proxies
    listed in ``TRUSTED_PROXIES`` (main.py). Reading those headers here
    again would bypass that trust policy, so this deliberately does not.
    """
    return str(request.url.replace(query="", fragment=""))


def _format_for_ua(ua: str) -> str:
    """User-Agent → subscription format (Marzban-style sniffing, multi-core)."""
    if any(k in ua for k in ("clash", "mihomo", "flclash", "stash")):
        return "clash-meta"
    if any(k in ua for k in ("sing-box", "singbox", "sfa", "sfi", "sfm")):
        return "sing-box"
    return ""


@zagros_admin_router.get("/users/by-username/{username}/devices")
async def enrolled_subscription_devices(username: str,
                                         runtime=Depends(get_runtime)):
    from app.platform.device_enrollment import list_devices

    row = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        raise HTTPException(404, "user not found")
    devices = await asyncio.to_thread(list_devices, runtime, row.id)
    return {"username": username, "device_limit": row.device_limit,
            "devices": devices}


@zagros_admin_router.delete("/users/by-username/{username}/devices/{device_id}")
async def remove_enrolled_subscription_device(username: str, device_id: int,
                                                runtime=Depends(get_runtime)):
    from app.platform.device_enrollment import remove_device

    row = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        raise HTTPException(404, "user not found")
    removed = await asyncio.to_thread(remove_device, runtime, row.id, device_id)
    if not removed:
        raise HTTPException(404, "device not found")
    return {"removed": removed}


@zagros_admin_router.delete("/users/by-username/{username}/devices")
async def clear_enrolled_subscription_devices(username: str,
                                               runtime=Depends(get_runtime)):
    from app.platform.device_enrollment import remove_device

    row = await asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        raise HTTPException(404, "user not found")
    removed = await asyncio.to_thread(remove_device, runtime, row.id, None)
    return {"removed": removed}


@zagros_admin_router.post("/users/{user_id}/subscription-token")
async def issue_subscription_token(user_id: int, runtime=Depends(get_runtime)):
    """Issue (rotate) the user's portal URL token; older links die at once."""
    token, _ = runtime.tokens.issue(user_id, ttl_seconds=10 * 365 * 24 * 3600,
                                    token_type="sub")
    payload = runtime.tokens.verify(token, expected_type="sub")
    await runtime.kv.set_value(f"portal.sub_jti.{user_id}", payload["jti"])
    settings = (await runtime.portal_settings.get_portal_settings()).normalize()
    # New links honor the configured canonical root path. /sub/<token> and
    # /zagros/sub/<token> remain permanent aliases for every older token.
    path = settings.canonical_path(token)
    prefix = (settings.public_base_url() or "").rstrip("/")
    return {"token": token, "path": path,
            "url": f"{prefix}{path}" if prefix else None}


@zagros_admin_router.post("/users/by-username/{username}/subscription-token")
async def issue_subscription_token_by_username(username: str, runtime=Depends(get_runtime)):
    """Same as by-id, for the dashboard which identifies users by username."""
    import asyncio as _asyncio

    row = await _asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        raise HTTPException(404, f"user '{username}' not found")
    return await issue_subscription_token(row.id, runtime)


@zagros_admin_router.get("/users/by-username/{username}/subscription-url")
async def canonical_subscription_url_by_username(
    username: str, runtime=Depends(get_runtime),
):
    """Build a copy/QR URL from the SQL portal settings source of truth.

    Legacy user serializers still expose their historical config.py-derived
    field for API compatibility. The dashboard must not absolutize that field
    against ``window.location.origin`` because doing so silently discards the
    dedicated subscription domain/port.
    """
    import asyncio as _asyncio

    from app.utils.jwt import create_subscription_token

    row = await _asyncio.to_thread(runtime.users.get_user_by_username, username)
    if row is None:
        raise HTTPException(404, f"user '{username}' not found")
    settings = (await runtime.portal_settings.get_portal_settings()).normalize()
    token = create_subscription_token(username)
    path = settings.canonical_path(token)
    base = (settings.public_base_url() or "").rstrip("/")
    return {"path": path, "url": f"{base}{path}" if base else None,
            "listener_mode": settings.listener_mode}


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
async def core_wizard_schema(core_id: str, runtime=Depends(get_runtime)):
    """Dynamic inbound-wizard blueprint for this engine and live runtime.

    SoftEther availability is refined from the installed binary's read-only
    ``vpncmd Help`` inventory.  The endpoint therefore cannot claim PPTP (or
    any other server transport) merely because a static UI label exists.
    """
    import asyncio as _asyncio

    from app.studio.wizard import blueprint_for

    try:
        blueprint = blueprint_for(core_id)
    except KeyError:
        raise HTTPException(404, f"no inbound-wizard blueprint for core '{core_id}'") from None
    if blueprint["core_id"] == "softether":
        from app.cores.drivers.softether.capabilities import (
            apply_softether_wizard_capabilities,
        )

        blueprint = await _asyncio.to_thread(
            apply_softether_wizard_capabilities, blueprint, runtime)
    return blueprint


@zagros_admin_router.get("/cores/{core_id}/suggest-port")
async def core_suggest_port(core_id: str, runtime=Depends(get_runtime)):
    """ — a fresh RANDOM five-digit listen-port suggestion
    for the wizard: never a famous default, never one the host or a managed
    core already binds (best-effort collision avoidance)."""
    _driver_or_404(runtime, core_id)
    from app.studio.ports import host_listening_ports, studio_used_ports, suggest_port

    excluded = await studio_used_ports(runtime)
    excluded |= host_listening_ports()
    return {"port": suggest_port(excluded)}


class StudioPatchBody(BaseModel):
    operations: list[PatchOperation]


@zagros_admin_router.post("/studio/{core_id}/preview")
async def studio_preview(core_id: str, body: StudioPatchBody,
                         runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    return await runtime.studio.preview(driver, body.operations)


async def _materialize_studio(runtime, core_id: str, driver, doc) -> str | None:
    """Push the CANDIDATE studio document INTO the core (every driver
    implements apply_studio_document) — BEFORE it is
    persisted (: stage → materialize → persist, so a core
    that refuses the document fails the request WITHOUT moving the stored
    document to a state the engine rejected; the field-reported split where
    the API answered an opaque 5xx while the inbound HAD been persisted is
    gone for good).

    A driver that refuses the document (CoreError — cardinality violation,
    untranslatable wizard field, failed restart) speaks to the OPERATOR, so
    it maps to 422 with the driver's own message instead of leaking out as
    an opaque 500 (the field-reported TUIC/OpenVPN/… wizard crash)."""
    hook = getattr(driver, "apply_studio_document", None)
    if hook is None or doc is None:
        return ("document saved; this engine applies it on next start "
                "(no live studio→core bridge for this driver)")
    try:
        # CoreManager owns the lifecycle lock and persists any settings the
        # service driver derives from this document (port, PSK, endpoint,
        # listener set). Direct driver calls here raced start/restart and lost
        # settings on panel reboot.
        await runtime.core_manager.apply_studio_document(core_id, doc)
        connections = getattr(runtime, "application_connections", None)
        if connections is not None:
            await connections.reconcile_local_core(core_id)
    except CoreError as exc:
        raise HTTPException(422, f"{core_id}: {exc}") from exc
    return None


async def _cascade_grants(runtime, core_id: str) -> None:
    """Item 6: an applied document may have REMOVED inbounds — cascade the
    change into materialized grants (prune dangling tags / revoke empty
    accounts) so a later User Edit can never die on a ghost tag. Runs AFTER
    the document persisted (the catalog reads the store)."""
    try:
        from app.platform.provisioning import (
            reconcile_accounts_after_inbound_change,
        )

        report = await reconcile_accounts_after_inbound_change(runtime, core_id)
        if any(report.get(k) for k in ("pruned", "revoked")):
            logger.info("studio apply on %s — grant cascade: %s", core_id, report)
    except Exception as exc:  # noqa: BLE001 — never mask a successful apply
        logger.warning("post-apply grant cascade failed on %s: %s", core_id, exc)


def _studio_error(exc: StudioError) -> HTTPException:
    """Map staged-mutation identity errors to honest HTTP statuses
: ghost tag → 404, identity clash → 409, anything
    else is a client-correctable 422 — an opaque 500 is NEVER right for
    lifecycle conflicts."""
    if isinstance(exc, StudioNotFoundError):
        return HTTPException(404, str(exc))
    if isinstance(exc, StudioConflictError):
        return HTTPException(409, str(exc))
    return HTTPException(422, str(exc))


async def _commit_staged(runtime, core_id: str, driver, result) -> dict:
    """DEPRECATED compatibility shim — the transaction (stage → materialize
    → persist under the core lock) now lives INSIDE the service
    (``wizard_create/update/delete``). Kept for one release for tests that
    emulate the routed flow; new callers use the service transactions."""
    if not result.changed:
        return {**result.model_dump(), "materialized": None,
                "notice": result.detail or "already in the requested state"}
    warning = await _materialize_studio(runtime, core_id, driver, result.document)
    await runtime.studio.persist(driver, result.document or {})
    await _cascade_grants(runtime, core_id)
    return {**result.model_dump(), "materialized": warning is None, "notice": warning}


def _materialize_hook(runtime, core_id: str, driver):
    """The callback the service transactions invoke INSIDE the lock — maps
    engine refusals to 422 before anything persists."""
    async def _run(doc):
        return await _materialize_studio(runtime, core_id, driver, doc)

    return _run


async def _respond_committed(runtime, core_id: str, result, *, warning=None) -> dict:
    """Tail of a committed studio transaction: grant cascade + response
    shaping (idempotent replays skip the cascade — nothing changed)."""
    if not result.changed:
        return {**result.model_dump(), "materialized": None,
                "notice": result.detail or "already in the requested state"}
    await _cascade_grants(runtime, core_id)
    if core_id != "xray" and result.document is not None:
        from app.portal.hostengine import reconcile_default_hosts

        inbounds = result.document.get("inbounds") or []
        tags = [str(item.get("tag")) for item in inbounds
                if isinstance(item, dict) and item.get("tag")]
        await reconcile_default_hosts(runtime.core_hosts, core_id, tags)
    return {**result.model_dump(),
            "materialized": warning is None,
            "notice": warning}


@zagros_admin_router.post("/studio/{core_id}/apply")
async def studio_apply(core_id: str, body: StudioPatchBody,
                       runtime=Depends(get_runtime)):
    driver = _driver_or_404(runtime, core_id)
    result = await runtime.studio.apply_operations(
        driver, body.operations, _materialize_hook(runtime, core_id, driver))
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    return await _respond_committed(runtime, core_id, result)


def _certs_data_dir(runtime) -> str:
    """The panel data dir for the managed certificate store — same contract
    as admin_api._data_dir (kept local: admin_api depends on THIS module,
    so importing it back would cycle)."""
    url = str(getattr(runtime, "database_url", "") or "")
    if url.startswith("sqlite:///"):
        from pathlib import Path

        return str(Path(url[10:]).parent)
    return "/var/lib/zagros"


def _resolve_certificate_ref(runtime, spec: InboundSpec) -> None:
    """Item 10: ``certificate_ref`` (a managed certificate NAME from the
    Certificates store) in a wizard spec is resolved server-side into the
    inline PEM pair drivers already understand — with REAL validation
    (parse + key-matches-cert + expiry surfaced), never trust by name.
    Mutates the spec in place; ref always wins over pasted content."""
    ref = spec.settings.pop("certificate_ref", None)
    if not ref:
        return
    from pathlib import Path

    data_dir = _certs_data_dir(runtime)
    base = Path(data_dir) / "certs" / str(ref)
    cert_path, key_path = base / "fullchain.pem", base / "key.pem"
    if not base.is_dir() or not cert_path.exists() or not key_path.exists():
        raise HTTPException(
            404, f"managed certificate '{ref}' not found under {data_dir}/certs/")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert_pem = cert_path.read_bytes()
    key_pem = key_path.read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
    except ValueError as exc:
        raise HTTPException(422, f"certificate '{ref}' is not a valid PEM pair: {exc}") from exc
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise HTTPException(422, f"certificate '{ref}' and its private key do NOT match")
    spec.settings["certificate"] = cert_pem.decode()
    spec.settings["certificate_key"] = key_pem.decode()


@zagros_admin_router.post("/studio/{core_id}/wizard/inbound")
async def studio_wizard_inbound(core_id: str, spec: InboundSpec,
                                runtime=Depends(get_runtime)):
    """Create — atomic + idempotent: staged under the
    per-core lock, materialized BEFORE persisted; an identical replay is a
    success without a duplicate; a conflicting tag is a 409."""
    driver = _driver_or_404(runtime, core_id)
    _resolve_certificate_ref(runtime, spec)
    try:
        result = await runtime.studio.wizard_create(
            driver, spec, _materialize_hook(runtime, core_id, driver))
    except StudioError as exc:
        raise _studio_error(exc) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    return await _respond_committed(runtime, core_id, result)


@zagros_admin_router.put("/studio/{core_id}/wizard/inbound/{tag}")
async def studio_wizard_update_inbound(core_id: str, tag: str, spec: InboundSpec,
                                       runtime=Depends(get_runtime)):
    """Item 11 — Edit an existing inbound through the same wizard flow
    (staged → materialized → persisted, atomically)."""
    driver = _driver_or_404(runtime, core_id)
    _resolve_certificate_ref(runtime, spec)
    try:
        result = await runtime.studio.wizard_update(
            driver, tag, spec, _materialize_hook(runtime, core_id, driver))
    except StudioError as exc:
        raise _studio_error(exc) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    return await _respond_committed(runtime, core_id, result)


@zagros_admin_router.delete("/studio/{core_id}/wizard/inbound/{tag}")
async def studio_wizard_delete_inbound(core_id: str, tag: str,
                                       runtime=Depends(get_runtime)):
    """Delete ONE inbound by its stable identity — the tag (item
    5; replaces the index-based frontend patch that could remove the WRONG
    listener off a stale snapshot). Ghost tag → 404; duplicate tags (broken
    document) → 409; success removes exactly one entry, cascades grants."""
    driver = _driver_or_404(runtime, core_id)
    try:
        result = await runtime.studio.wizard_delete(
            driver, tag, _materialize_hook(runtime, core_id, driver))
    except StudioError as exc:
        raise _studio_error(exc) from exc
    if not result.valid:
        raise HTTPException(422, {"errors": result.errors})
    if not result.changed:
        return {"ok": True, "deleted": None, "materialized": None,
                "notice": result.detail or "already absent"}
    notice = await _delete_cascade_notice(runtime, core_id)
    if core_id != "xray" and result.document is not None:
        from app.portal.hostengine import reconcile_default_hosts

        tags = [str(item.get("tag")) for item in (result.document.get("inbounds") or [])
                if isinstance(item, dict) and item.get("tag")]
        await reconcile_default_hosts(runtime.core_hosts, core_id, tags)
    elif core_id == "xray":
        # Grant cascade ran first; now the legacy inbound/host row can be
        # removed cleanly. Association rows (proxy exclusions / template
        # inbounds) pointing at the tag are removed first — their FKs carry
        # no ON DELETE CASCADE and MySQL answers 1451 otherwise — then the
        # inbound itself (ProxyHost goes with it via delete-orphan).
        import asyncio as _asyncio

        def _remove_legacy_host() -> None:
            from app.db import GetDB, crud

            with GetDB() as db:
                crud.remove_inbound_row(db, tag)

        await _asyncio.to_thread(_remove_legacy_host)
    return {"ok": True, "deleted": tag,
            "materialized": result.document is not None,
            "notice": notice}


async def _delete_cascade_notice(runtime, core_id: str) -> str | None:
    """Delete tail: grants bound to the removed inbound are pruned/revoked
    (item 6). Failures surface in logs only — the delete itself succeeded."""
    await _cascade_grants(runtime, core_id)
    return None


@zagros_admin_router.post("/studio/{core_id}/wizard/preview")
async def studio_wizard_preview(core_id: str, spec: InboundSpec,
                                runtime=Depends(get_runtime)):
    """Item 6 Preview gate: validate the wizard spec (patch + schema + diff)
    WITHOUT persisting or materializing — the stepper's review step calls
    this so an invalid inbound is rejected BEFORE any document mutation."""
    driver = _driver_or_404(runtime, core_id)
    _resolve_certificate_ref(runtime, spec)
    try:
        result = await runtime.studio.wizard_preview_inbound(driver, spec)
    except StudioError as exc:
        raise HTTPException(422, str(exc)) from exc
    return result


def _driver_or_404(runtime, core_id: str):
    try:
        return runtime.core_manager.get(core_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(404, f"core '{core_id}' is not installed") from exc


@zagros_admin_router.get("/settings/portal", response_model=PortalSettings)
async def get_portal_settings(runtime=Depends(get_runtime)):
    return await runtime.portal_settings.get_portal_settings()


def _validate_portal_certificate(runtime, settings: PortalSettings) -> None:
    ident = (settings.tls_certificate_id or "").strip()
    if not ident:
        return
    from app.platform import certificates

    data_dir = (str(Path(runtime.database_url[10:]).parent)
                if runtime.database_url.startswith("sqlite:///")
                else "/var/lib/zagros")
    found = next((item for item in certificates.scan(data_dir, managed_only=True)
                  if item.id == ident or item.name == ident), None)
    if found is None:
        raise ValueError(f"TLS certificate '{ident}' does not exist")
    if found.expired or not found.has_key:
        raise ValueError(f"TLS certificate '{ident}' is expired or has no private key")
    hostname = settings.public_base_url()
    if hostname:
        from urllib.parse import urlsplit
        hostname = urlsplit(hostname).hostname
    if hostname and not certificates.certificate_covers(found.path, hostname):
        raise ValueError(
            f"TLS certificate '{ident}' does not cover subscription hostname '{hostname}'")


@zagros_admin_router.put("/settings/portal", response_model=PortalSettings)
async def put_portal_settings(settings: PortalSettings, request: Request,
                              runtime=Depends(get_runtime)):
    previous = await runtime.portal_settings.get_portal_settings()
    try:
        settings = settings.normalize()
        _validate_portal_certificate(runtime, settings)
        # Listener first, persistence second: an unbindable domain/port/TLS
        # configuration can never replace last-known-good desired state.
        await runtime.subscription_listener.apply(settings, runtime, request.app)
        try:
            return await runtime.portal_settings.save_portal_settings(settings)
        except Exception:
            await runtime.subscription_listener.apply(previous, runtime, request.app)
            raise
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@zagros_admin_router.post("/settings/portal/test")
async def portal_settings_test(settings: PortalSettings,
                               runtime=Depends(get_runtime)):
    """Validate and show every URL family without mutating persistence."""
    try:
        settings = settings.normalize()
        _validate_portal_certificate(runtime, settings)
        if settings.listener_mode == "dedicated":
            await runtime.subscription_listener._preflight(runtime, settings)  # noqa: SLF001
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    base = settings.public_base_url() or "https://panel.example.com"
    path = settings.canonical_path()
    subscription = base.rstrip("/") + path
    qr_base = (settings.qr_base_url or base).rstrip("/")
    warnings: list[str] = []
    if settings.public_scheme == "https" and not settings.tls_certificate_id:
        warnings.append("HTTPS selected without a panel-managed certificate; an external reverse proxy must terminate TLS")
    return {
        "ok": True,
        "base_url": base,
        "subscription": subscription,
        "portal": subscription,
        "clash": subscription + "?format=clash-meta",
        "sing_box": subscription + "?format=sing-box",
        "qr_base_url": qr_base,
        "openvpn_host": qr_base,
        "wireguard_host": qr_base,
        "force_https": settings.force_https,
        "listener_mode": settings.listener_mode,
        "listener": runtime.subscription_listener.public_status(),
        "warnings": warnings,
    }


def _application_admin_error(exc: ApplicationApiError) -> HTTPException:
    return HTTPException(
        exc.status_code,
        {"error": exc.error_code, "message": str(exc)},
    )


async def _owner_admin_id_or_current(request: Request, runtime,
                                     explicit: int | None) -> int:
    """Create-call owner: explicit id, else the calling sudo admin."""
    if explicit is not None:
        return explicit
    header = request.headers.get("authorization", "")
    token = header.split(" ", 1)[1].strip() if " " in header else ""
    if not token:
        raise HTTPException(401, "missing credentials")
    from app.utils.jwt import get_admin_payload

    username = str((get_admin_payload(token) or {}).get("username") or "")
    if not username:
        raise HTTPException(401, "invalid or expired token")

    def _lookup() -> int | None:
        from sqlalchemy import select
        from sqlalchemy.exc import IntegrityError

        from app.persistence.models import AdminModel

        with runtime.session_factory() as session:
            row = session.execute(select(AdminModel).where(
                AdminModel.username == username)).scalar_one_or_none()
            if row is not None:
                return row.id
            # The platform admins table mirrors the legacy one (same rule as
            # the migration: username-keyed, hash copied as-is). A CLI-created
            # admin that postdates the migration has no mirror row yet, and
            # owner_admin_id is FK-bound to THIS table — so the first
            # ownership-taking call mirrors the identity. This creates no
            # credential: authentication keeps reading the legacy table, and
            # the row carries the CLI-set sudo flag and telegram id.
            from app.db import GetDB, crud

            with GetDB() as legacy_db:
                legacy = crud.get_admin(legacy_db, username=username)
                if legacy is None:
                    return None
                mirror = AdminModel(
                    username=legacy.username,
                    password_hash=legacy.hashed_password or "",
                    is_sudo=bool(legacy.is_sudo),
                    telegram_id=legacy.telegram_id)
            session.add(mirror)
            try:
                session.commit()
            except IntegrityError:
                # Lost a first-use race with another request; re-read theirs.
                session.rollback()
                row = session.execute(select(AdminModel).where(
                    AdminModel.username == username)).scalar_one_or_none()
                return row.id if row is not None else None
            return mirror.id

    admin_id = await asyncio.to_thread(_lookup)
    if admin_id is None:
        raise HTTPException(401, "admin account no longer exists")
    return admin_id


@zagros_admin_router.post("/applications", response_model=ApplicationBootstrap)
async def create_application(body: ApplicationCreateBody,
                             request: Request,
                             runtime=Depends(get_runtime)):
    """Create independent Ed25519/X25519 identities; returns public keys only."""
    from urllib.parse import urlsplit

    owner_admin_id = await _owner_admin_id_or_current(
        request, runtime, body.owner_admin_id)

    parsed = urlsplit(body.api_base_url.strip())
    loopback = parsed.hostname == "localhost"
    if parsed.hostname and not loopback:
        try:
            import ipaddress
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
    if (not parsed.hostname
            or parsed.scheme not in ({"http", "https"} if loopback else {"https"})):
        raise HTTPException(
            422, "api_base_url must use HTTPS (HTTP is allowed only on loopback)")
    try:
        return await asyncio.to_thread(
            runtime.application_auth_repository.create_application,
            owner_admin_id=owner_admin_id, name=body.name,
            api_base_url=body.api_base_url, default_lang=body.default_lang,
            branding=body.branding,
        )
    except ApplicationApiError as exc:
        raise _application_admin_error(exc) from exc


@zagros_admin_router.get("/applications",
                             response_model=list[ApplicationListItem])
async def list_applications(runtime=Depends(get_runtime)):
    """Every Application (admin projection — public identity only)."""
    try:
        return await asyncio.to_thread(
            runtime.application_auth_repository.list_applications)
    except ApplicationApiError as exc:
        raise _application_admin_error(exc) from exc


@zagros_admin_router.get("/users/{user_id}/application-overview",
                         response_model=UserApplicationOverview)
async def user_application_overview(user_id: int,
                                    runtime=Depends(get_runtime)):
    """One user's Application-login state: credentials, grants, builds.

    Feeds the Users dialog "Application login" section: whether app
    credentials were ever issued (never the hash), which Applications
    bound the user, and each bound app's latest build with its targets
    and files. 404 when the user does not exist.
    """
    user = await _application_overview_user(runtime, user_id=user_id)
    try:
        grants = await asyncio.to_thread(
            runtime.application_auth_repository.user_grants, user_id=user_id)
    except ApplicationApiError as exc:
        raise _application_admin_error(exc) from exc
    latest: dict[str, dict | None] = {}
    for grant in grants:
        app_id = grant["application_id"]
        try:
            items, _total = await asyncio.to_thread(
                runtime.build_service.list_builds, limit=1, offset=0,
                application_public_id=app_id)
        except Exception:  # noqa: BLE001 — builds must not kill the overview
            latest[app_id] = None
            continue
        if not items:
            latest[app_id] = None
            continue
        try:
            full = await asyncio.to_thread(
                runtime.build_service.get_build, items[0]["public_id"])
        except Exception:  # noqa: BLE001 — fall back to the list row
            full = items[0]
        jobs = full.get("targets", []) or []
        files = full.get("artifacts", []) or []
        latest[app_id] = {
            "build_id": full.get("public_id", ""),
            "version": full.get("version"),
            "build_number": full.get("build_number"),
            "status": full.get("status", ""),
            "progress": full.get("progress"),
            "created_at": full.get("created_at"),
            "targets": [{
                "platform": job.get("platform", ""),
                "arch": job.get("arch", ""),
                "artifact": job.get("artifact", ""),
                "status": job.get("status", ""),
            } for job in jobs],
            "artifacts": [{
                "platform": art.get("platform", ""),
                "arch": art.get("arch", ""),
                "artifact": art.get("artifact", ""),
                "filename": art.get("filename", ""),
                "rel_path": art.get("rel_path", ""),
                "sha256": art.get("sha256", ""),
                "size_bytes": art.get("size_bytes", 0),
            } for art in files],
        }
    overview_settings = await runtime.portal_settings.get_portal_settings()
    return {
        "user_id": user.id,
        "username": user.username,
        # Pre-migration rows store NULL (the CHECK allows it). The raw
        # value 'default' means "follow the panel-wide setting"; the mode
        # resolved for RIGHT NOW is 'effective_access_mode'.
        "access_mode": user.access_mode or "default",
        "effective_access_mode": _effective_access_mode(
            user, overview_settings),
        "app_username": user.app_username,
        "has_app_credentials": bool(
            user.app_username and user.app_password_hash),
        "grants": grants,
        "latest_builds": latest,
    }


async def _application_overview_user(runtime, *, user_id=None, username=None):
    """Resolve the platform user for an overview request (404 when absent)."""
    try:
        if user_id is not None:
            user = await asyncio.to_thread(runtime.users.get_user, user_id)
        else:
            user = await asyncio.to_thread(
                runtime.users.get_user_by_username, username)
    except Exception as exc:  # noqa: BLE001 — storage failure, not 404
        raise HTTPException(500, f"user lookup failed: {exc}") from exc
    if user is None:
        raise HTTPException(404, "user not found")
    return user


@zagros_admin_router.get("/users/by-username/{username}/application-overview",
                         response_model=UserApplicationOverview)
async def user_application_overview_by_username(
        username: str, runtime=Depends(get_runtime)):
    """Same overview addressed by username (the Users dialog uses this)."""
    user = await _application_overview_user(runtime, username=username)
    return await user_application_overview(user.id, runtime=runtime)


@zagros_admin_router.post(
    "/applications/{application_id}/grants",
    response_model=ApplicationGrantResult,
)
async def grant_application_user(application_id: str,
                                 body: ApplicationGrantBody,
                                 runtime=Depends(get_runtime)):
    try:
        return await asyncio.to_thread(
            runtime.application_auth_repository.grant_user,
            application_public_id=application_id, user_id=body.user_id)
    except ApplicationApiError as exc:
        raise _application_admin_error(exc) from exc


@zagros_admin_router.post(
    "/applications/{application_id}/activation-tickets",
    response_model=ActivationTicketResult,
)
async def issue_application_activation_ticket(
    application_id: str, body: ActivationTicketIssueBody,
    request: Request,
    runtime=Depends(get_runtime),
):
    """Return a user-bound ticket once for reseller QR/code delivery."""
    try:
        result = await asyncio.to_thread(
            runtime.application_auth_repository.issue_activation_ticket,
            application_public_id=application_id, user_id=body.user_id,
            ttl_seconds=body.ttl_seconds,
            intended_device_public_key=body.intended_device_public_key,
        )
        from app.platform.subscription_links import link_shape
        shape = link_shape()
        enroll_base = shape.get("base") or ""
        if not enroll_base or "*" in enroll_base:
            # No stable public identity (or a wildcard sub prefix that
            # must not mint the enrollment host): fall back to the
            # address the admin reached the panel on.
            enroll_base = str(request.base_url).rstrip("/")
        result["enrollment_url"] = (
            f"{enroll_base}/zagros/activate/{result['activation_ticket']}")
        return result
    except (ApplicationApiError, ValueError) as exc:
        if isinstance(exc, ApplicationApiError):
            raise _application_admin_error(exc) from exc
        raise HTTPException(422, "invalid intended device public key") from exc


@zagros_admin_router.get("/applications/{application_id}",
                         response_model=ApplicationDetail)
async def get_application_detail(application_id: str,
                                 runtime=Depends(get_runtime)):
    """One Application with its branding document (no key material)."""
    row = await asyncio.to_thread(
        runtime.application_auth_repository.get_application,
        application_id)
    if row is None:
        raise HTTPException(404, "application not found")
    return row


@zagros_admin_router.get("/applications/{application_id}/grants",
                         response_model=list[ApplicationGrantListItem])
async def list_application_grants(application_id: str,
                                  runtime=Depends(get_runtime)):
    """Users bound to one Application (the detail panel's grant list)."""
    repo = runtime.application_auth_repository
    row = await asyncio.to_thread(repo.get_application, application_id)
    if row is None:
        raise HTTPException(404, "application not found")
    return await asyncio.to_thread(repo.application_grants, application_id)


@zagros_admin_router.get("/applications/{application_id}/keys",
                         response_model=ApplicationPublicKeys)
async def get_application_public_keys(application_id: str,
                                      runtime=Depends(get_runtime)):
    """Active PUBLIC keys (b64url) — feeds the build-config prefill.

    Private key envelopes are never selected; only the already-public
    ``public_key`` column of the active KIDs.
    """
    repo = runtime.application_auth_repository
    row = await asyncio.to_thread(repo.get_application, application_id)
    if row is None:
        raise HTTPException(404, "application not found")
    return await asyncio.to_thread(
        repo.application_public_keys, application_id)


def _app_icons_dir(runtime) -> str:
    from app.portal.templates_store import data_dir_for

    return data_dir_for(runtime)


@zagros_admin_router.post("/applications/{application_id}/icon",
                          response_model=ApplicationIconMeta,
                          status_code=201)
async def upload_application_icon(application_id: str,
                                  file: UploadFile = File(...),
                                  runtime=Depends(get_runtime)):
    """Upload/replace the launcher icon (square PNG, <=1 MiB)."""
    from app.applicationapi.icons import (
        MAX_BYTES, IconValidationError, delete_icon_file, store_icon,
    )

    repo = runtime.application_auth_repository
    row = await asyncio.to_thread(repo.get_application, application_id)
    if row is None:
        raise HTTPException(404, "application not found")
    if row["status"] != "active":
        raise HTTPException(409, "application is not active")
    data = await file.read(MAX_BYTES + 1)
    if not data:
        raise HTTPException(422, "empty upload")
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "icon exceeds 1 MiB")
    data_dir = _app_icons_dir(runtime)
    try:
        meta = await asyncio.to_thread(
            store_icon, data_dir, application_id, bytes(data))
    except IconValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        saved = await asyncio.to_thread(
            repo.set_application_icon, application_id, meta)
    except Exception:  # noqa: BLE001 - never strand an orphan file
        await asyncio.to_thread(delete_icon_file, data_dir, application_id)
        raise
    if saved is None:  # deleted between the two calls
        await asyncio.to_thread(delete_icon_file, data_dir, application_id)
        raise HTTPException(404, "application not found")
    return meta


@zagros_admin_router.get("/applications/{application_id}/icon")
async def download_application_icon(application_id: str,
                                    runtime=Depends(get_runtime)):
    """Serve the uploaded launcher icon (404 when none)."""
    from app.applicationapi.icons import icon_file_path

    row = await asyncio.to_thread(
        runtime.application_auth_repository.get_application,
        application_id)
    if row is None:
        raise HTTPException(404, "application not found")
    icon = (row.get("branding") or {}).get("icon")
    path = icon_file_path(_app_icons_dir(runtime), application_id)
    if not icon or not path.is_file():
        raise HTTPException(404, "no icon uploaded")
    return FileResponse(path, media_type="image/png",
                        filename=f"{application_id}-icon.png")


@zagros_admin_router.delete("/applications/{application_id}/icon",
                            status_code=204)
async def delete_application_icon(application_id: str,
                                  runtime=Depends(get_runtime)):
    """Remove the launcher icon file + its branding document."""
    from app.applicationapi.icons import delete_icon_file

    repo = runtime.application_auth_repository
    row = await asyncio.to_thread(repo.get_application, application_id)
    if row is None:
        raise HTTPException(404, "application not found")
    if row["status"] != "active":
        raise HTTPException(409, "application is not active")
    await asyncio.to_thread(
        delete_icon_file, _app_icons_dir(runtime), application_id)
    await asyncio.to_thread(repo.set_application_icon, application_id, None)
    return None


@zagros_admin_router.post(
    "/applications/{application_id}/revoke",
    response_model=AuthorityRevokeResult,
)
async def admin_revoke_application(
    application_id: str, runtime=Depends(get_runtime),
):
    try:
        return await asyncio.to_thread(
            runtime.application_auth_repository.revoke_application,
            application_public_id=application_id,
        )
    except ApplicationApiError as exc:
        raise _application_admin_error(exc) from exc


@zagros_admin_router.post(
    "/applications/{application_id}/grants/{user_id}/revoke",
    response_model=AuthorityRevokeResult,
)
async def admin_revoke_application_grant(
    application_id: str, user_id: int, runtime=Depends(get_runtime),
):
    try:
        return await asyncio.to_thread(
            runtime.application_auth_repository.revoke_user_grant,
            application_public_id=application_id, user_id=user_id,
        )
    except ApplicationApiError as exc:
        raise _application_admin_error(exc) from exc


@zagros_admin_router.post(
    "/applications/{application_id}/keys/{key_id}/revoke",
    response_model=AuthorityRevokeResult,
)
async def admin_revoke_application_key(
    application_id: str, key_id: str, runtime=Depends(get_runtime),
):
    try:
        return await asyncio.to_thread(
            runtime.application_auth_repository.revoke_application_key,
            application_public_id=application_id, key_id=key_id,
        )
    except ApplicationApiError as exc:
        raise _application_admin_error(exc) from exc


@zagros_admin_router.post(
    "/applications/{application_id}/devices/{device_id}/revoke",
    response_model=DeviceRevokeResult,
)
async def admin_revoke_application_device(
    application_id: str, device_id: str, runtime=Depends(get_runtime),
):
    try:
        return await asyncio.to_thread(
            runtime.application_auth_repository.admin_revoke_application_device,
            application_public_id=application_id,
            target_device_key_id=device_id,
        )
    except ApplicationApiError as exc:
        raise _application_admin_error(exc) from exc


@zagros_admin_router.post("/users/{user_id}/app-credentials",
                    response_model=AppCredentials)
async def issue_app_credentials(user_id: int, runtime=Depends(get_runtime)):
    try:
        return await runtime.client_api.issue_app_credentials(user_id)
    except ClientApiError as exc:
        raise _client_error(exc) from exc


@zagros_admin_router.post("/users/{user_id}/access-mode",
                          response_model=AccessModeResult)
async def set_user_access_mode(user_id: int, body: AccessModeBody,
                               runtime=Depends(get_runtime)):
    """Switch one user's delivery mode (subscription <-> application).

    Leaving 'application' revokes the user's app authorities (same rule as
    the user upsert); the UI confirms before sending that direction.
    """
    requested = (body.mode or "").strip().lower()
    if requested not in ("default", "subscription", "application"):
        raise HTTPException(
            422, "mode must be 'default', 'subscription' or 'application'")
    # 'default' clears both per-user columns so the row follows the
    # panel-wide setting again; the hint lets the repository evaluate the
    # revoke-on-leave rule against the mode the user effectively has now.
    settings = await runtime.portal_settings.get_portal_settings()
    global_mode = _panel_default_access_mode(settings)
    try:
        await asyncio.to_thread(
            runtime.users.set_access_mode, user_id, requested,
            default_mode_hint=global_mode)
    except KeyError:
        raise HTTPException(404, "user not found") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    user = await asyncio.to_thread(runtime.users.get_user, user_id)
    return {"user_id": user_id,
            "username": user.username if user is not None else "",
            "access_mode": requested,
            "effective_access_mode": (requested if requested != "default"
                                      else global_mode)}


def _panel_default_access_mode(settings) -> str:
    """Panel-wide delivery default: 'application' or 'subscription'."""
    from app.portal.models import ClientAuthMode
    if getattr(settings, "client_auth_mode", None) is ClientAuthMode.APPLICATION_LOGIN:
        return "application"
    return "subscription"


def _effective_access_mode(user, settings) -> str:
    """Effective delivery mode: explicit per-user override, else panel default.

    Reads BOTH per-user columns (access_mode is canonical; client_auth_mode
    is the legacy shadow) so pre-migration and freshly-defaulted rows
    resolve the same way the delivery layer resolves them.
    """
    raw = ((getattr(user, "access_mode", None)
            or getattr(user, "client_auth_mode", None)) or "").strip().lower()
    if raw in ("application", "application_login"):
        return "application"
    if raw in ("subscription", "subscription_link"):
        return "subscription"
    return _panel_default_access_mode(settings)


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
